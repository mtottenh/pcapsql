//! Integration tests against a real S3-compatible object store (MinIO/SeaweedFS).
//!
//! Gated two ways so the normal `cargo test` run needs no object store:
//!   1. the `s3` cargo feature, and
//!   2. the `PCAPSQL_S3_TEST_ENDPOINT` environment variable.
//!
//! To run against a local store (see `testdata/cloud/`):
//! ```text
//! docker compose -f testdata/cloud/docker-compose.yml up -d   # MinIO
//! # or run SeaweedFS:  weed server -s3 -s3.config=testdata/cloud/s3.json
//! AWS_ACCESS_KEY_ID=pcapsqlkey AWS_SECRET_ACCESS_KEY=pcapsqlsecret \
//! AWS_REGION=us-east-1 PCAPSQL_S3_TEST_ENDPOINT=http://127.0.0.1:8333 \
//!   cargo test -p pcapsql-datafusion --features s3 --test cloud_integration -- --nocapture
//! ```
//!
//! The key property mirrors the local sources: parsing a cloud object at N
//! partitions (independent byte-range GETs) yields exactly the same rows in the
//! same order as parsing it at 1 partition.
#![cfg(feature = "s3")]

use object_store::{ObjectStore, PutPayload};
use pcapsql_core::io::{
    CloudLocation, CloudPacketSource, PacketReader, PacketSource, SeekablePacketSource,
};
use pcapsql_testgen::{generate, legacy_pcap, CaptureSpec, Format, GenPacket, LegacyVariant};

/// Endpoint of the test object store, or `None` to skip (store unavailable).
fn endpoint() -> Option<String> {
    std::env::var("PCAPSQL_S3_TEST_ENDPOINT")
        .ok()
        .filter(|s| !s.is_empty())
}

fn bucket() -> String {
    std::env::var("PCAPSQL_S3_TEST_BUCKET").unwrap_or_else(|_| "test-pcaps".to_string())
}

fn location(ep: &str, key: &str) -> CloudLocation {
    CloudLocation::parse(&format!("s3://{}/{}", bucket(), key))
        .expect("parse s3 url")
        .with_endpoint(ep)
}

/// Upload bytes through the same object_store backend the source reads through.
async fn upload(ep: &str, key: &str, bytes: Vec<u8>) {
    let loc = location(ep, key);
    let store = loc.build_store().expect("build store");
    store
        .put(&loc.object_path(), PutPayload::from(bytes))
        .await
        .expect("put object");
}

/// A real Ethernet/IPv4/UDP frame so protocol tables populate.
fn udp_packet(src_port: u16, payload_len: usize) -> Vec<u8> {
    let mut p = Vec::with_capacity(42 + payload_len);
    p.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    p.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    p.extend_from_slice(&[0x08, 0x00]);
    let ip_total = (20 + 8 + payload_len) as u16;
    p.push(0x45);
    p.push(0x00);
    p.extend_from_slice(&ip_total.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00, 0x40, 0x00]);
    p.push(64);
    p.push(17);
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend_from_slice(&[192, 168, 0, 1]);
    p.extend_from_slice(&[192, 168, 0, 2]);
    let udp_len = (8 + payload_len) as u16;
    p.extend_from_slice(&src_port.to_be_bytes());
    p.extend_from_slice(&53u16.to_be_bytes());
    p.extend_from_slice(&udp_len.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend(std::iter::repeat_n(0xAB, payload_len));
    p
}

/// Generate a capture > 16 MiB so the RangeRequest cost gate allows partitioning.
fn big_capture(count: usize, payload: usize) -> Vec<u8> {
    let packets: Vec<GenPacket> = (0..count)
        .map(|i| {
            let data = udp_packet(10_000 + (i % 5000) as u16, payload);
            let origlen = data.len() as u32;
            GenPacket {
                ts_sec: 1_700_000_000 + (i / 1000) as u32,
                ts_frac: (i as u32 * 251) % 1_000_000,
                data,
                origlen,
            }
        })
        .collect();
    legacy_pcap(LegacyVariant::LeMicro, 1, 65535, &packets).bytes
}

fn drain<R: PacketReader>(reader: &mut R) -> Vec<u64> {
    let mut out = Vec::new();
    loop {
        let mut batch = Vec::new();
        let n = reader
            .process_packets(256, |p| {
                batch.push(p.frame_number);
                Ok(())
            })
            .expect("process_packets");
        out.extend(batch);
        if n == 0 {
            break;
        }
    }
    out
}

/// Source-level: byte-range partitioned reads over the network reproduce the
/// sequential read exactly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s3_partition_equivalence_source_level() {
    let Some(ep) = endpoint() else {
        eprintln!("skipping cloud test: PCAPSQL_S3_TEST_ENDPOINT not set");
        return;
    };

    let key = "equiv/source_level.pcap";
    let total = 20_000u64;
    upload(&ep, key, big_capture(total as usize, 1000)).await;

    let source = CloudPacketSource::open(location(&ep, key))
        .expect("open cloud source")
        .with_index_stride(2048);

    assert!(
        source.metadata().size_bytes.unwrap() > 16 * 1024 * 1024,
        "object must be large enough to be worth partitioning"
    );

    // Sequential read over the network.
    let mut seq_reader = source.sequential_reader().expect("sequential reader");
    let seq = drain(&mut seq_reader);
    assert_eq!(seq, (1..=total).collect::<Vec<_>>());

    // Partitioned: independent byte-range GETs, reassembled in order.
    let ranges = source.partitions(4).expect("partitions");
    assert!(
        ranges.len() > 1,
        "a >16MiB object should split into multiple partitions, got {}",
        ranges.len()
    );
    let mut part = Vec::new();
    for range in &ranges {
        let mut r = source.reader_at(range).expect("reader_at over network");
        part.extend(drain(&mut r));
    }
    assert_eq!(
        part, seq,
        "partitioned (range-GET) read must equal sequential"
    );
}

/// A small object still reads correctly sequentially.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s3_small_object_sequential() {
    let Some(ep) = endpoint() else {
        eprintln!("skipping cloud test: PCAPSQL_S3_TEST_ENDPOINT not set");
        return;
    };

    let key = "small/tiny.pcap";
    upload(&ep, key, big_capture(50, 20)).await;

    let source = CloudPacketSource::open(location(&ep, key)).expect("open");
    let mut r = source.sequential_reader().expect("reader");
    assert_eq!(drain(&mut r).len(), 50);
}

// ----------------------------------------------------------------------------
// Format, compression and error-path coverage (ported from the pre-stage-6
// suite, now generated on the fly and exercised through the current API).
// ----------------------------------------------------------------------------

/// 200 UDP frames in the requested legacy variant.
fn small_capture(variant: LegacyVariant) -> Vec<u8> {
    let packets: Vec<GenPacket> = (0..200)
        .map(|i| {
            let data = udp_packet(40_000 + i as u16, 32);
            let origlen = data.len() as u32;
            GenPacket {
                ts_sec: 1_700_000_000 + i as u32,
                ts_frac: (i as u32 * 7919) % 1_000_000,
                data,
                origlen,
            }
        })
        .collect();
    legacy_pcap(variant, 1, 65535, &packets).bytes
}

fn count_sequential(source: &CloudPacketSource) -> usize {
    let mut r = source.sequential_reader().expect("sequential reader");
    drain(&mut r).len()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s3_not_found_is_an_error() {
    let Some(ep) = endpoint() else {
        eprintln!("skipping cloud test: PCAPSQL_S3_TEST_ENDPOINT not set");
        return;
    };
    assert!(CloudPacketSource::open(location(&ep, "missing/does-not-exist.pcap")).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s3_all_legacy_variants_and_pcapng() {
    let Some(ep) = endpoint() else {
        eprintln!("skipping cloud test: PCAPSQL_S3_TEST_ENDPOINT not set");
        return;
    };
    for (name, variant) in [
        ("le_micro", LegacyVariant::LeMicro),
        ("be_micro", LegacyVariant::BeMicro),
        ("le_nano", LegacyVariant::LeNano),
        ("be_nano", LegacyVariant::BeNano),
    ] {
        let key = format!("formats/{name}.pcap");
        upload(&ep, &key, small_capture(variant)).await;
        let source = CloudPacketSource::open(location(&ep, &key)).expect("open");
        assert_eq!(source.metadata().link_type, 1, "{name}: link type");
        assert_eq!(count_sequential(&source), 200, "{name}: frame count");
    }

    // PCAPNG, both byte orders, with a mid-stream IDB.
    for (name, format) in [("le", Format::Pcapng), ("be", Format::PcapngBe)] {
        let gc = generate(&CaptureSpec {
            format,
            seed: 11,
            packet_count: 200,
            min_size: 60,
            max_size: 200,
            link_type: 1,
            interfaces: vec![6, 9],
            sections: 2,
            add_interface_midstream: true,
        });
        let key = format!("formats/pcapng_{name}.pcapng");
        upload(&ep, &key, gc.bytes.clone()).await;
        let source = CloudPacketSource::open(location(&ep, &key)).expect("open pcapng");
        assert_eq!(source.metadata().link_type, 1);
        assert_eq!(count_sequential(&source), 200, "pcapng {name}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s3_compressed_objects_read_sequentially() {
    use std::io::Write;
    let Some(ep) = endpoint() else {
        eprintln!("skipping cloud test: PCAPSQL_S3_TEST_ENDPOINT not set");
        return;
    };
    let raw = small_capture(LegacyVariant::LeMicro);

    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&raw).unwrap();
    let gz = gz.finish().unwrap();
    let zst = zstd::encode_all(&raw[..], 3).unwrap();

    for (key, bytes) in [("compressed/c.pcap.gz", gz), ("compressed/c.pcap.zst", zst)] {
        upload(&ep, key, bytes).await;
        let source = CloudPacketSource::open(location(&ep, key)).expect("open compressed");
        assert_eq!(source.metadata().link_type, 1, "{key}");
        assert_eq!(count_sequential(&source), 200, "{key}");
        // Compressed objects are not partitionable: one whole-range partition.
        assert_eq!(source.partitions(4).expect("partitions").len(), 1, "{key}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s3_small_chunk_size_crosses_chunk_boundaries() {
    let Some(ep) = endpoint() else {
        eprintln!("skipping cloud test: PCAPSQL_S3_TEST_ENDPOINT not set");
        return;
    };
    let key = "chunks/small_chunks.pcap";
    upload(&ep, key, small_capture(LegacyVariant::LeMicro)).await;
    let source = CloudPacketSource::open(location(&ep, key).with_chunk_size(1024)).expect("open");
    assert_eq!(count_sequential(&source), 200);
}

/// The boundary index of a remote object is cached locally: a second source
/// over the same (unchanged) object partitions without re-downloading it, and
/// each partition reader fetches only its own byte range.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s3_index_is_cached_and_partitions_fetch_only_their_range() {
    let Some(ep) = endpoint() else {
        eprintln!("skipping cloud test: PCAPSQL_S3_TEST_ENDPOINT not set");
        return;
    };
    let cache = tempfile::TempDir::new().expect("tempdir");
    // Process-wide, but the cloud tests are the only readers of it.
    std::env::set_var("PCAPSQL_INDEX_CACHE", cache.path());

    let key = "cache/indexed.pcap";
    let total = 20_000u64;
    let bytes = big_capture(total as usize, 1000);
    let size = bytes.len() as u64;
    upload(&ep, key, bytes).await;

    let first = CloudPacketSource::open(location(&ep, key))
        .expect("open")
        .with_index_stride(2048);
    let ranges = first.partitions(4).expect("partitions");
    assert!(ranges.len() > 1);
    // Building the index read the whole object once.
    assert!(
        first.bytes_fetched() >= size,
        "index build must read the object"
    );
    assert!(
        std::fs::read_dir(cache.path()).unwrap().count() == 1,
        "one cached index file expected"
    );

    // A fresh source over the same object: the cached index is reused.
    let second = CloudPacketSource::open(location(&ep, key))
        .expect("open")
        .with_index_stride(2048);
    let ranges2 = second.partitions(4).expect("partitions");
    assert_eq!(ranges2, ranges);
    assert!(
        second.bytes_fetched() < 128 * 1024,
        "partitioning with a cached index must not download the object (fetched {} bytes)",
        second.bytes_fetched()
    );

    // Reading every partition fetches the object about once in total, not once
    // per partition plus an 8 MiB over-fetch each.
    let mut all = Vec::new();
    for r in &ranges2 {
        let mut reader = second.reader_at(r).expect("reader_at");
        all.extend(drain(&mut reader));
    }
    assert_eq!(all, (1..=total).collect::<Vec<_>>());
    let fetched = second.bytes_fetched();
    assert!(
        fetched < size + 2 * 1024 * 1024,
        "partition readers over-fetched: {fetched} bytes for a {size}-byte object"
    );

    // A changed object (different size) invalidates the cached index.
    upload(&ep, key, big_capture(total as usize + 1, 1000)).await;
    let third = CloudPacketSource::open(location(&ep, key))
        .expect("open")
        .with_index_stride(2048);
    let ranges3 = third.partitions(4).expect("partitions");
    assert_ne!(ranges3, ranges2);
    assert!(
        third.bytes_fetched() >= size,
        "stale cache must trigger a rebuild"
    );
}
