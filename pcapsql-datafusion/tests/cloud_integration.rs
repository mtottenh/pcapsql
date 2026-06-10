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
use pcapsql_datafusion::query::{CloudSourceOptions, EngineOptions, QueryEngine, SourceSpec};
use pcapsql_testgen::{legacy_pcap, GenPacket, LegacyVariant};

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

async fn run(engine: &QueryEngine, sql: &str) -> String {
    let batches = engine.query(sql).await.expect("query ok");
    arrow::util::pretty::pretty_format_batches(&batches)
        .expect("format")
        .to_string()
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
        "object must exceed the RangeRequest gate"
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

/// Engine-level: a SQL query returns identical results whether the cloud object
/// is parsed in 1 partition or N, and the shared pass runs exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s3_partition_equivalence_engine_level() {
    let Some(ep) = endpoint() else {
        eprintln!("skipping cloud test: PCAPSQL_S3_TEST_ENDPOINT not set");
        return;
    };

    let key = "equiv/engine_level.pcap";
    upload(&ep, key, big_capture(20_000, 1000)).await;

    let mk = |partitions: usize| {
        QueryEngine::open(
            SourceSpec::Url(format!("s3://{}/{}", bucket(), key)),
            EngineOptions {
                batch_size: 4096,
                target_partitions: Some(partitions),
                index_stride: Some(2048),
                cloud: CloudSourceOptions {
                    endpoint: Some(ep.clone()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
    };

    let e1 = mk(1).await.expect("engine n=1");
    let e4 = mk(4).await.expect("engine n=4");

    assert_eq!(e1.partition_count(), 1);
    assert!(
        e4.partition_count() > 1,
        "cloud object should be parsed in multiple partitions, got {}",
        e4.partition_count()
    );

    // One parse pass for a multi-table query.
    let _ = run(
        &e4,
        "SELECT f.frame_number, u.dst_port FROM frames f JOIN udp u USING (frame_number)",
    )
    .await;
    assert_eq!(e4.parse_pass_count(), 1);

    for sql in [
        "SELECT count(*) AS c FROM frames",
        "SELECT count(*) AS c FROM udp",
        "SELECT count(*) AS c FROM ipv4",
        "SELECT frame_number, length FROM frames ORDER BY frame_number LIMIT 500",
        "SELECT frame_number, dst_port FROM udp ORDER BY frame_number LIMIT 500",
    ] {
        let r1 = run(&e1, sql).await;
        let r4 = run(&e4, sql).await;
        assert_eq!(r1, r4, "cloud 1-vs-N mismatch for: {sql}");
    }
}

/// A small object is served single-partition (the cost gate avoids firing many
/// range GETs at a tiny object), and still queries correctly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s3_small_object_single_partition() {
    let Some(ep) = endpoint() else {
        eprintln!("skipping cloud test: PCAPSQL_S3_TEST_ENDPOINT not set");
        return;
    };

    let key = "small/tiny.pcap";
    upload(&ep, key, big_capture(50, 20)).await;

    let engine = QueryEngine::open(
        SourceSpec::Url(format!("s3://{}/{}", bucket(), key)),
        EngineOptions {
            batch_size: 1000,
            target_partitions: Some(4),
            cloud: CloudSourceOptions {
                endpoint: Some(ep.clone()),
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await
    .expect("engine");

    // Below the RangeRequest size gate -> single partition.
    assert_eq!(engine.partition_count(), 1);
    let frames = run(&engine, "SELECT count(*) AS c FROM frames").await;
    assert!(frames.contains("50"), "expected 50 frames:\n{frames}");
}
