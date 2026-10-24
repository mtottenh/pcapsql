//! Standard input as a capture source (`SourceSpec::Sequential`, what the
//! CLI's `--stdin` builds): one sequential parse pass over a stream that can
//! be read exactly once, and clear errors for everything that would need a
//! second one.

use std::io::{Cursor, Read, Write};

use arrow::array::{Array, Int64Array, RecordBatch};
use arrow::util::pretty::pretty_format_batches;
use pcapsql_core::{PacketSource, StdinPacketSource};
use pcapsql_datafusion::query::{
    EngineOptions, QueryEngine, RetentionPolicy, ServedFrom, SourceSpec,
};
use pcapsql_datafusion::Error;
use pcapsql_testgen::{
    legacy_pcap, pcapng, GenPacket, LegacyVariant, PcapngInterface, PcapngPacket, PcapngSection,
};

const N: usize = 60;

/// IPv4/UDP payload-bearing packet body (everything after the link layer).
fn ipv4_udp(src_port: u16, dst_port: u16, payload_len: usize) -> Vec<u8> {
    let mut p = Vec::new();
    let ip_total = (20 + 8 + payload_len) as u16;
    p.push(0x45); // version 4, IHL 5
    p.push(0x00); // DSCP/ECN
    p.extend_from_slice(&ip_total.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]); // id
    p.extend_from_slice(&[0x40, 0x00]); // flags DF
    p.push(64); // ttl
    p.push(17); // protocol UDP
    p.extend_from_slice(&[0x00, 0x00]); // header checksum (0 = unchecked)
    p.extend_from_slice(&[192, 168, 0, 1]); // src ip
    p.extend_from_slice(&[192, 168, 0, 2]); // dst ip
    let udp_len = (8 + payload_len) as u16;
    p.extend_from_slice(&src_port.to_be_bytes());
    p.extend_from_slice(&dst_port.to_be_bytes());
    p.extend_from_slice(&udp_len.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]); // checksum 0
    p.extend(std::iter::repeat_n(0xAB, payload_len));
    p
}

/// Ethernet/IPv4/UDP frame.
fn udp_packet(src_port: u16, dst_port: u16, payload_len: usize) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // dst mac
    p.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src mac
    p.extend_from_slice(&[0x08, 0x00]); // ethertype IPv4
    p.extend(ipv4_udp(src_port, dst_port, payload_len));
    p
}

/// Linux cooked (SLL, link type 113) IPv4/UDP frame, as `tcpdump -i any`
/// with an older libpcap or `dumpcap -i any` produce.
fn sll_udp_packet(src_port: u16, dst_port: u16, payload_len: usize) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&0u16.to_be_bytes()); // packet type: to us
    p.extend_from_slice(&1u16.to_be_bytes()); // ARPHRD_ETHER
    p.extend_from_slice(&6u16.to_be_bytes()); // address length
    p.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00]); // address (8 bytes)
    p.extend_from_slice(&0x0800u16.to_be_bytes()); // protocol IPv4
    p.extend(ipv4_udp(src_port, dst_port, payload_len));
    p
}

/// A legacy pcap (Ethernet) with `n` UDP packets.
fn ethernet_capture(n: usize) -> Vec<u8> {
    let packets: Vec<GenPacket> = (0..n)
        .map(|i| {
            let data = udp_packet(10_000 + i as u16, 53, i % 7);
            let origlen = data.len() as u32;
            GenPacket {
                ts_sec: 1_700_000_000 + i as u32,
                ts_frac: (i as u32 * 137) % 1_000_000,
                data,
                origlen,
            }
        })
        .collect();
    legacy_pcap(LegacyVariant::LeMicro, 1, 65535, &packets).bytes
}

/// A pcapng whose one interface is Linux SLL (113), with `n` UDP packets.
fn sll_pcapng_capture(n: usize) -> Vec<u8> {
    let packets = (0..n)
        .map(|i| {
            let data = sll_udp_packet(20_000 + i as u16, 53, i % 5);
            let origlen = data.len() as u32;
            PcapngPacket {
                interface_id: 0,
                ts_sec: 1_700_000_000 + i as u64,
                ts_frac_units: (i as u64 * 11) % 1_000_000,
                data,
                origlen,
            }
        })
        .collect();
    pcapng(&[PcapngSection {
        interfaces: vec![PcapngInterface {
            link_type: 113,
            tsresol: 6,
            snaplen: 262_144,
            if_tsoffset: 0,
        }],
        packets,
    }])
    .bytes
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    enc.write_all(bytes).unwrap();
    enc.finish().unwrap()
}

/// An engine over `reader` as a single-use stream.
async fn open_stream<R: Read + Send + 'static>(
    reader: R,
    opts: EngineOptions,
) -> Result<QueryEngine, Error> {
    let source = StdinPacketSource::from_reader(reader).expect("probe the stream head");
    QueryEngine::open(SourceSpec::Sequential(source), opts).await
}

fn one_shot_opts() -> EngineOptions {
    EngineOptions {
        batch_size: 16, // several batches per pass
        retention: RetentionPolicy::None,
        ..Default::default()
    }
}

async fn open(bytes: Vec<u8>) -> QueryEngine {
    open_stream(Cursor::new(bytes), one_shot_opts())
        .await
        .expect("open a stdin engine")
}

fn first_i64(batches: &[RecordBatch]) -> i64 {
    let batch = batches.iter().find(|b| b.num_rows() > 0).expect("a row");
    batch
        .column(0)
        .as_any()
        .downcast_ref::<Int64Array>()
        .expect("int64 column")
        .value(0)
}

fn pretty(batches: &[RecordBatch]) -> String {
    pretty_format_batches(batches).expect("format").to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_query_is_one_sequential_pass_and_no_fast_path() {
    let engine = open(ethernet_capture(N)).await;
    let out = engine
        .execute("SELECT count(*) FROM frames")
        .await
        .expect("count");
    assert_eq!(first_i64(&out.batches), N as i64);
    // No boundary index on a stream: the count is parsed, not read from an
    // index, and the pass is one partition.
    assert_eq!(out.stats.served_from, ServedFrom::Parse, "{:?}", out.stats);
    assert_eq!(out.stats.parse_passes, 1);
    assert_eq!(out.stats.partitions, 1);
    assert_eq!(out.stats.packets_scanned, N as u64);
    assert!(out.stats.complete_scan);
    assert_eq!(out.stats.rows_built.get("frames"), Some(&N));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rows_come_back_in_capture_order_and_limit_stops_early() {
    let engine = open(ethernet_capture(N)).await;
    let out = engine
        .execute("SELECT frame_number, length FROM frames LIMIT 5")
        .await
        .expect("limit");
    let frames: Vec<u64> = out
        .batches
        .iter()
        .flat_map(|b| {
            let col = b
                .column(0)
                .as_any()
                .downcast_ref::<arrow::array::UInt64Array>()
                .expect("u64");
            (0..b.num_rows()).map(move |i| col.value(i))
        })
        .collect();
    assert_eq!(frames, vec![1, 2, 3, 4, 5]);
    assert_eq!(out.stats.parse_passes, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_table_join_shares_the_one_pass() {
    let engine = open(ethernet_capture(N)).await;
    let out = engine
        .execute(
            "SELECT count(*) FROM frames f \
             JOIN udp u USING (frame_number) \
             JOIN ipv4 v USING (frame_number) \
             WHERE u.dst_port = 53",
        )
        .await
        .expect("join");
    assert_eq!(first_i64(&out.batches), N as i64);
    assert_eq!(out.stats.parse_passes, 1, "{:?}", out.stats);
    assert_eq!(out.stats.partitions, 1);
    // The joins are fused into one table of the pass (one row per frame
    // here), built from the udp and ipv4 layers; neither is a table of its
    // own in this pass.
    let fused: Vec<(&String, &usize)> = out
        .stats
        .rows_built
        .iter()
        .filter(|(name, _)| name.starts_with("fused_frames_udp_ipv4_"))
        .collect();
    assert_eq!(fused.len(), 1, "{:?}", out.stats.rows_built);
    assert_eq!(*fused[0].1, N);
    assert!(
        !out.stats.rows_built.contains_key("udp"),
        "{:?}",
        out.stats.rows_built
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_table_query_shares_the_one_pass() {
    let engine = open(ethernet_capture(N)).await;
    // A stream-analysis table pins the pass to the materialize path; the
    // packet table in the same query is built by the same pass.
    let out = engine
        .execute(
            "SELECT (SELECT count(*) FROM udp) AS udp_rows, \
                    (SELECT count(*) FROM tcp_connections) AS connections",
        )
        .await
        .expect("stream table query");
    let batch = out
        .batches
        .iter()
        .find(|b| b.num_rows() > 0)
        .expect("a row");
    let col = |i: usize| {
        batch
            .column(i)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("int64")
            .value(0)
    };
    assert_eq!(col(0), N as i64);
    assert_eq!(col(1), 0, "a UDP-only capture has no TCP connections");
    assert_eq!(out.stats.parse_passes, 1, "{:?}", out.stats);
    assert_eq!(out.stats.partitions, 1);
    assert_eq!(out.stats.stream_tables, vec!["tcp_connections".to_string()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explain_consumes_nothing() {
    let engine = open(ethernet_capture(N)).await;
    for sql in [
        "EXPLAIN SELECT * FROM frames",
        "EXPLAIN SELECT f.frame_number, u.dst_port FROM frames f JOIN udp u USING (frame_number)",
        "EXPLAIN SELECT count(*) FROM tcp_connections",
    ] {
        let out = engine.execute(sql).await.expect(sql);
        assert_eq!(out.stats.served_from, ServedFrom::PlanOnly, "{sql}");
        assert_eq!(out.stats.parse_passes, 0, "{sql}");
        assert!(pretty(&out.batches).contains("ProtocolScanExec"), "{sql}");
    }
    // The stream is intact: the real query still gets every packet.
    let out = engine
        .execute("SELECT count(*) FROM udp")
        .await
        .expect("query after explain");
    assert_eq!(first_i64(&out.batches), N as i64);
    assert_eq!(out.stats.parse_passes, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_query_over_the_capture_is_a_clear_error() {
    let engine = open(ethernet_capture(N)).await;
    let out = engine
        .execute("SELECT count(*) FROM frames")
        .await
        .expect("first query");
    assert_eq!(first_i64(&out.batches), N as i64);

    let err = engine
        .execute("SELECT count(*) FROM udp")
        .await
        .expect_err("second query must fail");
    assert!(
        err.to_string().contains("stdin was already consumed"),
        "{err}"
    );
    // Statements that parse nothing still work.
    let out = engine
        .execute("SELECT 1 AS one")
        .await
        .expect("no-scan query");
    assert_eq!(first_i64(&out.batches), 1);
    let out = engine
        .execute("EXPLAIN SELECT count(*) FROM frames")
        .await
        .expect("explain after the pass");
    assert_eq!(out.stats.served_from, ServedFrom::PlanOnly);
    // And the error is stable, not a hang.
    let err = engine
        .execute("SELECT count(*) FROM frames")
        .await
        .expect_err("third query must fail");
    assert!(err.to_string().contains("stdin was already consumed"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn time_range_udfs_are_rejected_without_consuming_the_stream() {
    let engine = open(ethernet_capture(N)).await;
    for sql in [
        "SELECT start_time() AS t0",
        "SELECT end_time() AS t1",
        "SELECT relative_time(timestamp) FROM frames",
        "EXPLAIN SELECT start_time() AS t0, relative_time(timestamp) FROM frames",
    ] {
        let err = engine.execute(sql).await.expect_err(sql);
        assert!(
            err.to_string().contains("not available on stdin"),
            "{sql}: {err}"
        );
    }
    // Rejected before any read: the one pass is still available.
    let out = engine
        .execute("SELECT min(timestamp) AS t0, max(timestamp) AS t1, count(*) FROM frames")
        .await
        .expect("query after rejected time UDF");
    assert_eq!(out.stats.parse_passes, 1);
    assert_eq!(out.stats.packets_scanned, N as u64);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn time_range_udfs_answer_from_the_completed_pass() {
    use arrow::array::TimestampMicrosecondArray;
    let engine = open(ethernet_capture(N)).await;
    let out = engine
        .execute("SELECT min(timestamp), max(timestamp) FROM frames")
        .await
        .expect("the one pass");
    assert_eq!(out.stats.parse_passes, 1);
    assert!(out.stats.complete_scan);
    let ts = |batches: &[RecordBatch], i: usize| {
        batches
            .iter()
            .find(|b| b.num_rows() > 0)
            .expect("a row")
            .column(i)
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .expect("timestamp(us)")
            .value(0)
    };
    let (t0, t1) = (ts(&out.batches, 0), ts(&out.batches, 1));

    // The pass read the whole stream, so the range is known: no second
    // pass is needed and none is attempted.
    let out = engine
        .execute("SELECT start_time() AS t0, end_time() AS t1")
        .await
        .expect("time UDFs after a complete pass");
    assert_eq!(out.stats.parse_passes, 0, "{:?}", out.stats);
    assert_eq!(out.stats.packets_scanned, 0);
    assert_eq!(ts(&out.batches, 0), t0);
    assert_eq!(ts(&out.batches, 1), t1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cache_on_touch_is_rejected_at_open() {
    let err = open_stream(
        Cursor::new(ethernet_capture(4)),
        EngineOptions {
            retention: RetentionPolicy::CacheOnTouch,
            ..Default::default()
        },
    )
    .await
    .err()
    .expect("CacheOnTouch must be rejected");
    assert!(err.to_string().contains("CacheOnTouch"), "{err}");

    // The default options ask for CacheOnTouch too.
    let err = open_stream(Cursor::new(ethernet_capture(4)), EngineOptions::default())
        .await
        .err()
        .expect("default options must be rejected");
    assert!(err.to_string().contains("RetentionPolicy::None"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn target_partitions_is_forced_to_one() {
    let engine = open_stream(
        Cursor::new(ethernet_capture(N)),
        EngineOptions {
            target_partitions: Some(4),
            ..one_shot_opts()
        },
    )
    .await
    .expect("open");
    let out = engine
        .execute("SELECT count(*) FROM udp")
        .await
        .expect("count");
    assert_eq!(first_i64(&out.batches), N as i64);
    assert_eq!(out.stats.partitions, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pcapng_with_sll_link_type_parses_linux_sll_rows() {
    let engine = open(sll_pcapng_capture(N)).await;
    let out = engine
        .execute(
            "SELECT count(*), min(s.arphrd_name), count(u.frame_number) \
             FROM linux_sll s JOIN udp u USING (frame_number)",
        )
        .await
        .expect("sll query");
    let batch = out
        .batches
        .iter()
        .find(|b| b.num_rows() > 0)
        .expect("a row");
    assert_eq!(
        batch
            .column(0)
            .as_any()
            .downcast_ref::<Int64Array>()
            .unwrap()
            .value(0),
        N as i64,
        "every packet is a linux_sll row (A9: the pcapng link type reaches the parser)"
    );
    let names = batch
        .column(1)
        .as_any()
        .downcast_ref::<arrow::array::StringArray>()
        .expect("utf8");
    assert_eq!(names.value(0), "ETHER");
    assert_eq!(
        batch
            .column(2)
            .as_any()
            .downcast_ref::<Int64Array>()
            .unwrap()
            .value(0),
        N as i64,
        "the UDP layer under the SLL header is parsed too"
    );
    assert_eq!(out.stats.parse_passes, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gzip_compressed_stream_is_decompressed_on_the_fly() {
    let engine = open(gzip(&ethernet_capture(N))).await;
    let out = engine
        .execute("SELECT count(*) FROM udp WHERE dst_port = 53")
        .await
        .expect("gzip count");
    assert_eq!(first_i64(&out.batches), N as i64);
    assert_eq!(out.stats.parse_passes, 1);
    assert_eq!(out.stats.partitions, 1);
}

/// A real pipe: the producer writes the capture in small chunks from another
/// thread, so the probe and the reader see short reads and block for data,
/// and end of input arrives when the writer closes its end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pipe_fed_in_chunks_is_read_to_eof() {
    let bytes = ethernet_capture(N);
    let (reader, mut writer) = std::io::pipe().expect("pipe");
    let producer = std::thread::spawn(move || {
        for chunk in bytes.chunks(7) {
            writer.write_all(chunk).expect("write chunk");
            std::thread::sleep(std::time::Duration::from_micros(200));
        }
        // Dropping the writer is end of input.
    });

    // `from_reader` blocks on the header; run it off the runtime.
    let source = tokio::task::spawn_blocking(move || {
        StdinPacketSource::from_reader(reader).expect("probe the pipe")
    })
    .await
    .expect("join");
    assert_eq!(source.metadata().link_type, 1);
    let engine = QueryEngine::open(SourceSpec::Sequential(source), one_shot_opts())
        .await
        .expect("open");

    let out = engine
        .execute(
            "SELECT count(*), min(frame_number), max(frame_number) FROM frames f \
             JOIN udp u USING (frame_number)",
        )
        .await
        .expect("query over the pipe");
    let batch = out
        .batches
        .iter()
        .find(|b| b.num_rows() > 0)
        .expect("a row");
    let int = |i: usize| {
        batch
            .column(i)
            .as_any()
            .downcast_ref::<Int64Array>()
            .unwrap()
            .value(0)
    };
    assert_eq!(int(0), N as i64);
    let u64_at = |i: usize| {
        batch
            .column(i)
            .as_any()
            .downcast_ref::<arrow::array::UInt64Array>()
            .unwrap()
            .value(0)
    };
    assert_eq!(u64_at(1), 1);
    assert_eq!(u64_at(2), N as u64);
    assert_eq!(out.stats.packets_scanned, N as u64);
    assert!(out.stats.complete_scan);
    producer.join().expect("producer thread");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn truncated_stream_yields_the_complete_prefix() {
    let bytes = ethernet_capture(N);
    let cut = bytes.len() - 9; // inside the last record
    let engine = open(bytes[..cut].to_vec()).await;
    let out = engine
        .execute("SELECT count(*) FROM frames")
        .await
        .expect("truncated capture still answers");
    assert_eq!(first_i64(&out.batches), (N - 1) as i64);
}

#[test]
fn source_metadata_has_no_size_or_count() {
    let source = StdinPacketSource::from_reader(Cursor::new(ethernet_capture(3))).unwrap();
    let meta = source.metadata();
    assert_eq!(meta.link_type, 1);
    assert!(meta.size_bytes.is_none());
    assert!(meta.packet_count.is_none());
    // `pcapsql_core::PacketSource` is the only source trait it implements:
    // the type system, not a flag, says "not seekable".
    fn is_packet_source<S: PacketSource>(_: &S) {}
    is_packet_source(&source);
}
