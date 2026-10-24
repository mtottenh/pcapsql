//! Continuous queries over a live stream (`EngineOptions::continuous`).
//!
//! A pipe plays the live capture: the test writes a legacy pcap header and
//! then appends packet records whenever it wants, so the engine sees an
//! unbounded source that delivers packets in its own time. The windowed
//! aggregate's output is read from `QueryEngine::execute_stream`.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use arrow::array::{Array, Int64Array, RecordBatch, TimestampMicrosecondArray, UInt64Array};
use arrow::util::pretty::pretty_format_batches;
use futures::StreamExt;
use pcapsql_core::StdinPacketSource;
use pcapsql_datafusion::query::{
    EngineOptions, QueryEngine, QueryStream, RetentionPolicy, SourceSpec,
};
use pcapsql_testgen::{legacy_pcap, GenPacket, LegacyVariant};

/// Capture start, aligned to 10 s.
const T0: u32 = 1_700_000_000;
/// Legacy pcap global header length.
const HEADER_LEN: usize = 24;

fn udp_packet(src_port: u16, payload_len: usize) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&[0xff; 6]);
    p.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    p.extend_from_slice(&[0x08, 0x00]);
    let ip_total = (20 + 8 + payload_len) as u16;
    p.push(0x45);
    p.push(0x00);
    p.extend_from_slice(&ip_total.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend_from_slice(&[0x40, 0x00]);
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

/// One packet record (no header) at `T0 + secs` with the given fraction.
fn record(secs: u32, micros: u32, src_port: u16, payload_len: usize) -> Vec<u8> {
    let data = udp_packet(src_port, payload_len);
    let origlen = data.len() as u32;
    let capture = legacy_pcap(
        LegacyVariant::LeMicro,
        1,
        65535,
        &[GenPacket {
            ts_sec: T0 + secs,
            ts_frac: micros,
            data,
            origlen,
        }],
    );
    capture.bytes[HEADER_LEN..].to_vec()
}

fn header() -> Vec<u8> {
    legacy_pcap(LegacyVariant::LeMicro, 1, 65535, &[]).bytes
}

/// The writing end of the live capture.
struct Feed {
    writer: Option<std::io::PipeWriter>,
}

impl Feed {
    fn send(&mut self, records: &[Vec<u8>]) {
        let w = self.writer.as_mut().expect("feed open");
        for r in records {
            w.write_all(r).expect("write record");
        }
        w.flush().expect("flush");
    }

    /// End of input.
    fn close(&mut self) {
        self.writer = None;
    }
}

struct Live {
    engine: QueryEngine,
    feed: Feed,
}

/// Open a continuous engine over a fresh pipe with the given options.
async fn live(configure: impl FnOnce(&mut EngineOptions)) -> Live {
    let (reader, mut writer) = std::io::pipe().expect("pipe");
    writer.write_all(&header()).expect("header");
    writer.flush().unwrap();
    let source = tokio::task::spawn_blocking(move || {
        StdinPacketSource::from_reader(reader).expect("probe the pipe")
    })
    .await
    .expect("join");
    let mut opts = EngineOptions {
        batch_size: 1000,
        retention: RetentionPolicy::None,
        continuous: true,
        allowed_lateness: Duration::from_secs(1),
        // Every packet is handed on at once, so the tests do not depend on
        // timing; the cadence test sets a real interval.
        flush_interval: Duration::ZERO,
        idle_timeout: None,
        ..Default::default()
    };
    configure(&mut opts);
    let engine = QueryEngine::open(SourceSpec::Sequential(source), opts)
        .await
        .expect("open continuous engine");
    Live {
        engine,
        feed: Feed {
            writer: Some(writer),
        },
    }
}

/// The next batch within `wait`, or `None`.
async fn next_within(stream: &mut QueryStream, wait: Duration) -> Option<RecordBatch> {
    match tokio::time::timeout(wait, stream.next()).await {
        Ok(Some(Ok(batch))) => Some(batch),
        Ok(Some(Err(e))) => panic!("stream error: {e}"),
        Ok(None) => None,
        Err(_) => None,
    }
}

/// Expect a batch within the test's patience.
async fn expect_batch(stream: &mut QueryStream, what: &str) -> RecordBatch {
    next_within(stream, Duration::from_secs(10))
        .await
        .unwrap_or_else(|| panic!("no batch within 10 s: {what}"))
}

/// Expect no batch for a while (the window must still be open).
async fn expect_quiet(stream: &mut QueryStream, what: &str) {
    if let Some(batch) = next_within(stream, Duration::from_millis(300)).await {
        panic!(
            "unexpected batch ({what}):\n{}",
            pretty_format_batches(&[batch]).unwrap()
        );
    }
}

fn pretty(batches: &[RecordBatch]) -> String {
    pretty_format_batches(batches).unwrap().to_string()
}

fn window_start_secs(batch: &RecordBatch, column: usize) -> Vec<i64> {
    batch
        .column(column)
        .as_any()
        .downcast_ref::<TimestampMicrosecondArray>()
        .unwrap()
        .values()
        .iter()
        .map(|us| us / 1_000_000 - i64::from(T0))
        .collect()
}

fn i64_column(batch: &RecordBatch, column: usize) -> Vec<i64> {
    batch
        .column(column)
        .as_any()
        .downcast_ref::<Int64Array>()
        .unwrap()
        .values()
        .to_vec()
}

fn u64_column(batch: &RecordBatch, column: usize) -> Vec<u64> {
    batch
        .column(column)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .unwrap()
        .values()
        .to_vec()
}

const TUMBLE_10S: &str = "tumble(frames, INTERVAL '10' SECOND)";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tumble_groups_and_aggregates_emit_per_closed_window() {
    let Live { engine, mut feed } = live(|_| {}).await;
    // Two aggregates and a non-window group column (A1/A2): per 10 s window
    // and frame length, count and total bytes.
    let mut stream = engine
        .execute_stream(&format!(
            "SELECT window_start, length, count(*) AS n, sum(length) AS bytes \
             FROM {TUMBLE_10S} GROUP BY 1, 2"
        ))
        .await
        .expect("plan");
    // Window [0, 10): three packets of two lengths, out of order within the
    // window (the 1 s packet after the 7 s one is behind the stream but its
    // window is open: counted).
    feed.send(&[
        record(2, 0, 1000, 10),
        record(7, 0, 2000, 20),
        record(1, 0, 1000, 10),
    ]);
    expect_quiet(&mut stream, "window [0, 10) is still open").await;
    // 12 s: watermark 11 s ≥ 10 s closes the first window.
    feed.send(&[record(12, 0, 1000, 10)]);
    let batch = expect_batch(&mut stream, "window [0, 10)").await;
    let expected = "\
+---------------------+--------+---+-------+
| window_start        | length | n | bytes |
+---------------------+--------+---+-------+
| 2023-11-14T22:13:20 | 52     | 2 | 104   |
| 2023-11-14T22:13:20 | 62     | 1 | 62    |
+---------------------+--------+---+-------+";
    assert_eq!(pretty(&[batch]), expected);
    expect_quiet(&mut stream, "window [10, 20) is still open").await;
    // End of input closes the rest.
    feed.close();
    let batch = expect_batch(&mut stream, "window [10, 20) at end of input").await;
    assert_eq!(window_start_secs(&batch, 0), vec![10]);
    assert_eq!(i64_column(&batch, 2), vec![1]);
    assert!(next_within(&mut stream, Duration::from_secs(5))
        .await
        .is_none());
    let stats = stream.finish().await.expect("stats");
    assert_eq!(stats.packets_scanned, 4);
    assert_eq!(stats.late_rows, 0);
    assert_eq!(stats.parse_passes, 1);
    assert_eq!(engine.last_parse_stats().packets_scanned, 4);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_rows_are_counted_only_once_their_window_closed() {
    let Live { engine, mut feed } = live(|o| o.allowed_lateness = Duration::from_millis(500)).await;
    let mut stream = engine
        .execute_stream(&format!(
            "SELECT window_start, count(*) AS n FROM {TUMBLE_10S} GROUP BY 1"
        ))
        .await
        .expect("plan");
    // 9.0 s, then 9.9 s, then 9.2 s: the last is 700 ms behind the stream,
    // more than the lateness, but its window [0, 10) is still open (watermark
    // 9.4 s) — counted (A7).
    feed.send(&[record(9, 0, 1000, 10), record(9, 900_000, 1000, 10)]);
    feed.send(&[record(9, 200_000, 1000, 10)]);
    expect_quiet(&mut stream, "[0, 10) open").await;
    // 10.6 s: watermark 10.1 s closes [0, 10) with its 3 rows.
    feed.send(&[record(10, 600_000, 1000, 10)]);
    let batch = expect_batch(&mut stream, "[0, 10)").await;
    assert_eq!(window_start_secs(&batch, 0), vec![0]);
    assert_eq!(i64_column(&batch, 1), vec![3]);
    // 9.5 s now: its window has been emitted → dropped and counted.
    feed.send(&[record(9, 500_000, 1000, 10)]);
    // Make the drop observable: close [10, 20) with a 21 s packet.
    feed.send(&[record(21, 0, 1000, 10)]);
    let batch = expect_batch(&mut stream, "[10, 20)").await;
    assert_eq!(window_start_secs(&batch, 0), vec![10]);
    assert_eq!(
        i64_column(&batch, 1),
        vec![1],
        "the late 9.5 s row is not in [10, 20)"
    );
    assert_eq!(stream.late_rows(), 1);
    feed.close();
    let batch = expect_batch(&mut stream, "[20, 30) at end").await;
    assert_eq!(i64_column(&batch, 1), vec![1]);
    let stats = stream.finish().await.expect("stats");
    assert_eq!(stats.late_rows, 1);
    assert_eq!(stats.packets_scanned, 6);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn where_on_a_source_column_and_filter_clause() {
    let Live { engine, mut feed } = live(|_| {}).await;
    // The WHERE is pushed below the window projection (still fused); FILTER
    // is honoured per aggregate (A12).
    let mut stream = engine
        .execute_stream(&format!(
            "SELECT window_start, count(*) AS n, \
             count(*) FILTER (WHERE length > 60) AS big, sum(length) AS bytes \
             FROM {TUMBLE_10S} WHERE length < 90 GROUP BY 1"
        ))
        .await
        .expect("plan");
    let plan = format!(
        "{}",
        datafusion::physical_plan::displayable(stream.plan().unwrap().as_ref()).indent(false)
    );
    assert!(plan.contains("StreamingWindowAggregateExec"), "{plan}");
    assert!(plan.contains("FilterExec"), "{plan}");
    // lengths: 42+10=52, 42+20=62, 42+50=92 (filtered out by WHERE), 42+30=72
    feed.send(&[
        record(1, 0, 1000, 10),
        record(2, 0, 1000, 20),
        record(3, 0, 1000, 50),
        record(4, 0, 1000, 30),
        record(15, 0, 1000, 10),
    ]);
    let batch = expect_batch(&mut stream, "[0, 10)").await;
    let expected = "\
+---------------------+---+-----+-------+
| window_start        | n | big | bytes |
+---------------------+---+-----+-------+
| 2023-11-14T22:13:20 | 3 | 2   | 186   |
+---------------------+---+-----+-------+";
    assert_eq!(pretty(&[batch]), expected);
    feed.close();
    let _ = expect_batch(&mut stream, "[10, 20)").await;
    stream.finish().await.expect("stats");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hop_windows_close_in_order() {
    let Live { engine, mut feed } = live(|_| {}).await;
    let mut stream = engine
        .execute_stream(
            "SELECT window_start, window_end, count(*) AS n \
             FROM hop(frames, INTERVAL '5' SECOND, INTERVAL '10' SECOND) GROUP BY 1, 2",
        )
        .await
        .expect("plan");
    // t = 7 s is in [0, 10) and [5, 15); t = 12 s in [5, 15) and [10, 20).
    feed.send(&[record(7, 0, 1000, 10), record(12, 0, 1000, 10)]);
    // 16.5 s: watermark 15.5 s closes [0, 10) and [5, 15), oldest first.
    feed.send(&[record(16, 500_000, 1000, 10)]);
    let first = expect_batch(&mut stream, "[0, 10)").await;
    assert_eq!(window_start_secs(&first, 0), vec![0]);
    assert_eq!(window_start_secs(&first, 1), vec![10]);
    assert_eq!(i64_column(&first, 2), vec![1]);
    let second = expect_batch(&mut stream, "[5, 15)").await;
    assert_eq!(window_start_secs(&second, 0), vec![5]);
    assert_eq!(i64_column(&second, 2), vec![2]);
    expect_quiet(&mut stream, "[10, 20) open").await;
    feed.close();
    let mut rest = Vec::new();
    while let Some(b) = next_within(&mut stream, Duration::from_secs(5)).await {
        rest.push(b);
    }
    let starts: Vec<i64> = rest.iter().flat_map(|b| window_start_secs(b, 0)).collect();
    assert_eq!(starts, vec![10, 15]);
    stream.finish().await.expect("stats");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn partial_batches_are_flushed_on_time_and_windows_close_on_the_next_event() {
    // batch_size 1000 and a 20 ms flush interval: a window's rows reach the
    // aggregate with the first packet that arrives after the interval, and the
    // window closes as soon as the watermark passes it — long before 1000
    // packets.
    let Live { engine, mut feed } = live(|o| {
        o.batch_size = 1000;
        o.flush_interval = Duration::from_millis(20);
    })
    .await;
    let mut stream = engine
        .execute_stream(&format!(
            "SELECT window_start, count(*) AS n FROM {TUMBLE_10S} GROUP BY 1"
        ))
        .await
        .expect("plan");
    feed.send(&[record(1, 0, 1000, 10), record(2, 0, 1000, 10)]);
    tokio::time::sleep(Duration::from_millis(100)).await;
    // The first packet of the next window both flushes the partial batch
    // (the interval has passed) and closes [0, 10).
    feed.send(&[record(11, 0, 1000, 10)]);
    let batch = expect_batch(&mut stream, "[0, 10) via time-based flush").await;
    assert_eq!(window_start_secs(&batch, 0), vec![0]);
    assert_eq!(i64_column(&batch, 1), vec![2]);
    // Without the flush this batch could only have been formed by 1000
    // packets or end of input; the feed is still open.
    feed.close();
    let _ = expect_batch(&mut stream, "[10, 20)").await;
    stream.finish().await.expect("stats");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_timeout_closes_open_windows_without_input() {
    let Live { engine, mut feed } =
        live(|o| o.idle_timeout = Some(Duration::from_millis(300))).await;
    let mut stream = engine
        .execute_stream(&format!(
            "SELECT window_start, count(*) AS n FROM {TUMBLE_10S} GROUP BY 1"
        ))
        .await
        .expect("plan");
    // Two packets whose batch is flushed by a third (interval passed); then
    // silence: the idle timeout closes [0, 10) and [10, 20).
    feed.send(&[record(1, 0, 1000, 10), record(2, 0, 1000, 10)]);
    tokio::time::sleep(Duration::from_millis(50)).await;
    feed.send(&[record(11, 0, 1000, 10)]);
    let first = expect_batch(&mut stream, "[0, 10) by watermark or idle").await;
    assert_eq!(window_start_secs(&first, 0), vec![0]);
    assert_eq!(i64_column(&first, 1), vec![2]);
    let second = expect_batch(&mut stream, "[10, 20) by idle timeout").await;
    assert_eq!(window_start_secs(&second, 0), vec![10]);
    assert_eq!(i64_column(&second, 1), vec![1]);
    // A row for the idle-closed window is late now.
    feed.send(&[record(12, 0, 1000, 10)]);
    tokio::time::sleep(Duration::from_millis(50)).await;
    feed.send(&[record(13, 0, 1000, 10)]);
    expect_quiet(&mut stream, "nothing to emit for late rows").await;
    assert_eq!(stream.late_rows(), 2);
    feed.close();
    assert!(next_within(&mut stream, Duration::from_secs(5))
        .await
        .is_none());
    let stats = stream.finish().await.expect("stats");
    assert_eq!(stats.late_rows, 2);
    assert_eq!(stats.packets_scanned, 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_stream_releases_the_producer() {
    let Live { engine, mut feed } = live(|_| {}).await;
    let stream = engine
        .execute_stream(&format!(
            "SELECT window_start, count(*) AS n FROM {TUMBLE_10S} GROUP BY 1"
        ))
        .await
        .expect("plan");
    feed.send(&[record(1, 0, 1000, 10)]);
    drop(stream);
    // The producer is blocked in read() on the pipe until the next byte; it
    // then sees its consumer gone and stops. Prove it by feeding and closing:
    // a second query must fail with "consumed" rather than hang, and the
    // engine is still usable for statements that parse nothing.
    feed.send(&[record(2, 0, 1000, 10)]);
    feed.close();
    let err = tokio::time::timeout(
        Duration::from_secs(10),
        engine.execute(&format!(
            "SELECT window_start, count(*) FROM {TUMBLE_10S} GROUP BY 1"
        )),
    )
    .await
    .expect("no hang")
    .unwrap_err()
    .to_string();
    assert!(err.contains("already consumed"), "{err}");
    let out = engine
        .execute("SELECT 1 AS one")
        .await
        .expect("scan-free query");
    assert_eq!(out.batches[0].num_rows(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn planning_errors_name_the_supported_shape() {
    let Live { engine, mut feed } = live(|_| {}).await;
    let cases: &[(&str, &[&str])] = &[
        (
            "SELECT window_start, link_type, count(*) \
             FROM session(frames, link_type, INTERVAL '5' SECOND) GROUP BY 1, 2",
            &["session()", "cannot run continuously", "tumble()"],
        ),
        (
            "SELECT count(*) FROM frames",
            &["GROUP BY window_start", "tumble() or hop()"],
        ),
        (
            &format!("SELECT count(*) FROM {TUMBLE_10S}"),
            &["GROUP BY window_start"],
        ),
        (
            &format!(
                "SELECT window_start, count(*) FROM {TUMBLE_10S} GROUP BY 1 ORDER BY 1 LIMIT 5"
            ),
            &["tumble() or hop()"],
        ),
        (
            "SELECT window_start, src_port, count(*) \
             FROM tumble(udp_packets, INTERVAL '10' SECOND) GROUP BY 1, 2",
            &["cannot join", "window `frames`"],
        ),
        (
            &format!(
                "SELECT window_start, count(*) FROM {TUMBLE_10S} t JOIN udp USING (frame_number) \
                 GROUP BY 1"
            ),
            &["cannot join"],
        ),
        (
            "SELECT count(*) FROM tcp_connections",
            &["stream tables", "tcp_connections"],
        ),
        (
            "SELECT count(*) FROM frames a JOIN frames b USING (frame_number)",
            &["scan one table twice"],
        ),
        (
            &format!(
                "SELECT window_start, array_agg(length ORDER BY length) FROM {TUMBLE_10S} GROUP BY 1"
            ),
            // An ordered aggregate needs a sort below it, so the chain does
            // not match and DataFusion's sanity check reports it.
            &["tumble() or hop()"],
        ),
    ];
    for (sql, needles) in cases {
        let err = match engine.execute_stream(sql).await {
            Ok(_) => panic!("expected a planning error: {sql}"),
            Err(e) => e.to_string(),
        };
        for needle in *needles {
            assert!(
                err.contains(needle),
                "{sql}\n  error: {err}\n  missing: {needle}"
            );
        }
    }
    // Nothing above consumed the stream: a real query still runs.
    let mut stream = engine
        .execute_stream(&format!(
            "SELECT window_start, count(*) AS n FROM {TUMBLE_10S} GROUP BY 1"
        ))
        .await
        .expect("plan");
    feed.send(&[record(1, 0, 1000, 10)]);
    feed.close();
    let batch = expect_batch(&mut stream, "[0, 10) at end").await;
    assert_eq!(i64_column(&batch, 1), vec![1]);
    stream.finish().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explain_shows_the_fused_aggregate_over_an_unbounded_scan() {
    let Live { engine, .. } = live(|o| o.idle_timeout = Some(Duration::from_secs(5))).await;
    let out = engine
        .execute(&format!(
            "EXPLAIN SELECT window_start, link_type, count(*), sum(length) \
             FROM {TUMBLE_10S} GROUP BY 1, 2"
        ))
        .await
        .expect("explain");
    let plan = pretty(&out.batches);
    assert!(
        plan.contains("StreamingWindowAggregateExec: window=TUMBLE(10s), timestamp=timestamp"),
        "{plan}"
    );
    assert!(
        plan.contains("allowed_lateness=1s, idle_timeout=5s"),
        "{plan}"
    );
    assert!(
        plan.contains("mode=plan-only, partitions=1, unbounded"),
        "{plan}"
    );
    assert!(!plan.contains("AggregateExec: mode="), "{plan}");
    assert_eq!(out.stats.parse_passes, 0);
    // hop too
    let out = engine
        .execute(
            "EXPLAIN SELECT window_start, count(*) \
             FROM hop(frames, INTERVAL '5' SECOND, INTERVAL '10' SECOND) GROUP BY 1",
        )
        .await
        .expect("explain hop");
    let plan = pretty(&out.batches);
    assert!(plan.contains("window=HOP(slide=5s, size=10s)"), "{plan}");
    assert!(plan.contains("HopAssignExec"), "{plan}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn continuous_needs_a_stream_source() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("x.pcap");
    std::fs::write(&path, header()).unwrap();
    let err = QueryEngine::open(
        SourceSpec::Path(path),
        EngineOptions {
            continuous: true,
            retention: RetentionPolicy::None,
            ..Default::default()
        },
    )
    .await
    .err()
    .expect("file source rejected")
    .to_string();
    assert!(err.contains("live stream"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn execute_stream_works_on_a_file_engine() {
    // The streaming API is not continuous-only: a file query streams its
    // batches and finish() reports its stats.
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("f.pcap");
    let mut bytes = header();
    for s in 0..5 {
        bytes.extend(record(s, 0, 1000, 10));
    }
    std::fs::write(&path, bytes).unwrap();
    let engine = QueryEngine::open(
        SourceSpec::Path(path),
        EngineOptions {
            retention: RetentionPolicy::None,
            target_partitions: Some(1),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let mut stream = engine
        .execute_stream("SELECT frame_number FROM frames ORDER BY 1")
        .await
        .unwrap();
    let mut frames = Vec::new();
    while let Some(b) = stream.next().await {
        frames.extend(u64_column(&b.unwrap(), 0));
    }
    assert_eq!(frames, vec![1, 2, 3, 4, 5]);
    let stats = stream.finish().await.unwrap();
    assert_eq!(stats.packets_scanned, 5);
    assert_eq!(stats.late_rows, 0);
    let _ = Arc::new(());
}
