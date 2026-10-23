//! Concurrency and plan-only behaviour of one `QueryEngine` (#123, #124).
//!
//! `docs/query-context-design.md` describes the architecture these tests
//! pin: queries on one engine must not interfere with each other, and
//! statements that never execute a scan (EXPLAIN, DDL) must not parse.

use std::sync::Arc;

use arrow::array::{Array, Int64Array, UInt32Array};
use arrow::record_batch::RecordBatch;
use pcapsql_datafusion::query::{
    EngineOptions, ProgressFn, QueryEngine, RetentionPolicy, SourceSpec,
};
use pcapsql_testgen::{legacy_pcap, GenPacket, LegacyVariant};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Fixture: a capture of minimal Ethernet/IPv4/UDP frames
// ---------------------------------------------------------------------------

fn udp_packet(src_port: u16, dst_port: u16, payload_len: usize) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&[0xff; 6]); // dst mac
    p.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src mac
    p.extend_from_slice(&[0x08, 0x00]); // IPv4
    let ip_total = (20 + 8 + payload_len) as u16;
    p.push(0x45);
    p.push(0x00);
    p.extend_from_slice(&ip_total.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]); // id
    p.extend_from_slice(&[0x40, 0x00]); // DF
    p.push(64); // ttl
    p.push(17); // UDP
    p.extend_from_slice(&[0x00, 0x00]); // checksum
    p.extend_from_slice(&[192, 168, 0, 1]);
    p.extend_from_slice(&[192, 168, 0, 2]);
    let udp_len = (8 + payload_len) as u16;
    p.extend_from_slice(&src_port.to_be_bytes());
    p.extend_from_slice(&dst_port.to_be_bytes());
    p.extend_from_slice(&udp_len.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend(std::iter::repeat_n(0xAB, payload_len));
    p
}

/// Write a capture of `n` UDP frames (frame `i` has `i % 7` payload bytes, so
/// `frames.length` takes several values).
fn write_capture(dir: &TempDir, n: usize) -> std::path::PathBuf {
    let packets: Vec<GenPacket> = (0..n)
        .map(|i| {
            let data = udp_packet(10_000 + (i % 1000) as u16, 53, i % 7);
            let origlen = data.len() as u32;
            GenPacket {
                ts_sec: 1_700_000_000 + i as u32,
                ts_frac: (i as u32 * 137) % 1_000_000,
                data,
                origlen,
            }
        })
        .collect();
    let path = dir.path().join("cap.pcap");
    std::fs::write(
        &path,
        legacy_pcap(LegacyVariant::LeMicro, 1, 65535, &packets).bytes,
    )
    .unwrap();
    path
}

async fn open(
    path: &std::path::Path,
    retention: RetentionPolicy,
    batch_size: usize,
    progress: Option<ProgressFn>,
) -> QueryEngine {
    QueryEngine::open(
        SourceSpec::Path(path.to_path_buf()),
        EngineOptions {
            batch_size,
            target_partitions: Some(1),
            index_stride: Some(8),
            retention,
            progress,
            ..Default::default()
        },
    )
    .await
    .expect("open engine")
}

fn total_rows(batches: &[RecordBatch]) -> usize {
    batches.iter().map(|b| b.num_rows()).sum()
}

/// The single `count(*)`-style value of a one-row, one-or-more-column result.
fn first_i64(batches: &[RecordBatch]) -> i64 {
    let batch = batches.iter().find(|b| b.num_rows() > 0).expect("a row");
    batch
        .column(0)
        .as_any()
        .downcast_ref::<Int64Array>()
        .expect("int64 column")
        .value(0)
}

// ---------------------------------------------------------------------------
// #123: a query issued while another query is between "tables prepared" and
// "physical plan built" must not interfere with it.
// ---------------------------------------------------------------------------

/// A query that is cheap to parse but expensive to *plan*: a `CASE` with
/// thousands of arms keeps the optimizer and the physical planner busy for
/// tens of milliseconds, which widens the window between the engine
/// preparing the query's tables and DataFusion's `scan` resolving them.
fn slow_to_plan_query(with_raw_data: bool) -> String {
    const ARMS: usize = 3000;
    let arms: Vec<String> = (1..=ARMS)
        .map(|i| format!("WHEN length = {i} THEN {i}"))
        .collect();
    let raw = if with_raw_data {
        ", max(length(hex(raw_data))) AS raw_len"
    } else {
        ""
    };
    format!(
        "SELECT count(*) AS n, sum(CASE {} ELSE 0 END) AS s{raw} FROM frames",
        arms.join(" ")
    )
}

/// Progress-callback choreography that forces query B into query A's
/// install -> physical-plan window.
///
/// The engine's `progress` callback runs on the parse thread with the
/// running packet total of the current pass; a second pass restarts at the
/// first chunk (`CHUNK` packets), which is how the two parses are told
/// apart. B is started (`start_b`) either when A's parse has read the whole
/// capture (`None`: A is about to install its stream receivers and plan) or
/// at A's first chunk (`CacheOnTouch`: B must read the cache *before* A
/// installs, so it misses and parses on its own). In the latter case B's
/// parse is then parked (`park_second_parse`) until A has finished reading,
/// so B's narrower install lands after A's wider one and inside A's window.
struct Choreography {
    n: u64,
    start_b: tokio::sync::mpsc::UnboundedSender<()>,
    start_b_at_first_chunk: bool,
    park_second_parse: bool,
    first_chunks_seen: std::sync::atomic::AtomicUsize,
    a_done: (std::sync::Mutex<bool>, std::sync::Condvar),
}

/// Packets per `process_packets` chunk in the engine's parse loops.
const CHUNK: u64 = 1024;

impl Choreography {
    fn on_progress(&self, total: u64) {
        use std::sync::atomic::Ordering;
        if total >= self.n {
            let (lock, cv) = &self.a_done;
            *lock.lock().unwrap() = true;
            cv.notify_all();
            if !self.start_b_at_first_chunk {
                let _ = self.start_b.send(());
            }
        } else if total == CHUNK {
            let k = self.first_chunks_seen.fetch_add(1, Ordering::SeqCst);
            if k == 0 {
                if self.start_b_at_first_chunk {
                    let _ = self.start_b.send(());
                }
            } else if self.park_second_parse {
                let (lock, cv) = &self.a_done;
                let mut done = lock.lock().unwrap();
                while !*done {
                    done = cv.wait(done).unwrap();
                }
            }
        }
    }
}

/// Run query A (slow to plan) and, inside A's install -> physical-plan
/// window, query B on the same engine. Both must succeed with correct
/// results whatever the engine does to serialize or isolate them.
///
/// Under `RetentionPolicy::None` B's pre-harvest `clear()` used to land in
/// A's planning window ("table 'frames' was not prepared"); under
/// `CacheOnTouch` B's narrower cache entry used to replace A's wider one
/// ("column 'raw_data' … was not materialized").
async fn overlap_case(retention: RetentionPolicy) {
    // Streaming: three batches of 500 fit the 4-batch exchange, so A's
    // producer finishes without a consumer. Cached: a longer capture so A is
    // still parsing when B reads the cache.
    let (n, batch_size) = match retention {
        RetentionPolicy::None => (1500usize, 500usize),
        RetentionPolicy::CacheOnTouch => (8000, 1000),
    };
    let dir = TempDir::new().unwrap();
    let path = write_capture(&dir, n);

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let cached = retention == RetentionPolicy::CacheOnTouch;
    let choreography = Arc::new(Choreography {
        n: n as u64,
        start_b: tx,
        start_b_at_first_chunk: cached,
        park_second_parse: cached,
        first_chunks_seen: Default::default(),
        a_done: Default::default(),
    });
    let progress: ProgressFn = Arc::new(move |total| choreography.on_progress(total));
    let engine = Arc::new(open(&path, retention, batch_size, Some(progress)).await);

    let a_sql = slow_to_plan_query(cached);
    let a = tokio::spawn({
        let engine = engine.clone();
        async move { engine.query(&a_sql).await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(60), rx.recv())
        .await
        .expect("A's parse should signal within 60s")
        .expect("progress sender alive");

    let b_sql = match retention {
        RetentionPolicy::None => "SELECT count(*) AS c FROM udp",
        RetentionPolicy::CacheOnTouch => "SELECT length FROM frames",
    };
    let b = engine.query(b_sql).await;
    let a = a.await.expect("A did not panic");

    let a = a.unwrap_or_else(|e| panic!("query A failed: {e}"));
    assert_eq!(first_i64(&a), n as i64, "A must count every frame");
    let b = b.unwrap_or_else(|e| panic!("query B failed: {e}"));
    match retention {
        RetentionPolicy::None => assert_eq!(first_i64(&b), n as i64),
        RetentionPolicy::CacheOnTouch => {
            assert_eq!(total_rows(&b), n);
            let lengths: Vec<u32> = b
                .iter()
                .flat_map(|batch| {
                    batch
                        .column(0)
                        .as_any()
                        .downcast_ref::<UInt32Array>()
                        .expect("length is u32")
                        .values()
                        .to_vec()
                })
                .collect();
            assert!(lengths.iter().all(|l| (42..49).contains(l)), "{lengths:?}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_query_in_planning_window_streaming() {
    overlap_case(RetentionPolicy::None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_query_in_planning_window_cached() {
    overlap_case(RetentionPolicy::CacheOnTouch).await;
}
