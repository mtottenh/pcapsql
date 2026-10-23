//! Concurrency and plan-only behaviour of one `QueryEngine` (#123, #124).
//!
//! `docs/query-context-design.md` describes the architecture these tests
//! pin: queries on one engine must not interfere with each other, and
//! statements that never execute a scan (EXPLAIN, DDL) must not parse.

use std::sync::Arc;

use arrow::array::{Array, Int64Array, UInt32Array};
use arrow::record_batch::RecordBatch;
use pcapsql_datafusion::query::{
    EngineOptions, ProgressFn, QueryEngine, RetentionPolicy, ServedFrom, SourceSpec,
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
            // The cache only widens: B's narrower install must not have
            // replaced A's entry, so A's columns are still served from cache.
            let again = engine
                .execute("SELECT max(length(hex(raw_data))) AS r FROM frames")
                .await
                .expect("cached query");
            assert_eq!(
                again.stats.parse_passes, 0,
                "the wider cache entry must survive a concurrent narrower query"
            );
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

// ---------------------------------------------------------------------------
// #124: statements that never poll a scan (EXPLAIN, DDL) must not parse.
// ---------------------------------------------------------------------------

fn pretty(batches: &[RecordBatch]) -> String {
    arrow::util::pretty::pretty_format_batches(batches)
        .expect("format")
        .to_string()
}

/// A fresh engine per case: under `CacheOnTouch` an earlier query would have
/// cached the table, and EXPLAIN would then show it as prepared.
async fn fresh(path: &std::path::Path, retention: RetentionPolicy) -> QueryEngine {
    open(path, retention, 1000, None).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explain_does_not_parse() {
    let dir = TempDir::new().unwrap();
    let path = write_capture(&dir, 300);
    for retention in [RetentionPolicy::None, RetentionPolicy::CacheOnTouch] {
        for sql in [
            "EXPLAIN SELECT * FROM frames",
            "EXPLAIN SELECT f.frame_number, u.dst_port FROM frames f \
             JOIN udp u USING (frame_number) ORDER BY f.frame_number",
            // A view: its member tables are inlined at logical planning.
            "EXPLAIN SELECT frame_number, dst_port FROM udp_packets WHERE dst_port = 53",
            // Time UDFs are folded at planning from the boundary index.
            "EXPLAIN SELECT relative_time(timestamp) FROM frames",
        ] {
            let engine = fresh(&path, retention).await;
            let out = pretty(
                &engine
                    .query(sql)
                    .await
                    .unwrap_or_else(|e| panic!("{sql}: {e}")),
            );
            assert!(
                out.contains("ProtocolScanExec") && out.contains("plan-only"),
                "{retention:?} {sql}: expected plan-only scans in\n{out}"
            );
            let stats = engine.last_parse_stats();
            assert_eq!(
                stats.served_from,
                ServedFrom::PlanOnly,
                "{retention:?} {sql}"
            );
            assert_eq!(stats.parse_passes, 0, "{retention:?} {sql}");
            assert_eq!(stats.packets_scanned, 0, "{retention:?} {sql}");
            assert!(
                stats.rows_built.is_empty(),
                "{retention:?} {sql}: {stats:?}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explain_analyze_executes_and_parses() {
    let dir = TempDir::new().unwrap();
    let path = write_capture(&dir, 300);
    for retention in [RetentionPolicy::None, RetentionPolicy::CacheOnTouch] {
        let engine = fresh(&path, retention).await;
        let out = pretty(
            &engine
                .query("EXPLAIN ANALYZE SELECT count(*) AS c FROM udp")
                .await
                .expect("explain analyze"),
        );
        // (Over exactly-sized materialized batches DataFusion folds the
        // count into a constant, so the scan itself may not be displayed.)
        assert!(out.contains("Plan with Metrics"), "{out}");
        let stats = engine.last_parse_stats();
        assert_eq!(
            stats.served_from,
            ServedFrom::Parse,
            "{retention:?}: {stats:?}"
        );
        assert_eq!(stats.parse_passes, 1, "{retention:?}: {stats:?}");
        assert_eq!(stats.packets_scanned, 300, "{retention:?}: {stats:?}");
    }
}

/// A gzip-compressed copy of the capture: not seekable, so no boundary index.
fn gzip_copy(dir: &TempDir, raw: &std::path::Path) -> std::path::PathBuf {
    use std::io::Write;
    let path = dir.path().join("cap.pcap.gz");
    let mut enc = flate2::write::GzEncoder::new(
        std::fs::File::create(&path).unwrap(),
        flate2::Compression::fast(),
    );
    enc.write_all(&std::fs::read(raw).unwrap()).unwrap();
    enc.finish().unwrap();
    path
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explain_time_udf_without_index_reports_the_bootstrap_pass() {
    // Accepted behaviour: `start_time()` / `end_time()` / `relative_time()`
    // are folded at planning, so even EXPLAIN needs the capture time range.
    // A source with a boundary index answers it for free; a compressed one
    // has none and pays one header-only pass (frames only, no protocol
    // parser), once per engine. The pass is reported, not hidden.
    let dir = TempDir::new().unwrap();
    let raw = write_capture(&dir, 300);
    let gz = gzip_copy(&dir, &raw);
    for retention in [RetentionPolicy::None, RetentionPolicy::CacheOnTouch] {
        let engine = fresh(&gz, retention).await;
        let out = pretty(
            &engine
                .query("EXPLAIN SELECT start_time() AS t0, relative_time(timestamp) AS rel FROM frames")
                .await
                .expect("explain"),
        );
        assert!(out.contains("plan-only"), "{out}");
        let stats = engine.last_parse_stats();
        assert_eq!(stats.served_from, ServedFrom::PlanOnly, "{stats:?}");
        assert_eq!(stats.parse_passes, 1, "the bootstrap pass: {stats:?}");
        assert_eq!(stats.packets_scanned, 300, "{stats:?}");
        assert!(stats.rows_built.is_empty(), "{stats:?}");

        // Established once: the next statement pays nothing.
        engine
            .query("EXPLAIN SELECT end_time()")
            .await
            .expect("explain");
        let stats = engine.last_parse_stats();
        assert_eq!(stats.served_from, ServedFrom::PlanOnly);
        assert_eq!(
            (stats.parse_passes, stats.packets_scanned),
            (0, 0),
            "{stats:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ddl_and_statements_do_not_parse() {
    let dir = TempDir::new().unwrap();
    let path = write_capture(&dir, 300);
    let engine = fresh(&path, RetentionPolicy::CacheOnTouch).await;

    // DDL on the shared context: no parse, and the view is usable afterwards.
    engine
        .query("CREATE VIEW udp_ports AS SELECT frame_number, dst_port FROM udp")
        .await
        .expect("create view");
    let stats = engine.last_parse_stats();
    assert_eq!(stats.served_from, ServedFrom::PlanOnly, "{stats:?}");
    assert_eq!(stats.parse_passes, 0, "{stats:?}");
    let out = engine
        .query("SELECT count(*) AS c FROM udp_ports")
        .await
        .expect("select from view");
    assert_eq!(first_i64(&out), 300);
    assert_eq!(engine.last_parse_stats().parse_passes, 1);

    // DESCRIBE answers from the static schema.
    let out = engine.query("DESCRIBE frames").await.expect("describe");
    assert!(total_rows(&out) > 0);
    assert_eq!(engine.last_parse_stats().served_from, ServedFrom::PlanOnly);

    // Session statements too.
    engine
        .query("SET datafusion.execution.batch_size = 4096")
        .await
        .expect("set");
    assert_eq!(engine.last_parse_stats().served_from, ServedFrom::PlanOnly);

    // CTAS over a capture table cannot be prepared: a clear error, no parse.
    let err = engine
        .query("CREATE TABLE t AS SELECT frame_number FROM frames")
        .await
        .expect_err("ctas over a capture table is rejected");
    assert!(err.to_string().contains("not supported"), "{err}");

    // INSERT INTO a memory table from a capture table is a query: it is
    // planned with the prepared tables and parses once.
    engine
        .query("CREATE TABLE sink (frame_number BIGINT UNSIGNED)")
        .await
        .expect("create table");
    engine
        .query("INSERT INTO sink SELECT frame_number FROM frames WHERE frame_number <= 10")
        .await
        .expect("insert from capture table");
    let stats = engine.last_parse_stats();
    assert_eq!(stats.served_from, ServedFrom::Parse, "{stats:?}");
    assert_eq!(stats.parse_passes, 1, "{stats:?}");
    let out = engine
        .query("SELECT count(*) AS c FROM sink")
        .await
        .expect("count sink");
    assert_eq!(first_i64(&out), 10);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn context_queries_plan_but_fail_at_execution() {
    // Direct use of the session context bypasses QueryEngine::query: EXPLAIN
    // works (plan-only scans), a data query fails when executed.
    let dir = TempDir::new().unwrap();
    let path = write_capture(&dir, 50);
    let engine = fresh(&path, RetentionPolicy::None).await;
    let ctx = engine.context();

    let out = ctx
        .sql("EXPLAIN SELECT count(*) FROM udp")
        .await
        .expect("plan")
        .collect()
        .await
        .expect("explain via context");
    assert!(pretty(&out).contains("plan-only"));

    let err = ctx
        .sql("SELECT count(*) FROM udp")
        .await
        .expect("plan")
        .collect()
        .await
        .expect_err("execution must fail");
    assert!(
        err.to_string().contains("was not prepared for this query"),
        "{err}"
    );

    // Also on a CacheOnTouch engine that has the table cached: the cache is
    // read into a query's own context, never by the context directly.
    let engine = fresh(&path, RetentionPolicy::CacheOnTouch).await;
    engine
        .query("SELECT count(*) AS c FROM udp")
        .await
        .expect("cache udp");
    let err = engine
        .context()
        .sql("SELECT count(*) FROM udp")
        .await
        .expect("plan")
        .collect()
        .await
        .expect_err("execution must fail even when the table is cached");
    assert!(
        err.to_string().contains("was not prepared for this query"),
        "{err}"
    );
}

// ---------------------------------------------------------------------------
// Cancellation: dropping a query's future releases its stream producers.
// ---------------------------------------------------------------------------

/// Parks the parse thread of the first query at its first progress chunk
/// (telling the test it is parked) until the test opens the gate.
struct Gate {
    parked: tokio::sync::mpsc::UnboundedSender<()>,
    open: (std::sync::Mutex<bool>, std::sync::Condvar),
    first_seen: std::sync::atomic::AtomicBool,
}

impl Gate {
    fn on_progress(&self, total: u64) {
        use std::sync::atomic::Ordering;
        if total != CHUNK || self.first_seen.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = self.parked.send(());
        let (lock, cv) = &self.open;
        let mut open = lock.lock().unwrap();
        while !*open {
            open = cv.wait(open).unwrap();
        }
    }

    fn release(&self) {
        let (lock, cv) = &self.open;
        *lock.lock().unwrap() = true;
        cv.notify_all();
    }
}

/// Run a streaming query whose producer parks after its first chunk, cancel
/// the query, release the producer, and require the next query to complete.
///
/// The runtime has a single blocking thread: a producer that did not notice
/// its consumers were gone would keep it, and the next query's producer could
/// never start. With `batch_size` below the chunk a batch is already in
/// flight when the producer parks (the query is cancelled inside `collect`);
/// above the capture size nothing has been sent yet.
fn cancel_case(batch_size: usize) {
    const N: usize = 3000;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let dir = TempDir::new().unwrap();
        let path = write_capture(&dir, N);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let gate = Arc::new(Gate {
            parked: tx,
            open: Default::default(),
            first_seen: Default::default(),
        });
        let progress: ProgressFn = {
            let gate = gate.clone();
            Arc::new(move |total| gate.on_progress(total))
        };
        let engine = Arc::new(open(&path, RetentionPolicy::None, batch_size, Some(progress)).await);

        let cancelled = tokio::spawn({
            let engine = engine.clone();
            async move { engine.query("SELECT frame_number, dst_port FROM udp").await }
        });
        tokio::time::timeout(std::time::Duration::from_secs(30), rx.recv())
            .await
            .expect("producer parks within 30s")
            .expect("gate alive");
        // Let the query reach `collect` (it is already past planning once the
        // producer runs), then drop its future.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());

        // The producer resumes, must see its consumers gone and exit, freeing
        // the only blocking thread for the next query.
        gate.release();
        let out = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            engine.query("SELECT count(*) AS c FROM udp"),
        )
        .await
        .expect("a cancelled query's producer must not block the next query")
        .expect("query ok");
        assert_eq!(first_i64(&out), N as i64);
    });
}

#[test]
fn cancelled_query_releases_producer_mid_stream() {
    cancel_case(1000);
}

#[test]
fn cancelled_query_releases_producer_before_first_batch() {
    cancel_case(5000);
}

// ---------------------------------------------------------------------------
// #123: many concurrent queries of different shapes on one engine.
// ---------------------------------------------------------------------------

async fn open_partitioned(path: &std::path::Path, retention: RetentionPolicy) -> QueryEngine {
    QueryEngine::open(
        SourceSpec::Path(path.to_path_buf()),
        EngineOptions {
            batch_size: 1000,
            target_partitions: Some(2),
            index_stride: Some(8),
            retention,
            ..Default::default()
        },
    )
    .await
    .expect("open engine")
}

/// Fast path, LIMIT, pushed filter, join, self-join (materialize rule), a
/// stream table (single-partition pass), the time UDFs and `raw_data`.
const MIXED: &[&str] = &[
    "SELECT count(*) AS c FROM frames",
    "SELECT frame_number, length FROM frames ORDER BY frame_number LIMIT 5",
    "SELECT frame_number, src_port FROM udp WHERE dst_port = 53 ORDER BY frame_number LIMIT 7",
    "SELECT f.frame_number, u.src_port FROM frames f JOIN udp u USING (frame_number) \
     ORDER BY f.frame_number LIMIT 9",
    "SELECT a.frame_number, b.frame_number AS next FROM frames a \
     JOIN frames b ON b.frame_number = a.frame_number + 1 ORDER BY a.frame_number LIMIT 3",
    "SELECT count(*) AS c FROM http2",
    "SELECT start_time() AS t0, end_time() AS t1",
    "SELECT max(length(hex(raw_data))) AS r FROM frames",
];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_mixed_queries_match_sequential() {
    let dir = TempDir::new().unwrap();
    let path = write_capture(&dir, 2000);
    for retention in [RetentionPolicy::None, RetentionPolicy::CacheOnTouch] {
        let baseline = open_partitioned(&path, retention).await;
        let mut expected = Vec::with_capacity(MIXED.len());
        for sql in MIXED {
            expected.push(pretty(&baseline.query(sql).await.expect("baseline")));
        }

        let engine = Arc::new(open_partitioned(&path, retention).await);
        let mut tasks = tokio::task::JoinSet::new();
        for task in 0..8usize {
            let engine = engine.clone();
            let expected = expected.clone();
            tasks.spawn(async move {
                for round in 0..8usize {
                    for k in 0..MIXED.len() {
                        let i = (k + task + round) % MIXED.len();
                        let out = engine.execute(MIXED[i]).await.unwrap_or_else(|e| {
                            panic!("{retention:?} task {task}: {}: {e}", MIXED[i])
                        });
                        assert_eq!(
                            pretty(&out.batches),
                            expected[i],
                            "{retention:?} task {task} round {round}: {}",
                            MIXED[i]
                        );
                        assert!(out.stats.parse_passes <= 1, "{:?}", out.stats);
                    }
                }
            });
        }
        while let Some(joined) = tasks.join_next().await {
            joined.expect("query task");
        }
    }
}
