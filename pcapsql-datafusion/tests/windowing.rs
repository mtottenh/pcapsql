//! End-to-end tests for the `tumble`, `hop` and `session` table functions.
//!
//! A generated UDP capture with three flows (keyed by source port), uneven
//! packet sizes and deliberately out-of-order timestamps is windowed through
//! the engine, and every result is checked against an equivalent query
//! written without the functions (`date_bin`-free integer arithmetic on
//! `frames.timestamp`, `UNION ALL` of shifted windows, a `LAG`-based
//! gaps-and-islands query), under both retention policies.

use arrow::util::pretty::pretty_format_batches;
use pcapsql_datafusion::query::{
    EngineOptions, QueryEngine, RetentionPolicy, ServedFrom, SourceSpec,
};
use pcapsql_testgen::{legacy_pcap, GenPacket, GeneratedCapture, LegacyVariant};
use tempfile::TempDir;

/// Capture start, aligned to 10 s (and therefore to the tumble windows below).
const T0: u32 = 1_700_000_000;

/// Ethernet/IPv4/UDP frame with the given ports and payload length.
fn udp_packet(src_port: u16, dst_port: u16, payload_len: usize) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
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
    p.extend_from_slice(&dst_port.to_be_bytes());
    p.extend_from_slice(&udp_len.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend(std::iter::repeat_n(0xAB, payload_len));
    p
}

/// (source port, seconds after `T0`, microseconds) per frame, in file order.
///
/// Ports 1000 and 2000 spread over ~100 s in a scrambled order; port 3000 is
/// the review's failing session input — gap 5 s, timestamps 1 s, 20 s, 2 s —
/// whose third packet belongs to the *first* session although it arrives
/// after the second one started.
fn frames_spec() -> Vec<(u16, u32, u32)> {
    let mut spec: Vec<(u16, u32, u32)> = (0..30u32)
        .map(|i| {
            let port = if i % 2 == 0 { 1000 } else { 2000 };
            let secs = (i * 37) % 101;
            let micros = (i * 137_003) % 1_000_000;
            (port, secs, micros)
        })
        .collect();
    spec.extend([(3000, 1, 0), (3000, 20, 0), (3000, 2, 0)]);
    spec
}

fn make_capture() -> GeneratedCapture {
    let packets: Vec<GenPacket> = frames_spec()
        .into_iter()
        .enumerate()
        .map(|(i, (port, secs, micros))| {
            let data = udp_packet(port, 53, 8 + (i % 5) * 10);
            let origlen = data.len() as u32;
            GenPacket {
                ts_sec: T0 + secs,
                ts_frac: micros,
                data,
                origlen,
            }
        })
        .collect();
    legacy_pcap(LegacyVariant::LeMicro, 1, 65535, &packets)
}

struct Fixture {
    _dir: TempDir,
    path: std::path::PathBuf,
}

fn fixture() -> Fixture {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("windows.pcap");
    std::fs::write(&path, make_capture().bytes).unwrap();
    Fixture { _dir: dir, path }
}

async fn engine(fx: &Fixture, retention: RetentionPolicy, partitions: usize) -> QueryEngine {
    QueryEngine::open(
        SourceSpec::Path(fx.path.clone()),
        EngineOptions {
            batch_size: 7,
            retention,
            target_partitions: Some(partitions),
            index_stride: Some(4),
            ..Default::default()
        },
    )
    .await
    .expect("build engine")
}

async fn run(engine: &QueryEngine, sql: &str) -> String {
    let batches = engine
        .query(sql)
        .await
        .unwrap_or_else(|e| panic!("query failed: {e}\n{sql}"));
    pretty_format_batches(&batches).expect("format").to_string()
}

async fn error_of(engine: &QueryEngine, sql: &str) -> String {
    match engine.query(sql).await {
        Ok(_) => panic!("expected an error from: {sql}"),
        Err(e) => e.to_string(),
    }
}

/// `frames.timestamp` floored to a multiple of `size_us` microseconds (all
/// capture timestamps are after the epoch, so truncation floors), shifted
/// back by `shift_us`, as a `Timestamp(Microsecond)`.
fn floored(size_us: i64, shift_us: i64) -> String {
    format!(
        "arrow_cast((CAST(timestamp AS BIGINT) / {size_us}) * {size_us} - {shift_us}, \
         'Timestamp(Microsecond, None)')"
    )
}

const TUMBLE_10S: &str = "tumble(frames, INTERVAL '10' SECOND)";

/// Queries whose results must be identical with and without the window
/// functions: (windowed, hand-written equivalent).
fn equivalences() -> Vec<(String, String)> {
    let ten = 10_000_000;
    let mut cases = vec![
        // Tumbling count per window.
        (
            format!("SELECT window_start, count(*) AS n FROM {TUMBLE_10S} GROUP BY 1 ORDER BY 1"),
            format!(
                "SELECT {} AS window_start, count(*) AS n FROM frames GROUP BY 1 ORDER BY 1",
                floored(ten, 0)
            ),
        ),
        // A non-window group column and two aggregates, with window_end.
        (
            format!(
                "SELECT window_start, window_end, link_type, count(*) AS n, sum(length) AS bytes \
                 FROM {TUMBLE_10S} GROUP BY 1, 2, 3 ORDER BY 1, 3"
            ),
            format!(
                "SELECT {} AS window_start, {} AS window_end, link_type, \
                 count(*) AS n, sum(length) AS bytes FROM frames GROUP BY 1, 2, 3 ORDER BY 1, 3",
                floored(ten, 0),
                floored(ten, -ten)
            ),
        ),
        // WHERE on a source column (pushed below the window assignment).
        (
            format!(
                "SELECT window_start, count(*) AS n, min(length) AS shortest FROM {TUMBLE_10S} \
                 WHERE length > 70 GROUP BY 1 ORDER BY 1"
            ),
            format!(
                "SELECT {} AS window_start, count(*) AS n, min(length) AS shortest FROM frames \
                 WHERE length > 70 GROUP BY 1 ORDER BY 1",
                floored(ten, 0)
            ),
        ),
        // WHERE on a window column (stays above the assignment).
        (
            format!(
                "SELECT window_start, count(*) AS n FROM {TUMBLE_10S} \
                 WHERE window_start >= TIMESTAMP '2023-11-14T22:14:00Z' GROUP BY 1 ORDER BY 1"
            ),
            format!(
                "SELECT window_start, count(*) AS n FROM (SELECT {} AS window_start FROM frames) \
                 WHERE window_start >= TIMESTAMP '2023-11-14T22:14:00Z' GROUP BY 1 ORDER BY 1",
                floored(ten, 0)
            ),
        ),
        // Fully qualified source and a source-qualified timestamp column.
        (
            "SELECT window_start, count(*) AS n \
             FROM tumble(datafusion.public.frames, frames.timestamp, INTERVAL '10' SECOND) \
             GROUP BY 1 ORDER BY 1"
                .to_string(),
            format!(
                "SELECT {} AS window_start, count(*) AS n FROM frames GROUP BY 1 ORDER BY 1",
                floored(ten, 0)
            ),
        ),
        (
            "SELECT window_start, count(*) AS n \
             FROM session(public.udp_packets, udp_packets.src_port, INTERVAL '5' SECOND) \
             WHERE src_port = 3000 GROUP BY 1 ORDER BY 1"
                .to_string(),
            "SELECT window_start, count(*) AS n \
             FROM session(udp_packets, src_port, INTERVAL '5' SECOND) \
             WHERE src_port = 3000 GROUP BY 1 ORDER BY 1"
                .to_string(),
        ),
        // Explicit timestamp column and a relation alias.
        (
            "SELECT w.window_start, sum(w.length) AS bytes \
             FROM tumble(frames, timestamp, INTERVAL '10' SECOND) AS w GROUP BY 1 ORDER BY 1"
                .to_string(),
            format!(
                "SELECT {} AS window_start, sum(length) AS bytes FROM frames GROUP BY 1 ORDER BY 1",
                floored(ten, 0)
            ),
        ),
        // A *_packets view as the source, grouped by a view column.
        (
            "SELECT window_start, src_port, count(*) AS n \
             FROM tumble(udp_packets, INTERVAL '10' SECOND) GROUP BY 1, 2 ORDER BY 1, 2"
                .to_string(),
            format!(
                "SELECT {} AS window_start, src_port, count(*) AS n FROM udp_packets \
                 GROUP BY 1, 2 ORDER BY 1, 2",
                floored(ten, 0)
            ),
        ),
        // Hop with size = 3 × slide: every frame in three windows.
        (
            "SELECT window_start, count(*) AS n, sum(length) AS bytes \
             FROM hop(frames, INTERVAL '10' SECOND, INTERVAL '30' SECOND) GROUP BY 1 ORDER BY 1"
                .to_string(),
            format!(
                "SELECT window_start, count(*) AS n, sum(length) AS bytes FROM ( \
                   SELECT {} AS window_start, length FROM frames UNION ALL \
                   SELECT {} AS window_start, length FROM frames UNION ALL \
                   SELECT {} AS window_start, length FROM frames) GROUP BY 1 ORDER BY 1",
                floored(ten, 0),
                floored(ten, ten),
                floored(ten, 2 * ten)
            ),
        ),
        // Hop with a size that is not a multiple of the slide (25 s / 10 s):
        // the oldest candidate window only sometimes reaches the frame.
        (
            "SELECT window_start, window_end, count(*) AS n \
             FROM hop(frames, INTERVAL '10' SECOND, INTERVAL '25' SECOND) GROUP BY 1, 2 ORDER BY 1"
                .to_string(),
            format!(
                "SELECT window_start, window_start + INTERVAL '25' SECOND AS window_end, \
                 count(*) AS n FROM ( \
                   SELECT {} AS window_start, timestamp FROM frames UNION ALL \
                   SELECT {} AS window_start, timestamp FROM frames UNION ALL \
                   SELECT {} AS window_start, timestamp FROM frames) \
                 WHERE window_start + INTERVAL '25' SECOND > timestamp GROUP BY 1 ORDER BY 1",
                floored(ten, 0),
                floored(ten, ten),
                floored(ten, 2 * ten)
            ),
        ),
        // Sessions per source port with a 5 s gap, over a join view whose
        // rows are not time-ordered per key: a gaps-and-islands query.
        (
            "SELECT src_port, window_start, window_end, count(*) AS n \
             FROM session(udp_packets, src_port, INTERVAL '5' SECOND) \
             GROUP BY 1, 2, 3 ORDER BY 1, 2"
                .to_string(),
            "WITH ordered AS ( \
               SELECT src_port, timestamp, \
                 CASE WHEN CAST(timestamp AS BIGINT) \
                      - LAG(CAST(timestamp AS BIGINT)) OVER (PARTITION BY src_port ORDER BY timestamp) \
                      > 5000000 THEN 1 ELSE 0 END AS brk \
               FROM udp_packets), \
             islands AS ( \
               SELECT src_port, timestamp, \
                 SUM(brk) OVER (PARTITION BY src_port ORDER BY timestamp \
                                ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS sid \
               FROM ordered) \
             SELECT src_port, min(timestamp) AS window_start, \
               max(timestamp) + INTERVAL '5' SECOND AS window_end, count(*) AS n \
             FROM islands GROUP BY src_port, sid ORDER BY 1, 2"
                .to_string(),
        ),
    ];
    // Un-ORDERed row output stays in capture order through every operator.
    for source in [
        TUMBLE_10S,
        "hop(frames, INTERVAL '10' SECOND, INTERVAL '30' SECOND)",
        "session(udp_packets, src_port, INTERVAL '5' SECOND)",
    ] {
        cases.push((
            format!("SELECT frame_number FROM {source}"),
            format!("SELECT frame_number FROM {source} ORDER BY frame_number"),
        ));
    }
    cases
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn window_functions_match_hand_written_sql_under_both_policies() {
    let fx = fixture();
    let streaming = engine(&fx, RetentionPolicy::None, 4).await;
    let cached = engine(&fx, RetentionPolicy::CacheOnTouch, 4).await;
    let single = engine(&fx, RetentionPolicy::None, 1).await;
    for (windowed, reference) in equivalences() {
        let expected = run(&single, &reference).await;
        assert!(
            expected.lines().count() > 4,
            "reference query produced no rows:\n{reference}\n{expected}"
        );
        for (name, eng) in [
            ("None/4", &streaming),
            ("CacheOnTouch/4", &cached),
            ("None/1", &single),
        ] {
            let got = run(eng, &windowed).await;
            assert_eq!(
                got, expected,
                "[{name}] {windowed}\n-- differs from --\n{reference}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_bounds_for_out_of_order_input() {
    let fx = fixture();
    let eng = engine(&fx, RetentionPolicy::None, 4).await;
    // Port 3000 arrives as 1 s, 20 s, 2 s: the 2 s packet belongs to the
    // first session, which runs to 2 s + gap, and the 20 s packet is alone.
    let got = run(
        &eng,
        "SELECT window_start, window_end, count(*) AS n \
         FROM session(udp_packets, src_port, INTERVAL '5' SECOND) \
         WHERE src_port = 3000 GROUP BY 1, 2 ORDER BY 1",
    )
    .await;
    let expected = "\
+---------------------+---------------------+---+
| window_start        | window_end          | n |
+---------------------+---------------------+---+
| 2023-11-14T22:13:21 | 2023-11-14T22:13:27 | 2 |
| 2023-11-14T22:13:40 | 2023-11-14T22:13:45 | 1 |
+---------------------+---------------------+---+";
    assert_eq!(got, expected);
    // Every row's timestamp lies inside its window, for every function.
    for source in [
        TUMBLE_10S,
        "hop(frames, INTERVAL '10' SECOND, INTERVAL '25' SECOND)",
        "session(udp_packets, src_port, INTERVAL '5' SECOND)",
    ] {
        let got = run(
            &eng,
            &format!(
                "SELECT count(*) AS outside FROM {source} \
                 WHERE timestamp < window_start OR timestamp >= window_end"
            ),
        )
        .await;
        assert!(
            got.contains("| 0 "),
            "{source}: rows outside their window:\n{got}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hop_row_multiplicity_and_window_width() {
    let fx = fixture();
    let eng = engine(&fx, RetentionPolicy::None, 2).await;
    let frames = run(&eng, "SELECT count(*) AS n FROM frames").await;
    let hopped = run(
        &eng,
        "SELECT count(*) / 3 AS n FROM hop(frames, INTERVAL '10' SECOND, INTERVAL '30' SECOND)",
    )
    .await;
    assert_eq!(
        hopped, frames,
        "size = 3 × slide puts every frame in 3 windows"
    );
    for (source, width) in [
        (TUMBLE_10S, "10"),
        (
            "hop(frames, INTERVAL '10' SECOND, INTERVAL '30' SECOND)",
            "30",
        ),
    ] {
        let got = run(
            &eng,
            &format!(
                "SELECT count(*) AS wrong FROM {source} \
                 WHERE window_end <> window_start + INTERVAL '{width}' SECOND"
            ),
        )
        .await;
        assert!(got.contains("| 0 "), "{source}: window width:\n{got}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hop_expansion_is_chunked_and_capped() {
    let fx = fixture();
    let eng = engine(&fx, RetentionPolicy::None, 2).await;
    // 3600 windows per frame: 33 × 3600 rows, emitted in batch-sized slices
    // (batch_size 7 here) rather than as one rows × k batch per input batch.
    // DataFusion's CoalesceBatchesExec re-merges the slices up to its 8192-row
    // target, so what is observable here is that no batch exceeds that; an
    // unsliced expansion would hand out 7 × 3600 = 25 200-row batches
    // unchanged (large batches are passed through, not split).
    let batches = eng
        .query("SELECT frame_number FROM hop(frames, INTERVAL '1' SECOND, INTERVAL '1' HOUR)")
        .await
        .expect("hop 3600");
    let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    assert_eq!(rows, 33 * 3600);
    assert!(batches.len() >= 2, "{} batches", batches.len());
    assert!(
        batches.iter().all(|b| b.num_rows() <= 8192),
        "largest batch {} rows",
        batches.iter().map(|b| b.num_rows()).max().unwrap_or(0)
    );
    let got = run(
        &eng,
        "SELECT count(*) AS n, count(DISTINCT frame_number) AS frames \
         FROM hop(frames, INTERVAL '1' SECOND, INTERVAL '1' HOUR)",
    )
    .await;
    assert!(got.contains("| 118800 | 33     |"), "{got}");
    // Beyond the cap the query is refused at planning.
    let err = error_of(
        &eng,
        "SELECT count(*) FROM hop(frames, INTERVAL '1' SECOND, INTERVAL '1' DAY)",
    )
    .await;
    assert!(
        err.contains("86400 windows") && err.contains("10000"),
        "{err}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn time_zoned_timestamps_keep_their_unit() {
    let fx = fixture();
    let eng = engine(&fx, RetentionPolicy::None, 1).await;
    let _ = run(
        &eng,
        "CREATE VIEW tz AS SELECT arrow_cast(v, 'Timestamp(Microsecond, Some(\"+02:00\"))') AS ts, k \
         FROM (VALUES (-1, 'a'), (3600000000, 'a')) t(v, k)",
    )
    .await;
    for source in [
        "tumble(tz, ts, INTERVAL '1' HOUR)",
        "hop(tz, ts, INTERVAL '30' MINUTE, INTERVAL '1' HOUR)",
        "session(tz, ts, k, INTERVAL '1' HOUR)",
    ] {
        let got = run(
            &eng,
            &format!(
                "SELECT DISTINCT arrow_typeof(window_start) AS s, arrow_typeof(window_end) AS e \
                 FROM {source}"
            ),
        )
        .await;
        // arrow_typeof prints the unit in DataFusion's short form.
        assert!(
            got.matches("Timestamp(µs, \"+02:00\")").count() == 2,
            "{source}:\n{got}"
        );
    }
    // The bins are still floored in absolute time: -1 µs is in the UTC hour
    // ending at the epoch, which the +02:00 zone displays as 01:00-02:00.
    let got = run(
        &eng,
        "SELECT window_start, window_end FROM tumble(tz, ts, INTERVAL '1' HOUR) ORDER BY 1",
    )
    .await;
    assert!(
        got.contains("1970-01-01T01:00:00+02:00 | 1970-01-01T02:00:00+02:00"),
        "{got}"
    );
    assert!(
        got.contains("1970-01-01T03:00:00+02:00 | 1970-01-01T04:00:00+02:00"),
        "{got}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explain_shows_the_rewrite_and_scans_are_pruned() {
    let fx = fixture();
    let eng = engine(&fx, RetentionPolicy::None, 2).await;

    // EXPLAIN is plan-only (nothing parsed) and shows the real operators:
    // the date_bin projection and a frames scan pruned to the timestamp.
    let plan = run(
        &eng,
        &format!("EXPLAIN SELECT window_start, count(*) FROM {TUMBLE_10S} GROUP BY 1"),
    )
    .await;
    assert!(plan.contains("date_bin"), "{plan}");
    assert!(
        plan.contains("TableScan: frames projection=[timestamp]"),
        "{plan}"
    );
    assert!(plan.contains("ProtocolScanExec"), "{plan}");
    assert!(!plan.contains("raw_data"), "{plan}");
    let stats = eng.last_parse_stats();
    assert_eq!(stats.served_from, ServedFrom::PlanOnly);
    assert_eq!(stats.parse_passes, 0);

    let plan = run(
        &eng,
        "EXPLAIN SELECT window_start, count(*) \
         FROM hop(frames, INTERVAL '10' SECOND, INTERVAL '30' SECOND) GROUP BY 1",
    )
    .await;
    assert!(
        plan.contains("HopAssign: timestamp=frames.timestamp"),
        "{plan}"
    );
    assert!(plan.contains("HopAssignExec"), "{plan}");
    assert!(
        plan.contains("TableScan: frames projection=[timestamp]"),
        "{plan}"
    );

    let plan = run(
        &eng,
        "EXPLAIN SELECT window_start, src_port, count(*) \
         FROM session(udp_packets, src_port, INTERVAL '5' SECOND) GROUP BY 1, 2",
    )
    .await;
    assert!(
        plan.contains("SessionAssign: timestamp=udp_packets.timestamp, key=udp_packets.src_port"),
        "{plan}"
    );
    assert!(plan.contains("SessionAssignExec"), "{plan}");
    // Under RetentionPolicy::None the view's joins are fused into one scan
    // the parser builds (see `fusion`); its columns are the ones the query
    // needs, flattened as `<alias>__<column>`.
    assert!(
        plan.contains("TableScan: fused_frames_udp_ethernet_ipv4_ipv6_"),
        "{plan}"
    );
    assert!(plan.contains("f__timestamp"), "{plan}");
    assert!(plan.contains("udp__src_port"), "{plan}");
    assert!(!plan.contains("TableScan: udp "), "{plan}");
    assert!(!plan.contains("Join"), "{plan}");

    // Under RetentionPolicy::None the pruned column set is what gets parsed
    // and streamed; the query only works because the projection reached the
    // scan (a subset-prepared table rejects an unprojected scan).
    let _ = run(
        &eng,
        &format!("SELECT window_start, count(*) FROM {TUMBLE_10S} GROUP BY 1"),
    )
    .await;
    let stats = eng.last_parse_stats();
    assert_eq!(stats.served_from, ServedFrom::Parse);
    assert_eq!(stats.parse_passes, 1);
    assert_eq!(stats.rows_built.get("frames"), Some(&33));
    assert!(
        !stats.rows_built.contains_key("udp"),
        "{:?}",
        stats.rows_built
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cache_on_touch_caches_only_the_pruned_columns() {
    let fx = fixture();
    let eng = engine(&fx, RetentionPolicy::CacheOnTouch, 2).await;
    let _ = run(
        &eng,
        &format!("SELECT window_start, count(*) FROM {TUMBLE_10S} GROUP BY 1"),
    )
    .await;
    assert_eq!(eng.last_parse_stats().parse_passes, 1);
    // The cache now holds frames{timestamp}: a query on that column is a hit…
    let _ = run(&eng, "SELECT timestamp FROM frames LIMIT 1").await;
    assert_eq!(
        eng.last_parse_stats().parse_passes,
        0,
        "timestamp was cached"
    );
    // …while one on an unrelated column has to parse again, which it would
    // not if the window query had materialized every frames column.
    let _ = run(&eng, "SELECT raw_data FROM frames LIMIT 1").await;
    assert_eq!(
        eng.last_parse_stats().parse_passes,
        1,
        "raw_data was not cached"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn user_views_and_null_timestamps() {
    let fx = fixture();
    let eng = engine(&fx, RetentionPolicy::None, 2).await;
    // A view created at runtime is a valid source; its timestamp is null on
    // odd frames, which get null window bounds (one row for hop, no session).
    let _ = run(
        &eng,
        "CREATE VIEW half AS SELECT frame_number, \
         CASE WHEN frame_number % 2 = 0 THEN timestamp END AS timestamp FROM frames",
    )
    .await;
    for source in [
        "tumble(half, INTERVAL '10' SECOND)",
        "hop(half, INTERVAL '10' SECOND, INTERVAL '10' SECOND)",
        "session(half, frame_number, INTERVAL '10' SECOND)",
    ] {
        let got = run(
            &eng,
            &format!(
                "SELECT count(*) FILTER (WHERE window_start IS NULL) AS no_window, \
                 count(*) FILTER (WHERE window_end IS NULL) AS no_end, \
                 count(*) FILTER (WHERE frame_number % 2 = 1) AS odd, \
                 count(*) AS total FROM {source}"
            ),
        )
        .await;
        assert!(
            got.contains("| 17        | 17     | 17  | 33    |"),
            "{source}:\n{got}"
        );
    }
    // A view over a window function is a view like any other.
    let _ = run(
        &eng,
        &format!("CREATE VIEW per_window AS SELECT window_start, count(*) AS n FROM {TUMBLE_10S} GROUP BY 1"),
    )
    .await;
    let via_view = run(&eng, "SELECT * FROM per_window ORDER BY 1").await;
    let direct = run(
        &eng,
        &format!("SELECT window_start, count(*) AS n FROM {TUMBLE_10S} GROUP BY 1 ORDER BY 1"),
    )
    .await;
    assert_eq!(via_view, direct);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn planning_errors() {
    let fx = fixture();
    let eng = engine(&fx, RetentionPolicy::None, 1).await;
    let cases: &[(&str, &[&str])] = &[
        (
            "SELECT * FROM tumble(tcp, INTERVAL '10' SECOND)",
            &["no `timestamp` column", "tcp_packets"],
        ),
        (
            "SELECT * FROM tumble(tcp_connections, INTERVAL '10' SECOND)",
            &["no `timestamp` column", "`frames` or a `*_packets` view"],
        ),
        (
            "SELECT * FROM tumble(no_such_table, INTERVAL '10' SECOND)",
            &["not found", "no_such_table"],
        ),
        (
            "SELECT * FROM tumble(frames, INTERVAL '1' MONTH)",
            &["months"],
        ),
        (
            "SELECT * FROM tumble(frames, INTERVAL '0' SECOND)",
            &["positive"],
        ),
        ("SELECT * FROM tumble(frames, 10)", &["INTERVAL"]),
        ("SELECT * FROM tumble(frames)", &["tumble(source, size)"]),
        (
            "SELECT * FROM tumble(frames, length, INTERVAL '1' SECOND)",
            &["Timestamp(Microsecond)", "UInt32"],
        ),
        (
            "SELECT * FROM tumble(frames, nope, INTERVAL '1' SECOND)",
            &["no column 'nope'"],
        ),
        (
            "SELECT * FROM hop(frames, INTERVAL '30' SECOND, INTERVAL '10' SECOND)",
            &["slide", "must not exceed"],
        ),
        (
            "SELECT * FROM session(udp_packets, nope, INTERVAL '1' SECOND)",
            &["no column 'nope'", "key"],
        ),
        (
            "SELECT * FROM session(udp_packets, src_port)",
            &["session(source, key_column, gap)"],
        ),
        (
            "SELECT * FROM tumble(hop(frames, INTERVAL '1' SECOND, INTERVAL '2' SECOND), \
             INTERVAL '10' SECOND)",
            &["cannot be nested", "CREATE VIEW"],
        ),
        (
            "SELECT * FROM tumble(frames, udp.timestamp, INTERVAL '10' SECOND)",
            &["qualified by 'udp'", "not the source 'frames'"],
        ),
        (
            "SELECT * FROM tumble(a.b.c.frames, INTERVAL '10' SECOND)",
            &["too many parts"],
        ),
    ];
    for (sql, needles) in cases {
        let err = error_of(&eng, sql).await;
        for needle in *needles {
            assert!(
                err.contains(needle),
                "{sql}\n  error: {err}\n  missing: {needle}"
            );
        }
    }
}
