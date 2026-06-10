//! End-to-end tests for the shared single-parse-pass engine path (#6) and
//! 1-vs-N partition equivalence at the SQL layer (#9).

use arrow::util::pretty::pretty_format_batches;
use pcapsql_datafusion::query::{EngineOptions, QueryEngine, RetentionPolicy, SourceSpec};
use pcapsql_testgen::{legacy_pcap, GenPacket, GeneratedCapture, LegacyVariant};
use tempfile::TempDir;

/// Build a minimal valid Ethernet/IPv4/UDP frame so the ethernet/ipv4/udp
/// tables actually populate.
fn udp_packet(src_port: u16, dst_port: u16, payload_len: usize) -> Vec<u8> {
    let mut p = Vec::new();
    // Ethernet
    p.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // dst mac
    p.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src mac
    p.extend_from_slice(&[0x08, 0x00]); // ethertype IPv4
                                        // IPv4
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
                                            // UDP
    let udp_len = (8 + payload_len) as u16;
    p.extend_from_slice(&src_port.to_be_bytes());
    p.extend_from_slice(&dst_port.to_be_bytes());
    p.extend_from_slice(&udp_len.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]); // checksum 0
    p.extend(std::iter::repeat_n(0xAB, payload_len));
    p
}

fn make_capture(n: usize) -> GeneratedCapture {
    let packets: Vec<GenPacket> = (0..n)
        .map(|i| {
            let data = udp_packet(10_000 + i as u16, 53, 8);
            let origlen = data.len() as u32;
            GenPacket {
                ts_sec: 1_700_000_000 + i as u32,
                ts_frac: (i as u32 * 137) % 1_000_000,
                data,
                origlen,
            }
        })
        .collect();
    legacy_pcap(LegacyVariant::LeMicro, 1, 65535, &packets)
}

async fn engine(path: &std::path::Path, partitions: usize) -> QueryEngine {
    QueryEngine::open(
        SourceSpec::Path(path.to_path_buf()),
        EngineOptions {
            batch_size: 1000,
            target_partitions: Some(partitions),
            index_stride: Some(4),
            ..Default::default()
        },
    )
    .await
    .expect("build engine")
}

async fn run(engine: &QueryEngine, sql: &str) -> String {
    let batches = engine.query(sql).await.expect("query ok");
    pretty_format_batches(&batches).expect("format").to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_parse_one_pass_and_partition_equivalence() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("cap.pcap");
    std::fs::write(&path, make_capture(60).bytes).unwrap();

    let e1 = engine(&path, 1).await;
    let e4 = engine(&path, 4).await;

    // A query touching multiple protocol tables performs exactly ONE parse
    // pass over the file, not one per table — the shared-parse invariant.
    let _ = run(
        &e4,
        "SELECT f.frame_number, u.dst_port \
         FROM frames f JOIN udp u USING (frame_number) \
         JOIN ipv4 v USING (frame_number)",
    )
    .await;
    let stats = e4.last_parse_stats();
    assert_eq!(
        stats.parse_passes, 1,
        "shared parse must perform exactly one pass regardless of tables touched"
    );
    assert!(
        stats.partitions >= 2,
        "mmap (SeekCost::Free) should split into multiple partitions, got {}",
        stats.partitions
    );
    assert_eq!(stats.rows_built.get("frames"), Some(&60));
    assert_eq!(stats.rows_built.get("udp"), Some(&60));

    let _ = run(&e1, "SELECT count(*) AS c FROM frames").await;
    assert_eq!(e1.last_parse_stats().partitions, 1);

    // The default retention (CacheOnTouch) serves repeat queries with no
    // further parsing.
    let _ = run(&e4, "SELECT count(*) AS c FROM udp").await;
    assert_eq!(
        e4.last_parse_stats().parse_passes,
        0,
        "cached tables must not re-parse"
    );

    // 1-vs-N partition equivalence at the SQL layer: identical rows, identical
    // order, for frames, protocol tables and a join.
    let queries = [
        "SELECT count(*) AS c FROM frames",
        "SELECT count(*) AS c FROM udp",
        "SELECT count(*) AS c FROM ipv4",
        "SELECT frame_number, length FROM frames ORDER BY frame_number",
        "SELECT frame_number, src_port, dst_port FROM udp ORDER BY frame_number",
        "SELECT f.frame_number, u.src_port FROM frames f \
         JOIN udp u USING (frame_number) ORDER BY f.frame_number",
    ];
    for sql in queries {
        let r1 = run(&e1, sql).await;
        let r4 = run(&e4, sql).await;
        assert_eq!(r1, r4, "1-vs-N partition mismatch for: {sql}");
    }

    // Sanity: the data actually populated the protocol tables.
    let frames = run(&e1, "SELECT count(*) AS c FROM frames").await;
    assert!(frames.contains("60"), "expected 60 frames:\n{frames}");
    let udp = run(&e1, "SELECT count(*) AS c FROM udp").await;
    assert!(udp.contains("60"), "expected 60 udp rows:\n{udp}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scoped_parse_builds_only_referenced_tables() {
    // RetentionPolicy::None scopes the parse to the query's tables: a query
    // over `udp` must materialize only `udp` (its L2/L3 dependencies are
    // parsed for routing but not built as tables, and unrelated app
    // protocols like `tls` are never even parsed).
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("cap.pcap");
    std::fs::write(&path, make_capture(40).bytes).unwrap();

    let engine = QueryEngine::open(
        SourceSpec::Path(path.clone()),
        EngineOptions {
            batch_size: 1000,
            target_partitions: Some(4),
            index_stride: Some(4),
            retention: RetentionPolicy::None,
            ..Default::default()
        },
    )
    .await
    .expect("build engine");

    let out = run(
        &engine,
        "SELECT dst_port FROM udp ORDER BY dst_port LIMIT 1",
    )
    .await;
    assert!(out.contains("53"), "expected udp rows:\n{out}");

    let stats = engine.last_parse_stats();
    assert_eq!(stats.parse_passes, 1);
    // Only the referenced table is materialized.
    let built: Vec<&String> = stats
        .rows_built
        .iter()
        .filter(|(_, n)| **n > 0)
        .map(|(t, _)| t)
        .collect();
    assert_eq!(built, vec![&"udp".to_string()], "scoped to udp only");
    assert!(
        !stats.rows_built.contains_key("tcp") && !stats.rows_built.contains_key("tls"),
        "unreferenced protocols must not be materialized: {:?}",
        stats.rows_built.keys().collect::<Vec<_>>()
    );

    // RetentionPolicy::None retains nothing: the next query re-parses.
    let _ = run(&engine, "SELECT count(*) AS c FROM frames").await;
    assert_eq!(engine.last_parse_stats().parse_passes, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn empty_capture_yields_zero_rows() {
    // A header-only legacy capture with no packets is a valid (empty)
    // capture: open succeeds and queries see zero rows.
    let gc = legacy_pcap(LegacyVariant::LeMicro, 1, 65535, &[]);
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("empty.pcap");
    std::fs::write(&path, gc.bytes).unwrap();
    let engine = QueryEngine::open(
        SourceSpec::Path(path.clone()),
        EngineOptions {
            batch_size: 1000,
            target_partitions: Some(4),
            ..Default::default()
        },
    )
    .await
    .expect("empty capture opens");
    let out = run(&engine, "SELECT count(*) AS c FROM frames").await;
    assert!(out.contains("0"), "expected zero frames:\n{out}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http2_stream_table_is_on_demand() {
    // `http2` is produced by the stream-analysis pass, not the packet parse,
    // and only when a query references it. This capture has no HTTP/2, so the
    // pass runs and yields an empty table (no error).
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("cap.pcap");
    std::fs::write(&path, make_capture(50).bytes).unwrap();

    // A query that does NOT reference http2 must not run the stream pass.
    let e1 = engine(&path, 2).await;
    let _ = run(&e1, "SELECT count(*) AS c FROM udp").await;
    assert!(
        !e1.last_parse_stats().rows_built.contains_key("http2"),
        "stream pass must not run for a non-stream query"
    );

    // Referencing http2 runs the stream pass on demand and returns empty.
    let e2 = engine(&path, 2).await;
    let out = run(&e2, "SELECT count(*) AS c FROM http2").await;
    assert!(out.contains('0'), "expected empty http2:\n{out}");
    assert!(
        e2.last_parse_stats().rows_built.contains_key("http2"),
        "querying http2 must run the stream pass"
    );
}

/// Build a streaming (RetentionPolicy::None) engine.
async fn streaming_engine(path: &std::path::Path, partitions: usize) -> QueryEngine {
    QueryEngine::open(
        SourceSpec::Path(path.to_path_buf()),
        EngineOptions {
            batch_size: 64,
            target_partitions: Some(partitions),
            index_stride: Some(8),
            retention: RetentionPolicy::None,
            ..Default::default()
        },
    )
    .await
    .expect("build engine")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn streaming_results_match_materialized() {
    // The streaming path (None) must produce identical results to the
    // materialized path (CacheOnTouch), across scans, filters and joins.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("cap.pcap");
    std::fs::write(&path, make_capture(200).bytes).unwrap();

    let streamed = streaming_engine(&path, 4).await;
    let materialized = engine(&path, 4).await; // default CacheOnTouch

    for sql in [
        "SELECT count(*) AS c FROM frames",
        "SELECT count(*) AS c FROM udp",
        "SELECT frame_number, length FROM frames ORDER BY frame_number",
        "SELECT frame_number, src_port, dst_port FROM udp WHERE dst_port = 53 \
         ORDER BY frame_number",
        "SELECT f.frame_number, u.src_port FROM frames f \
         JOIN udp u USING (frame_number) ORDER BY f.frame_number",
    ] {
        let s = run(&streamed, sql).await;
        let m = run(&materialized, sql).await;
        assert_eq!(s, m, "streaming vs materialized mismatch for: {sql}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn streaming_limit_stops_scan_early() {
    // A LIMIT pushed to the scan caps each partition and stops the parse
    // before consuming the whole capture.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("cap.pcap");
    std::fs::write(&path, make_capture(5000).bytes).unwrap();

    let engine = streaming_engine(&path, 1).await;
    let out = run(&engine, "SELECT frame_number FROM udp LIMIT 5").await;
    assert!(out.contains('1'), "expected rows:\n{out}");

    let stats = engine.last_parse_stats();
    assert!(
        !stats.complete_scan,
        "LIMIT should stop the scan early (packets_scanned = {})",
        stats.packets_scanned
    );
    assert!(
        stats.packets_scanned < 5000,
        "LIMIT should read far fewer than all packets, read {}",
        stats.packets_scanned
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn streaming_hash_join_completes_without_deadlock() {
    // A hash join drains one side fully before the other — the unbounded
    // exchange must not deadlock (it degrades to buffering). The result must
    // still match the materialized engine.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("cap.pcap");
    std::fs::write(&path, make_capture(300).bytes).unwrap();

    let streamed = streaming_engine(&path, 4).await;
    streamed
        .context()
        .state_ref()
        .write()
        .config_mut()
        .options_mut()
        .optimizer
        .prefer_hash_join = true;

    let sql = "SELECT f.frame_number, u.dst_port FROM frames f \
               JOIN udp u USING (frame_number) ORDER BY f.frame_number";
    let s = run(&streamed, sql).await;

    let materialized = engine(&path, 4).await;
    let m = run(&materialized, sql).await;
    assert_eq!(s, m, "hash-join streaming result must match materialized");
}
