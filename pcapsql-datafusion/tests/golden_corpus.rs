//! Golden query corpus: cross-phase result-identity guard.
//!
//! Fixed, hand-crafted captures are queried with a corpus covering every
//! populated protocol table plus joins, aggregates, LIMIT, views, list
//! columns, `raw_data`, VLAN and VXLAN encapsulation, the time UDFs, and
//! queries that reference the same table twice. The second capture uses the
//! Linux "cooked" (SLL) link type, as `tcpdump -i any` writes, so the
//! non-Ethernet link-layer path is guarded too; the routing capture pins the
//! full `SELECT *` column set of the routing and tunnel tables. Results are compared
//! byte-for-byte against checked-in snapshots, so any refactor that changes
//! query results — row content, order, types, or formatting — fails loudly.
//!
//! Regenerate snapshots after an *intentional* change with:
//! ```text
//! PCAPSQL_GOLDEN_UPDATE=1 cargo test -p pcapsql-datafusion --test golden_corpus
//! ```
//! and review the diff like any other code change.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use arrow::util::pretty::pretty_format_batches;
use pcapsql_datafusion::query::{EngineOptions, QueryEngine, RetentionPolicy, SourceSpec};
// The captures and the queries: the corpus both frontends test against.
use pcapsql_testgen::corpus::*;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

async fn engine(path: &Path, partitions: usize) -> QueryEngine {
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
    let batches = engine.query(sql).await.unwrap_or_else(|e| {
        panic!("query failed: {sql}\n{e}");
    });
    pretty_format_batches(&batches).expect("format").to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn golden_corpus_matches_snapshots() {
    let dir = TempDir::new().unwrap();
    let eth_path = dir.path().join("corpus.pcap");
    std::fs::write(&eth_path, corpus_capture()).unwrap();
    let sll_path = dir.path().join("corpus_sll.pcap");
    std::fs::write(&sll_path, sll_capture()).unwrap();
    let sll2_path = dir.path().join("corpus_sll2.pcap");
    std::fs::write(&sll2_path, sll2_capture()).unwrap();
    let http_path = dir.path().join("corpus_http.pcap");
    std::fs::write(&http_path, http_capture()).unwrap();
    let routing_path = dir.path().join("corpus_routing.pcap");
    std::fs::write(&routing_path, routing_capture()).unwrap();
    let tunnels_path = dir.path().join("corpus_tunnels.pcap");
    std::fs::write(&tunnels_path, tunnels_capture()).unwrap();

    let update = std::env::var("PCAPSQL_GOLDEN_UPDATE").is_ok();
    if update {
        std::fs::create_dir_all(golden_dir()).unwrap();
    }

    let eth = (engine(&eth_path, 2).await, engine(&eth_path, 1).await);
    let sll = (engine(&sll_path, 2).await, engine(&sll_path, 1).await);
    let sll2 = (engine(&sll2_path, 2).await, engine(&sll2_path, 1).await);
    let http = (engine(&http_path, 2).await, engine(&http_path, 1).await);
    let routing = (
        engine(&routing_path, 2).await,
        engine(&routing_path, 1).await,
    );
    let tunnels = (
        engine(&tunnels_path, 2).await,
        engine(&tunnels_path, 1).await,
    );
    // One-shot CLI path: RetentionPolicy::None streams rather than
    // materializes. Its results must be identical.
    let streaming = |path: &Path| {
        QueryEngine::open(
            SourceSpec::Path(path.to_path_buf()),
            EngineOptions {
                batch_size: 1000,
                target_partitions: Some(2),
                index_stride: Some(4),
                retention: RetentionPolicy::None,
                ..Default::default()
            },
        )
    };
    let eth_streamed = streaming(&eth_path).await.expect("build streaming engine");
    let sll_streamed = streaming(&sll_path).await.expect("build streaming engine");
    let sll2_streamed = streaming(&sll2_path).await.expect("build streaming engine");
    let http_streamed = streaming(&http_path).await.expect("build streaming engine");
    let routing_streamed = streaming(&routing_path)
        .await
        .expect("build streaming engine");
    let tunnels_streamed = streaming(&tunnels_path)
        .await
        .expect("build streaming engine");

    let mut failures = Vec::new();
    for (capture, name, sql) in CORPUS {
        let path = match capture {
            Capture::Eth => &eth_path,
            Capture::Sll => &sll_path,
            Capture::Sll2 => &sll2_path,
            Capture::Http => &http_path,
            Capture::Routing => &routing_path,
            Capture::Tunnels => &tunnels_path,
        };
        // Fresh engines (materialized and streaming) for queries whose result
        // depends on engine-wide state no earlier query may have established.
        let fresh_engines = if FRESH_ENGINE_QUERIES.contains(name) {
            Some((
                engine(path, 2).await,
                engine(path, 1).await,
                streaming(path).await.expect("build streaming engine"),
            ))
        } else {
            None
        };
        let (e2, e1, streamed) = match (&fresh_engines, capture) {
            (Some(f), _) => (&f.0, &f.1, &f.2),
            (None, Capture::Eth) => (&eth.0, &eth.1, &eth_streamed),
            (None, Capture::Sll) => (&sll.0, &sll.1, &sll_streamed),
            (None, Capture::Sll2) => (&sll2.0, &sll2.1, &sll2_streamed),
            (None, Capture::Http) => (&http.0, &http.1, &http_streamed),
            (None, Capture::Routing) => (&routing.0, &routing.1, &routing_streamed),
            (None, Capture::Tunnels) => (&tunnels.0, &tunnels.1, &tunnels_streamed),
        };
        let got = run(e2, sql).await;

        // Partition-count independence is part of the contract.
        let got_p1 = run(e1, sql).await;
        assert_eq!(
            got, got_p1,
            "{name}: results differ between 1 and 2 partitions"
        );
        // Streaming (one-shot) vs materialized (REPL) must agree.
        let got_stream = run(streamed, sql).await;
        assert_eq!(
            got, got_stream,
            "{name}: streaming result differs from materialized"
        );

        let snap_path = golden_dir().join(format!("{name}.snap"));
        if update {
            std::fs::write(&snap_path, &got).unwrap();
            continue;
        }
        let expected = std::fs::read_to_string(&snap_path).unwrap_or_else(|e| {
            panic!(
                "missing snapshot {} ({e}); run with PCAPSQL_GOLDEN_UPDATE=1 to create",
                snap_path.display()
            )
        });
        if got != expected {
            failures.push(format!(
                "=== {name} ===\n--- expected ---\n{expected}\n--- got ---\n{got}\n"
            ));
        }
    }

    // The whole corpus of a capture at once, from concurrent tasks on one
    // engine, under both retention policies: results must still match the
    // snapshots. Queries that must be the first on a fresh engine are left
    // out.
    if !update {
        let captures = [
            (Capture::Eth, &eth_path),
            (Capture::Sll, &sll_path),
            (Capture::Sll2, &sll2_path),
            (Capture::Http, &http_path),
            (Capture::Routing, &routing_path),
            (Capture::Tunnels, &tunnels_path),
        ];
        for (capture, path) in captures {
            for retention in [RetentionPolicy::CacheOnTouch, RetentionPolicy::None] {
                let eng = Arc::new(
                    QueryEngine::open(
                        SourceSpec::Path(path.to_path_buf()),
                        EngineOptions {
                            batch_size: 1000,
                            target_partitions: Some(2),
                            index_stride: Some(4),
                            retention,
                            ..Default::default()
                        },
                    )
                    .await
                    .expect("build engine"),
                );
                let mut tasks = tokio::task::JoinSet::new();
                for (c, name, sql) in CORPUS {
                    if *c != capture || FRESH_ENGINE_QUERIES.contains(name) {
                        continue;
                    }
                    let eng = eng.clone();
                    tasks.spawn(async move { (*name, run(&eng, sql).await) });
                }
                while let Some(joined) = tasks.join_next().await {
                    let (name, got) = joined.expect("query task");
                    let expected =
                        std::fs::read_to_string(golden_dir().join(format!("{name}.snap")))
                            .expect("snapshot");
                    if got != expected {
                        failures.push(format!(
                            "=== {name} (concurrent, {retention:?}) ===\n\
                             --- expected ---\n{expected}\n--- got ---\n{got}\n"
                        ));
                    }
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "golden corpus mismatches:\n{}",
        failures.join("\n")
    );
}

/// Stream tables are built by a subscriber of the one packet pass: a query
/// mixing a stream table and a packet table reads the capture once, as one
/// partition (reassembly order), and reports which tables pinned it. Under
/// `CacheOnTouch` the stream table is then served from cache.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stream_tables_share_the_packet_pass() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("corpus_http.pcap");
    std::fs::write(&path, http_capture()).unwrap();
    let mixed = "SELECT m.method, t.dst_port FROM http_messages m \
                 JOIN tcp t USING (frame_number) ORDER BY m.frame_number";

    for retention in [RetentionPolicy::CacheOnTouch, RetentionPolicy::None] {
        let eng = QueryEngine::open(
            SourceSpec::Path(path.clone()),
            EngineOptions {
                batch_size: 1000,
                target_partitions: Some(2),
                index_stride: Some(4),
                retention,
                ..Default::default()
            },
        )
        .await
        .expect("open engine");

        let out = run(&eng, mixed).await;
        assert!(out.contains("GET"), "{out}");
        let stats = eng.last_parse_stats();
        assert_eq!(
            stats.parse_passes, 1,
            "{retention:?}: one read for a mixed query"
        );
        assert_eq!(
            stats.partitions, 1,
            "{retention:?}: reassembly pins one partition"
        );
        assert_eq!(stats.stream_tables, vec!["http_messages".to_string()]);
        assert_eq!(stats.rows_built.get("http_messages"), Some(&2));
        assert!(stats.complete_scan);

        // A plain packet query afterwards is not pinned: the same engine
        // splits this capture into its two requested partitions.
        run(&eng, "SELECT count(*) FROM udp").await;
        let stats = eng.last_parse_stats();
        assert!(stats.stream_tables.is_empty());
        assert_eq!(
            stats.partitions, 2,
            "{retention:?}: unpinned query uses both partitions"
        );

        let again = run(&eng, "SELECT count(*) AS n FROM http_messages").await;
        assert!(again.contains("| 2 "), "{again}");
        let stats = eng.last_parse_stats();
        match retention {
            RetentionPolicy::CacheOnTouch => {
                assert_eq!(stats.parse_passes, 0, "stream table served from cache")
            }
            RetentionPolicy::None => {
                assert_eq!(stats.parse_passes, 1);
                assert_eq!(stats.partitions, 1);
            }
        }
    }
}

/// Ethernet trailer padding is not TCP payload: a padded capture must
/// reassemble exactly like the unpadded one (same messages, same byte
/// counts), and the TLS 1.3 negotiation must be read from supported_versions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stream_tables_ignore_ethernet_padding() {
    let dir = TempDir::new().unwrap();
    let plain = dir.path().join("plain.pcap");
    let padded = dir.path().join("padded.pcap");
    std::fs::write(&plain, http_capture()).unwrap();
    std::fs::write(&padded, padded_http_capture()).unwrap();
    assert!(std::fs::metadata(&padded).unwrap().len() > std::fs::metadata(&plain).unwrap().len());

    let queries = [
        "SELECT frame_number, method, status_code, host, content_length FROM http_messages \
         ORDER BY frame_number",
        "SELECT connection_id, bytes_to_server, bytes_to_client, state, duration_us \
         FROM tcp_connections ORDER BY connection_id",
        "SELECT version, cipher_suite, sni, alpn FROM tls_sessions",
    ];
    let (e_plain, e_padded) = (engine(&plain, 1).await, engine(&padded, 1).await);
    for sql in queries {
        let a = run(&e_plain, sql).await;
        let b = run(&e_padded, sql).await;
        assert_eq!(a, b, "padding changed the result of: {sql}\n{a}\n{b}");
    }
    let http = run(&e_padded, "SELECT count(*) AS n FROM http_messages").await;
    assert!(http.contains("| 2 "), "{http}");
    let bytes = run(
        &e_padded,
        "SELECT bytes_to_server FROM tcp_connections WHERE server_port = 80",
    )
    .await;
    assert!(bytes.contains("| 100 "), "{bytes}");
    let tls = run(&e_padded, "SELECT version FROM tls_sessions").await;
    assert!(tls.contains("TLS 1.3"), "{tls}");
}

/// NTP packet (48 bytes): LI=0, VN=4, mode=3 (client), stratum 2, poll 6,
/// precision -20, root delay 0.5 s, root dispersion 0.25 s, ref id
/// 10.0.0.9, transmit timestamp 2023-11-14T22:13:20Z (NTP era 0).
fn ntp_client_packet() -> Vec<u8> {
    let mut p = vec![0x23, 2, 6, 0xEC];
    p.extend_from_slice(&0x0000_8000u32.to_be_bytes()); // root delay 0.5
    p.extend_from_slice(&0x0000_4000u32.to_be_bytes()); // root dispersion 0.25
    p.extend_from_slice(&[10, 0, 0, 9]);
    p.extend_from_slice(&[0u8; 24]); // reference, origin, receive: unset
    let ntp_seconds: u32 = 1_700_000_000 + 2_208_988_800;
    p.extend_from_slice(&ntp_seconds.to_be_bytes());
    p.extend_from_slice(&0x8000_0000u32.to_be_bytes()); // + 0.5 s
    p
}

/// The `ntp` table shipped with Int8/Float64 columns no builder supported,
/// so any capture with NTP failed to materialize. Pin that it works and that
/// the values are in real units.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ntp_table_materializes_with_real_units() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ntp.pcap");
    let frame = eth(
        MAC_B,
        MAC_A,
        ETH_IP4,
        &ipv4(
            [10, 0, 0, 1],
            [10, 0, 0, 9],
            17,
            1,
            &udp(123, 123, &ntp_client_packet()),
        ),
    );
    std::fs::write(&path, to_capture(vec![frame], LINKTYPE_ETHERNET)).unwrap();
    let eng = engine(&path, 1).await;
    let out = run(
        &eng,
        "SELECT version, mode, stratum, poll, precision, root_delay, root_dispersion, \
         reference_id, transmit_ts FROM ntp",
    )
    .await;
    assert!(out.contains("| 4 "), "{out}");
    assert!(out.contains("| -20 "), "precision must be signed: {out}");
    assert!(out.contains("| 0.5 "), "root delay in seconds: {out}");
    assert!(out.contains("| 0.25 "), "root dispersion in seconds: {out}");
    assert!(out.contains("10.0.0.9"), "{out}");
    assert!(
        out.contains("1700000000.5"),
        "transmit_ts as Unix seconds: {out}"
    );
    // SELECT * exercises every column's builder.
    let all = run(&eng, "SELECT * FROM ntp").await;
    assert!(all.contains("| 2 "), "{all}");
}

// ---------------------------------------------------------------------------
// The `*_packets` views against the shared fused scans
// ---------------------------------------------------------------------------

/// The rows of `batches` as text, a string per cell, NULL spelled out.
fn row_texts(batches: &[arrow::record_batch::RecordBatch]) -> Vec<Vec<String>> {
    use arrow::util::display::{ArrayFormatter, FormatOptions};
    let options = FormatOptions::default().with_null("NULL");
    let mut rows = Vec::new();
    for batch in batches {
        let columns: Vec<ArrayFormatter<'_>> = batch
            .columns()
            .iter()
            .map(|column| ArrayFormatter::try_new(column.as_ref(), &options).expect("formatter"))
            .collect();
        for row in 0..batch.num_rows() {
            rows.push(columns.iter().map(|c| c.value(row).to_string()).collect());
        }
    }
    rows
}

/// The rows of a view as `pcapsql_core::scan` defines it: one pass over the
/// capture at `path` with the view's fused scan as the only output, into an
/// Arrow sink small enough to fill in the middle of a frame.
fn fused_view(
    path: &Path,
    view: &pcapsql_core::scan::PacketsView,
) -> (arrow::datatypes::Schema, Vec<Vec<String>>) {
    use pcapsql_core::io::{ReadPacketReader, StreamHeader};
    use pcapsql_core::scan::{Catalog, PartitionScan, ScanPlan, Step, TimestampUnit};
    use pcapsql_datafusion::query::arrow_schema::out_columns_to_arrow_schema;
    use pcapsql_datafusion::query::builders::ArrowSink;

    let registry = Arc::new(pcapsql_core::default_registry());
    let plan = ScanPlan {
        fused: vec![view.full_scan()],
        timestamps: TimestampUnit::Micros,
        ..ScanPlan::default()
    }
    .compile(Catalog::builtin(), &registry)
    .expect("the view compiles");
    let columns = plan.outputs()[0].columns.clone();
    let schema = out_columns_to_arrow_schema(&columns);
    let mut sink = ArrowSink::new(&columns, 3);

    let mut file = std::io::BufReader::new(std::fs::File::open(path).expect("open the capture"));
    let (header, head) = StreamHeader::probe(&mut file).expect("probe the capture");
    let reader = ReadPacketReader::sequential(file, &header, head).expect("a reader");
    let mut scan = PartitionScan::new(reader, Arc::new(plan), registry);
    let mut batches = Vec::new();
    loop {
        match scan
            .step(std::slice::from_mut(&mut sink), 64)
            .expect("step")
        {
            Step::More => {}
            Step::Flush(_) => batches.extend(sink.take_batch().expect("a batch")),
            Step::Done | Step::End => break,
        }
    }
    batches.extend(sink.take_batch().expect("a batch"));
    (schema, row_texts(&batches))
}

/// Captures of real traffic, from the reader's fuzz corpus: protocols and
/// encapsulations the hand-made corpus does not have.
const REAL_CAPTURES: &[&str] = &[
    "NTP_sync.pcap",
    "arp-storm.pcap",
    "dhcp.pcap",
    "dns.cap",
    "gre_keyed.pcap",
    "gtp_user.pcap",
    "http.pcap",
    "ipinip.pcap",
    "ipv4frags.pcap",
    "ldap-ssl.pcapng",
    "tcp-ecn-sample.pcap",
    "tls12-dsb.pcapng",
    "triple_encap_vxlan_ipinip.pcap",
    "v6-http.cap",
    "v6.pcap",
    "vxlan_simple.pcap",
];

/// Every `*_packets` view that `pcapsql_core::scan` defines as a fused scan
/// (`PacketsView`, what the DuckDB extension's `read_<proto>_packets`
/// return) holds exactly what the SQL view of the same name holds here: the
/// same columns (names, order, types) and the same rows, NULLs included.
///
/// The SQL view is evaluated by DataFusion's joins (the caching engine does
/// not fuse). Its rows have no order of their own, so they are compared in
/// `ORDER BY frame_number, encap_depth`, which is the order the fused scan
/// produces by itself; rows that tie on both are compared as a set. The
/// one-shot engine, whose optimizer fuses the view's joins onto the same
/// core evaluator, must agree too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn packets_views_equal_the_shared_fused_scans() {
    use pcapsql_core::scan::PacketsView;
    use pcapsql_datafusion::query::views;

    // The same set of views: every SQL view that is a join of one
    // encapsulation level, under the same name and description.
    let not_fused = ["tunneled_packets", "ip4_in_ip6", "ip6_in_ip6", "packets"];
    let sql_views: Vec<_> = views::all_views()
        .into_iter()
        .filter(|view| !not_fused.contains(&view.name))
        .collect();
    assert_eq!(
        sql_views.iter().map(|v| v.name).collect::<Vec<_>>(),
        PacketsView::all()
            .iter()
            .map(|v| v.name)
            .collect::<Vec<_>>()
    );
    for (sql, fused) in sql_views.iter().zip(PacketsView::all()) {
        assert_eq!(sql.description, fused.description, "{}", sql.name);
    }

    let dir = TempDir::new().unwrap();
    let mut captures: Vec<(String, PathBuf)> = Vec::new();
    for (name, bytes) in [
        ("eth", corpus_capture()),
        ("sll", sll_capture()),
        ("sll2", sll2_capture()),
        ("http", http_capture()),
        ("routing", routing_capture()),
        ("tunnels", tunnels_capture()),
        ("views", views_capture()),
    ] {
        let path = dir.path().join(format!("{name}.pcap"));
        std::fs::write(&path, bytes).unwrap();
        captures.push((name.to_owned(), path));
    }
    let real = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fuzz/corpus/fuzz_pcap_reader");
    for name in REAL_CAPTURES {
        captures.push(((*name).to_owned(), real.join(name)));
    }

    let mut failures = Vec::new();
    let mut rows_per_view = std::collections::BTreeMap::new();
    let mut ties = 0;
    for (capture, path) in &captures {
        let joined = engine(path, 2).await;
        let streamed = QueryEngine::open(
            SourceSpec::Path(path.clone()),
            EngineOptions {
                batch_size: 1000,
                target_partitions: Some(2),
                index_stride: Some(4),
                retention: RetentionPolicy::None,
                ..Default::default()
            },
        )
        .await
        .expect("build streaming engine");
        for view in PacketsView::all() {
            let case = format!("{} over {capture}", view.name);
            let (schema, fused) = fused_view(path, view);

            // The columns.
            let table = joined.context().table(view.name).await.expect("the view");
            let declared: Vec<(String, arrow::datatypes::DataType)> = table
                .schema()
                .fields()
                .iter()
                .map(|f| (f.name().clone(), f.data_type().clone()))
                .collect();
            let ours: Vec<(String, arrow::datatypes::DataType)> = schema
                .fields()
                .iter()
                .map(|f| (f.name().clone(), f.data_type().clone()))
                .collect();
            if declared != ours {
                failures.push(format!("{case}: columns {declared:?} != {ours:?}"));
                continue;
            }
            let position = |name: &str| ours.iter().position(|(n, _)| n == name).unwrap();
            let (frame, depth) = (position("frame_number"), position("encap_depth"));
            let key = |row: &Vec<String>| -> (u64, u64) {
                (row[frame].parse().unwrap(), row[depth].parse().unwrap())
            };

            // The fused scan's own order.
            let keys: Vec<(u64, u64)> = fused.iter().map(key).collect();
            if !keys.is_sorted() {
                failures.push(format!("{case}: the fused rows are not in capture order"));
            }
            ties += keys.windows(2).filter(|pair| pair[0] == pair[1]).count();
            let mut fused_sorted = fused.clone();
            fused_sorted.sort();
            *rows_per_view.entry(view.name).or_insert(0usize) += fused.len();

            let sql = format!(
                "SELECT * FROM {} ORDER BY frame_number, encap_depth",
                view.name
            );
            for (engine, which) in [(&joined, "joins"), (&streamed, "one-shot")] {
                let batches = engine
                    .query(&sql)
                    .await
                    .unwrap_or_else(|e| panic!("{case}: {e}"));
                let rows = row_texts(&batches);
                if rows.iter().map(key).collect::<Vec<_>>() != keys {
                    failures.push(format!(
                        "{case} ({which}): {} rows in another order than the fused scan's {}",
                        rows.len(),
                        fused.len()
                    ));
                    continue;
                }
                let mut rows_sorted = rows;
                rows_sorted.sort();
                if let Some(n) = (0..rows_sorted.len()).find(|&n| rows_sorted[n] != fused_sorted[n])
                {
                    failures.push(format!(
                        "{case} ({which}): a row differs\n  view:  {:?}\n  fused: {:?}",
                        rows_sorted[n], fused_sorted[n]
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} differences:\n{}",
        failures.len(),
        failures.join("\n")
    );
    // The comparison is not of empty tables: every view has rows somewhere.
    let empty: Vec<_> = rows_per_view
        .iter()
        .filter(|(_, rows)| **rows == 0)
        .map(|(name, _)| *name)
        .collect();
    assert!(empty.is_empty(), "no capture has rows for {empty:?}");
    eprintln!(
        "rows per view: {rows_per_view:?}; rows tying on (frame_number, encap_depth): {ties}"
    );
}
