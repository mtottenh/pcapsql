//! `read_<proto>_packets`: the `*_packets` views of the shared scan layer, each scanned in one
//! pass as a fused scan.
//!
//! A view is a join: `tcp_packets` is `frames` joined with `tcp` on `frame_number`, and with
//! `ethernet`, `ipv4` and `ipv6` on `(frame_number, encap_depth)`. The scan layer evaluates it
//! frame by frame, and DuckDB sees one table function. What it must return is checked against
//! two references:
//!
//! - **the join, run by DuckDB**: the same join written in SQL over `read_<table>` functions,
//!   one scan per table, generated from the view's definition
//!   (`pcapsql_core::scan::PacketsView`). The rows are the same, in the same order (the join is
//!   ordered by frame and encapsulation level, which is the order a view scan returns by
//!   itself);
//! - **the scan layer alone**: core's driver over the same bytes into a recording sink, cell by
//!   cell with typed reads, which pins down what the extension adds: columns, types, chunks.
//!
//! Both hold on one thread and on four, with captures split into partitions and not, with the
//! filters on `frame_number` and `timestamp` used by the scan and with DuckDB alone applying
//! them. The captures are those of the golden corpus, real ones, and generated ones of several
//! chunks. (That the definitions are the DataFusion frontend's SQL views is that frontend's test:
//! `packets_views_equal_the_shared_fused_scans`, over the same captures.)
//!
//! The rest is that a view function is a scan function like any other: several files, the
//! `filename` column, `strict`, `read_pcap(protocol := ...)`, `pcap_schema`, and `pcap_views()`.

use duckdb_neo::{connection::Connection, Parameters, Result};
use pcapsql_core::scan::{testing::Cell, Catalog, ColKind, FusedValue, JoinKind, PacketsView};
use pcapsql_duckdb_itest::{
    column, connect, golden, reference_rows, reference_view_rows, replay::query_cells, rows, value,
    Fixture,
};

fn execute(connection: &Connection, sql: &str) {
    connection
        .execute(sql, Parameters::None)
        .unwrap_or_else(|error| panic!("{sql}: {error}"));
}

fn set(connection: &Connection, setting: &str, value: impl std::fmt::Display) {
    execute(connection, &format!("SET {setting} = {value}"));
}

/// How a scan is run: the number of threads, and whether captures are split.
const LAYOUTS: [(usize, bool); 4] = [(1, false), (4, false), (4, true), (1, true)];

/// Run scans on `threads` threads, with captures of any size cut at checkpoints `stride`
/// frames apart when `split`, and whole when not.
fn lay_out(connection: &Connection, (threads, split): (usize, bool), stride: u64) {
    set(connection, "pcapsql_parallel_scan", split);
    set(connection, "pcapsql_parallel_min_file_size", 0);
    set(connection, "pcapsql_index_stride", stride);
    set(connection, "threads", threads);
}

fn pushdown(connection: &Connection, on: bool) {
    set(connection, "pcapsql_filter_pushdown", on);
}

/// The DEBUG records the extension logged since the log was last cleared, oldest first.
fn logged(connection: &Connection) -> Vec<String> {
    let records = column(
        connection,
        "SELECT message FROM duckdb_logs WHERE type = 'pcapsql' AND log_level = 'DEBUG' \
         ORDER BY timestamp, context_id",
    )
    .unwrap();
    execute(connection, "CALL truncate_duckdb_logs()");
    records
}

/// `count` UDP frames; every fifth is inside VXLAN and every seventh inside two.
fn mixed_frames(count: u32) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| match i {
            _ if i % 7 == 6 => golden::nested_vxlan_frame(i),
            _ if i % 5 == 4 => golden::vxlan_frame(i),
            _ => golden::udp_frame(i),
        })
        .collect()
}

/// A capture file of the tests.
struct Capture {
    name: String,
    path: String,
    bytes: Vec<u8>,
    /// How far apart the places are at which a split scan may cut it.
    stride: u64,
    /// One of [`REAL_CAPTURES`]. These are compared in the two layouts furthest apart only:
    /// they are there for their protocols, not for where a scan is cut.
    real: bool,
}

impl Capture {
    fn frames(&self) -> usize {
        reference_rows(&self.bytes, "frames").1.len()
    }
}

/// Captures of real traffic, from the seeds of the reader's fuzzer: protocols and
/// encapsulations the hand-made captures do not have (DHCP, NTP, SSH, GRE, ICMPv6 with NDP and
/// MLD, IP in IP). They are the ones the DataFusion frontend compares its views over.
const REAL_CAPTURES: [&str; 16] = [
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

/// The captures the views are compared over: those of the golden corpus, the capture of the
/// protocols the corpus lacks, the real ones, and a generated one of `mixed` frames, which
/// fills several chunks and has frames with two and three rows per view at the places it is
/// cut.
fn captures(fixture: &Fixture, mixed: u32) -> Vec<Capture> {
    let mut captures: Vec<Capture> = golden::VIEW_CAPTURES
        .iter()
        .map(|name| {
            let bytes = golden::capture(name);
            Capture {
                name: (*name).to_owned(),
                path: fixture.write(&format!("{name}.pcap"), &bytes),
                bytes,
                stride: 2,
                real: false,
            }
        })
        .collect();
    let seeds =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/fuzz_pcap_reader");
    for name in REAL_CAPTURES {
        let path = seeds.join(name);
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        captures.push(Capture {
            name: name.to_owned(),
            // A copy: the path of the repository is not ours to put between quotes.
            path: fixture.write(&format!("real-{name}"), &bytes),
            bytes,
            stride: 4,
            real: true,
        });
    }
    let bytes = golden::pcapng(mixed_frames(mixed));
    captures.push(Capture {
        name: "mixed".to_owned(),
        path: fixture.write("mixed.pcapng", &bytes),
        bytes,
        stride: 64,
        real: false,
    });
    captures
}

/// `name` as an SQL identifier.
fn quoted(name: &str) -> String {
    format!("\"{name}\"")
}

/// The view as a join DuckDB runs: one scan function per table, joined as the view's
/// definition says, with its columns under their names, its filter, and `filter` (a condition
/// on the frame, which is `f` here) besides. The rows are ordered by frame and by the level of
/// the anchor.
fn join_sql(view: &PacketsView, path: &str, filter: &str) -> String {
    let catalog = Catalog::builtin();
    let members = view.members();
    let table_column = |member: u16, column| {
        let member = &members[usize::from(member)];
        let name = catalog.get(member.member.table).get(column).name;
        format!("{}.{}", quoted(member.alias), quoted(name))
    };
    let select: Vec<String> = view
        .columns()
        .iter()
        .enumerate()
        .map(|(index, column)| {
            let value = match view.value(index) {
                FusedValue::Column { member, column } => table_column(*member, *column),
                FusedValue::Coalesce(arguments) => {
                    let arguments: Vec<String> = arguments
                        .iter()
                        .map(|(member, column)| table_column(*member, *column))
                        .collect();
                    format!("COALESCE({})", arguments.join(", "))
                }
                FusedValue::Present { cases, otherwise } => {
                    let whens: Vec<String> = cases
                        .iter()
                        .map(|(member, label)| {
                            format!(
                                "WHEN {}.frame_number IS NOT NULL THEN '{label}'",
                                quoted(members[usize::from(*member)].alias)
                            )
                        })
                        .collect();
                    format!("CASE {} ELSE '{otherwise}' END", whens.join(" "))
                }
            };
            format!("{value} AS {}", quoted(column.name))
        })
        .collect();
    let mut from = String::new();
    for member in members {
        let scan = format!("read_{}('{path}') {}", member.table, quoted(member.alias));
        match member.member.join {
            None => from.push_str(&scan),
            Some(join) => {
                let this = quoted(member.alias);
                let with = quoted(members[join.with].alias);
                let kind = match join.kind {
                    JoinKind::Inner => "JOIN",
                    JoinKind::Left => "LEFT JOIN",
                };
                let depth = if join.depth {
                    format!(" AND {this}.encap_depth = {with}.encap_depth")
                } else {
                    String::new()
                };
                from.push_str(&format!(
                    " {kind} {scan} ON {this}.frame_number = {with}.frame_number{depth}"
                ));
            }
        }
    }
    let mut conditions = Vec::new();
    if let Some(filter) = view.filter() {
        let values: Vec<String> = filter.any_of.iter().map(i64::to_string).collect();
        conditions.push(format!(
            "{} IN ({})",
            table_column(filter.member, filter.column),
            values.join(", ")
        ));
    }
    if !filter.is_empty() {
        conditions.push(filter.to_owned());
    }
    let condition = if conditions.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conditions.join(" AND "))
    };
    format!(
        "SELECT {} FROM {from}{condition} ORDER BY \"f\".frame_number, {}.encap_depth",
        select.join(", "),
        quoted(members[1].alias)
    )
}

/// The `(frame_number, encap_depth)` of every row of a view's result as text.
fn keys(view: &PacketsView, rows: &[Vec<String>]) -> Vec<(u64, u64)> {
    let position = |name: &str| {
        view.columns()
            .iter()
            .position(|column| column.name == name)
            .unwrap()
    };
    let (frame, depth) = (position("frame_number"), position("encap_depth"));
    rows.iter()
        .map(|row| (row[frame].parse().unwrap(), row[depth].parse().unwrap()))
        .collect()
}

/// Assert that `actual`, the rows of a scan of `view`, are those of `expected`, the rows of its
/// join in frame and level order: in that order, and the same rows. Rows that tie on frame and
/// level have no order in the join and are compared as a set.
fn assert_is_the_join(
    view: &PacketsView,
    actual: &[Vec<String>],
    expected: &[Vec<String>],
    what: &str,
) {
    assert_eq!(
        actual.len(),
        expected.len(),
        "{what}: the number of rows of the scan, and of the join"
    );
    assert!(
        keys(view, actual) == keys(view, expected),
        "{what}: the rows are in another order than the join's"
    );
    let (mut actual, mut expected) = (actual.to_vec(), expected.to_vec());
    actual.sort();
    expected.sort();
    assert!(
        actual == expected,
        "{what}: the first row that differs (scan, join): {:?}",
        actual.iter().zip(&expected).find(|(a, e)| a != e)
    );
}

/// Filters on the frame for a capture of `frames` frames, as a scan of a view takes them and
/// as the join takes them (where the frame is `f`): none, a range of frame numbers, a lower
/// bound in time, and both.
fn frame_filters(connection: &Connection, capture: &Capture) -> Vec<(String, String)> {
    let frames = capture.frames();
    let (low, high) = (frames / 4, frames - frames / 4);
    // The time of a frame a third of the way in, as DuckDB writes it.
    let time = value(
        connection,
        &format!(
            "SELECT timestamp::VARCHAR FROM read_frames('{}') WHERE frame_number = {}",
            capture.path,
            (frames / 3).max(1)
        ),
    )
    .unwrap();
    let both = |column: &dyn Fn(&str) -> String| -> Vec<String> {
        vec![
            String::new(),
            format!(
                "{} > {low} AND {} <= {high}",
                column("frame_number"),
                column("frame_number")
            ),
            format!("{} >= TIMESTAMP_NS '{time}'", column("timestamp")),
            format!(
                "{} < TIMESTAMP_NS '{time}' AND {} >= 2",
                column("timestamp"),
                column("frame_number")
            ),
        ]
    };
    both(&|name| name.to_owned())
        .into_iter()
        .zip(both(&|name| format!("\"f\".{name}")))
        .collect()
}

#[test]
fn every_view_is_the_join_of_its_tables_as_duckdb_runs_it() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let mut with_rows = std::collections::BTreeSet::new();
    let (mut compared, mut filtered_rows) = (0, 0);
    let captures = captures(&fixture, 1500);
    for capture in &captures {
        let mut filters = frame_filters(&connection, capture);
        if capture.real {
            // The whole view and the frame range.
            filters.truncate(2);
        }
        for view in PacketsView::all() {
            for (number, (scan_filter, join_filter)) in filters.iter().enumerate() {
                // The join, with DuckDB applying every filter to whole scans on one thread.
                lay_out(&connection, (1, false), capture.stride);
                pushdown(&connection, false);
                let join = join_sql(view, &capture.path, join_filter);
                let expected =
                    rows(&connection, &join).unwrap_or_else(|error| panic!("{join}: {error}"));
                if !expected.is_empty() {
                    with_rows.insert(view.name);
                    filtered_rows += usize::from(number > 0) * expected.len();
                }

                let condition = match scan_filter.as_str() {
                    "" => String::new(),
                    filter => format!(" WHERE {filter}"),
                };
                let scan = format!(
                    "SELECT * FROM read_{}('{}'){condition}",
                    view.name, capture.path
                );
                // Every layout for the whole view and for the frame range; the two furthest
                // apart for the filters in time, and for the real captures.
                let layouts = if number < 2 && !capture.real {
                    &LAYOUTS[..]
                } else {
                    &[LAYOUTS[0], LAYOUTS[2]][..]
                };
                for &layout in layouts {
                    lay_out(&connection, layout, capture.stride);
                    for taken_over in [true, false] {
                        pushdown(&connection, taken_over);
                        let actual = rows(&connection, &scan)
                            .unwrap_or_else(|error| panic!("{scan}: {error}"));
                        let what = format!(
                            "{scan} over {} on {} threads, split: {}, pushdown: {taken_over}",
                            capture.name, layout.0, layout.1
                        );
                        assert_is_the_join(view, &actual, &expected, &what);
                        compared += 1;
                    }
                }
            }
        }
    }
    // Every view has rows in some capture, and the filters left rows to compare.
    let all: std::collections::BTreeSet<&str> =
        PacketsView::all().iter().map(|view| view.name).collect();
    assert_eq!(with_rows, all);
    assert!(filtered_rows > 1000, "{filtered_rows}");
    assert_eq!(captures.len(), 7 + 16 + 1);
    assert_eq!(compared, 21 * (8 * (2 * 4 + 2 * 2) + 16 * 2 * 2) * 2);
    Ok(())
}

/// Assert that `sql` returns exactly `expected`, in order, read as `kinds`.
fn assert_cells(connection: &Connection, sql: &str, kinds: &[ColKind], expected: &[Vec<Cell>]) {
    let actual =
        query_cells(connection, sql, kinds).unwrap_or_else(|error| panic!("{sql}: {error}"));
    assert_eq!(actual.len(), expected.len(), "{sql}: number of rows");
    for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
        assert_eq!(actual, expected, "{sql}: row {index}");
    }
}

#[test]
fn every_view_returns_the_cells_of_the_scan_layer() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    execute(&connection, "CALL enable_logging(level = 'debug')");
    let mut rows_of_all = 0;
    for capture in captures(&fixture, 6000) {
        for view in PacketsView::all() {
            let (columns, expected) = reference_view_rows(&capture.bytes, view);
            let kinds: Vec<ColKind> = columns.iter().map(|column| column.kind).collect();
            rows_of_all += expected.len();

            // The columns DuckDB sees are the view's, in this engine's types.
            let function = format!("read_{}('{}')", view.name, capture.path);
            let described = rows(
                &connection,
                &format!("SELECT column_name FROM (DESCRIBE SELECT * FROM {function})"),
            )?;
            let names: Vec<&str> = described.iter().map(|row| row[0].as_str()).collect();
            let declared: Vec<&str> = view.columns().iter().map(|column| column.name).collect();
            assert_eq!(names, declared, "{function}");

            let layouts = if capture.real {
                &[LAYOUTS[0], LAYOUTS[2]][..]
            } else {
                &LAYOUTS[..]
            };
            for &layout in layouts {
                lay_out(&connection, layout, capture.stride);
                logged(&connection);
                assert_cells(
                    &connection,
                    &format!("SELECT * FROM {function}"),
                    &kinds,
                    &expected,
                );
                // One scan of the capture, split when asked to and when there is a place to.
                let records = logged(&connection);
                let scans: Vec<&String> = records
                    .iter()
                    .filter(|record| record.contains("': partitions: "))
                    .collect();
                assert_eq!(scans.len(), 1, "{function}: {records:?}");
                assert!(
                    scans[0].starts_with(&format!("read_{}: scanning", view.name)),
                    "{}",
                    scans[0]
                );
                if layout == (4, true) && capture.frames() >= 8 {
                    assert!(
                        !scans[0].contains("partitions: 1 "),
                        "{function}: {}",
                        scans[0]
                    );
                }
                if layout != LAYOUTS[0] && layout != LAYOUTS[2] {
                    continue;
                }
                // The count needs no column, and is the number of rows all the same.
                assert_eq!(
                    value(&connection, &format!("SELECT count(*) FROM {function}"))?,
                    expected.len().to_string(),
                    "{function}"
                );
                // A projection in another order, and the generic function.
                let reversed: Vec<String> =
                    declared.iter().rev().map(|name| quoted(name)).collect();
                let kinds_reversed: Vec<ColKind> = kinds.iter().rev().copied().collect();
                let expected_reversed: Vec<Vec<Cell>> = expected
                    .iter()
                    .map(|row| row.iter().rev().cloned().collect())
                    .collect();
                assert_cells(
                    &connection,
                    &format!(
                        "SELECT {} FROM read_pcap('{}', protocol := '{}')",
                        reversed.join(", "),
                        capture.path,
                        view.name
                    ),
                    &kinds_reversed,
                    &expected_reversed,
                );
            }
        }
    }
    assert!(rows_of_all > 10_000, "{rows_of_all}");
    Ok(())
}

#[test]
fn a_view_fills_several_chunks_and_stops_at_a_limit() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let bytes = golden::legacy_nanos(mixed_frames(9000));
    let path = fixture.write("mixed.pcap", &bytes);
    let view = PacketsView::get("udp_packets").unwrap();
    let (columns, expected) = reference_view_rows(&bytes, view);
    let kinds: Vec<ColKind> = columns.iter().map(|column| column.kind).collect();
    // More rows than frames (a tunnelled frame has two or three), in several chunks.
    assert!(expected.len() > 9000 + 9000 / 5 && expected.len() > 4 * 2048);
    for layout in LAYOUTS {
        lay_out(&connection, layout, 256);
        let from = format!("read_udp_packets('{path}')");
        assert_cells(
            &connection,
            &format!("SELECT * FROM {from}"),
            &kinds,
            &expected,
        );
        for (limit, offset) in [(1, 0), (5, 2047), (3000, 2040), (7, 12_000)] {
            let end = (offset + limit).min(expected.len());
            assert_cells(
                &connection,
                &format!("SELECT * FROM {from} LIMIT {limit} OFFSET {offset}"),
                &kinds,
                &expected[offset.min(end)..end],
            );
        }
        // A table made from the scan holds the rows in the scan's order.
        execute(
            &connection,
            &format!("CREATE OR REPLACE TABLE stored AS SELECT * FROM {from}"),
        );
        assert_cells(&connection, "SELECT * FROM stored", &kinds, &expected);
        // A filter on a column of a lower layer, which DuckDB applies.
        let inner = value(
            &connection,
            &format!("SELECT count(*) FROM {from} WHERE encap_depth > 0 AND src_ip_v4 IS NOT NULL"),
        )?;
        let tunnelled = expected
            .iter()
            .filter(|row| matches!(row[columns.len() - 2], Cell::U8(depth) if depth > 0))
            .count();
        assert_eq!(inner, tunnelled.to_string());
        assert!(tunnelled > 0);
    }
    Ok(())
}

#[test]
fn filters_on_the_frame_are_taken_over_by_a_view_scan() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    execute(&connection, "CALL enable_logging(level = 'debug')");
    let bytes = golden::legacy_nanos(mixed_frames(400));
    let path = fixture.write("mixed.pcap", &bytes);
    let from = format!("read_udp_packets('{path}')");
    let plan = |sql: &str| -> String {
        let plan = rows(&connection, &format!("EXPLAIN {sql}")).unwrap();
        plan[0][1].clone()
    };
    lay_out(&connection, (1, false), 16);

    // An upper bound on the frame number ends the read, and stays in DuckDB's plan.
    let sql = format!("SELECT count(*) FROM {from} WHERE frame_number <= 20");
    pushdown(&connection, true);
    assert!(
        plan(&sql).contains("Function: READ_UDP_PACKETS"),
        "{}",
        plan(&sql)
    );
    assert!(plan(&sql).contains("Filter ─"), "{}", plan(&sql));
    logged(&connection);
    let taken_over = value(&connection, &sql)?;
    let records = logged(&connection);
    assert!(
        records.iter().any(|r| r.contains("; filter: frame_number")),
        "{records:?}"
    );
    assert!(
        records
            .iter()
            .any(|r| r.contains(": 20 packets from frame 1, 0 of them not accepted")),
        "{records:?}"
    );
    // With the setting off the scan reads everything and DuckDB filters.
    pushdown(&connection, false);
    assert!(plan(&sql).contains("Filter ─"), "{}", plan(&sql));
    logged(&connection);
    assert_eq!(value(&connection, &sql)?, taken_over);
    let records = logged(&connection);
    assert!(
        !records.iter().any(|r| r.contains("; filter: ")),
        "{records:?}"
    );
    assert!(
        records
            .iter()
            .any(|r| r.contains(": 400 packets from frame 1")),
        "{records:?}"
    );
    // 20 frames: 2 inside two tunnels (three rows), 4 inside one (two rows), 14 plain.
    assert_eq!(taken_over, "28");

    // A lower bound on the frame number skips partitions of a split capture; a bound in time
    // rejects packets without parsing them. A filter on another column stays with DuckDB.
    pushdown(&connection, true);
    lay_out(&connection, (4, true), 16);
    let sql = format!("SELECT count(*) FROM {from} WHERE frame_number > 300 AND dst_port = 9999");
    assert!(plan(&sql).contains("Filter ─"), "{}", plan(&sql));
    logged(&connection);
    assert_eq!(value(&connection, &sql)?, "100");
    let records = logged(&connection);
    let read: u64 = records
        .iter()
        .filter_map(|record| {
            let (_, rest) = record.split_once("': ")?;
            let (packets, rest) = rest.split_once(' ')?;
            rest.starts_with("packets from frame")
                .then(|| packets.parse::<u64>().unwrap())
        })
        .sum();
    assert!((100..=116).contains(&read), "{read} packets: {records:?}");
    Ok(())
}

#[test]
fn a_view_reads_several_files_with_their_names() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let a_bytes = golden::capture("tunnels");
    let b_bytes = golden::legacy_nanos(mixed_frames(300));
    let c_bytes = golden::capture("eth");
    let a = fixture.write("a.pcap", &a_bytes);
    let b = fixture.write("b.pcap", &b_bytes);
    let c = fixture.write("c.pcap", &c_bytes);
    let pattern = fixture.path("?.pcap");
    for view in ["tcp_packets", "udp_packets", "dns_packets"] {
        let view = PacketsView::get(view).unwrap();
        let (columns, rows_a) = reference_view_rows(&a_bytes, view);
        let (_, rows_b) = reference_view_rows(&b_bytes, view);
        let (_, rows_c) = reference_view_rows(&c_bytes, view);
        let mut kinds: Vec<ColKind> = columns.iter().map(|column| column.kind).collect();
        let all: Vec<Vec<Cell>> = [&rows_c, &rows_a, &rows_b]
            .into_iter()
            .flatten()
            .cloned()
            .collect();
        let named: Vec<Vec<Cell>> = [(&rows_c, &c), (&rows_a, &a), (&rows_b, &b)]
            .into_iter()
            .flat_map(|(rows, path)| {
                rows.iter().map(move |row| {
                    let mut row = row.clone();
                    row.push(Cell::Str(path.clone()));
                    row
                })
            })
            .collect();
        let list = format!("['{c}', '{a}', '{b}']");
        for layout in LAYOUTS {
            lay_out(&connection, layout, 8);
            // A list is read in its order; frame numbers start at 1 in each file.
            assert_cells(
                &connection,
                &format!("SELECT * FROM read_{}({list})", view.name),
                &kinds,
                &all,
            );
            kinds.push(ColKind::Str);
            assert_cells(
                &connection,
                &format!("SELECT * FROM read_{}({list}, filename := true)", view.name),
                &kinds,
                &named,
            );
            kinds.pop();
            // A pattern is read in the order of the paths, and a filter on the frame applies
            // to each file.
            let per_file = rows(
                &connection,
                &format!(
                    "SELECT parse_filename(filename), count(*), min(frame_number) \
                     FROM read_{}('{pattern}', filename := true) WHERE frame_number >= 3 \
                     GROUP BY ALL ORDER BY ALL",
                    view.name
                ),
            )?;
            let expected: Vec<Vec<String>> = [
                ("a.pcap", &rows_a),
                ("b.pcap", &rows_b),
                ("c.pcap", &rows_c),
            ]
            .into_iter()
            .filter_map(|(name, rows)| {
                let frames: Vec<u64> = rows
                    .iter()
                    .filter_map(|row| match row[0] {
                        Cell::U64(frame) if frame >= 3 => Some(frame),
                        _ => None,
                    })
                    .collect();
                let first = frames.iter().min()?;
                Some(vec![
                    name.to_owned(),
                    frames.len().to_string(),
                    first.to_string(),
                ])
            })
            .collect();
            assert_eq!(per_file, expected, "{}", view.name);
        }
    }
    Ok(())
}

#[test]
fn a_view_function_takes_the_arguments_of_a_scan_function() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let bytes = golden::legacy(mixed_frames(40));
    let path = fixture.write("whole.pcap", &bytes);
    // Cut inside the last record.
    let cut = fixture.write("cut.pcap", &bytes[..bytes.len() - 10]);

    // The complete frames of a truncated capture are returned; strict makes that an error.
    let whole = value(
        &connection,
        &format!("SELECT count(*) FROM read_udp_packets('{path}')"),
    )?;
    let lenient = value(
        &connection,
        &format!("SELECT count(*) FROM read_udp_packets('{cut}')"),
    )?;
    // 40 frames: 5 inside two tunnels (three rows), 7 inside one (two rows), 28 plain. The
    // last is inside one.
    assert_eq!(whole, "57");
    assert_eq!(lenient, "55");
    assert_eq!(
        value(
            &connection,
            &format!("SELECT count(*) FROM read_udp_packets('{path}', strict := true)")
        )?,
        whole
    );
    let error = rows(
        &connection,
        &format!("SELECT count(*) FROM read_udp_packets('{cut}', strict := true)"),
    )
    .unwrap_err();
    for part in ["read_udp_packets: ", "cut.pcap' is truncated", "frame 39"] {
        assert!(error.message.contains(part), "{error}");
    }

    // The errors of a scan function, under the view function's name.
    for (call, parts) in [
        ("read_tcp_packets()".to_owned(), vec!["read_tcp_packets"]),
        (
            format!("read_tcp_packets('{}')", fixture.path("absent.pcap")),
            vec!["absent.pcap"],
        ),
        (
            format!("read_tcp_packets('{path}', protocol := 'tcp')"),
            vec!["protocol"],
        ),
        (
            format!("read_tcp_packets('{path}', strict := NULL)"),
            vec!["read_tcp_packets: strict", "must not be NULL"],
        ),
        (
            format!("read_pcap('{path}', protocol := 'packets')"),
            vec![
                "read_pcap: there is no protocol table 'packets'",
                "pcap_protocols() lists the tables and pcap_views() the views",
            ],
        ),
        (
            "pcap_schema('tunneled_packets')".to_owned(),
            vec![
                "pcap_schema: there is no protocol table 'tunneled_packets'",
                "pcap_views() the views",
            ],
        ),
        (
            // `filename` is a column only when asked for.
            format!("(SELECT filename FROM read_tcp_packets('{path}'))"),
            vec!["filename"],
        ),
    ] {
        let sql = format!("SELECT * FROM {call}");
        let error = rows(&connection, &sql).expect_err(&sql);
        for part in parts {
            assert!(error.message.contains(part), "{sql}: {error}");
        }
    }

    // Any case of the name, as for a table.
    assert_eq!(
        value(
            &connection,
            &format!("SELECT count(*) FROM read_pcap('{path}', protocol := 'UDP_Packets')")
        )?,
        whole
    );
    // A capture path named where a table is expected is still `frames`.
    assert_eq!(
        value(&connection, &format!("SELECT count(*) FROM '{path}'"))?,
        "40"
    );
    Ok(())
}

#[test]
fn the_views_are_listed_and_described() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let path = fixture.write("eth.pcap", &golden::capture("eth"));

    let listed = rows(&connection, "SELECT * FROM pcap_views()")?;
    assert_eq!(listed.len(), PacketsView::all().len());
    let mut views: Vec<&PacketsView> = PacketsView::all().iter().collect();
    views.sort_by_key(|view| view.name);
    for (row, view) in listed.iter().zip(views) {
        assert_eq!(
            row,
            &[
                view.name.to_owned(),
                view.description.to_owned(),
                view.anchor.to_owned(),
                view.columns().len().to_string()
            ]
        );
        // A function per view, with the parameters of a scan function.
        let function = format!("read_{}", view.name);
        assert_eq!(
            rows(
                &connection,
                &format!(
                    "SELECT function_type, parameters::VARCHAR FROM duckdb_functions() \
                     WHERE function_name = '{function}'"
                )
            )?,
            [["table".to_owned(), "[files, strict, filename]".to_owned()]],
            "{function}"
        );
        // `pcap_schema` describes what the function returns.
        let schema = rows(
            &connection,
            &format!(
                "SELECT column_name, column_type FROM pcap_schema('{}')",
                view.name
            ),
        )?;
        let described = rows(
            &connection,
            &format!("SELECT column_name, column_type FROM (DESCRIBE SELECT * FROM {function}('{path}'))"),
        )?;
        assert_eq!(schema, described, "{function}");
        // The protocol is a table of `pcap_protocols()`; the view is not.
        assert_eq!(
            value(
                &connection,
                &format!(
                    "SELECT count(*) FILTER (name = '{}') || ',' || count(*) FILTER (name = '{}') \
                     FROM pcap_protocols()",
                    view.anchor, view.name
                )
            )?,
            "1,0",
            "{function}"
        );
    }
    assert_eq!(
        rows(
            &connection,
            "SELECT column_name, column_type FROM (DESCRIBE SELECT * FROM pcap_views())"
        )?,
        [
            ["name", "VARCHAR"],
            ["description", "VARCHAR"],
            ["protocol", "VARCHAR"],
            ["column_count", "UINTEGER"]
        ]
    );
    // What `pcap_protocols()` lists is what it listed before there were views.
    assert_eq!(
        value(&connection, "SELECT count(*) FROM pcap_protocols()")?,
        "28"
    );

    // The documented example: addresses of the anchor's level, formatted by the scalars.
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT frame_number, ip4_to_string(src_ip_v4), src_port, dst_port, \
                 tcp_flags_str(flags), ttl, encap_depth \
                 FROM read_tcp_packets('{path}') ORDER BY frame_number LIMIT 1"
            )
        )?
        .len(),
        1
    );
    Ok(())
}
