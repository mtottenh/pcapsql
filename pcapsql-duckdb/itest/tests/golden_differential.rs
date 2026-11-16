//! Differential test against the DataFusion frontend: the queries of its golden corpus, run
//! through DuckDB over the same captures, must return what its committed snapshots hold.
//!
//! The captures and the queries are those of `pcapsql-datafusion/tests/golden_corpus.rs` itself
//! (both take them from `pcapsql_testgen::corpus`), and the expected results are the snapshots in
//! `pcapsql-datafusion/tests/golden/`, which are Arrow's pretty-printed tables. For each corpus
//! capture a DuckDB database gets one view per scan table (`CREATE VIEW tcp AS SELECT * FROM
//! read_tcp('<capture>')`) and one per packets view (`CREATE VIEW tcp_packets AS SELECT * FROM
//! read_tcp_packets('<capture>')`), so that the corpus SQL runs as it is written.
//!
//! # What is compared
//!
//! Every corpus query over the per-packet tables, the stream tables and the `*_packets` views
//! the extension has: [`COMPARED`]. A query runs unchanged unless DuckDB's SQL means something else by it, or
//! it calls a function that takes the capture here (the time functions); those
//! are rewritten, with the reason. A view here is one fused scan
//! (`read_<proto>_packets`), where the snapshot was made by DataFusion from its SQL view: that
//! the two agree is what `tests/packets_views.rs` and the DataFusion frontend's own test show
//! in general, and this shows on the queries users were given as examples.
//!
//! # What is not, and why
//!
//! [`NOT_COMPARED`] lists every other corpus query with its reason: it reads a view of the
//! DataFusion frontend the extension does not offer (`packets`, `tunneled_packets`); it calls a
//! DataFusion-only function; or its row order is not determined by the query. A corpus query in neither list fails the test, so a query added to the corpus has to
//! be put in one of them.
//!
//! # What is normalised
//!
//! Only how a value is printed, and the column the DuckDB tables have in addition:
//!
//! - **NULL.** Arrow prints an empty cell, DuckDB `NULL`. (So NULL and the empty string cannot
//!   be told apart here; `scan.rs` compares cells, not text.)
//! - **BLOB.** Arrow prints lower-case hexadecimal, DuckDB an escaped string.
//! - **Lists.** Arrow prints `[a, b]` with an empty item for NULL; DuckDB quotes strings that
//!   could be misread and prints `NULL`. Of a struct in a list Arrow prints `{lo: 1, hi: 2}`,
//!   DuckDB `{'lo': 1, 'hi': 2}`.
//! - **Timestamps.** DuckDB's are TIMESTAMP_NS, DataFusion's microseconds; Arrow prints
//!   `2023-11-14T22:13:21.001`, DuckDB `2023-11-14 22:13:21.001`. The instant must be equal.
//! - **The `timestamp` column of protocol tables**, which DataFusion's tables do not have: it is
//!   dropped from a `SELECT *` (decision D5 of the roadmap).

use std::collections::{BTreeMap, BTreeSet};

use duckdb_neo::{connection::Connection, Parameters, Result};
use pcapsql_duckdb_itest::{column, connect, golden, rows, Fixture};

/// The corpus queries that are compared: the snapshot's name and, where the corpus SQL cannot
/// run unchanged, the SQL DuckDB runs instead and why.
const COMPARED: &[(&str, Option<(&str, &str)>)] = &[
    ("q01_frames", None),
    ("q02_count", None),
    ("q03_ethernet", None),
    ("q04_ipv4", None),
    ("q05_tcp", None),
    ("q06_udp", None),
    ("q07_dns", None),
    ("q08_arp", None),
    ("q09_icmp", None),
    ("q10_ipv6", None),
    ("q11_join", None),
    ("q12_agg", None),
    ("q13_limit", None),
    (
        "q14_raw_hex",
        Some((
            "SELECT frame_number, length(hex(raw_data)) // 2 AS len, \
             lower(substr(hex(raw_data), 1, 24)) AS eth_header_prefix \
             FROM frames ORDER BY frame_number",
            "DuckDB's hex() is upper case and its / is not integer division",
        )),
    ),
    ("q15_timestamp", None),
    ("q17_dns_answers", None),
    ("q18_where", None),
    ("q19_vlan", None),
    ("q20_vxlan", None),
    ("q21_ethernet_encap", None),
    ("q22_udp_inner", None),
    ("q23_ipv4_inner", None),
    ("q26_self_join", None),
    ("q27_in_subquery", None),
    ("q28_one_header_per_level", None),
    ("q29_http_not_a_message_start", None),
    ("s01_sll", None),
    ("s02_sll_ipv4", None),
    ("s03_sll_udp_tcp_icmp", None),
    ("s04_sll_dns", None),
    ("s05_sll_tcp_only", None),
    ("t01_sll2", None),
    ("t02_sll2_ipv4_ipv6", None),
    ("t03_sll2_per_interface", None),
    ("t04_sll2_dns_icmp", None),
    ("t05_sll2_tcp_only", None),
    ("t08_one_header_per_level", None),
    ("u06_http_table", None),
    ("v01_bgp", None),
    ("v02_ospf", None),
    ("v03_gtp", None),
    ("v04_ipv6", None),
    ("v09_one_header_per_level", None),
    ("f01_same_table_two_aliases", None),
    ("f02_order_by_root_depth", None),
    // The `*_packets` views: each a fused scan here.
    ("q16_tcp_packets_view", None),
    ("q26_udp_packets_vxlan_levels", None),
    ("q28_view_plus_member", None),
    ("u07_http_packets_view", None),
    ("v05_bgp_packets_view", None),
    ("v06_ospf_packets_view", None),
    ("v07_gtp_packets_view", None),
    ("v08_gtp_frame_levels", None),
    ("t01_tcp_packets_levels", None),
    ("t02_udp_packets_levels", None),
    ("t03_icmp_packets_levels", None),
    ("t04_arp_packets_levels", None),
    // No ORDER BY: a view scan returns its rows in capture order, as DataFusion's fused join
    // does.
    ("f03_view_limit_offset", None),
    ("f06_view_joined_with_member", None),
    // The stream tables, alone and joined with per-packet tables.
    ("u01_tcp_connections", None),
    ("u02_http_messages", None),
    ("u03_tls_sessions", None),
    ("u04_stream_join_packet", None),
    ("u05_http2_empty", None),
    ("u09_http_vs_http_messages", None),
    // The histogram functions: the same statistics, the same buckets, and in `h02` the same
    // bytes of the serialized histogram; `h06` with one significant figure.
    ("h01_hdr_statistics", None),
    ("h02_hdr_bytes", None),
    ("h03_hdr_group_by", None),
    ("h04_hdr_buckets", None),
    ("h05_hdr_no_rows", None),
    ("h06_hdr_sigfigs", None),
    // The time functions, which here take the capture: `{capture}` is its path.
    (
        "q24_time_udfs",
        Some((
            "SELECT frame_number, relative_time(timestamp, '{capture}') AS rel, \
             start_time('{capture}') AS t0, end_time('{capture}') AS t1 \
             FROM frames ORDER BY frame_number LIMIT 2",
            TIME_FUNCTIONS,
        )),
    ),
    (
        "q25_time_range_only",
        Some((
            "SELECT start_time('{capture}') AS t0, end_time('{capture}') AS t1",
            TIME_FUNCTIONS,
        )),
    ),
];

/// Why the queries of the time functions are rewritten.
const TIME_FUNCTIONS: &str = "the DataFusion frontend has one capture per session and its time \
                              functions take none; the extension's take the capture files";

const VIEW: &str = "reads `packets` or `tunneled_packets`, views of the DataFusion frontend that \
                    join across encapsulation levels; the extension does not offer them";
const WINDOW: &str = "calls a window table function only the DataFusion frontend has";
const UNORDERED: &str = "its rows depend on an order the query does not fix";

/// The corpus queries that are not compared, each with the reason.
const NOT_COMPARED: &[(&str, &str)] = &[
    ("q27_packets_view_vxlan_levels", VIEW),
    ("q30_tumble", WINDOW),
    ("q31_hop", WINDOW),
    ("q32_session", WINDOW),
    ("u08_packets_view_http_columns", VIEW),
    ("t05_packets_levels", VIEW),
    ("t06_packets_one_row_per_level", VIEW),
    ("t07_tunneled_packets", VIEW),
    ("f04_derived_table_limit_under_left_join", UNORDERED),
    ("f05_left_join_under_limit", UNORDERED),
];

/// The tables the snapshots that are compared read. The test fails if a query stops covering
/// one of them.
const TABLES_WITH_A_SNAPSHOT: [&str; 21] = [
    "arp",
    "bgp",
    "dns",
    "ethernet",
    "frames",
    "gtp",
    "http",
    "http2",
    "http_messages",
    "icmp",
    "ipv4",
    "ipv6",
    "linux_sll",
    "ospf",
    "sll2",
    "tcp",
    "tcp_connections",
    "tls_sessions",
    "udp",
    "vlan",
    "vxlan",
];

/// A result as text: the column names and the rows.
#[derive(Debug, PartialEq, Eq)]
struct Table {
    header: Vec<String>,
    rows: Vec<Vec<String>>,
}

/// Parse a table as Arrow pretty-prints it:
///
/// ```text
/// +--------------+-----------+
/// | frame_number | ethertype |
/// +--------------+-----------+
/// | 1            | 2048      |
/// +--------------+-----------+
/// ```
///
/// A result without rows is printed as `++` twice and has no header.
fn parse_snapshot(name: &str, text: &str) -> Table {
    let mut lines = text.lines().filter(|line| line.starts_with('|'));
    let cells = |line: &str| -> Vec<String> {
        let inner = line
            .strip_prefix("| ")
            .and_then(|line| line.strip_suffix(" |"))
            .unwrap_or_else(|| panic!("{name}: unexpected line {line:?}"));
        inner
            .split(" | ")
            .map(|cell| cell.trim().to_owned())
            .collect()
    };
    let header = lines.next().map(cells).unwrap_or_default();
    let rows: Vec<Vec<String>> = lines.map(cells).collect();
    for row in &rows {
        // A cell that contained " | " would have been split.
        assert_eq!(row.len(), header.len(), "{name}: {row:?}");
    }
    Table { header, rows }
}

/// A timestamp printed with nine fractional digits, as Arrow prints it: the fraction in groups
/// of three digits, without trailing groups of zeros.
fn arrow_timestamp(nanos: &str) -> String {
    let (seconds, fraction) = nanos.split_once('.').expect("a fraction");
    assert_eq!(fraction.len(), 9, "{nanos}");
    let mut fraction = fraction;
    while let Some(shorter) = fraction.strip_suffix("000") {
        fraction = shorter;
    }
    if fraction.is_empty() {
        seconds.to_owned()
    } else {
        format!("{seconds}.{fraction}")
    }
}

/// Run `sql` and return its result printed the way Arrow prints it (see the module
/// documentation for what that covers).
fn duckdb_table(connection: &Connection, sql: &str) -> Result<Table> {
    let described = rows(
        connection,
        &format!("SELECT column_name, column_type FROM (DESCRIBE {sql})"),
    )?;
    let mut select = Vec::new();
    for (index, column) in described.iter().enumerate() {
        let c = format!("c{index}");
        let item = |element: &str| {
            format!(
                "'[' || array_to_string(list_transform({c}, lambda x: coalesce({element}, '')), ', ') || ']'"
            )
        };
        select.push(match column[1].as_str() {
            "BLOB" => format!("lower(hex({c}))"),
            "BLOB[]" => item("lower(hex(x))"),
            // The names of the fields are not quoted by Arrow. (No field of a struct here is
            // text, which could hold a quote of its own.)
            list if list.starts_with("STRUCT(") && list.ends_with("[]") => {
                item("replace(x::VARCHAR, '''', '')")
            }
            list if list.ends_with("[]") => item("x::VARCHAR"),
            "TIMESTAMP_NS" | "TIMESTAMP" => format!("strftime({c}, '%Y-%m-%dT%H:%M:%S.%n')"),
            _ => c,
        });
    }
    let names: Vec<String> = (0..described.len())
        .map(|index| format!("c{index}"))
        .collect();
    let normalised = format!(
        "SELECT {} FROM ({sql}) AS q({})",
        select.join(", "),
        names.join(", ")
    );
    let mut result = rows(connection, &normalised)?;
    for row in &mut result {
        for (cell, column) in row.iter_mut().zip(&described) {
            if cell == "NULL" {
                cell.clear();
            } else if column[1].starts_with("TIMESTAMP") {
                *cell = arrow_timestamp(cell);
            }
        }
    }
    Ok(Table {
        header: described
            .into_iter()
            .map(|mut column| column.swap_remove(0))
            .collect(),
        rows: result,
    })
}

/// Remove the `timestamp` column the DuckDB protocol tables have and DataFusion's do not, from a
/// result whose columns are otherwise those of `expected`.
fn without_d5_timestamp(mut actual: Table, expected: &Table) -> (Table, bool) {
    let position = actual.header.iter().position(|name| name == "timestamp");
    let Some(position) =
        position.filter(|_| !expected.header.iter().any(|name| name == "timestamp"))
    else {
        return (actual, false);
    };
    actual.header.remove(position);
    for row in &mut actual.rows {
        row.remove(position);
    }
    (actual, true)
}

/// A database with a view of every scan table and of every packets view over one corpus
/// capture, and the path of that capture.
fn database(fixture: &Fixture, capture: &str) -> Result<(Connection, String)> {
    let connection = connect()?;
    let path = fixture.write(&format!("{capture}.pcap"), &golden::capture(capture));
    let relations = "SELECT name FROM pcap_protocols() UNION ALL SELECT name FROM pcap_views()";
    for table in column(&connection, relations)? {
        connection.execute(
            format!("CREATE VIEW \"{table}\" AS SELECT * FROM read_{table}('{path}')"),
            Parameters::None,
        )?;
    }
    Ok((connection, path))
}

#[test]
fn every_corpus_query_is_compared_or_accounted_for() {
    let corpus: BTreeSet<&str> = golden::queries().iter().map(|query| query.name).collect();
    assert_eq!(
        corpus.len(),
        golden::queries().len(),
        "a snapshot name is used twice"
    );
    let compared: BTreeSet<&str> = COMPARED.iter().map(|(name, _)| *name).collect();
    let skipped: BTreeSet<&str> = NOT_COMPARED.iter().map(|(name, _)| *name).collect();
    assert_eq!(compared.len(), COMPARED.len());
    assert_eq!(skipped.len(), NOT_COMPARED.len());

    let both: Vec<_> = compared.intersection(&skipped).collect();
    assert!(both.is_empty(), "both compared and not: {both:?}");
    let listed: BTreeSet<&str> = compared.union(&skipped).copied().collect();
    let unknown: Vec<_> = listed.difference(&corpus).collect();
    assert!(unknown.is_empty(), "not in the corpus: {unknown:?}");
    let unaccounted: Vec<_> = corpus.difference(&listed).collect();
    assert!(
        unaccounted.is_empty(),
        "corpus queries that are neither compared nor listed with a reason: {unaccounted:?}"
    );

    // The parser of snapshots, on the shapes the corpus has.
    let table = parse_snapshot("q21", &golden::snapshot("q21_ethernet_encap"));
    assert_eq!(
        table.header,
        [
            "frame_number",
            "src_mac",
            "encap_depth",
            "tunnel_type",
            "tunnel_id"
        ]
    );
    assert_eq!(table.rows.len(), 3);
    assert_eq!(table.rows[0], ["10", "020000000001", "0", "", ""]);
    assert_eq!(table.rows[2], ["11", "020000000022", "1", "vxlan", "42"]);
    let empty = parse_snapshot("q28", &golden::snapshot("q28_one_header_per_level"));
    assert!(empty.header.is_empty() && empty.rows.is_empty());
    assert_eq!(
        arrow_timestamp("2023-11-14T22:13:21.001000000"),
        "2023-11-14T22:13:21.001"
    );
    assert_eq!(
        arrow_timestamp("2023-11-14T22:13:20.000000000"),
        "2023-11-14T22:13:20"
    );
    assert_eq!(
        arrow_timestamp("2023-11-14T22:13:20.000001000"),
        "2023-11-14T22:13:20.000001"
    );
    assert_eq!(
        arrow_timestamp("2023-11-14T22:13:20.100000001"),
        "2023-11-14T22:13:20.100000001"
    );
}

#[test]
fn duckdb_returns_what_the_datafusion_snapshots_hold() -> Result<()> {
    let fixture = Fixture::new();
    let mut databases = BTreeMap::new();
    for capture in golden::CAPTURES {
        databases.insert(capture, database(&fixture, capture)?);
    }
    let queries: BTreeMap<&str, golden::Query> = golden::queries()
        .into_iter()
        .map(|query| (query.name, query))
        .collect();

    let mut failures = Vec::new();
    let mut rows_compared = 0;
    let mut tables_read = BTreeSet::new();
    let mut timestamps_dropped = Vec::new();
    for (name, rewritten) in COMPARED {
        let query = queries[name];
        let (connection, path) = &databases[query.capture];
        let sql = rewritten.map_or(query.sql, |(sql, _why)| sql);
        let sql = &sql.replace("{capture}", path);
        let expected = parse_snapshot(name, &golden::snapshot(name));
        let actual = match duckdb_table(connection, sql) {
            Ok(actual) => actual,
            Err(error) => {
                failures.push(format!("{name}: {sql}\n  {error}"));
                continue;
            }
        };
        let (mut actual, dropped) = without_d5_timestamp(actual, &expected);
        if dropped {
            timestamps_dropped.push(*name);
        }
        // Arrow prints a result without rows without its header.
        if expected.header.is_empty() && actual.rows.is_empty() {
            actual.header.clear();
        }
        if actual != expected {
            let mut report = format!("{name}: {sql}");
            if actual.header != expected.header {
                report += &format!(
                    "\n  columns: {:?}\n  expected: {:?}",
                    actual.header, expected.header
                );
            }
            if actual.rows.len() != expected.rows.len() {
                report += &format!(
                    "\n  {} rows, expected {}",
                    actual.rows.len(),
                    expected.rows.len()
                );
            }
            for (index, (actual, expected)) in actual.rows.iter().zip(&expected.rows).enumerate() {
                if actual != expected {
                    report += &format!("\n  row {index}: {actual:?}\n  expected: {expected:?}");
                }
            }
            failures.push(report);
        }
        rows_compared += expected.rows.len();
        // The tables the query names (as whole words after FROM or JOIN).
        let words: Vec<&str> = sql
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .collect();
        for pair in words.windows(2) {
            if pair[0].eq_ignore_ascii_case("from") || pair[0].eq_ignore_ascii_case("join") {
                tables_read.insert(pair[1].to_owned());
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} queries differ:\n{}",
        failures.len(),
        COMPARED.len(),
        failures.join("\n")
    );

    // The comparison was of something: this many rows, over every table that has a snapshot.
    assert!(rows_compared > 120, "{rows_compared}");
    for table in TABLES_WITH_A_SNAPSHOT {
        assert!(
            tables_read.contains(table),
            "no compared query reads {table}: {tables_read:?}"
        );
    }
    // The D5 column was dropped exactly where a protocol table is read with `SELECT *`.
    assert_eq!(
        timestamps_dropped,
        ["v01_bgp", "v02_ospf", "v03_gtp", "v04_ipv6"]
    );
    Ok(())
}
