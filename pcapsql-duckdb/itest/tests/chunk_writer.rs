//! `ChunkWriter`, the extension's row sink, against real DuckDB chunks.
//!
//! Rows go in through the test-only table function `chunk_rows` (`src/replay.rs`), which writes
//! them with a `ChunkWriter` over the output chunk of each `exec` call, and come back out of
//! the query result: as SQL text where DuckDB's own rendering is the point, and as the `Cell`s
//! of the shared sink conformance suite otherwise.
//!
//! The first test is that suite, `pcapsql_core::scan::testing::run_conformance`, which every
//! sink of the scan layer must pass. The others pin what the suite does not reach: DuckDB's
//! types and rendering, lists that outgrow their child vector, chunk boundaries within one
//! query, projection, and what a misused writer does.

use std::sync::Arc;

use duckdb_neo::{connection::Connection, Result};
use pcapsql_core::scan::{
    testing::{run_conformance, Cell, RecordingSink, SinkHarness, CONFORMANCE_CAPACITIES},
    ColKind, OutColumn,
};
use pcapsql_duckdb::engine::types;
use pcapsql_duckdb_itest::{
    connect,
    replay::{column, query_cells, Case, Mode, Replay},
    rows, value,
};

/// The capacity of DuckDB's chunks, which `the_chunk_capacity_bounds_every_chunk` checks.
const CHUNK: usize = 2048;

fn setup() -> Result<(Connection, Arc<Replay>)> {
    let connection = connect()?;
    let replay = Replay::register(&connection)?;
    Ok((connection, replay))
}

fn strings(cells: &[&str]) -> Vec<String> {
    cells.iter().map(|cell| cell.to_string()).collect()
}

fn text(value: &str) -> Cell {
    Cell::Str(value.to_owned())
}

fn kinds(columns: &[OutColumn]) -> Vec<ColKind> {
    columns.iter().map(|column| column.kind).collect()
}

// ---------------------------------------------------------------------------------------------
// The shared conformance suite
// ---------------------------------------------------------------------------------------------

/// Runs the suite against `ChunkWriter`.
///
/// The suite fills a sink, takes the rows out, and fills it again. A `ChunkWriter` lives for
/// one `exec` call and its rows leave with the chunk, so the sink the suite writes to is core's
/// `RecordingSink`, and `drain` replays what it recorded through `chunk_rows`: one query, whose
/// `exec` writes the rows with a `ChunkWriter` and fails unless the writer reports `Full` on
/// exactly the row the recording sink did. The cells are then read back from the query result.
///
/// The suite's capacity is the writer's row limit. At 2,048 that is the capacity of DuckDB's
/// chunk itself (`ChunkWriter::new`); below it the writer is told to be full earlier
/// (`ChunkWriter::with_row_limit`), which also puts every drain in a chunk of its own.
struct Harness {
    connection: Connection,
    replay: Arc<Replay>,
    /// The columns and capacity of the sink the suite is filling.
    columns: Vec<OutColumn>,
    capacity: usize,
    drains: usize,
}

impl SinkHarness for Harness {
    type Sink = RecordingSink;

    fn new_sink(&mut self, columns: &[OutColumn], capacity: usize) -> RecordingSink {
        assert!(capacity <= CHUNK, "a chunk holds {CHUNK} rows");
        self.columns = columns.to_vec();
        self.capacity = capacity;
        RecordingSink::new(columns, Some(capacity))
    }

    fn drain(&mut self, sink: &mut RecordingSink) -> Vec<Vec<Cell>> {
        let rows = sink.take_rows();
        let count = rows.len();
        let id = self.replay.add(Case {
            columns: self.columns.clone(),
            rows,
            row_limit: (self.capacity < CHUNK).then_some(self.capacity),
            mode: Mode::Rows,
        });
        let cells = if self.columns.is_empty() {
            // Rows without columns: only their number comes back.
            let counted = value(
                &self.connection,
                &format!("SELECT count(*) FROM chunk_rows({id})"),
            )
            .unwrap();
            vec![Vec::new(); counted.parse().unwrap()]
        } else {
            query_cells(
                &self.connection,
                &format!("SELECT * FROM chunk_rows({id})"),
                &kinds(&self.columns),
            )
            .unwrap()
        };
        // What the sink held fits one chunk.
        let expected: &[usize] = if count == 0 { &[] } else { &[count] };
        assert_eq!(self.replay.take_chunks(id), expected);
        self.replay.remove(id);
        self.drains += 1;
        cells
    }
}

#[test]
fn chunk_writer_passes_the_sink_conformance_suite() -> Result<()> {
    let (connection, replay) = setup()?;
    assert!(CONFORMANCE_CAPACITIES.contains(&CHUNK));
    let mut harness = Harness {
        connection,
        replay,
        columns: Vec::new(),
        capacity: 0,
        drains: 0,
    };
    run_conformance(&mut harness);
    assert!(harness.drains > 100, "{} drains", harness.drains);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Direct tests
// ---------------------------------------------------------------------------------------------

const MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
const IP6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const LOOPBACK6: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

/// One column of every kind the catalogue uses.
fn all_columns() -> Vec<OutColumn> {
    vec![
        column("id", ColKind::U64),
        column("flag", ColKind::Bool),
        column("tiny", ColKind::U8),
        column("small", ColKind::U16),
        column("medium", ColKind::U32),
        column("big", ColKind::U64),
        column("signed_tiny", ColKind::I8),
        column("signed_big", ColKind::I64),
        column("real", ColKind::F64),
        column("text", ColKind::Str),
        column("bin", ColKind::Bin),
        column("mac", ColKind::Fixed(6)),
        column("ip6", ColKind::Fixed(16)),
        column("ts_us", ColKind::TsMicros),
        column("ts_ns", ColKind::TsNanos),
        column("ports", ColKind::ListU16),
        column("addrs", ColKind::ListU32),
        column("names", ColKind::ListStr),
        column("ip6s", ColKind::ListFixed(16)),
    ]
}

/// A row of [`all_columns`] with a value in every column.
fn full_row(id: u64) -> Vec<Cell> {
    vec![
        Cell::U64(id),
        Cell::Bool(true),
        Cell::U8(u8::MAX),
        Cell::U16(u16::MAX),
        Cell::U32(u32::MAX),
        Cell::U64(u64::MAX),
        Cell::I8(i8::MIN),
        Cell::I64(i64::MIN),
        Cell::F64(1.5),
        text("h\u{e9}llo, longer than twelve bytes"),
        Cell::Bytes(vec![0x00, 0xff, b'A']),
        Cell::Bytes(MAC.to_vec()),
        Cell::Bytes(IP6.to_vec()),
        Cell::Timestamp(1_700_000_000_123_456),
        Cell::Timestamp(1_700_000_000_123_456_789),
        Cell::List(vec![Cell::U16(80), Cell::U16(443)]),
        Cell::List(vec![Cell::U32(3_232_235_777)]),
        Cell::List(vec![text("a.example"), text("b")]),
        Cell::List(vec![
            Cell::Bytes(IP6.to_vec()),
            Cell::Bytes(LOOPBACK6.to_vec()),
        ]),
    ]
}

/// A row of [`all_columns`] that is NULL in every column but the first.
fn null_row(id: u64) -> Vec<Cell> {
    let mut row = vec![Cell::Null; all_columns().len()];
    row[0] = Cell::U64(id);
    row
}

#[test]
fn every_kind_has_its_duckdb_type_and_holds_a_value_and_null() -> Result<()> {
    let (connection, replay) = setup()?;
    let columns = all_columns();
    let id = replay.add(Case {
        columns: columns.clone(),
        rows: vec![full_row(1), null_row(2), full_row(3)],
        ..Case::default()
    });

    // DuckDB names each column's type as `types::sql_name` says it will.
    let described = rows(
        &connection,
        &format!("SELECT column_name, column_type FROM (DESCRIBE SELECT * FROM chunk_rows({id}))"),
    )?;
    let expected: Vec<Vec<String>> = columns
        .iter()
        .map(|column| strings(&[column.name, types::sql_name(column.kind)]))
        .collect();
    assert_eq!(described, expected);
    assert_eq!(
        described[11..15],
        [
            strings(&["mac", "BLOB"]),
            strings(&["ip6", "BLOB"]),
            strings(&["ts_us", "TIMESTAMP"]),
            strings(&["ts_ns", "TIMESTAMP_NS"]),
        ]
    );

    // The values, as DuckDB renders them. The addresses go through the extension's own
    // functions, which take exactly these types.
    let rendered = rows(
        &connection,
        &format!(
            "SELECT * REPLACE (mac_to_string(mac) AS mac, ip6_to_string(ip6) AS ip6,
                              format_ip4_list(addrs) AS addrs, format_ip6_list(ip6s) AS ip6s)
             FROM chunk_rows({id})"
        ),
    )?;
    let full = |id: &str| {
        strings(&[
            id,
            "true",
            "255",
            "65535",
            "4294967295",
            "18446744073709551615",
            "-128",
            "-9223372036854775808",
            "1.5",
            "h\u{e9}llo, longer than twelve bytes",
            "\\x00\\xFFA",
            "aa:bb:cc:dd:ee:ff",
            "2001:db8::1",
            "2023-11-14 22:13:20.123456",
            "2023-11-14 22:13:20.123456789",
            "[80, 443]",
            "[192.168.1.1]",
            "[a.example, b]",
            "['2001:db8::1', '::1']",
        ])
    };
    let mut nulls = strings(&["NULL"; 19]);
    nulls[0] = "2".to_owned();
    assert_eq!(rendered, [full("1"), nulls, full("3")]);

    // NULL is NULL to SQL, not a default value.
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT count(*), count(flag), count(tiny), count(small), count(medium),
                        count(big), count(signed_tiny), count(signed_big), count(real),
                        count(text), count(bin), count(mac), count(ip6), count(ts_us),
                        count(ts_ns), count(ports), count(addrs), count(names), count(ip6s)
                 FROM chunk_rows({id})"
            ),
        )?,
        [strings(&[
            "3", "2", "2", "2", "2", "2", "2", "2", "2", "2", "2", "2", "2", "2", "2", "2", "2",
            "2", "2"
        ])]
    );

    // And the cells come back as they went in.
    assert_eq!(
        query_cells(
            &connection,
            &format!("SELECT * FROM chunk_rows({id})"),
            &kinds(&columns)
        )?,
        [full_row(1), null_row(2), full_row(3)]
    );
    Ok(())
}

#[test]
fn lists_are_null_empty_mixed_or_longer_than_a_chunk() -> Result<()> {
    let (connection, replay) = setup()?;
    let columns = vec![
        column("id", ColKind::U64),
        column("ports", ColKind::ListU16),
        column("addrs", ColKind::ListU32),
        column("names", ColKind::ListStr),
        column("ip6s", ColKind::ListFixed(16)),
    ];
    let long_name = |i: usize| format!("name-{i}-with-a-tail-that-does-not-fit-inline");
    let rows_in = vec![
        // NULL lists.
        vec![Cell::U64(0), Cell::Null, Cell::Null, Cell::Null, Cell::Null],
        // Empty lists.
        vec![
            Cell::U64(1),
            Cell::List(vec![]),
            Cell::List(vec![]),
            Cell::List(vec![]),
            Cell::List(vec![]),
        ],
        // NULL items between values, first and last.
        vec![
            Cell::U64(2),
            Cell::List(vec![Cell::Null, Cell::U16(2), Cell::Null]),
            Cell::List(vec![Cell::U32(7), Cell::Null]),
            Cell::List(vec![text(""), Cell::Null, text("z")]),
            Cell::List(vec![Cell::Null, Cell::Bytes(IP6.to_vec())]),
        ],
        // Lists of only NULLs.
        vec![
            Cell::U64(3),
            Cell::List(vec![Cell::Null]),
            Cell::List(vec![Cell::Null, Cell::Null]),
            Cell::List(vec![Cell::Null]),
            Cell::List(vec![Cell::Null]),
        ],
        // More items than a chunk has rows: the child vector grows, more than once, while the
        // cell is written, with a NULL in the part written after it grew.
        vec![
            Cell::U64(4),
            Cell::List((0..5000).map(|i| Cell::U16(i as u16)).collect()),
            Cell::List(
                (0..9000u32)
                    .map(|i| if i == 8000 { Cell::Null } else { Cell::U32(i) })
                    .collect(),
            ),
            Cell::List((0..5000).map(|i| text(&long_name(i))).collect()),
            Cell::List((0..5000).map(|i| Cell::Bytes(vec![i as u8; 16])).collect()),
        ],
        // And the cells after it still land in the right place.
        vec![
            Cell::U64(5),
            Cell::List(vec![Cell::U16(9)]),
            Cell::List(vec![Cell::U32(9)]),
            Cell::List(vec![text(&long_name(9))]),
            Cell::List(vec![Cell::Bytes(LOOPBACK6.to_vec())]),
        ],
        vec![
            Cell::U64(6),
            Cell::List(vec![]),
            Cell::Null,
            Cell::List(vec![]),
            Cell::Null,
        ],
    ];
    let id = replay.add(Case {
        columns: columns.clone(),
        rows: rows_in.clone(),
        ..Case::default()
    });

    assert_eq!(
        query_cells(
            &connection,
            &format!("SELECT * FROM chunk_rows({id})"),
            &kinds(&columns)
        )?,
        rows_in
    );

    // The same through SQL: NULL lists, empty lists and NULL items are three different things.
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT id, ports IS NULL, len(ports), list_count(ports), names::VARCHAR,
                        len(addrs), len(names), len(ip6s)
                 FROM chunk_rows({id}) WHERE id < 4"
            ),
        )?,
        [
            strings(&["0", "true", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL"]),
            strings(&["1", "false", "0", "0", "[]", "0", "0", "0"]),
            strings(&["2", "false", "3", "1", "['', NULL, z]", "2", "3", "2"]),
            strings(&["3", "false", "1", "0", "[NULL]", "2", "1", "1"]),
        ]
    );
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT len(ports), list_sum(ports), len(addrs), list_count(addrs),
                        addrs[8001] IS NULL, addrs[9000], names[5000], ip6s[300] = repeat('\\x2B', 16)::BLOB
                 FROM chunk_rows({id}) WHERE id = 4"
            ),
        )?,
        [strings(&[
            "5000",
            "12497500",
            "9000",
            "8999",
            "true",
            "8999",
            &long_name(4999),
            "true",
        ])]
    );
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT ports, addrs, names, format_ip6_list(ip6s) FROM chunk_rows({id})
                 WHERE id >= 5"
            ),
        )?,
        [
            strings(&["[9]", "[9]", &format!("[{}]", long_name(9)), "['::1']"]),
            strings(&["[]", "NULL", "[]", "NULL"]),
        ]
    );
    Ok(())
}

#[test]
fn empty_and_nul_bearing_strings_and_blobs_are_values() -> Result<()> {
    let (connection, replay) = setup()?;
    let columns = vec![
        column("id", ColKind::U64),
        column("text", ColKind::Str),
        column("bin", ColKind::Bin),
    ];
    let rows_in = vec![
        vec![Cell::U64(0), text(""), Cell::Bytes(vec![])],
        vec![Cell::U64(1), Cell::Null, Cell::Null],
        // An interior NUL is part of the value, short (inline) or long (in the arena).
        vec![
            Cell::U64(2),
            text("nul\0inside\0"),
            Cell::Bytes(vec![0, 1, 0]),
        ],
        vec![
            Cell::U64(3),
            text("a longer string with a NUL\0 in the middle of it"),
            Cell::Bytes(vec![0; 300]),
        ],
        // Exactly at the inline limit, and one past it.
        vec![Cell::U64(4), text("twelve bytes"), Cell::Bytes(vec![7; 12])],
        vec![
            Cell::U64(5),
            text("thirteen byte"),
            Cell::Bytes(vec![7; 13]),
        ],
        vec![Cell::U64(6), text("\0"), Cell::Bytes(vec![0])],
    ];
    let id = replay.add(Case {
        columns: columns.clone(),
        rows: rows_in.clone(),
        ..Case::default()
    });

    assert_eq!(
        query_cells(
            &connection,
            &format!("SELECT * FROM chunk_rows({id})"),
            &kinds(&columns)
        )?,
        rows_in
    );
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT id, text IS NULL, bin IS NULL, strlen(text), octet_length(bin),
                        text::BLOB, text = '', bin = ''::BLOB
                 FROM chunk_rows({id}) WHERE id <= 2 OR id = 6"
            ),
        )?,
        [
            strings(&["0", "false", "false", "0", "0", "", "true", "true"]),
            strings(&["1", "true", "true", "NULL", "NULL", "NULL", "NULL", "NULL"]),
            strings(&[
                "2",
                "false",
                "false",
                "11",
                "3",
                "nul\\x00inside\\x00",
                "false",
                "false"
            ]),
            strings(&["6", "false", "false", "1", "1", "\\x00", "false", "false"]),
        ]
    );
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT text = 'nul' || chr(0) || 'inside' || chr(0),
                        bin = '\\x00\\x01\\x00'::BLOB
                 FROM chunk_rows({id}) WHERE id = 2"
            ),
        )?,
        [strings(&["true", "true"])]
    );
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT id, strlen(text), octet_length(bin), bin = repeat(bin[1:1]::VARCHAR, octet_length(bin))::BLOB
                 FROM chunk_rows({id}) WHERE id BETWEEN 3 AND 5"
            ),
        )?,
        [
            strings(&["3", "47", "300", "true"]),
            strings(&["4", "12", "12", "true"]),
            strings(&["5", "13", "13", "true"]),
        ]
    );
    Ok(())
}

#[test]
fn fixed_size_values_are_blobs_of_their_width() -> Result<()> {
    let (connection, replay) = setup()?;
    let columns = vec![
        column("mac", ColKind::Fixed(6)),
        column("ip6", ColKind::Fixed(16)),
    ];
    let rows_in = vec![
        vec![Cell::Bytes(MAC.to_vec()), Cell::Bytes(IP6.to_vec())],
        vec![Cell::Null, Cell::Null],
        // All zero is an address, not NULL; 16 bytes do not fit a slot and go to the arena.
        vec![Cell::Bytes(vec![0; 6]), Cell::Bytes(vec![0; 16])],
        vec![Cell::Bytes(vec![0xff; 6]), Cell::Bytes(vec![0xff; 16])],
    ];
    let id = replay.add(Case {
        columns: columns.clone(),
        rows: rows_in.clone(),
        ..Case::default()
    });

    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT typeof(mac), octet_length(mac), mac_to_string(mac), mac = mac('aa:bb:cc:dd:ee:ff'),
                        typeof(ip6), octet_length(ip6), ip6_to_string(ip6), ip6 = ip6('2001:db8::1')
                 FROM chunk_rows({id})"
            ),
        )?,
        [
            strings(&[
                "BLOB",
                "6",
                "aa:bb:cc:dd:ee:ff",
                "true",
                "BLOB",
                "16",
                "2001:db8::1",
                "true"
            ]),
            strings(&["BLOB", "NULL", "NULL", "NULL", "BLOB", "NULL", "NULL", "NULL"]),
            strings(&[
                "BLOB",
                "6",
                "00:00:00:00:00:00",
                "false",
                "BLOB",
                "16",
                "::",
                "false"
            ]),
            strings(&[
                "BLOB",
                "6",
                "ff:ff:ff:ff:ff:ff",
                "false",
                "BLOB",
                "16",
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                "false"
            ]),
        ]
    );
    assert_eq!(
        query_cells(
            &connection,
            &format!("SELECT * FROM chunk_rows({id})"),
            &kinds(&columns)
        )?,
        rows_in
    );
    Ok(())
}

#[test]
fn timestamps_keep_their_unit_to_the_nanosecond() -> Result<()> {
    let (connection, replay) = setup()?;
    let columns = vec![
        column("ts_ns", ColKind::TsNanos),
        column("ts_us", ColKind::TsMicros),
    ];
    let nanos = [
        1_700_000_000_123_456_789,
        1_700_000_000_000_000_001,
        0,
        -1,
        // 2262-04-11: about as far as nanoseconds in an i64 reach.
        9_223_372_036_000_000_001,
    ];
    let mut rows_in: Vec<Vec<Cell>> = nanos
        .iter()
        .map(|&ns| vec![Cell::Timestamp(ns), Cell::Timestamp(ns.div_euclid(1000))])
        .collect();
    rows_in.push(vec![Cell::Null, Cell::Null]);
    let id = replay.add(Case {
        columns: columns.clone(),
        rows: rows_in.clone(),
        ..Case::default()
    });

    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT typeof(ts_ns), ts_ns, epoch_ns(ts_ns), typeof(ts_us), ts_us, epoch_us(ts_us)
                 FROM chunk_rows({id})"
            ),
        )?,
        [
            strings(&[
                "TIMESTAMP_NS",
                "2023-11-14 22:13:20.123456789",
                "1700000000123456789",
                "TIMESTAMP",
                "2023-11-14 22:13:20.123456",
                "1700000000123456",
            ]),
            strings(&[
                "TIMESTAMP_NS",
                "2023-11-14 22:13:20.000000001",
                "1700000000000000001",
                "TIMESTAMP",
                "2023-11-14 22:13:20",
                "1700000000000000",
            ]),
            strings(&[
                "TIMESTAMP_NS",
                "1970-01-01 00:00:00",
                "0",
                "TIMESTAMP",
                "1970-01-01 00:00:00",
                "0",
            ]),
            strings(&[
                "TIMESTAMP_NS",
                "1969-12-31 23:59:59.999999999",
                "-1",
                "TIMESTAMP",
                "1969-12-31 23:59:59.999999",
                "-1",
            ]),
            strings(&[
                "TIMESTAMP_NS",
                "2262-04-11 23:47:16.000000001",
                "9223372036000000001",
                "TIMESTAMP",
                "2262-04-11 23:47:16",
                "9223372036000000",
            ]),
            strings(&["TIMESTAMP_NS", "NULL", "NULL", "TIMESTAMP", "NULL", "NULL"]),
        ]
    );
    // A nanosecond apart is not equal, and the order is the order of the integers.
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT count(DISTINCT ts_ns), min(ts_ns) = make_timestamp_ns(-1),
                        max(ts_ns) - min(ts_ns) > INTERVAL 290 YEAR,
                        count(*) FILTER (ts_ns = TIMESTAMP_NS '2023-11-14 22:13:20.123456789')
                 FROM chunk_rows({id})"
            ),
        )?,
        [strings(&["5", "true", "true", "1"])]
    );
    assert_eq!(
        query_cells(
            &connection,
            &format!("SELECT * FROM chunk_rows({id})"),
            &kinds(&columns)
        )?,
        rows_in
    );
    Ok(())
}

/// Row `id` of a table of [`all_columns`]: values, NULLs and lists of varying length, so that
/// no two neighbouring rows look alike.
fn varied_row(id: u64) -> Vec<Cell> {
    let n = id as usize;
    match id % 4 {
        0 => full_row(id),
        1 => null_row(id),
        2 => vec![
            Cell::U64(id),
            Cell::Bool(id % 8 == 2),
            Cell::U8(id as u8),
            Cell::Null,
            Cell::U32(id as u32),
            Cell::U64(id * 3),
            Cell::Null,
            Cell::I64(-(id as i64)),
            Cell::F64(id as f64 / 4.0),
            text(&format!("row {id}")),
            Cell::Bytes(vec![id as u8; n % 40]),
            Cell::Null,
            Cell::Bytes(vec![id as u8; 16]),
            Cell::Timestamp(id as i64),
            Cell::Timestamp(1_700_000_000_000_000_000 + id as i64),
            Cell::List((0..n % 7).map(|i| Cell::U16(i as u16)).collect()),
            Cell::Null,
            Cell::List(
                (0..n % 5)
                    .map(|i| text(&format!("label-{id}-{i}.example.org")))
                    .collect(),
            ),
            Cell::List(vec![]),
        ],
        _ => vec![
            Cell::U64(id),
            Cell::Null,
            Cell::Null,
            Cell::U16(id as u16),
            Cell::Null,
            Cell::Null,
            Cell::I8(id as i8),
            Cell::Null,
            Cell::Null,
            text(""),
            Cell::Bytes(vec![]),
            Cell::Bytes(vec![id as u8; 6]),
            Cell::Null,
            Cell::Null,
            Cell::Timestamp(-(id as i64)),
            Cell::Null,
            Cell::List(vec![Cell::U32(id as u32), Cell::Null]),
            Cell::List(vec![Cell::Null, text("x")]),
            Cell::List(
                (0..n % 3)
                    .map(|_| Cell::Bytes(vec![id as u8; 16]))
                    .collect(),
            ),
        ],
    }
}

#[test]
fn the_chunk_capacity_bounds_every_chunk() -> Result<()> {
    let (connection, replay) = setup()?;
    let columns = all_columns();
    let rows_in: Vec<Vec<Cell>> = (0..5000).map(varied_row).collect();
    let id = replay.add(Case {
        columns: columns.clone(),
        rows: rows_in.clone(),
        ..Case::default()
    });

    // 5,000 rows are three `exec` calls: two full chunks and the rest. (`exec` itself fails
    // unless the writer reports `Full` on exactly row 2,048 of a chunk.)
    let cells = query_cells(
        &connection,
        &format!("SELECT * FROM chunk_rows({id})"),
        &kinds(&columns),
    )?;
    assert_eq!(cells.len(), 5000);
    assert!(cells == rows_in, "a cell changed on its way through DuckDB");
    assert_eq!(replay.take_chunks(id), [CHUNK, CHUNK, 5000 - 2 * CHUNK]);
    let all: Vec<usize> = (0..columns.len()).collect();
    assert_eq!(replay.take_projections(id), vec![all; 3]);

    // An operator that sizes vectors of its own from the chunks (what an oversized chunk
    // breaks) agrees on the rows.
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT count(*), sum(id), count(text), sum(len(ports)), max(strlen(text)),
                        count(DISTINCT ts_ns)
                 FROM chunk_rows({id})"
            ),
        )?,
        [strings(&["5000", "12497500", "3750", "6249", "32", "2501"])]
    );
    assert_eq!(replay.take_chunks(id), [CHUNK, CHUNK, 5000 - 2 * CHUNK]);

    // A row limit below the capacity cuts the same rows into smaller chunks.
    let limited = replay.add(Case {
        columns: columns.clone(),
        rows: rows_in[..100].to_vec(),
        row_limit: Some(7),
        mode: Mode::Rows,
    });
    let cells = query_cells(
        &connection,
        &format!("SELECT * FROM chunk_rows({limited})"),
        &kinds(&columns),
    )?;
    assert!(cells == rows_in[..100], "a cell changed");
    let mut expected = vec![7; 14];
    expected.push(2);
    assert_eq!(replay.take_chunks(limited), expected);

    // A limit above the capacity is the capacity.
    let generous = replay.add(Case {
        columns: vec![column("id", ColKind::U64)],
        rows: (0..3000).map(|id| vec![Cell::U64(id)]).collect(),
        row_limit: Some(1_000_000),
        mode: Mode::Rows,
    });
    assert_eq!(
        value(
            &connection,
            &format!("SELECT sum(id) FROM chunk_rows({generous})")
        )?,
        "4498500"
    );
    assert_eq!(replay.take_chunks(generous), [CHUNK, 3000 - CHUNK]);
    Ok(())
}

#[test]
fn a_projection_writes_only_the_projected_vectors() -> Result<()> {
    let (connection, replay) = setup()?;
    let columns = all_columns();
    let rows_in: Vec<Vec<Cell>> = (0..3000).map(varied_row).collect();
    let id = replay.add(Case {
        columns: columns.clone(),
        rows: rows_in.clone(),
        ..Case::default()
    });

    // Two columns, in an order of the query's choosing.
    let cells = query_cells(
        &connection,
        &format!("SELECT names, id FROM chunk_rows({id})"),
        &[ColKind::ListStr, ColKind::U64],
    )?;
    let expected: Vec<Vec<Cell>> = rows_in
        .iter()
        .map(|row| vec![row[17].clone(), row[0].clone()])
        .collect();
    assert!(cells == expected, "a projected cell changed");
    let projections = replay.take_projections(id);
    assert_eq!(projections.len(), 2);
    for projection in projections {
        let mut sorted = projection.clone();
        sorted.sort();
        assert_eq!(sorted, [0, 17], "{projection:?}");
    }
    replay.take_chunks(id);

    // `count(*)` needs no column. DuckDB still hands `exec` a chunk with one vector, for a
    // column of its choosing, and the writer fills it like any other.
    assert_eq!(
        value(
            &connection,
            &format!("SELECT count(*) FROM chunk_rows({id})")
        )?,
        "3000"
    );
    let projections = replay.take_projections(id);
    assert_eq!(projections.len(), 2);
    assert!(
        projections.iter().all(|projection| projection.len() == 1),
        "{projections:?}"
    );
    assert_eq!(replay.take_chunks(id), [CHUNK, 3000 - CHUNK]);
    Ok(())
}

#[test]
fn an_output_without_columns_counts_its_rows() -> Result<()> {
    let (connection, replay) = setup()?;
    let id = replay.add(Case {
        rows: vec![Vec::new(); 5000],
        ..Case::default()
    });

    // The writer is given no columns; the chunk still has the one vector DuckDB projects.
    assert_eq!(
        value(
            &connection,
            &format!("SELECT count(*) FROM chunk_rows({id})")
        )?,
        "5000"
    );
    assert_eq!(replay.take_chunks(id), [CHUNK, CHUNK, 5000 - 2 * CHUNK]);
    assert_eq!(replay.take_projections(id), vec![vec![0]; 3]);

    // Read anyway, the vector nobody wrote is NULL, not leftover memory.
    assert_eq!(
        rows(
            &connection,
            &format!("SELECT count(*), count(never_written) FROM chunk_rows({id})"),
        )?,
        [strings(&["5000", "0"])]
    );

    let none = replay.add(Case::default());
    assert_eq!(
        value(
            &connection,
            &format!("SELECT count(*) FROM chunk_rows({none})")
        )?,
        "0"
    );
    assert_eq!(replay.take_chunks(none), [0usize; 0]);
    Ok(())
}

/// The connection still answers: nothing raised an INTERNAL error, which would have
/// invalidated the database.
fn assert_usable(connection: &Connection) {
    assert_eq!(value(connection, "SELECT 42").unwrap(), "42");
}

#[test]
fn a_row_past_the_capacity_is_refused_not_stored() -> Result<()> {
    let (connection, replay) = setup()?;
    for row_limit in [None, Some(3)] {
        let id = replay.add(Case {
            columns: all_columns(),
            rows: (0..3000).map(varied_row).collect(),
            row_limit,
            mode: Mode::PastFull,
        });
        let error = value(
            &connection,
            &format!("SELECT count(*) FROM chunk_rows({id})"),
        )
        .unwrap_err();
        assert!(
            error
                .message
                .contains("a row is written to a full output chunk"),
            "{error}"
        );
        // The same when the first write of the extra row is a list or a string.
        let error = value(
            &connection,
            &format!("SELECT max(names) FROM chunk_rows({id})"),
        )
        .unwrap_err();
        assert!(error.message.contains("full output chunk"), "{error}");
        let error = value(
            &connection,
            &format!("SELECT max(text) FROM chunk_rows({id})"),
        )
        .unwrap_err();
        assert!(error.message.contains("full output chunk"), "{error}");
        assert_usable(&connection);
    }

    // And for rows without columns, where `end_row` is the only call.
    let id = replay.add(Case {
        rows: vec![Vec::new(); 3000],
        mode: Mode::PastFull,
        ..Case::default()
    });
    let error = value(
        &connection,
        &format!("SELECT count(*) FROM chunk_rows({id})"),
    )
    .unwrap_err();
    assert!(error.message.contains("full output chunk"), "{error}");
    assert_usable(&connection);
    Ok(())
}

#[test]
fn a_value_of_the_wrong_kind_is_refused_not_stored() -> Result<()> {
    let (connection, replay) = setup()?;
    // `u16` on a column of every other kind: two bytes written to a BOOLEAN or a VARCHAR slot
    // would corrupt the vector.
    for kind in kinds(&all_columns()) {
        let id = replay.add(Case {
            columns: vec![column("c", kind)],
            rows: vec![vec![Cell::Null]],
            mode: Mode::WrongKind,
            ..Case::default()
        });
        let result = rows(&connection, &format!("SELECT * FROM chunk_rows({id})"));
        if kind == ColKind::U16 {
            assert_eq!(result?, [strings(&["NULL"])]);
        } else {
            let error = result.unwrap_err();
            assert!(
                error
                    .message
                    .contains("output column 0 does not store u16 values"),
                "{kind:?}: {error}"
            );
        }
        assert_usable(&connection);
    }
    Ok(())
}

#[test]
fn columns_that_do_not_match_the_chunk_are_an_error() -> Result<()> {
    let (connection, replay) = setup()?;
    // The writer is told that every column is a `Str`. It checks each vector's type before it
    // takes a pointer, so this is an error from `new`, not a string written to an integer.
    for kind in kinds(&all_columns()) {
        let id = replay.add(Case {
            columns: vec![column("c", kind)],
            rows: vec![vec![Cell::Null]],
            mode: Mode::WrongColumns,
            ..Case::default()
        });
        let result = rows(&connection, &format!("SELECT * FROM chunk_rows({id})"));
        if kind == ColKind::Str {
            assert_eq!(result?, [strings(&["NULL"])]);
        } else {
            let error = result.unwrap_err();
            assert!(
                error.message.contains("logical type mismatch"),
                "{kind:?}: {error}"
            );
            assert!(!error.message.contains("panic"), "{kind:?}: {error}");
        }
        assert_usable(&connection);
    }
    Ok(())
}

#[test]
fn a_writer_dropped_without_finish_leaves_no_rows() -> Result<()> {
    let (connection, replay) = setup()?;
    let id = replay.add(Case {
        columns: all_columns(),
        rows: (0..100).map(varied_row).collect(),
        mode: Mode::Unfinished,
        ..Case::default()
    });
    // The vectors were sized to the capacity for writing; without `finish` none of that may
    // reach DuckDB as rows.
    assert_eq!(
        rows(
            &connection,
            &format!("SELECT count(*), count(text) FROM chunk_rows({id})")
        )?,
        [strings(&["0", "0"])]
    );
    assert_eq!(
        rows(&connection, &format!("SELECT * FROM chunk_rows({id})"))?,
        Vec::<Vec<String>>::new()
    );
    assert_usable(&connection);
    Ok(())
}

#[test]
fn a_list_dropped_without_finish_leaves_its_cell_and_its_neighbours_alone() -> Result<()> {
    let (connection, replay) = setup()?;
    let columns = all_columns();
    let rows_in: Vec<Vec<Cell>> = (0..50).map(varied_row).collect();
    let id = replay.add(Case {
        columns: columns.clone(),
        rows: rows_in.clone(),
        mode: Mode::AbandonedList,
        ..Case::default()
    });
    // The abandoned items are overwritten by the list that is written next.
    assert_eq!(
        query_cells(
            &connection,
            &format!("SELECT * FROM chunk_rows({id})"),
            &kinds(&columns)
        )?,
        rows_in
    );
    Ok(())
}
