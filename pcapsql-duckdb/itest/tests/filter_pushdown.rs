//! Filters on `frame_number` and `timestamp`, which a scan applies itself.
//!
//! A scan that takes over a filter must return exactly the rows DuckDB would have kept. The
//! reference is DuckDB: with `pcapsql_filter_pushdown = false` the scan is offered nothing,
//! reads everything, and DuckDB filters its rows. Every query here returns the same with the
//! setting on and off, on one thread and on four, with captures split into partitions and not.
//!
//! The rest is about what is saved and what is not taken over: that every filter stays in
//! DuckDB's plan (`EXPLAIN`), which partitions and how many packets a scan reads (the DEBUG records of
//! the scan, which carry the driver's `ScanStats`), and what DuckDB does with parameters.

use std::io::Write;

use duckdb_neo::{connection::Connection, vector::Unknown, Parameters, Result};
use pcapsql_core::scan::testing::Cell;
use pcapsql_duckdb_itest::{column, connect, golden, reference_rows, rows, value, Fixture};
use pcapsql_testgen::SplitMix64;

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn set(connection: &Connection, setting: &str, value: impl std::fmt::Display) {
    execute(connection, &format!("SET {setting} = {value}"));
}

fn execute(connection: &Connection, sql: &str) {
    connection
        .execute(sql, Parameters::None)
        .unwrap_or_else(|error| panic!("{sql}: {error}"));
}

/// Scan captures of any size in partitions, cut at checkpoints `stride` frames apart, on
/// `threads` threads.
fn partitioned(connection: &Connection, threads: usize, stride: u64) {
    set(connection, "pcapsql_parallel_scan", true);
    set(connection, "pcapsql_parallel_min_file_size", 0);
    set(connection, "pcapsql_index_stride", stride);
    set(connection, "threads", threads);
}

/// Scan every capture as one partition, on `threads` threads.
fn unpartitioned(connection: &Connection, threads: usize) {
    set(connection, "pcapsql_parallel_scan", false);
    set(connection, "threads", threads);
}

/// How a scan is run: the number of threads, and whether captures are split.
const LAYOUTS: [(usize, bool); 4] = [(1, false), (4, false), (4, true), (1, true)];

fn lay_out(connection: &Connection, (threads, split): (usize, bool), stride: u64) {
    if split {
        partitioned(connection, threads, stride);
    } else {
        unpartitioned(connection, threads);
    }
}

fn pushdown(connection: &Connection, on: bool) {
    set(connection, "pcapsql_filter_pushdown", on);
}

/// Run `sql` with the scan taking filters over and with DuckDB applying them all, assert that
/// the rows are the same and in the same order, and return them.
fn same_either_way(connection: &Connection, sql: &str, what: &str) -> Vec<Vec<String>> {
    pushdown(connection, false);
    let expected = rows(connection, sql).unwrap_or_else(|error| panic!("{sql}: {error}"));
    pushdown(connection, true);
    let actual = rows(connection, sql).unwrap_or_else(|error| panic!("{sql}: {error}"));
    assert!(
        actual == expected,
        "{what}: {sql}: {} rows with the filters in the scan, {} with DuckDB's; the first \
         that differs: {:?}",
        actual.len(),
        expected.len(),
        actual.iter().zip(&expected).find(|(a, e)| a != e)
    );
    actual
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

/// What the DEBUG records of one statement say its scans did.
#[derive(Debug, Default, PartialEq, Eq)]
struct Scanned {
    /// Per file: the `partitions:` note.
    layouts: Vec<String>,
    /// Per file: the `filter:` note, if the scan had a predicate.
    filters: Vec<Option<String>>,
    /// Per partition scanned to its end: its first frame, the packets read, and those of them
    /// the predicate rejected. In order of the first frame.
    partitions: Vec<(u64, u64, u64)>,
}

impl Scanned {
    fn of(records: &[String]) -> Self {
        let mut scanned = Self::default();
        for record in records {
            if let Some((_, rest)) = record.split_once("': partitions: ") {
                let (layout, rest) = rest.split_once("; columns: ").unwrap();
                scanned.layouts.push(layout.to_owned());
                let filter = rest.split_once("; filter: ").map(|(_, filter)| filter);
                scanned.filters.push(filter.map(str::to_owned));
            } else if let Some((_, rest)) = record.split_once("': ") {
                // "<n> packets from frame <f>[, <s> of them not accepted by the filter]"
                let words: Vec<&str> = rest.split([' ', ',']).collect();
                assert_eq!(words[1..4], ["packets", "from", "frame"], "{record}");
                let skipped = match words.get(6) {
                    Some(skipped) => skipped.parse().unwrap(),
                    None => 0,
                };
                scanned.partitions.push((
                    words[4].parse().unwrap(),
                    words[0].parse().unwrap(),
                    skipped,
                ));
            } else {
                panic!("an unknown log record: {record}");
            }
        }
        scanned.partitions.sort_unstable();
        scanned
    }

    /// The packets read, and those of them the predicate rejected.
    fn packets(&self) -> (u64, u64) {
        self.partitions
            .iter()
            .fold((0, 0), |(read, skipped), partition| {
                (read + partition.1, skipped + partition.2)
            })
    }
}

/// Run `sql` and return its first column and what its scans did.
fn scanned(connection: &Connection, sql: &str) -> (Vec<String>, Scanned) {
    logged(connection);
    let result = column(connection, sql).unwrap_or_else(|error| panic!("{sql}: {error}"));
    (result, Scanned::of(&logged(connection)))
}

/// Whether DuckDB's plan for `sql` has a filter above the scan.
fn filtered_by_duckdb(connection: &Connection, sql: &str) -> bool {
    let plan = rows(connection, &format!("EXPLAIN {sql}"))
        .unwrap_or_else(|error| panic!("EXPLAIN {sql}: {error}"));
    let plan = &plan[0][1];
    assert!(plan.contains("Function: READ_"), "{plan}");
    plan.contains("Filter ─")
}

/// The timestamp of every frame of `capture`, in nanoseconds, in capture order.
fn timestamps(capture: &[u8]) -> Vec<i64> {
    let (columns, rows) = reference_rows(capture, "frames");
    let index = columns
        .iter()
        .position(|column| column.name == "timestamp")
        .unwrap();
    rows.iter()
        .map(|row| match &row[index] {
            Cell::Timestamp(nanos) => *nanos,
            other => panic!("timestamp is {other:?}"),
        })
        .collect()
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

/// A capture whose timestamps do not ascend: they jump back and forth over a span of half as
/// many seconds as there are frames, so that every second is that of two frames, far apart,
/// and every window of a partitioned scan covers most of the span.
fn shuffled_times(frames: u32) -> Vec<u8> {
    let half = frames / 2;
    golden::legacy_nanos_at(mixed_frames(frames), |i| {
        let second = (i as u32).wrapping_mul(7919) % half;
        (golden::FIRST_SECOND + second, golden::nanos_of(i))
    })
}

/// A capture file with what the tests need to know of it.
struct Capture {
    path: String,
    frames: usize,
    /// The timestamp of every frame, in nanoseconds.
    times: Vec<i64>,
}

impl Capture {
    fn write(fixture: &Fixture, name: &str, capture: &[u8]) -> Self {
        Self::write_as(fixture, name, capture, capture)
    }

    /// `capture`, stored as `bytes` (a compressed copy of it).
    fn write_as(fixture: &Fixture, name: &str, capture: &[u8], bytes: &[u8]) -> Self {
        let times = timestamps(capture);
        Self {
            path: fixture.write(name, bytes),
            frames: times.len(),
            times,
        }
    }
}

/// A `TIMESTAMP_NS` constant of `nanos`.
fn ns(nanos: i64) -> String {
    format!("make_timestamp_ns({nanos})")
}

const OPERATORS: [&str; 5] = ["=", "<", "<=", ">", ">="];

/// The operator with its operands exchanged.
fn reversed(operator: &str) -> &'static str {
    match operator {
        "=" => "=",
        "<" => ">",
        "<=" => ">=",
        ">" => "<",
        ">=" => "<=",
        other => panic!("{other}"),
    }
}

/// A random condition on `capture`'s frames: mostly a comparison of `frame_number` or
/// `timestamp` with a constant at or next to a value the capture has, sometimes a condition
/// the scan cannot take over. With `any_table` it is on those two columns only, which every
/// table has.
fn condition(random: &mut SplitMix64, capture: &Capture, stride: u64, any_table: bool) -> String {
    let frames = capture.frames as u64;
    let operator = OPERATORS[random.next_in_range(0, 4)];
    // A frame number: an end of the capture, an end of a checkpoint window, or anywhere.
    let mut frame = || -> u64 {
        let around = match random.next_in_range(0, 5) {
            0 => 1,
            1 => frames,
            2 => stride * random.next_in_range(0, (frames / stride) as usize) as u64,
            _ => random.next_in_range(1, frames as usize) as u64,
        };
        (around + random.next_in_range(0, 2) as u64).saturating_sub(1)
    };
    let (first, second) = (frame(), frame());
    // A timestamp: that of a frame, or a nanosecond or a microsecond off it.
    let mut time = || -> i64 {
        let of = capture.times[random.next_in_range(0, capture.frames - 1)];
        of + [0, 0, 1, -1, 1000, -1000, 999][random.next_in_range(0, 6)]
    };
    let (early, late) = (time(), time());
    match random.next_in_range(0, 19) {
        0..=3 => format!("frame_number {operator} {first}"),
        4 => format!("{first} {} frame_number", reversed(operator)),
        5 => format!(
            "frame_number BETWEEN {} AND {}",
            first.min(second),
            first.max(second)
        ),
        6 => format!("frame_number BETWEEN {first} AND {second}"),
        7..=9 => format!("timestamp {operator} {}", ns(early)),
        10 => format!("{} {} timestamp", ns(early), reversed(operator)),
        11 => format!(
            "timestamp BETWEEN {} AND {}",
            ns(early.min(late)),
            ns(early.max(late))
        ),
        12 => format!(
            "timestamp >= {} AND timestamp < {}",
            ns(early.min(late)),
            ns(early.max(late))
        ),
        // A constant of a coarser type, which DuckDB converts: microseconds.
        13 => format!(
            "timestamp {operator} make_timestamp({})",
            early.div_euclid(1000)
        ),
        // What the scan leaves to DuckDB.
        14 => format!("frame_number <> {first}"),
        15 => format!("frame_number IN ({first}, {second})"),
        16 => format!("frame_number % 3 {operator} 1"),
        17 => format!(
            "(frame_number {operator} {first} OR timestamp > {})",
            ns(late)
        ),
        _ if any_table => format!("frame_number + 1 {operator} {second}"),
        // A column of the packet record, and one of the protocol.
        18 => format!("length {operator} 60"),
        _ => format!("src_port {operator} 1500"),
    }
}

/// One to three conditions, all of which must hold.
fn filter(random: &mut SplitMix64, capture: &Capture, stride: u64, any_table: bool) -> String {
    let count = random.next_in_range(1, 3);
    let conditions: Vec<String> = (0..count)
        .map(|_| condition(random, capture, stride, any_table))
        .collect();
    conditions.join(" AND ")
}

/// Queries that show which rows `filter` keeps of a scan of `capture`: of the table of frames
/// and of one with several rows per frame, unless the filter is on a column only one of them
/// has.
fn queries(capture: &Capture, filter: &str) -> Vec<String> {
    let path = &capture.path;
    let mut queries = Vec::new();
    if !["src_port", "dst_port", "encap_depth"]
        .iter()
        .any(|column| filter.contains(column))
    {
        queries.extend([
            format!("SELECT * EXCLUDE (raw_data) FROM read_frames('{path}') WHERE {filter}"),
            // Without the columns the filter is on in the result.
            format!("SELECT count(*), sum(length) FROM read_frames('{path}') WHERE {filter}"),
        ]);
    }
    if !["length", "link_type"]
        .iter()
        .any(|column| filter.contains(column))
    {
        queries.extend([
            format!(
                "SELECT frame_number, timestamp, src_port, encap_depth FROM read_udp('{path}') \
                 WHERE {filter}"
            ),
            format!("SELECT src_port FROM read_udp('{path}') WHERE {filter} LIMIT 7 OFFSET 3"),
        ]);
    }
    queries
}

const STRIDE: u64 = 100;

#[test]
fn random_filters_keep_the_rows_duckdb_would_keep() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let ascending = golden::legacy(mixed_frames(1500));
    let nanos = golden::pcapng(mixed_frames(1200));
    let captures = [
        Capture::write(&fixture, "ascending.pcap", &ascending),
        Capture::write(&fixture, "nanos.pcapng", &nanos),
        Capture::write(&fixture, "shuffled.pcap", &shuffled_times(1300)),
        // Timestamps from five seconds before 1970 on.
        Capture::write(
            &fixture,
            "epoch.pcapng",
            &golden::pcapng_from(mixed_frames(900), -5),
        ),
        Capture::write_as(&fixture, "ascending.pcap.gz", &ascending, &gzip(&ascending)),
    ];
    assert!(captures[3].times[0] < 0 && captures[3].times[899] > 0);
    assert!(captures[2].times.windows(2).any(|pair| pair[1] < pair[0]));

    let mut random = SplitMix64::new(0x70_63_61_70);
    let mut kept = 0;
    for (number, capture) in captures.iter().enumerate() {
        for round in 0..40 {
            let filter = filter(&mut random, capture, STRIDE, false);
            // Every filter on one layout, and every fourth on all of them.
            let layouts: &[(usize, bool)] = if round % 4 == 0 {
                &LAYOUTS
            } else {
                &LAYOUTS[(number + round) % 4..][..1]
            };
            for layout in layouts {
                lay_out(&connection, *layout, STRIDE);
                for sql in queries(capture, &filter) {
                    kept += same_either_way(&connection, &sql, &format!("{layout:?}")).len();
                }
            }
        }
    }
    // The filters are not all so narrow, or so wide, that nothing is tested.
    assert!(kept > 10_000, "{kept} rows");
    Ok(())
}

#[test]
fn chosen_filters_keep_the_rows_duckdb_would_keep() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let capture = Capture::write(
        &fixture,
        "nanos.pcap",
        &golden::legacy_nanos(mixed_frames(900)),
    );
    let shuffled = Capture::write(&fixture, "shuffled.pcap", &shuffled_times(900));
    let (first, last) = (capture.times[0], capture.times[899]);
    let middle = capture.times[450];
    let filters: Vec<String> = [
        // The ends of the capture, and past them.
        "frame_number = 1",
        "frame_number = 900",
        "frame_number = 901",
        "frame_number = 0",
        "frame_number <= 1",
        "frame_number < 1",
        "frame_number >= 900",
        "frame_number > 900",
        "frame_number > 899",
        "frame_number < 2",
        "frame_number >= 1",
        "frame_number <= 900",
        // The ends of a checkpoint window.
        "frame_number = 100",
        "frame_number = 101",
        "frame_number > 100 AND frame_number <= 200",
        "frame_number >= 101 AND frame_number < 201",
        "frame_number BETWEEN 100 AND 101",
        // Empty and inverted ranges.
        "frame_number > 5 AND frame_number < 6",
        "frame_number > 5 AND frame_number < 5",
        "frame_number >= 5 AND frame_number <= 5",
        "frame_number BETWEEN 7 AND 3",
        "frame_number BETWEEN 7 AND 7",
        "frame_number > 7 AND frame_number < 3",
        // Constants of other types, signs and sizes.
        "frame_number > -1",
        "frame_number >= -5 AND frame_number < 5",
        "frame_number < -1",
        "frame_number = -3",
        "frame_number < 18446744073709551615",
        "frame_number <= 18446744073709551615",
        "frame_number < 18446744073709551616",
        "frame_number > 18446744073709551616",
        "frame_number = 18446744073709551616",
        "frame_number < 5::BIGINT",
        "frame_number < 5::UTINYINT",
        "frame_number <= 5::HUGEINT",
        "frame_number::HUGEINT < 5",
        "frame_number::BIGINT < 5",
        "frame_number::DOUBLE < 5",
        "frame_number < 4.5",
        "frame_number <= 4.0",
        "frame_number < '7'",
        "frame_number < 3e2",
        "frame_number = 5.0::FLOAT",
        // What DuckDB rewrites, and what it must keep.
        "NOT (frame_number > 5)",
        "NOT (frame_number <= 895)",
        "frame_number + 1 < 5",
        "frame_number - 1 > 895",
        "frame_number * 2 < 9",
        "frame_number <> 5 AND frame_number < 9",
        "frame_number != 1",
        "frame_number IN (1, 450, 900, 901)",
        "frame_number NOT IN (1, 450, 900)",
        "frame_number IN (7)",
        "frame_number = 1 OR frame_number = 900",
        "frame_number < 3 OR frame_number > 898",
        "(frame_number < 3 OR length > 100) AND frame_number < 50",
        "frame_number IS NOT DISTINCT FROM 5",
        "frame_number IS DISTINCT FROM 5 AND frame_number < 8",
        "frame_number IS NOT NULL AND frame_number < 4",
        "frame_number IS NULL",
        "frame_number < length",
        "frame_number + length < 80",
        "frame_number < frame_number + 1 AND frame_number < 4",
        "frame_number = original_length - 40",
        "CASE WHEN frame_number < 5 THEN true ELSE length > 100 END",
        "frame_number < random() * 0 + 5",
        // Other columns: of the record, and of the protocol.
        "length > 60 AND frame_number < 300",
        "link_type = 1 AND frame_number BETWEEN 10 AND 20",
        "length = 46",
        "dst_port = 9999 AND frame_number < 30",
        "encap_depth = 0 AND frame_number BETWEEN 5 AND 15",
        "encap_depth > 0 AND frame_number > 880",
        "src_port > 1100 AND src_port < 1200",
        "true",
        "false",
        "NULL",
        "frame_number < NULL",
        "frame_number = NULL OR frame_number = 3",
    ]
    .iter()
    .map(|filter| (*filter).to_owned())
    .chain([
        // Timestamps, to the nanosecond: the first and the last frame's, and one off them.
        format!("timestamp = {}", ns(first)),
        format!("timestamp = {}", ns(first + 1)),
        format!("timestamp = {}", ns(first - 1)),
        format!("timestamp = {}", ns(last)),
        format!("timestamp < {}", ns(first)),
        format!("timestamp <= {}", ns(first)),
        format!("timestamp > {}", ns(last)),
        format!("timestamp >= {}", ns(last)),
        format!("timestamp > {}", ns(last - 1)),
        format!(
            "timestamp >= {} AND timestamp <= {}",
            ns(middle),
            ns(middle)
        ),
        format!(
            "timestamp > {} AND timestamp < {}",
            ns(middle - 1),
            ns(middle + 1)
        ),
        format!(
            "timestamp > {} AND timestamp < {}",
            ns(middle),
            ns(middle + 1)
        ),
        format!("timestamp BETWEEN {} AND {}", ns(middle), ns(last)),
        format!("timestamp BETWEEN {} AND {}", ns(last), ns(middle)),
        format!("timestamp >= {} AND frame_number <= 460", ns(middle)),
        format!("{} <= timestamp AND 460 >= frame_number", ns(middle)),
        // A microsecond constant against the nanosecond column: the frame's timestamp has
        // digits below the microsecond, so `=` finds nothing and the bounds are not the
        // frame's own.
        format!("timestamp = make_timestamp({})", middle / 1000),
        format!("timestamp >= make_timestamp({})", middle / 1000),
        format!("timestamp > make_timestamp({})", middle / 1000),
        format!("timestamp < make_timestamp({})", middle / 1000 + 1),
        format!("timestamp::TIMESTAMP = make_timestamp({})", middle / 1000),
        format!("timestamp::TIMESTAMP >= make_timestamp({})", middle / 1000),
        format!("timestamp::TIMESTAMP < make_timestamp({})", middle / 1000),
        format!("epoch_ns(timestamp) >= {middle}"),
        format!("epoch_us(timestamp) = {}", middle / 1000),
        format!(
            "date_trunc('second', timestamp) = date_trunc('second', {})",
            ns(middle)
        ),
        // Literals DuckDB converts.
        "timestamp >= TIMESTAMP '2023-11-14 22:20:00'".to_owned(),
        "timestamp >= TIMESTAMP '2023-11-14 22:20:00.000001'".to_owned(),
        "timestamp < TIMESTAMP_S '2023-11-14 22:20:00'".to_owned(),
        "timestamp < TIMESTAMP_MS '2023-11-14 22:20:00.5'".to_owned(),
        "timestamp >= TIMESTAMP_NS '2023-11-14 22:20:00.123456789'".to_owned(),
        "timestamp >= '2023-11-14 22:20:00.123456789'".to_owned(),
        "timestamp >= DATE '2023-11-14'".to_owned(),
        "timestamp < DATE '2023-11-15'".to_owned(),
        "timestamp::DATE = DATE '2023-11-14'".to_owned(),
        "timestamp < 'infinity'".to_owned(),
        "timestamp > 'infinity'".to_owned(),
        "timestamp > '-infinity'".to_owned(),
        "timestamp <= '-infinity'::TIMESTAMP".to_owned(),
        "timestamp >= 'epoch'".to_owned(),
        "timestamp < TIMESTAMP '1969-12-31 23:59:59.999999'".to_owned(),
        "timestamp >= current_date".to_owned(),
        "timestamp < now()::TIMESTAMP_NS".to_owned(),
        "timestamp < NULL".to_owned(),
        "timestamp IS NOT NULL AND frame_number > 898".to_owned(),
    ])
    .collect();

    for layout in LAYOUTS {
        lay_out(&connection, layout, STRIDE);
        // The capture whose timestamps do not ascend on one thread unsplit, and on four split.
        let captures: &[&Capture] = match layout {
            (1, false) | (4, true) => &[&capture, &shuffled],
            _ => &[&capture],
        };
        for filter in &filters {
            for capture in captures {
                for sql in queries(capture, filter) {
                    same_either_way(&connection, &sql, &format!("{layout:?}"));
                }
            }
        }
    }

    // Some of them by their numbers, so that the two ways are not wrong together.
    partitioned(&connection, 4, STRIDE);
    pushdown(&connection, true);
    let path = &capture.path;
    let count = |filter: &str| -> String {
        let sql = format!("SELECT count(*) FROM read_frames('{path}') WHERE {filter}");
        value(&connection, &sql).unwrap_or_else(|error| panic!("{sql}: {error}"))
    };
    let frames = |filter: &str| -> Vec<String> {
        let sql = format!("SELECT frame_number FROM read_frames('{path}') WHERE {filter}");
        column(&connection, &sql).unwrap_or_else(|error| panic!("{sql}: {error}"))
    };
    assert_eq!(frames("frame_number = 1"), ["1"]);
    assert_eq!(frames("frame_number >= 900"), ["900"]);
    assert_eq!(
        frames("frame_number > 100 AND frame_number <= 102"),
        ["101", "102"]
    );
    assert_eq!(frames("frame_number BETWEEN 100 AND 101"), ["100", "101"]);
    assert_eq!(count("frame_number > 5 AND frame_number < 6"), "0");
    assert_eq!(count("frame_number BETWEEN 7 AND 3"), "0");
    assert_eq!(count("frame_number > -1"), "900");
    assert_eq!(count("frame_number < 18446744073709551616"), "900");
    assert_eq!(count("frame_number < 4.5"), "4");
    assert_eq!(frames(&format!("timestamp = {}", ns(middle))), ["451"]);
    assert_eq!(count(&format!("timestamp = {}", ns(middle + 1))), "0");
    assert_eq!(
        count(&format!("timestamp = make_timestamp({})", middle / 1000)),
        "0"
    );
    assert_eq!(frames(&format!("timestamp <= {}", ns(first))), ["1"]);
    assert_eq!(count(&format!("timestamp < {}", ns(first))), "0");
    assert_eq!(frames(&format!("timestamp >= {}", ns(last))), ["900"]);
    assert_eq!(count(&format!("timestamp > {}", ns(last))), "0");
    assert_eq!(
        frames(&format!(
            "timestamp > {} AND timestamp < {}",
            ns(middle - 1),
            ns(middle + 1)
        )),
        ["451"]
    );
    assert_eq!(
        count(&format!(
            "timestamp > {} AND timestamp < {}",
            ns(middle),
            ns(middle + 1)
        )),
        "0"
    );
    // The second of frame 451 holds that frame only; in the shuffled capture every second is
    // that of two frames.
    let second = middle - middle.rem_euclid(1_000_000_000);
    let within = format!(
        "timestamp >= {} AND timestamp < {}",
        ns(second),
        ns(second + 1_000_000_000)
    );
    assert_eq!(frames(&within), ["451"]);
    let second = shuffled.times[123] - shuffled.times[123].rem_euclid(1_000_000_000);
    let both = format!(
        "SELECT frame_number FROM read_frames('{}') WHERE timestamp >= {} AND timestamp < {}",
        shuffled.path,
        ns(second),
        ns(second + 1_000_000_000)
    );
    assert_eq!(column(&connection, &both)?, ["124", "574"]);
    Ok(())
}

#[test]
fn the_corpus_captures_filter_the_same_either_way() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let mut random = SplitMix64::new(77);
    for name in golden::CAPTURES {
        let bytes = golden::capture(name);
        let capture = Capture::write(&fixture, &format!("{name}.pcap"), &bytes);
        let tables = column(
            &connection,
            "SELECT name FROM pcap_protocols() ORDER BY name",
        )?;
        for layout in [(1, false), (4, true)] {
            // The corpus captures have a few dozen frames: a window of three.
            lay_out(&connection, layout, 3);
            for _ in 0..6 {
                let filter = filter(&mut random, &capture, 3, true);
                for table in &tables {
                    let sql = format!(
                        "SELECT * FROM read_{table}('{}') WHERE {filter}",
                        capture.path
                    );
                    same_either_way(&connection, &sql, &format!("{name}, {layout:?}"));
                }
            }
        }
    }
    Ok(())
}

#[test]
fn explain_shows_every_filter_and_what_the_scan_filters_by() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    execute(&connection, "CALL enable_logging(level = 'debug')");
    let capture = Capture::write(&fixture, "x.pcap", &golden::legacy_nanos(mixed_frames(50)));
    let time = ns(capture.times[20]);
    let later = ns(capture.times[30]);
    // (the filter, what the scan filters by). DuckDB keeps every filter in its plan, so that
    // two scans of one file with different filters are not taken for the same (see
    // `two_scans_of_one_capture_with_different_filters_keep_their_own_rows`).
    let cases: Vec<(String, Option<String>)> = vec![
        // Exact: the scan returns the rows the filter keeps.
        (
            "frame_number <= 5".into(),
            Some("frame_number in (.., 5]".into()),
        ),
        (
            "5 >= frame_number".into(),
            Some("frame_number in (.., 5]".into()),
        ),
        (
            "frame_number = 5".into(),
            Some("frame_number in [5, 5]".into()),
        ),
        (
            "frame_number > 5".into(),
            Some("frame_number in (5, ..)".into()),
        ),
        (
            "frame_number < 5::BIGINT".into(),
            Some("frame_number in (.., 5)".into()),
        ),
        (
            "frame_number::HUGEINT < 5".into(),
            Some("frame_number in (.., 5)".into()),
        ),
        (
            "frame_number < '7'".into(),
            Some("frame_number in (.., 7)".into()),
        ),
        (
            "NOT (frame_number > 5)".into(),
            Some("frame_number in (.., 5]".into()),
        ),
        (
            "frame_number + 1 < 5".into(),
            Some("frame_number in (.., 4)".into()),
        ),
        // Exact, and true of every frame or of none.
        ("frame_number > -1".into(), None),
        ("frame_number < 18446744073709551616".into(), None),
        ("frame_number < 0".into(), Some("no frame".into())),
        ("frame_number < -1".into(), Some("no frame".into())),
        (
            "frame_number > 18446744073709551616".into(),
            Some("no frame".into()),
        ),
        (
            format!("timestamp >= {time}"),
            Some(format!("timestamp in [{}, ..) ns", capture.times[20])),
        ),
        (
            format!("{time} < timestamp"),
            Some(format!("timestamp in ({}, ..) ns", capture.times[20])),
        ),
        (
            format!("timestamp = {time}"),
            Some(format!(
                "timestamp in [{}, {}] ns",
                capture.times[20], capture.times[20]
            )),
        ),
        (
            "timestamp >= TIMESTAMP '2023-11-14 22:13:25'".into(),
            Some("timestamp in [1700000005000000000, ..) ns".into()),
        ),
        (
            "timestamp >= DATE '2023-11-15'".into(),
            Some("timestamp in [1700006400000000000, ..) ns".into()),
        ),
        (
            "timestamp < '2023-11-14 22:13:25.123456789'".into(),
            Some("timestamp in (.., 1700000005123456789) ns".into()),
        ),
        ("timestamp > 'infinity'".into(), Some("no frame".into())),
        (
            format!("timestamp >= {time} AND frame_number < 40"),
            Some(format!(
                "frame_number in (.., 40) and timestamp in [{}, ..) ns",
                capture.times[20]
            )),
        ),
        // A range on one column reaches the scan as a BETWEEN that does not say whether its
        // bounds are inclusive: the scan reads the inclusive range.
        (
            "frame_number BETWEEN 3 AND 7".into(),
            Some("frame_number in [3, 7]".into()),
        ),
        (
            "frame_number > 3 AND frame_number < 7".into(),
            Some("frame_number in [3, 7]".into()),
        ),
        (
            "frame_number >= 3 AND frame_number < 7".into(),
            Some("frame_number in [3, 7]".into()),
        ),
        (
            format!("timestamp >= {time} AND timestamp < {later}"),
            Some(format!(
                "timestamp in [{}, {}] ns",
                capture.times[20], capture.times[30]
            )),
        ),
        (
            format!("timestamp BETWEEN {time} AND {later} AND frame_number <= 25"),
            Some(format!(
                "frame_number in (.., 25] and timestamp in [{}, {}] ns",
                capture.times[20], capture.times[30]
            )),
        ),
        // Not understood: DuckDB's, and the scan reads everything.
        ("frame_number <> 5".into(), None),
        ("frame_number IN (1, 2)".into(), None),
        ("frame_number = 1 OR frame_number = 2".into(), None),
        ("frame_number IS NOT DISTINCT FROM 5".into(), None),
        ("frame_number < length".into(), None),
        ("frame_number % 2 = 0".into(), None),
        ("frame_number < 2.5".into(), None),
        ("frame_number::BIGINT < 5".into(), None),
        ("frame_number::DOUBLE < 5".into(), None),
        ("length > 60".into(), None),
        (
            "timestamp::TIMESTAMP >= TIMESTAMP '2023-11-14 22:13:25'".into(),
            None,
        ),
        ("timestamp::DATE = DATE '2023-11-14'".into(), None),
        ("epoch_ns(timestamp) > 5".into(), None),
        // Both kinds: the scan uses its part.
        (
            "frame_number < 20 AND length > 60".into(),
            Some("frame_number in (.., 20)".into()),
        ),
        (
            "frame_number < 20 AND frame_number <> 7".into(),
            Some("frame_number in (.., 20)".into()),
        ),
        (
            "(frame_number > 3 AND frame_number < 7) OR length > 1000".into(),
            None,
        ),
    ];
    for function in ["read_frames", "read_udp"] {
        for (filter, predicate) in &cases {
            if function == "read_udp" && filter.contains("length") {
                continue;
            }
            let sql = format!(
                "SELECT count(*) FROM {function}('{}') WHERE {filter}",
                capture.path
            );
            pushdown(&connection, true);
            assert!(
                filtered_by_duckdb(&connection, &sql),
                "{sql}: no filter above the scan"
            );
            let (_, scan) = scanned(&connection, &sql);
            // A predicate no frame satisfies may also be found out by DuckDB, which then
            // plans no scan at all.
            assert_eq!(scan.filters, std::slice::from_ref(predicate), "{sql}");

            // With the setting off, every filter is DuckDB's and the scan has none.
            pushdown(&connection, false);
            assert!(filtered_by_duckdb(&connection, &sql), "{sql}");
            let (_, scan) = scanned(&connection, &sql);
            assert_eq!(scan.filters, [None], "{sql}");
            assert_eq!(scan.packets(), (50, 0), "{sql}");
        }
    }
    Ok(())
}

#[test]
fn a_time_window_reads_the_partitions_it_overlaps() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    execute(&connection, "CALL enable_logging(level = 'debug')");
    const FRAMES: u32 = 20_000;
    let capture = Capture::write(
        &fixture,
        "day.pcap",
        &golden::legacy((0..FRAMES).map(golden::udp_frame).collect()),
    );
    let path = &capture.path;
    // Eight partitions of 2,500 frames, each five checkpoint windows of 500.
    partitioned(&connection, 8, 500);
    pushdown(&connection, true);
    let at = |frame: usize| ns(capture.times[frame - 1]);
    let count = |filter: &str| -> (String, Scanned) {
        let sql = format!("SELECT count(*) FROM read_udp('{path}') WHERE {filter}");
        let (result, scanned) = scanned(&connection, &sql);
        (result[0].clone(), scanned)
    };
    let layout = |partitions: usize, frames: u64, of: usize| {
        format!(
            "{partitions} (of 20000 frames, cut at checkpoints 500 frames apart; the filter \
             leaves {frames} frames in {partitions} of {of} partitions)"
        )
    };

    // Without a filter: everything.
    let (rows, scan) = count("true");
    assert_eq!(rows, "20000");
    assert_eq!(
        scan.layouts,
        ["8 (of 20000 frames, cut at checkpoints 500 frames apart)"]
    );
    assert_eq!(scan.partitions.len(), 8);
    assert_eq!(scan.packets(), (20_000, 0));

    // A window of frames 5001 to 6000, which are two checkpoint windows of the third
    // partition. The last window of the capture is read too: a capture may have grown since
    // its index was built, and nothing is known of the timestamps of what was appended.
    let (rows, scan) = count(&format!("timestamp BETWEEN {} AND {}", at(5001), at(6000)));
    assert_eq!(rows, "1000");
    assert_eq!(scan.layouts, [layout(2, 1500, 8)]);
    assert_eq!(scan.partitions, [(5001, 1000, 0), (19_501, 500, 500)]);

    // The same window as two comparisons, half open, and off the checkpoints: the windows it
    // touches are read, and the frames outside it are not parsed.
    let (rows, scan) = count(&format!(
        "timestamp >= {} AND timestamp < {}",
        at(5100),
        at(5900)
    ));
    assert_eq!(rows, "800");
    assert_eq!(scan.layouts, [layout(2, 1500, 8)]);
    assert_eq!(scan.partitions, [(5001, 1000, 199), (19_501, 500, 500)]);

    // A window across two partitions (frames 7001 to 8000 of 5001..7500 and 7501..10000).
    let (rows, scan) = count(&format!(
        "timestamp >= {} AND timestamp <= {}",
        at(7001),
        at(8000)
    ));
    assert_eq!(rows, "1000");
    assert_eq!(scan.layouts, [layout(3, 1500, 8)]);
    assert_eq!(
        scan.partitions,
        [(7001, 500, 0), (7501, 500, 0), (19_501, 500, 500)]
    );

    // One bound, which the scan takes over: everything before frame 1001, and the last window.
    let (rows, scan) = count(&format!("timestamp < {}", at(1001)));
    assert_eq!(rows, "1000");
    assert_eq!(scan.layouts, [layout(2, 1500, 8)]);
    assert_eq!(scan.partitions, [(1, 1000, 0), (19_501, 500, 500)]);

    // With an upper bound on the frame number the end of the capture is ruled out too.
    let (rows, scan) = count(&format!(
        "timestamp BETWEEN {} AND {} AND frame_number <= 6000",
        at(5001),
        at(6000)
    ));
    assert_eq!(rows, "1000");
    assert_eq!(scan.layouts, [layout(1, 1000, 8)]);
    assert_eq!(scan.partitions, [(5001, 1000, 0)]);

    // A range of frame numbers: the one window it is in, read as far as its last frame.
    let (rows, scan) = count("frame_number BETWEEN 5100 AND 5200");
    assert_eq!(rows, "101");
    assert_eq!(scan.layouts, [layout(1, 500, 8)]);
    assert_eq!(scan.partitions, [(5001, 200, 99)]);
    let (rows, scan) = count("frame_number > 19990");
    assert_eq!(rows, "10");
    assert_eq!(scan.layouts, [layout(1, 500, 8)]);
    assert_eq!(scan.partitions, [(19_501, 500, 490)]);
    let (rows, scan) = count("frame_number <= 10");
    assert_eq!(rows, "10");
    assert_eq!(scan.partitions, [(1, 10, 0)]);

    // A window before the capture, or after it: the last window only, with nothing in it.
    let (rows, scan) = count("timestamp < TIMESTAMP '2001-01-01 00:00:00'");
    assert_eq!(rows, "0");
    assert_eq!(scan.layouts, [layout(1, 500, 8)]);
    assert_eq!(scan.partitions, [(19_501, 500, 500)]);

    // A filter no frame satisfies reads nothing at all.
    for filter in [
        "frame_number < 1",
        "timestamp > 'infinity'",
        "frame_number > 18446744073709551615 AND timestamp < 'infinity'",
    ] {
        let (rows, scan) = count(filter);
        assert_eq!(rows, "0");
        assert!(scan.partitions.is_empty(), "{filter}: {scan:?}");
        assert_eq!(
            scan.layouts,
            ["0 (the filter accepts no frame)"],
            "{filter}"
        );
    }
    // A range that is empty because its bounds are exclusive is not known to be: the scan
    // reads as far as the two frames at its bounds, and DuckDB drops them.
    let (rows, scan) = count("frame_number > 7 AND frame_number < 8");
    assert_eq!(rows, "0");
    assert_eq!(scan.partitions, [(1, 8, 6)]);

    // With the setting off the scan reads the capture, whatever the filter.
    pushdown(&connection, false);
    let (rows, scan) = count(&format!("timestamp BETWEEN {} AND {}", at(5001), at(6000)));
    assert_eq!(rows, "1000");
    assert_eq!(scan.packets(), (20_000, 0));
    assert_eq!(scan.partitions.len(), 8);

    // Timestamps that do not ascend: a window is ruled out by the smallest and the largest
    // timestamp in it, so one second, which two frames far apart have, leaves the windows of
    // those two (and every window whose range of timestamps spans that second).
    pushdown(&connection, true);
    let shuffled = Capture::write(&fixture, "shuffled.pcap", &shuffled_times(FRAMES));
    let second = shuffled.times[777] - shuffled.times[777].rem_euclid(1_000_000_000);
    let sql = format!(
        "SELECT frame_number FROM read_frames('{}') WHERE timestamp >= {} AND timestamp < {}",
        shuffled.path,
        ns(second),
        ns(second + 1_000_000_000)
    );
    let (frames, scan) = scanned(&connection, &sql);
    assert_eq!(frames, ["778", "10778"]);
    let (read, skipped) = scan.packets();
    assert_eq!(read - skipped, 2);
    assert!(read <= u64::from(FRAMES), "{scan:?}");
    Ok(())
}

#[test]
fn an_upper_frame_bound_ends_the_read_of_a_capture_that_is_not_split() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    execute(&connection, "CALL enable_logging(level = 'debug')");
    let bytes = golden::legacy((0..20_000).map(golden::udp_frame).collect());
    let gz = Capture::write_as(&fixture, "big.pcap.gz", &bytes, &gzip(&bytes));
    let plain = Capture::write(&fixture, "big.pcap", &bytes);
    partitioned(&connection, 8, 500);
    pushdown(&connection, true);
    let at = |frame: usize| ns(gz.times[frame - 1]);

    for (capture, threads) in [(&gz, 8), (&plain, 1)] {
        set(&connection, "threads", threads);
        let count = |filter: &str| -> (String, Scanned) {
            let sql = format!(
                "SELECT count(*) FROM read_udp('{}') WHERE {filter}",
                capture.path
            );
            let (result, scanned) = scanned(&connection, &sql);
            (result[0].clone(), scanned)
        };
        // Exact bounds: the read ends with the last frame they admit.
        let (rows, scan) = count("frame_number <= 100");
        assert_eq!(rows, "100");
        assert_eq!(scan.layouts.len(), 1);
        assert!(scan.layouts[0].starts_with("1 ("), "{scan:?}");
        assert_eq!(scan.partitions, [(1, 100, 0)]);
        assert_eq!(count("frame_number < 100").1.partitions, [(1, 99, 0)]);
        assert_eq!(count("frame_number = 7").1.partitions, [(1, 7, 6)]);
        assert_eq!(count("frame_number = 7").0, "1");
        // A range, which DuckDB keeps: the read ends at its upper bound all the same.
        let (rows, scan) = count("frame_number BETWEEN 50 AND 100");
        assert_eq!(rows, "51");
        assert_eq!(scan.partitions, [(1, 100, 49)]);
        let (rows, scan) = count("frame_number > 50 AND frame_number < 100");
        assert_eq!(rows, "49");
        assert_eq!(scan.partitions, [(1, 100, 49)]);
        // A lower bound alone, or a bound on the time, ends nothing: every frame is read,
        // and those outside are not parsed.
        assert_eq!(
            count("frame_number > 19990").1.partitions,
            [(1, 20_000, 19_990)]
        );
        let (rows, scan) = count(&format!("timestamp < {}", at(101)));
        assert_eq!(rows, "100");
        assert_eq!(scan.partitions, [(1, 20_000, 19_900)]);
        // Both: the frame bound ends the read.
        let (rows, scan) = count(&format!("timestamp >= {} AND frame_number <= 300", at(101)));
        assert_eq!(rows, "200");
        assert_eq!(scan.partitions, [(1, 300, 100)]);
        // Nothing to read.
        let (rows, scan) = count("frame_number < 1");
        assert_eq!(rows, "0");
        assert!(scan.partitions.is_empty());
        assert_eq!(scan.layouts, ["0 (the filter accepts no frame)"]);
    }
    Ok(())
}

#[test]
fn a_frame_number_filter_applies_to_each_of_several_files() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    execute(&connection, "CALL enable_logging(level = 'debug')");
    let small = golden::legacy(mixed_frames(40));
    let large = golden::pcapng(mixed_frames(2000));
    let other = golden::legacy_nanos(mixed_frames(700));
    let a = fixture.write("a.pcap", &small);
    let b = fixture.write("b.pcapng", &large);
    let c = fixture.write("c.pcap.gz", &gzip(&other));
    let files = format!("['{a}', '{b}', '{c}']");

    for layout in LAYOUTS {
        lay_out(&connection, layout, 100);
        let what = format!("{layout:?}");
        for filter in [
            "frame_number <= 3",
            "frame_number = 40",
            "frame_number BETWEEN 39 AND 41",
            "frame_number > 38 AND frame_number < 42",
            "frame_number > 690",
            "frame_number >= 2000",
            "frame_number > 2000",
            "frame_number < 1",
            "frame_number <= 3 AND filename LIKE '%.pcapng'",
            "frame_number % 500 = 0",
            "timestamp >= TIMESTAMP '2023-11-14 22:13:59' AND frame_number < 45",
        ] {
            for sql in [
                format!(
                    "SELECT parse_filename(filename), frame_number, length \
                     FROM read_frames({files}, filename := true) WHERE {filter}"
                ),
                format!("SELECT count(*) FROM read_udp({files}, filename := true) WHERE {filter}"),
                format!(
                    "SELECT frame_number, src_port FROM read_udp({files}, filename := true) \
                     WHERE {filter}"
                ),
            ] {
                same_either_way(&connection, &sql, &what);
            }
        }
        // The frames of each file that have the number, in file order: frame_number counts
        // within a file, and so does a filter on it.
        pushdown(&connection, true);
        let frames = |filter: &str| -> Vec<Vec<String>> {
            let sql = format!(
                "SELECT parse_filename(filename), frame_number \
                 FROM read_frames({files}, filename := true) WHERE {filter}"
            );
            rows(&connection, &sql).unwrap_or_else(|error| panic!("{sql}: {error}"))
        };
        assert_eq!(
            frames("frame_number <= 2"),
            [
                ["a.pcap", "1"],
                ["a.pcap", "2"],
                ["b.pcapng", "1"],
                ["b.pcapng", "2"],
                ["c.pcap.gz", "1"],
                ["c.pcap.gz", "2"]
            ],
            "{what}"
        );
        assert_eq!(
            frames("frame_number BETWEEN 40 AND 41"),
            [
                ["a.pcap", "40"],
                ["b.pcapng", "40"],
                ["b.pcapng", "41"],
                ["c.pcap.gz", "40"],
                ["c.pcap.gz", "41"]
            ],
            "{what}"
        );
        assert_eq!(
            frames("frame_number >= 700"),
            (700..=2000)
                .map(|frame| vec!["b.pcapng".to_owned(), frame.to_string()])
                .chain([vec!["c.pcap.gz".to_owned(), "700".to_owned()]])
                .collect::<Vec<_>>(),
            "{what}"
        );
    }

    // What is read of each file: the first frames of each, and of the split one the window
    // they are in.
    partitioned(&connection, 4, 100);
    pushdown(&connection, true);
    let sql = format!("SELECT count(*) FROM read_frames({files}) WHERE frame_number <= 3");
    let (rows, scan) = scanned(&connection, &sql);
    assert_eq!(rows, ["9"]);
    assert_eq!(
        scan.layouts,
        [
            "1 (40 frames give no place to split at, with a checkpoint every 100 frames)",
            "1 (of 2000 frames, cut at checkpoints 100 frames apart; the filter leaves 100 \
             frames in 1 of 4 partitions)",
            "1 (a compressed capture cannot be split)",
        ]
    );
    assert_eq!(scan.partitions, [(1, 3, 0), (1, 3, 0), (1, 3, 0)]);
    // A filter no frame satisfies opens none of them.
    let sql = format!("SELECT count(*) FROM read_frames({files}) WHERE frame_number < 1");
    let (rows, scan) = scanned(&connection, &sql);
    assert_eq!(rows, ["0"]);
    assert_eq!(scan.layouts, ["0 (the filter accepts no frame)"; 3]);
    assert!(scan.partitions.is_empty());
    Ok(())
}

#[test]
fn a_prepared_filter_is_taken_over_when_it_has_its_value() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    execute(&connection, "CALL enable_logging(level = 'debug')");
    let capture = Capture::write(&fixture, "x.pcap", &golden::legacy_nanos(mixed_frames(600)));
    let path = &capture.path;
    partitioned(&connection, 4, 100);
    pushdown(&connection, true);

    // The filter is not understood while it holds a parameter. DuckDB plans the statement
    // again when it is executed, with the value in its place, and the scan then takes it over:
    // each execution filters by its own value.
    execute(
        &connection,
        &format!(
            "PREPARE upto AS SELECT frame_number FROM read_frames('{path}') \
             WHERE frame_number <= $1"
        ),
    );
    for bound in [7_u64, 3, 250, 0, 600, 7] {
        let (frames, scan) = scanned(&connection, &format!("EXECUTE upto({bound})"));
        let expected: Vec<String> = (1..=bound).map(|frame| frame.to_string()).collect();
        assert_eq!(frames, expected, "upto({bound})");
        let filter = match bound {
            0 => "no frame".to_owned(),
            bound => format!("frame_number in (.., {bound}]"),
        };
        assert_eq!(scan.filters, [Some(filter)], "upto({bound})");
        assert_eq!(scan.packets(), (bound, 0), "upto({bound})");
    }
    // The value has its own type when the statement is planned again: a negative one is
    // compared as an integer, and no frame number is below it.
    let (frames, scan) = scanned(&connection, "EXECUTE upto(-1)");
    assert!(frames.is_empty());
    assert_eq!(scan.filters, [Some("no frame".to_owned())]);
    assert!(scan.partitions.is_empty());

    // The same through the client API, which prepares, binds and runs in one call.
    let sql = format!("SELECT count(*) FROM read_frames('{path}') WHERE frame_number <= $1");
    for (parameter, expected) in [(5_i64, 5_u64), (600, 600), (601, 600), (-3, 0)] {
        logged(&connection);
        let count = {
            let mut result =
                connection.query(sql.as_str(), Parameters::positional(&[&parameter]))?;
            let chunk = result.next_chunk()?.expect("count(*) returns a row");
            chunk
                .get_vector_at::<Unknown>(0)?
                .get_value_slow(0)?
                .to_string()
        };
        assert_eq!(count, expected.to_string(), "$1 = {parameter}");
        let scan = Scanned::of(&logged(&connection));
        assert_eq!(scan.packets(), (expected, 0), "$1 = {parameter}");
        assert!(scan.filters[0].is_some(), "$1 = {parameter}: {scan:?}");
    }

    // Two parameters on one column: a range, which the scan narrows by and DuckDB keeps.
    execute(
        &connection,
        &format!(
            "PREPARE between AS SELECT count(*) FROM read_udp('{path}') \
             WHERE timestamp >= $1 AND timestamp < $2 AND frame_number % 2 = $3"
        ),
    );
    for (from, to) in [(100, 200), (1, 600), (300, 300), (500, 450)] {
        let call = format!(
            "EXECUTE between({}, {}, 0)",
            ns(capture.times[from - 1]),
            ns(capture.times[to - 1])
        );
        let (count, scan) = scanned(&connection, &call);
        let direct = format!(
            "SELECT count(*) FROM read_udp('{path}') WHERE frame_number >= {from} \
             AND frame_number < {to} AND frame_number % 2 = 0"
        );
        pushdown(&connection, false);
        assert_eq!(count, column(&connection, &direct)?, "{call}");
        pushdown(&connection, true);
        if let [Some(filter)] = &scan.filters[..] {
            assert!(
                filter == "no frame" || filter.starts_with("timestamp in ["),
                "{call}: {filter}"
            );
        } else {
            // An inverted range DuckDB may find out for itself: no scan.
            assert!(scan.filters.is_empty(), "{call}: {scan:?}");
        }
    }

    // Without parameters the filter is taken over when the statement is prepared, and every
    // execution uses it.
    execute(
        &connection,
        &format!("PREPARE nine AS SELECT count(*) FROM read_udp('{path}') WHERE frame_number <= 9"),
    );
    let direct = value(
        &connection,
        &format!("SELECT count(*) FROM read_udp('{path}') WHERE frame_number <= 9"),
    )?;
    for _ in 0..3 {
        let (count, scan) = scanned(&connection, "EXECUTE nine");
        assert_eq!(count, std::slice::from_ref(&direct));
        assert_eq!(scan.filters, [Some("frame_number in (.., 9]".to_owned())]);
        assert_eq!(scan.packets(), (9, 0));
    }
    // The setting counts when a statement is planned: this one keeps its filter in the scan.
    pushdown(&connection, false);
    let (count, scan) = scanned(&connection, "EXECUTE nine");
    assert_eq!(count, std::slice::from_ref(&direct));
    assert_eq!(scan.packets(), (9, 0));
    // One with a parameter is planned again, and so follows the setting.
    let (frames, scan) = scanned(&connection, "EXECUTE upto(4)");
    assert_eq!(frames, ["1", "2", "3", "4"]);
    assert_eq!(scan.filters, [None]);
    assert_eq!(scan.packets(), (600, 0));

    // A view, a subquery and a join pass the filter down to their scans.
    pushdown(&connection, true);
    execute(
        &connection,
        &format!("CREATE VIEW udp AS SELECT * FROM read_udp('{path}')"),
    );
    for sql in [
        "SELECT count(*) FROM udp WHERE frame_number <= 12".to_owned(),
        format!(
            "SELECT count(*) FROM (SELECT frame_number AS n, length FROM read_frames('{path}')) \
             WHERE n <= 12 AND length > 0"
        ),
        format!(
            "WITH frames AS (SELECT * FROM read_frames('{path}')) \
             SELECT count(*) FROM frames WHERE frame_number <= 12"
        ),
    ] {
        let (_, scan) = scanned(&connection, &sql);
        assert_eq!(
            scan.filters,
            [Some("frame_number in (.., 12]".to_owned())],
            "{sql}"
        );
        assert_eq!(scan.packets(), (12, 0), "{sql}");
        same_either_way(&connection, &sql, "");
    }
    let join = format!(
        "SELECT f.frame_number, u.src_port FROM read_frames('{path}') f \
         JOIN read_udp('{path}') u USING (frame_number) \
         WHERE f.frame_number BETWEEN 100 AND 110 AND u.encap_depth = 0 ORDER BY ALL"
    );
    assert_eq!(same_either_way(&connection, &join, "").len(), 11);
    Ok(())
}

#[test]
fn two_scans_of_one_capture_with_different_filters_keep_their_own_rows() -> Result<()> {
    // DuckDB's `common_subplan` optimizer merges subplans whose plans are the same. Two scans
    // of one file are the same call, so if a filter went into the scan and out of the plan,
    // two differently filtered scans would look alike and one would get the other's rows.
    let connection = connect()?;
    let fixture = Fixture::new();
    let capture = Capture::write(&fixture, "x.pcap", &golden::legacy_nanos(mixed_frames(300)));
    let path = &capture.path;
    let early = ns(capture.times[10]);
    let late = ns(capture.times[294]);
    // (the first filter, the second, the frames of each)
    let filters = [
        ("frame_number < 10", "frame_number > 295", 9, 5),
        (
            &*format!("timestamp < {early}"),
            &*format!("timestamp > {late}"),
            10,
            5,
        ),
    ];
    for (first, second, first_count, second_count) in filters {
        let union = format!(
            "SELECT 'a', count(*) FROM read_frames('{path}') WHERE {first} \
             UNION ALL SELECT 'b', count(*) FROM read_frames('{path}') WHERE {second} \
             ORDER BY ALL"
        );
        // The two sides are alike but for their filters, as in the union.
        let join = format!(
            "SELECT a.n, b.n \
             FROM (SELECT count(*) AS n, min(frame_number) AS low \
                   FROM read_frames('{path}') WHERE {first}) a \
             JOIN (SELECT count(*) AS n, min(frame_number) AS low \
                   FROM read_frames('{path}') WHERE {second}) b \
             ON a.low < b.low"
        );
        let udp = format!(
            "SELECT 'a', count(DISTINCT frame_number) FROM read_udp('{path}') WHERE {first} \
             UNION ALL SELECT 'b', count(DISTINCT frame_number) FROM read_udp('{path}') \
             WHERE {second} ORDER BY ALL"
        );
        // A common table expression that DuckDB inlines: a copy of one scan for each use.
        let cte = format!(
            "WITH t AS NOT MATERIALIZED (SELECT frame_number, timestamp FROM read_frames('{path}')) \
             SELECT 'a', count(*) FROM t WHERE {first} \
             UNION ALL SELECT 'b', count(*) FROM t WHERE {second} ORDER BY ALL"
        );
        for layout in LAYOUTS {
            lay_out(&connection, layout, 50);
            let what = format!("{layout:?}");
            let expected = vec![
                vec!["a".to_owned(), first_count.to_string()],
                vec!["b".to_owned(), second_count.to_string()],
            ];
            assert_eq!(
                same_either_way(&connection, &union, &what),
                expected,
                "{union}"
            );
            assert_eq!(same_either_way(&connection, &udp, &what), expected, "{udp}");
            assert_eq!(same_either_way(&connection, &cte, &what), expected, "{cte}");
            assert_eq!(
                same_either_way(&connection, &join, &what),
                [[first_count.to_string(), second_count.to_string()]],
                "{join}"
            );
        }
    }
    Ok(())
}

#[test]
fn a_filter_that_ends_a_read_early_finds_the_capture_truncated_only_when_strict() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    execute(&connection, "CALL enable_logging(level = 'warning')");
    let whole = golden::legacy((0..3000).map(golden::udp_frame).collect());
    let cut = &whole[..whole.len() - 5];
    let plain = fixture.write("cut.pcap", cut);
    let gz = fixture.write("cut.pcap.gz", &gzip(cut));
    let warnings = || -> usize {
        let count = value(
            &connection,
            "SELECT count(*) FROM duckdb_logs WHERE type = 'pcapsql' AND log_level = 'WARNING'",
        )
        .unwrap();
        execute(&connection, "CALL truncate_duckdb_logs()");
        count.parse().unwrap()
    };
    let truncated = |sql: &str| {
        let error = rows(&connection, sql).expect_err(sql);
        assert!(error.message.contains("is truncated"), "{sql}: {error}");
        assert!(error.message.contains("frame 2999,"), "{sql}: {error}");
    };
    pushdown(&connection, true);

    // Read as one partition: on one thread, on four with the parallel scan off, and the
    // compressed capture on four threads with it on. Like a LIMIT, a frame bound that ends the
    // read before the broken tail reports nothing; a filter that reads to the end does. A
    // strict scan is about the whole capture: it reads on to the end and fails, whatever the
    // bound.
    let one_partition: [(&dyn Fn(), &[&String]); 3] = [
        (&|| partitioned(&connection, 1, 500), &[&plain, &gz]),
        (&|| unpartitioned(&connection, 4), &[&plain, &gz]),
        (&|| partitioned(&connection, 4, 500), &[&gz]),
    ];
    for (set_up, paths) in one_partition {
        set_up();
        for path in paths {
            let sql = format!("SELECT count(*) FROM read_udp('{path}') WHERE frame_number <= 100");
            assert_eq!(value(&connection, &sql)?, "100", "{sql}");
            assert_eq!(warnings(), 0, "{sql}");
            let to_the_end =
                format!("SELECT count(*) FROM read_udp('{path}') WHERE frame_number > 100");
            assert_eq!(value(&connection, &to_the_end)?, "2899");
            assert_eq!(warnings(), 1);
            for filter in [
                "frame_number <= 100",
                "frame_number > 100",
                "frame_number = 1",
            ] {
                truncated(&format!(
                    "SELECT count(*) FROM read_udp('{path}', strict := true) WHERE {filter}"
                ));
            }
        }
    }

    // Split on four threads: a strict scan looks at the tail when it starts, whatever the
    // filter leaves of the capture, as it does whatever a LIMIT leaves. The same errors.
    partitioned(&connection, 4, 500);
    let sql = format!("SELECT count(*) FROM read_udp('{plain}') WHERE frame_number <= 100");
    assert_eq!(value(&connection, &sql)?, "100");
    assert_eq!(warnings(), 0);
    for filter in [
        "frame_number <= 100",
        "frame_number > 100",
        "frame_number = 1",
    ] {
        truncated(&format!(
            "SELECT count(*) FROM read_udp('{plain}', strict := true) WHERE {filter}"
        ));
    }
    Ok(())
}

#[test]
fn the_setting_is_a_boolean_that_is_on_by_default() -> Result<()> {
    let connection = connect()?;
    assert_eq!(
        value(
            &connection,
            "SELECT current_setting('pcapsql_filter_pushdown')"
        )?,
        "true"
    );
    assert_eq!(
        rows(
            &connection,
            "SELECT input_type, description FROM duckdb_settings() \
             WHERE name = 'pcapsql_filter_pushdown'"
        )?,
        [[
            "BOOLEAN",
            "Apply filters on frame_number and timestamp in the scan of a capture"
        ]]
    );
    execute(&connection, "SET pcapsql_filter_pushdown = false");
    assert_eq!(
        value(
            &connection,
            "SELECT current_setting('pcapsql_filter_pushdown')"
        )?,
        "false"
    );
    execute(&connection, "RESET pcapsql_filter_pushdown");
    assert_eq!(
        value(
            &connection,
            "SELECT current_setting('pcapsql_filter_pushdown')"
        )?,
        "true"
    );
    let error = connection
        .execute("SET pcapsql_filter_pushdown = NULL", Parameters::None)
        .unwrap_err();
    assert!(
        error
            .message
            .contains("pcapsql_filter_pushdown must not be NULL"),
        "{error}"
    );
    assert!(connection
        .execute(
            "SET pcapsql_filter_pushdown = 'sometimes'",
            Parameters::None
        )
        .is_err());
    Ok(())
}
