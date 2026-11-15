//! `pcap_time_range(files)` and the macros over it: `start_time(files)`, `end_time(files)` and
//! `relative_time(ts, files)`.
//!
//! What the table function says of a capture is compared with what a scan of its frames
//! returns and with what core's packet reader delivers; what the macros return is compared with
//! the DataFusion frontend's functions of the same names in `golden_differential.rs` (the corpus
//! queries `q24_time_udfs` and `q25_time_range_only`).

use std::io::Write;
use std::path::Path;

use duckdb_neo::{connection::Connection, Parameters, Result};
use pcapsql_core::io::{PacketReader, ReadPacketReader, StreamHeader};
use pcapsql_duckdb_itest::{column, connect, golden, rows, value, Fixture};
use pcapsql_testgen::{legacy_pcap, LegacyVariant};

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn zstd(bytes: &[u8]) -> Vec<u8> {
    zstd::encode_all(bytes, 3).unwrap()
}

fn row(cells: &[&str]) -> Vec<String> {
    cells.iter().map(|cell| cell.to_string()).collect()
}

fn frames(count: u32) -> Vec<Vec<u8>> {
    (0..count).map(golden::udp_frame).collect()
}

/// A capture without a frame: the header of a legacy pcap file and nothing else.
fn empty_capture() -> Vec<u8> {
    legacy_pcap(LegacyVariant::LeMicro, 1, 65535, &[]).bytes
}

/// The smallest and largest timestamp (nanoseconds) and the number of the frames core's packet
/// reader delivers from `bytes`, and whether the capture ends inside a record.
fn reference(bytes: &[u8]) -> (Option<(i64, i64)>, u64, bool) {
    let mut input = bytes;
    let (header, head) = StreamHeader::probe(&mut input).unwrap();
    let mut reader = ReadPacketReader::sequential(input, &header, head).unwrap();
    let mut range: Option<(i64, i64)> = None;
    let mut count = 0;
    while reader
        .process_packets(1000, |packet| {
            let at = packet.timestamp_ns;
            range = Some(range.map_or((at, at), |(start, end)| (start.min(at), end.max(at))));
            count += 1;
            Ok(())
        })
        .unwrap()
        > 0
    {}
    (range, count, reader.truncated())
}

/// `epoch_ns` of both ends, the frames and `truncated` of the one row of `path`.
const SUMMARY: &str =
    "epoch_ns(start_time)::VARCHAR, epoch_ns(end_time)::VARCHAR, frames, truncated";

fn summary_row(range: Option<(i64, i64)>, count: u64, truncated: bool) -> Vec<String> {
    let end = |pick: fn((i64, i64)) -> i64| {
        range.map_or_else(|| "NULL".to_owned(), |range| pick(range).to_string())
    };
    vec![
        end(|range| range.0),
        end(|range| range.1),
        count.to_string(),
        truncated.to_string(),
    ]
}

/// The captures of the fuzzing corpus: real ones, classic pcap of either byte order and pcapng.
fn corpus() -> Vec<(String, String)> {
    let directory =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/fuzz_pcap_reader");
    let mut captures: Vec<(String, String)> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .map(|path| {
            (
                path.file_name().unwrap().to_str().unwrap().to_owned(),
                path.to_str().unwrap().to_owned(),
            )
        })
        .collect();
    captures.sort();
    assert!(captures.len() >= 25, "{}", captures.len());
    captures
}

#[test]
fn the_function_and_its_columns() -> Result<()> {
    let connection = connect()?;
    assert_eq!(
        rows(
            &connection,
            "SELECT function_type, parameters::VARCHAR, parameter_types::VARCHAR
             FROM duckdb_functions() WHERE function_name = 'pcap_time_range'",
        )?,
        [row(&["table", "[files, strict]", "[ANY, BOOLEAN]"])]
    );
    let fixture = Fixture::new();
    let path = fixture.write("a.pcap", &golden::legacy(frames(3)));
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT column_name, column_type FROM (DESCRIBE SELECT * FROM pcap_time_range('{path}'))"
            ),
        )?,
        [
            row(&["filename", "VARCHAR"]),
            row(&["start_time", "TIMESTAMP_NS"]),
            row(&["end_time", "TIMESTAMP_NS"]),
            row(&["frames", "UBIGINT"]),
            row(&["duration", "DOUBLE"]),
            row(&["link_type", "UINTEGER"]),
            row(&["truncated", "BOOLEAN"]),
        ]
    );
    // The type of `read_frames.timestamp`.
    assert_eq!(
        value(
            &connection,
            &format!("SELECT typeof(timestamp) FROM read_frames('{path}') LIMIT 1")
        )?,
        "TIMESTAMP_NS"
    );
    assert_eq!(
        rows(
            &connection,
            &format!("SELECT * FROM pcap_time_range('{path}')")
        )?,
        [row(&[
            &path,
            "2023-11-14 22:13:20",
            "2023-11-14 22:13:22.002",
            "3",
            "2.002",
            "1",
            "false",
        ])]
    );
    Ok(())
}

#[test]
fn a_row_is_what_a_scan_of_the_frames_finds() -> Result<()> {
    let connection = connect()?;
    let mut compared = 0;
    for (name, path) in corpus() {
        let bytes = std::fs::read(&path).unwrap();
        let (range, count, truncated) = reference(&bytes);
        let expected = summary_row(range, count, truncated);
        assert_eq!(
            rows(
                &connection,
                &format!("SELECT {SUMMARY} FROM pcap_time_range('{path}')")
            )?,
            std::slice::from_ref(&expected),
            "{name}"
        );
        // And what DuckDB aggregates from the scan function, with the filename as it expanded.
        assert_eq!(
            rows(
                &connection,
                &format!(
                    "SELECT epoch_ns(min(timestamp))::VARCHAR, epoch_ns(max(timestamp))::VARCHAR,
                            count(*), false, any_value(filename)
                     FROM read_frames('{path}', filename := true)"
                )
            )?[0][..3],
            expected[..3],
            "{name}"
        );
        assert_eq!(
            value(
                &connection,
                &format!("SELECT filename FROM pcap_time_range('{path}')")
            )?,
            path
        );
        compared += 1;
    }
    assert!(compared >= 25);
    Ok(())
}

#[test]
fn nanoseconds_compression_and_formats() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let nanos = golden::legacy_nanos(frames(700));
    let ng = golden::pcapng(frames(300));
    // Not in time order: the range is over all frames.
    let shuffled = golden::legacy_nanos_at(frames(5), |i| {
        [(50, 7), (10, 1), (90, 999_999_999), (10, 0), (60, 5)][i]
    });
    for (name, plain, written) in [
        ("nanos.pcap", &nanos, nanos.clone()),
        ("nanos.pcap.gz", &nanos, gzip(&nanos)),
        ("nanos.pcap.zst", &nanos, zstd(&nanos)),
        ("ng.pcapng", &ng, ng.clone()),
        ("ng.pcapng.gz", &ng, gzip(&ng)),
        ("shuffled.pcap", &shuffled, shuffled.clone()),
    ] {
        let path = fixture.write(name, &written);
        let (range, count, truncated) = reference(plain);
        assert!(!truncated);
        assert_eq!(
            rows(
                &connection,
                &format!("SELECT {SUMMARY} FROM pcap_time_range('{path}')")
            )?,
            [summary_row(range, count, false)],
            "{name}"
        );
    }
    let path = fixture.path("shuffled.pcap");
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT start_time::VARCHAR, end_time::VARCHAR, duration FROM pcap_time_range('{path}')"
            )
        )?,
        [row(&[
            "1970-01-01 00:00:10",
            "1970-01-01 00:01:30.999999999",
            "80.999999999",
        ])]
    );
    // The digits below the microsecond are kept.
    let path = fixture.path("nanos.pcap");
    let first = value(
        &connection,
        &format!("SELECT epoch_ns(start_time) % 1000 FROM pcap_time_range('{path}')"),
    )?;
    assert_eq!(first, (golden::nanos_of(0) % 1000).to_string());
    assert_ne!(first, "0");
    Ok(())
}

#[test]
fn several_files_are_a_row_each_whatever_the_threads() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let mut expected = Vec::new();
    for index in 0..12_u32 {
        let capture = golden::legacy_nanos_at(frames(40 + index), |i| {
            (1_000 * (index + 1) + i as u32, index)
        });
        let name = format!("part-{index:02}.pcap");
        let path = if index % 3 == 0 {
            fixture.write(&format!("{name}.gz"), &gzip(&capture))
        } else {
            fixture.write(&name, &capture)
        };
        let (range, count, _) = reference(&capture);
        let mut row = vec![path];
        row.extend(summary_row(range, count, false));
        expected.push(row);
    }
    expected.sort();
    let pattern = fixture.path("part-*");
    for threads in [1, 4] {
        connection.execute(format!("SET threads = {threads}"), Parameters::None)?;
        assert_eq!(
            rows(
                &connection,
                &format!(
                    "SELECT filename, {SUMMARY} FROM pcap_time_range('{pattern}') ORDER BY filename"
                )
            )?,
            expected,
            "{threads} threads"
        );
        // A list, with a file named twice: read twice.
        let first = &expected[0][0];
        let last = &expected[11][0];
        assert_eq!(
            column(
                &connection,
                &format!(
                    "SELECT filename FROM pcap_time_range(['{last}', '{first}', '{last}']) ORDER BY ALL"
                )
            )?,
            [first.clone(), last.clone(), last.clone()],
        );
    }
    // The macros over the files: the smallest start and the largest end.
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT epoch_ns(start_time('{pattern}')), epoch_ns(end_time('{pattern}')),
                        (SELECT epoch_ns(min(timestamp)) FROM read_frames('{pattern}')),
                        (SELECT epoch_ns(max(timestamp)) FROM read_frames('{pattern}'))"
            )
        )?,
        [row(&[
            "1000000000000",
            "12050000000011",
            "1000000000000",
            "12050000000011",
        ])]
    );
    Ok(())
}

#[test]
fn a_capture_without_frames_has_a_row_of_nulls_and_the_macros_are_null() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let empty = fixture.write("empty.pcap", &empty_capture());
    let full = fixture.write("full.pcap", &golden::legacy(frames(2)));
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT start_time, end_time, frames, duration, link_type, truncated
                 FROM pcap_time_range('{empty}')"
            )
        )?,
        [row(&["NULL", "NULL", "0", "NULL", "1", "false"])]
    );
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT start_time('{empty}'), end_time('{empty}'),
                        relative_time(TIMESTAMP_NS '2023-11-14 22:13:20', '{empty}'),
                        typeof(start_time('{empty}')), typeof(relative_time(now(), '{empty}'))"
            )
        )?,
        [row(&["NULL", "NULL", "NULL", "TIMESTAMP_NS", "DOUBLE"])]
    );
    // With a capture that has frames, the empty one adds nothing.
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT start_time(['{empty}', '{full}'])::VARCHAR, end_time(['{full}', '{empty}'])::VARCHAR"
            )
        )?,
        [row(&["2023-11-14 22:13:20", "2023-11-14 22:13:21.001"])]
    );
    Ok(())
}

#[test]
fn relative_time_is_seconds_since_the_start_as_a_double() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let capture = golden::legacy_nanos(frames(50));
    let path = fixture.write("a.pcap", &capture);
    let (range, _, _) = reference(&capture);
    let start = range.unwrap().0;
    let actual = rows(
        &connection,
        &format!(
            "SELECT epoch_ns(timestamp), relative_time(timestamp, '{path}'),
                    typeof(relative_time(timestamp, '{path}'))
             FROM read_frames('{path}') ORDER BY frame_number"
        ),
    )?;
    assert_eq!(actual.len(), 50);
    for cells in &actual {
        let at: i64 = cells[0].parse().unwrap();
        // The division the command-line tool's function does, on nanoseconds.
        let expected = (at - start) as f64 / 1e9;
        assert_eq!(cells[1].parse::<f64>().unwrap(), expected, "{cells:?}");
        assert_eq!(cells[2], "DOUBLE");
    }
    // NULL in, NULL out; a TIMESTAMP (microseconds) and a TIMESTAMPTZ are taken too, and a
    // timestamp before the start is negative.
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT relative_time(NULL::TIMESTAMP_NS, '{path}'),
                        relative_time(TIMESTAMP '2023-11-14 22:13:21.5', '{path}')
                            - relative_time(TIMESTAMP '2023-11-14 22:13:20.5', '{path}'),
                        relative_time(TIMESTAMPTZ '2023-11-14 22:13:19+00', '{path}') < -0.9,
                        relative_time(start_time('{path}'), '{path}')"
            )
        )?,
        [row(&["NULL", "1.0", "true", "0.0"])]
    );
    Ok(())
}

/// The number of `PCAP_TIME_RANGE` scans in the plan of `sql`, and how many rows they
/// returned when it ran.
fn time_range_scans(connection: &Connection, sql: &str) -> Result<(usize, Vec<String>)> {
    let plan = rows(connection, &format!("EXPLAIN (ANALYZE, FORMAT JSON) {sql}"))?;
    let text = plan
        .iter()
        .flat_map(|row| row.iter())
        .cloned()
        .collect::<String>();
    let scans = text.matches("PCAP_TIME_RANGE").count();
    Ok((scans, vec![text]))
}

#[test]
fn the_subquery_runs_once_for_a_projection_and_a_filter() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let path = fixture.write("a.pcap", &golden::legacy(frames(5000)));
    let sql = format!(
        "SELECT frame_number, relative_time(timestamp, '{path}') AS rel
         FROM read_frames('{path}')
         WHERE relative_time(timestamp, '{path}') BETWEEN 10 AND 12.5
         ORDER BY frame_number"
    );
    // Frame i (from 0) is at i seconds and i milliseconds.
    assert_eq!(
        rows(&connection, &sql)?,
        [
            row(&["11", "10.01"]),
            row(&["12", "11.011"]),
            row(&["13", "12.012"])
        ]
    );
    // One scan of `pcap_time_range` in the plan, though the macro is written three times and
    // applied to 5,000 rows: DuckDB plans the subquery as one common subplan.
    let (scans, plan) = time_range_scans(&connection, &sql)?;
    assert_eq!(scans, 1, "{plan:?}");
    // A second file is a second subquery.
    let other = fixture.write("b.pcap", &golden::legacy(frames(3)));
    let (scans, plan) = time_range_scans(
        &connection,
        &format!(
            "SELECT relative_time(timestamp, '{path}'), relative_time(timestamp, '{other}')
             FROM read_frames('{path}')"
        ),
    )?;
    assert_eq!(scans, 2, "{plan:?}");
    Ok(())
}

#[test]
fn a_truncated_capture_is_flagged_or_refused_when_strict() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let whole = golden::legacy(frames(30));
    let cut = &whole[..whole.len() - 7];
    let (range, count, truncated) = reference(cut);
    assert!(truncated);
    assert_eq!(count, 29);
    for (name, bytes) in [("cut.pcap", cut.to_vec()), ("cut.pcap.gz", gzip(cut))] {
        let path = fixture.write(name, &bytes);
        assert_eq!(
            rows(
                &connection,
                &format!("SELECT {SUMMARY} FROM pcap_time_range('{path}')")
            )?,
            [summary_row(range, 29, true)],
            "{name}"
        );
        let error = rows(
            &connection,
            &format!("SELECT * FROM pcap_time_range('{path}', strict := true)"),
        )
        .unwrap_err();
        assert!(
            error.message.contains(&format!(
                "pcap_time_range: '{path}' is truncated: the capture ends inside the record that \
                 follows frame 29"
            )),
            "{error}"
        );
        // The macros read without `strict`: the complete frames.
        assert_eq!(
            value(&connection, &format!("SELECT epoch_ns(end_time('{path}'))"))?,
            range.unwrap().1.to_string()
        );
    }
    // A whole capture is not refused, and a truncated one among several fails the statement.
    let good = fixture.write("good.pcap", &whole);
    assert_eq!(
        value(
            &connection,
            &format!("SELECT frames FROM pcap_time_range('{good}', strict := true)")
        )?,
        "30"
    );
    let cut_path = fixture.path("cut.pcap");
    assert!(rows(
        &connection,
        &format!("SELECT * FROM pcap_time_range(['{good}', '{cut_path}'], strict := true)"),
    )
    .is_err());
    Ok(())
}

#[test]
fn what_cannot_be_read_is_an_error_that_names_the_function() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let good = fixture.write("good.pcap", &golden::legacy(frames(2)));
    let text = fixture.write("notes.txt", b"not a capture, whatever its length is\n");
    let missing = fixture.path("missing.pcap");
    let nothing = fixture.path("*.pcapng");
    for (sql, expected) in [
        (
            format!("SELECT * FROM pcap_time_range('{text}')"),
            "is not a capture file pcapsql can read".to_owned(),
        ),
        (
            format!("SELECT * FROM pcap_time_range(['{good}', '{text}'])"),
            format!("pcap_time_range: '{text}' is not a capture file"),
        ),
        (
            format!("SELECT * FROM pcap_time_range('{missing}')"),
            "missing.pcap".to_owned(),
        ),
        (
            format!("SELECT * FROM pcap_time_range('{nothing}')"),
            format!("pcap_time_range: no file matches the pattern '{nothing}'"),
        ),
        (
            "SELECT * FROM pcap_time_range(NULL)".to_owned(),
            "pcap_time_range: the capture file must not be NULL".to_owned(),
        ),
        (
            "SELECT * FROM pcap_time_range([])".to_owned(),
            "pcap_time_range: the list of capture files is empty".to_owned(),
        ),
        (
            "SELECT * FROM pcap_time_range(42)".to_owned(),
            "pcap_time_range: the capture files must be a VARCHAR path or pattern".to_owned(),
        ),
        (
            format!("SELECT * FROM pcap_time_range('{good}', strict := NULL)"),
            "pcap_time_range: strict must be a constant and must not be NULL".to_owned(),
        ),
        // The macros are that function: its errors, and no capture that is a column.
        (
            format!("SELECT start_time('{text}')"),
            "is not a capture file pcapsql can read".to_owned(),
        ),
        (
            format!("SELECT end_time('{nothing}')"),
            "no file matches the pattern".to_owned(),
        ),
        (
            format!(
                "SELECT relative_time(timestamp, filename) FROM read_frames('{good}', filename := true)"
            ),
            "\"pcap_time_range\" does not support lateral join column parameters".to_owned(),
        ),
    ] {
        let error = rows(&connection, &sql).unwrap_err();
        assert!(error.message.contains(&expected), "{sql}: {error}");
    }
    Ok(())
}

#[test]
fn the_macros_are_registered_with_their_parameters() -> Result<()> {
    let connection = connect()?;
    assert_eq!(
        rows(
            &connection,
            "SELECT function_name, function_type, parameters::VARCHAR, macro_definition
             FROM duckdb_functions()
             WHERE function_name IN ('start_time', 'end_time', 'relative_time')
             ORDER BY function_name",
        )?,
        [
            row(&[
                "end_time",
                "macro",
                "[files]",
                "(SELECT max(end_time) FROM pcap_time_range(files))"
            ]),
            row(&[
                "relative_time",
                "macro",
                "[ts, files]",
                "((epoch_ns(ts) - epoch_ns((SELECT min(start_time) FROM pcap_time_range(files)))) / 1e9)"
            ]),
            row(&[
                "start_time",
                "macro",
                "[files]",
                "(SELECT min(start_time) FROM pcap_time_range(files))"
            ]),
        ]
    );
    Ok(())
}
