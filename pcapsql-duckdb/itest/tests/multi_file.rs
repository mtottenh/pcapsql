//! Several captures in one call: a list, a glob pattern, a list of patterns; the `filename`
//! column; and the replacement scan (`FROM 'x.pcap'`).
//!
//! What a call over several files must return is the rows of each file's own scan, one file
//! after the other in the order the files are read. `reference_rows` gives the rows of one
//! capture without DuckDB; the tests here concatenate them and compare, cell by cell and in
//! order, on 1, 2, 4 and 8 threads, with the files split into partitions and not.

use std::io::Write;

use duckdb_neo::{connection::Connection, Parameters, Result};
use pcapsql_core::scan::{testing::Cell, ColKind, OutColumn};
use pcapsql_duckdb_itest::{
    column, connect, golden, reference_rows, replay::query_cells, rows, value, Fixture,
};

const THREADS: [usize; 4] = [1, 2, 4, 8];

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn zstd(bytes: &[u8]) -> Vec<u8> {
    zstd::encode_all(bytes, 3).unwrap()
}

fn set(connection: &Connection, setting: &str, value: impl std::fmt::Display) {
    let sql = format!("SET {setting} = {value}");
    connection
        .execute(sql.as_str(), Parameters::None)
        .unwrap_or_else(|error| panic!("{sql}: {error}"));
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

/// The records of `level` the extension logged since the log was last cleared, oldest first.
fn logged(connection: &Connection, level: &str) -> Vec<String> {
    let records = column(
        connection,
        &format!(
            "SELECT message FROM duckdb_logs WHERE type = 'pcapsql' AND log_level = '{level}' \
             ORDER BY timestamp, context_id"
        ),
    )
    .unwrap();
    execute(connection, "CALL truncate_duckdb_logs()");
    records
}

/// A SQL list of `paths`.
fn list(paths: &[&str]) -> String {
    let quoted: Vec<String> = paths.iter().map(|path| format!("'{path}'")).collect();
    format!("[{}]", quoted.join(", "))
}

fn kinds(columns: &[OutColumn]) -> Vec<ColKind> {
    columns.iter().map(|column| column.kind).collect()
}

/// Assert that `sql` returns exactly `expected`, in order.
fn assert_cells(connection: &Connection, sql: &str, kinds: &[ColKind], expected: &[Vec<Cell>]) {
    let actual =
        query_cells(connection, sql, kinds).unwrap_or_else(|error| panic!("{sql}: {error}"));
    assert_eq!(actual.len(), expected.len(), "{sql}: number of rows");
    for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
        assert_eq!(actual, expected, "{sql}: row {index}");
    }
}

/// The files a scan read, in the order of their first row: the runs of its `filename` column.
fn files_read(connection: &Connection, from: &str) -> Vec<String> {
    let sql = format!("SELECT filename FROM {from}");
    let mut files = column(connection, &sql).unwrap_or_else(|error| panic!("{sql}: {error}"));
    files.dedup();
    files
}

/// `count` UDP frames from number `first`; every fifth is inside VXLAN and every seventh inside
/// two, so that a frame has one, two or three rows in `udp`.
fn mixed_frames(first: u32, count: u32) -> Vec<Vec<u8>> {
    (first..first + count)
        .map(|i| match i {
            _ if i % 7 == 6 => golden::nested_vxlan_frame(i),
            _ if i % 5 == 4 => golden::vxlan_frame(i),
            _ => golden::udp_frame(i),
        })
        .collect()
}

/// Captures of different formats, sizes and compressions, and the name each is written under.
/// No two hold the same frames.
fn captures() -> Vec<(&'static str, Vec<u8>, Vec<u8>)> {
    let plain = |name, bytes: Vec<u8>| (name, bytes.clone(), bytes);
    let one = golden::legacy(mixed_frames(0, 5000));
    let two = golden::pcapng(mixed_frames(10_000, 3000));
    let three = golden::legacy_nanos(mixed_frames(20_000, 2500));
    let four = golden::pcapng(mixed_frames(30_000, 2100));
    let five = golden::legacy(mixed_frames(40_000, 1));
    // (name, the capture, the bytes of the file)
    vec![
        plain("c-legacy.pcap", one),
        plain("a-ng.pcapng", two),
        ("d-nanos.pcap.gz", three.clone(), gzip(&three)),
        ("b-ng.pcapng.zst", four.clone(), zstd(&four)),
        plain("e-one.cap", five),
    ]
}

#[test]
fn a_list_a_pattern_and_a_list_of_patterns_are_read_in_order() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let frames = |first| golden::legacy(mixed_frames(first, 30));
    // Written in an order that is neither that of their names nor that of any list below.
    let names = [
        "m2.pcap",
        "a10.pcap",
        "z.pcapng",
        "a9.pcap",
        "m1.pcap",
        "B.pcap",
        "a1.pcap.gz",
        "notes.txt",
    ];
    for (number, name) in names.iter().enumerate() {
        let capture = frames(1000 * number as u32);
        match *name {
            "z.pcapng" => fixture.write(name, &golden::pcapng(mixed_frames(77, 30))),
            "a1.pcap.gz" => fixture.write(name, &gzip(&capture)),
            "notes.txt" => fixture.write(name, b"not a capture"),
            _ => fixture.write(name, &capture),
        };
    }
    let path = |name: &str| fixture.path(name);
    let paths = |names: &[&str]| -> Vec<String> { names.iter().map(|name| path(name)).collect() };
    let read = |files: &str| {
        files_read(
            &connection,
            &format!("read_frames({files}, filename := true)"),
        )
    };

    for threads in THREADS {
        partitioned(&connection, threads, 7);
        // One path.
        assert_eq!(read(&format!("'{}'", path("m2.pcap"))), paths(&["m2.pcap"]));
        // A list: its order, which is not that of the names.
        let given = ["m2.pcap", "a10.pcap", "z.pcapng", "B.pcap"];
        let given_paths = paths(&given);
        let given_refs: Vec<&str> = given_paths.iter().map(String::as_str).collect();
        assert_eq!(read(&list(&given_refs)), given_paths, "{threads} threads");
        // A list of one.
        assert_eq!(read(&list(&[&path("a9.pcap")])), paths(&["a9.pcap"]));
        // A pattern: the paths in ascending order, byte by byte. An upper-case letter sorts
        // before the lower-case ones, and `a10` before `a9`.
        assert_eq!(
            read(&format!("'{}'", path("*.pcap"))),
            paths(&["B.pcap", "a10.pcap", "a9.pcap", "m1.pcap", "m2.pcap"]),
            "{threads} threads"
        );
        assert_eq!(
            read(&format!("'{}'", path("a*"))),
            paths(&["a1.pcap.gz", "a10.pcap", "a9.pcap"])
        );
        assert_eq!(
            read(&format!("'{}'", path("m?.pcap"))),
            paths(&["m1.pcap", "m2.pcap"])
        );
        assert_eq!(
            read(&format!("'{}'", path("[mz]*.pcap*"))),
            paths(&["m1.pcap", "m2.pcap", "z.pcapng"])
        );
        // A list of patterns and paths: the entries in the order of the list, each pattern's
        // files sorted within it.
        assert_eq!(
            read(&list(&[
                &path("m*.pcap"),
                &path("z.pcapng"),
                &path("a*.pcap")
            ])),
            paths(&["m1.pcap", "m2.pcap", "z.pcapng", "a10.pcap", "a9.pcap"]),
            "{threads} threads"
        );
        // A file named twice is read twice, and so is one that two entries match.
        let twice = [path("m1.pcap"), path("a9.pcap"), path("m1.pcap")];
        let twice_refs: Vec<&str> = twice.iter().map(String::as_str).collect();
        assert_eq!(read(&list(&twice_refs)), twice, "{threads} threads");
        let from = format!(
            "read_frames({})",
            list(&[&path("m1.pcap"), &path("m*.pcap"), &path("m1.pcap")])
        );
        assert_eq!(
            rows(
                &connection,
                &format!(
                    "SELECT count(*), count(DISTINCT frame_number), max(frame_number) FROM {from}"
                )
            )?,
            [["120", "30", "30"]],
            "{threads} threads"
        );
    }
    Ok(())
}

#[test]
fn the_rows_are_those_of_each_file_one_file_after_the_other() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let captures = captures();
    let mut paths = Vec::new();
    for (name, _, bytes) in &captures {
        paths.push(fixture.write(name, bytes));
    }
    // The list order is that of `captures`; the pattern's is that of the names.
    let listed: Vec<usize> = (0..captures.len()).collect();
    let mut sorted = listed.clone();
    sorted.sort_by_key(|index| captures[*index].0);
    assert_ne!(listed, sorted);
    let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
    let calls = [
        (list(&refs), listed),
        (format!("'{}'", fixture.path("*")), sorted),
    ];

    for table in ["frames", "udp", "vxlan"] {
        let per_file: Vec<(Vec<OutColumn>, Vec<Vec<Cell>>)> = captures
            .iter()
            .map(|(_, capture, _)| reference_rows(capture, table))
            .collect();
        let mut kinds = kinds(&per_file[0].0);
        kinds.push(ColKind::Str);
        for (files, order) in &calls {
            // Every column and the file each row is from.
            let mut expected = Vec::new();
            for index in order {
                for row in &per_file[*index].1 {
                    let mut row = row.clone();
                    row.push(Cell::Str(paths[*index].clone()));
                    expected.push(row);
                }
            }
            let from = format!("read_{table}({files}, filename := true)");
            let generic = format!("read_pcap({files}, protocol := '{table}', filename := true)");
            let all = format!("SELECT * FROM {from}");
            let frame_numbers: Vec<String> = expected
                .iter()
                .map(|row| match &row[0] {
                    Cell::U64(frame) => frame.to_string(),
                    other => panic!("frame_number is {other:?}"),
                })
                .collect();

            for threads in THREADS {
                for split in [true, false] {
                    if split {
                        partitioned(&connection, threads, 400);
                    } else {
                        unpartitioned(&connection, threads);
                    }
                    let what = format!("{table}, {threads} threads, split: {split}");
                    assert_cells(&connection, &all, &kinds, &expected);
                    assert_cells(
                        &connection,
                        &format!("SELECT * FROM {generic}"),
                        &kinds,
                        &expected,
                    );
                    // frame_number starts at 1 in each file.
                    assert_eq!(
                        column(&connection, &format!("SELECT frame_number FROM {from}"))?,
                        frame_numbers,
                        "{what}"
                    );
                    // Order where DuckDB must keep it: a table made from the scan, the first
                    // rows, and rows from the middle, which are in the second file read.
                    execute(
                        &connection,
                        &format!("CREATE OR REPLACE TABLE stored AS {all}"),
                    );
                    assert_cells(&connection, "SELECT * FROM stored", &kinds, &expected);
                    let offset = per_file[order[0]].1.len() - 3;
                    assert_cells(
                        &connection,
                        &format!("{all} LIMIT 9 OFFSET {offset}"),
                        &kinds,
                        &expected[offset..offset + 9],
                    );
                    assert_eq!(
                        value(&connection, &format!("SELECT count(*) FROM {from}"))?,
                        expected.len().to_string(),
                        "{what}"
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn work_is_spread_across_files_and_within_them() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    execute(&connection, "CALL enable_logging(level = 'debug')");
    let large = golden::legacy(mixed_frames(0, 4000));
    let small = golden::legacy(mixed_frames(5000, 40));
    let large_path = fixture.write("large.pcap", &large);
    let small_path = fixture.write("small.pcap", &small);
    let gz_path = fixture.write("large.pcap.gz", &gzip(&large));
    let files = list(&[&small_path, &large_path, &gz_path, &small_path]);
    let rows_of = |capture: &[u8]| reference_rows(capture, "udp").1.len();
    let expected = 2 * rows_of(&small) + 2 * rows_of(&large);

    // Split wherever a file is 1000 frames or more. The compressed file cannot be split and
    // takes no share of the threads; the plain large file is nearly all of the bytes of the
    // others and is split for all four threads. The small ones are not a thread's worth, so
    // nobody looks for a place to split them at.
    partitioned(&connection, 4, 1000);
    logged(&connection, "DEBUG");
    assert_eq!(
        value(
            &connection,
            &format!("SELECT count(*) FROM read_udp({files})")
        )?,
        expected.to_string()
    );
    let records = logged(&connection, "DEBUG");
    let layouts: Vec<(&str, &str)> = records
        .iter()
        .filter_map(|record| record.split_once("': partitions: "))
        .map(|(file, rest)| {
            let file = file.rsplit_once('/').unwrap().1;
            (file, rest.split("; columns: ").next().unwrap())
        })
        .collect();
    assert_eq!(
        layouts,
        [
            (
                "small.pcap",
                "1 (the other files of the scan keep DuckDB's 4 threads busy)"
            ),
            (
                "large.pcap",
                "4 (of 4000 frames, cut at checkpoints 1000 frames apart)"
            ),
            ("large.pcap.gz", "1 (a compressed capture cannot be split)"),
            (
                "small.pcap",
                "1 (the other files of the scan keep DuckDB's 4 threads busy)"
            ),
        ]
    );
    // Each of the seven partitions was scanned to its end once, and the record says of which
    // file it is.
    let mut finished: Vec<(usize, String)> = records
        .iter()
        .filter_map(|record| record.split_once(" finished partition "))
        .map(|(_, rest)| {
            let mut words = rest.split(' ');
            let partition = words.next().unwrap().parse().unwrap();
            assert_eq!(words.next(), Some("of"));
            assert_eq!(words.next(), Some("7"), "{rest}");
            let file = rest.split('\'').nth(1).unwrap().rsplit_once('/').unwrap().1;
            (partition, file.to_owned())
        })
        .collect();
    finished.sort();
    let files: Vec<&str> = finished.iter().map(|(_, file)| file.as_str()).collect();
    assert_eq!(
        finished.iter().map(|(p, _)| *p).collect::<Vec<_>>(),
        [1, 2, 3, 4, 5, 6, 7]
    );
    assert_eq!(
        files,
        [
            "small.pcap",
            "large.pcap",
            "large.pcap",
            "large.pcap",
            "large.pcap",
            "large.pcap.gz",
            "small.pcap"
        ]
    );
    assert_eq!(records.len(), 4 + 7, "{records:#?}");

    // Files that are a thread's worth each are the partitions: none is split, so none is
    // read once for its record boundaries before the scan. With fewer files than threads
    // each is split for its share.
    let layouts_of = |files: &str| -> Result<Vec<String>> {
        logged(&connection, "DEBUG");
        let copies = files.matches(".pcap'").count();
        assert_eq!(
            value(
                &connection,
                &format!("SELECT count(*) FROM read_udp({files})")
            )?,
            (copies * rows_of(&large)).to_string()
        );
        Ok(logged(&connection, "DEBUG")
            .iter()
            .filter_map(|record| record.split_once("': partitions: "))
            .map(|(_, rest)| rest.split("; columns: ").next().unwrap().to_owned())
            .collect())
    };
    assert_eq!(
        layouts_of(&list(&[large_path.as_str(); 4]))?,
        ["1 (the other files of the scan keep DuckDB's 4 threads busy)"; 4]
    );
    assert_eq!(
        layouts_of(&list(&[large_path.as_str(); 6]))?,
        ["1 (the other files of the scan keep DuckDB's 4 threads busy)"; 6]
    );
    assert_eq!(
        layouts_of(&list(&[large_path.as_str(); 2]))?,
        ["2 (of 4000 frames, cut at checkpoints 1000 frames apart)"; 2]
    );
    assert_eq!(
        layouts_of(&list(&[large_path.as_str()]))?,
        ["4 (of 4000 frames, cut at checkpoints 1000 frames apart)"]
    );
    Ok(())
}

#[test]
fn what_cannot_be_read_is_an_error_that_names_it() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let good = fixture.write("good.pcap", &golden::capture("eth"));
    let other = fixture.write("other.pcap", &golden::capture("http"));
    let text = fixture.write("notes.txt", b"these are not packets, not at all");
    fixture.write("empty.pcap", b"");
    let missing = fixture.path("missing.pcap");
    let cases: Vec<(String, Vec<&str>)> = vec![
        // A pattern that matches nothing, alone and in a list.
        (
            format!("read_tcp('{}')", fixture.path("*.pcapng")),
            vec!["read_tcp: no file matches the pattern '", "*.pcapng'"],
        ),
        (
            format!(
                "read_pcap({})",
                list(&[&good, &fixture.path("nothing-?.pcap")])
            ),
            vec!["read_pcap: no file matches the pattern '", "nothing-?.pcap'"],
        ),
        // A path that does not exist, wherever it is in the list.
        (
            format!("read_tcp({})", list(&[&good, &missing, &other])),
            vec!["missing.pcap"],
        ),
        // A file that is not a capture: named by a list, and matched by a pattern.
        (
            format!("read_tcp({})", list(&[&good, &text, &other])),
            vec!["read_tcp: '", "notes.txt' is not a capture file pcapsql can read"],
        ),
        (
            format!("read_udp('{}')", fixture.path("*")),
            vec!["read_udp: '", "empty.pcap' is not a capture file pcapsql can read"],
        ),
        (
            format!("read_udp('{}')", fixture.path("[gn]*")),
            vec!["read_udp: '", "notes.txt' is not a capture file pcapsql can read"],
        ),
        // The argument.
        (
            "read_tcp([])".to_owned(),
            vec!["read_tcp: the list of capture files is empty"],
        ),
        (
            "read_tcp([]::VARCHAR[])".to_owned(),
            vec!["read_tcp: the list of capture files is empty"],
        ),
        (
            format!("read_tcp(['{good}', NULL])"),
            vec!["read_tcp: the capture file must not be NULL"],
        ),
        (
            format!("read_tcp(['{good}', ''])"),
            vec!["read_tcp: the capture file must not be an empty path"],
        ),
        (
            "read_tcp(NULL::VARCHAR[])".to_owned(),
            vec!["read_tcp: the capture file must not be NULL"],
        ),
        (
            "read_tcp([1, 2])".to_owned(),
            vec!["read_tcp: the capture files must be a VARCHAR path or pattern, or a list of them, not INTEGER[]"],
        ),
        (
            format!("read_tcp([['{good}']])"),
            vec!["read_tcp: the capture files must be", "not VARCHAR[][]"],
        ),
        (
            format!("read_tcp({{'file': '{good}'}})"),
            vec!["read_tcp: the capture files must be", "STRUCT"],
        ),
        (
            format!("read_tcp('{good}', filename := NULL)"),
            vec!["read_tcp: filename must be a constant and must not be NULL"],
        ),
        (
            format!("read_tcp('{good}', filename := 'yes please')"),
            vec!["yes please"],
        ),
    ];
    for (from, expected) in &cases {
        for sql in [
            format!("SELECT * FROM {from}"),
            format!("DESCRIBE SELECT * FROM {from}"),
        ] {
            let error = rows(&connection, &sql).expect_err(&sql);
            for text in expected {
                assert!(error.message.contains(text), "{sql}: {error}");
            }
            assert!(!error.message.contains("INTERNAL"), "{sql}: {error}");
        }
    }
    // The connection is as good as before.
    assert_eq!(
        value(
            &connection,
            &format!(
                "SELECT count(*) > 0 FROM read_tcp({})",
                list(&[&good, &other])
            )
        )?,
        "true"
    );

    // Nothing is listed or opened that the session may not access.
    execute(&connection, "SET enable_external_access = false");
    for from in [
        format!("read_tcp('{}')", fixture.path("*.pcap")),
        format!("read_tcp({})", list(&[&good, &other])),
        format!("read_tcp('{good}')"),
        format!("'{good}'"),
        format!("'{}'", fixture.path("*.pcap")),
    ] {
        let sql = format!("SELECT count(*) FROM {from}");
        let error = rows(&connection, &sql).expect_err(&sql);
        assert!(
            error.message.contains("disabled by configuration"),
            "{sql}: {error}"
        );
    }
    Ok(())
}

#[test]
fn the_filename_column_is_the_path_of_each_row() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    execute(&connection, "CALL enable_logging(level = 'debug')");
    let first = golden::legacy(mixed_frames(0, 5000));
    let second = golden::pcapng(mixed_frames(9000, 700));
    let a = fixture.write("a.pcap", &first);
    let b = fixture.write("b.pcapng.gz", &gzip(&second));
    let files = list(&[&b, &a]);
    let from = format!("read_udp({files}, filename := true)");
    let rows_of = |capture: &[u8]| reference_rows(capture, "udp").1.len();
    let (rows_a, rows_b) = (rows_of(&first), rows_of(&second));

    // The column is declared after the table's, as VARCHAR, only when asked for.
    let described = |from: &str| -> Vec<Vec<String>> {
        rows(
            &connection,
            &format!("SELECT column_name, column_type FROM (DESCRIBE SELECT * FROM {from})"),
        )
        .unwrap()
    };
    let without = described(&format!("read_udp({files})"));
    let with = described(&from);
    assert_eq!(with.len(), without.len() + 1);
    assert_eq!(with[..without.len()], without[..]);
    assert_eq!(with.last().unwrap(), &["filename", "VARCHAR"]);
    assert_eq!(
        described(&format!("read_udp({files}, filename := false)")),
        without
    );
    // It is a column of the call: the table's schema does not have it.
    assert_eq!(
        value(
            &connection,
            "SELECT count(*) FROM pcap_schema('udp') WHERE column_name = 'filename'"
        )?,
        "0"
    );
    let error = rows(
        &connection,
        &format!("SELECT filename FROM read_udp({files})"),
    )
    .unwrap_err();
    assert!(error.message.contains("filename"), "{error}");

    for threads in THREADS {
        for split in [true, false] {
            if split {
                partitioned(&connection, threads, 300);
            } else {
                unpartitioned(&connection, threads);
            }
            let what = format!("{threads} threads, split: {split}");
            let per_file = vec![
                vec![b.clone(), rows_b.to_string()],
                vec![a.clone(), rows_a.to_string()],
            ];
            // Alone: the rows are counted, nothing is parsed for them but the layers that say
            // whether a frame has a row.
            logged(&connection, "DEBUG");
            let names = column(&connection, &format!("SELECT filename FROM {from}"))?;
            assert_eq!(names.len(), rows_a + rows_b, "{what}");
            assert!(names[..rows_b].iter().all(|name| *name == b), "{what}");
            assert!(names[rows_b..].iter().all(|name| *name == a), "{what}");
            let records = logged(&connection, "DEBUG");
            let scans: Vec<&String> = records
                .iter()
                .filter(|record| record.contains("': partitions: "))
                .collect();
            assert_eq!(scans.len(), 2, "{records:#?}");
            for scan in scans {
                assert!(scan.contains("; columns: none (row count); "), "{scan}");
            }
            // In an aggregate, with and without a column of the table.
            assert_eq!(
                rows(
                    &connection,
                    &format!(
                        "SELECT filename, count(*) FROM {from} GROUP BY ALL ORDER BY ALL DESC"
                    )
                )?,
                per_file,
                "{what}"
            );
            assert_eq!(
                rows(
                    &connection,
                    &format!(
                        "SELECT filename, count(frame_number) FROM {from} GROUP BY ALL \
                         ORDER BY ALL DESC"
                    )
                )?,
                per_file,
                "{what}"
            );
            // Between and before the table's columns, and with a filter on it.
            assert_eq!(
                rows(
                    &connection,
                    &format!("SELECT src_port, filename, frame_number FROM {from} LIMIT 4")
                )?,
                rows(
                    &connection,
                    &format!("SELECT src_port, '{b}', frame_number FROM read_udp('{b}') LIMIT 4")
                )?,
                "{what}"
            );
            assert_eq!(
                rows(
                    &connection,
                    &format!(
                        "SELECT filename, frame_number, dst_port FROM {from} \
                         WHERE filename LIKE '%a.pcap' AND frame_number <= 2"
                    )
                )?,
                [
                    vec![a.clone(), "1".to_owned(), "9999".to_owned()],
                    vec![a.clone(), "2".to_owned(), "9999".to_owned()]
                ],
                "{what}"
            );
            assert_eq!(
                value(
                    &connection,
                    &format!("SELECT count(*) FROM {from} WHERE filename = '{b}'")
                )?,
                rows_b.to_string(),
                "{what}"
            );
            // Not used: the scan does not produce it.
            logged(&connection, "DEBUG");
            assert_eq!(
                value(&connection, &format!("SELECT sum(length) FROM {from}"))?,
                value(
                    &connection,
                    &format!("SELECT sum(length) FROM read_udp({files})")
                )?,
                "{what}"
            );
            for record in logged(&connection, "DEBUG") {
                if record.contains("': partitions: ") {
                    assert!(record.contains("; columns: length; "), "{record}");
                }
            }
            assert_eq!(
                value(&connection, &format!("SELECT count(*) FROM {from}"))?,
                (rows_a + rows_b).to_string(),
                "{what}"
            );
        }
    }

    // One file, and a path longer than DuckDB keeps inline in a string.
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT DISTINCT filename FROM read_pcap('{a}', protocol := 'vxlan', \
                 filename := true)"
            )
        )?,
        [[a.as_str()]]
    );
    Ok(())
}

#[test]
fn a_truncated_file_among_several_is_reported_on_its_own() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    execute(&connection, "CALL enable_logging(level = 'warning')");
    let frames: Vec<Vec<u8>> = (0..3000).map(golden::udp_frame).collect();
    let whole = golden::legacy(frames.clone());
    let cut = whole[..whole.len() - 5].to_vec();
    let complete = golden::legacy(frames[..2999].to_vec());
    let before = fixture.write("1-whole.pcap", &whole);
    let broken = fixture.write("2-cut.pcap", &cut);
    let gz = fixture.write("3-cut.pcap.gz", &gzip(&cut));
    let after = fixture.write("4-whole.pcap", &whole);
    let files = format!("'{}'", fixture.path("*"));

    let (columns, rows_whole) = reference_rows(&whole, "udp");
    let rows_cut = reference_rows(&complete, "udp").1;
    let mut expected = rows_whole.clone();
    expected.extend(rows_cut.clone());
    expected.extend(rows_cut);
    expected.extend(rows_whole);
    let kinds = kinds(&columns);

    for threads in THREADS {
        for split in [true, false] {
            if split {
                partitioned(&connection, threads, 500);
            } else {
                unpartitioned(&connection, threads);
            }
            let what = format!("{threads} threads, split: {split}");
            logged(&connection, "WARNING");
            // The complete frames of every file, the files after the broken ones included.
            assert_cells(
                &connection,
                &format!("SELECT * FROM read_udp({files})"),
                &kinds,
                &expected,
            );
            // One warning per truncated file, which names it.
            let mut warnings = logged(&connection, "WARNING");
            warnings.sort();
            assert_eq!(warnings.len(), 2, "{what}: {warnings:#?}");
            for (warning, file) in warnings.iter().zip([&broken, &gz]) {
                for text in [
                    "read_udp: '",
                    file.as_str(),
                    "' is truncated",
                    "frame 2999,",
                ] {
                    assert!(warning.contains(text), "{what}: {warning}");
                }
            }
            assert!(!warnings.iter().any(|w| w.contains("whole")), "{what}");

            // strict: the error names the first broken file the scan gets to. On one
            // partition per file that is whichever a worker finishes first.
            let sql = format!("SELECT count(*) FROM read_udp({files}, strict := true)");
            let error = rows(&connection, &sql).expect_err(&sql);
            assert!(error.message.contains("is truncated"), "{what}: {error}");
            assert!(
                error.message.contains("2-cut.pcap") || error.message.contains("3-cut.pcap.gz"),
                "{what}: {error}"
            );
            assert!(!error.message.contains("INTERNAL"), "{what}: {error}");
            // Without the broken files a strict scan is fine.
            assert_eq!(
                value(
                    &connection,
                    &format!(
                        "SELECT count(*) FROM read_udp({}, strict := true)",
                        list(&[&before, &after])
                    )
                )?,
                (2 * 3000).to_string()
            );
            logged(&connection, "WARNING");
        }
    }
    Ok(())
}

#[test]
fn a_quoted_capture_path_is_read_as_its_frames() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let capture = golden::legacy(mixed_frames(0, 3000));
    let other = golden::pcapng(mixed_frames(5000, 100));
    let (columns, reference) = reference_rows(&capture, "frames");
    let kinds = kinds(&columns);
    let frames = |bytes: &[u8]| reference_rows(bytes, "frames").1.len();

    // Every extension, in any case, compressed and not.
    let forms: Vec<(&str, Vec<u8>)> = vec![
        ("x.pcap", capture.clone()),
        ("x.cap", capture.clone()),
        ("X.PCAP", capture.clone()),
        ("x.Cap", capture.clone()),
        ("x.pcap.gz", gzip(&capture)),
        ("x.cap.GZ", gzip(&capture)),
        ("x.pcap.zst", zstd(&capture)),
        ("x.cap.zst", zstd(&capture)),
    ];
    for threads in [1, 4] {
        partitioned(&connection, threads, 500);
        for (name, bytes) in &forms {
            let path = fixture.write(name, bytes);
            assert_cells(
                &connection,
                &format!("SELECT * FROM '{path}'"),
                &kinds,
                &reference,
            );
            // Like any table: an alias, a filter, a join.
            assert_eq!(
                rows(
                    &connection,
                    &format!(
                        "SELECT f.frame_number, f.length FROM '{path}' AS f \
                         WHERE f.frame_number = 2999"
                    )
                )?,
                [["2999", "46"]],
                "{name}"
            );
            assert_eq!(
                value(
                    &connection,
                    &format!(
                        "SELECT count(*) FROM '{path}' f JOIN read_udp('{path}') u \
                         USING (frame_number) WHERE u.encap_depth = 0"
                    )
                )?,
                "3000",
                "{name}"
            );
        }
        for (name, bytes) in [
            ("y.pcapng", other.clone()),
            ("y.PcapNg", other.clone()),
            ("y.pcapng.gz", gzip(&other)),
            ("y.pcapng.zst", zstd(&other)),
        ] {
            let path = fixture.write(name, &bytes);
            assert_eq!(
                value(&connection, &format!("SELECT count(*) FROM '{path}'"))?,
                frames(&other).to_string(),
                "{name}"
            );
            // The name need not be quoted with single quotes: it is an identifier.
            assert_eq!(
                value(&connection, &format!("SELECT count(*) FROM \"{path}\""))?,
                frames(&other).to_string(),
                "{name}"
            );
        }
        // A pattern that ends in a capture extension: every file it matches.
        fixture.write("z.cap", &other);
        let both = fixture.path("[xz].cap");
        assert_eq!(
            value(&connection, &format!("SELECT count(*) FROM '{both}'"))?,
            (3000 + frames(&other)).to_string()
        );
        // One that does not is not a capture path, whatever it would match.
        let sql = format!("SELECT count(*) FROM '{}'", fixture.path("y.pcapng*"));
        let error = rows(&connection, &sql).expect_err(&sql);
        assert!(error.message.contains("does not exist"), "{error}");
        assert_eq!(
            value(
                &connection,
                &format!("SELECT count(*) FROM '{}'", fixture.path("*.pcap"))
            )?,
            "3000"
        );
    }
    // The columns are those of the frames table.
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT column_name, column_type FROM (DESCRIBE SELECT * FROM '{}')",
                fixture.path("x.pcap")
            )
        )?,
        rows(
            &connection,
            "SELECT column_name, column_type FROM pcap_schema('frames')"
        )?
    );

    // Names that are not capture paths are not answered: DuckDB says what it always says.
    fixture.write("notes.txt", b"text");
    fixture.write("x.pcap.bak", &capture);
    for name in [
        fixture.path("x.pcap.bak"),
        fixture.path("x.pcapx"),
        "pcap".to_owned(),
        "frames".to_owned(),
        "no_such_table".to_owned(),
    ] {
        let sql = format!("SELECT count(*) FROM '{name}'");
        let error = rows(&connection, &sql).expect_err(&sql);
        assert!(
            !error.message.contains("read_pcap"),
            "{sql} was answered: {error}"
        );
    }
    // DuckDB's own replacement scans still answer theirs.
    let csv = fixture.write("numbers.csv", b"n\n1\n2\n3\n");
    assert_eq!(
        value(&connection, &format!("SELECT sum(n) FROM '{csv}'"))?,
        "6"
    );
    // A capture path that cannot be read is read_pcap's error.
    for (name, text) in [
        (fixture.path("missing.pcap"), "missing.pcap"),
        (fixture.path("nothing*.pcap"), "read_pcap: no file matches"),
    ] {
        let sql = format!("SELECT count(*) FROM '{name}'");
        let error = rows(&connection, &sql).expect_err(&sql);
        assert!(error.message.contains(text), "{sql}: {error}");
    }
    let wrong = fixture.write(
        "wrong.pcap",
        b"this is not a capture at all, whatever its name",
    );
    let error = rows(&connection, &format!("SELECT * FROM '{wrong}'")).unwrap_err();
    assert!(
        error
            .message
            .contains("wrong.pcap' is not a capture file pcapsql can read"),
        "{error}"
    );
    // A name with a schema in front is a table someone means.
    let error = rows(&connection, "SELECT * FROM main.\"x.pcap\"").unwrap_err();
    assert!(!error.message.contains("read_pcap"), "{error}");
    Ok(())
}

#[test]
fn a_table_or_view_of_that_name_comes_before_the_replacement_scan() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let path = fixture.write("x.pcap", &golden::legacy(mixed_frames(0, 30)));
    let from = format!("SELECT count(*) FROM '{path}'");
    assert_eq!(value(&connection, &from)?, "30");

    // DuckDB looks in the catalog first and asks the replacement scans only when nothing of
    // that name is there.
    execute(
        &connection,
        &format!("CREATE TABLE \"{path}\" AS SELECT 7 AS frame_number"),
    );
    assert_eq!(value(&connection, &from)?, "1");
    assert_eq!(
        value(&connection, &format!("SELECT frame_number FROM '{path}'"))?,
        "7"
    );
    // The file is still there for the function.
    assert_eq!(
        value(
            &connection,
            &format!("SELECT count(*) FROM read_pcap('{path}')")
        )?,
        "30"
    );
    execute(&connection, &format!("DROP TABLE \"{path}\""));
    assert_eq!(value(&connection, &from)?, "30");

    execute(
        &connection,
        &format!("CREATE VIEW \"{path}\" AS SELECT * FROM range(3)"),
    );
    assert_eq!(value(&connection, &from)?, "3");
    execute(&connection, &format!("DROP VIEW \"{path}\""));
    // A common table expression of that name too.
    assert_eq!(
        value(
            &connection,
            &format!("WITH \"{path}\" AS (SELECT 1) SELECT count(*) FROM '{path}'")
        )?,
        "1"
    );
    Ok(())
}

#[test]
fn a_view_over_a_pattern_lists_the_files_each_time_it_is_queried() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let capture = |first| golden::legacy(mixed_frames(first, 10));
    fixture.write("a.pcap", &capture(0));
    let pattern = fixture.path("*.pcap");
    execute(
        &connection,
        &format!("CREATE VIEW frames AS SELECT * FROM read_frames('{pattern}', filename := true)"),
    );
    execute(
        &connection,
        &format!("CREATE VIEW quoted AS SELECT * FROM '{pattern}'"),
    );
    execute(
        &connection,
        &format!("PREPARE counted AS SELECT count(*) FROM read_frames('{pattern}')"),
    );
    // DuckDB's own reader, for comparison.
    fixture.write("a.csv", b"n\n1\n");
    execute(
        &connection,
        &format!(
            "CREATE VIEW numbers AS SELECT * FROM read_csv('{}')",
            fixture.path("*.csv")
        ),
    );
    let counts = || -> Vec<String> {
        [
            "SELECT count(*) FROM frames",
            "SELECT count(DISTINCT filename) FROM frames",
            "SELECT count(*) FROM quoted",
            "SELECT count(*) FROM numbers",
        ]
        .iter()
        .map(|sql| value(&connection, sql).unwrap())
        .collect()
    };
    assert_eq!(counts(), ["10", "1", "10", "1"]);
    assert_eq!(value(&connection, "EXECUTE counted")?, "10");

    // A view is bound when it is queried: a file that appears is read, as with read_csv.
    fixture.write("b.pcap", &capture(100));
    fixture.write("b.csv", b"n\n2\n3\n");
    assert_eq!(counts(), ["20", "2", "20", "3"]);
    // A prepared statement was bound when it was prepared: it reads the files of that time.
    assert_eq!(value(&connection, "EXECUTE counted")?, "10");
    Ok(())
}
