//! Parallel scans: a capture read as several partitions by several workers.
//!
//! What a partitioned scan must return is what the scan of one partition returns, row for row
//! and in the same order, without an `ORDER BY`. The tests here run the same queries with
//! `pcapsql_parallel_scan` off and then on at 1, 2, 4 and 8 threads, and compare: over every
//! table of every capture of the golden corpus, over generated captures of many chunks, over
//! frames with several rows at the places a capture is cut, over truncated and damaged
//! captures and over compressed ones.
//!
//! A capture is cut at the checkpoints of the boundary index, which are `pcapsql_index_stride`
//! frames apart, and only from `pcapsql_parallel_min_file_size` bytes on. The defaults (65,536
//! frames, 4 MiB) would leave every capture here in one piece, so the tests set a stride of a
//! few frames and, for the small captures, a minimum size of 0.
//!
//! That a scan was partitioned, and which worker scanned which partition, is read back from
//! DuckDB's log, where the extension writes one DEBUG record per scan and one per partition.

use std::collections::BTreeSet;
use std::io::Write;

use duckdb_neo::{connection::Connection, Parameters, Result};
use pcapsql_core::scan::{testing::Cell, ColKind, OutColumn};
use pcapsql_duckdb_itest::{
    column, connect, golden, reference_rows, replay::query_cells, rows, value, Fixture,
};

/// The thread counts every comparison is made at.
const THREADS: [usize; 4] = [1, 2, 4, 8];

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

/// The start of an error message: a parse error carries the bytes it could not parse.
fn brief(error: &duckdb_neo::Error) -> &str {
    let end = error.message.len().min(400);
    error.message.get(..end).unwrap_or(&error.message)
}

fn set(connection: &Connection, setting: &str, value: impl std::fmt::Display) {
    let sql = format!("SET {setting} = {value}");
    connection
        .execute(sql.as_str(), Parameters::None)
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

/// Scan every capture as one partition.
fn unpartitioned(connection: &Connection) {
    set(connection, "pcapsql_parallel_scan", false);
}

/// The DEBUG records the extension logged since the log was last cleared, oldest first.
fn logged(connection: &Connection) -> Vec<String> {
    let records = column(
        connection,
        "SELECT message FROM duckdb_logs WHERE type = 'pcapsql' AND log_level = 'DEBUG' \
         ORDER BY timestamp, context_id",
    )
    .unwrap();
    connection
        .execute("CALL truncate_duckdb_logs()", Parameters::None)
        .unwrap();
    records
}

/// The warnings the extension logged since the log was last cleared.
fn warnings(connection: &Connection) -> Vec<String> {
    let warnings = column(
        connection,
        "SELECT message FROM duckdb_logs WHERE type = 'pcapsql' AND log_level = 'WARNING'",
    )
    .unwrap();
    connection
        .execute("CALL truncate_duckdb_logs()", Parameters::None)
        .unwrap();
    warnings
}

/// How the scans in `records` were run.
#[derive(Debug, Default)]
struct Scans {
    /// The `partitions:` note of every scan: the number, and the reason in brackets.
    layouts: Vec<String>,
    /// `(worker, partition)` of every partition a worker scanned to its end.
    finished: Vec<(usize, usize)>,
}

impl Scans {
    fn of(records: &[String]) -> Self {
        let mut scans = Self::default();
        for record in records {
            if let Some((_, rest)) = record.split_once("': partitions: ") {
                let note = rest.split("; columns: ").next().unwrap();
                scans.layouts.push(note.to_owned());
            } else if let Some((_, rest)) = record.split_once(": worker ") {
                let mut words = rest.split(' ');
                let worker = words.next().unwrap().parse().unwrap();
                assert_eq!(words.next(), Some("finished"), "{record}");
                assert_eq!(words.next(), Some("partition"), "{record}");
                let partition = words.next().unwrap().parse().unwrap();
                scans.finished.push((worker, partition));
            } else {
                panic!("an unknown log record: {record}");
            }
        }
        scans
    }

    /// The number of partitions of the one scan in the records.
    fn partitions(&self) -> usize {
        assert_eq!(self.layouts.len(), 1, "{self:?}");
        let number = self.layouts[0].split(' ').next().unwrap();
        number.parse().unwrap_or_else(|_| panic!("{self:?}"))
    }

    /// The workers that scanned a partition.
    fn workers(&self) -> BTreeSet<usize> {
        self.finished.iter().map(|(worker, _)| *worker).collect()
    }

    /// Assert that the one scan in the records had `partitions` partitions and that each was
    /// scanned to its end exactly once.
    fn assert_complete(&self, partitions: usize, what: &str) {
        assert_eq!(self.partitions(), partitions, "{what}: {self:?}");
        let mut scanned: Vec<usize> = self.finished.iter().map(|(_, p)| *p).collect();
        scanned.sort_unstable();
        let all: Vec<usize> = (1..=partitions).collect();
        assert_eq!(scanned, all, "{what}: {self:?}");
    }
}

fn kinds(columns: &[OutColumn]) -> Vec<ColKind> {
    columns.iter().map(|column| column.kind).collect()
}

/// Assert that `sql` returns exactly `expected`, in order.
fn assert_cells(connection: &Connection, sql: &str, columns: &[OutColumn], expected: &[Vec<Cell>]) {
    let actual = query_cells(connection, sql, &kinds(columns))
        .unwrap_or_else(|error| panic!("{sql}: {error}"));
    assert_eq!(actual.len(), expected.len(), "{sql}: number of rows");
    for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
        for ((actual, expected), column) in actual.iter().zip(expected).zip(columns) {
            assert_eq!(
                actual, expected,
                "{sql}: row {index}, column {}",
                column.name
            );
        }
    }
}

/// Queries over `from` (a scan of the capture at `path`) whose results depend on the rows a
/// scan returns and, where they have no `ORDER BY`, on their order.
fn shapes(path: &str, from: &str) -> Vec<String> {
    vec![
        // Projections: one column, and every column in another order.
        format!("SELECT frame_number FROM {from}"),
        format!("SELECT * EXCLUDE (frame_number), frame_number FROM {from}"),
        // Aggregates, which do not ask where a row is from.
        format!("SELECT count(*) FROM {from}"),
        format!(
            "SELECT count(*), min(frame_number), max(frame_number), sum(frame_number), \
             count(DISTINCT frame_number) FROM {from}"
        ),
        format!("SELECT frame_number, count(*) FROM {from} GROUP BY ALL ORDER BY ALL"),
        // The first rows, and rows from the middle.
        format!("SELECT * FROM {from} LIMIT 1"),
        format!("SELECT * FROM {from} LIMIT 3 OFFSET 2"),
        format!("SELECT frame_number FROM {from} LIMIT 5 OFFSET 7"),
        // A filter between the scan and the result.
        format!("SELECT * FROM {from} WHERE frame_number % 3 = 1"),
        // A join of two scans of the capture.
        format!(
            "SELECT f.frame_number, f.length, t.frame_number FROM read_frames('{path}') f \
             JOIN {from} t ON t.frame_number = f.frame_number ORDER BY ALL"
        ),
        format!(
            "SELECT count(*) FROM read_frames('{path}') f, {from} t \
             WHERE t.frame_number = f.frame_number + 1"
        ),
    ]
}

/// The results of [`shapes`], and the rows a table made from the scan holds.
fn results(connection: &Connection, path: &str, from: &str) -> Vec<Vec<Vec<String>>> {
    let mut results: Vec<Vec<Vec<String>>> = shapes(path, from)
        .iter()
        .map(|sql| rows(connection, sql).unwrap_or_else(|error| panic!("{sql}: {error}")))
        .collect();
    let stored = format!("CREATE OR REPLACE TABLE stored AS SELECT * FROM {from}");
    connection
        .execute(stored.as_str(), Parameters::None)
        .unwrap_or_else(|error| panic!("{stored}: {error}"));
    results.push(rows(connection, "SELECT * FROM stored").unwrap());
    results
}

/// Assert that the queries of [`results`] return on `threads` threads, partitioned, what
/// `expected` holds.
fn assert_results(
    connection: &Connection,
    path: &str,
    from: &str,
    expected: &[Vec<Vec<String>>],
    threads: usize,
) {
    let actual = results(connection, path, from);
    let mut names = shapes(path, from);
    names.push(format!("CREATE TABLE AS SELECT * FROM {from}"));
    for ((actual, expected), sql) in actual.iter().zip(expected).zip(&names) {
        assert!(
            actual == expected,
            "{threads} threads: {sql}: {} rows, {} expected; the first that differs: {:?}",
            actual.len(),
            expected.len(),
            actual.iter().zip(expected).find(|(a, e)| a != e)
        );
    }
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

#[test]
fn every_table_of_every_corpus_capture_is_the_same_in_partitions() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    connection.execute("CALL enable_logging(level = 'debug')", Parameters::None)?;
    let tables = column(
        &connection,
        "SELECT name FROM pcap_protocols() ORDER BY name",
    )?;
    // The captures have a few dozen frames: a place to cut after every second one.
    const STRIDE: u64 = 2;

    let mut compared = 0;
    for name in golden::CAPTURES {
        let capture = golden::capture(name);
        let path = fixture.write(&format!("{name}.pcap"), &capture);
        // From 3 frames (two partitions) to a few dozen.
        let frames = reference_rows(&capture, "frames").1.len();
        assert!(frames >= 3, "{name}: {frames} frames");

        // What one partition returns.
        unpartitioned(&connection);
        let mut expected = Vec::new();
        for table in &tables {
            let from = format!("read_{table}('{path}')");
            let (columns, reference) = reference_rows(&capture, table);
            assert_cells(
                &connection,
                &format!("SELECT * FROM {from}"),
                &columns,
                &reference,
            );
            // The queries are run for the tables that have rows in this capture.
            let shapes = (!reference.is_empty()).then(|| results(&connection, &path, &from));
            expected.push((from, columns, reference, shapes));
        }
        logged(&connection);

        for threads in THREADS {
            partitioned(&connection, threads, STRIDE);
            for (from, columns, reference, shapes) in &expected {
                let select = format!("SELECT * FROM {from}");
                assert_cells(&connection, &select, columns, reference);
                // A partition per thread, up to one per checkpoint; one thread is not split.
                let checkpoints = frames.div_ceil(STRIDE as usize);
                let partitions = if threads == 1 {
                    1
                } else {
                    threads.min(checkpoints)
                };
                Scans::of(&logged(&connection)).assert_complete(partitions, &select);

                assert_eq!(
                    value(&connection, &format!("SELECT count(*) FROM {from}"))?,
                    reference.len().to_string(),
                    "{threads} threads: {from}"
                );
                if let Some(shapes) = shapes {
                    assert_results(&connection, &path, from, shapes, threads);
                    compared += 1;
                }
                logged(&connection);
            }
        }
    }
    // Tables with rows, over the six captures and the four thread counts.
    assert!(compared >= 6 * 4 * 4, "{compared}");
    Ok(())
}

#[test]
fn a_capture_of_many_chunks_is_the_same_in_partitions() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    connection.execute("CALL enable_logging(level = 'debug')", Parameters::None)?;

    // Partitions of 1,500 to 6,000 frames, which is one to nine chunks of a table.
    const FRAMES: u32 = 12_000;
    const STRIDE: u64 = 500;
    let legacy = golden::legacy(mixed_frames(FRAMES));
    let pcapng = golden::pcapng(mixed_frames(FRAMES));

    // (file, capture, tables, whether the queries of `shapes` are run as well)
    for (file, capture, tables, queries) in [
        ("mixed.pcap", &legacy, &["frames", "udp"][..], true),
        ("mixed.pcap", &legacy, &["ethernet", "vxlan"][..], false),
        ("mixed.pcapng", &pcapng, &["frames", "udp"][..], false),
    ] {
        let path = fixture.write(file, capture);
        for table in tables {
            let from = format!("read_{table}('{path}')");
            let select = format!("SELECT * FROM {from}");
            let (columns, reference) = reference_rows(capture, table);
            let deep = format!(
                "SELECT frame_number FROM {from} LIMIT 10 OFFSET {}",
                reference.len() * 2 / 3
            );

            unpartitioned(&connection);
            set(&connection, "threads", 4);
            assert_cells(&connection, &select, &columns, &reference);
            let expected = queries.then(|| results(&connection, &path, &from));
            let expected_deep = column(&connection, &deep)?;
            assert_eq!(expected_deep.len(), 10);
            let scans = Scans::of(&logged(&connection));
            assert!(
                scans.layouts.iter().all(|note| note.starts_with("1 (")),
                "{scans:?}"
            );

            for threads in THREADS {
                partitioned(&connection, threads, STRIDE);
                assert_cells(&connection, &select, &columns, &reference);
                let scans = Scans::of(&logged(&connection));
                scans.assert_complete(threads, &select);

                if let Some(expected) = &expected {
                    assert_results(&connection, &path, &from, expected, threads);
                }
                assert_eq!(column(&connection, &deep)?, expected_deep, "{deep}");
                assert_eq!(
                    value(&connection, &format!("SELECT count(*) FROM {from}"))?,
                    reference.len().to_string()
                );
                logged(&connection);
            }
        }
    }
    Ok(())
}

#[test]
fn several_workers_scan_a_partitioned_capture() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    connection.execute("CALL enable_logging(level = 'debug')", Parameters::None)?;
    let capture = golden::legacy(mixed_frames(60_000));
    let path = fixture.write("mixed.pcap", &capture);
    let udp = reference_rows(&capture, "udp").1.len();
    // Large enough to be split without lowering the minimum size.
    assert!(capture.len() > 4 << 20, "{} bytes", capture.len());
    set(&connection, "pcapsql_index_stride", 1000);
    set(&connection, "threads", 4);

    // Whether the order of the rows matters to the query or not.
    for sql in [
        format!("SELECT count(*), count(DISTINCT src_port) FROM read_udp('{path}')"),
        format!("SELECT * FROM read_udp('{path}')"),
        format!("CREATE OR REPLACE TABLE stored AS SELECT * FROM read_udp('{path}')"),
    ] {
        logged(&connection);
        let result = rows(&connection, &sql)?;
        if sql.starts_with("SELECT count") {
            assert_eq!(result[0][0], udp.to_string(), "{sql}");
        } else if sql.starts_with("SELECT") {
            assert_eq!(result.len(), udp, "{sql}");
        }
        let scans = Scans::of(&logged(&connection));
        scans.assert_complete(4, &sql);
        assert!(
            scans.workers().len() >= 2,
            "{sql}: every partition was scanned by one worker: {scans:?}"
        );
    }
    Ok(())
}

/// Frames that have 3, 2, 1, 3, 2, 1, ... rows in `ethernet`, `ipv4` and `udp`, after `lead`
/// frames of one row each.
fn tunnel_frames(lead: u32, count: u32) -> Vec<Vec<u8>> {
    (0..lead)
        .map(golden::udp_frame)
        .chain((lead..lead + count).map(|i| match (i - lead) % 3 {
            0 => golden::nested_vxlan_frame(i),
            1 => golden::vxlan_frame(i),
            _ => golden::udp_frame(i),
        }))
        .collect()
}

#[test]
fn frames_with_several_rows_are_whole_where_a_capture_is_cut() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    connection.execute("CALL enable_logging(level = 'debug')", Parameters::None)?;

    // With a checkpoint at every frame, at every second and at every seventh, the cuts fall
    // before and after frames of one, two and three rows; the lead moves them by one frame.
    for (lead, stride) in [(0, 1), (1, 1), (0, 2), (1, 2), (2, 7)] {
        let capture = golden::legacy(tunnel_frames(lead, 3000));
        let path = fixture.write(&format!("tunnels-{lead}-{stride}.pcap"), &capture);
        for table in ["ethernet", "ipv4", "udp", "vxlan", "frames"] {
            let (columns, reference) = reference_rows(&capture, table);
            let select = format!("SELECT * FROM read_{table}('{path}')");
            for threads in [2, 4, 8] {
                partitioned(&connection, threads, stride);
                assert_cells(&connection, &select, &columns, &reference);
                Scans::of(&logged(&connection)).assert_complete(threads, &select);
                // And counted, which reads no column and asks for no order.
                let counted = value(
                    &connection,
                    &format!(
                        "SELECT count(*) FROM read_{table}('{path}') WHERE frame_number > 1500"
                    ),
                )?;
                let after = reference
                    .iter()
                    .filter(|row| matches!(row[0], Cell::U64(frame) if frame > 1500))
                    .count();
                assert_eq!(counted, after.to_string(), "{select}");
                logged(&connection);
            }
        }
    }
    Ok(())
}

#[test]
fn a_truncated_capture_is_reported_once_by_a_partitioned_scan() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    connection.execute("CALL enable_logging(level = 'warning')", Parameters::None)?;

    const FRAMES: u32 = 20_000;
    let frames: Vec<Vec<u8>> = (0..FRAMES).map(golden::udp_frame).collect();
    let record = 16 + frames[0].len();
    let legacy = golden::legacy(frames.clone());
    let pcapng = golden::pcapng(frames.clone());
    let cut = |bytes: &[u8], by: usize| bytes[..bytes.len() - by].to_vec();
    // (file, bytes, complete frames): cut inside the last record, inside its header, in the
    // middle of the capture, and a pcapng capture cut inside a block.
    let cases: Vec<(&str, Vec<u8>, u32)> = vec![
        ("data.pcap", cut(&legacy, 5), FRAMES - 1),
        ("header.pcap", cut(&legacy, record - 7), FRAMES - 1),
        (
            "middle.pcap",
            cut(&legacy, 7000 * record + 20),
            FRAMES - 7001,
        ),
        ("block.pcapng", cut(&pcapng, 9), FRAMES - 1),
    ];
    for (file, bytes, complete) in cases {
        let path = fixture.write(file, &bytes);
        let whole: Vec<Vec<u8>> = frames[..complete as usize].to_vec();
        let prefix = if file.contains("pcapng") {
            golden::pcapng(whole)
        } else {
            golden::legacy(whole)
        };
        let (columns, reference) = reference_rows(&prefix, "udp");
        assert_eq!(reference.len(), complete as usize);
        let from = format!("read_udp('{path}')");
        let strict = format!("read_udp('{path}', strict := true)");

        for threads in [2, 4, 8] {
            partitioned(&connection, threads, 500);
            warnings(&connection);
            // By default: the complete frames, every one of them, and one warning.
            assert_cells(
                &connection,
                &format!("SELECT * FROM {from}"),
                &columns,
                &reference,
            );
            let logged = warnings(&connection);
            assert_eq!(logged.len(), 1, "{threads} threads: {from}: {logged:?}");
            for text in [
                "read_udp: ".to_owned(),
                file.to_owned(),
                "is truncated".to_owned(),
                format!("frame {complete},"),
                "strict := true".to_owned(),
            ] {
                assert!(logged[0].contains(&text), "{from}: {}", logged[0]);
            }
            assert_eq!(
                value(&connection, &format!("SELECT count(*) FROM {from}"))?,
                complete.to_string()
            );
            assert_eq!(warnings(&connection).len(), 1, "{from}: count(*)");

            // strict: an error that names the file and the last complete frame, whether or
            // not the query would have read to the end of the capture.
            for sql in [
                format!("SELECT * FROM {strict}"),
                format!("SELECT count(*) FROM {strict}"),
                format!("SELECT frame_number FROM {strict} LIMIT 2"),
                format!("CREATE OR REPLACE TABLE cut AS SELECT * FROM {strict}"),
            ] {
                let error = rows(&connection, &sql).expect_err(&sql);
                for text in [file, "is truncated", &format!("frame {complete},")] {
                    assert!(error.message.contains(text), "{sql}: {error}");
                }
                assert!(!error.message.contains("INTERNAL"), "{sql}: {error}");
            }
            assert!(
                warnings(&connection).is_empty(),
                "{from}: strict logs nothing, it fails"
            );
            // A limit returns the first frames; the tail may or may not have been reached.
            assert_eq!(
                column(
                    &connection,
                    &format!("SELECT frame_number FROM {from} LIMIT 2")
                )?,
                ["1", "2"]
            );
            assert!(warnings(&connection).len() <= 1);
        }

        // One partition gets to the tail only when it reads that far.
        unpartitioned(&connection);
        assert_eq!(
            column(
                &connection,
                &format!("SELECT frame_number FROM {strict} LIMIT 2")
            )?,
            ["1", "2"]
        );
        assert!(warnings(&connection).is_empty());
    }

    // A complete capture is neither, in any number of partitions.
    for (file, bytes) in [("whole.pcap", &legacy), ("whole.pcapng", &pcapng)] {
        let path = fixture.write(file, bytes);
        for threads in [2, 8] {
            partitioned(&connection, threads, 500);
            for strict in ["", ", strict := true"] {
                assert_eq!(
                    value(
                        &connection,
                        &format!("SELECT count(*) FROM read_udp('{path}'{strict})")
                    )?,
                    FRAMES.to_string()
                );
            }
        }
        assert!(warnings(&connection).is_empty(), "{file}");
    }
    Ok(())
}

/// The offsets of the blocks of a pcapng capture.
fn pcapng_blocks(bytes: &[u8]) -> Vec<usize> {
    let mut blocks = Vec::new();
    let mut at = 0;
    while at + 8 <= bytes.len() {
        blocks.push(at);
        at += u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
    }
    assert_eq!(at, bytes.len());
    blocks
}

#[test]
fn a_damaged_block_in_the_middle_fails_a_partitioned_scan_as_it_fails_any() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    connection.execute("CALL enable_logging(level = 'debug')", Parameters::None)?;

    const FRAMES: u32 = 20_000;
    let mut damaged = golden::pcapng((0..FRAMES).map(golden::udp_frame).collect());
    let blocks = pcapng_blocks(&damaged);
    // The Enhanced Packet Block of frame 12,001 (after a section header and an interface
    // description) gets a length that is not a block length.
    let at = blocks[2 + 12_000];
    assert_eq!(damaged[at..at + 4], 6u32.to_le_bytes());
    damaged[at + 4..at + 8].copy_from_slice(&7u32.to_le_bytes());
    let path = fixture.write("damaged.pcapng", &damaged);

    unpartitioned(&connection);
    let sql = format!("SELECT count(*) FROM read_udp('{path}')");
    let expected = rows(&connection, &sql).unwrap_err();
    assert!(
        expected.message.contains("after frame 12000"),
        "{}",
        brief(&expected)
    );

    for threads in THREADS {
        partitioned(&connection, threads, 500);
        for sql in [
            sql.clone(),
            format!("SELECT * FROM read_udp('{path}')"),
            format!("SELECT * FROM read_frames('{path}', strict := true)"),
            format!("CREATE OR REPLACE TABLE damaged AS SELECT * FROM read_frames('{path}')"),
        ] {
            logged(&connection);
            let error = rows(&connection, &sql).expect_err(&sql);
            // The error of the scan of one partition, once.
            assert!(
                error.message.contains("damaged.pcapng")
                    && error.message.contains("cannot read")
                    && error.message.contains("after frame 12000"),
                "{sql}: {}",
                brief(&error)
            );
            assert_eq!(
                error.message.matches("cannot read").count(),
                1,
                "{}",
                brief(&error)
            );
            assert!(
                !error.message.contains("INTERNAL"),
                "{sql}: {}",
                brief(&error)
            );
            assert!(!error.message.contains("panic"), "{sql}: {}", brief(&error));
            // The pass that looks for places to cut cannot get past the block either, so the
            // capture is read in one piece.
            let scans = Scans::of(&logged(&connection));
            assert_eq!(scans.layouts.len(), 1, "{scans:?}");
            if threads > 1 {
                assert!(
                    scans.layouts[0].starts_with("1 (the index pass failed"),
                    "{scans:?}"
                );
            }
        }
        // The frames before the damage can still be asked for, and the connection is fine.
        assert_eq!(
            column(
                &connection,
                &format!("SELECT frame_number FROM read_frames('{path}') LIMIT 3")
            )?,
            ["1", "2", "3"]
        );
        assert!(rows(&connection, "SELECT * FROM damaged").is_err());
    }
    Ok(())
}

/// A capture that is damaged after the scan has started: the place is found by the worker that
/// gets there, not by the pass that cuts the capture. The query fails once, with that worker's
/// error, and the other workers stop.
#[test]
fn an_error_in_one_worker_fails_the_query_once() -> Result<()> {
    use std::os::unix::fs::FileExt;

    let connection = connect()?;
    let fixture = Fixture::new();

    // Records of a kilobyte, so that the rows of a partition do not fit the buffer of a result
    // that is not being read: the workers wait for the reader.
    const FRAMES: u32 = 48_000;
    let frame = |i: u32| {
        let mut frame = golden::udp_frame(i);
        frame.resize(1000, 0xa5);
        frame
    };
    let capture = golden::pcapng((0..FRAMES).map(frame).collect());
    assert!(capture.len() > 40 << 20);
    let blocks = pcapng_blocks(&capture);
    // The Enhanced Packet Block of frame 35,001, after a section header and an interface
    // description: near the end of the third of four partitions of 12,000 frames.
    let at = blocks[2 + 35_000];
    assert_eq!(capture[at..at + 4], 6u32.to_le_bytes());

    for round in 0..2 {
        let path = fixture.write(&format!("live-{round}.pcapng"), &capture);
        partitioned(&connection, 4, 1000);
        let mut result = connection.query(
            format!("SELECT * FROM read_frames('{path}')").as_str(),
            Parameters::None,
        )?;
        let first = result.next_chunk()?.expect("the first chunk");
        let mut read = first.row_count()?;
        assert!(read > 0);
        drop(first);

        // The block now has a length that is not a block length.
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.write_all_at(&7u32.to_le_bytes(), at as u64 + 4)
            .unwrap();
        file.sync_all().unwrap();
        drop(file);

        let error = loop {
            match result.next_chunk() {
                Ok(Some(chunk)) => read += chunk.row_count()?,
                Ok(None) => panic!("round {round}: the scan ended after {read} rows"),
                Err(error) => break error,
            }
        };
        drop(result);
        // The rows before the damage at most, then the error of the worker that met it.
        assert!(read <= 35_000, "round {round}: {read} rows");
        assert!(
            error.message.contains("cannot read") && error.message.contains("after frame 35000"),
            "{}",
            brief(&error)
        );
        assert_eq!(
            error.message.matches("read_frames: ").count(),
            1,
            "{}",
            brief(&error)
        );
        assert!(!error.message.contains("INTERNAL"), "{}", brief(&error));

        // The connection is usable, and the capture now fails every scan the same way.
        assert_eq!(value(&connection, "SELECT 42")?, "42");
        let again = rows(
            &connection,
            &format!("SELECT count(*) FROM read_frames('{path}')"),
        )
        .unwrap_err();
        assert!(
            again.message.contains("after frame 35000"),
            "{}",
            brief(&again)
        );
    }
    Ok(())
}

#[test]
fn compressed_and_small_captures_are_read_as_one_partition() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    connection.execute("CALL enable_logging(level = 'debug')", Parameters::None)?;
    let capture = golden::legacy(mixed_frames(20_000));
    let (columns, reference) = reference_rows(&capture, "udp");
    let layout = |sql: &str| -> String {
        logged(&connection);
        assert_eq!(
            value(&connection, sql).unwrap_or_else(|error| panic!("{sql}: {error}")),
            reference.len().to_string(),
            "{sql}"
        );
        let scans = Scans::of(&logged(&connection));
        assert_eq!(scans.partitions(), scans.finished.len(), "{scans:?}");
        scans.layouts.into_iter().next().unwrap()
    };

    // Compressed: whatever the settings say.
    partitioned(&connection, 8, 100);
    let mut zstd = zstd::Encoder::new(Vec::new(), 3).unwrap();
    zstd.write_all(&capture).unwrap();
    for (file, bytes) in [
        ("mixed.pcap.gz", gzip(&capture)),
        ("mixed.pcap.zst", zstd.finish().unwrap()),
    ] {
        let path = fixture.write(file, &bytes);
        let from = format!("read_udp('{path}')");
        assert_eq!(
            layout(&format!("SELECT count(*) FROM {from}")),
            "1 (a compressed capture cannot be split)"
        );
        assert_cells(
            &connection,
            &format!("SELECT * FROM {from}"),
            &columns,
            &reference,
        );
    }

    // The same capture as it is: split, until something says not to.
    let path = fixture.write("mixed.pcap", &capture);
    let count = format!("SELECT count(*) FROM read_udp('{path}')");
    assert_eq!(
        layout(&count),
        "8 (of 20000 frames, cut at checkpoints 100 frames apart)"
    );
    // Fewer checkpoints than threads.
    set(&connection, "pcapsql_index_stride", 6000);
    assert_eq!(
        layout(&count),
        "4 (of 20000 frames, cut at checkpoints 6000 frames apart)"
    );
    // One checkpoint: the default stride is longer than this capture.
    connection.execute("RESET pcapsql_index_stride", Parameters::None)?;
    assert_eq!(
        layout(&count),
        "1 (20000 frames give no place to split at, with a checkpoint every 65536 frames)"
    );
    set(&connection, "pcapsql_index_stride", 100);
    // Smaller than the minimum size, which by default is 4 MiB.
    connection.execute("RESET pcapsql_parallel_min_file_size", Parameters::None)?;
    let note = layout(&count);
    assert_eq!(
        note,
        format!(
            "1 ({} bytes is less than pcapsql_parallel_min_file_size = 4194304)",
            capture.len()
        )
    );
    set(&connection, "pcapsql_parallel_min_file_size", capture.len());
    assert!(layout(&count).starts_with("8 ("));
    set(
        &connection,
        "pcapsql_parallel_min_file_size",
        capture.len() + 1,
    );
    assert!(layout(&count).starts_with("1 ("));
    set(&connection, "pcapsql_parallel_min_file_size", 0);
    // One thread, and the switch.
    set(&connection, "threads", 1);
    assert_eq!(layout(&count), "1 (DuckDB has one thread)");
    set(&connection, "threads", 8);
    set(&connection, "pcapsql_parallel_scan", false);
    assert_eq!(layout(&count), "1 (pcapsql_parallel_scan is off)");
    Ok(())
}

#[test]
fn the_settings_have_defaults_and_refuse_what_they_cannot_use() -> Result<()> {
    let connection = connect()?;
    for (setting, default) in [
        ("pcapsql_parallel_scan", "true"),
        ("pcapsql_parallel_min_file_size", "4194304"),
        ("pcapsql_index_stride", "65536"),
    ] {
        let current = format!("SELECT current_setting('{setting}')");
        assert_eq!(value(&connection, &current)?, default, "{setting}");
        let described = rows(
            &connection,
            &format!("SELECT description FROM duckdb_settings() WHERE name = '{setting}'"),
        )?;
        assert_eq!(described.len(), 1, "{setting}");
        assert!(!described[0][0].is_empty(), "{setting}");
    }
    for (sql, text) in [
        (
            "SET pcapsql_index_stride = 0",
            "pcapsql_index_stride must be at least 1",
        ),
        ("SET pcapsql_index_stride = NULL", "must not be NULL"),
        ("SET pcapsql_parallel_scan = NULL", "must not be NULL"),
        ("SET pcapsql_parallel_min_file_size = -1", ""),
        ("SET pcapsql_parallel_scan = 'perhaps'", ""),
    ] {
        let error = connection.execute(sql, Parameters::None).expect_err(sql);
        assert!(error.message.contains(text), "{sql}: {error}");
    }
    // A refused value changes nothing.
    assert_eq!(
        value(
            &connection,
            "SELECT current_setting('pcapsql_index_stride')"
        )?,
        "65536"
    );
    set(&connection, "pcapsql_index_stride", 7);
    set(&connection, "pcapsql_parallel_scan", false);
    assert_eq!(
        rows(
            &connection,
            "SELECT current_setting('pcapsql_index_stride'), \
             current_setting('pcapsql_parallel_scan')"
        )?,
        [["7", "false"]]
    );
    connection.execute("RESET pcapsql_index_stride", Parameters::None)?;
    assert_eq!(
        value(
            &connection,
            "SELECT current_setting('pcapsql_index_stride')"
        )?,
        "65536"
    );
    Ok(())
}

#[test]
fn a_bound_plan_is_partitioned_afresh_by_each_execution() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    connection.execute("CALL enable_logging(level = 'debug')", Parameters::None)?;
    let short = golden::legacy(mixed_frames(9000));
    let long = golden::legacy(mixed_frames(21_000));
    let path = fixture.write("grows.pcap", &short);
    partitioned(&connection, 4, 500);

    connection.execute(
        format!("CREATE VIEW udp AS SELECT * FROM read_udp('{path}')").as_str(),
        Parameters::None,
    )?;
    connection.execute(
        format!(
            "PREPARE numbered AS SELECT frame_number FROM read_frames('{path}') \
             WHERE frame_number % $1 = 0"
        )
        .as_str(),
        Parameters::None,
    )?;
    for capture in [&short, &long, &short] {
        // The file is replaced between executions: the plan was bound to the path.
        fixture.write("grows.pcap", capture);
        let (columns, reference) = reference_rows(capture, "udp");
        let frames = reference_rows(capture, "frames").1.len();
        for _ in 0..2 {
            logged(&connection);
            assert_cells(&connection, "SELECT * FROM udp", &columns, &reference);
            Scans::of(&logged(&connection)).assert_complete(4, "the view");
            let expected: Vec<String> = (1..=frames)
                .filter(|frame| frame % 1000 == 0)
                .map(|frame| frame.to_string())
                .collect();
            assert_eq!(column(&connection, "EXECUTE numbered(1000)")?, expected);
            Scans::of(&logged(&connection)).assert_complete(4, "the prepared statement");
        }
    }
    Ok(())
}
