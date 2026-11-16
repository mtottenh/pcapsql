//! The index cache: a scan of a capture that an earlier scan in the same database split uses
//! that scan's index of the capture, and skips the pass over the capture that builds one.
//!
//! What the scan did is read back from DuckDB's log, where the extension writes one DEBUG
//! record per file it scans. Its `partitions:` note says how the file was split, and ends with
//! `index kept from an earlier scan` when the index came from the cache, which is exactly when
//! the pass did not run (`layout.rs`).
//!
//! The rows are compared with what the shared scan layer reads from the capture without DuckDB
//! (`reference_rows`), cell by cell and in order, so that an index that no longer fits the
//! file could not go unnoticed.

use duckdb_neo::{connection::Connection, Parameters, Result};
use pcapsql_core::scan::{testing::Cell, ColKind, OutColumn};
use pcapsql_duckdb_itest::{
    column, connect, golden, reference_rows, replay::query_cells, rows, value, Fixture,
};

/// The end of the note of a scan whose index came from the cache.
const KEPT: &str = "; index kept from an earlier scan)";

/// The note of a scan that splits a file as `built` says, with the index of an earlier scan.
fn kept(built: &str) -> String {
    format!("{}{KEPT}", built.strip_suffix(')').unwrap())
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

/// A connection to a new database, whose cache is empty, that logs what its scans do.
fn logging() -> Connection {
    let connection = connect().unwrap();
    connection
        .execute("CALL enable_logging(level = 'debug')", Parameters::None)
        .unwrap();
    connection
}

/// The `partitions:` notes of the scans logged since the log was last cleared, oldest first.
fn notes(connection: &Connection) -> Vec<String> {
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
        .iter()
        .filter_map(|record| record.split_once("': partitions: "))
        .map(|(_, rest)| rest.split("; columns: ").next().unwrap().to_owned())
        .collect()
}

/// The one note of the one scan logged since the log was last cleared.
fn note(connection: &Connection) -> String {
    let notes = notes(connection);
    assert_eq!(notes.len(), 1, "{notes:?}");
    notes.into_iter().next().unwrap()
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
        assert_eq!(actual, expected, "{sql}: row {index}");
    }
}

/// `count` UDP frames from number `first`; every fifth is inside VXLAN and every seventh
/// inside two, so that the records are of three lengths.
fn mixed_frames(first: u32, count: u32) -> Vec<Vec<u8>> {
    (first..first + count)
        .map(|i| match i {
            _ if i % 7 == 6 => golden::nested_vxlan_frame(i),
            _ if i % 5 == 4 => golden::vxlan_frame(i),
            _ => golden::udp_frame(i),
        })
        .collect()
}

/// The frames of the captures here, and the stride they are cut with: 24 checkpoints, and on
/// four threads partitions that start at frames 1, 3001, 6001 and 9001.
const FRAMES: u32 = 12_000;
const STRIDE: u64 = 500;

/// The byte offset of each record of a classic pcap capture, in frame order.
fn records(bytes: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut at = 24;
    while at + 16 <= bytes.len() {
        offsets.push(at);
        at += 16 + u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap()) as usize;
    }
    assert_eq!(at, bytes.len());
    offsets
}

/// The byte offset of each block of a pcapng capture.
fn blocks(bytes: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut at = 0;
    while at + 8 <= bytes.len() {
        offsets.push(at);
        at += u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
    }
    assert_eq!(at, bytes.len());
    offsets
}

/// A classic pcap capture with frames 5000 and 5001 as one record, by one length field
/// rewritten: the window of checkpoints that holds them has one record fewer, of the same
/// bytes, and every byte at every checkpoint is as it was.
fn merged_at_5000(legacy: &[u8]) -> Vec<u8> {
    let mut merged = legacy.to_vec();
    let offsets = records(legacy);
    let (a, b) = (offsets[4999], offsets[5000]);
    let length = get_u32(legacy, a + 8) + 16 + get_u32(legacy, b + 8);
    put_u32(&mut merged, a + 8, length);
    put_u32(&mut merged, a + 12, length);
    merged
}

/// A little-endian pcapng block of `block_type` with `body`, padded.
fn ng_block(block_type: u32, body: &[u8]) -> Vec<u8> {
    let padded = body.len().div_ceil(4) * 4;
    let total = (12 + padded) as u32;
    let mut block = block_type.to_le_bytes().to_vec();
    block.extend_from_slice(&total.to_le_bytes());
    block.extend_from_slice(body);
    block.resize(8 + padded, 0);
    block.extend_from_slice(&total.to_le_bytes());
    block
}

fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn get_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

#[test]
fn a_second_scan_uses_the_index_of_the_first_and_returns_the_same_rows() -> Result<()> {
    let fixture = Fixture::new();
    let captures = [
        (
            "mixed.pcap",
            golden::legacy(mixed_frames(0, FRAMES)),
            "1 (DuckDB has one thread)",
        ),
        (
            "mixed.pcapng",
            golden::pcapng(mixed_frames(0, FRAMES)),
            "1 (DuckDB has one thread)",
        ),
    ];
    for (name, capture, one_thread) in &captures {
        let path = fixture.write(name, capture);
        for table in ["udp", "frames"] {
            let (columns, reference) = reference_rows(capture, table);
            let select = format!("SELECT * FROM read_{table}('{path}')");
            let deep = format!(
                "SELECT frame_number FROM read_{table}('{path}') LIMIT 5 OFFSET {}",
                reference.len() * 2 / 3
            );
            for threads in [1, 2, 4] {
                // A new database: nothing kept yet.
                let connection = logging();
                partitioned(&connection, threads, STRIDE);
                let built = if threads == 1 {
                    one_thread.to_string()
                } else {
                    format!("{threads} (of {FRAMES} frames, cut at checkpoints 500 frames apart)")
                };
                let kept = if threads == 1 {
                    built.clone()
                } else {
                    kept(&built)
                };
                assert_cells(&connection, &select, &columns, &reference);
                assert_eq!(note(&connection), built, "{select}, {threads} threads");
                // The same rows in the same order, from the index of the first scan.
                assert_cells(&connection, &select, &columns, &reference);
                assert_eq!(note(&connection), kept, "{select}, {threads} threads");
                let first = column(&connection, &deep)?;
                assert_eq!(first.len(), 5);
                assert_eq!(column(&connection, &deep)?, first, "{deep}");
                assert_eq!(
                    value(
                        &connection,
                        &format!("SELECT count(*) FROM read_{table}('{path}')")
                    )?,
                    reference.len().to_string()
                );
                assert_eq!(notes(&connection), [kept.clone(), kept.clone(), kept]);
            }
        }
    }
    Ok(())
}

#[test]
fn the_scans_of_one_database_share_its_cache_and_another_database_has_its_own() -> Result<()> {
    let fixture = Fixture::new();
    let capture = golden::legacy(mixed_frames(0, FRAMES));
    let path = fixture.write("mixed.pcap", &capture);
    let built = format!("4 (of {FRAMES} frames, cut at checkpoints 500 frames apart)");
    let kept = kept(&built);
    let frames = format!("SELECT count(*) FROM read_frames('{path}')");
    let udp = format!("SELECT count(*) FROM read_udp('{path}')");

    let connection = logging();
    partitioned(&connection, 4, STRIDE);
    value(&connection, &frames)?;
    assert_eq!(note(&connection), built);
    // Another function, and `read_pcap`, of the same database.
    value(&connection, &udp)?;
    assert_eq!(note(&connection), kept);
    value(
        &connection,
        &format!("SELECT count(*) FROM read_pcap('{path}', protocol := 'ipv4')"),
    )?;
    assert_eq!(note(&connection), kept);
    // A join of two scans of the file: both use it.
    value(
        &connection,
        &format!(
            "SELECT count(*) FROM read_frames('{path}') f JOIN read_udp('{path}') u \
             USING (frame_number)"
        ),
    )?;
    assert_eq!(notes(&connection), [kept.clone(), kept.clone()]);

    // Another database starts without it.
    let other = logging();
    partitioned(&other, 4, STRIDE);
    value(&other, &udp)?;
    assert_eq!(note(&other), built);

    // Another stride is another index.
    set(&connection, "pcapsql_index_stride", 1000);
    value(&connection, &udp)?;
    assert_eq!(
        note(&connection),
        format!("4 (of {FRAMES} frames, cut at checkpoints 1000 frames apart)")
    );
    set(&connection, "pcapsql_index_stride", STRIDE);
    value(&connection, &udp)?;
    assert_eq!(note(&connection), kept);
    Ok(())
}

/// A file written again between two scans, with other content of the same size: all of it,
/// and a stretch in the middle that leaves the first and last 64 KiB as they were.
#[test]
fn a_file_rewritten_with_the_same_size_is_indexed_again() -> Result<()> {
    let fixture = Fixture::new();
    let frames = mixed_frames(0, FRAMES);
    let first = golden::legacy(frames.clone());
    let built = format!("4 (of {FRAMES} frames, cut at checkpoints 500 frames apart)");
    let kept = kept(&built);
    let again = |why: &str| {
        built.replace(
            ')',
            &format!("; the kept index no longer matched ({why}) and was built again)"),
        )
    };

    // Other frames of the same lengths, at the same times: the first packet differs.
    let mut others = mixed_frames(100_000, FRAMES);
    for (other, frame) in others.iter_mut().zip(&frames) {
        other.resize(frame.len(), 0);
    }
    // The frames of a stretch in the middle in the other order: records of three lengths are
    // shuffled there, so the checkpoint of frame 6001, where the third partition starts, no
    // longer falls on the same record.
    let mut shuffled = frames.clone();
    shuffled[4000..8000].reverse();
    let shuffled = golden::legacy(shuffled);
    let edge = 64 << 10;
    assert_eq!(shuffled[..edge], first[..edge]);
    assert_eq!(
        shuffled[shuffled.len() - edge..],
        first[first.len() - edge..]
    );

    for (rewritten, why) in [
        (
            golden::legacy(others),
            "the first 64 KiB of the file changed",
        ),
        (shuffled, "the record of frame 6001 changed"),
    ] {
        assert_eq!(rewritten.len(), first.len());
        let path = fixture.write("rewritten.pcap", &first);
        let connection = logging();
        partitioned(&connection, 4, STRIDE);
        for (capture, expected) in [
            (&first, built.clone()),
            (&first, kept.clone()),
            (&rewritten, again(why)),
            (&rewritten, kept.clone()),
            (&first, again(why)),
        ] {
            fixture.write("rewritten.pcap", capture);
            let (columns, reference) = reference_rows(capture, "udp");
            assert_cells(
                &connection,
                &format!("SELECT * FROM read_udp('{path}')"),
                &columns,
                &reference,
            );
            assert_eq!(note(&connection), expected);
        }
    }
    Ok(())
}

/// A file rewritten with the same size, the same first and last 64 KiB and the same records at
/// the checkpoints where its partitions start and end, but other records in between: what the
/// checks before the scan cannot see. Two records merged into one, or one split in two, in
/// the window before frame 6001, where the second partition of four ends. The scan finds it
/// at the end of that partition and fails, and the next scan builds the index again.
#[test]
fn records_that_moved_between_checkpoints_fail_the_scan_once() -> Result<()> {
    let fixture = Fixture::new();
    let legacy = golden::legacy(mixed_frames(0, FRAMES));
    let pcapng = golden::pcapng(mixed_frames(0, FRAMES));

    let merged = merged_at_5000(&legacy);
    let a = records(&legacy)[4999];
    // Frame 5000 as two records: the first 14 bytes of its packet, and the rest after a record
    // header written over the next 16.
    let mut split = legacy.clone();
    let data = get_u32(&legacy, a + 8);
    put_u32(&mut split, a + 8, 14);
    put_u32(&mut split, a + 12, 14);
    let second = a + 16 + 14;
    split.copy_within(a..a + 8, second);
    put_u32(&mut split, second + 8, data - 14 - 16);
    put_u32(&mut split, second + 12, data - 14 - 16);
    // The Enhanced Packet Blocks of frames 5000 and 5001 as one block.
    let mut merged_ng = pcapng.clone();
    let blocks = blocks(&pcapng);
    let (a, b) = (blocks[2 + 4999], blocks[2 + 5000]);
    let (first, next) = (get_u32(&pcapng, a + 4), get_u32(&pcapng, b + 4));
    put_u32(&mut merged_ng, a + 4, first + next);
    put_u32(&mut merged_ng, a + 20, first + next - 32);
    put_u32(&mut merged_ng, a + 24, first + next - 32);
    put_u32(&mut merged_ng, b + next as usize - 4, first + next);

    for (name, original, rewritten, frames) in [
        ("merged.pcap", &legacy, merged, FRAMES - 1),
        ("split.pcap", &legacy, split, FRAMES + 1),
        ("merged.pcapng", &pcapng, merged_ng, FRAMES - 1),
    ] {
        assert_eq!(rewritten.len(), original.len());
        let edge = 64 << 10;
        assert_eq!(rewritten[..edge], original[..edge], "{name}");
        assert_eq!(
            rewritten[rewritten.len() - edge..],
            original[original.len() - edge..],
            "{name}"
        );
        let (columns, reference) = reference_rows(&rewritten, "udp");
        assert_eq!(
            reference_rows(&rewritten, "frames").1.len(),
            frames as usize
        );
        let path = fixture.write(name, original);
        let connection = logging();
        partitioned(&connection, 4, STRIDE);
        let select = format!("SELECT * FROM read_udp('{path}')");
        value(
            &connection,
            &format!("SELECT count(*) FROM read_udp('{path}')"),
        )?;
        assert!(!note(&connection).ends_with(KEPT));

        fixture.write(name, &rewritten);
        let error = rows(&connection, &select).expect_err(name);
        let changed = format!(
            "'{path}' changed after its index was built: by the index frame 6001 starts at byte "
        );
        assert!(
            error.message.contains(&changed)
                && error.message.contains(", but frame 6000 ends at byte ")
                && error.message.contains("run the query again"),
            "{name}: {error}"
        );
        assert!(!error.message.contains("INTERNAL"), "{name}: {error}");
        assert_eq!(
            notes(&connection),
            [format!(
                "4 (of {FRAMES} frames, cut at checkpoints 500 frames apart{KEPT}"
            )]
        );
        // The index was dropped: the next scan builds it, from the file as it is now.
        assert_cells(&connection, &select, &columns, &reference);
        assert_eq!(
            note(&connection),
            format!("4 (of {frames} frames, cut at checkpoints 500 frames apart)"),
            "{name}"
        );
        assert_cells(&connection, &select, &columns, &reference);
        assert!(note(&connection).ends_with(KEPT), "{name}");
    }
    Ok(())
}

#[test]
fn the_cache_can_be_turned_off() -> Result<()> {
    let fixture = Fixture::new();
    let capture = golden::legacy(mixed_frames(0, FRAMES));
    let path = fixture.write("mixed.pcap", &capture);
    let built = format!("4 (of {FRAMES} frames, cut at checkpoints 500 frames apart)");
    let kept = kept(&built);
    let count = format!("SELECT count(*) FROM read_udp('{path}')");
    let rows_of = reference_rows(&capture, "udp").1.len().to_string();

    let connection = logging();
    partitioned(&connection, 4, STRIDE);
    let setting = "SELECT current_setting('pcapsql_index_cache')";
    assert_eq!(value(&connection, setting)?, "true");
    let described = column(
        &connection,
        "SELECT description FROM duckdb_settings() WHERE name = 'pcapsql_index_cache'",
    )?;
    assert_eq!(described.len(), 1);
    assert!(!described[0].is_empty());

    // Off: every scan builds the index, and none is kept.
    set(&connection, "pcapsql_index_cache", false);
    for _ in 0..2 {
        assert_eq!(value(&connection, &count)?, rows_of);
        assert_eq!(note(&connection), built);
    }
    set(&connection, "pcapsql_index_cache", true);
    for expected in [&built, &kept] {
        assert_eq!(value(&connection, &count)?, rows_of);
        assert_eq!(&note(&connection), expected);
    }
    // Off again: what is kept is not used, and stays for when it is on.
    set(&connection, "pcapsql_index_cache", false);
    assert_eq!(value(&connection, &count)?, rows_of);
    assert_eq!(note(&connection), built);
    connection.execute("RESET pcapsql_index_cache", Parameters::None)?;
    assert_eq!(value(&connection, setting)?, "true");
    assert_eq!(value(&connection, &count)?, rows_of);
    assert_eq!(note(&connection), kept);

    let error = connection
        .execute("SET pcapsql_index_cache = NULL", Parameters::None)
        .expect_err("NULL");
    assert!(error.message.contains("must not be NULL"), "{error}");
    assert_eq!(value(&connection, setting)?, "true");
    Ok(())
}

/// The pass that builds the index for a scan with an upper bound on `frame_number` stops at
/// the bound, and what it builds is not kept. An index of the whole capture serves any bound:
/// it is cut at the bound, so the partitions are those the pass would give.
#[test]
fn an_index_built_to_a_frame_bound_is_not_kept() -> Result<()> {
    let fixture = Fixture::new();
    let capture = golden::legacy(mixed_frames(0, FRAMES));
    let path = fixture.write("mixed.pcap", &capture);
    let frames = reference_rows(&capture, "frames").1.len().to_string();
    let count = |connection: &Connection, from: &str, filter: &str| -> (String, String) {
        let sql = format!("SELECT count(*) FROM {from} WHERE {filter}");
        let rows = value(connection, &sql).unwrap_or_else(|error| panic!("{sql}: {error}"));
        (rows, note(connection))
    };
    let plain = format!("read_frames('{path}')");
    let strict = format!("read_frames('{path}', strict := true)");
    let built = format!("4 (of {FRAMES} frames, cut at checkpoints 500 frames apart)");

    let connection = logging();
    partitioned(&connection, 4, STRIDE);
    let bounded = "frame_number <= 3000";
    let first = "4 (of the first 3000 frames, cut at checkpoints 500 frames apart; the filter \
                 leaves 3000 frames in 4 of 4 partitions)"
        .to_owned();
    for _ in 0..2 {
        assert_eq!(
            count(&connection, &plain, bounded),
            ("3000".into(), first.clone())
        );
    }
    assert_eq!(
        count(&connection, &plain, "true"),
        (frames.clone(), built.clone())
    );
    // The whole index, cut where each bound is, or not cut.
    for (filter, rows) in [
        (bounded, 3000),
        ("frame_number BETWEEN 5100 AND 5200", 101),
        ("frame_number > 11990", 10),
        ("frame_number <= 20000", FRAMES),
    ] {
        // What the pass gives: the scan of a new database.
        let fresh = logging();
        partitioned(&fresh, 4, STRIDE);
        let (expected, pass) = count(&fresh, &plain, filter);
        assert_eq!(expected, rows.to_string(), "{filter}");
        assert!(!pass.ends_with(KEPT), "{pass}");
        assert_eq!(
            count(&connection, &plain, filter),
            (expected, kept(&pass)),
            "{filter}"
        );
    }

    // A strict scan's pass reads to the end whatever the bound, and a bound past the last
    // frame lets the pass get there: either index is of the whole capture, and is kept.
    for (from, filter) in [(&strict, bounded), (&plain, "frame_number <= 20000")] {
        let connection = logging();
        partitioned(&connection, 4, STRIDE);
        let (_, note) = count(&connection, from, filter);
        assert!(!note.contains("the first"), "{from} {filter}: {note}");
        assert!(!note.ends_with(KEPT), "{note}");
        let (_, note) = count(&connection, &plain, "true");
        assert_eq!(note, kept(&built), "{from} {filter}");
    }
    Ok(())
}

/// Files whose indexes are kept are split for all of DuckDB's threads, since no pass is run
/// for them; a file whose index is built is split for its share of the threads, as before.
#[test]
fn files_whose_indexes_are_kept_are_split_for_all_the_threads() -> Result<()> {
    let fixture = Fixture::new();
    let capture = golden::legacy(mixed_frames(0, FRAMES));
    let paths: Vec<String> = ["a", "b", "c", "d"]
        .iter()
        .map(|name| fixture.write(&format!("{name}.pcap"), &capture))
        .collect();
    let list = format!(
        "[{}]",
        paths
            .iter()
            .map(|path| format!("'{path}'"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let (columns, one) = reference_rows(&capture, "udp");
    let all: Vec<Vec<Cell>> = (0..4).flat_map(|_| one.iter().cloned()).collect();
    let select = format!("SELECT * FROM read_udp({list})");
    let busy = "1 (the other files of the scan keep DuckDB's 4 threads busy)".to_owned();
    let kept = format!("4 (of {FRAMES} frames, cut at checkpoints 500 frames apart{KEPT}");

    let connection = logging();
    partitioned(&connection, 4, STRIDE);
    // Four files of one size on four threads: none is split, so none is indexed, and nothing
    // is kept.
    for _ in 0..2 {
        assert_cells(&connection, &select, &columns, &all);
        assert_eq!(notes(&connection), vec![busy.clone(); 4]);
    }
    // Two of them on their own: split, and their indexes kept.
    for path in &paths[..2] {
        value(
            &connection,
            &format!("SELECT count(*) FROM read_udp('{path}')"),
        )?;
        assert!(!note(&connection).ends_with(KEPT));
    }
    assert_cells(&connection, &select, &columns, &all);
    assert_eq!(
        notes(&connection),
        [kept.clone(), kept.clone(), busy.clone(), busy]
    );
    for path in &paths[2..] {
        value(
            &connection,
            &format!("SELECT count(*) FROM read_udp('{path}')"),
        )?;
        notes(&connection);
    }
    for threads in [2, 4] {
        set(&connection, "threads", threads);
        assert_cells(&connection, &select, &columns, &all);
        assert_eq!(
            notes(&connection),
            vec![kept.replacen('4', &threads.to_string(), 1); 4]
        );
    }
    Ok(())
}

/// A scan with a filter on `frame_number` or `timestamp` reads the same partitions, and gets
/// the same rows, from a kept index as from one it builds.
#[test]
fn a_kept_index_reads_what_a_built_one_reads() -> Result<()> {
    let fixture = Fixture::new();
    let capture = golden::legacy_nanos(mixed_frames(0, FRAMES));
    let path = fixture.write("mixed.pcap", &capture);
    // The time of frame `frame` (`legacy_nanos`).
    let at = |frame: u32| {
        let nanos = i64::from(golden::FIRST_SECOND + frame - 1) * 1_000_000_000
            + i64::from(golden::nanos_of(frame as usize - 1));
        format!("make_timestamp_ns({nanos})")
    };
    let filters = [
        "true".to_owned(),
        format!("timestamp BETWEEN {} AND {}", at(5001), at(6000)),
        format!("timestamp >= {} AND timestamp < {}", at(7100), at(7900)),
        format!("timestamp > {}", at(11_000)),
        format!("timestamp < {} AND frame_number <= 6000", at(1001)),
        "frame_number BETWEEN 5100 AND 5200".to_owned(),
        "frame_number > 11990".to_owned(),
        "frame_number <= 10".to_owned(),
    ];
    // The rows, and what each partition read: the log records of the workers, without the
    // worker's number, which is any.
    let scanned = |connection: &Connection, sql: &str| -> (Vec<Vec<String>>, Vec<String>) {
        connection
            .execute("CALL truncate_duckdb_logs()", Parameters::None)
            .unwrap();
        let rows = rows(connection, sql).unwrap_or_else(|error| panic!("{sql}: {error}"));
        let mut partitions: Vec<String> = column(
            connection,
            "SELECT message FROM duckdb_logs WHERE type = 'pcapsql' AND log_level = 'DEBUG' \
             AND message LIKE '% finished partition %'",
        )
        .unwrap()
        .iter()
        .map(|record| record.split_once(" finished ").unwrap().1.to_owned())
        .collect();
        partitions.sort();
        (rows, partitions)
    };

    let connection = logging();
    partitioned(&connection, 4, STRIDE);
    value(
        &connection,
        &format!("SELECT count(*) FROM read_frames('{path}')"),
    )?;
    assert_eq!(
        note(&connection),
        format!("4 (of {FRAMES} frames, cut at checkpoints 500 frames apart)")
    );
    for filter in &filters {
        let sql = format!("SELECT frame_number, src_port FROM read_udp('{path}') WHERE {filter}");
        set(&connection, "pcapsql_index_cache", false);
        let built = scanned(&connection, &sql);
        set(&connection, "pcapsql_index_cache", true);
        let from_kept = scanned(&connection, &sql);
        assert!(!built.0.is_empty(), "{filter}");
        assert!(!built.1.is_empty(), "{filter}");
        assert_eq!(from_kept, built, "{filter}");
        assert!(note(&connection).ends_with(KEPT), "{filter}");
    }
    Ok(())
}

/// In a pcapng capture blocks that are not packets may come between the last packet of a
/// partition and the first of the next: an interface description, a new section. A partition
/// then ends before the next one starts, which is not a change of the file.
#[test]
fn blocks_between_two_partitions_of_a_pcapng_capture_are_no_change() -> Result<()> {
    use pcapsql_testgen::{pcapng_ordered, PcapngBlock, PcapngInterface, PcapngOrderedSection};

    let interface = |tsresol| PcapngInterface {
        link_type: 1,
        tsresol,
        snaplen: 65535,
        if_tsoffset: 0,
    };
    let packet = |interface_id, i: u32, data: Vec<u8>| {
        PcapngBlock::Packet(pcapsql_testgen::PcapngPacket {
            interface_id,
            ts_sec: u64::from(golden::FIRST_SECOND + i),
            ts_frac_units: u64::from(i),
            origlen: data.len() as u32,
            data,
        })
    };
    let frames = mixed_frames(0, 2000);
    // An interface declared before frame 501, and a new section before frame 1001: the
    // partitions on four threads start at frames 1, 501, 1001 and 1501.
    let mut first = vec![PcapngBlock::Interface(interface(6))];
    for (i, frame) in frames[..1000].iter().enumerate() {
        if i == 500 {
            first.push(PcapngBlock::Interface(interface(9)));
        }
        first.push(packet(u32::from(i >= 500), i as u32, frame.clone()));
    }
    let mut second = vec![PcapngBlock::Interface(interface(9))];
    for (i, frame) in frames[1000..].iter().enumerate() {
        second.push(packet(0, 1000 + i as u32, frame.clone()));
    }
    let capture = pcapng_ordered(&[
        PcapngOrderedSection { blocks: first },
        PcapngOrderedSection { blocks: second },
    ])
    .bytes;
    let fixture = Fixture::new();
    let path = fixture.write("sections.pcapng", &capture);
    let (columns, reference) = reference_rows(&capture, "udp");
    let select = format!("SELECT * FROM read_udp('{path}')");
    let built = "4 (of 2000 frames, cut at checkpoints 500 frames apart)";

    let connection = logging();
    partitioned(&connection, 4, STRIDE);
    for expected in [built.to_owned(), kept(built)] {
        assert_cells(&connection, &select, &columns, &reference);
        assert_eq!(note(&connection), expected);
    }
    Ok(())
}

/// A known limit of the cache, not a wanted behaviour (the documentation of the `index_cache`
/// module and the reference say so): records merged in place, in a part of the capture a
/// filtered scan does not read, are not seen, and the frames the scan reads after them are
/// numbered by the kept index, one too high, with no error. With the cache off the frames are
/// numbered as they are now.
#[test]
fn known_limit_records_merged_in_place_shift_the_frame_numbers_of_a_filtered_scan() -> Result<()> {
    let fixture = Fixture::new();
    let original = golden::legacy(mixed_frames(0, FRAMES));
    let path = fixture.write("merged.pcap", &original);
    let connection = logging();
    partitioned(&connection, 4, STRIDE);
    value(
        &connection,
        &format!("SELECT count(*) FROM read_frames('{path}')"),
    )?;
    assert!(!note(&connection).ends_with(KEPT));
    fixture.write("merged.pcap", &merged_at_5000(&original));

    // Frame `i` of `golden::legacy` (from 0) is at FIRST_SECOND + i seconds and i
    // milliseconds, so the time tells the record: `record` is its `i`. After the merge the
    // record of frame 9001 before is frame 9000.
    let base = u64::from(golden::FIRST_SECOND) * 1000;
    let record = format!("(epoch_ms(timestamp) - {base}) // 1001");
    let at = |i: u64| format!("make_timestamp({}::BIGINT)", (base + 1001 * i) * 1000);
    let queries = [
        format!(
            "SELECT frame_number, {record} FROM read_frames('{path}') \
             WHERE frame_number BETWEEN 9001 AND 9003 ORDER BY 1"
        ),
        format!(
            "SELECT frame_number, {record} FROM read_frames('{path}') \
             WHERE timestamp >= {} AND timestamp < {} ORDER BY 1",
            at(9000),
            at(9003)
        ),
        format!(
            "SELECT count(*), max(frame_number) FROM read_frames('{path}') \
             WHERE frame_number > 6000"
        ),
    ];
    let pairs = |pairs: &[(u32, u32)]| -> Vec<Vec<String>> {
        pairs
            .iter()
            .map(|(a, b)| vec![a.to_string(), b.to_string()])
            .collect()
    };
    let shifted = [
        pairs(&[(9001, 9000), (9002, 9001), (9003, 9002)]),
        pairs(&[(9001, 9000), (9002, 9001), (9003, 9002)]),
        pairs(&[(6000, FRAMES)]),
    ];
    let right = [
        pairs(&[(9001, 9001), (9002, 9002), (9003, 9003)]),
        pairs(&[(9000, 9000), (9001, 9001), (9002, 9002)]),
        pairs(&[(5999, FRAMES - 1)]),
    ];
    for (sql, (shifted, right)) in queries.iter().zip(shifted.iter().zip(&right)) {
        set(&connection, "pcapsql_index_cache", true);
        assert_eq!(&rows(&connection, sql)?, shifted, "{sql}");
        assert!(
            notes(&connection).iter().all(|note| note.ends_with(KEPT)),
            "{sql}"
        );
        set(&connection, "pcapsql_index_cache", false);
        assert_eq!(&rows(&connection, sql)?, right, "{sql}");
        notes(&connection);
    }
    Ok(())
}

/// Blocks that the reader does not number, between the last frame of a partition and the first
/// of the next: an obsolete Packet Block (type 2, which the parser does not decode), a custom
/// block and a block of a type nothing defines. The partition then ends before the next one
/// starts, at a block that is not a frame, and that is not a change of the file.
#[test]
fn blocks_that_are_no_frames_between_two_partitions_of_a_pcapng_capture_are_no_change() -> Result<()>
{
    let plain = golden::pcapng(mixed_frames(0, 2000));
    let offsets = blocks(&plain);
    // A section header, an interface description, then a block per frame. The extra blocks
    // come after frames 500, 1000 and 1500, where the partitions on four threads end.
    let packet = [
        0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 9, 9, 9, 9,
    ];
    let extra = [
        (500, ng_block(2, &packet)),
        (1000, ng_block(0x0000_0BAD, &[1, 2, 3, 4, 5, 6])),
        (1500, ng_block(0x0000_0101, &[1, 2, 3])),
    ];
    let mut capture = Vec::new();
    let mut from = 0;
    for (frame, block) in &extra {
        let at = offsets[2 + frame];
        capture.extend_from_slice(&plain[from..at]);
        capture.extend_from_slice(block);
        from = at;
    }
    capture.extend_from_slice(&plain[from..]);
    let fixture = Fixture::new();
    let path = fixture.write("extra.pcapng", &capture);
    let (columns, reference) = reference_rows(&capture, "udp");
    assert_eq!(reference_rows(&capture, "frames").1.len(), 2000);
    let select = format!("SELECT * FROM read_udp('{path}')");
    let built = "4 (of 2000 frames, cut at checkpoints 500 frames apart)";

    let connection = logging();
    partitioned(&connection, 4, STRIDE);
    for expected in [built.to_owned(), kept(built)] {
        assert_cells(&connection, &select, &columns, &reference);
        assert_eq!(note(&connection), expected);
    }
    // The setting off: an index built for the scan, checked the same way.
    set(&connection, "pcapsql_index_cache", false);
    assert_cells(&connection, &select, &columns, &reference);
    assert_eq!(note(&connection), built);
    Ok(())
}
