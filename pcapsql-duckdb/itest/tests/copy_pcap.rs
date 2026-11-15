//! `COPY ... TO 'x.pcap' (FORMAT pcap)`: the rows of a query written as a classic pcap file.
//!
//! What a copy must write is a file that reads back, with `read_frames`, as the rows it was
//! given: the same timestamps, lengths, link type and bytes, in the same order. The tests
//! compare the two sides with DuckDB, and the bytes of the file with what a pcap file is.

use std::io::Write;
use std::path::Path;

use duckdb_neo::{connection::Connection, Parameters, Result};
use pcapsql_duckdb_itest::{connect, golden, rows, value, Fixture};

/// What `read_frames` tells of a packet besides its number, a timestamp to the nanosecond.
const FRAME: &str = "epoch_ns(timestamp), length, original_length, link_type, raw_data";

const MAGIC_MICROS: [u8; 4] = [0xd4, 0xc3, 0xb2, 0xa1];
const MAGIC_NANOS: [u8; 4] = [0x4d, 0x3c, 0xb2, 0xa1];

fn execute(connection: &Connection, sql: &str) {
    connection
        .execute(sql, Parameters::None)
        .unwrap_or_else(|error| panic!("{sql}: {error}"));
}

/// The message of the error `sql` fails with.
fn error(connection: &Connection, sql: &str) -> String {
    match connection.execute(sql, Parameters::None) {
        Ok(_) => panic!("{sql} did not fail"),
        Err(error) => error.message,
    }
}

/// The packets of the capture `path`, in file order.
fn frames(connection: &Connection, path: &str) -> Vec<Vec<String>> {
    let sql = format!("SELECT {FRAME} FROM read_frames('{path}') ORDER BY frame_number");
    rows(connection, &sql).unwrap_or_else(|error| panic!("{sql}: {error}"))
}

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error| panic!("{path}: {error}"))
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

/// The captures of the fuzzing corpus (real captures: classic pcap of either byte order,
/// pcapng, Ethernet, Linux cooked, netlink and NFLOG), as name and bytes.
fn corpus() -> Vec<(String, Vec<u8>)> {
    let directory =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/fuzz_pcap_reader");
    let mut captures: Vec<(String, Vec<u8>)> = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("{}: {error}", directory.display()))
        .map(|entry| {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap().to_owned();
            (name, std::fs::read(&path).unwrap())
        })
        .collect();
    captures.sort();
    assert!(captures.len() >= 25, "{} captures", captures.len());
    captures
}

/// A capture of `count` UDP frames, a second apart: classic pcap, little-endian, microseconds,
/// snapshot length 65535.
fn udp_capture(count: u32) -> Vec<u8> {
    golden::legacy((0..count).map(golden::udp_frame).collect())
}

#[test]
fn every_corpus_capture_round_trips() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let mut link_types = std::collections::BTreeSet::new();
    let mut formats = std::collections::BTreeSet::new();
    for (name, bytes) in corpus() {
        let input = fixture.write(&name, &bytes);
        let expected = frames(&connection, &input);
        assert!(!expected.is_empty(), "{name} has no packets");
        let of_capture: std::collections::BTreeSet<&str> =
            expected.iter().map(|frame| frame[3].as_str()).collect();
        let output = fixture.path(&format!("copy-of-{name}.pcap"));
        let copy =
            format!("COPY (SELECT * FROM read_frames('{input}')) TO '{output}' (FORMAT pcap)");
        // A pcapng capture may have interfaces of several link types, which no pcap file can
        // hold: none of the corpus does.
        assert_eq!(of_capture.len(), 1, "{name}: link types {of_capture:?}");
        execute(&connection, &copy);

        assert_eq!(frames(&connection, &output), expected, "{name}");
        let written = read(&output);
        // read_frames returns TIMESTAMP_NS, so the file counts nanoseconds.
        assert_eq!(written[..4], MAGIC_NANOS, "{name}");
        assert_eq!(
            u32_at(&written, 20).to_string(),
            *of_capture.first().unwrap(),
            "{name}"
        );
        link_types.extend(of_capture.into_iter().map(str::to_owned));
        formats.insert(bytes[..4].to_vec());
    }
    // Ethernet, Linux cooked, NFLOG and netlink; both byte orders of pcap, and pcapng.
    for link_type in ["1", "113", "239", "253"] {
        assert!(link_types.contains(link_type), "{link_types:?}");
    }
    assert_eq!(formats.len(), 3, "{formats:?}");
    Ok(())
}

/// The header of a classic pcap file has nothing a copy cannot be told: with the unit and the
/// snapshot length of the input, the copy of a little-endian capture is the input.
#[test]
fn a_copy_of_a_little_endian_microsecond_pcap_is_byte_identical() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let mut compared = 0;
    for (name, bytes) in corpus() {
        if bytes[..4] != MAGIC_MICROS {
            continue;
        }
        let input = fixture.write(&name, &bytes);
        let output = fixture.path(&format!("copy-of-{name}"));
        execute(
            &connection,
            &format!(
                "COPY (SELECT * FROM read_frames('{input}')) TO '{output}' \
                 (FORMAT pcap, PRECISION 'us', SNAPLEN {})",
                u32_at(&bytes, 16)
            ),
        );
        assert!(read(&output) == bytes, "{name}: the copy differs");
        compared += 1;
    }
    assert!(compared >= 15, "{compared} captures compared");
    Ok(())
}

#[test]
fn compressed_and_pcapng_inputs_round_trip() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let frames_of = |count: u32| (0..count).map(golden::udp_frame).collect::<Vec<_>>();
    let plain = golden::legacy(frames_of(300));
    for (name, bytes) in [
        ("plain.pcap.gz", gzip(&plain)),
        ("plain.pcap.zst", zstd::encode_all(&plain[..], 3).unwrap()),
        ("nanos.pcapng", golden::pcapng(frames_of(300))),
        ("nanos.pcapng.gz", gzip(&golden::pcapng(frames_of(300)))),
    ] {
        let input = fixture.write(name, &bytes);
        let output = fixture.path(&format!("{name}.out.pcap"));
        execute(
            &connection,
            &format!("COPY (SELECT * FROM read_frames('{input}')) TO '{output}' (FORMAT pcap)"),
        );
        let expected = frames(&connection, &input);
        assert_eq!(expected.len(), 300, "{name}");
        assert_eq!(frames(&connection, &output), expected, "{name}");
    }
    // Decompressed, the gzip input is the plain capture again.
    let output = fixture.path("plain.pcap.gz.out.pcap");
    execute(
        &connection,
        &format!(
            "COPY (SELECT * FROM read_frames('{}')) TO '{output}' \
             (FORMAT pcap, PRECISION 'us', SNAPLEN 65535)",
            fixture.path("plain.pcap.gz")
        ),
    );
    assert!(read(&output) == plain);
    Ok(())
}

#[test]
fn a_filtered_copy_holds_the_selected_frames() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let input = fixture.write("in.pcap", &udp_capture(5_000));
    let output = fixture.path("out.pcap");
    let filter = "frame_number % 7 = 3 AND length > 0";
    execute(
        &connection,
        &format!(
            "COPY (SELECT * FROM read_frames('{input}') WHERE {filter}) TO '{output}' (FORMAT pcap)"
        ),
    );
    let selected = rows(
        &connection,
        &format!("SELECT {FRAME} FROM read_frames('{input}') WHERE {filter} ORDER BY frame_number"),
    )?;
    assert_eq!(selected.len(), 714);
    assert_eq!(frames(&connection, &output), selected);

    // A table function of protocol rows joined back to the frames: the TCP-less capture has
    // UDP only, so every frame with an odd source port.
    execute(
        &connection,
        &format!(
            "COPY (SELECT f.* FROM read_frames('{input}') f JOIN read_udp('{input}') u \
             USING (frame_number) WHERE u.src_port % 2 = 1 ORDER BY frame_number) \
             TO '{output}' (FORMAT pcap)"
        ),
    );
    assert_eq!(
        value(
            &connection,
            &format!("SELECT count(*) FROM read_frames('{output}')")
        )?,
        "2500"
    );
    assert_eq!(
        value(
            &connection,
            &format!("SELECT count(*) FROM read_udp('{output}') WHERE src_port % 2 = 0")
        )?,
        "0"
    );
    Ok(())
}

#[test]
fn an_empty_result_is_a_capture_without_packets() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let input = fixture.write("in.pcap", &udp_capture(10));
    let output = fixture.path("empty.pcap");
    execute(
        &connection,
        &format!(
            "COPY (SELECT * FROM read_frames('{input}') WHERE false) TO '{output}' (FORMAT pcap)"
        ),
    );
    let written = read(&output);
    assert_eq!(written.len(), 24);
    assert_eq!(written[..4], MAGIC_NANOS);
    assert_eq!(u32_at(&written, 16), 262_144);
    // No row says the link type: Ethernet.
    assert_eq!(u32_at(&written, 20), 1);
    assert_eq!(
        value(
            &connection,
            &format!("SELECT count(*) FROM read_frames('{output}')")
        )?,
        "0"
    );

    execute(
        &connection,
        &format!(
            "COPY (SELECT * FROM read_frames('{input}') WHERE false) TO '{output}' \
             (FORMAT pcap, LINKTYPE linux_sll2, SNAPLEN 96, PRECISION us)"
        ),
    );
    let written = read(&output);
    assert_eq!(written.len(), 24);
    assert_eq!(written[..4], MAGIC_MICROS);
    assert_eq!((u32_at(&written, 16), u32_at(&written, 20)), (96, 276));
    Ok(())
}

#[test]
fn nanosecond_timestamps_are_kept_unless_microseconds_are_asked_for() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let frames_in: Vec<Vec<u8>> = (0..200).map(golden::udp_frame).collect();
    let input = fixture.write("nanos.pcap", &golden::legacy_nanos(frames_in));
    let sub_micro = value(
        &connection,
        &format!(
            "SELECT count(*) FROM read_frames('{input}') WHERE epoch_ns(timestamp) % 1000 <> 0"
        ),
    )?;
    assert_eq!(
        sub_micro, "200",
        "the input has digits below the microsecond"
    );

    let output = fixture.path("default.pcap");
    execute(
        &connection,
        &format!("COPY (SELECT * FROM read_frames('{input}')) TO '{output}' (FORMAT pcap)"),
    );
    assert_eq!(read(&output)[..4], MAGIC_NANOS);
    assert_eq!(frames(&connection, &output), frames(&connection, &input));
    // The writer of the test data and this one agree on every byte.
    assert!(read(&output)[24..] == read(&input)[24..]);

    // Asked for: what is below a microsecond is dropped, not rounded.
    let output = fixture.path("micros.pcap");
    execute(
        &connection,
        &format!(
            "COPY (SELECT * FROM read_frames('{input}')) TO '{output}' (FORMAT pcap, PRECISION 'us')"
        ),
    );
    assert_eq!(read(&output)[..4], MAGIC_MICROS);
    let truncated = rows(
        &connection,
        &format!(
            "SELECT epoch_ns(timestamp) - epoch_ns(timestamp) % 1000, length, original_length, \
             link_type, raw_data FROM read_frames('{input}') ORDER BY frame_number"
        ),
    )?;
    assert_eq!(frames(&connection, &output), truncated);
    Ok(())
}

/// The unit of the file follows the type of the `timestamp` column.
#[test]
fn every_timestamp_type_is_written_in_a_unit_that_holds_it() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    // 2024-01-01 00:00:01 UTC.
    const SECOND: i64 = 1_704_067_201;
    for (literal, magic, nanos) in [
        (
            "TIMESTAMP_NS '2024-01-01 00:00:01.123456789'",
            MAGIC_NANOS,
            123_456_789,
        ),
        (
            "TIMESTAMP '2024-01-01 00:00:01.123456'",
            MAGIC_MICROS,
            123_456_000,
        ),
        (
            "TIMESTAMP_MS '2024-01-01 00:00:01.123'",
            MAGIC_MICROS,
            123_000_000,
        ),
        ("TIMESTAMP_S '2024-01-01 00:00:01'", MAGIC_MICROS, 0),
        (
            "TIMESTAMPTZ '2024-01-01 01:00:01.5+01'",
            MAGIC_MICROS,
            500_000_000,
        ),
    ] {
        let output = fixture.path("one.pcap");
        execute(
            &connection,
            &format!(
                "COPY (SELECT '\\x01\\x02\\x03'::BLOB AS raw_data, {literal} AS timestamp) \
                 TO '{output}' (FORMAT pcap)"
            ),
        );
        assert_eq!(read(&output)[..4], magic, "{literal}");
        assert_eq!(
            frames(&connection, &output),
            [[
                (SECOND * 1_000_000_000 + nanos).to_string(),
                "3".to_owned(),
                "3".to_owned(),
                "1".to_owned(),
                "\\x01\\x02\\x03".to_owned()
            ]],
            "{literal}"
        );
    }
    // A microsecond column in a nanosecond file, when that is asked for.
    let output = fixture.path("one.pcap");
    execute(
        &connection,
        &format!(
            "COPY (SELECT ''::BLOB AS raw_data, TIMESTAMP '2024-01-01 00:00:01.5' AS timestamp) \
             TO '{output}' (FORMAT pcap, PRECISION 'nanoseconds')"
        ),
    );
    assert_eq!(read(&output)[..4], MAGIC_NANOS);
    assert_eq!(
        value(
            &connection,
            &format!("SELECT epoch_ns(timestamp) FROM read_frames('{output}')")
        )?,
        (SECOND * 1_000_000_000 + 500_000_000).to_string()
    );
    Ok(())
}

#[test]
fn columns_are_found_by_name_and_the_others_are_ignored() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let input = fixture.write("in.pcap", &golden::capture("sll"));
    let expected = frames(&connection, &input);
    assert_eq!(expected[0][3], "113");
    let output = fixture.path("out.pcap");

    // Another order, other letter cases, wider and signed integers, and columns that are not
    // a packet's.
    execute(
        &connection,
        &format!(
            "COPY (SELECT 'x' AS note, raw_data AS \"RAW_DATA\", link_type::BIGINT AS Link_Type, \
             frame_number, original_length::TINYINT AS original_length, length, \
             timestamp AS \"Timestamp\", 42 AS answer \
             FROM read_frames('{input}')) TO '{output}' (FORMAT pcap)"
        ),
    );
    assert_eq!(frames(&connection, &output), expected);

    // Without the optional columns a packet is as long as its bytes, and Ethernet.
    execute(
        &connection,
        &format!(
            "COPY (SELECT timestamp, raw_data FROM read_frames('{input}')) TO '{output}' \
             (FORMAT pcap)"
        ),
    );
    let as_ethernet: Vec<Vec<String>> = expected
        .iter()
        .map(|frame| {
            let mut frame = frame.clone();
            frame[2] = frame[1].clone();
            frame[3] = "1".to_owned();
            frame
        })
        .collect();
    assert_eq!(frames(&connection, &output), as_ethernet);

    // NULL in an optional column is the column missing for that row.
    execute(
        &connection,
        &format!(
            "COPY (SELECT timestamp, raw_data, \
             CASE WHEN frame_number % 2 = 0 THEN link_type END AS link_type, \
             CASE WHEN frame_number % 2 = 0 THEN original_length + 1000 END AS original_length \
             FROM read_frames('{input}') ORDER BY frame_number DESC) TO '{output}' \
             (FORMAT pcap, LINKTYPE 113)"
        ),
    );
    let count = expected.len();
    let mut reversed: Vec<Vec<String>> = expected.clone();
    reversed.reverse();
    for (index, frame) in reversed.iter_mut().enumerate() {
        let frame_number = count - index;
        frame[2] = if frame_number.is_multiple_of(2) {
            (frame[2].parse::<u32>().unwrap() + 1000).to_string()
        } else {
            frame[1].clone()
        };
    }
    assert_eq!(frames(&connection, &output), reversed);
    Ok(())
}

#[test]
fn the_link_type_is_the_option_or_that_of_the_first_row() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let ethernet = fixture.write("eth.pcap", &golden::capture("eth"));
    let cooked = fixture.write("sll.pcap", &golden::capture("sll"));
    let output = fixture.path("out.pcap");
    let link_type_of = |sql: &str| {
        execute(&connection, sql);
        u32_at(&read(&output), 20)
    };

    let frames_of = |path: &str| format!("SELECT * FROM read_frames('{path}')");
    let untyped = |path: &str| format!("SELECT * EXCLUDE (link_type) FROM read_frames('{path}')");
    let copy =
        |query: &str, options: &str| format!("COPY ({query}) TO '{output}' (FORMAT pcap{options})");
    assert_eq!(link_type_of(&copy(&frames_of(&ethernet), "")), 1);
    assert_eq!(link_type_of(&copy(&frames_of(&cooked), "")), 113);
    assert_eq!(
        link_type_of(&copy(&frames_of(&cooked), ", LINKTYPE 113")),
        113
    );
    assert_eq!(
        link_type_of(&copy(&frames_of(&cooked), ", LINKTYPE 'LINUX_SLL'")),
        113
    );
    assert_eq!(link_type_of(&copy(&untyped(&cooked), "")), 1);
    assert_eq!(
        link_type_of(&copy(&untyped(&cooked), ", LINKTYPE linktype_linux_sll")),
        113
    );
    assert_eq!(
        link_type_of(&copy(&untyped(&cooked), ", LINKTYPE 147")),
        147
    );

    // One file, one link type: the first row whose type is another fails the statement.
    let both = format!(
        "SELECT * FROM read_frames(['{ethernet}', '{cooked}']) ORDER BY link_type, frame_number"
    );
    let ethernet_frames = frames(&connection, &ethernet).len();
    let message = error(&connection, &copy(&both, ""));
    assert!(
        message.contains(&format!(
            "pcap COPY: row {} has the link type 113, and the link type of the file is 1 \
             (that of the first row). A pcap file has one link type",
            ethernet_frames + 1
        )),
        "{message}"
    );
    let message = error(
        &connection,
        &copy(&frames_of(&ethernet), ", LINKTYPE LINUX_SLL"),
    );
    assert!(
        message.contains(
            "row 1 has the link type 1, and the link type of the file is 113 (the LINKTYPE option)"
        ),
        "{message}"
    );
    let message = error(
        &connection,
        &copy(
            &format!(
                "SELECT raw_data, timestamp, CASE WHEN frame_number > 2 THEN link_type END AS \
                 link_type FROM read_frames('{cooked}') ORDER BY frame_number"
            ),
            "",
        ),
    );
    assert!(
        message.contains(
            "row 3 has the link type 113, and the link type of the file is 1 (Ethernet, as the \
             first row has none)"
        ),
        "{message}"
    );

    // What the message proposes: a file per link type.
    let directory = fixture.path("by-link-type");
    execute(
        &connection,
        &format!(
            "COPY ({both}) TO '{directory}' \
             (FORMAT pcap, PARTITION_BY (link_type), WRITE_PARTITION_COLUMNS)"
        ),
    );
    for (link_type, input) in [(1, &ethernet), (113, &cooked)] {
        let part = format!("{directory}/link_type={link_type}/data_0.pcap");
        assert_eq!(u32_at(&read(&part), 20), link_type);
        let mut written = frames(&connection, &part);
        let mut expected = frames(&connection, input);
        // The order within a partition is DuckDB's.
        written.sort();
        expected.sort();
        assert_eq!(written, expected, "link type {link_type}");
    }
    Ok(())
}

#[test]
fn a_packet_longer_than_the_snapshot_length_is_cut_and_keeps_its_length() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let input = fixture.write("in.pcap", &golden::capture("http"));
    let output = fixture.path("out.pcap");
    let longest: u32 = value(
        &connection,
        &format!("SELECT max(length) FROM read_frames('{input}')"),
    )?
    .parse()
    .unwrap();
    assert!(longest > 60, "the capture has frames longer than 60 bytes");
    execute(
        &connection,
        &format!(
            "COPY (SELECT * FROM read_frames('{input}')) TO '{output}' (FORMAT pcap, SNAPLEN 60)"
        ),
    );
    assert_eq!(u32_at(&read(&output), 16), 60);
    let cut = rows(
        &connection,
        &format!(
            "SELECT epoch_ns(timestamp), least(length, 60), original_length, link_type, \
             raw_data[:60] FROM read_frames('{input}') ORDER BY frame_number"
        ),
    )?;
    assert_eq!(frames(&connection, &output), cut);
    Ok(())
}

#[test]
fn a_query_that_is_not_packets_is_refused_at_bind() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let input = fixture.write("in.pcap", &udp_capture(10));
    let output = fixture.path("out.pcap");
    let frames_of = format!("read_frames('{input}')");
    for (query, expected) in [
        (
            "SELECT 1 AS a, 'x' AS b".to_owned(),
            "pcap COPY: the query must have a column raw_data (BLOB, the bytes of a packet) and \
             a column timestamp (TIMESTAMP_NS or another TIMESTAMP type); original_length and \
             link_type (integers) are optional and other columns are ignored. It has: a, b.",
        ),
        (
            format!("SELECT frame_number, timestamp, length FROM {frames_of}"),
            "It has: frame_number, timestamp, length.",
        ),
        (
            format!("SELECT raw_data FROM {frames_of}"),
            "It has: raw_data.",
        ),
        (
            format!("SELECT timestamp, raw_data::VARCHAR AS raw_data FROM {frames_of}"),
            "pcap COPY: the column raw_data is VARCHAR: it must be BLOB",
        ),
        (
            format!("SELECT raw_data, timestamp::DATE AS timestamp FROM {frames_of}"),
            "pcap COPY: the column timestamp is DATE: it must be TIMESTAMP_NS, TIMESTAMP, \
             TIMESTAMP_MS, TIMESTAMP_S or TIMESTAMPTZ",
        ),
        (
            format!("SELECT raw_data, epoch_ns(timestamp) AS timestamp FROM {frames_of}"),
            "pcap COPY: the column timestamp is BIGINT: it must be",
        ),
        (
            format!(
                "SELECT raw_data, timestamp, length::DOUBLE AS original_length FROM {frames_of}"
            ),
            "pcap COPY: the column original_length is DOUBLE: it must be an integer of at most 64 \
             bits",
        ),
        (
            format!("SELECT raw_data, timestamp, 'ETHERNET' AS link_type FROM {frames_of}"),
            "pcap COPY: the column link_type is VARCHAR: it must be an integer of at most 64 bits",
        ),
        (
            format!("SELECT raw_data, timestamp, link_type::HUGEINT AS link_type FROM {frames_of}"),
            "pcap COPY: the column link_type is HUGEINT: it must be an integer of at most 64 bits",
        ),
    ] {
        let message = error(
            &connection,
            &format!("COPY ({query}) TO '{output}' (FORMAT pcap)"),
        );
        assert!(message.contains(expected), "{query}: {message}");
        assert!(!Path::new(&output).exists(), "{query} left a file");
    }

    for (options, expected) in [
        ("COMPRESSION gzip", "pcap COPY: unknown option COMPRESSION: the options of the format are LINKTYPE, SNAPLEN and PRECISION"),
        ("LINKTYPE 'token ring'", "pcap COPY: LINKTYPE 'token ring' is neither a number from 0 to 65535 nor a link type this extension has a name for"),
        ("LINKTYPE 65536", "pcap COPY: LINKTYPE '65536' is neither a number"),
        ("LINKTYPE -1", "pcap COPY: LINKTYPE '-1' is neither a number"),
        ("LINKTYPE", "pcap COPY: LINKTYPE 'true' is neither a number"),
        ("SNAPLEN 0", "pcap COPY: SNAPLEN '0' is not a number of bytes from 1 to 4294967295"),
        ("SNAPLEN 4294967296", "pcap COPY: SNAPLEN '4294967296' is not a number of bytes"),
        ("SNAPLEN 'all'", "pcap COPY: SNAPLEN 'all' is not a number of bytes"),
        ("PRECISION 'ms'", "pcap COPY: PRECISION 'ms' is neither 'ns' (nanoseconds) nor 'us' (microseconds)"),
        ("PRECISION 9", "pcap COPY: PRECISION '9' is neither"),
    ] {
        let message = error(
            &connection,
            &format!("COPY (SELECT * FROM {frames_of}) TO '{output}' (FORMAT pcap, {options})"),
        );
        assert!(message.contains(expected), "{options}: {message}");
        assert!(!Path::new(&output).exists(), "{options} left a file");
    }
    Ok(())
}

#[test]
fn a_row_that_is_not_a_packet_fails_the_statement_and_names_the_row() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    // More than one chunk, so that the failing row is not in the first batch.
    let input = fixture.write("in.pcap", &udp_capture(6_000));
    let output = fixture.path("out.pcap");
    let existing = fixture.write("existing.pcap", &udp_capture(3));
    for (columns, expected) in [
        (
            "timestamp, CASE WHEN frame_number <> 5000 THEN raw_data END AS raw_data",
            "pcap COPY: row 5000 has no raw_data (NULL)",
        ),
        (
            "raw_data, CASE WHEN frame_number <> 4321 THEN timestamp END AS timestamp",
            "pcap COPY: row 4321 has no timestamp (NULL)",
        ),
        (
            "raw_data, CASE WHEN frame_number < 3000 THEN timestamp \
             ELSE TIMESTAMP_NS '1969-12-31 23:59:59.999999999' END AS timestamp",
            "pcap COPY: row 3000 has a timestamp a pcap file cannot store: its range is \
             1970-01-01 00:00:00 to 2106-02-07 06:28:15 UTC",
        ),
        (
            "raw_data, CASE WHEN frame_number < 2 THEN timestamp::TIMESTAMP \
             ELSE TIMESTAMP '2106-02-07 06:28:16' END AS timestamp",
            "pcap COPY: row 2 has a timestamp a pcap file cannot store",
        ),
        (
            // Beyond what nanoseconds in 64 bits can count.
            "raw_data, TIMESTAMP '9999-01-01 00:00:00' AS timestamp",
            "pcap COPY: row 1 has a timestamp a pcap file cannot store",
        ),
        (
            "raw_data, timestamp, CASE WHEN frame_number = 2500 THEN -1 ELSE 60 END \
             AS original_length",
            "pcap COPY: row 2500 has the original_length -1, which is not a length a pcap file \
             can store (0 to 4294967295)",
        ),
        (
            "raw_data, timestamp, 4294967296 AS original_length",
            "pcap COPY: row 1 has the original_length 4294967296",
        ),
        (
            "raw_data, timestamp, CASE WHEN frame_number = 7 THEN 65536 ELSE 1 END AS link_type",
            "pcap COPY: row 7 has the link_type 65536, which is not a link type (0 to 65535)",
        ),
    ] {
        for target in [&output, &existing] {
            let message = error(
                &connection,
                &format!(
                    "COPY (SELECT {columns} FROM read_frames('{input}') ORDER BY frame_number) \
                     TO '{target}' (FORMAT pcap)"
                ),
            );
            assert!(message.contains(expected), "{columns}: {message}");
        }
        // DuckDB removes the file a failed statement created, and had not touched the one
        // that was there: it writes a temporary file beside it.
        assert!(!Path::new(&output).exists(), "{columns} left a file");
        assert!(read(&existing) == udp_capture(3), "{columns}");
        let left: Vec<String> = std::fs::read_dir(Path::new(&output).parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name != "in.pcap" && name != "existing.pcap")
            .collect();
        assert!(left.is_empty(), "{columns} left {left:?}");
    }

    // The last second a pcap record can name is written.
    execute(
        &connection,
        &format!(
            "COPY (SELECT ''::BLOB AS raw_data, TIMESTAMP_NS '2106-02-07 06:28:15.999999999' \
             AS timestamp) TO '{output}' (FORMAT pcap)"
        ),
    );
    assert_eq!(
        value(
            &connection,
            &format!("SELECT timestamp::VARCHAR FROM read_frames('{output}')")
        )?,
        "2106-02-07 06:28:15.999999999"
    );
    // And a statement over an existing file replaces it.
    execute(
        &connection,
        &format!("COPY (SELECT * FROM read_frames('{input}')) TO '{existing}' (FORMAT pcap)"),
    );
    assert_eq!(frames(&connection, &existing).len(), 6_000);
    Ok(())
}

/// A capture of many chunks, scanned in partitions on four threads: the file has the rows in
/// the order of the query.
#[test]
fn an_ordered_copy_of_a_large_capture_keeps_the_order_on_four_threads() -> Result<()> {
    const FRAMES: u32 = 60_000;
    let connection = connect()?;
    let fixture = Fixture::new();
    let capture = udp_capture(FRAMES);
    let input = fixture.write("in.pcap", &capture);
    for setting in [
        "threads = 4",
        "pcapsql_parallel_scan = true",
        "pcapsql_parallel_min_file_size = 0",
        "pcapsql_index_stride = 1000",
    ] {
        execute(&connection, &format!("SET {setting}"));
    }
    let as_input = "FORMAT pcap, PRECISION 'us', SNAPLEN 65535";
    let in_capture_order = frames(&connection, &input);
    assert_eq!(in_capture_order.len(), FRAMES as usize);

    let ordered = fixture.path("ordered.pcap");
    execute(
        &connection,
        &format!(
            "COPY (SELECT * FROM read_frames('{input}') ORDER BY frame_number) \
             TO '{ordered}' ({as_input})"
        ),
    );
    assert!(
        frames(&connection, &ordered) == in_capture_order,
        "ORDER BY frame_number"
    );
    // The same bytes but for the timestamps: the capture counts the milliseconds of a frame
    // past the second, and the copy has them in the seconds.
    assert_eq!(read(&ordered).len(), capture.len());

    let reversed = fixture.path("reversed.pcap");
    execute(
        &connection,
        &format!(
            "COPY (SELECT * FROM read_frames('{input}') ORDER BY frame_number DESC) \
             TO '{reversed}' ({as_input})"
        ),
    );
    let mismatches = value(
        &connection,
        &format!(
            "SELECT count(*) FROM read_frames('{input}') a FULL JOIN read_frames('{reversed}') b \
             ON a.frame_number = {FRAMES} + 1 - b.frame_number \
             WHERE a.raw_data IS DISTINCT FROM b.raw_data \
                OR a.timestamp IS DISTINCT FROM b.timestamp"
        ),
    )?;
    assert_eq!(mismatches, "0", "ORDER BY frame_number DESC");

    // An order that is not the capture's: by the bytes of the packets.
    let by_bytes = fixture.path("by-bytes.pcap");
    execute(
        &connection,
        &format!(
            "COPY (SELECT * FROM read_frames('{input}') WHERE frame_number % 3 <> 0 \
             ORDER BY raw_data DESC, frame_number) TO '{by_bytes}' ({as_input})"
        ),
    );
    let expected = rows(
        &connection,
        &format!(
            "SELECT {FRAME} FROM read_frames('{input}') WHERE frame_number % 3 <> 0 \
             ORDER BY raw_data DESC, frame_number"
        ),
    )?;
    assert_eq!(expected.len(), 40_000);
    assert!(
        frames(&connection, &by_bytes) == expected,
        "ORDER BY raw_data"
    );
    Ok(())
}

/// Not a promise of SQL, and written down as what DuckDB 2.0.0 does: it runs the copy
/// function of an extension as a sink that is not parallel, so the scan under it runs on one
/// thread and a copy without `ORDER BY` has the frames in the order of the capture. A DuckDB
/// that changes this fails here, and `docs/duckdb-extension-reference.md` says what to expect.
#[test]
fn duckdb_2_0_0_feeds_an_unordered_copy_in_capture_order() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let input = fixture.write("in.pcap", &udp_capture(60_000));
    for setting in [
        "threads = 4",
        "pcapsql_parallel_scan = true",
        "pcapsql_parallel_min_file_size = 0",
        "pcapsql_index_stride = 1000",
    ] {
        execute(&connection, &format!("SET {setting}"));
    }
    let output = fixture.path("out.pcap");
    execute(
        &connection,
        &format!(
            "COPY (SELECT * FROM read_frames('{input}')) TO '{output}' \
             (FORMAT pcap, PRECISION 'us', SNAPLEN 65535)"
        ),
    );
    assert!(frames(&connection, &output) == frames(&connection, &input));
    Ok(())
}

#[test]
fn the_statistics_of_a_copy_are_those_of_the_file() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let input = fixture.write("in.pcap", &udp_capture(4_000));
    let output = fixture.path("out.pcap");
    let copy = format!("COPY (SELECT * FROM read_frames('{input}')) TO '{output}'");

    assert_eq!(
        value(&connection, &format!("{copy} (FORMAT pcap)"))?,
        "4000"
    );
    let statistics = rows(&connection, &format!("{copy} (FORMAT pcap, RETURN_STATS)"))?;
    assert_eq!(statistics.len(), 1);
    assert_eq!(statistics[0][0], output);
    assert_eq!(statistics[0][1], "4000");
    assert_eq!(statistics[0][2], read(&output).len().to_string());

    Ok(())
}

/// DuckDB takes the format of a statement that names none from the end of the file name.
#[test]
fn a_file_named_pcap_is_written_as_pcap_without_the_format_option() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let input = fixture.write("in.pcap", &udp_capture(100));
    let query = format!("SELECT * FROM read_frames('{input}')");
    let output = fixture.path("out.pcap");
    execute(&connection, &format!("COPY ({query}) TO '{output}'"));
    assert_eq!(read(&output)[..4], MAGIC_NANOS);
    assert_eq!(frames(&connection, &output), frames(&connection, &input));

    // So it does for `x.pcap.gz`, and this format does not compress: refused, not written
    // under a name that says it is.
    for name in ["out.pcap.gz", "out.pcap.zst", "OUT.PCAP.GZ"] {
        let output = fixture.path(name);
        for options in ["", " (FORMAT pcap)"] {
            let message = error(
                &connection,
                &format!("COPY ({query}) TO '{output}'{options}"),
            );
            assert!(
                message.contains("pcap COPY: the output is not compressed, and")
                    && message.contains(name),
                "{name}: {message}"
            );
        }
        assert!(!Path::new(&output).exists(), "{name}");
    }
    Ok(())
}

/// DuckDB's own options that write several files: each file is a capture of its own.
#[test]
fn a_file_per_thread_holds_the_frames_between_them() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let input = fixture.write("in.pcap", &udp_capture(40_000));
    for setting in [
        "threads = 4",
        "pcapsql_parallel_min_file_size = 0",
        "pcapsql_index_stride = 1000",
    ] {
        execute(&connection, &format!("SET {setting}"));
    }
    let directory = fixture.path("per-thread");
    execute(
        &connection,
        &format!(
            "COPY (SELECT * FROM read_frames('{input}')) TO '{directory}' \
             (FORMAT pcap, PER_THREAD_OUTPUT)"
        ),
    );
    let files = std::fs::read_dir(&directory).unwrap().count();
    assert!(files >= 1, "{files} files");
    let difference = value(
        &connection,
        &format!(
            "SELECT count(*) FROM (\
             (SELECT {FRAME} FROM read_frames('{input}') EXCEPT ALL \
              SELECT {FRAME} FROM read_frames('{directory}/*.pcap')) \
             UNION ALL \
             (SELECT {FRAME} FROM read_frames('{directory}/*.pcap') EXCEPT ALL \
              SELECT {FRAME} FROM read_frames('{input}')))"
        ),
    )?;
    assert_eq!(difference, "0");
    assert_eq!(
        value(
            &connection,
            &format!("SELECT count(*) FROM read_frames('{directory}/*.pcap')")
        )?,
        "40000"
    );
    Ok(())
}

/// The output is opened through DuckDB's file system, so what DuckDB refuses is refused.
#[test]
fn duckdb_decides_where_a_copy_may_write() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let input = fixture.write("in.pcap", &udp_capture(10));
    let query = format!("SELECT * FROM read_frames('{input}')");
    execute(&connection, &format!("CREATE TABLE packets AS {query}"));

    let missing = fixture.path("no-such-directory/out.pcap");
    let message = error(
        &connection,
        &format!("COPY packets TO '{missing}' (FORMAT pcap)"),
    );
    assert!(message.contains("no-such-directory/out.pcap"), "{message}");

    execute(&connection, "SET enable_external_access = false");
    let output = fixture.path("denied.pcap");
    let message = error(
        &connection,
        &format!("COPY packets TO '{output}' (FORMAT pcap)"),
    );
    assert!(
        message.contains("file system operations are disabled by configuration"),
        "{message}"
    );
    assert!(!Path::new(&output).exists());
    Ok(())
}
