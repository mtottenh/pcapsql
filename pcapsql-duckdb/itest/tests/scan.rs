//! The scan table functions, `read_<table>(file)` and `read_pcap(file, protocol := ...)`.
//!
//! What a scan must return is known without DuckDB: `reference_rows` reads a capture with the
//! shared scan layer alone (core's driver into a recording sink). The tests here compare that
//! with what a query returns, cell by cell and in order, for every table over the captures of
//! the golden corpus and over generated captures that cross chunk boundaries, are compressed,
//! are pcapng, or have nanosecond timestamps. The rest covers the SQL surface: columns,
//! arguments, errors, projection.
//!
//! `scan_regressions.rs` holds the tests of the defects of the previous extension, and
//! `golden_differential.rs` compares with the DataFusion frontend.

use std::io::Write;

use duckdb_neo::{connection::Connection, Parameters, Result};
use pcapsql_core::scan::{testing::Cell, ColKind, OutColumn};
use pcapsql_duckdb_itest::{
    column, connect, golden, reference_rows, replay::query_cells, rows, value, Fixture,
};

/// DuckDB's chunk size, which the row counts used here are chosen around.
const CHUNK: usize = 2048;

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn zstd(bytes: &[u8]) -> Vec<u8> {
    zstd::encode_all(bytes, 3).unwrap()
}

/// The tables of the frames the extension reads, by name: `frames` and the protocol tables.
/// The stream tables have `stream_tables.rs`.
fn tables(connection: &Connection) -> Vec<String> {
    column(
        connection,
        "SELECT name FROM pcap_protocols() WHERE kind <> 'stream' ORDER BY name",
    )
    .unwrap()
}

fn kinds(columns: &[OutColumn]) -> Vec<ColKind> {
    columns.iter().map(|column| column.kind).collect()
}

/// Assert that `SELECT * FROM <from>` returns exactly the rows of `table` in `capture`, in
/// order, and return how many there are.
fn assert_table(connection: &Connection, from: &str, capture: &[u8], table: &str) -> usize {
    let (columns, expected) = reference_rows(capture, table);
    let sql = format!("SELECT * FROM {from}");
    let actual = query_cells(connection, &sql, &kinds(&columns))
        .unwrap_or_else(|error| panic!("{sql}: {error}"));
    assert_eq!(actual.len(), expected.len(), "{sql}: number of rows");
    for (index, (actual, expected)) in actual.iter().zip(&expected).enumerate() {
        for ((actual, expected), column) in actual.iter().zip(expected).zip(&columns) {
            assert_eq!(
                actual, expected,
                "{sql}: row {index}, column {}",
                column.name
            );
        }
    }
    expected.len()
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
fn every_table_has_a_function_with_the_columns_of_pcap_schema() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let path = fixture.write("eth.pcap", &golden::capture("eth"));

    let tables = tables(&connection);
    assert_eq!(tables.len(), 28);
    for table in &tables {
        let schema = rows(
            &connection,
            &format!("SELECT column_name, column_type FROM pcap_schema('{table}')"),
        )?;
        assert!(schema.len() >= 5, "{table}");
        for from in [
            format!("read_{table}('{path}')"),
            format!("read_pcap('{path}', protocol := '{table}')"),
        ] {
            let described = rows(
                &connection,
                &format!("SELECT column_name, column_type FROM (DESCRIBE SELECT * FROM {from})"),
            )?;
            assert_eq!(described, schema, "{from}");
        }

        // Every scan table starts with the frame's number and its timestamp in nanoseconds.
        assert_eq!(schema[0], ["frame_number", "UBIGINT"], "{table}");
        assert_eq!(schema[1], ["timestamp", "TIMESTAMP_NS"], "{table}");
        if table != "frames" {
            let last: Vec<&str> = schema[schema.len() - 3..]
                .iter()
                .map(|column| column[0].as_str())
                .collect();
            assert_eq!(last, ["encap_depth", "tunnel_type", "tunnel_id"], "{table}");
        }
    }
    Ok(())
}

#[test]
fn every_table_of_every_corpus_capture_equals_the_shared_scan_layer() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let tables = tables(&connection);
    let mut total = 0;
    for name in golden::CAPTURES {
        let capture = golden::capture(name);
        let path = fixture.write(&format!("{name}.pcap"), &capture);
        let mut populated = 0;
        for table in &tables {
            let count = assert_table(
                &connection,
                &format!("read_{table}('{path}')"),
                &capture,
                table,
            );
            let generic = format!("read_pcap('{path}', protocol := '{table}')");
            assert_eq!(assert_table(&connection, &generic, &capture, table), count);
            // The row count alone, which reads no column.
            assert_eq!(
                value(
                    &connection,
                    &format!("SELECT count(*) FROM read_{table}('{path}')")
                )?,
                count.to_string(),
                "{name}: {table}"
            );
            populated += usize::from(count > 0);
            total += count;
        }
        // Every capture has frames, a link layer, a network layer and a transport.
        assert!(populated >= 4, "{name}: {populated} tables have rows");
    }
    // The corpus is not empty-handed: this many rows were compared.
    assert!(total > 150, "{total}");
    Ok(())
}

#[test]
fn read_pcap_reads_frames_unless_a_protocol_is_named() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let capture = golden::capture("eth");
    let path = fixture.write("eth.pcap", &capture);

    assert_eq!(
        assert_table(
            &connection,
            &format!("read_pcap('{path}')"),
            &capture,
            "frames"
        ),
        11
    );
    assert_eq!(
        rows(
            &connection,
            &format!("SELECT frame_number, length, link_type FROM read_pcap('{path}') LIMIT 2")
        )?,
        [["1", "54", "1"], ["2", "54", "1"]]
    );
    // The protocol in any case, as pcap_schema takes it.
    for protocol in ["tcp", "TCP", "Tcp"] {
        let from = format!("read_pcap('{path}', protocol := '{protocol}')");
        assert_eq!(assert_table(&connection, &from, &capture, "tcp"), 4);
    }
    // Both named parameters, in either order.
    for arguments in [
        "protocol := 'udp', strict := true",
        "strict := true, protocol := 'udp'",
    ] {
        let from = format!("read_pcap('{path}', {arguments})");
        assert_eq!(assert_table(&connection, &from, &capture, "udp"), 6);
    }
    Ok(())
}

#[test]
fn bad_arguments_are_bind_errors_that_say_what_is_wrong() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let path = fixture.write("eth.pcap", &golden::capture("eth"));
    let text = fixture.write("notes.txt", b"this is not a capture, only some text\n");
    let empty = fixture.write("empty.pcap", b"");
    let short = fixture.write("short.pcap", &golden::capture("eth")[..10]);
    let missing = fixture.path("missing.pcap");

    let cases: Vec<(String, &[&str])> =
        vec![
        // The protocol.
        (
            format!("read_pcap('{path}', protocol := 'nope')"),
            &["read_pcap", "no protocol table 'nope'", "pcap_protocols()"],
        ),
        (
            format!("read_pcap('{path}', protocol := NULL)"),
            &["read_pcap: protocol", "must not be NULL"],
        ),
        // It is a named parameter: the capture is the only positional argument.
        (
            format!("read_pcap('{path}', 'tcp')"),
            &["No function matches"],
        ),
        (
            format!("read_tcp('{path}', protocol := 'tcp')"),
            &["protocol"],
        ),
        // strict.
        (
            format!("read_tcp('{path}', strict := NULL)"),
            &["read_tcp: strict", "must not be NULL"],
        ),
        (
            format!("read_tcp('{path}', strict := 'perhaps')"),
            &["perhaps"],
        ),
        // The file argument.
        (
            "read_tcp(NULL)".to_owned(),
            &["read_tcp: the capture file must not be NULL"],
        ),
        (
            "read_pcap(NULL::VARCHAR)".to_owned(),
            &["read_pcap: the capture file must not be NULL"],
        ),
        (
            "read_frames(42)".to_owned(),
            &["read_frames: the capture files must be a VARCHAR path or pattern, or a list of \
               them, not INTEGER"],
        ),
        (
            "read_frames('')".to_owned(),
            &["read_frames: the capture file must not be an empty path"],
        ),
        ("read_frames()".to_owned(), &["read_frames"]),
        // The file itself.
        (format!("read_udp('{missing}')"), &["missing.pcap"]),
        (
            format!("read_udp('{text}')"),
            &[
                "read_udp",
                "notes.txt",
                "is not a capture file pcapsql can read",
            ],
        ),
        (
            format!("read_udp('{empty}')"),
            &[
                "read_udp",
                "empty.pcap",
                "is not a capture file pcapsql can read",
            ],
        ),
        (
            format!("read_udp('{short}')"),
            &[
                "read_udp",
                "short.pcap",
                "is not a capture file pcapsql can read",
            ],
        ),
        (
            format!("read_pcap('{text}', protocol := 'dns')"),
            &["read_pcap", "notes.txt"],
        ),
    ];
    for (from, expected) in cases {
        // DESCRIBE binds without running: all of these fail before a scan starts.
        for sql in [
            format!("SELECT * FROM {from}"),
            format!("DESCRIBE SELECT * FROM {from}"),
        ] {
            let error = rows(&connection, &sql).expect_err(&sql);
            for text in expected {
                assert!(error.message.contains(text), "{sql}: {error}");
            }
            assert!(!error.message.contains("INTERNAL"), "{sql}: {error}");
            assert!(!error.message.contains("panic"), "{sql}: {error}");
        }
    }

    // None of that cost the connection anything.
    assert_eq!(
        value(
            &connection,
            &format!("SELECT count(*) FROM read_frames('{path}')")
        )?,
        "11"
    );
    Ok(())
}

#[test]
fn a_capture_is_only_read_where_duckdb_allows_it() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let path = fixture.write("eth.pcap", &golden::capture("eth"));
    let count = format!("SELECT count(*) FROM read_tcp('{path}')");
    assert_eq!(value(&connection, &count)?, "4");

    connection.execute("SET enable_external_access = false", Parameters::None)?;
    for sql in [
        count,
        format!("DESCRIBE SELECT * FROM read_pcap('{path}')"),
        format!("SELECT * FROM read_pcap('{path}', protocol := 'dns')"),
    ] {
        let error = rows(&connection, &sql).expect_err(&sql);
        assert!(
            error.message.contains("disabled by configuration"),
            "{sql}: {error}"
        );
    }
    Ok(())
}

#[test]
fn compressed_captures_read_like_the_plain_ones() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    // Several chunks of rows, and more bytes than one read of the file returns once inflated.
    let big = golden::legacy(mixed_frames(6000));
    for (name, capture) in [("eth", golden::capture("eth")), ("big", big)] {
        let files = [
            fixture.write(&format!("{name}.pcap.gz"), &gzip(&capture)),
            fixture.write(&format!("{name}.pcap.zst"), &zstd(&capture)),
            // The compression is found in the bytes, not in the name.
            fixture.write(&format!("{name}-gzip.bin"), &gzip(&capture)),
            fixture.write(&format!("{name}-zstd.pcap"), &zstd(&capture)),
        ];
        for path in files {
            for table in ["frames", "ethernet", "ipv4", "udp", "dns", "vxlan"] {
                assert_table(
                    &connection,
                    &format!("read_{table}('{path}', strict := true)"),
                    &capture,
                    table,
                );
            }
        }
    }
    Ok(())
}

#[test]
fn pcapng_and_legacy_captures_of_the_same_frames_have_the_same_rows() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let frames = mixed_frames(5000);
    let legacy = golden::legacy_nanos(frames.clone());
    let pcapng = golden::pcapng(frames);
    let legacy_path = fixture.write("frames.pcap", &legacy);
    let pcapng_path = fixture.write("frames.pcapng", &pcapng);
    let pcapng_gz = fixture.write("frames.pcapng.gz", &gzip(&pcapng));

    for table in ["frames", "ethernet", "ipv4", "udp", "vxlan", "tcp"] {
        let (columns, expected) = reference_rows(&legacy, table);
        // The two formats hold the same packets with the same timestamps.
        assert!(reference_rows(&pcapng, table).1 == expected, "{table}");
        for path in [&legacy_path, &pcapng_path, &pcapng_gz] {
            let sql = format!("SELECT * FROM read_{table}('{path}', strict := true)");
            let actual = query_cells(&connection, &sql, &kinds(&columns))?;
            assert!(actual == expected, "{sql}");
        }
    }
    assert_eq!(
        value(
            &connection,
            &format!("SELECT count(*) FROM read_udp('{pcapng_path}')")
        )?,
        reference_rows(&legacy, "udp").1.len().to_string()
    );
    Ok(())
}

#[test]
fn timestamps_are_exact_to_the_nanosecond() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let frames: Vec<Vec<u8>> = (0..3000).map(golden::udp_frame).collect();
    for (file, capture) in [
        ("nanos.pcap", golden::legacy_nanos(frames.clone())),
        ("nanos.pcapng", golden::pcapng(frames.clone())),
    ] {
        let path = fixture.write(file, &capture);
        for table in ["frames", "udp"] {
            let from = format!("read_{table}('{path}')");
            assert_eq!(
                value(
                    &connection,
                    &format!("SELECT DISTINCT typeof(timestamp) FROM {from}")
                )?,
                "TIMESTAMP_NS",
                "{from}"
            );
            // The text DuckDB shows, digit for digit.
            assert_eq!(
                rows(&connection, &format!("SELECT frame_number, timestamp::VARCHAR FROM {from} WHERE frame_number IN (1, 2, 3000) ORDER BY 1"))?,
                [
                    ["1", "2023-11-14 22:13:20.123456789"],
                    ["2", "2023-11-14 22:13:21.12345779"],
                    ["3000", "2023-11-14 23:03:19.126458788"],
                ],
                "{from}"
            );
            // Every frame, as a number of nanoseconds.
            let nanos = column(
                &connection,
                &format!("SELECT epoch_ns(timestamp) FROM {from}"),
            )?;
            assert_eq!(nanos.len(), 3000);
            for (i, nanos) in nanos.iter().enumerate() {
                let expected = (i64::from(golden::FIRST_SECOND) + i as i64) * 1_000_000_000
                    + i64::from(golden::nanos_of(i));
                assert_eq!(*nanos, expected.to_string(), "{from}: frame {}", i + 1);
            }
        }
    }

    // A microsecond capture is the same instant, with zeros below the microsecond.
    let path = fixture.write("micros.pcap", &golden::legacy(frames));
    assert_eq!(
        rows(&connection, &format!("SELECT timestamp::VARCHAR, epoch_ns(timestamp) FROM read_frames('{path}') WHERE frame_number = 2"))?,
        [["2023-11-14 22:13:21.001", "1700000001001000000"]]
    );
    Ok(())
}

#[test]
fn a_capture_of_many_chunks_returns_every_frame_once_and_in_order() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    const FRAMES: u32 = 12_345;
    assert!(FRAMES as usize > 6 * CHUNK);
    let capture = golden::legacy((0..FRAMES).map(golden::udp_frame).collect());
    let path = fixture.write("many.pcap", &capture);

    for table in ["frames", "ethernet", "ipv4", "udp"] {
        let from = format!("read_{table}('{path}')");
        // Without ORDER BY: a scan returns the frames in capture order.
        let numbers = column(&connection, &format!("SELECT frame_number FROM {from}"))?;
        assert_eq!(numbers.len(), FRAMES as usize, "{from}");
        assert!(
            numbers
                .iter()
                .zip(1u32..)
                .all(|(number, expected)| *number == expected.to_string()),
            "{from}: the frame numbers are not 1, 2, 3, ..."
        );
        assert_eq!(
            rows(&connection, &format!("SELECT count(*), count(DISTINCT frame_number), min(frame_number), max(frame_number) FROM {from}"))?,
            [[FRAMES.to_string(), FRAMES.to_string(), "1".to_owned(), FRAMES.to_string()]],
            "{from}"
        );
        assert_table(&connection, &from, &capture, table);
    }

    // The payload of frame i spells i - 1, and so do its addresses: no row was put together
    // from two frames.
    assert_eq!(
        value(
            &connection,
            &format!(
                "SELECT count(*) FROM read_frames('{path}') f JOIN read_ipv4('{path}') i USING (frame_number)
                 WHERE right(pcap_hex(f.raw_data), 8) = printf('%08x', frame_number - 1)
                   AND i.src_ip = ip4('10.0.0.0') + frame_number - 1
                   AND i.timestamp = f.timestamp"
            )
        )?,
        FRAMES.to_string()
    );
    Ok(())
}

#[test]
fn a_query_gets_only_the_columns_it_uses_in_the_order_it_asked() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let capture = golden::legacy(mixed_frames(5000));
    let path = fixture.write("mixed.pcap", &capture);
    let (columns, expected) = reference_rows(&capture, "udp");
    let index = |name: &str| {
        columns
            .iter()
            .position(|column| column.name == name)
            .unwrap()
    };

    for names in [
        &["dst_port", "frame_number"][..],
        &["tunnel_id", "timestamp", "src_port", "encap_depth"],
        &["length"],
        &["tunnel_type", "frame_number", "tunnel_type"],
    ] {
        let picked: Vec<usize> = names.iter().map(|name| index(name)).collect();
        let sql = format!("SELECT {} FROM read_udp('{path}')", names.join(", "));
        let kinds: Vec<ColKind> = picked.iter().map(|&i| columns[i].kind).collect();
        let actual = query_cells(&connection, &sql, &kinds)?;
        let expected: Vec<Vec<Cell>> = expected
            .iter()
            .map(|row| picked.iter().map(|&i| row[i].clone()).collect())
            .collect();
        assert!(actual == expected, "{sql}");
    }

    // A filter on a column that is not selected, and an aggregate over an expression.
    let inner = expected
        .iter()
        .filter(|row| row[index("encap_depth")] != Cell::U8(0))
        .count();
    assert!(inner > 1000);
    assert_eq!(
        value(
            &connection,
            &format!("SELECT count(frame_number) FROM read_udp('{path}') WHERE encap_depth > 0")
        )?,
        inner.to_string()
    );
    assert_eq!(
        value(
            &connection,
            &format!("SELECT count(*) FROM read_udp('{path}')")
        )?,
        expected.len().to_string()
    );

    // DuckDB's plan names the columns the function is asked for.
    let plan = rows(
        &connection,
        &format!("EXPLAIN SELECT dst_port FROM read_udp('{path}') WHERE encap_depth > 0"),
    )?;
    let plan = &plan[0][1];
    assert!(plan.contains("READ_UDP"), "{plan}");
    assert!(
        plan.contains("dst_port") && plan.contains("encap_depth"),
        "{plan}"
    );
    assert!(!plan.contains("src_port"), "{plan}");
    Ok(())
}

/// The scans the extension logged (at debug level) since the log was last cleared: what each
/// was asked for and which protocols it parsed.
fn logged_scans(connection: &Connection) -> Vec<String> {
    let scans = column(
        connection,
        "SELECT message FROM duckdb_logs WHERE type = 'pcapsql' AND log_level = 'DEBUG' \
         AND message LIKE '%: scanning %' ORDER BY timestamp, context_id",
    )
    .unwrap();
    connection
        .execute("CALL truncate_duckdb_logs()", Parameters::None)
        .unwrap();
    scans
}

#[test]
fn a_query_of_frame_columns_parses_no_protocol() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let capture = golden::legacy(mixed_frames(3000));
    let path = fixture.write("mixed.pcap", &capture);
    connection.execute("CALL enable_logging(level = 'debug')", Parameters::None)?;
    logged_scans(&connection);

    // The extension logs what each scan parses; that is what this test reads back.
    let scan_of = |sql: &str| -> (String, String) {
        let result = value(&connection, sql).unwrap_or_else(|error| panic!("{sql}: {error}"));
        let scans = logged_scans(&connection);
        assert_eq!(scans.len(), 1, "{sql}: {scans:?}");
        (result, scans.into_iter().next().unwrap())
    };
    let parsed = |scan: &str| scan.rsplit("protocols parsed: ").next().unwrap().to_owned();

    // `frames`: whatever is selected, no parser runs.
    for (select, columns, result) in [
        ("count(*)", "frame_number", "3000"),
        ("max(frame_number)", "frame_number", "3000"),
        ("count(DISTINCT timestamp)", "timestamp", "3000"),
        ("sum(length) > 0", "length", "true"),
        ("count(raw_data)", "raw_data", "3000"),
    ] {
        for from in [
            format!("read_frames('{path}')"),
            format!("read_pcap('{path}')"),
        ] {
            let (actual, scan) = scan_of(&format!("SELECT {select} FROM {from}"));
            assert_eq!(actual, result, "{select} FROM {from}");
            assert!(
                scan.contains(&format!("columns: {columns}; protocols parsed: none")),
                "{scan}"
            );
        }
    }

    // A protocol table parses its protocol and what leads to it, and extracts only the fields
    // of the columns in use: none for a row count or the frame's own columns.
    let rows_of = |table: &str| reference_rows(&capture, table).1.len().to_string();
    for select in ["count(*)", "count(frame_number)", "count(timestamp)"] {
        let (actual, scan) = scan_of(&format!("SELECT {select} FROM read_udp('{path}')"));
        assert_eq!(actual, rows_of("udp"), "{select}");
        let parsed = parsed(&scan);
        assert!(parsed.contains("udp (no fields)"), "{scan}");
        for other in ["dns", "tcp", "icmp", "http"] {
            assert!(!parsed.contains(other), "{scan}");
        }
    }
    let (actual, scan) = scan_of(&format!("SELECT count(dst_port) FROM read_udp('{path}')"));
    assert_eq!(actual, rows_of("udp"));
    assert!(scan.contains("columns: dst_port;"), "{scan}");
    assert!(parsed(&scan).contains("udp (fields: dst_port)"), "{scan}");

    // Every column: the parser extracts every field.
    let (first, scan) = scan_of(&format!("SELECT * FROM read_vxlan('{path}') LIMIT 1"));
    assert_eq!(first, "5");
    assert!(parsed(&scan).ends_with("vxlan"), "{scan}");
    Ok(())
}

#[test]
fn a_table_with_few_rows_is_found_in_a_long_capture() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    // One DNS query every 4,000 frames among 30,000 that are something else.
    const FRAMES: u32 = 30_000;
    let frames: Vec<Vec<u8>> = (0..FRAMES)
        .map(|i| {
            if i % 4000 == 17 {
                golden::dns_query_frame()
            } else {
                golden::udp_frame(i)
            }
        })
        .collect();
    let capture = golden::legacy(frames);
    let path = fixture.write("sparse.pcap", &capture);

    let expected: Vec<String> = (0..FRAMES)
        .filter(|i| i % 4000 == 17)
        .map(|i| (i + 1).to_string())
        .collect();
    assert_eq!(expected.len(), 8);
    assert_eq!(
        column(
            &connection,
            &format!("SELECT frame_number FROM read_dns('{path}')")
        )?,
        expected
    );
    assert_table(&connection, &format!("read_dns('{path}')"), &capture, "dns");
    // A table with no row at all.
    assert_eq!(
        rows(&connection, &format!("SELECT * FROM read_tcp('{path}')"))?.len(),
        0
    );
    assert_eq!(
        value(
            &connection,
            &format!("SELECT count(*) FROM read_tcp('{path}')")
        )?,
        "0"
    );

    // LIMIT: the first rows, whether the scan is cut short or not.
    assert_eq!(
        column(
            &connection,
            &format!("SELECT frame_number FROM read_dns('{path}') LIMIT 3")
        )?,
        expected[..3]
    );
    assert_eq!(
        column(
            &connection,
            &format!("SELECT frame_number FROM read_frames('{path}') LIMIT 5 OFFSET 2047")
        )?,
        ["2048", "2049", "2050", "2051", "2052"]
    );
    Ok(())
}

#[test]
fn a_function_is_scanned_afresh_by_each_reference_and_each_execution() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let capture = golden::legacy(mixed_frames(5000));
    let path = fixture.write("mixed.pcap", &capture);
    let udp = reference_rows(&capture, "udp").1.len();
    let ethernet = reference_rows(&capture, "ethernet").1.len();

    // Two scans of one capture in one query, and a self join.
    assert_eq!(
        rows(&connection, &format!("SELECT (SELECT count(*) FROM read_udp('{path}')), (SELECT count(*) FROM read_ethernet('{path}')), (SELECT count(*) FROM read_udp('{path}'))"))?,
        [[udp.to_string(), ethernet.to_string(), udp.to_string()]]
    );
    assert_eq!(
        value(&connection, &format!("SELECT count(*) FROM read_frames('{path}') a JOIN read_frames('{path}') b ON b.frame_number = a.frame_number + 1"))?,
        "4999"
    );
    assert_eq!(
        value(&connection, &format!("SELECT count(*) FROM (SELECT * FROM read_udp('{path}') UNION ALL SELECT * FROM read_udp('{path}'))"))?,
        (2 * udp).to_string()
    );

    // A view and a prepared statement are bound once and run many times.
    connection.execute(
        format!("CREATE VIEW udp AS SELECT * FROM read_udp('{path}')"),
        Parameters::None,
    )?;
    connection.execute(format!("PREPARE counted AS SELECT count(*) FROM read_ethernet('{path}') WHERE encap_depth >= $1"), Parameters::None)?;
    for _ in 0..3 {
        assert_eq!(
            value(&connection, "SELECT count(*) FROM udp")?,
            udp.to_string()
        );
        assert_eq!(
            value(&connection, "EXECUTE counted(0)")?,
            ethernet.to_string()
        );
    }

    // The rows can be stored, and are the same rows.
    connection.execute(
        format!("CREATE TABLE stored AS SELECT * FROM read_udp('{path}')"),
        Parameters::None,
    )?;
    assert_table(&connection, "stored", &capture, "udp");

    // The estimate DuckDB plans with is a guess from the file size, shown as one.
    let plan = rows(
        &connection,
        &format!("EXPLAIN SELECT * FROM read_frames('{path}')"),
    )?;
    let estimate = capture.len() / 512;
    assert!(
        plan[0][1].contains(&format!("~{estimate} rows")),
        "{}",
        plan[0][1]
    );
    Ok(())
}

#[test]
fn threads_do_not_change_what_a_scan_returns() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let capture = golden::legacy(mixed_frames(20_000));
    let path = fixture.write("mixed.pcap", &capture);
    for threads in [1, 2, 8] {
        connection.execute(format!("SET threads = {threads}"), Parameters::None)?;
        for table in ["frames", "ethernet", "udp", "vxlan"] {
            assert_table(
                &connection,
                &format!("read_{table}('{path}')"),
                &capture,
                table,
            );
        }
    }
    Ok(())
}

#[test]
fn a_scan_reports_its_progress_as_the_share_of_the_file_read() -> Result<()> {
    use duckdb_neo::query_progress::QueryProgressTracker;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let connection = connect()?;
    let fixture = Fixture::new();
    // Large enough for the scan to take a while: DuckDB samples the progress as it runs.
    let capture = golden::legacy(mixed_frames(250_000));
    let path = fixture.write("long.pcap", &capture);
    connection.execute("SET progress_bar_time = 0", Parameters::None)?;
    // One partition, read by the thread that also updates the progress, between the slices of
    // its task: the samples then follow the scan. With several partitions (the capture is
    // large enough) DuckDB updates the progress when that thread has finished a slice of its
    // own partition, by when the others are nearly through theirs, and a sampler may see
    // nothing between the first read and the end. `scan_parallel.rs` has the test for that
    // case, which reads the progress between the chunks of a result.
    connection.execute("SET pcapsql_parallel_scan = false", Parameters::None)?;
    let tracker = QueryProgressTracker::new(&connection)?;

    let done = Arc::new(AtomicBool::new(false));
    let sampler = {
        let done = done.clone();
        std::thread::spawn(move || {
            let mut seen = Vec::new();
            while !done.load(Ordering::Relaxed) {
                if let Ok(Some(progress)) = tracker.snapshot() {
                    seen.push(progress.percentage);
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            seen
        })
    };
    let rows = value(
        &connection,
        &format!("SELECT count(tunnel_id) FROM read_udp('{path}')"),
    );
    done.store(true, Ordering::Relaxed);
    let seen = sampler.join().unwrap();
    assert!(rows?.parse::<u64>().unwrap() > 50_000);

    let seen: Vec<f64> = seen
        .into_iter()
        .filter(|percentage| *percentage >= 0.0)
        .collect();
    // A percentage of the file, not a fraction mistaken for one: it gets well past 1.
    assert!(
        seen.iter().all(|percentage| *percentage <= 100.0),
        "{seen:?}"
    );
    assert!(seen.iter().any(|percentage| *percentage > 10.0), "{seen:?}");
    assert!(
        seen.windows(2).all(|pair| pair[0] <= pair[1]),
        "progress went backwards"
    );
    Ok(())
}
