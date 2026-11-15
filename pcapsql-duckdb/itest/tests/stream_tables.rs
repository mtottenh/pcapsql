//! The stream tables: `read_tcp_connections`, `read_tls_sessions`, `read_http_messages`,
//! `read_http2` and `read_pcap(protocol := ...)` of them, and the TLS key log.
//!
//! What a scan of a stream table must return is known without DuckDB, as for a packet table:
//! `reference_rows` reads a capture with the shared scan layer alone, and
//! `reference_rows_decrypted` does it with a key log. The tests compare that with what a query
//! returns, cell by cell and in order: over the captures of the golden corpus, over the
//! captures of `pcapsql_testgen::tls` (HTTP/2 over TLS 1.3, HTTP/2 and HTTP/1.1 over TLS 1.2)
//! with their key logs, and over a generated capture whose tables are larger than a chunk. `golden_differential.rs` compares the same
//! tables with the DataFusion frontend's snapshots.
//!
//! The rest is what is particular to these tables: one partition per file whatever the
//! settings, no filter taken over by the scan, `connection_id` per file, and where a key log
//! comes from (the `keylog` parameter, the setting `pcapsql_keylog`) and what happens when it
//! cannot be read.

use std::io::Write;

use duckdb_neo::{connection::Connection, Parameters, Result};
use pcapsql_core::scan::{testing::Cell, ColKind, OutColumn};
use pcapsql_duckdb_itest::{
    column, connect, golden, reference_rows, reference_rows_decrypted, replay::query_cells, rows,
    value, Fixture,
};
use pcapsql_testgen::corpus::{
    eth, ipv4, tcp, to_capture, ETH_IP4, HTTP_REQUEST, HTTP_RESPONSE, LINKTYPE_ETHERNET, MAC_A,
    MAC_B,
};
use pcapsql_testgen::tls::{FIXTURES, TLS13_HTTP2_CAPTURE, TLS13_HTTP2_KEYLOG};

const STREAM_TABLES: [&str; 4] = ["http2", "http_messages", "tcp_connections", "tls_sessions"];

/// DuckDB's chunk size.
const CHUNK: usize = 2048;

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn zstd(bytes: &[u8]) -> Vec<u8> {
    zstd::encode_all(bytes, 3).unwrap()
}

fn execute(connection: &Connection, sql: &str) {
    connection
        .execute(sql, Parameters::None)
        .unwrap_or_else(|error| panic!("{sql}: {error}"));
}

fn set(connection: &Connection, setting: &str, value: impl std::fmt::Display) {
    execute(connection, &format!("SET {setting} = {value}"));
}

/// The error of a query that must fail.
fn failure(connection: &Connection, sql: &str) -> String {
    rows(connection, sql).expect_err(sql).message
}

/// The debug records the extension logged since the log was last cleared, oldest first.
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

/// `count` HTTP/1.1 exchanges, each on a connection of its own from a client of its own:
/// handshake, request, response, and a close for every connection but each fourth, which
/// stays open. Eight frames per closed connection, five per open one.
fn http_exchanges(count: u32) -> Vec<Vec<u8>> {
    let server = [10, 0, 0, 2];
    let request = HTTP_REQUEST.len() as u32;
    let response = HTTP_RESPONSE.len() as u32;
    let mut frames = Vec::new();
    for i in 0..count {
        let client = [10, 1, (i >> 8) as u8, i as u8];
        let port = 20_000 + (i % 30_000) as u16;
        let mut segment = |to_server: bool, tcp_bytes: Vec<u8>| {
            let (source, destination, from, to) = if to_server {
                (client, server, MAC_A, MAC_B)
            } else {
                (server, client, MAC_B, MAC_A)
            };
            let id = frames.len() as u16;
            frames.push(eth(
                to,
                from,
                ETH_IP4,
                &ipv4(source, destination, 6, id, &tcp_bytes),
            ));
        };
        segment(true, tcp(port, 80, 1000, 0, 0x02, &[]));
        segment(false, tcp(80, port, 5000, 1001, 0x12, &[]));
        segment(true, tcp(port, 80, 1001, 5001, 0x10, &[]));
        segment(true, tcp(port, 80, 1001, 5001, 0x18, HTTP_REQUEST));
        segment(
            false,
            tcp(80, port, 5001, 1001 + request, 0x18, HTTP_RESPONSE),
        );
        if i % 4 == 3 {
            continue;
        }
        segment(
            true,
            tcp(port, 80, 1001 + request, 5001 + response, 0x11, &[]),
        );
        segment(
            false,
            tcp(80, port, 5001 + response, 1002 + request, 0x11, &[]),
        );
        segment(
            true,
            tcp(port, 80, 1002 + request, 5002 + response, 0x10, &[]),
        );
    }
    frames
}

/// A capture of `count` [`http_exchanges`].
fn http_exchange_capture(count: u32) -> Vec<u8> {
    to_capture(http_exchanges(count), LINKTYPE_ETHERNET)
}

#[test]
fn the_stream_tables_have_functions_with_the_columns_of_pcap_schema() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let path = fixture.write("http.pcap", &golden::capture("http"));

    assert_eq!(
        column(
            &connection,
            "SELECT name FROM pcap_protocols() WHERE kind = 'stream' ORDER BY name"
        )?,
        STREAM_TABLES
    );
    for table in STREAM_TABLES {
        let schema = rows(
            &connection,
            &format!("SELECT column_name, column_type, nullable FROM pcap_schema('{table}')"),
        )?;
        for from in [
            format!("read_{table}('{path}')"),
            format!("read_pcap('{path}', protocol := '{table}')"),
        ] {
            let described = rows(
                &connection,
                &format!("SELECT column_name, column_type FROM (DESCRIBE SELECT * FROM {from})"),
            )?;
            let expected: Vec<&[String]> = schema.iter().map(|column| &column[..2]).collect();
            assert_eq!(described, expected, "{from}");
        }
        // The frame a row belongs to, the connection it is of, and no tunnel: a stream table
        // has no `timestamp` of a frame.
        assert_eq!(schema[0], ["frame_number", "UBIGINT", "false"], "{table}");
        assert_eq!(schema[1], ["connection_id", "UBIGINT", "false"], "{table}");
        let last: Vec<&str> = schema[schema.len() - 3..]
            .iter()
            .map(|column| column[0].as_str())
            .collect();
        assert_eq!(last, ["encap_depth", "tunnel_type", "tunnel_id"], "{table}");
        assert!(!schema.iter().any(|c| c[0] == "timestamp"), "{table}");

        // The function has `keylog` after the parameters every scan function has.
        assert_eq!(
            value(
                &connection,
                &format!(
                    "SELECT parameters::VARCHAR FROM duckdb_functions() \
                     WHERE function_name = 'read_{table}'"
                )
            )?,
            "[files, strict, filename, keylog]",
            "{table}"
        );
    }
    assert_eq!(
        value(
            &connection,
            "SELECT parameters::VARCHAR FROM duckdb_functions() WHERE function_name = 'read_pcap'"
        )?,
        "[files, protocol, strict, filename, keylog]"
    );
    // The times of a connection are in the engine's unit, like a frame's.
    assert_eq!(
        column(
            &connection,
            "SELECT column_name FROM pcap_schema('tcp_connections') \
             WHERE column_type = 'TIMESTAMP_NS' ORDER BY column_name"
        )?,
        ["end_time", "start_time"]
    );
    Ok(())
}

#[test]
fn every_stream_table_of_every_capture_equals_the_shared_scan_layer() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let mut captures: Vec<(String, Vec<u8>)> = golden::CAPTURES
        .iter()
        .map(|name| ((*name).to_owned(), golden::capture(name)))
        .collect();
    for (stem, _, capture, _) in FIXTURES {
        captures.push(((*stem).to_owned(), capture.to_vec()));
    }
    // Tables of more than one chunk: 5,000 connections, 10,000 messages.
    captures.push(("exchanges".to_owned(), http_exchange_capture(5000)));

    let mut total = 0;
    for (name, capture) in &captures {
        let path = fixture.write(&format!("{name}.pcap"), capture);
        for table in STREAM_TABLES {
            let (columns, expected) = reference_rows(capture, table);
            for threads in [1, 4] {
                set(&connection, "threads", threads);
                for from in [
                    format!("read_{table}('{path}')"),
                    format!("read_pcap('{path}', protocol := '{table}')"),
                ] {
                    let sql = format!("SELECT * FROM {from}");
                    assert_cells(&connection, &sql, &columns, &expected);
                    // The row count alone, which reads no column.
                    assert_eq!(
                        value(&connection, &format!("SELECT count(*) FROM {from}"))?,
                        expected.len().to_string(),
                        "{from}"
                    );
                }
            }
            total += expected.len();
        }
    }
    let (_, connections) = reference_rows(&captures.last().unwrap().1, "tcp_connections");
    assert_eq!(connections.len(), 5000);
    assert!(connections.len() > 2 * CHUNK);
    assert!(total > 15_000, "{total}");
    Ok(())
}

#[test]
fn a_compressed_capture_and_a_pcapng_give_the_same_tables() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let capture = http_exchange_capture(700);
    let plain = fixture.write("plain.pcap", &capture);
    let gz = fixture.write("capture.pcap.gz", &gzip(&capture));
    let zst = fixture.write("capture.pcap.zst", &zstd(&capture));
    let pcapng = golden::pcapng(http_exchanges(700));
    let ng = fixture.write("capture.pcapng", &pcapng);
    let ng_gz = fixture.write("capture.pcapng.gz", &gzip(&pcapng));

    for table in ["tcp_connections", "http_messages"] {
        let (columns, expected) = reference_rows(&capture, table);
        assert!(expected.len() >= 700);
        for path in [&plain, &gz, &zst] {
            let sql = format!("SELECT * FROM read_{table}('{path}')");
            assert_cells(&connection, &sql, &columns, &expected);
        }
        // The pcapng has its own timestamps; everything else is the same capture.
        let (columns, expected) = reference_rows(&pcapng, table);
        for path in [&ng, &ng_gz] {
            let sql = format!("SELECT * FROM read_{table}('{path}')");
            assert_cells(&connection, &sql, &columns, &expected);
        }
    }
    Ok(())
}

#[test]
fn a_capture_is_one_partition_whatever_the_settings() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let capture = http_exchange_capture(1500);
    let path = fixture.write("exchanges.pcap", &capture);
    execute(&connection, "CALL enable_logging(level = 'debug')");
    // What splits a packet table of this capture into several partitions.
    set(&connection, "pcapsql_parallel_scan", true);
    set(&connection, "pcapsql_parallel_min_file_size", 0);
    set(&connection, "pcapsql_index_stride", 100);
    set(&connection, "threads", 8);

    logged(&connection);
    let frames = value(
        &connection,
        &format!("SELECT count(*) FROM read_tcp('{path}')"),
    )?;
    assert_eq!(frames, "10875");
    let records = logged(&connection);
    assert!(
        records
            .iter()
            .any(|record| record.contains("partitions: 8 (of 10875 frames")),
        "{records:#?}"
    );

    for table in ["tcp_connections", "http_messages"] {
        let (columns, expected) = reference_rows(&capture, table);
        let sql = format!("SELECT * FROM read_{table}('{path}')");
        assert_cells(&connection, &sql, &columns, &expected);
        let records = logged(&connection);
        let scanning: Vec<&String> = records
            .iter()
            .filter(|record| record.contains("scanning"))
            .collect();
        assert_eq!(scanning.len(), 1, "{records:#?}");
        assert!(
            scanning[0].contains(
                "partitions: 1 (a stream table is built from the whole capture, read in order)"
            ),
            "{}",
            scanning[0]
        );
        // One worker read all of it, from its first frame.
        let finished: Vec<&String> = records
            .iter()
            .filter(|record| record.contains("finished partition"))
            .collect();
        assert_eq!(finished.len(), 1, "{records:#?}");
        assert!(
            finished[0].contains("finished partition 1 of 1")
                && finished[0].contains("10875 packets from frame 1"),
            "{}",
            finished[0]
        );
    }
    Ok(())
}

#[test]
fn a_projection_reads_the_columns_asked_for_in_their_order() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let capture = golden::capture("http");
    let path = fixture.write("http.pcap", &capture);
    execute(&connection, "CALL enable_logging(level = 'debug')");

    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT server_port, client_ip, state, frame_number, is_complete \
                 FROM read_tcp_connections('{path}')"
            )
        )?,
        [
            ["80", "10.0.0.1", "time_wait", "1", "true"],
            ["443", "10.0.0.1", "reset", "9", "true"]
        ]
    );
    let records = logged(&connection);
    assert!(
        records.iter().any(|record| record
            .contains("columns: server_port, client_ip, state, frame_number, is_complete;")),
        "{records:#?}"
    );
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT status_code, method, direction FROM read_http_messages('{path}') \
                 ORDER BY frame_number DESC"
            )
        )?,
        [["200", "NULL", "to_client"], ["NULL", "GET", "to_server"]]
    );
    // A row count reads one column of DuckDB's choosing, or none.
    logged(&connection);
    assert_eq!(
        value(
            &connection,
            &format!("SELECT count(*) FROM read_tls_sessions('{path}')")
        )?,
        "1"
    );
    let records = logged(&connection);
    assert!(
        records
            .iter()
            .any(|record| record.contains("columns: frame_number;")
                || record.contains("columns: none (row count);")),
        "{records:#?}"
    );
    // A LIMIT is applied to the rows the scan returns.
    assert_eq!(
        column(
            &connection,
            &format!("SELECT client_port FROM read_tcp_connections('{path}') LIMIT 1")
        )?,
        ["40002"]
    );
    Ok(())
}

#[test]
fn filters_are_applied_by_duckdb_to_the_rows_of_a_full_scan() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let capture = http_exchange_capture(600);
    let path = fixture.write("exchanges.pcap", &capture);
    execute(&connection, "CALL enable_logging(level = 'debug')");

    let (columns, all) = reference_rows(&capture, "tcp_connections");
    let frame_number = |row: &Vec<Cell>| match row[0] {
        Cell::U64(frame) => frame,
        ref other => panic!("{other:?}"),
    };
    assert_eq!(columns[0].name, "frame_number");
    type Keep = fn(u64) -> bool;
    let filters: [(&str, Keep); 6] = [
        ("frame_number <= 100", |frame| frame <= 100),
        ("frame_number > 4000", |frame| frame > 4000),
        ("frame_number = 9", |frame| frame == 9),
        ("frame_number BETWEEN 50 AND 500", |frame| {
            (50..=500).contains(&frame)
        }),
        ("frame_number < 1", |_| false),
        ("frame_number >= 1 AND frame_number < 30", |frame| {
            frame < 30
        }),
    ];
    for pushdown in [true, false] {
        set(&connection, "pcapsql_filter_pushdown", pushdown);
        for (filter, keep) in filters {
            let expected: Vec<Vec<Cell>> = all
                .iter()
                .filter(|row| keep(frame_number(row)))
                .cloned()
                .collect();
            let sql = format!("SELECT * FROM read_tcp_connections('{path}') WHERE {filter}");
            logged(&connection);
            assert_cells(&connection, &sql, &columns, &expected);
            // The scan read every frame and was given no filter.
            let records = logged(&connection);
            assert!(
                records
                    .iter()
                    .any(|record| record.contains("4350 packets from frame 1")),
                "{filter}: {records:#?}"
            );
            assert!(
                !records.iter().any(|record| record.contains("filter")),
                "{filter}: {records:#?}"
            );
            // DuckDB kept the filter in its plan.
            let plan = rows(&connection, &format!("EXPLAIN {sql}"))?;
            assert!(
                plan.iter().any(|row| row[1].contains("frame_number")),
                "{filter}: {plan:?}"
            );
        }
    }

    // A filter on a time of the connection, and on a value.
    let sql = format!(
        "SELECT count(*) FROM read_tcp_connections('{path}') \
         WHERE start_time >= TIMESTAMP_NS '2023-11-14 22:13:20' AND state = 'established'"
    );
    assert_eq!(value(&connection, &sql)?, "150");
    assert_eq!(
        value(
            &connection,
            &format!(
                "SELECT count(*) FROM read_http_messages('{path}') \
                 WHERE frame_number < 100 AND method = 'GET'"
            )
        )?,
        "14"
    );
    Ok(())
}

#[test]
fn every_file_is_a_scan_of_its_own() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let first = http_exchange_capture(900);
    let second = golden::capture("http");
    let third = http_exchange_capture(40);
    let a = fixture.write("a-first.pcap", &first);
    let b = fixture.write("b-second.pcap.gz", &gzip(&second));
    let c = fixture.write("c-third.pcap", &third);

    for threads in [1, 4] {
        set(&connection, "threads", threads);
        for table in ["tcp_connections", "http_messages", "tls_sessions"] {
            let (columns, mut expected) = reference_rows(&first, table);
            expected.extend(reference_rows(&second, table).1);
            expected.extend(reference_rows(&third, table).1);
            for files in [
                format!("['{a}', '{b}', '{c}']"),
                format!("'{}'", fixture.path("*")),
                format!("['{}', '{c}']", fixture.path("[ab]-*")),
            ] {
                let sql = format!("SELECT * FROM read_{table}({files})");
                assert_cells(&connection, &sql, &columns, &expected);
            }
            // The list's order is the order of the rows.
            let (_, mut reversed) = reference_rows(&third, table);
            reversed.extend(reference_rows(&first, table).1);
            let sql = format!("SELECT * FROM read_{table}(['{c}', '{a}'])");
            assert_cells(&connection, &sql, &columns, &reversed);
        }

        // Connections are numbered within a file: the ids of two files overlap, and the file
        // tells them apart.
        let files = format!("['{a}', '{b}', '{c}'], filename := true");
        assert_eq!(
            rows(
                &connection,
                &format!(
                    "SELECT parse_filename(filename), count(*), count(DISTINCT connection_id), \
                            min(connection_id) \
                     FROM read_tcp_connections({files}) GROUP BY ALL ORDER BY 1"
                )
            )?,
            [
                ["a-first.pcap", "900", "900", "1"],
                ["b-second.pcap.gz", "2", "2", "1"],
                ["c-third.pcap", "40", "40", "1"]
            ]
        );
        assert_eq!(
            rows(
                &connection,
                &format!(
                    "SELECT count(*), count(DISTINCT connection_id), \
                            count(DISTINCT (filename, connection_id)) \
                     FROM read_tcp_connections({files})"
                )
            )?,
            [["942", "900", "942"]]
        );
        // A join of two stream tables over several files is on both.
        assert_eq!(
            value(
                &connection,
                &format!(
                    "SELECT count(*) FROM read_http_messages({files}) m \
                     JOIN read_tcp_connections({files}) c USING (filename, connection_id) \
                     WHERE m.frame_number BETWEEN c.first_frame AND c.last_frame"
                )
            )?,
            "1882"
        );
        // The column alone, and with the others in any order.
        assert_eq!(
            rows(
                &connection,
                &format!(
                    "SELECT parse_filename(filename), count(*) FROM read_http_messages({files}) \
                     GROUP BY ALL ORDER BY 1"
                )
            )?,
            [
                ["a-first.pcap", "1800"],
                ["b-second.pcap.gz", "2"],
                ["c-third.pcap", "80"]
            ]
        );
        assert_eq!(
            rows(
                &connection,
                &format!(
                    "SELECT parse_filename(filename), sni, connection_id \
                     FROM read_pcap({files}, protocol := 'tls_sessions')"
                )
            )?,
            [["b-second.pcap.gz", "example.test", "2"]]
        );
    }
    Ok(())
}

#[test]
fn a_truncated_capture_gives_its_complete_frames_or_fails_when_strict() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    execute(&connection, "CALL enable_logging(level = 'warning')");
    let frames = http_exchanges(700);
    let whole = to_capture(frames.clone(), LINKTYPE_ETHERNET);
    let cut = whole[..whole.len() - 7].to_vec();
    let complete = to_capture(frames[..frames.len() - 1].to_vec(), LINKTYPE_ETHERNET);
    let path = fixture.write("cut.pcap", &cut);
    let good = fixture.write("whole.pcap", &whole);

    for table in ["tcp_connections", "http_messages"] {
        let (columns, expected) = reference_rows(&complete, table);
        assert!(expected.len() >= 700);
        execute(&connection, "CALL truncate_duckdb_logs()");
        let sql = format!("SELECT * FROM read_{table}('{path}')");
        assert_cells(&connection, &sql, &columns, &expected);
        let warnings = column(
            &connection,
            "SELECT message FROM duckdb_logs WHERE type = 'pcapsql' AND log_level = 'WARNING'",
        )?;
        assert_eq!(warnings.len(), 1, "{warnings:#?}");
        assert!(
            warnings[0].contains(&format!("read_{table}: '{path}' is truncated")),
            "{}",
            warnings[0]
        );

        // strict: no row, whatever the query goes on to read. The capture is read to its end
        // before the first row, so a LIMIT does not get around it.
        for query in ["*", "count(*)"] {
            for limit in ["", " LIMIT 1"] {
                let sql =
                    format!("SELECT {query} FROM read_{table}('{path}', strict := true){limit}");
                let error = failure(&connection, &sql);
                assert!(
                    error.contains(&format!("read_{table}: '{path}' is truncated"))
                        && error.contains("without strict := true"),
                    "{sql}: {error}"
                );
            }
        }
        // Among several files the complete ones do not help.
        let error = failure(
            &connection,
            &format!("SELECT count(*) FROM read_{table}(['{good}', '{path}'], strict := true)"),
        );
        assert!(error.contains("is truncated"), "{error}");
        // A whole capture passes.
        let (columns, expected) = reference_rows(&whole, table);
        let sql = format!("SELECT * FROM read_{table}('{good}', strict := true)");
        assert_cells(&connection, &sql, &columns, &expected);
    }
    Ok(())
}

#[test]
fn files_that_cannot_be_read_fail_at_bind() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let missing = fixture.path("missing.pcap");
    let text = fixture.write("notes.txt", b"this is not a capture, whatever it is called");
    for table in STREAM_TABLES {
        let error = failure(
            &connection,
            &format!("SELECT * FROM read_{table}('{missing}')"),
        );
        assert!(error.contains("missing.pcap"), "{table}: {error}");
        let error = failure(
            &connection,
            &format!("SELECT * FROM read_{table}('{text}')"),
        );
        assert!(
            error.contains(&format!("read_{table}: '{text}' is not a capture file")),
            "{table}: {error}"
        );
        let error = failure(
            &connection,
            &format!("SELECT * FROM read_{table}('{}')", fixture.path("*.none")),
        );
        assert!(
            error.contains(&format!("read_{table}: no file matches the pattern")),
            "{table}: {error}"
        );
        let error = failure(&connection, &format!("SELECT * FROM read_{table}([])"));
        assert!(
            error.contains("the list of capture files is empty"),
            "{error}"
        );
    }
    Ok(())
}

/// TLS 1.2 as TLS 1.3, and HTTP/1.1 inside TLS as HTTP/2: every fixture of
/// `pcapsql_testgen::tls` with its key log.
#[test]
fn a_key_log_decrypts_every_tls_fixture() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    // (the file stem, the session, the table of what it carries and its rows)
    let expected = [
        (
            "tls13_http2",
            ["TLS 1.3", "TLS_AES_128_GCM_SHA256", "h2"],
            ("http2", "8"),
        ),
        (
            "tls12_http2",
            ["TLS 1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "h2"],
            ("http2", "8"),
        ),
        (
            "tls12_http1",
            [
                "TLS 1.2",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "http/1.1",
            ],
            ("http_messages", "2"),
        ),
    ];
    assert_eq!(expected.len(), FIXTURES.len());
    let mut paths = Vec::new();
    for ((stem, _, bytes, keylog), (name, session, (carried, messages))) in
        FIXTURES.iter().zip(expected)
    {
        assert_eq!(*stem, name);
        let capture = fixture.write(&format!("{stem}.pcap"), bytes);
        let keys = fixture.write(&format!("{stem}.keys"), keylog.as_bytes());
        let session_sql = |arguments: &str| {
            format!(
                "SELECT version, cipher_suite, alpn, is_decrypted \
                 FROM read_tls_sessions({arguments})"
            )
        };
        let count = |table: &str, arguments: &str| {
            value(
                &connection,
                &format!("SELECT count(*) FROM read_{table}({arguments})"),
            )
        };

        // Without the key log: the session, and nothing of what it carries.
        let without = format!("'{capture}'");
        assert_eq!(
            rows(&connection, &session_sql(&without))?,
            [[session[0], session[1], session[2], "false"]],
            "{stem}"
        );
        assert_eq!(count("http2", &without)?, "0", "{stem}");
        assert_eq!(count("http_messages", &without)?, "0", "{stem}");

        // With it: decrypted, and every stream table is what the scan layer builds with
        // the same key log.
        let with = format!("'{capture}', keylog := '{keys}'");
        assert_eq!(
            rows(&connection, &session_sql(&with))?,
            [[session[0], session[1], session[2], "true"]],
            "{stem}"
        );
        for table in STREAM_TABLES {
            let (columns, rows) = reference_rows_decrypted(bytes, table, keylog);
            for from in [
                format!("read_{table}({with})"),
                format!("read_pcap('{capture}', protocol := '{table}', keylog := '{keys}')"),
            ] {
                assert_cells(
                    &connection,
                    &format!("SELECT * FROM {from}"),
                    &columns,
                    &rows,
                );
            }
            let expected = if table == carried { messages } else { "0" };
            if table == "http2" || table == "http_messages" {
                assert_eq!(count(table, &with)?, expected, "{stem}: {table}");
            }
        }
        // Every row is of the connection and the session that carried it.
        assert_eq!(
            rows(
                &connection,
                &format!(
                    "SELECT count(*), count(c.connection_id), count(s.connection_id), \
                            any_value(c.server_port), bool_and(s.is_decrypted) \
                     FROM read_{carried}({with}) h \
                     LEFT JOIN read_tcp_connections({with}) c USING (connection_id) \
                     LEFT JOIN read_tls_sessions({with}) s USING (connection_id)"
                )
            )?,
            [[messages, messages, messages, "443", "true"]],
            "{stem}"
        );
        paths.push(capture);
    }

    // HTTP/1.1 inside TLS, as the columns of `http_messages`.
    let capture = &paths[2];
    let keys = fixture.path("tls12_http1.keys");
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT frame_number, direction, is_request, method, uri, host, status_code, \
                        content_type, content_length \
                 FROM read_http_messages('{capture}', keylog := '{keys}')"
            )
        )?,
        [
            [
                "8",
                "to_server",
                "true",
                "GET",
                "/index.html",
                "example.test",
                "NULL",
                "NULL",
                "NULL"
            ],
            [
                "10",
                "to_client",
                "false",
                "NULL",
                "NULL",
                "NULL",
                "200",
                "text/plain",
                "5"
            ]
        ]
    );

    // One key log with the secrets of every session, for a scan of every capture; and as
    // the setting.
    let all: String = FIXTURES.iter().map(|(.., keylog)| *keylog).collect();
    let all = fixture.write("all.keys", all.as_bytes());
    let files = format!("['{}']", paths.join("', '"));
    let sessions = |arguments: &str| {
        rows(
            &connection,
            &format!(
                "SELECT parse_filename(filename), version, is_decrypted \
                 FROM read_tls_sessions({files}, filename := true{arguments}) ORDER BY 1"
            ),
        )
    };
    let decrypted = |decrypted: &'static str| {
        [
            ["tls12_http1.pcap", "TLS 1.2", decrypted],
            ["tls12_http2.pcap", "TLS 1.2", decrypted],
            ["tls13_http2.pcap", "TLS 1.3", decrypted],
        ]
    };
    assert_eq!(
        sessions(&format!(", keylog := '{all}'"))?,
        decrypted("true")
    );
    assert_eq!(sessions("")?, decrypted("false"));
    set(&connection, "pcapsql_keylog", format!("'{all}'"));
    assert_eq!(sessions("")?, decrypted("true"));
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT parse_filename(filename), count(*) \
                 FROM read_http2({files}, filename := true) GROUP BY ALL ORDER BY 1"
            )
        )?,
        [["tls12_http2.pcap", "8"], ["tls13_http2.pcap", "8"]]
    );
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT parse_filename(filename), count(*) \
                 FROM read_http_messages({files}, filename := true) GROUP BY ALL ORDER BY 1"
            )
        )?,
        [["tls12_http1.pcap", "2"]]
    );
    // The key log of one session decrypts that one.
    let one = fixture.path("tls12_http2.keys");
    assert_eq!(
        sessions(&format!(", keylog := '{one}'"))?,
        [
            ["tls12_http1.pcap", "TLS 1.2", "false"],
            ["tls12_http2.pcap", "TLS 1.2", "true"],
            ["tls13_http2.pcap", "TLS 1.3", "false"],
        ]
    );
    execute(&connection, "RESET pcapsql_keylog");
    Ok(())
}

/// The fixture capture and its key log, written to files.
fn tls_fixture(fixture: &Fixture) -> (String, String) {
    (
        fixture.write("tls13_http2.pcap", TLS13_HTTP2_CAPTURE),
        fixture.write("tls13_http2.keys", TLS13_HTTP2_KEYLOG.as_bytes()),
    )
}

/// Whether the one TLS session of `from` was decrypted, and how many HTTP/2 frames there are.
fn decrypted(connection: &Connection, arguments: &str) -> (String, String) {
    let session = format!("SELECT is_decrypted FROM read_tls_sessions({arguments})");
    let frames = format!("SELECT count(*) FROM read_http2({arguments})");
    (
        value(connection, &session).unwrap_or_else(|error| panic!("{session}: {error}")),
        value(connection, &frames).unwrap_or_else(|error| panic!("{frames}: {error}")),
    )
}

const DECRYPTED: (&str, &str) = ("true", "8");
const NOT_DECRYPTED: (&str, &str) = ("false", "0");

fn pair((session, frames): &(String, String)) -> (&str, &str) {
    (session, frames)
}

#[test]
fn a_key_log_decrypts_tls_and_gives_the_http2_frames() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let (capture, keys) = tls_fixture(&fixture);

    // Without a key log: the handshake's metadata, and no HTTP/2.
    assert_eq!(
        pair(&decrypted(&connection, &format!("'{capture}'"))),
        NOT_DECRYPTED
    );
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT version, cipher_suite, sni, alpn, is_decrypted \
                 FROM read_tls_sessions('{capture}')"
            )
        )?,
        [[
            "TLS 1.3",
            "TLS_AES_128_GCM_SHA256",
            "example.test",
            "h2",
            "false"
        ]]
    );

    // With it, every stream table is what the scan layer builds with the same key log.
    for table in STREAM_TABLES {
        let (columns, expected) =
            reference_rows_decrypted(TLS13_HTTP2_CAPTURE, table, TLS13_HTTP2_KEYLOG);
        for from in [
            format!("read_{table}('{capture}', keylog := '{keys}')"),
            format!("read_pcap('{capture}', protocol := '{table}', keylog := '{keys}')"),
            format!("read_pcap('{capture}', keylog := '{keys}', protocol := '{table}')"),
        ] {
            assert_cells(
                &connection,
                &format!("SELECT * FROM {from}"),
                &columns,
                &expected,
            );
        }
    }
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT version, cipher_suite, sni, alpn, is_decrypted \
                 FROM read_tls_sessions('{capture}', keylog := '{keys}')"
            )
        )?,
        [[
            "TLS 1.3",
            "TLS_AES_128_GCM_SHA256",
            "example.test",
            "h2",
            "true"
        ]]
    );
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT frame_number, frame_type, stream_id, method, path, authority, status, \
                        data_length \
                 FROM read_http2('{capture}', keylog := '{keys}') \
                 WHERE frame_type <> 'SETTINGS'"
            )
        )?,
        [
            [
                "10",
                "HEADERS",
                "1",
                "GET",
                "/",
                "example.test",
                "NULL",
                "NULL"
            ],
            ["11", "HEADERS", "1", "NULL", "NULL", "NULL", "200", "NULL"],
            ["12", "DATA", "1", "NULL", "NULL", "NULL", "NULL", "5"],
            ["13", "GOAWAY", "0", "NULL", "NULL", "NULL", "NULL", "NULL"]
        ]
    );

    // The scan's log record says how much the key log holds, and none of it.
    execute(&connection, "CALL enable_logging(level = 'debug')");
    logged(&connection);
    let sql = format!("SELECT count(*) FROM read_http2('{capture}', keylog := '{keys}')");
    assert_eq!(value(&connection, &sql)?, "8");
    let records = logged(&connection);
    assert!(
        records
            .iter()
            .any(|record| record.contains("; key log: secrets of 1 TLS sessions")),
        "{records:#?}"
    );
    for line in TLS13_HTTP2_KEYLOG.lines() {
        for field in line.split_whitespace() {
            assert!(
                !records.iter().any(|record| record.contains(field)),
                "{field}: {records:#?}"
            );
        }
    }
    // Entries of labels pcapsql does not read are counted, and not named.
    let random = "1111111111111111111111111111111111111111111111111111111111111111";
    let ech = fixture.write(
        "other-labels.keys",
        format!("ECH_SECRET {random} 00ff\n{TLS13_HTTP2_KEYLOG}ECH_CONFIG {random} 0011\n")
            .as_bytes(),
    );
    let sql = format!("SELECT count(*) FROM read_http2('{capture}', keylog := '{ech}')");
    assert_eq!(value(&connection, &sql)?, "8");
    let records = logged(&connection);
    assert!(
        records.iter().any(|record| record
            .contains("; key log: secrets of 1 TLS sessions (2 entries of other labels skipped)")),
        "{records:#?}"
    );
    assert!(
        !records
            .iter()
            .any(|record| record.contains("ECH") || record.contains(random)),
        "{records:#?}"
    );
    assert_eq!(
        value(
            &connection,
            &format!("SELECT count(*) FROM read_http2('{capture}')")
        )?,
        "0"
    );
    assert!(
        !logged(&connection)
            .iter()
            .any(|record| record.contains("key log")),
        "a scan without a key log says nothing of one"
    );
    execute(&connection, "CALL disable_logging()");

    // Every HTTP/2 frame is of the connection and the session that carried it.
    let with_keys = format!("'{capture}', keylog := '{keys}'");
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT count(*), count(c.connection_id), count(s.connection_id), \
                        any_value(c.server_port), bool_and(s.is_decrypted) \
                 FROM read_http2({with_keys}) h \
                 LEFT JOIN read_tcp_connections({with_keys}) c USING (connection_id) \
                 LEFT JOIN read_tls_sessions({with_keys}) s USING (connection_id)"
            )
        )?,
        [["8", "8", "8", "443", "true"]]
    );

    // A compressed capture, several files (one key log for all), and the file's name.
    let gz = fixture.write("again.pcap.gz", &gzip(TLS13_HTTP2_CAPTURE));
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT parse_filename(filename), count(*), count(DISTINCT connection_id) \
                 FROM read_http2(['{capture}', '{gz}'], keylog := '{keys}', filename := true) \
                 GROUP BY ALL ORDER BY 1"
            )
        )?,
        [["again.pcap.gz", "8", "1"], ["tls13_http2.pcap", "8", "1"]]
    );
    // A capture the key log has no session of is read as without one.
    let other = fixture.write("http.pcap", &golden::capture("http"));
    assert_eq!(
        pair(&decrypted(
            &connection,
            &format!("'{other}', keylog := '{keys}'")
        )),
        NOT_DECRYPTED
    );
    Ok(())
}

#[test]
fn the_parameter_wins_over_the_setting() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let (capture, keys) = tls_fixture(&fixture);
    let garbage = fixture.write("garbage.keys", b"this is not a key log\n");
    let quoted = format!("'{capture}'");

    assert_eq!(
        value(&connection, "SELECT current_setting('pcapsql_keylog')")?,
        ""
    );
    assert_eq!(pair(&decrypted(&connection, &quoted)), NOT_DECRYPTED);

    // The setting, for a call that names no key log.
    set(&connection, "pcapsql_keylog", format!("'{keys}'"));
    assert_eq!(pair(&decrypted(&connection, &quoted)), DECRYPTED);
    // NULL is "not given".
    assert_eq!(
        pair(&decrypted(
            &connection,
            &format!("{quoted}, keylog := NULL")
        )),
        DECRYPTED
    );
    // The parameter wins: an empty one reads without a key log.
    assert_eq!(
        pair(&decrypted(&connection, &format!("{quoted}, keylog := ''"))),
        NOT_DECRYPTED
    );
    // And a file that is not a key log fails, though the setting names a good one.
    let error = failure(
        &connection,
        &format!("SELECT * FROM read_http2({quoted}, keylog := '{garbage}')"),
    );
    assert!(error.contains("is not a TLS key log"), "{error}");
    assert!(!error.contains("pcapsql_keylog"), "{error}");

    // The other way around: the setting's file is not looked at when the call names one.
    set(&connection, "pcapsql_keylog", format!("'{garbage}'"));
    assert_eq!(
        pair(&decrypted(
            &connection,
            &format!("{quoted}, keylog := '{keys}'")
        )),
        DECRYPTED
    );
    assert_eq!(
        pair(&decrypted(&connection, &format!("{quoted}, keylog := ''"))),
        NOT_DECRYPTED
    );
    // Without the parameter the setting is used, and the message says where the path is from.
    let error = failure(&connection, &format!("SELECT * FROM read_http2({quoted})"));
    assert!(
        error.contains(&format!(
            "read_http2: '{garbage}' (the setting pcapsql_keylog) is not a TLS key log"
        )),
        "{error}"
    );
    // Only a scan of a stream table reads the key log: the others are not in the way.
    assert_eq!(
        value(
            &connection,
            &format!("SELECT count(*) FROM read_tcp({quoted})")
        )?,
        "16"
    );
    assert_eq!(
        value(&connection, &format!("SELECT count(*) FROM {quoted}"))?,
        "16"
    );
    assert_eq!(
        value(
            &connection,
            &format!("SELECT count(*) FROM read_tls_packets({quoted})")
        )?,
        "10"
    );

    execute(&connection, "RESET pcapsql_keylog");
    assert_eq!(
        value(&connection, "SELECT current_setting('pcapsql_keylog')")?,
        ""
    );
    assert_eq!(pair(&decrypted(&connection, &quoted)), NOT_DECRYPTED);
    let error = connection
        .execute("SET pcapsql_keylog = NULL", Parameters::None)
        .expect_err("NULL is not a path");
    assert!(
        error.message.contains("pcapsql_keylog must not be NULL"),
        "{error}"
    );
    Ok(())
}

#[test]
fn the_setting_reaches_views_and_prepared_statements() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let (capture, keys) = tls_fixture(&fixture);
    execute(
        &connection,
        &format!("CREATE VIEW sessions AS SELECT * FROM read_tls_sessions('{capture}')"),
    );
    execute(
        &connection,
        &format!("CREATE VIEW http2 AS SELECT * FROM read_http2('{capture}')"),
    );
    let through_views = |connection: &Connection| -> Result<(String, String)> {
        Ok((
            value(connection, "SELECT is_decrypted FROM sessions")?,
            value(connection, "SELECT count(*) FROM http2")?,
        ))
    };
    assert_eq!(pair(&through_views(&connection)?), NOT_DECRYPTED);
    // A view is bound when it is queried, with the setting as it is then.
    set(&connection, "pcapsql_keylog", format!("'{keys}'"));
    assert_eq!(pair(&through_views(&connection)?), DECRYPTED);
    assert_eq!(
        rows(
            &connection,
            "SELECT h.method, s.sni FROM http2 h JOIN sessions s USING (connection_id) \
             WHERE h.method IS NOT NULL"
        )?,
        [["GET", "example.test"]]
    );
    // A prepared statement is bound when it is prepared.
    execute(&connection, "PREPARE frames AS SELECT count(*) FROM http2");
    assert_eq!(value(&connection, "EXECUTE frames")?, "8");
    execute(&connection, "SET pcapsql_keylog = ''");
    assert_eq!(pair(&through_views(&connection)?), NOT_DECRYPTED);

    // The replacement scan is what it was: a capture named as a table is its frames.
    set(&connection, "pcapsql_keylog", format!("'{keys}'"));
    assert_eq!(
        rows(
            &connection,
            &format!("SELECT count(*), max(frame_number) FROM '{capture}'")
        )?,
        [["16", "16"]]
    );
    assert_eq!(
        column(
            &connection,
            &format!("SELECT column_name FROM (DESCRIBE SELECT * FROM '{capture}') LIMIT 2")
        )?,
        ["frame_number", "timestamp"]
    );
    Ok(())
}

#[test]
fn a_key_log_that_cannot_be_read_fails_the_statement_without_its_content() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let (capture, keys) = tls_fixture(&fixture);
    let secret = "5ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2";
    assert_eq!(secret.len(), 64);
    let random = "1111111111111111111111111111111111111111111111111111111111111111";

    // A file that is not there.
    let missing = fixture.path("missing.keys");
    for table in STREAM_TABLES {
        let error = failure(
            &connection,
            &format!("SELECT * FROM read_{table}('{capture}', keylog := '{missing}')"),
        );
        assert!(
            error.contains(&format!(
                "read_{table}: cannot open the key log '{missing}'"
            )),
            "{error}"
        );
    }
    let error = failure(
        &connection,
        &format!(
            "SELECT * FROM read_pcap('{capture}', protocol := 'http2', keylog := '{missing}')"
        ),
    );
    assert!(
        error.contains(&format!("read_pcap: cannot open the key log '{missing}'")),
        "{error}"
    );

    // A directory: it opens or not, and cannot be read as a key log either way.
    let directory = fixture.path("");
    let error = failure(
        &connection,
        &format!("SELECT * FROM read_http2('{capture}', keylog := '{directory}')"),
    );
    assert!(error.contains("key log"), "{error}");

    // Files that are something else. The message has the path and the line, and nothing of
    // what the file holds.
    let cases: [(&str, Vec<u8>, &str); 7] = [
        (
            "prose.keys",
            b"# a comment\n\nthese are just some words\n".to_vec(),
            "line 3: expected 3 space-separated fields, got 5",
        ),
        (
            "label.keys",
            format!(
                "{}\nSUPER_SECRET_LABEL {random} {secret}words\n",
                TLS13_HTTP2_KEYLOG.trim_end()
            )
            .into_bytes(),
            "line 5 is not a key log entry (an unknown label, not followed by a 64-digit \
             client random and a hexadecimal value)",
        ),
        (
            "known.keys",
            format!("ECH_SECRET {random} {secret}\nCLIENT_TRAFFIC_SECRET_0 {random} 5ec2zz\n")
                .into_bytes(),
            "line 2: invalid hex character: z",
        ),
        (
            "short.keys",
            format!("CLIENT_TRAFFIC_SECRET_0 {secret}ab {secret}\n").into_bytes(),
            "line 1: expected 64 hex chars for client_random, got 66",
        ),
        (
            "master.keys",
            format!("CLIENT_RANDOM {random} {secret}\n").into_bytes(),
            "line 1: expected 96 hex chars for master_secret, got 64",
        ),
        (
            "private.pem",
            format!("-----BEGIN PRIVATE KEY-----\n{secret}\n-----END PRIVATE KEY-----\n")
                .into_bytes(),
            "line 1 is not a key log entry",
        ),
        // Not text at all: the capture itself.
        (
            "capture.keys",
            TLS13_HTTP2_CAPTURE.to_vec(),
            "stream did not contain valid UTF-8",
        ),
    ];
    for (name, bytes, expected) in cases {
        let path = fixture.write(name, &bytes);
        let error = failure(
            &connection,
            &format!("SELECT * FROM read_tls_sessions('{capture}', keylog := '{path}')"),
        );
        assert!(
            error.contains(&format!(
                "read_tls_sessions: '{path}' is not a TLS key log pcapsql can read"
            )) && error.contains(expected),
            "{name}: {error}"
        );
        // (Apart from the path, which is the caller's own text.)
        let said = error.replace(&path, "");
        for content in [secret, random, "SUPER_SECRET", "BEGIN", "words", "5ec2"] {
            assert!(!said.contains(content), "{name}: {error}");
        }
        // The same through the setting.
        set(&connection, "pcapsql_keylog", format!("'{path}'"));
        let error = failure(
            &connection,
            &format!("SELECT * FROM read_tls_sessions('{capture}')"),
        );
        assert!(
            error.contains("(the setting pcapsql_keylog) is not a TLS key log")
                && error.contains(expected),
            "{name}: {error}"
        );
        execute(&connection, "RESET pcapsql_keylog");
    }

    // A key log without an entry is one: nothing is decrypted.
    let empty = fixture.write("empty.keys", b"# nothing was logged\n\n");
    assert_eq!(
        pair(&decrypted(
            &connection,
            &format!("'{capture}', keylog := '{empty}'")
        )),
        NOT_DECRYPTED
    );
    // The good one still is, with Windows line ends and a comment too, and with a byte order
    // mark and entries of labels pcapsql does not read (NSS writes ECH_SECRET and ECH_CONFIG).
    let crlf = fixture.write(
        "crlf.keys",
        format!(
            "# from a browser\r\n{}",
            TLS13_HTTP2_KEYLOG.replace('\n', "\r\n")
        )
        .as_bytes(),
    );
    let ech = fixture.write(
        "ech.keys",
        format!(
            "\u{feff}ECH_SECRET {random} {secret}\r\n{}ECH_CONFIG {random} 0011aabb\r\n",
            TLS13_HTTP2_KEYLOG.replace('\n', "\r\n")
        )
        .as_bytes(),
    );
    for path in [&keys, &crlf, &ech] {
        assert_eq!(
            pair(&decrypted(
                &connection,
                &format!("'{capture}', keylog := '{path}'")
            )),
            DECRYPTED
        );
    }

    // The file is read when the statement is bound: one that is replaced is read anew.
    let replaced = fixture.write("replaced.keys", b"not a key log");
    let sql = format!("SELECT count(*) FROM read_http2('{capture}', keylog := '{replaced}')");
    assert!(failure(&connection, &sql).contains("is not a TLS key log"));
    fixture.write("replaced.keys", TLS13_HTTP2_KEYLOG.as_bytes());
    assert_eq!(value(&connection, &sql)?, "8");
    Ok(())
}

#[test]
fn a_packet_table_takes_no_key_log_and_read_pcap_ignores_it_for_one() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let (capture, keys) = tls_fixture(&fixture);
    let missing = fixture.path("missing.keys");

    // The functions of packet tables and views do not have the parameter.
    for function in ["read_tcp", "read_frames", "read_tls", "read_tls_packets"] {
        let error = failure(
            &connection,
            &format!("SELECT * FROM {function}('{capture}', keylog := '{keys}')"),
        );
        assert!(
            error.contains("keylog") && error.contains(function),
            "{function}: {error}"
        );
    }
    // `read_pcap` has it for the stream tables it can read. For any other table or view it is
    // not looked at: the file is not opened, so it need not exist.
    for protocol in ["frames", "tcp", "tls", "tls_packets"] {
        let plain = value(
            &connection,
            &format!("SELECT count(*) FROM read_pcap('{capture}', protocol := '{protocol}')"),
        )?;
        for path in [&keys, &missing] {
            assert_eq!(
                value(
                    &connection,
                    &format!(
                        "SELECT count(*) FROM read_pcap('{capture}', protocol := '{protocol}', \
                         keylog := '{path}')"
                    )
                )?,
                plain,
                "{protocol}"
            );
        }
    }
    assert_eq!(
        value(
            &connection,
            &format!("SELECT count(*) FROM read_pcap('{capture}', keylog := '{missing}')")
        )?,
        "16"
    );
    // The `tls` table of the frames is not decrypted by a key log: it is the handshake.
    assert_eq!(
        value(
            &connection,
            &format!(
                "SELECT count(*) FROM read_pcap('{capture}', protocol := 'tls', \
                 keylog := '{keys}')"
            )
        )?,
        value(
            &connection,
            &format!("SELECT count(*) FROM read_tls('{capture}')")
        )?
    );
    // A key log must be a constant path.
    let error = failure(
        &connection,
        &format!("SELECT * FROM read_http2('{capture}', keylog := 42)"),
    );
    assert!(!error.is_empty());
    Ok(())
}
