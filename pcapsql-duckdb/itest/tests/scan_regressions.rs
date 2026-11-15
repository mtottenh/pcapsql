//! Regression tests for the three defects the audit of the previous extension inferred, and for
//! errors in the middle of a capture.
//!
//! 1. **NULL `answer_ip6s`.** The AAAA answers of a DNS response were lost: the list column was
//!    NULL. They must be in `answer_ip6s`, as 16-byte values.
//! 2. **Over-capacity chunk.** A frame with several rows in one table (a tunnelled packet) that
//!    met the end of an output chunk either overfilled the chunk or lost or repeated rows. Every
//!    row must come back exactly once, whatever the position of the frame in the chunk.
//! 3. **Silent truncation.** A capture cut off inside a record, and any read error, ended the
//!    scan as if the capture were complete. A truncated capture must say so (a warning in
//!    DuckDB's log; an error with `strict := true`), and a damaged capture must fail the query.

use std::io::Write;

use duckdb_neo::{connection::Connection, Parameters, Result};
use pcapsql_core::scan::{testing::Cell, ColKind};
use pcapsql_duckdb_itest::{
    column, connect, golden, reference_rows, replay::query_cells, rows, value, Fixture,
};

const CHUNK: usize = 2048;

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

/// Assert that `SELECT * FROM <from>` returns exactly the rows of `table` in `capture`, in
/// order, and return how many there are.
fn assert_table(connection: &Connection, from: &str, capture: &[u8], table: &str) -> usize {
    let (columns, expected) = reference_rows(capture, table);
    let kinds: Vec<ColKind> = columns.iter().map(|column| column.kind).collect();
    let sql = format!("SELECT * FROM {from}");
    let actual =
        query_cells(connection, &sql, &kinds).unwrap_or_else(|error| panic!("{sql}: {error}"));
    assert!(
        actual == expected,
        "{sql}: {} rows, expected {}, or rows that differ",
        actual.len(),
        expected.len()
    );
    expected.len()
}

// ---------------------------------------------------------------------------------------------
// 1. DNS AAAA answers
// ---------------------------------------------------------------------------------------------

#[test]
fn dns_aaaa_answers_are_in_answer_ip6s() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let capture = golden::legacy(vec![
        golden::dns_query_frame(),
        golden::dns_aaaa_frame(),
        golden::udp_frame(3),
    ]);
    let path = fixture.write("aaaa.pcap", &capture);

    // The cells as DuckDB holds them.
    let cells = query_cells(
        &connection,
        &format!("SELECT frame_number, answer_count, answer_ip6s, answer_ip4s, answer_ttls FROM read_dns('{path}')"),
        &[ColKind::U64, ColKind::U16, ColKind::ListFixed(16), ColKind::ListU32, ColKind::ListU32],
    )?;
    let aaaa: Vec<Cell> = golden::AAAA_ANSWERS
        .iter()
        .map(|address| Cell::Bytes(address.to_vec()))
        .collect();
    assert_eq!(
        cells,
        [
            // The query: no answers, which is an empty list, not NULL.
            vec![
                Cell::U64(1),
                Cell::U16(0),
                Cell::List(vec![]),
                Cell::List(vec![]),
                Cell::List(vec![])
            ],
            vec![
                Cell::U64(2),
                Cell::U16(3),
                Cell::List(aaaa),
                Cell::List(vec![Cell::U32(u32::from_be_bytes(golden::A_ANSWER))]),
                Cell::List(vec![Cell::U32(60), Cell::U32(61), Cell::U32(62)]),
            ],
        ]
    );

    // The same through SQL, the way a user would look at it.
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT answer_ip6s IS NULL, len(answer_ip6s), typeof(answer_ip6s),
                        array_to_string(list_transform(answer_ip6s, lambda a: ip6_to_string(a)), ' '),
                        format_ip4_list(answer_ip4s)::VARCHAR
                 FROM read_dns('{path}') WHERE answer_count > 0"
            )
        )?,
        [[
            "false",
            "2",
            "BLOB[]",
            "2001:db8::1 2606:2800:220:1:248:1893:25c8:1946",
            "[93.184.216.34]"
        ]]
    );
    // And when the list is the only column the query reads.
    assert_eq!(
        column(
            &connection,
            &format!("SELECT len(answer_ip6s) FROM read_dns('{path}') ORDER BY frame_number")
        )?,
        ["0", "2"]
    );
    assert_eq!(
        value(&connection, &format!("SELECT count(*) FROM read_pcap('{path}', protocol := 'dns') WHERE answer_ip6s IS NULL"))?,
        "0"
    );
    assert_table(&connection, &format!("read_dns('{path}')"), &capture, "dns");

    // Many of them, across chunks: the list's child vector grows and no list is lost.
    let many = golden::legacy((0..5000).map(|_| golden::dns_aaaa_frame()).collect());
    let path = fixture.write("many-aaaa.pcap", &many);
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT count(*), count(answer_ip6s), sum(len(answer_ip6s)), sum(len(answer_ip4s)),
                        count(DISTINCT answer_ip6s), bool_and(ip6_to_string(answer_ip6s[2]) = '2606:2800:220:1:248:1893:25c8:1946')
                 FROM read_dns('{path}')"
            )
        )?,
        [["5000", "5000", "10000", "5000", "1", "true"]]
    );
    assert_table(&connection, &format!("read_dns('{path}')"), &many, "dns");
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// 2. Frames with several rows across chunk boundaries
// ---------------------------------------------------------------------------------------------

/// Frames that have 3, 2, 1, 3, 2, 1, ... rows in `ethernet`, `ipv4` and `udp`, after `lead`
/// frames of one row each, which shift where the chunk boundaries fall.
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
fn frames_with_several_rows_return_every_row_once_across_chunk_boundaries() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();

    // With no lead, row 2,048 is the second of the three rows of a frame; each lead frame moves
    // the boundary by one row, so that it falls before, inside (at either place) and after a
    // frame with three rows, and inside a frame with two.
    for lead in 0..6 {
        const FRAMES: u32 = 6000;
        let capture = golden::legacy(tunnel_frames(lead, FRAMES));
        let path = fixture.write(&format!("tunnels-{lead}.pcap"), &capture);
        let expected_rows = (lead + FRAMES * 2) as usize;
        assert!(expected_rows > 5 * CHUNK);

        for table in ["ethernet", "ipv4", "udp"] {
            let from = format!("read_{table}('{path}')");
            // Every cell of every row, in capture order.
            assert_eq!(
                assert_table(&connection, &from, &capture, table),
                expected_rows,
                "{from}"
            );
            // Each (frame, depth) exactly once, and each frame with all its levels.
            assert_eq!(
                rows(
                    &connection,
                    &format!(
                        "SELECT count(*), count(DISTINCT (frame_number, encap_depth)), count(DISTINCT frame_number),
                                count(*) FILTER (encap_depth = 0), count(*) FILTER (encap_depth = 1), count(*) FILTER (encap_depth = 2)
                         FROM {from}"
                    )
                )?,
                [[
                    expected_rows.to_string(),
                    expected_rows.to_string(),
                    (lead + FRAMES).to_string(),
                    (lead + FRAMES).to_string(),
                    (FRAMES * 2 / 3).to_string(),
                    (FRAMES / 3).to_string(),
                ]],
                "{from}"
            );
            assert_eq!(
                value(
                    &connection,
                    &format!(
                        "SELECT count(*) FROM (
                             SELECT frame_number, count(*) AS levels, max(encap_depth) AS deepest,
                                    CASE WHEN frame_number <= {lead} THEN 1
                                         ELSE 3 - (frame_number - 1 - {lead}) % 3 END AS expected
                             FROM {from} GROUP BY frame_number)
                         WHERE levels <> expected OR deepest <> levels - 1"
                    )
                )?,
                "0",
                "{from}"
            );
            // The rows of a frame are adjacent and ordered by depth, without ORDER BY.
            let order = rows(
                &connection,
                &format!("SELECT frame_number, encap_depth FROM {from}"),
            )?;
            let key = |row: &Vec<String>| {
                (
                    row[0].parse::<u64>().unwrap(),
                    row[1].parse::<u8>().unwrap(),
                )
            };
            assert!(
                order.windows(2).all(|pair| key(&pair[0]) < key(&pair[1])),
                "{from}: order"
            );
        }
        // A table where the same frames have 2, 1 and 0 rows.
        assert_eq!(
            assert_table(
                &connection,
                &format!("read_vxlan('{path}')"),
                &capture,
                "vxlan"
            ),
            FRAMES as usize
        );
    }
    Ok(())
}

#[test]
fn a_frame_with_several_rows_is_whole_after_a_limit_or_a_filter() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let capture = golden::legacy(tunnel_frames(0, 6000));
    let path = fixture.write("tunnels.pcap", &capture);
    let (_, expected) = reference_rows(&capture, "ethernet");

    // A LIMIT that ends inside a frame, at and around the chunk size.
    for limit in [
        1,
        2,
        3,
        CHUNK - 1,
        CHUNK,
        CHUNK + 1,
        2 * CHUNK,
        2 * CHUNK + 2,
    ] {
        let actual = rows(
            &connection,
            &format!("SELECT frame_number, encap_depth FROM read_ethernet('{path}') LIMIT {limit}"),
        )?;
        let expected: Vec<Vec<String>> = expected[..limit]
            .iter()
            .map(|row| {
                let (Cell::U64(frame), Some(Cell::U8(depth))) = (&row[0], row.iter().rev().nth(2))
                else {
                    panic!("unexpected row {row:?}");
                };
                vec![frame.to_string(), depth.to_string()]
            })
            .collect();
        assert!(actual == expected, "LIMIT {limit}");
    }

    // The innermost level of every frame that has three: one row each.
    assert_eq!(
        rows(&connection, &format!("SELECT count(*), count(DISTINCT frame_number), min(tunnel_type), max(tunnel_id) FROM read_ethernet('{path}') WHERE encap_depth = 2"))?,
        // The innermost VNI is the frame's index, at most 5,997.
        [["2000", "2000", "vxlan", "5997"]]
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// 3. Truncation and errors in the middle of a capture
// ---------------------------------------------------------------------------------------------

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

#[test]
fn a_truncated_capture_is_reported_and_is_an_error_when_strict() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    connection.execute("CALL enable_logging(level = 'warning')", Parameters::None)?;

    const FRAMES: u32 = 5000;
    let frames: Vec<Vec<u8>> = (0..FRAMES).map(golden::udp_frame).collect();
    let record = 16 + frames[0].len();
    let legacy = golden::legacy(frames.clone());
    let pcapng = golden::pcapng(frames.clone());

    // (file, bytes, complete frames): cut inside the packet data of the last record, inside
    // its header, in the middle of the capture, and a pcapng capture cut inside a block.
    let cut = |bytes: &[u8], by: usize| bytes[..bytes.len() - by].to_vec();
    let cases: Vec<(&str, Vec<u8>, u32)> = vec![
        ("data.pcap", cut(&legacy, 5), FRAMES - 1),
        ("header.pcap", cut(&legacy, record - 7), FRAMES - 1),
        ("one-byte.pcap", cut(&legacy, record - 1), FRAMES - 1),
        (
            "middle.pcap",
            cut(&legacy, 1000 * record + 20),
            FRAMES - 1001,
        ),
        ("first.pcap", legacy[..24 + 30].to_vec(), 0),
        ("block.pcapng", cut(&pcapng, 9), FRAMES - 1),
        ("data.pcap.gz", gzip(&cut(&legacy, 5)), FRAMES - 1),
        ("block.pcapng.gz", gzip(&cut(&pcapng, 9)), FRAMES - 1),
    ];
    for (file, bytes, complete) in cases {
        let path = fixture.write(file, &bytes);
        // What the complete frames hold: the capture without its broken tail.
        let whole: Vec<Vec<u8>> = frames[..complete as usize].to_vec();
        let prefix = if file.contains("pcapng") {
            golden::pcapng(whole)
        } else {
            golden::legacy(whole)
        };

        for table in ["frames", "udp"] {
            // By default: the complete frames, every one of them, and a warning in the log.
            let from = format!("read_{table}('{path}')");
            warnings(&connection);
            assert_eq!(
                assert_table(&connection, &from, &prefix, table),
                complete as usize,
                "{from}"
            );
            let logged = warnings(&connection);
            assert_eq!(logged.len(), 1, "{from}: {logged:?}");
            for text in [
                format!("read_{table}: "),
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

            // strict: an error that names the file and the last complete frame; no rows.
            for sql in [
                format!("SELECT * FROM read_{table}('{path}', strict := true)"),
                format!("SELECT count(*) FROM read_{table}('{path}', strict := true)"),
                format!("SELECT count(*) FROM read_pcap('{path}', protocol := '{table}', strict := true)"),
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
            // strict := false is the default, spelled out.
            assert_eq!(
                value(
                    &connection,
                    &format!("SELECT count(*) FROM read_{table}('{path}', strict := false)")
                )?,
                complete.to_string()
            );
            warnings(&connection);
        }
    }

    // A complete capture is neither: no warning, and strict changes nothing.
    for (file, bytes) in [
        ("whole.pcap", &legacy),
        ("whole.pcapng", &pcapng),
        ("whole.pcap.gz", &gzip(&legacy)),
    ] {
        let path = fixture.write(file, bytes);
        for strict in ["", ", strict := true", ", strict := false"] {
            assert_eq!(
                value(
                    &connection,
                    &format!("SELECT count(*) FROM read_udp('{path}'{strict})")
                )?,
                FRAMES.to_string()
            );
        }
        assert!(warnings(&connection).is_empty(), "{file}");
    }
    Ok(())
}

#[test]
fn a_limit_that_stops_before_the_end_does_not_report_the_truncation() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    let legacy = golden::legacy((0..10_000).map(golden::udp_frame).collect());
    let path = fixture.write("cut.pcap", &legacy[..legacy.len() - 5]);
    // The scan is not run to the end of the capture, so the broken tail is never reached.
    assert_eq!(
        column(
            &connection,
            &format!("SELECT frame_number FROM read_frames('{path}', strict := true) LIMIT 2")
        )?,
        ["1", "2"]
    );
    // Run to the end, it is.
    let error = rows(
        &connection,
        &format!("SELECT frame_number FROM read_frames('{path}', strict := true)"),
    )
    .unwrap_err();
    assert!(error.message.contains("is truncated"), "{error}");
    Ok(())
}

/// The offset of every block of a little-endian pcapng capture.
fn pcapng_blocks(bytes: &[u8]) -> Vec<usize> {
    let mut blocks = Vec::new();
    let mut at = 0;
    while at + 8 <= bytes.len() {
        blocks.push(at);
        let length = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        assert!(
            length >= 12 && length % 4 == 0,
            "block at {at} has length {length}"
        );
        at += length;
    }
    assert_eq!(at, bytes.len());
    blocks
}

#[test]
fn a_damaged_capture_fails_the_query_instead_of_ending_it() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    connection.execute("CALL enable_logging(level = 'warning')", Parameters::None)?;

    const FRAMES: u32 = 6000;
    let frames: Vec<Vec<u8>> = (0..FRAMES).map(golden::udp_frame).collect();
    let record = 16 + frames[0].len();
    let legacy = golden::legacy(frames.clone());
    let pcapng = golden::pcapng(frames);

    // A record in the middle of a legacy capture that declares 4 GiB of packet data.
    let mut absurd = legacy.clone();
    let at = 24 + 3000 * record + 8;
    absurd[at..at + 4].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
    // A pcapng block in the middle whose length is not a block length.
    let mut block = pcapng.clone();
    let blocks = pcapng_blocks(&block);
    let at = blocks[blocks.len() / 2];
    assert_eq!(
        block[at..at + 4],
        6u32.to_le_bytes(),
        "an Enhanced Packet Block"
    );
    block[at + 4..at + 8].copy_from_slice(&7u32.to_le_bytes());
    // A gzip stream with bytes changed in the middle, and one cut off in the middle.
    let compressed = gzip(&legacy);
    let mut corrupt = compressed.clone();
    let middle = corrupt.len() / 2;
    for byte in &mut corrupt[middle..middle + 64] {
        *byte ^= 0x5a;
    }
    let cut_stream = compressed[..compressed.len() / 2].to_vec();
    // A zstd frame carries a checksum of its content only when asked to; without one, changed
    // bytes inflate to a different capture, not to an error.
    let mut corrupt_zstd = {
        let mut encoder = zstd::Encoder::new(Vec::new(), 3).unwrap();
        encoder.include_checksum(true).unwrap();
        encoder.write_all(&legacy).unwrap();
        encoder.finish().unwrap()
    };
    let middle = corrupt_zstd.len() / 2;
    for byte in &mut corrupt_zstd[middle..middle + 64] {
        *byte ^= 0x5a;
    }

    // The absurd record cannot be told from a capture that was cut off: the record declares
    // more bytes than the file has left. It is reported as a truncation, not passed over.
    let path = fixture.write("absurd.pcap", &absurd);
    warnings(&connection);
    assert_eq!(
        value(
            &connection,
            &format!("SELECT count(*) FROM read_frames('{path}')")
        )?,
        "3000"
    );
    let logged = warnings(&connection);
    assert_eq!(logged.len(), 1, "{logged:?}");
    assert!(
        logged[0].contains("is truncated") && logged[0].contains("frame 3000,"),
        "{}",
        logged[0]
    );
    let error = rows(
        &connection,
        &format!("SELECT count(*) FROM read_frames('{path}', strict := true)"),
    )
    .unwrap_err();
    assert!(error.message.contains("is truncated"), "{error}");

    for (file, bytes) in [
        ("block.pcapng", block),
        ("corrupt.pcap.gz", corrupt),
        ("cut-stream.pcap.gz", cut_stream),
        ("corrupt.pcap.zst", corrupt_zstd),
    ] {
        let path = fixture.write(file, &bytes);
        // With or without strict: this is not a capture that merely stops early.
        for sql in [
            format!("SELECT count(*) FROM read_frames('{path}')"),
            format!("SELECT * FROM read_udp('{path}')"),
            format!("SELECT count(*) FROM read_udp('{path}', strict := true)"),
            format!("CREATE OR REPLACE TABLE damaged AS SELECT * FROM read_frames('{path}')"),
        ] {
            let error = rows(&connection, &sql).expect_err(&format!("{file}: {sql}"));
            assert!(error.message.contains(file), "{sql}: {error}");
            assert!(error.message.contains("cannot read"), "{sql}: {error}");
            assert!(!error.message.contains("INTERNAL"), "{sql}: {error}");
            assert!(!error.message.contains("panic"), "{sql}: {error}");
        }
        // The frames before the damage can still be asked for.
        assert_eq!(
            column(
                &connection,
                &format!("SELECT frame_number FROM read_frames('{path}') LIMIT 3")
            )?,
            ["1", "2", "3"],
            "{file}"
        );
    }
    // Nothing was stored by the statements that failed, and the connection is fine.
    assert!(rows(&connection, "SELECT * FROM damaged").is_err());
    assert_eq!(
        value(&connection, "SELECT count(*) FROM pcap_protocols()")?,
        "28"
    );
    Ok(())
}
