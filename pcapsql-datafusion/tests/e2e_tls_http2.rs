//! End-to-end tests for the TLS tables and what a key log decrypts.
//!
//! These tests verify the full pipeline from PCAP → Protocol Parsing →
//! DataFusion → SQL Results, on the generated captures of
//! `pcapsql_testgen::tls` kept in `pcapsql-testgen/fixtures/`, each with
//! its key log: HTTP/2 over TLS 1.3, HTTP/2 over TLS 1.2 and HTTP/1.1 over
//! TLS 1.2. `pcapsql-core/tests/tls_fixtures.rs` holds the captures against
//! their description and covers the other cipher suites; here it is what
//! SQL sees.

use std::sync::Arc;

use arrow::array::{Array, Int64Array, StringArray};
use arrow::record_batch::RecordBatch;
use arrow::util::display::array_value_to_string;

use pcapsql_core::KeyLog;
use pcapsql_datafusion::query::{EngineOptions, QueryEngine, SourceSpec};
use pcapsql_testgen::tls::FIXTURES;

// ============================================================================
// Test Helpers
// ============================================================================

/// An engine over the fixture `stem`, with or without its key log.
async fn fixture_engine(stem: &str, keylog: bool) -> QueryEngine {
    let (_, _, _, keys) = FIXTURES
        .iter()
        .find(|(name, ..)| *name == stem)
        .unwrap_or_else(|| panic!("no fixture {stem}"));
    let capture = format!(
        "{}/../pcapsql-testgen/fixtures/{stem}.pcap",
        env!("CARGO_MANIFEST_DIR")
    );
    open(&capture, keylog.then(|| KeyLog::parse(keys).unwrap())).await
}

async fn open(capture: &str, keylog: Option<KeyLog>) -> QueryEngine {
    QueryEngine::open(
        SourceSpec::Path(capture.into()),
        EngineOptions {
            keylog: keylog.map(Arc::new),
            ..Default::default()
        },
    )
    .await
    .expect("the capture opens")
}

/// Run a SQL query and return results
async fn query(engine: &QueryEngine, sql: &str) -> Vec<RecordBatch> {
    engine.query(sql).await.expect("Query should succeed")
}

/// Get scalar i64 from single-row result
fn get_i64(results: &[RecordBatch], col: usize) -> i64 {
    let batch = &results[0];
    let array = batch
        .column(col)
        .as_any()
        .downcast_ref::<Int64Array>()
        .expect("Expected Int64Array");
    array.value(0)
}

/// The single count a query returns.
async fn count(engine: &QueryEngine, sql: &str) -> i64 {
    get_i64(&query(engine, sql).await, 0)
}

/// Get scalar string from single-row result
fn get_string(results: &[RecordBatch], row: usize, col: usize) -> Option<String> {
    if results.is_empty() || results[0].num_rows() <= row {
        return None;
    }
    let batch = &results[0];
    let array = batch
        .column(col)
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("Expected StringArray");
    if array.is_null(row) {
        None
    } else {
        Some(array.value(row).to_string())
    }
}

/// Every row of a query, each a list of its values as text (`NULL` for
/// null).
async fn rows(engine: &QueryEngine, sql: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    for batch in query(engine, sql).await {
        for row in 0..batch.num_rows() {
            rows.push(
                batch
                    .columns()
                    .iter()
                    .map(|column| {
                        if column.is_null(row) {
                            "NULL".to_owned()
                        } else {
                            array_value_to_string(column, row).unwrap()
                        }
                    })
                    .collect(),
            );
        }
    }
    rows
}

// ============================================================================
// The `tls` table: one row per packet that starts with a TLS record
// ============================================================================

/// The records of the TLS 1.2 capture, encrypted ones included: a record
/// whose content is encrypted is a row with its header and no handshake or
/// alert field, and an application-data record says how long it is.
#[tokio::test]
async fn test_tls_table_has_a_row_for_encrypted_records() {
    let engine = fixture_engine("tls12_http2", false).await;
    let rows = rows(
        &engine,
        "SELECT frame_number, record_type, version, handshake_type, is_change_cipher_spec,
                has_app_data, app_data_length, alert_level
         FROM tls ORDER BY frame_number",
    )
    .await;
    let expected = [
        // ClientHello; the ServerHello that starts the server's flight; the
        // ClientKeyExchange that starts the client's.
        ["4", "22", "TLS 1.0", "1", "NULL", "NULL", "NULL", "NULL"],
        ["5", "22", "TLS 1.2", "2", "NULL", "NULL", "NULL", "NULL"],
        ["6", "22", "TLS 1.2", "16", "NULL", "NULL", "NULL", "NULL"],
        // The server's ChangeCipherSpec (its encrypted Finished follows in
        // the same segment).
        ["7", "20", "TLS 1.2", "NULL", "true", "NULL", "NULL", "NULL"],
        // Application data: the lengths are the records', with the 8 bytes
        // of explicit nonce and the 16 of the tag.
        ["8", "23", "TLS 1.2", "NULL", "NULL", "true", "57", "NULL"],
        ["9", "23", "TLS 1.2", "NULL", "NULL", "true", "33", "NULL"],
        ["10", "23", "TLS 1.2", "NULL", "NULL", "true", "79", "NULL"],
        // The first half of the response's segment: a record that is not
        // complete in its packet has the header fields only. The second
        // half (frame 12) starts inside that record and is not a row.
        [
            "11", "23", "TLS 1.2", "NULL", "NULL", "NULL", "NULL", "NULL",
        ],
        ["13", "23", "TLS 1.2", "NULL", "NULL", "true", "41", "NULL"],
        // The client's close_notify, encrypted: no alert fields.
        [
            "14", "21", "TLS 1.2", "NULL", "NULL", "NULL", "NULL", "NULL",
        ],
    ];
    assert_eq!(rows, expected);
}

/// The TLS 1.3 capture: every record after the hellos is application data
/// on the wire.
#[tokio::test]
async fn test_tls13_table_rows() {
    let engine = fixture_engine("tls13_http2", false).await;
    let rows = rows(
        &engine,
        "SELECT record_type, count(*), min(frame_number), max(frame_number),
                count(app_data_length), count(handshake_type)
         FROM tls GROUP BY record_type ORDER BY record_type",
    )
    .await;
    assert_eq!(
        rows,
        [
            ["22", "2", "4", "5", "0", "2"],
            ["23", "8", "6", "13", "8", "0"]
        ]
    );
}

/// Test TLS 1.2 handshake metadata extraction
#[tokio::test]
async fn test_tls12_handshake_metadata() {
    let engine = fixture_engine("tls12_http2", false).await;
    let rows = rows(
        &engine,
        "SELECT frame_number, sni, alpn, cipher_suite_count FROM tls WHERE handshake_type = 1",
    )
    .await;
    assert_eq!(rows, [["4", "example.test", "h2", "3"]]);
    let rows = self::rows(
        &engine,
        "SELECT frame_number, selected_cipher, selected_cipher_id, alpn
         FROM tls WHERE handshake_type = 2",
    )
    .await;
    assert_eq!(
        rows,
        [["5", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "49199", "h2"]]
    );
}

/// Test JA3 and JA3S fingerprint extraction
#[tokio::test]
async fn test_tls12_ja3_fingerprints() {
    let engine = fixture_engine("tls12_http2", false).await;
    let results = query(
        &engine,
        "SELECT ja3, ja3_hash FROM tls WHERE handshake_type = 1",
    )
    .await;
    // Version 1.2, the three suites offered, SNI and ALPN.
    assert_eq!(
        get_string(&results, 0, 0).as_deref(),
        Some("771,4865-4866-49199,0-16,,")
    );
    assert_eq!(get_string(&results, 0, 1).map(|hash| hash.len()), Some(32));
    let results = query(
        &engine,
        "SELECT ja3s, ja3s_hash FROM tls WHERE handshake_type = 2",
    )
    .await;
    assert_eq!(get_string(&results, 0, 0).as_deref(), Some("771,49199,16"));
    assert_eq!(get_string(&results, 0, 1).map(|hash| hash.len()), Some(32));
}

/// Test TLS table JOIN with the TCP and frames tables: every row of `tls`
/// is a frame and a segment to or from port 443.
#[tokio::test]
async fn test_tls_joins_tcp_and_frames() {
    for (stem, ..) in FIXTURES {
        let engine = fixture_engine(stem, false).await;
        let records = count(&engine, "SELECT count(*) FROM tls").await;
        assert!(records > 0, "{stem}");
        let joined = count(
            &engine,
            "SELECT count(*) FROM tls t
             JOIN tcp ON t.frame_number = tcp.frame_number
             JOIN frames f ON t.frame_number = f.frame_number
             WHERE (tcp.src_port = 443 OR tcp.dst_port = 443) AND f.length > 0",
        )
        .await;
        assert_eq!(joined, records, "{stem}");
        let results = query(&engine, "SELECT * FROM tls LIMIT 2").await;
        let limited: usize = results.iter().map(|b| b.num_rows()).sum();
        assert_eq!(limited, 2, "{stem}");
    }
}

// ============================================================================
// Decryption with a key log (`EngineOptions::keylog`, the CLI's `--keylog`)
// ============================================================================

/// With its key log a session is decrypted, whatever the version; without
/// it, it is the same session, not decrypted.
#[tokio::test]
async fn test_keylog_decrypts_the_session() {
    let expected = [
        ("tls13_http2", "TLS 1.3", "TLS_AES_128_GCM_SHA256", "h2"),
        (
            "tls12_http2",
            "TLS 1.2",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "h2",
        ),
        (
            "tls12_http1",
            "TLS 1.2",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "http/1.1",
        ),
    ];
    assert_eq!(expected.len(), FIXTURES.len());
    let sql = "SELECT version, cipher_suite, sni, alpn, is_decrypted FROM tls_sessions";
    for (stem, version, cipher_suite, alpn) in expected {
        for keylog in [true, false] {
            let engine = fixture_engine(stem, keylog).await;
            let decrypted = if keylog { "true" } else { "false" };
            assert_eq!(
                rows(&engine, sql).await,
                [[version, cipher_suite, "example.test", alpn, decrypted]],
                "{stem}, key log: {keylog}"
            );
        }
    }
}

/// With the key log `http2` has the frames of the exchange, for TLS 1.2 as
/// for TLS 1.3; without it `http2` is empty.
#[tokio::test]
async fn test_keylog_gives_http2_rows() {
    for stem in ["tls13_http2", "tls12_http2"] {
        let engine = fixture_engine(stem, true).await;
        let frames = rows(
            &engine,
            "SELECT frame_type, stream_id, method, path, authority, status, data_length
             FROM http2",
        )
        .await;
        let null = "NULL";
        let expected = [
            ["SETTINGS", "0", null, null, null, null, null],
            ["SETTINGS", "0", null, null, null, null, null],
            ["SETTINGS", "0", null, null, null, null, null],
            ["HEADERS", "1", "GET", "/", "example.test", null, null],
            ["SETTINGS", "0", null, null, null, null, null],
            ["HEADERS", "1", null, null, null, "200", null],
            ["DATA", "1", null, null, null, null, "5"],
            ["GOAWAY", "0", null, null, null, null, null],
        ];
        assert_eq!(frames, expected, "{stem}");
        assert_eq!(
            count(&engine, "SELECT count(*) FROM http_messages").await,
            0,
            "{stem}"
        );

        let engine = fixture_engine(stem, false).await;
        assert_eq!(
            count(&engine, "SELECT count(*) FROM http2").await,
            0,
            "{stem}"
        );
    }
}

/// With the key log, HTTP/1.1 inside TLS is in `http_messages`, as HTTP/1.1
/// in the clear is; without it there is none.
#[tokio::test]
async fn test_keylog_gives_http_messages_rows() {
    let engine = fixture_engine("tls12_http1", true).await;
    let messages = rows(
        &engine,
        "SELECT frame_number, direction, is_request, method, uri, host, status_code,
                content_type, content_length
         FROM http_messages ORDER BY frame_number",
    )
    .await;
    let null = "NULL";
    let expected = [
        [
            "8",
            "to_server",
            "true",
            "GET",
            "/index.html",
            "example.test",
            null,
            null,
            null,
        ],
        [
            "10",
            "to_client",
            "false",
            null,
            null,
            null,
            "200",
            "text/plain",
            "5",
        ],
    ];
    assert_eq!(messages, expected);
    assert_eq!(count(&engine, "SELECT count(*) FROM http2").await, 0);

    let engine = fixture_engine("tls12_http1", false).await;
    assert_eq!(
        count(&engine, "SELECT count(*) FROM http_messages").await,
        0
    );
}

/// `connection_id` is `tcp_connections.connection_id` in every decrypted
/// row: the join matches each of them, and the connection is the TLS
/// session's.
#[tokio::test]
async fn test_decrypted_rows_join_tcp_connections_on_connection_id() {
    for (stem, table, expected) in [
        ("tls13_http2", "http2", 8),
        ("tls12_http2", "http2", 8),
        ("tls12_http1", "http_messages", 2),
    ] {
        let engine = fixture_engine(stem, true).await;
        let all = count(&engine, &format!("SELECT count(*) FROM {table}")).await;
        assert_eq!(all, expected, "{stem}");
        let joined = count(
            &engine,
            &format!(
                "SELECT count(*) FROM {table}
                 JOIN tcp_connections c USING (connection_id)
                 JOIN tls_sessions s USING (connection_id)
                 WHERE c.server_port = 443 AND s.is_decrypted"
            ),
        )
        .await;
        assert_eq!(joined, all, "{stem}");
    }
}

/// A key log with the secrets of other sessions too, as the file
/// SSLKEYLOGFILE names usually is.
#[tokio::test]
async fn test_one_keylog_for_every_capture() {
    let keys: String = FIXTURES.iter().map(|(.., keys)| *keys).collect();
    let keylog = KeyLog::parse(&keys).unwrap();
    assert_eq!(keylog.session_count(), FIXTURES.len());
    for (stem, ..) in FIXTURES {
        let capture = format!(
            "{}/../pcapsql-testgen/fixtures/{stem}.pcap",
            env!("CARGO_MANIFEST_DIR")
        );
        let engine = open(&capture, Some(keylog.clone())).await;
        assert_eq!(
            count(
                &engine,
                "SELECT count(*) FROM tls_sessions WHERE is_decrypted"
            )
            .await,
            1,
            "{stem}"
        );
    }
}

// ============================================================================
// A capture without a link layer
// ============================================================================

/// `tls12-dsb.pcapng` is raw IPv4 (`LINKTYPE_IPV4`): its frames are
/// datagrams, and its two connections are connections.
#[tokio::test]
async fn test_raw_ipv4_capture_has_connections() {
    let capture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fuzz/corpus/fuzz_pcap_reader/tls12-dsb.pcapng"
    );
    let engine = open(capture, None).await;
    assert_eq!(count(&engine, "SELECT count(*) FROM frames").await, 17);
    assert_eq!(count(&engine, "SELECT count(*) FROM ipv4").await, 17);
    assert_eq!(count(&engine, "SELECT count(*) FROM tcp").await, 17);
    assert_eq!(count(&engine, "SELECT count(*) FROM ethernet").await, 0);
    assert_eq!(
        rows(
            &engine,
            "SELECT connection_id, server_port, packets_to_server, packets_to_client
             FROM tcp_connections ORDER BY connection_id"
        )
        .await,
        [["1", "443", "4", "5"], ["2", "443", "4", "4"]]
    );
    assert_eq!(
        rows(
            &engine,
            "SELECT sni, version FROM tls_sessions ORDER BY sni"
        )
        .await,
        [["example.com", "TLS 1.2"], ["example.net", "TLS 1.2"]]
    );
}
