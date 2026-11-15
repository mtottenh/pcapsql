//! HTTP/2 over TLS 1.3, decrypted with a key log, through the scan driver.
//!
//! The capture is `pcapsql_testgen::tls`: one connection, a TLS 1.3
//! handshake, one HTTP/2 request and its response. Checked here:
//!
//! 1. the capture kept in `pcapsql-testgen/fixtures/` is what the
//!    description in `pcapsql_testgen::tls` gives when its records are
//!    sealed with the keys the decryption derives (so the file can be made
//!    again: `PCAPSQL_FIXTURE_UPDATE=1 cargo test -p pcapsql-core --test
//!    tls13_http2`), and its key log is the one generated;
//! 2. with the key log, `tls_sessions.is_decrypted` and the rows of
//!    `http2`; without it, no `http2` row;
//! 3. `http2.connection_id` is the connection of `tcp_connections` and
//!    `tls_sessions` the frame was carried by.

use std::io::Cursor;
use std::sync::Arc;

use pcapsql_core::io::{ReadPacketReader, StreamHeader};
use pcapsql_core::scan::testing::{Cell, RecordingSink};
use pcapsql_core::scan::{Catalog, CompiledScan, PartitionScan, ScanPlan, Step, TableScan};
use pcapsql_core::tls::derive_tls13_keys;
use pcapsql_core::{default_registry, KeyLog};
use pcapsql_testgen::tls::{
    tls13_http2_capture_with, tls13_http2_keylog, traffic_secret, Record, TLS13_HTTP2_CAPTURE,
    TLS13_HTTP2_CIPHER_SUITE, TLS13_HTTP2_KEYLOG,
};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};

/// `record` as a TLS 1.3 record on the wire (RFC 8446, section 5.2).
fn seal(record: &Record) -> Vec<u8> {
    let secret = traffic_secret(record.sender, record.phase);
    let keys = derive_tls13_keys(&secret, TLS13_HTTP2_CIPHER_SUITE).unwrap();
    let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &keys.key).unwrap());
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(&keys.iv);
    for (byte, sequence) in nonce[4..].iter_mut().zip(record.sequence.to_be_bytes()) {
        *byte ^= sequence;
    }
    let mut body = record.plaintext.clone();
    body.push(record.content_type);
    let length = (body.len() + AES_128_GCM.tag_len()) as u16;
    // Application data, legacy version 1.2.
    let mut header = [23, 0x03, 0x03, 0, 0];
    header[3..].copy_from_slice(&length.to_be_bytes());
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(header),
        &mut body,
    )
    .unwrap();
    [header.as_slice(), &body].concat()
}

#[test]
fn the_fixture_is_the_generated_capture() {
    let capture = tls13_http2_capture_with(seal);
    let keylog = tls13_http2_keylog();
    if std::env::var_os("PCAPSQL_FIXTURE_UPDATE").is_some() {
        let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/../pcapsql-testgen/fixtures");
        std::fs::write(format!("{fixtures}/tls13_http2.pcap"), &capture).unwrap();
        std::fs::write(format!("{fixtures}/tls13_http2.keys"), &keylog).unwrap();
        return;
    }
    assert!(
        capture == TLS13_HTTP2_CAPTURE,
        "fixtures/tls13_http2.pcap is not the generated capture"
    );
    assert_eq!(keylog, TLS13_HTTP2_KEYLOG);
}

const TABLES: [&str; 3] = ["tcp_connections", "tls_sessions", "http2"];

/// The rows of each output of a scan, with the plan they are of.
type Scanned = (Arc<CompiledScan>, Vec<Vec<Vec<Cell>>>);

/// Every row of [`TABLES`], all default columns.
fn scan(keylog: Option<&KeyLog>) -> Scanned {
    let registry = Arc::new(default_registry());
    let streams = TABLES
        .iter()
        .map(|table| {
            let (id, def) = Catalog::builtin().table(table).unwrap();
            TableScan::new(id, def.default_columns().map(|(c, _)| c).collect())
        })
        .collect();
    let plan = ScanPlan {
        streams,
        ..Default::default()
    };
    let plan = Arc::new(plan.compile(Catalog::builtin(), &registry).unwrap());
    let mut read = Cursor::new(TLS13_HTTP2_CAPTURE);
    let (header, head) = StreamHeader::probe(&mut read).unwrap();
    let reader = ReadPacketReader::sequential(read, &header, head).unwrap();
    let mut scan = PartitionScan::new(reader, plan.clone(), registry);
    if let Some(keylog) = keylog {
        scan = scan.with_keylog(keylog);
    }
    let mut sinks: Vec<RecordingSink> = plan
        .outputs()
        .iter()
        .map(|output| RecordingSink::new(&output.columns, None))
        .collect();
    while scan.step(&mut sinks, 4).unwrap() != Step::End {}
    let rows = sinks.iter_mut().map(RecordingSink::take_rows).collect();
    (plan, rows)
}

/// The value of `column` in each row of output `output`.
fn column((plan, rows): &Scanned, output: usize, column: &str) -> Vec<Cell> {
    let index = plan.outputs()[output]
        .columns
        .iter()
        .position(|c| c.name == column)
        .unwrap_or_else(|| panic!("no column {column}"));
    rows[output].iter().map(|row| row[index].clone()).collect()
}

fn text(text: &str) -> Cell {
    Cell::Str(text.to_owned())
}

#[test]
fn a_key_log_decrypts_the_session_and_gives_the_http2_frames() {
    let keylog = KeyLog::parse(TLS13_HTTP2_KEYLOG).unwrap();
    let scanned = scan(Some(&keylog));
    let cells = |output, name| column(&scanned, output, name);

    assert_eq!(cells(1, "is_decrypted"), [Cell::Bool(true)]);
    assert_eq!(cells(1, "version"), [text("TLS 1.3")]);
    assert_eq!(cells(1, "alpn"), [text("h2")]);

    // In capture order: the SETTINGS of each side, the request, the
    // response and its body, the client's GOAWAY.
    assert_eq!(
        cells(2, "frame_type"),
        ["SETTINGS", "SETTINGS", "SETTINGS", "HEADERS", "SETTINGS", "HEADERS", "DATA", "GOAWAY"]
            .map(text)
    );
    assert_eq!(
        cells(2, "frame_number"),
        [8, 9, 10, 10, 11, 11, 12, 13].map(Cell::U64)
    );
    assert_eq!(
        cells(2, "stream_id"),
        [0, 0, 0, 1, 0, 1, 1, 0].map(Cell::U32)
    );
    let of_request = |name| cells(2, name)[3].clone();
    assert_eq!(of_request("method"), text("GET"));
    assert_eq!(of_request("path"), text("/"));
    assert_eq!(of_request("scheme"), text("https"));
    assert_eq!(of_request("authority"), text("example.test"));
    assert_eq!(of_request("user_agent"), text("pcapsql-corpus/1.0"));
    assert_eq!(cells(2, "status")[5], Cell::U16(200));
    assert_eq!(cells(2, "content_type")[5], text("text/plain"));
    assert_eq!(cells(2, "data_length")[6], Cell::U64(5));
}

#[test]
fn every_http2_frame_has_the_id_of_its_tcp_connection() {
    let keylog = KeyLog::parse(TLS13_HTTP2_KEYLOG).unwrap();
    let scanned = scan(Some(&keylog));
    let connections = column(&scanned, 0, "connection_id");
    let [connection] = connections.as_slice() else {
        panic!("one connection, not {connections:?}");
    };
    assert!(matches!(connection, Cell::U64(_)));
    assert_eq!(
        column(&scanned, 1, "connection_id"),
        std::slice::from_ref(connection)
    );
    let frames = column(&scanned, 2, "connection_id");
    assert_eq!(frames.len(), 8);
    assert!(frames.iter().all(|id| id == connection), "{frames:?}");
}

#[test]
fn without_a_key_log_nothing_is_decrypted() {
    let scanned = scan(None);
    assert_eq!(column(&scanned, 1, "is_decrypted"), [Cell::Bool(false)]);
    assert!(scanned.1[2].is_empty());
    assert_eq!(scanned.1[0].len(), 1);
}
