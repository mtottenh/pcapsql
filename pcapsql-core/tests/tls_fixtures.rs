//! HTTP over TLS, decrypted with a key log, through the scan driver.
//!
//! The captures are `pcapsql_testgen::tls`: one connection each, a TLS 1.2
//! or 1.3 handshake, one HTTP/2 or HTTP/1.1 request and its response. The
//! generator describes the records and [`seal`] encrypts them, with its own
//! implementation of the record protection (RFC 5246 and 5288, RFC 7905,
//! RFC 8446) on `ring`'s HMAC and AEAD primitives: nothing of
//! `pcapsql_core::tls` is used to build what it is tested with. Checked
//! here:
//!
//! 1. the captures kept in `pcapsql-testgen/fixtures/` are what the
//!    generator gives (so the files can be made again:
//!    `PCAPSQL_FIXTURE_UPDATE=1 cargo test -p pcapsql-core --test
//!    tls_fixtures`), and their key logs are the ones generated;
//! 2. with the key log, `tls_sessions.is_decrypted` and the rows of `http2`
//!    or `http_messages`, for every cipher suite the decryption has, both
//!    versions and both record layouts; without it, or with a suite it does
//!    not have, or with the wrong secrets, no row;
//! 3. the rows carry the `connection_id` of `tcp_connections`;
//! 4. in the packet table `tls`, an encrypted TLS 1.2 `Finished` is a row
//!    with its record header only, whatever its explicit nonce;
//! 5. a capture from the field (`tls12-dsb.pcapng`: Wireshark's TLS 1.2
//!    sample with its secrets in Decryption Secrets Blocks) decrypts.

use std::io::Cursor;
use std::sync::Arc;

use pcapsql_core::io::{ReadPacketReader, StreamHeader};
use pcapsql_core::scan::testing::{Cell, RecordingSink};
use pcapsql_core::scan::{Catalog, CompiledScan, PartitionScan, ScanPlan, Step, TableScan};
use pcapsql_core::{default_registry, KeyLog};
use pcapsql_testgen::tls::{
    Application, ExplicitNonce, Layout, Scenario, Version, FIXTURES, TLS12_HTTP1,
    TLS12_HTTP1_CAPTURE, TLS12_HTTP1_KEYLOG, TLS12_HTTP2, TLS12_HTTP2_CAPTURE, TLS12_HTTP2_KEYLOG,
    TLS13_HTTP2, TLS13_HTTP2_CAPTURE, TLS13_HTTP2_KEYLOG,
};

/// The record protection of TLS 1.2 (AEAD suites) and TLS 1.3, sealing.
mod seal {
    use pcapsql_testgen::tls::{
        ExplicitNonce, Record, Scenario, Sender, Version, MASTER_SECRET, SERVER_RANDOM,
    };
    use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
    use ring::hmac;

    /// The TLS 1.2 suites with an AEAD cipher that pcapsql names.
    pub const TLS12_SUITES: [u16; 11] = [
        0xc02f, 0xc030, 0xcca8, 0xc02b, 0xc02c, 0xcca9, 0x009e, 0x009f, 0xccaa, 0x009c, 0x009d,
    ];
    /// The TLS 1.3 suites pcapsql names.
    pub const TLS13_SUITES: [u16; 3] = [0x1301, 0x1302, 0x1303];

    /// The AEAD cipher of a suite and the hash of its PRF or HKDF, from the
    /// IANA registry's names: `..._WITH_<cipher>_<hash>`.
    fn suite(id: u16) -> Option<(&'static aead::Algorithm, hmac::Algorithm)> {
        match id {
            0x1301 | 0xc02f | 0xc02b | 0x009e | 0x009c => {
                Some((&aead::AES_128_GCM, hmac::HMAC_SHA256))
            }
            0x1302 | 0xc030 | 0xc02c | 0x009f | 0x009d => {
                Some((&aead::AES_256_GCM, hmac::HMAC_SHA384))
            }
            0x1303 | 0xcca8 | 0xcca9 | 0xccaa => {
                Some((&aead::CHACHA20_POLY1305, hmac::HMAC_SHA256))
            }
            _ => None,
        }
    }

    /// `P_hash(secret, seed)` of RFC 5246, section 5: `length` bytes.
    fn p_hash(hash: hmac::Algorithm, secret: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
        let key = hmac::Key::new(hash, secret);
        let mut output = Vec::new();
        // A(0) = seed, A(i) = HMAC(secret, A(i-1))
        let mut a = seed.to_vec();
        while output.len() < length {
            a = hmac::sign(&key, &a).as_ref().to_vec();
            output.extend_from_slice(hmac::sign(&key, &[a.as_slice(), seed].concat()).as_ref());
        }
        output.truncate(length);
        output
    }

    /// `HKDF-Expand-Label(secret, label, "", length)` of RFC 8446, section
    /// 7.1, for a length of at most one hash output: the first block of
    /// HKDF-Expand (RFC 5869) is `HMAC(secret, info | 0x01)`.
    fn hkdf_expand_label(
        hash: hmac::Algorithm,
        secret: &[u8],
        label: &str,
        length: usize,
    ) -> Vec<u8> {
        let label = format!("tls13 {label}");
        let mut info = (length as u16).to_be_bytes().to_vec();
        info.push(label.len() as u8);
        info.extend_from_slice(label.as_bytes());
        info.push(0); // no context
        info.push(1); // the block's number
        let block = hmac::sign(&hmac::Key::new(hash, secret), &info);
        block.as_ref()[..length].to_vec()
    }

    /// `iv` with the sequence number XORed into its last eight bytes.
    fn xor_sequence(iv: &[u8], sequence: u64) -> [u8; 12] {
        let mut nonce = [0_u8; 12];
        nonce.copy_from_slice(iv);
        for (byte, sequence) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
            *byte ^= sequence;
        }
        nonce
    }

    /// `record` of `scenario` as a TLS record on the wire. A suite without
    /// an AEAD cipher gives a record of the right shape that nothing
    /// decrypts.
    pub fn seal(scenario: &Scenario, record: &Record) -> Vec<u8> {
        let Some((cipher, hash)) = suite(scenario.cipher_suite) else {
            let body: Vec<u8> = record.plaintext.iter().map(|byte| byte ^ 0xa5).collect();
            let outer = match scenario.version {
                Version::Tls12 => record.content_type,
                Version::Tls13 => 23,
            };
            let mut sealed = vec![outer, 0x03, 0x03];
            sealed.extend_from_slice(&((body.len() + 16) as u16).to_be_bytes());
            sealed.extend_from_slice(&body);
            sealed.extend_from_slice(&[0xa5; 16]);
            return sealed;
        };
        let key = |bytes: &[u8]| LessSafeKey::new(UnboundKey::new(cipher, bytes).unwrap());
        match scenario.version {
            // RFC 8446, section 5.2: the content type goes inside, the
            // record says application data, the header is the AAD.
            Version::Tls13 => {
                let secret = scenario.traffic_secret(record.sender, record.phase);
                let write_key = hkdf_expand_label(hash, &secret, "key", cipher.key_len());
                let iv = hkdf_expand_label(hash, &secret, "iv", 12);
                let mut body = record.plaintext.clone();
                body.push(record.content_type);
                let length = (body.len() + cipher.tag_len()) as u16;
                let mut header = [23, 0x03, 0x03, 0, 0];
                header[3..].copy_from_slice(&length.to_be_bytes());
                key(&write_key)
                    .seal_in_place_append_tag(
                        Nonce::assume_unique_for_key(xor_sequence(&iv, record.sequence)),
                        Aad::from(header),
                        &mut body,
                    )
                    .unwrap();
                [header.as_slice(), &body].concat()
            }
            // RFC 5246, section 6.3: the key block is client key, server
            // key, client IV, server IV (an AEAD suite has no MAC keys).
            Version::Tls12 => {
                let chacha = cipher == &aead::CHACHA20_POLY1305;
                // RFC 5288: 4 bytes of salt and 8 in each record. RFC 7905:
                // 12 bytes of IV and nothing in the record.
                let iv_len = if chacha { 12 } else { 4 };
                let seed = [
                    b"key expansion".as_slice(),
                    &SERVER_RANDOM,
                    &scenario.client_random(),
                ]
                .concat();
                let block = p_hash(
                    hash,
                    &MASTER_SECRET,
                    &seed,
                    2 * cipher.key_len() + 2 * iv_len,
                );
                let side = match record.sender {
                    Sender::Client => 0,
                    Sender::Server => 1,
                };
                let write_key = &block[side * cipher.key_len()..][..cipher.key_len()];
                let iv = &block[2 * cipher.key_len() + side * iv_len..][..iv_len];
                // The explicit part of an AES-GCM nonce is the sender's
                // choice, as long as it does not repeat.
                let explicit = match scenario.explicit_nonce {
                    ExplicitNonce::Sequence => record.sequence,
                    ExplicitNonce::Counter => {
                        0x7063_6170_7371_6c00_u64 + side as u64 * 0x100 + record.sequence
                    }
                }
                .to_be_bytes();
                let (nonce, explicit) = if chacha {
                    (xor_sequence(iv, record.sequence), &explicit[..0])
                } else {
                    let mut nonce = [0_u8; 12];
                    nonce[..4].copy_from_slice(iv);
                    nonce[4..].copy_from_slice(&explicit);
                    (nonce, &explicit[..])
                };
                // seq_num | type | version | length of the plaintext
                let mut aad = record.sequence.to_be_bytes().to_vec();
                aad.extend_from_slice(&[record.content_type, 0x03, 0x03]);
                aad.extend_from_slice(&(record.plaintext.len() as u16).to_be_bytes());
                let mut body = record.plaintext.clone();
                key(write_key)
                    .seal_in_place_append_tag(
                        Nonce::assume_unique_for_key(nonce),
                        Aad::from(aad),
                        &mut body,
                    )
                    .unwrap();
                let mut sealed = vec![record.content_type, 0x03, 0x03];
                sealed.extend_from_slice(&((explicit.len() + body.len()) as u16).to_be_bytes());
                sealed.extend_from_slice(explicit);
                sealed.extend_from_slice(&body);
                sealed
            }
        }
    }
}

/// The capture of `scenario`, sealed.
fn capture(scenario: &Scenario) -> Vec<u8> {
    scenario.capture_with(|record| seal::seal(scenario, record))
}

#[test]
fn the_fixtures_are_the_generated_captures() {
    for (stem, scenario, kept, kept_keylog) in FIXTURES {
        let capture = capture(scenario);
        let keylog = scenario.keylog();
        if std::env::var_os("PCAPSQL_FIXTURE_UPDATE").is_some() {
            let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/../pcapsql-testgen/fixtures");
            std::fs::write(format!("{fixtures}/{stem}.pcap"), &capture).unwrap();
            std::fs::write(format!("{fixtures}/{stem}.keys"), &keylog).unwrap();
            continue;
        }
        assert!(
            capture == *kept,
            "fixtures/{stem}.pcap is not the generated capture"
        );
        assert_eq!(keylog, *kept_keylog, "fixtures/{stem}.keys");
    }
}

const TABLES: [&str; 4] = ["tcp_connections", "tls_sessions", "http2", "http_messages"];
const CONNECTIONS: usize = 0;
const SESSIONS: usize = 1;
const HTTP2: usize = 2;
const HTTP1: usize = 3;

/// The rows of each output of a scan, with the plan they are of.
type Scanned = (Arc<CompiledScan>, Vec<Vec<Vec<Cell>>>);

/// Every row of [`TABLES`] for `capture`, all default columns.
fn scan(capture: &[u8], keylog: Option<&str>) -> Scanned {
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
    let mut read = Cursor::new(capture);
    let (header, head) = StreamHeader::probe(&mut read).unwrap();
    let reader = ReadPacketReader::sequential(read, &header, head).unwrap();
    let mut scan = PartitionScan::new(reader, plan.clone(), registry);
    if let Some(keylog) = keylog {
        scan = scan.with_keylog(&KeyLog::parse(keylog).unwrap());
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

/// The frames of the HTTP/2 exchange, in capture order: the SETTINGS of
/// each side, the request, the response and its body, the client's GOAWAY.
const HTTP2_FRAMES: [&str; 8] = [
    "SETTINGS", "SETTINGS", "SETTINGS", "HEADERS", "SETTINGS", "HEADERS", "DATA", "GOAWAY",
];

/// The session is decrypted and the HTTP/2 exchange is in `http2`, every
/// frame with the id of the one TCP connection.
fn assert_http2_exchange(scanned: &Scanned, what: &str) {
    let cells = |output, name| column(scanned, output, name);
    assert_eq!(
        cells(SESSIONS, "is_decrypted"),
        [Cell::Bool(true)],
        "{what}"
    );
    assert_eq!(cells(HTTP2, "frame_type"), HTTP2_FRAMES.map(text), "{what}");
    assert_eq!(
        cells(HTTP2, "stream_id"),
        [0, 0, 0, 1, 0, 1, 1, 0].map(Cell::U32),
        "{what}"
    );
    let of_request = |name| cells(HTTP2, name)[3].clone();
    assert_eq!(of_request("method"), text("GET"), "{what}");
    assert_eq!(of_request("path"), text("/"), "{what}");
    assert_eq!(of_request("scheme"), text("https"), "{what}");
    assert_eq!(of_request("authority"), text("example.test"), "{what}");
    assert_eq!(
        of_request("user_agent"),
        text("pcapsql-corpus/1.0"),
        "{what}"
    );
    assert_eq!(cells(HTTP2, "status")[5], Cell::U16(200), "{what}");
    assert_eq!(
        cells(HTTP2, "content_type")[5],
        text("text/plain"),
        "{what}"
    );
    assert_eq!(cells(HTTP2, "data_length")[6], Cell::U64(5), "{what}");
    assert!(scanned.1[HTTP1].is_empty(), "{what}");
    assert_one_connection(scanned, HTTP2, what);
}

/// The session is decrypted and the HTTP/1.1 exchange is in
/// `http_messages`, both messages with the id of the one TCP connection.
fn assert_http1_exchange(scanned: &Scanned, what: &str) {
    let cells = |output, name| column(scanned, output, name);
    assert_eq!(
        cells(SESSIONS, "is_decrypted"),
        [Cell::Bool(true)],
        "{what}"
    );
    assert_eq!(
        cells(HTTP1, "is_request"),
        [true, false].map(Cell::Bool),
        "{what}"
    );
    assert_eq!(
        cells(HTTP1, "direction"),
        ["to_server", "to_client"].map(text),
        "{what}"
    );
    assert_eq!(cells(HTTP1, "method")[0], text("GET"), "{what}");
    assert_eq!(cells(HTTP1, "uri")[0], text("/index.html"), "{what}");
    assert_eq!(cells(HTTP1, "host")[0], text("example.test"), "{what}");
    assert_eq!(
        cells(HTTP1, "user_agent")[0],
        text("pcapsql-corpus/1.0"),
        "{what}"
    );
    assert_eq!(cells(HTTP1, "http_version")[1], text("HTTP/1.1"), "{what}");
    assert_eq!(cells(HTTP1, "status_code")[1], Cell::U16(200), "{what}");
    assert_eq!(
        cells(HTTP1, "content_type")[1],
        text("text/plain"),
        "{what}"
    );
    assert_eq!(cells(HTTP1, "content_length")[1], Cell::U64(5), "{what}");
    assert_eq!(cells(HTTP1, "server")[1], text("corpus"), "{what}");
    assert!(scanned.1[HTTP2].is_empty(), "{what}");
    assert_one_connection(scanned, HTTP1, what);
}

/// There is one TCP connection, and its id is the session's and that of
/// every row of `output`.
fn assert_one_connection(scanned: &Scanned, output: usize, what: &str) {
    let connections = column(scanned, CONNECTIONS, "connection_id");
    let [connection] = connections.as_slice() else {
        panic!("{what}: one connection, not {connections:?}");
    };
    assert!(matches!(connection, Cell::U64(_)));
    assert_eq!(
        column(scanned, SESSIONS, "connection_id"),
        std::slice::from_ref(connection),
        "{what}"
    );
    let rows = column(scanned, output, "connection_id");
    assert!(!rows.is_empty(), "{what}");
    assert!(rows.iter().all(|id| id == connection), "{what}: {rows:?}");
}

/// No record was decrypted: the session says so and there is no HTTP row.
fn assert_not_decrypted(scanned: &Scanned, what: &str) {
    assert_eq!(
        column(scanned, SESSIONS, "is_decrypted"),
        [Cell::Bool(false)],
        "{what}"
    );
    assert!(scanned.1[HTTP2].is_empty(), "{what}");
    assert!(scanned.1[HTTP1].is_empty(), "{what}");
    assert_eq!(scanned.1[CONNECTIONS].len(), 1, "{what}");
}

#[test]
fn tls13_http2_is_decrypted_with_its_key_log() {
    let scanned = scan(TLS13_HTTP2_CAPTURE, Some(TLS13_HTTP2_KEYLOG));
    let cells = |output, name| column(&scanned, output, name);
    assert_http2_exchange(&scanned, "tls13_http2");
    assert_eq!(cells(SESSIONS, "version"), [text("TLS 1.3")]);
    assert_eq!(
        cells(SESSIONS, "cipher_suite"),
        [text("TLS_AES_128_GCM_SHA256")]
    );
    assert_eq!(cells(SESSIONS, "alpn"), [text("h2")]);
    // One record per segment.
    assert_eq!(
        cells(HTTP2, "frame_number"),
        [8, 9, 10, 10, 11, 11, 12, 13].map(Cell::U64)
    );
}

#[test]
fn tls12_http2_is_decrypted_with_its_key_log() {
    let scanned = scan(TLS12_HTTP2_CAPTURE, Some(TLS12_HTTP2_KEYLOG));
    let cells = |output, name| column(&scanned, output, name);
    assert_http2_exchange(&scanned, "tls12_http2");
    assert_eq!(cells(SESSIONS, "version"), [text("TLS 1.2")]);
    assert_eq!(
        cells(SESSIONS, "cipher_suite"),
        [text("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")]
    );
    assert_eq!(cells(SESSIONS, "cipher_suite_id"), [Cell::U16(0xc02f)]);
    assert_eq!(cells(SESSIONS, "sni"), [text("example.test")]);
    assert_eq!(cells(SESSIONS, "alpn"), [text("h2")]);
    assert_eq!(cells(SESSIONS, "frame_number"), [Cell::U64(4)]);
    assert_eq!(cells(SESSIONS, "server_hello_frame"), [Cell::U64(5)]);
    // Frames 6 and 7 are each side's ChangeCipherSpec and Finished. The
    // response is two records in the segments 11 and 12, the first of which
    // ends in frame 12, with the first bytes of the DATA frame in it.
    assert_eq!(
        cells(HTTP2, "frame_number"),
        [8, 9, 10, 10, 12, 12, 12, 13].map(Cell::U64)
    );
}

#[test]
fn tls12_http1_is_decrypted_with_its_key_log() {
    let scanned = scan(TLS12_HTTP1_CAPTURE, Some(TLS12_HTTP1_KEYLOG));
    let cells = |output, name| column(&scanned, output, name);
    assert_http1_exchange(&scanned, "tls12_http1");
    assert_eq!(cells(SESSIONS, "version"), [text("TLS 1.2")]);
    assert_eq!(
        cells(SESSIONS, "cipher_suite"),
        [text("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")]
    );
    assert_eq!(cells(SESSIONS, "alpn"), [text("http/1.1")]);
    // The request is frame 8; the response ends with the second record of
    // the segments 9 and 10.
    assert_eq!(cells(HTTP1, "frame_number"), [8, 10].map(Cell::U64));
}

#[test]
fn without_a_key_log_nothing_is_decrypted() {
    for (stem, _, capture, _) in FIXTURES {
        assert_not_decrypted(&scan(capture, None), stem);
    }
}

#[test]
fn one_key_log_holds_the_secrets_of_every_fixture() {
    let keylog: String = FIXTURES.iter().map(|(.., keylog)| *keylog).collect();
    for (stem, scenario, capture, _) in FIXTURES {
        let scanned = scan(capture, Some(&keylog));
        match scenario.application {
            Application::Http2 => assert_http2_exchange(&scanned, stem),
            Application::Http1 => assert_http1_exchange(&scanned, stem),
        }
    }
}

#[test]
fn the_key_log_of_another_session_decrypts_nothing() {
    for (stem, _, capture, _) in FIXTURES {
        let others: String = FIXTURES
            .iter()
            .filter(|(other, ..)| other != stem)
            .map(|(.., keylog)| *keylog)
            .collect();
        assert_not_decrypted(&scan(capture, Some(&others)), stem);
    }
}

#[test]
fn the_wrong_secrets_decrypt_nothing() {
    for (stem, scenario, capture, keylog) in FIXTURES {
        // The same client random with other secrets: every secret of the
        // fixtures is one byte value throughout.
        let random: String = scenario
            .client_random()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let wrong: String = keylog
            .lines()
            .map(|line| {
                let (label_and_random, secret) = line.rsplit_once(' ').unwrap();
                assert!(label_and_random.ends_with(&random));
                format!("{label_and_random} {}\n", "0f".repeat(secret.len() / 2))
            })
            .collect();
        assert_ne!(wrong, *keylog);
        assert_not_decrypted(&scan(capture, Some(&wrong)), stem);
    }
}

/// `scenario` in both layouts.
fn layouts(scenario: Scenario) -> [Scenario; 2] {
    [Layout::Separate, Layout::Batched].map(|layout| Scenario { layout, ..scenario })
}

#[test]
fn every_suite_with_an_aead_decrypts() {
    let suites = seal::TLS12_SUITES
        .map(|suite| (Version::Tls12, "TLS 1.2", suite))
        .into_iter()
        .chain(seal::TLS13_SUITES.map(|suite| (Version::Tls13, "TLS 1.3", suite)));
    let nonces = [ExplicitNonce::Sequence, ExplicitNonce::Counter];
    for ((version, version_name, cipher_suite), explicit_nonce) in suites
        .flat_map(|suite| nonces.map(|nonce| (suite, nonce)))
        .filter(|((version, ..), nonce)| *version == Version::Tls12 || *nonce == nonces[0])
    {
        for scenario in layouts(Scenario {
            version,
            cipher_suite,
            explicit_nonce,
            ..TLS13_HTTP2
        }) {
            let what = format!("{scenario:x?}");
            let scanned = scan(&capture(&scenario), Some(&scenario.keylog()));
            assert_http2_exchange(&scanned, &what);
            assert_eq!(
                column(&scanned, SESSIONS, "version"),
                [text(version_name)],
                "{what}"
            );
            assert_eq!(
                column(&scanned, SESSIONS, "cipher_suite_id"),
                [Cell::U16(cipher_suite)],
                "{what}"
            );
            // Named, not `0x....`.
            let names = column(&scanned, SESSIONS, "cipher_suite");
            assert!(
                matches!(names.as_slice(), [Cell::Str(name)] if name.starts_with("TLS_")),
                "{what}: {names:?}"
            );
        }
    }
}

/// `record_type` and `handshake_type` of each row of the packet table `tls`.
fn tls_rows(capture: &[u8]) -> Vec<(Cell, Cell)> {
    let registry = Arc::new(default_registry());
    let (id, def) = Catalog::builtin().table("tls").unwrap();
    let plan = ScanPlan {
        tables: vec![TableScan::new(
            id,
            def.default_columns().map(|(c, _)| c).collect(),
        )],
        ..Default::default()
    };
    let plan = Arc::new(plan.compile(Catalog::builtin(), &registry).unwrap());
    let mut read = Cursor::new(capture);
    let (header, head) = StreamHeader::probe(&mut read).unwrap();
    let reader = ReadPacketReader::sequential(read, &header, head).unwrap();
    let mut scan = PartitionScan::new(reader, plan.clone(), registry);
    let mut sinks: Vec<RecordingSink> = plan
        .outputs()
        .iter()
        .map(|output| RecordingSink::new(&output.columns, None))
        .collect();
    while scan.step(&mut sinks, 4).unwrap() != Step::End {}
    let scanned = (
        plan,
        sinks.iter_mut().map(RecordingSink::take_rows).collect(),
    );
    column(&scanned, 0, "record_type")
        .into_iter()
        .zip(column(&scanned, 0, "handshake_type"))
        .collect()
}

/// An encrypted TLS 1.2 `Finished` is not handshake messages, though with
/// the sequence number as its explicit nonce (0, as Go, NSS and BoringSSL
/// send it) it starts with the bytes of two empty HelloRequests.
#[test]
fn an_encrypted_finished_is_a_tls_row_with_its_header_only() {
    let nonces = [ExplicitNonce::Sequence, ExplicitNonce::Counter];
    let scenarios = [TLS12_HTTP1, TLS12_HTTP2]
        .into_iter()
        .flat_map(|scenario| {
            nonces.map(|explicit_nonce| Scenario {
                explicit_nonce,
                ..scenario
            })
        })
        .flat_map(layouts);
    for scenario in scenarios {
        let what = format!("{scenario:x?}");
        let rows = tls_rows(&capture(&scenario));
        let handshake_types: Vec<&Cell> = rows.iter().map(|(_, h)| h).collect();
        assert!(
            !handshake_types.contains(&&Cell::U8(0)),
            "{what}: {handshake_types:?}"
        );
        // With one record per segment, the two `Finished` start theirs,
        // after the ClientHello, the server's four plaintext messages and
        // the ClientKeyExchange.
        if scenario.layout == Layout::Separate {
            let handshakes: Vec<&Cell> = rows
                .iter()
                .filter(|(record_type, _)| *record_type == Cell::U8(22))
                .map(|(_, handshake_type)| handshake_type)
                .collect();
            assert_eq!(
                handshakes,
                [1, 2, 11, 12, 14, 16]
                    .map(Cell::U8)
                    .iter()
                    .chain(&[Cell::Null, Cell::Null])
                    .collect::<Vec<_>>(),
                "{what}"
            );
        }
    }
    // The fixture with sequence numbers as nonces, and its HTTP exchange.
    assert_eq!(TLS12_HTTP1.explicit_nonce, ExplicitNonce::Sequence);
    assert!(!tls_rows(TLS12_HTTP1_CAPTURE).is_empty());
    let scanned = scan(TLS12_HTTP1_CAPTURE, Some(TLS12_HTTP1_KEYLOG));
    assert_http1_exchange(&scanned, "tls12_http1");
}

#[test]
fn http1_is_recognised_with_and_without_alpn() {
    for version in [Version::Tls12, Version::Tls13] {
        for alpn in [true, false] {
            for scenario in layouts(Scenario {
                version,
                alpn,
                ..TLS12_HTTP1
            }) {
                let what = format!("{scenario:x?}");
                let scanned = scan(&capture(&scenario), Some(&scenario.keylog()));
                assert_http1_exchange(&scanned, &what);
                let expected = if alpn { text("http/1.1") } else { Cell::Null };
                assert_eq!(column(&scanned, SESSIONS, "alpn"), [expected], "{what}");
            }
        }
    }
}

#[test]
fn http2_is_recognised_without_alpn() {
    for scenario in [TLS12_HTTP2, TLS13_HTTP2].into_iter().flat_map(layouts) {
        let scenario = Scenario {
            alpn: false,
            ..scenario
        };
        let what = format!("{scenario:x?}");
        let scanned = scan(&capture(&scenario), Some(&scenario.keylog()));
        assert_http2_exchange(&scanned, &what);
    }
}

#[test]
fn a_suite_without_an_aead_is_not_decrypted() {
    // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA256
    // and TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (a MAC and a block cipher,
    // not an AEAD), and TLS_AES_128_CCM_SHA256 (an AEAD pcapsql does not
    // have).
    let suites = [
        (Version::Tls12, 0xc013),
        (Version::Tls12, 0x003c),
        (Version::Tls12, 0xc027),
        (Version::Tls13, 0x1304),
    ];
    for (version, cipher_suite) in suites {
        for scenario in layouts(Scenario {
            version,
            cipher_suite,
            ..TLS13_HTTP2
        }) {
            let what = format!("{scenario:x?}");
            let scanned = scan(&capture(&scenario), Some(&scenario.keylog()));
            assert_not_decrypted(&scanned, &what);
            // The session is still described.
            assert_eq!(
                column(&scanned, SESSIONS, "cipher_suite_id"),
                [Cell::U16(cipher_suite)],
                "{what}"
            );
        }
    }
}

/// The TLS key logs in the Decryption Secrets Blocks of a little-endian
/// pcapng capture (block type 10, secrets type `TLSK`), as one key log.
fn decryption_secrets(capture: &[u8]) -> String {
    let word = |bytes: &[u8]| u32::from_le_bytes(bytes[..4].try_into().unwrap());
    let mut keylog = String::new();
    let mut rest = capture;
    while rest.len() >= 12 {
        let (block, after) = rest.split_at(word(&rest[4..]) as usize);
        if word(block) == 10 && word(&block[8..]) == 0x544c_534b {
            let secrets = &block[16..][..word(&block[12..]) as usize];
            keylog.push_str(std::str::from_utf8(secrets).unwrap());
            keylog.push('\n');
        }
        rest = after;
    }
    keylog
}

/// Wireshark's `tls12-dsb.pcapng`: two TLS 1.2 connections
/// (`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, made by curl and a real
/// server) captured without their TCP handshakes on a link without a link
/// layer (`LINKTYPE_IPV4`), with their master secrets in the capture. Each
/// is a `HEAD` request and its response, a `Finished` and a `close_notify`
/// from each side; every record has to decrypt for the next one to.
#[test]
fn a_capture_from_the_field_decrypts_with_the_secrets_it_carries() {
    let capture = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fuzz/corpus/fuzz_pcap_reader/tls12-dsb.pcapng"
    ))
    .unwrap();
    let keylog = decryption_secrets(&capture);
    assert_eq!(keylog.matches("CLIENT_RANDOM ").count(), 2);

    let scanned = scan(&capture, Some(&keylog));
    let cells = |output, name| column(&scanned, output, name);
    assert_eq!(cells(CONNECTIONS, "connection_id"), [1, 2].map(Cell::U64));
    assert_eq!(cells(SESSIONS, "connection_id"), [1, 2].map(Cell::U64));
    assert_eq!(
        cells(SESSIONS, "is_decrypted"),
        [true, true].map(Cell::Bool)
    );
    assert_eq!(cells(SESSIONS, "version"), ["TLS 1.2", "TLS 1.2"].map(text));
    assert_eq!(
        cells(SESSIONS, "cipher_suite"),
        ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"; 2].map(text)
    );
    assert_eq!(
        cells(SESSIONS, "sni"),
        ["example.com", "example.net"].map(text)
    );
    // The requests. The responses are not rows: a response to HEAD
    // announces a Content-Length it does not send, and the HTTP/1 stream
    // parser, which does not know what was asked, waits for that body.
    assert_eq!(cells(HTTP1, "connection_id"), [1, 2].map(Cell::U64));
    assert_eq!(cells(HTTP1, "frame_number"), [6, 14].map(Cell::U64));
    assert_eq!(cells(HTTP1, "method"), ["HEAD", "HEAD"].map(text));
    assert_eq!(
        cells(HTTP1, "host"),
        ["example.com", "example.net"].map(text)
    );
    assert_eq!(
        cells(HTTP1, "user_agent"),
        ["curl/7.62.0", "curl/7.62.0"].map(text)
    );
    assert!(scanned.1[HTTP2].is_empty());

    // Without the secrets: the same connections and sessions, nothing read.
    let scanned = scan(&capture, None);
    assert_eq!(
        column(&scanned, SESSIONS, "is_decrypted"),
        [false, false].map(Cell::Bool)
    );
    assert_eq!(scanned.1[CONNECTIONS].len(), 2);
    assert!(scanned.1[HTTP1].is_empty());
}
