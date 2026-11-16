//! Captures of HTTP over TLS, with the key logs that decrypt them.
//!
//! A [`Scenario`] is one TCP connection (`10.0.0.1:40010` to
//! `10.0.0.2:443`): the TCP handshake, a TLS handshake of the scenario's
//! version and cipher suite, one HTTP exchange (HTTP/2 or HTTP/1.1) in
//! application-data records, and an orderly close.
//!
//! This crate has no dependencies, so it does not encrypt. What is
//! encrypted is described here ([`Record`]: who sends it, under which
//! secret, with which sequence number) and the caller seals it:
//! [`Scenario::capture_with`] builds the capture around the records a
//! sealing function returns. `pcapsql-core/tests/tls_fixtures.rs` does that
//! with its own implementation of the record protection of RFC 5246, 5288,
//! 7905 and 8446, and checks that the result is, byte for byte, the capture
//! kept in `fixtures/` ([`FIXTURES`]), which is what the other tests and
//! the SQL tests of the DuckDB extension read, each with its key log.
//!
//! The secrets are made up for the fixtures and protect nothing.

use crate::corpus::{
    eth, ipv4, tcp, tls_handshake_record, to_capture, ETH_IP4, HTTP_REQUEST, HTTP_RESPONSE,
    LINKTYPE_ETHERNET, MAC_A, MAC_B,
};

/// The protocol version a scenario negotiates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    Tls12,
    Tls13,
}

/// What the connection carries inside TLS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Application {
    /// One HTTP/2 request and its response (ALPN `h2`).
    Http2,
    /// One HTTP/1.1 request and its response (ALPN `http/1.1`).
    Http1,
}

/// How records are laid out in handshake messages, records and segments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    /// One handshake message per record and one record per segment. The
    /// server of a TLS 1.3 scenario sends no `EncryptedExtensions`, so the
    /// protocol it selected is not in the capture.
    Separate,
    /// The way a stack that batches its writes sends them: the handshake
    /// messages of a flight share a record, the records of a flight share a
    /// segment, the response is two records that do not end where its
    /// parts do and whose segment is cut in the middle of a record, and the
    /// client closes with a `close_notify` alert.
    Batched,
}

/// How a TLS 1.2 sender of an AES-GCM suite chooses the explicit part of
/// each record's nonce (RFC 5288: 8 bytes, sent before the ciphertext).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExplicitNonce {
    /// The record's sequence number, so 0 for the `Finished` of each side:
    /// what Go's crypto/tls, NSS and BoringSSL send.
    Sequence,
    /// A counter that does not start at the sequence number (`pcapsql\0`
    /// and up, a different one for each side), so that a decryption that
    /// used the sequence number instead of the bytes in the record fails.
    Counter,
}

/// One connection to describe: see the [module](self).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scenario {
    pub version: Version,
    /// The cipher suite the server selects.
    pub cipher_suite: u16,
    pub application: Application,
    pub layout: Layout,
    /// Whether the handshake negotiates the application protocol (ALPN).
    pub alpn: bool,
    /// The explicit nonces of the records of a TLS 1.2 AES-GCM suite.
    pub explicit_nonce: ExplicitNonce,
}

/// HTTP/2 over TLS 1.3 with `TLS_AES_128_GCM_SHA256`.
pub const TLS13_HTTP2: Scenario = Scenario {
    version: Version::Tls13,
    cipher_suite: 0x1301,
    application: Application::Http2,
    layout: Layout::Separate,
    alpn: true,
    explicit_nonce: ExplicitNonce::Sequence,
};

/// HTTP/2 over TLS 1.2 with `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.
pub const TLS12_HTTP2: Scenario = Scenario {
    version: Version::Tls12,
    cipher_suite: 0xc02f,
    application: Application::Http2,
    layout: Layout::Batched,
    alpn: true,
    explicit_nonce: ExplicitNonce::Counter,
};

/// HTTP/1.1 over TLS 1.2 with `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`,
/// with the sequence numbers as explicit nonces.
pub const TLS12_HTTP1: Scenario = Scenario {
    version: Version::Tls12,
    cipher_suite: 0xc02f,
    application: Application::Http1,
    layout: Layout::Batched,
    alpn: true,
    explicit_nonce: ExplicitNonce::Sequence,
};

/// The capture of [`TLS13_HTTP2`], as `fixtures/tls13_http2.pcap` holds it.
pub const TLS13_HTTP2_CAPTURE: &[u8] = include_bytes!("../fixtures/tls13_http2.pcap");
/// The key log of [`TLS13_HTTP2_CAPTURE`] (NSS key log format).
pub const TLS13_HTTP2_KEYLOG: &str = include_str!("../fixtures/tls13_http2.keys");
/// The capture of [`TLS12_HTTP2`], as `fixtures/tls12_http2.pcap` holds it.
pub const TLS12_HTTP2_CAPTURE: &[u8] = include_bytes!("../fixtures/tls12_http2.pcap");
/// The key log of [`TLS12_HTTP2_CAPTURE`].
pub const TLS12_HTTP2_KEYLOG: &str = include_str!("../fixtures/tls12_http2.keys");
/// The capture of [`TLS12_HTTP1`], as `fixtures/tls12_http1.pcap` holds it.
pub const TLS12_HTTP1_CAPTURE: &[u8] = include_bytes!("../fixtures/tls12_http1.pcap");
/// The key log of [`TLS12_HTTP1_CAPTURE`].
pub const TLS12_HTTP1_KEYLOG: &str = include_str!("../fixtures/tls12_http1.keys");

/// The scenarios kept in `fixtures/`: the file stem, the scenario, the
/// capture (`<stem>.pcap`) and its key log (`<stem>.keys`).
pub const FIXTURES: &[(&str, Scenario, &[u8], &str)] = &[
    (
        "tls13_http2",
        TLS13_HTTP2,
        TLS13_HTTP2_CAPTURE,
        TLS13_HTTP2_KEYLOG,
    ),
    (
        "tls12_http2",
        TLS12_HTTP2,
        TLS12_HTTP2_CAPTURE,
        TLS12_HTTP2_KEYLOG,
    ),
    (
        "tls12_http1",
        TLS12_HTTP1,
        TLS12_HTTP1_CAPTURE,
        TLS12_HTTP1_KEYLOG,
    ),
];

/// Which side sends a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sender {
    Client,
    Server,
}

/// Which of a side's secrets protects a record. TLS 1.2 has one key per
/// side, so all its records are [`Phase::Application`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// The TLS 1.3 handshake traffic secret: the encrypted handshake.
    Handshake,
    /// The first TLS 1.3 application traffic secret (everything after
    /// `Finished`), or the TLS 1.2 keys.
    Application,
}

/// One TLS record to encrypt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub sender: Sender,
    pub phase: Phase,
    /// The record's sequence number under its key, from 0. In TLS 1.2 the
    /// `Finished` of each side is its record 0.
    pub sequence: u64,
    /// 21 alert, 22 handshake, 23 application data. In TLS 1.2 this is the
    /// type in the record header; TLS 1.3 puts it inside the encryption.
    pub content_type: u8,
    pub plaintext: Vec<u8>,
}

/// A part of a flight: bytes sent as they are, or a record to seal.
enum Piece {
    Plain(Vec<u8>),
    Sealed(Record),
}

/// What one side sends in one go.
struct Flight {
    sender: Sender,
    pieces: Vec<Piece>,
    /// Sent as two segments, cut in the middle.
    halved: bool,
}

/// The server random of every scenario.
pub const SERVER_RANDOM: [u8; 32] = [0x22; 32];

/// The TLS 1.2 master secret of every scenario.
pub const MASTER_SECRET: [u8; 48] = [0xe5; 48];

const ALERT: u8 = 21;
const HANDSHAKE: u8 = 22;
const APPLICATION_DATA: u8 = 23;

/// The HTTP/2 client connection preface.
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// An HTTP/2 frame.
fn h2_frame(frame_type: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = (payload.len() as u32).to_be_bytes()[1..].to_vec();
    frame.push(frame_type);
    frame.push(flags);
    frame.extend_from_slice(&stream.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// An HPACK literal header field with incremental indexing whose name is
/// entry `name` of the static table.
fn hpack_literal(name: u8, value: &str) -> Vec<u8> {
    let mut field = vec![0x40 | name, value.len() as u8];
    field.extend_from_slice(value.as_bytes());
    field
}

/// A handshake message.
fn handshake(message_type: u8, body: &[u8]) -> Vec<u8> {
    let mut message = vec![message_type];
    message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    message.extend_from_slice(body);
    message
}

/// A record that is not encrypted, with record version 1.2.
fn plain_record(content_type: u8, body: &[u8]) -> Vec<u8> {
    let mut record = vec![content_type, 0x03, 0x03];
    record.extend_from_slice(&(body.len() as u16).to_be_bytes());
    record.extend_from_slice(body);
    record
}

/// An extension of a hello.
fn extension(extension_type: u16, body: &[u8]) -> Vec<u8> {
    let mut extension = extension_type.to_be_bytes().to_vec();
    extension.extend_from_slice(&(body.len() as u16).to_be_bytes());
    extension.extend_from_slice(body);
    extension
}

/// The application_layer_protocol_negotiation extension naming `protocol`.
fn alpn_extension(protocol: &str) -> Vec<u8> {
    let mut list = ((protocol.len() + 1) as u16).to_be_bytes().to_vec();
    list.push(protocol.len() as u8);
    list.extend_from_slice(protocol.as_bytes());
    extension(16, &list)
}

impl Scenario {
    /// The client random, which is what a key log is looked up by: `0x11`
    /// throughout for [`TLS13_HTTP2`], and different in its first bytes for
    /// every other scenario, so that the key logs of several scenarios can
    /// be one file.
    pub fn client_random(&self) -> [u8; 32] {
        let mut random = [0x11; 32];
        let [high, low] = (self.cipher_suite ^ TLS13_HTTP2.cipher_suite).to_be_bytes();
        let differences = [
            u8::from(self.version != TLS13_HTTP2.version),
            high,
            low,
            u8::from(self.application != TLS13_HTTP2.application),
            u8::from(self.layout != TLS13_HTTP2.layout),
            u8::from(self.alpn != TLS13_HTTP2.alpn),
        ];
        for (byte, difference) in random.iter_mut().zip(differences) {
            *byte ^= difference;
        }
        random
    }

    /// The ALPN protocol id of the application.
    pub fn protocol(&self) -> &'static str {
        match self.application {
            Application::Http2 => "h2",
            Application::Http1 => "http/1.1",
        }
    }

    /// The length of a TLS 1.3 traffic secret of the suite: the output of
    /// its hash.
    fn secret_len(&self) -> usize {
        match self.cipher_suite {
            0x1302 => 48,
            _ => 32,
        }
    }

    /// The TLS 1.3 traffic secret of `sender` in `phase`: one byte value
    /// throughout.
    pub fn traffic_secret(&self, sender: Sender, phase: Phase) -> Vec<u8> {
        let byte = match (sender, phase) {
            (Sender::Client, Phase::Handshake) => 0xa1,
            (Sender::Server, Phase::Handshake) => 0xb2,
            (Sender::Client, Phase::Application) => 0xc3,
            (Sender::Server, Phase::Application) => 0xd4,
        };
        vec![byte; self.secret_len()]
    }

    /// The key log of the capture: the four traffic secrets of a TLS 1.3
    /// connection, the master secret of a TLS 1.2 one.
    pub fn keylog(&self) -> String {
        let hex = |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
        let random = hex(&self.client_random());
        match self.version {
            Version::Tls12 => format!("CLIENT_RANDOM {random} {}\n", hex(&MASTER_SECRET)),
            Version::Tls13 => [
                (
                    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                    Sender::Client,
                    Phase::Handshake,
                ),
                (
                    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                    Sender::Server,
                    Phase::Handshake,
                ),
                (
                    "CLIENT_TRAFFIC_SECRET_0",
                    Sender::Client,
                    Phase::Application,
                ),
                (
                    "SERVER_TRAFFIC_SECRET_0",
                    Sender::Server,
                    Phase::Application,
                ),
            ]
            .iter()
            .map(|&(label, sender, phase)| {
                format!(
                    "{label} {random} {}\n",
                    hex(&self.traffic_secret(sender, phase))
                )
            })
            .collect(),
        }
    }

    /// The ClientHello record: SNI `example.test`, the two suites
    /// [`TLS13_HTTP2`] offers and the one the server selects.
    fn client_hello(&self) -> Vec<u8> {
        let mut suites = vec![0x1301_u16, 0x1302];
        if !suites.contains(&self.cipher_suite) {
            suites.push(self.cipher_suite);
        }
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&self.client_random());
        body.push(0); // session id
        body.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
        for suite in suites {
            body.extend_from_slice(&suite.to_be_bytes());
        }
        body.extend_from_slice(&[0x01, 0x00]); // compression: null
        let name = b"example.test";
        // server_name: list(len) -> type 0, name(len), name
        let mut names = ((name.len() + 3) as u16).to_be_bytes().to_vec();
        names.push(0);
        names.extend_from_slice(&(name.len() as u16).to_be_bytes());
        names.extend_from_slice(name);
        let mut extensions = extension(0, &names);
        if self.alpn {
            extensions.extend(alpn_extension(self.protocol()));
        }
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        tls_handshake_record(0x0301, 1, &body)
    }

    /// The ServerHello message. TLS 1.3 is negotiated in supported_versions
    /// (the version field stays 1.2) and selects the application protocol
    /// later, in `EncryptedExtensions`; TLS 1.2 selects it here.
    fn server_hello(&self) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&SERVER_RANDOM);
        body.push(0); // session id
        body.extend_from_slice(&self.cipher_suite.to_be_bytes());
        body.push(0); // compression: null
        let extensions = match self.version {
            Version::Tls13 => extension(43, &[0x03, 0x04]),
            Version::Tls12 if self.alpn => alpn_extension(self.protocol()),
            Version::Tls12 => Vec::new(),
        };
        if !extensions.is_empty() {
            body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            body.extend_from_slice(&extensions);
        }
        handshake(2, &body)
    }

    /// A `Finished` message. The verify data, which a passive reader does
    /// not check, is as long as the version makes it.
    fn finished(&self) -> Vec<u8> {
        let length = match self.version {
            Version::Tls12 => 12,
            Version::Tls13 => self.secret_len(),
        };
        handshake(20, &vec![0x5a; length])
    }

    /// The records of the application, as (sender, plaintext): the request
    /// and the response of [`Scenario::application`].
    fn exchange(&self) -> Vec<(Sender, Vec<u8>)> {
        use Sender::{Client, Server};
        let batched = self.layout == Layout::Batched;
        match self.application {
            Application::Http2 => {
                const DATA: u8 = 0;
                const HEADERS: u8 = 1;
                const SETTINGS: u8 = 4;
                const GOAWAY: u8 = 7;
                const END_STREAM: u8 = 0x01;
                const ACK: u8 = 0x01;
                const END_HEADERS: u8 = 0x04;

                // GET https://example.test/ with a user-agent.
                let mut request = vec![0x82, 0x87, 0x84];
                request.extend(hpack_literal(1, "example.test"));
                request.extend(hpack_literal(58, "pcapsql-corpus/1.0"));
                // 200 with a content type and length.
                let mut response = vec![0x88];
                response.extend(hpack_literal(31, "text/plain"));
                response.extend(hpack_literal(28, "5"));

                let mut headers = [
                    h2_frame(SETTINGS, ACK, 0, &[]),
                    h2_frame(HEADERS, END_HEADERS, 1, &response),
                ]
                .concat();
                let mut data = h2_frame(DATA, END_STREAM, 1, b"hello");
                if batched {
                    // The first record ends inside the DATA frame's header.
                    headers.extend(data.drain(..4));
                }
                vec![
                    (Client, [PREFACE, &h2_frame(SETTINGS, 0, 0, &[])].concat()),
                    (Server, h2_frame(SETTINGS, 0, 0, &[])),
                    (
                        Client,
                        [
                            h2_frame(SETTINGS, ACK, 0, &[]),
                            h2_frame(HEADERS, END_STREAM | END_HEADERS, 1, &request),
                        ]
                        .concat(),
                    ),
                    (Server, headers),
                    (Server, data),
                    // Last stream 1, NO_ERROR.
                    (Client, h2_frame(GOAWAY, 0, 0, &[0, 0, 0, 1, 0, 0, 0, 0])),
                ]
            }
            Application::Http1 => {
                // The first record ends inside the body when batched, and
                // inside the headers when not.
                let cut = HTTP_RESPONSE.len() - if batched { 3 } else { 30 };
                vec![
                    (Client, HTTP_REQUEST.to_vec()),
                    (Server, HTTP_RESPONSE[..cut].to_vec()),
                    (Server, HTTP_RESPONSE[cut..].to_vec()),
                ]
            }
        }
    }

    /// Everything after the TCP handshake, in the order it is sent.
    fn flights(&self) -> Vec<Flight> {
        use Sender::{Client, Server};
        let batched = self.layout == Layout::Batched;
        // The next sequence number of each side under each secret.
        let mut next = [[0_u64; 2]; 2];
        let mut sealed = |sender: Sender, phase: Phase, content_type: u8, plaintext: Vec<u8>| {
            let counter = &mut next[sender as usize][phase as usize];
            let sequence = *counter;
            *counter += 1;
            Piece::Sealed(Record {
                sender,
                phase,
                sequence,
                content_type,
                plaintext,
            })
        };
        let mut flights = Vec::new();
        // The pieces of one side: one flight when batched, else one each.
        let mut send = |sender: Sender, pieces: Vec<Piece>| {
            if batched {
                flights.push(Flight {
                    sender,
                    pieces,
                    halved: false,
                });
            } else {
                flights.extend(pieces.into_iter().map(|piece| Flight {
                    sender,
                    pieces: vec![piece],
                    halved: false,
                }));
            }
        };
        // Handshake messages: one record when batched, else one each.
        let messages = |messages: Vec<Vec<u8>>| -> Vec<Vec<u8>> {
            if batched {
                vec![messages.concat()]
            } else {
                messages
            }
        };
        let plain = |messages: Vec<Vec<u8>>| -> Vec<Piece> {
            messages
                .iter()
                .map(|message| Piece::Plain(plain_record(HANDSHAKE, message)))
                .collect()
        };

        send(Client, vec![Piece::Plain(self.client_hello())]);
        match self.version {
            Version::Tls13 => {
                send(Server, plain(vec![self.server_hello()]));
                let mut flight = Vec::new();
                if batched {
                    let extensions = if self.alpn {
                        alpn_extension(self.protocol())
                    } else {
                        Vec::new()
                    };
                    let mut body = (extensions.len() as u16).to_be_bytes().to_vec();
                    body.extend_from_slice(&extensions);
                    flight.push(handshake(8, &body));
                }
                flight.push(self.finished());
                send(
                    Server,
                    messages(flight)
                        .into_iter()
                        .map(|message| sealed(Server, Phase::Handshake, HANDSHAKE, message))
                        .collect(),
                );
                send(
                    Client,
                    vec![sealed(Client, Phase::Handshake, HANDSHAKE, self.finished())],
                );
            }
            Version::Tls12 => {
                // One certificate, which nothing here reads.
                let certificate = [0x30, 0x82, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef];
                let mut chain = vec![0, 0, certificate.len() as u8 + 3];
                chain.extend_from_slice(&[0, 0, certificate.len() as u8]);
                chain.extend_from_slice(&certificate);
                // A named curve (x25519), a public key and a signature
                // (rsa_pkcs1_sha256) that nothing here checks.
                let mut exchange = vec![3, 0x00, 0x1d, 32];
                exchange.extend_from_slice(&[0x77; 32]);
                exchange.extend_from_slice(&[0x04, 0x01, 0x00, 0x08]);
                exchange.extend_from_slice(&[0x99; 8]);
                let mut key = vec![32];
                key.extend_from_slice(&[0x88; 32]);
                send(
                    Server,
                    plain(messages(vec![
                        self.server_hello(),
                        handshake(11, &chain),
                        handshake(12, &exchange),
                        handshake(14, &[]),
                    ])),
                );
                let change_cipher_spec = || Piece::Plain(plain_record(20, &[1]));
                let mut flight = plain(vec![handshake(16, &key)]);
                flight.push(change_cipher_spec());
                flight.push(sealed(
                    Client,
                    Phase::Application,
                    HANDSHAKE,
                    self.finished(),
                ));
                send(Client, flight);
                send(
                    Server,
                    vec![
                        change_cipher_spec(),
                        sealed(Server, Phase::Application, HANDSHAKE, self.finished()),
                    ],
                );
            }
        }

        let mut exchange = self.exchange().into_iter().peekable();
        while let Some((sender, plaintext)) = exchange.next() {
            let mut pieces = vec![sealed(
                sender,
                Phase::Application,
                APPLICATION_DATA,
                plaintext,
            )];
            // What the same side sends next is the same flight.
            while let Some((_, plaintext)) = exchange.next_if(|(next, _)| *next == sender) {
                pieces.push(sealed(
                    sender,
                    Phase::Application,
                    APPLICATION_DATA,
                    plaintext,
                ));
            }
            send(sender, pieces);
        }
        if batched {
            // close_notify, at warning level.
            send(
                Client,
                vec![sealed(Client, Phase::Application, ALERT, vec![1, 0])],
            );
        }
        if batched {
            // The response: the server's last flight of two records.
            let response = flights
                .iter_mut()
                .rev()
                .find(|flight| flight.sender == Server && flight.pieces.len() == 2)
                .expect("the response is two records");
            response.halved = true;
        }
        flights
    }

    /// The encrypted records of the capture, in the order they are sent.
    pub fn records(&self) -> Vec<Record> {
        self.flights()
            .into_iter()
            .flat_map(|flight| flight.pieces)
            .filter_map(|piece| match piece {
                Piece::Sealed(record) => Some(record),
                Piece::Plain(_) => None,
            })
            .collect()
    }

    /// The capture, with every record of [`Scenario::records`] replaced by
    /// what `seal` returns for it: the whole TLS record, header included.
    pub fn capture_with(&self, mut seal: impl FnMut(&Record) -> Vec<u8>) -> Vec<u8> {
        const CLIENT: ([u8; 4], u16) = ([10, 0, 0, 1], 40010);
        const SERVER: ([u8; 4], u16) = ([10, 0, 0, 2], 443);
        const SYN: u8 = 0x02;
        const ACK: u8 = 0x10;
        const FIN_ACK: u8 = 0x11;
        const SYN_ACK: u8 = 0x12;
        const PSH_ACK: u8 = 0x18;

        // The next sequence number of each side: the client's, the server's.
        let mut next = [3000_u32, 9000];
        let mut frames: Vec<Vec<u8>> = Vec::new();
        let mut send = |sender: Sender, flags: u8, payload: &[u8]| {
            let (from, to, mac_from, mac_to, me, peer) = match sender {
                Sender::Client => (CLIENT, SERVER, MAC_A, MAC_B, 0, 1),
                Sender::Server => (SERVER, CLIENT, MAC_B, MAC_A, 1, 0),
            };
            // The first SYN acknowledges nothing.
            let ack = if flags == SYN { 0 } else { next[peer] };
            let segment = tcp(from.1, to.1, next[me], ack, flags, payload);
            // SYN and FIN each take a sequence number.
            let control = u32::from(flags & 0x03 != 0);
            next[me] += payload.len() as u32 + control;
            let id = frames.len() as u16 + 1;
            frames.push(eth(
                mac_to,
                mac_from,
                ETH_IP4,
                &ipv4(from.0, to.0, 6, id, &segment),
            ));
        };

        send(Sender::Client, SYN, &[]);
        send(Sender::Server, SYN_ACK, &[]);
        send(Sender::Client, ACK, &[]);
        for flight in self.flights() {
            let mut payload = Vec::new();
            for piece in &flight.pieces {
                match piece {
                    Piece::Plain(bytes) => payload.extend_from_slice(bytes),
                    Piece::Sealed(record) => payload.extend(seal(record)),
                }
            }
            if flight.halved {
                let (first, second) = payload.split_at(payload.len() / 2);
                send(flight.sender, ACK, first);
                send(flight.sender, PSH_ACK, second);
            } else {
                send(flight.sender, PSH_ACK, &payload);
            }
        }
        send(Sender::Client, FIN_ACK, &[]);
        send(Sender::Server, FIN_ACK, &[]);
        send(Sender::Client, ACK, &[]);
        to_capture(frames, LINKTYPE_ETHERNET)
    }
}
