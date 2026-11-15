//! A capture of HTTP/2 over TLS 1.3, with the key log that decrypts it.
//!
//! One TCP connection (`10.0.0.1:40010` to `10.0.0.2:443`): the handshake,
//! a TLS 1.3 handshake (`TLS_AES_128_GCM_SHA256`, ALPN `h2`) that ends with
//! each side's encrypted `Finished`, then one HTTP/2 request and its
//! response in application-data records, and an orderly close. Sixteen
//! frames, one TLS record per segment.
//!
//! This crate has no dependencies, so it does not encrypt. What is
//! encrypted is described here ([`Record`]: who sends it, under which
//! secret, with which sequence number) and the caller seals it:
//! [`tls13_http2_capture_with`] builds the capture around the records a
//! sealing function returns. `pcapsql-core/tests/tls13_http2_fixture.rs`
//! does that with the cipher the decryption uses and checks that the result
//! is, byte for byte, the capture kept in `fixtures/`
//! ([`TLS13_HTTP2_CAPTURE`]), which is what every other test and the SQL
//! tests of the DuckDB extension read, with its key log
//! ([`TLS13_HTTP2_KEYLOG`]).
//!
//! The secrets are made up for the fixture and protect nothing.

use crate::corpus::{
    client_hello, eth, ipv4, server_hello, tcp, to_capture, ETH_IP4, LINKTYPE_ETHERNET, MAC_A,
    MAC_B,
};

/// The capture, as `fixtures/tls13_http2.pcap` holds it.
pub const TLS13_HTTP2_CAPTURE: &[u8] = include_bytes!("../fixtures/tls13_http2.pcap");

/// The key log of [`TLS13_HTTP2_CAPTURE`] (NSS key log format), as
/// `fixtures/tls13_http2.keys` holds it.
pub const TLS13_HTTP2_KEYLOG: &str = include_str!("../fixtures/tls13_http2.keys");

/// The cipher suite the server selects: `TLS_AES_128_GCM_SHA256`.
pub const TLS13_HTTP2_CIPHER_SUITE: u16 = 0x1301;

/// The client random of [`client_hello`], which is what a key log is
/// looked up by.
const CLIENT_RANDOM: [u8; 32] = [0x11; 32];

/// Which side sends a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sender {
    Client,
    Server,
}

/// Which of a side's two traffic secrets protects a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// The handshake traffic secret: the encrypted handshake messages.
    Handshake,
    /// The first application traffic secret: everything after `Finished`.
    Application,
}

/// The traffic secret of `sender` in `phase`: 32 bytes of one value.
pub fn traffic_secret(sender: Sender, phase: Phase) -> [u8; 32] {
    let byte = match (sender, phase) {
        (Sender::Client, Phase::Handshake) => 0xa1,
        (Sender::Server, Phase::Handshake) => 0xb2,
        (Sender::Client, Phase::Application) => 0xc3,
        (Sender::Server, Phase::Application) => 0xd4,
    };
    [byte; 32]
}

/// The key log of the capture, built from [`traffic_secret`]: four lines.
pub fn tls13_http2_keylog() -> String {
    let hex = |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
    let random = hex(&CLIENT_RANDOM);
    [
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
        format!("{label} {random} {}\n", hex(&traffic_secret(sender, phase)))
    })
    .collect()
}

/// One TLS 1.3 record to encrypt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub sender: Sender,
    pub phase: Phase,
    /// The record's sequence number under its secret, from 0.
    pub sequence: u64,
    /// The content type inside the encryption: 22 handshake, 23 application
    /// data.
    pub content_type: u8,
    pub plaintext: Vec<u8>,
}

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

/// A `Finished` handshake message. The verify data is not checked by a
/// passive reader.
fn finished() -> Vec<u8> {
    let mut message = vec![20, 0, 0, 32];
    message.extend_from_slice(&[0x5a; 32]);
    message
}

/// The encrypted records of the capture, in the order they are sent.
pub fn tls13_http2_records() -> Vec<Record> {
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

    let record = |sender, phase, sequence, content_type, plaintext| Record {
        sender,
        phase,
        sequence,
        content_type,
        plaintext,
    };
    let app =
        |sender, sequence, plaintext| record(sender, Phase::Application, sequence, 23, plaintext);
    vec![
        record(Sender::Server, Phase::Handshake, 0, 22, finished()),
        record(Sender::Client, Phase::Handshake, 0, 22, finished()),
        app(
            Sender::Client,
            0,
            [PREFACE, &h2_frame(SETTINGS, 0, 0, &[])].concat(),
        ),
        app(Sender::Server, 0, h2_frame(SETTINGS, 0, 0, &[])),
        app(
            Sender::Client,
            1,
            [
                h2_frame(SETTINGS, ACK, 0, &[]),
                h2_frame(HEADERS, END_STREAM | END_HEADERS, 1, &request),
            ]
            .concat(),
        ),
        app(
            Sender::Server,
            1,
            [
                h2_frame(SETTINGS, ACK, 0, &[]),
                h2_frame(HEADERS, END_HEADERS, 1, &response),
            ]
            .concat(),
        ),
        app(Sender::Server, 2, h2_frame(DATA, END_STREAM, 1, b"hello")),
        // Last stream 1, NO_ERROR.
        app(
            Sender::Client,
            2,
            h2_frame(GOAWAY, 0, 0, &[0, 0, 0, 1, 0, 0, 0, 0]),
        ),
    ]
}

/// The capture, with every record of [`tls13_http2_records`] replaced by
/// what `seal` returns for it: the whole TLS record, header included.
pub fn tls13_http2_capture_with(mut seal: impl FnMut(&Record) -> Vec<u8>) -> Vec<u8> {
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
    send(Sender::Client, PSH_ACK, &client_hello("example.test", "h2"));
    send(
        Sender::Server,
        PSH_ACK,
        &server_hello(TLS13_HTTP2_CIPHER_SUITE),
    );
    for record in tls13_http2_records() {
        send(record.sender, PSH_ACK, &seal(&record));
    }
    send(Sender::Client, FIN_ACK, &[]);
    send(Sender::Server, FIN_ACK, &[]);
    send(Sender::Client, ACK, &[]);
    to_capture(frames, LINKTYPE_ETHERNET)
}
