//! TLS stream parser with decryption support.
//!
//! This parser extends the basic TLS metadata extraction with actual decryption
//! of TLS records when SSLKEYLOGFILE keys are available.
//!
//! Which records of a connection are protected depends on the version. In
//! TLS 1.3 they are the records of type application data, whose real type
//! is inside the encryption. In TLS 1.2 they are every record a side sends
//! after its ChangeCipherSpec, of any type, starting with its `Finished`:
//! each of them counts in the sequence number the next one is
//! authenticated with, so all of them are decrypted, not only the
//! application data.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use compact_str::CompactString;
use tls_parser::{
    parse_tls_extensions, parse_tls_plaintext, TlsExtension, TlsMessage, TlsMessageHandshake,
};

use super::tls::is_tls_port;
use crate::format::names::tls_version_name;
use crate::schema::{DataKind, FieldDescriptor};
use crate::stream::OwnedFieldValue;
use crate::stream::{Direction, ParsedMessage, StreamContext, StreamParseResult, StreamParser};
use crate::tls::{
    extract_tls13_inner_content_type, Direction as TlsDirection, KeyLog, TlsSession, TlsVersion,
};

/// TLS content types.
mod content_type {
    pub const CHANGE_CIPHER_SPEC: u8 = 20;
    pub const ALERT: u8 = 21;
    pub const HANDSHAKE: u8 = 22;
    pub const APPLICATION_DATA: u8 = 23;
}

/// Handshake message types read from decrypted records.
mod handshake_type {
    pub const ENCRYPTED_EXTENSIONS: u8 = 8;
    pub const FINISHED: u8 = 20;
}

/// The parser of what a TLS connection carries.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Application {
    Http2,
    Http1,
    /// A protocol no stream parser reads.
    Other,
}

impl Application {
    /// The application an ALPN protocol id names.
    fn of_alpn(protocol: &str) -> Self {
        match protocol {
            "h2" => Application::Http2,
            "http/1.1" | "http/1.0" => Application::Http1,
            _ => Application::Other,
        }
    }

    /// The name of the stream parser, when there is one.
    fn parser(self) -> Option<&'static str> {
        match self {
            Application::Http2 => Some("http2"),
            Application::Http1 => Some("http"),
            Application::Other => None,
        }
    }
}

/// The HTTP/2 client connection preface, which a connection that
/// negotiated nothing is recognised by.
const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

fn index(direction: Direction) -> usize {
    match direction {
        Direction::ToServer => 0,
        Direction::ToClient => 1,
    }
}

/// Per-connection TLS state.
struct ConnectionTlsState {
    /// TLS session for decryption
    session: TlsSession,
    /// Whether each side (see [`index`]) has sent its ChangeCipherSpec:
    /// before TLS 1.3, everything it sends after that is protected.
    change_cipher_spec_seen: [bool; 2],
    /// The decrypted handshake messages of each side that are not complete
    /// yet: a message can span records.
    handshake: [Vec<u8>; 2],
    /// Whether the client offered `h2` (ALPN).
    client_offers_http2: bool,
    /// The protocol the server selected (ALPN), as an application.
    selected: Option<Application>,
    /// What the application data is parsed as, decided with the first of it.
    application: Option<Application>,
}

impl ConnectionTlsState {
    fn new(keylog: Arc<KeyLog>) -> Self {
        Self {
            session: TlsSession::new(keylog),
            change_cipher_spec_seen: [false; 2],
            handshake: [Vec::new(), Vec::new()],
            client_offers_http2: false,
            selected: None,
            application: None,
        }
    }

    /// Whether the record of type `record_type` that a side sends is
    /// protected: see the [module](self).
    fn is_protected(&self, direction: Direction, record_type: u8) -> bool {
        if self.session.handshake().effective_version() == Some(TlsVersion::Tls13) {
            record_type == content_type::APPLICATION_DATA
        } else {
            record_type == content_type::APPLICATION_DATA
                || (record_type != content_type::CHANGE_CIPHER_SPEC
                    && self.change_cipher_spec_seen[index(direction)])
        }
    }

    /// What the application data is, of which `data` from `direction` is
    /// the first: what the server selected; without that, HTTP/2 when the
    /// client starts with its preface or, the server speaking first, when
    /// the client offered it; else HTTP/1.
    fn application(&mut self, direction: Direction, data: &[u8]) -> Application {
        if let Some(application) = self.application {
            return application;
        }
        let http2 = match direction {
            Direction::ToServer => {
                let shared = data.len().min(HTTP2_PREFACE.len());
                data[..shared] == HTTP2_PREFACE[..shared]
            }
            Direction::ToClient => self.client_offers_http2,
        };
        let application = match self.selected {
            Some(selected) => selected,
            None if http2 => Application::Http2,
            None => Application::Http1,
        };
        self.application = Some(application);
        application
    }
}

/// TLS stream parser with decryption support.
///
/// When constructed with a `KeyLog`, this parser will attempt to decrypt
/// TLS application data and return it via `StreamParseResult::Transform`
/// for further parsing by child protocol parsers (HTTP/2, HTTP/1).
pub struct DecryptingTlsStreamParser {
    /// KeyLog for looking up TLS session keys
    keylog: Arc<KeyLog>,
    /// Per-connection TLS state
    sessions: Arc<Mutex<HashMap<u64, ConnectionTlsState>>>,
}

/// The fields of one record's message.
type Fields = HashMap<&'static str, OwnedFieldValue>;

impl DecryptingTlsStreamParser {
    /// Create a new decrypting TLS parser with the given keylog.
    pub fn new(keylog: KeyLog) -> Self {
        Self {
            keylog: Arc::new(keylog),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create from an already-wrapped keylog.
    pub fn with_keylog(keylog: Arc<KeyLog>) -> Self {
        Self {
            keylog,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Remove state for a closed connection.
    pub fn remove_connection(&self, connection_id: u64) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(&connection_id);
    }

    /// Convert stream Direction to TLS Direction.
    fn to_tls_direction(direction: Direction) -> TlsDirection {
        match direction {
            Direction::ToServer => TlsDirection::ClientToServer,
            Direction::ToClient => TlsDirection::ServerToClient,
        }
    }

    /// Process a handshake message that was sent in the clear.
    fn process_handshake(
        state: &mut ConnectionTlsState,
        handshake: &TlsMessageHandshake,
        fields: &mut Fields,
    ) {
        match handshake {
            TlsMessageHandshake::ClientHello(ch) => {
                // Extract client_random
                let mut client_random = [0u8; 32];
                client_random.copy_from_slice(ch.random);
                state.session.process_client_hello(client_random);

                fields.insert("handshake_type", OwnedFieldValue::Str("ClientHello"));

                // Extract SNI and ALPN from extensions
                if let Some(ext_data) = &ch.ext {
                    if let Ok((_, extensions)) = parse_tls_extensions(ext_data) {
                        for ext in extensions {
                            match ext {
                                TlsExtension::SNI(sni_list) => {
                                    for (name_type, name) in sni_list {
                                        if name_type.0 == 0 {
                                            // Host name
                                            if let Ok(sni) = std::str::from_utf8(name) {
                                                fields.insert(
                                                    "sni",
                                                    OwnedFieldValue::OwnedString(
                                                        CompactString::new(sni),
                                                    ),
                                                );
                                            }
                                        }
                                    }
                                }
                                TlsExtension::ALPN(alpn_list) => {
                                    let protocols: Vec<&str> = alpn_list
                                        .iter()
                                        .filter_map(|p| std::str::from_utf8(p).ok())
                                        .collect();
                                    state.client_offers_http2 = protocols.contains(&"h2");
                                    if !protocols.is_empty() {
                                        fields.insert(
                                            "alpn",
                                            OwnedFieldValue::OwnedString(CompactString::new(
                                                protocols.join(","),
                                            )),
                                        );
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }

            TlsMessageHandshake::ServerHello(sh) => {
                // Extract server_random and cipher suite
                let mut server_random = [0u8; 32];
                server_random.copy_from_slice(sh.random);

                let cipher_suite = sh.cipher.0;

                // Detect TLS version (check for TLS 1.3 via supported_versions extension)
                let extensions = sh
                    .ext
                    .and_then(|ext_data| parse_tls_extensions(ext_data).ok())
                    .map(|(_, extensions)| extensions)
                    .unwrap_or_default();
                let version = if selects_tls13(&extensions) {
                    TlsVersion::Tls13
                } else {
                    TlsVersion::from_wire(sh.version.0).unwrap_or(TlsVersion::Tls12)
                };
                // Before TLS 1.3 the server selects the protocol here.
                if let Some(selected) = selected_alpn(&extensions) {
                    state.selected = Some(selected);
                }

                // Try to establish keys (may fail if keys not in keylog)
                let _ = state
                    .session
                    .process_server_hello(server_random, cipher_suite, version);

                fields.insert("handshake_type", OwnedFieldValue::Str("ServerHello"));
                fields.insert("cipher_suite", OwnedFieldValue::UInt16(cipher_suite));
                fields.insert("server_version", OwnedFieldValue::UInt16(sh.version.0));
                // The negotiated version, which for TLS 1.3 is not the one
                // on the wire: `to_wire()` is the record layer's, 1.2.
                let selected = match version {
                    TlsVersion::Tls13 => 0x0304,
                    earlier => earlier.to_wire(),
                };
                fields.insert("selected_version", OwnedFieldValue::UInt16(selected));

                if let Some(name) = state.session.cipher_suite_name() {
                    fields.insert(
                        "cipher_suite_name",
                        OwnedFieldValue::OwnedString(CompactString::new(name)),
                    );
                }
            }

            _ => {
                // Other handshake messages don't affect our state
            }
        }
    }

    /// Process the decrypted content of a handshake record: the complete
    /// messages of the side's handshake stream so far.
    ///
    /// Read from them: the protocol a TLS 1.3 server selects
    /// (`EncryptedExtensions`), and `Finished`, after which a TLS 1.3 side
    /// changes keys.
    fn process_decrypted_handshake(
        state: &mut ConnectionTlsState,
        content: &[u8],
        direction: Direction,
    ) {
        let mut stream = std::mem::take(&mut state.handshake[index(direction)]);
        stream.extend_from_slice(content);
        let mut rest = stream.as_slice();
        while let [message_type, a, b, c, after @ ..] = rest {
            let length = u32::from_be_bytes([0, *a, *b, *c]) as usize;
            if after.len() < length {
                break;
            }
            let (body, after) = after.split_at(length);
            rest = after;
            match *message_type {
                handshake_type::ENCRYPTED_EXTENSIONS => {
                    // extensions<0..2^16-1>
                    let selected = body
                        .get(2..)
                        .and_then(|extensions| parse_tls_extensions(extensions).ok())
                        .and_then(|(_, extensions)| selected_alpn(&extensions));
                    if let Some(selected) = selected {
                        state.selected = Some(selected);
                    }
                }
                handshake_type::FINISHED => match direction {
                    Direction::ToClient => state.session.mark_server_finished(),
                    Direction::ToServer => state.session.mark_client_finished(),
                },
                _ => {}
            }
        }
        let consumed = stream.len() - rest.len();
        stream.drain(..consumed);
        state.handshake[index(direction)] = stream;
    }

    /// One record that is not protected: the handshake up to
    /// ChangeCipherSpec, and alerts before it.
    fn process_plain_record(
        state: &mut ConnectionTlsState,
        record: &[u8],
        direction: Direction,
        fields: &mut Fields,
    ) {
        let payload = &record[5..];
        match record[0] {
            content_type::HANDSHAKE => {
                fields.insert("record_type", OwnedFieldValue::Str("Handshake"));

                // Parse handshake using tls-parser
                if let Ok((_, record)) = parse_tls_plaintext(record) {
                    for msg in &record.msg {
                        if let TlsMessage::Handshake(hs) = msg {
                            Self::process_handshake(state, hs, fields);
                        }
                    }
                }
            }
            content_type::CHANGE_CIPHER_SPEC => {
                fields.insert("record_type", OwnedFieldValue::Str("ChangeCipherSpec"));
                state.change_cipher_spec_seen[index(direction)] = true;
            }
            content_type::ALERT => {
                fields.insert("record_type", OwnedFieldValue::Str("Alert"));
                insert_alert(payload, fields);
            }
            other => {
                fields.insert(
                    "record_type",
                    OwnedFieldValue::OwnedString(CompactString::new(format!("Unknown({other})"))),
                );
            }
        }
    }

    /// One protected record: decrypted when the session has its keys.
    /// Returns the application data it carries.
    fn process_protected_record(
        state: &mut ConnectionTlsState,
        record: &[u8],
        direction: Direction,
        fields: &mut Fields,
    ) -> Option<Vec<u8>> {
        let record_type = record[0];
        let payload = &record[5..];
        fields.insert(
            "record_type",
            OwnedFieldValue::Str(match record_type {
                content_type::HANDSHAKE => "Handshake",
                content_type::ALERT => "Alert",
                _ => "ApplicationData",
            }),
        );
        if !state.session.can_decrypt() {
            fields.insert(
                "encrypted_length",
                OwnedFieldValue::UInt16(payload.len() as u16),
            );
            return None;
        }
        let tls_direction = Self::to_tls_direction(direction);
        let mut plaintext = match state
            .session
            .decrypt_record(tls_direction, record_type, payload)
        {
            Ok(plaintext) => plaintext,
            Err(e) => {
                // Decryption failed - note it and continue
                fields.insert(
                    "decrypt_error",
                    OwnedFieldValue::OwnedString(CompactString::new(e.to_string())),
                );
                return None;
            }
        };
        fields.insert(
            "decrypted_length",
            OwnedFieldValue::UInt64(plaintext.len() as u64),
        );
        // What the record carries: in TLS 1.3 the type is the last byte
        // of the plaintext that is not padding.
        let content_type =
            if state.session.handshake().effective_version() == Some(TlsVersion::Tls13) {
                let (inner_type, content) = extract_tls13_inner_content_type(&plaintext)?;
                plaintext.truncate(content.len());
                inner_type
            } else {
                record_type
            };
        match content_type {
            content_type::HANDSHAKE => {
                Self::process_decrypted_handshake(state, &plaintext, direction);
                None
            }
            content_type::ALERT => {
                insert_alert(&plaintext, fields);
                None
            }
            content_type::APPLICATION_DATA => Some(plaintext),
            _ => None,
        }
    }
}

/// The level and description of an alert.
fn insert_alert(alert: &[u8], fields: &mut Fields) {
    if let [level, description, ..] = alert {
        fields.insert("alert_level", OwnedFieldValue::UInt8(*level));
        fields.insert("alert_description", OwnedFieldValue::UInt8(*description));
    }
}

/// Whether a ServerHello's extensions select TLS 1.3 (supported_versions).
fn selects_tls13(extensions: &[TlsExtension]) -> bool {
    extensions.iter().any(|extension| {
        matches!(extension, TlsExtension::SupportedVersions(versions)
            if versions.iter().any(|version| version.0 == 0x0304))
    })
}

/// The protocol a server's extensions select (ALPN), as an application.
fn selected_alpn(extensions: &[TlsExtension]) -> Option<Application> {
    extensions.iter().find_map(|extension| match extension {
        TlsExtension::ALPN(protocols) => protocols
            .first()
            .and_then(|protocol| std::str::from_utf8(protocol).ok())
            .map(Application::of_alpn),
        _ => None,
    })
}

impl StreamParser for DecryptingTlsStreamParser {
    fn name(&self) -> &'static str {
        "tls_decrypt"
    }

    fn display_name(&self) -> &'static str {
        "TLS (Decrypting)"
    }

    fn can_parse_stream(&self, context: &StreamContext) -> bool {
        is_tls_port(context.dst_port) || is_tls_port(context.src_port)
    }

    fn parse_stream(&self, data: &[u8], context: &StreamContext) -> StreamParseResult {
        let mut sessions = self.sessions.lock().unwrap();
        let state = sessions
            .entry(context.connection_id)
            .or_insert_with(|| ConnectionTlsState::new(Arc::clone(&self.keylog)));

        let mut messages = Vec::new();
        let mut decrypted_data = Vec::new();
        // The complete records of `data`: the caller keeps what is not
        // consumed and gives it again with what follows.
        let mut rest = data;
        while let [record_type, major, minor, high, low, after @ ..] = rest {
            let length = u16::from_be_bytes([*high, *low]) as usize;
            if after.len() < length {
                break; // Incomplete record
            }
            let (record, after) = rest.split_at(5 + length);
            rest = after;

            let mut fields = HashMap::new();
            let version = u16::from_be_bytes([*major, *minor]);
            fields.insert("version", tls_version_name(version).into());

            if state.is_protected(context.direction, *record_type) {
                let application =
                    Self::process_protected_record(state, record, context.direction, &mut fields);
                if let Some(application) = application {
                    decrypted_data.extend_from_slice(&application);
                }
            } else {
                Self::process_plain_record(state, record, context.direction, &mut fields);
            }

            // Create message for this record
            let message = ParsedMessage {
                protocol: "tls",
                connection_id: context.connection_id,
                message_id: context.messages_parsed as u32 + messages.len() as u32,
                direction: context.direction,
                frame_number: 0, // Will be set by manager
                fields,
            };
            messages.push(message);
        }
        let bytes_consumed = data.len() - rest.len();

        if bytes_consumed == 0 {
            // No complete record yet
            return StreamParseResult::NeedMore {
                minimum_bytes: Some(5), // At least record header
            };
        }
        let child_protocol = if decrypted_data.is_empty() {
            None
        } else {
            state
                .application(context.direction, &decrypted_data)
                .parser()
        };
        match child_protocol {
            // Decrypted data of a protocol with a parser
            Some(child_protocol) => StreamParseResult::Transform {
                child_protocol,
                child_data: decrypted_data,
                bytes_consumed,
                messages,
            },
            None => StreamParseResult::Complete {
                messages,
                bytes_consumed,
            },
        }
    }

    fn message_schema(&self) -> Vec<FieldDescriptor> {
        vec![
            FieldDescriptor::new("connection_id", DataKind::UInt64),
            FieldDescriptor::new("record_type", DataKind::String).set_nullable(true),
            FieldDescriptor::new("version", DataKind::String).set_nullable(true),
            FieldDescriptor::new("handshake_type", DataKind::String).set_nullable(true),
            FieldDescriptor::new("sni", DataKind::String).set_nullable(true),
            FieldDescriptor::new("alpn", DataKind::String).set_nullable(true),
            FieldDescriptor::new("cipher_suite", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("cipher_suite_name", DataKind::String).set_nullable(true),
            FieldDescriptor::new("decrypted_length", DataKind::UInt64).set_nullable(true),
            FieldDescriptor::new("encrypted_length", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("decrypt_error", DataKind::String).set_nullable(true),
            FieldDescriptor::new("alert_level", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("alert_description", DataKind::UInt8).set_nullable(true),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_context() -> StreamContext {
        StreamContext {
            connection_id: 1,
            direction: Direction::ToServer,
            src_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            src_port: 54321,
            dst_port: 443,
            bytes_parsed: 0,
            messages_parsed: 0,
            alpn: None,
        }
    }

    fn empty_keylog() -> KeyLog {
        KeyLog::new()
    }

    #[test]
    fn test_is_tls_port() {
        assert!(is_tls_port(443));
        assert!(is_tls_port(8443));
        assert!(is_tls_port(993));
        assert!(!is_tls_port(80));
        assert!(!is_tls_port(22));
    }

    #[test]
    fn test_can_parse_stream() {
        let parser = DecryptingTlsStreamParser::new(empty_keylog());
        let ctx = test_context();
        assert!(parser.can_parse_stream(&ctx));

        let mut ctx_http = ctx.clone();
        ctx_http.dst_port = 80;
        ctx_http.src_port = 54321;
        assert!(!parser.can_parse_stream(&ctx_http));
    }

    #[test]
    fn test_parse_incomplete_record() {
        let parser = DecryptingTlsStreamParser::new(empty_keylog());
        let ctx = test_context();

        // Only 3 bytes - not enough for header
        let data = vec![22, 3, 3];
        let result = parser.parse_stream(&data, &ctx);

        assert!(matches!(result, StreamParseResult::NeedMore { .. }));
    }

    #[test]
    fn test_parse_handshake_record() {
        let parser = DecryptingTlsStreamParser::new(empty_keylog());
        let ctx = test_context();

        // Build a minimal ClientHello-like handshake record
        let mut record = vec![
            22, // Handshake
            3, 3, // TLS 1.2
            0, 44, // Length (44 bytes)
            1,  // ClientHello type
            0, 0, 40, // Handshake length (40 bytes)
            3, 3, // Client version
        ];
        // Random (32 bytes)
        record.extend_from_slice(&[0u8; 32]);
        // Session ID length (0)
        record.push(0);
        // Cipher suites length (2) + one suite
        record.extend_from_slice(&[0, 2, 0, 0xff]);
        // Compression methods length (1) + null
        record.extend_from_slice(&[1, 0]);

        let result = parser.parse_stream(&record, &ctx);

        match result {
            StreamParseResult::Complete {
                messages,
                bytes_consumed,
            } => {
                assert_eq!(bytes_consumed, 49); // 5 + 44
                assert_eq!(messages.len(), 1);
                assert_eq!(messages[0].protocol, "tls");
            }
            _ => panic!("Expected Complete, got {:?}", result),
        }
    }

    #[test]
    fn test_parse_application_data_without_keys() {
        let parser = DecryptingTlsStreamParser::new(empty_keylog());
        let ctx = test_context();

        // Application data record
        let record = vec![
            23, // ApplicationData
            3, 3, // TLS 1.2
            0, 10, // Length
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, // Encrypted data
        ];

        let result = parser.parse_stream(&record, &ctx);

        match result {
            StreamParseResult::Complete {
                messages,
                bytes_consumed,
            } => {
                assert_eq!(bytes_consumed, 15);
                assert_eq!(messages.len(), 1);
                assert!(messages[0].fields.contains_key("encrypted_length"));
            }
            _ => panic!("Expected Complete, got {:?}", result),
        }
    }

    #[test]
    fn test_parse_alert_record() {
        let parser = DecryptingTlsStreamParser::new(empty_keylog());
        let ctx = test_context();

        // Alert record
        let record = vec![
            21, // Alert
            3, 3, // TLS 1.2
            0, 2, // Length
            1, 0, // Warning, close_notify
        ];

        let result = parser.parse_stream(&record, &ctx);

        match result {
            StreamParseResult::Complete { messages, .. } => {
                assert_eq!(messages.len(), 1);
                assert_eq!(
                    messages[0].fields.get("alert_level"),
                    Some(&OwnedFieldValue::UInt8(1))
                );
            }
            _ => panic!("Expected Complete"),
        }
    }

    #[test]
    fn test_multiple_records() {
        let parser = DecryptingTlsStreamParser::new(empty_keylog());
        let ctx = test_context();

        // Two small records
        let data = vec![
            // First record (ChangeCipherSpec)
            20, 3, 3, 0, 1, 1, // Second record (ApplicationData)
            23, 3, 3, 0, 5, 1, 2, 3, 4, 5,
        ];

        let result = parser.parse_stream(&data, &ctx);

        match result {
            StreamParseResult::Complete {
                messages,
                bytes_consumed,
            } => {
                assert_eq!(bytes_consumed, 16); // 6 + 10
                assert_eq!(messages.len(), 2);
            }
            _ => panic!("Expected Complete"),
        }
    }

    #[test]
    fn test_to_tls_direction() {
        assert_eq!(
            DecryptingTlsStreamParser::to_tls_direction(Direction::ToServer),
            TlsDirection::ClientToServer
        );
        assert_eq!(
            DecryptingTlsStreamParser::to_tls_direction(Direction::ToClient),
            TlsDirection::ServerToClient
        );
    }
}
