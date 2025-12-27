//! TLS stream parser with decryption support.
//!
//! This parser extends the basic TLS metadata extraction with actual decryption
//! of TLS records when SSLKEYLOGFILE keys are available.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::BytesMut;
use compact_str::CompactString;
use tls_parser::{
    parse_tls_extensions, parse_tls_plaintext, TlsExtension, TlsMessage, TlsMessageHandshake,
};

use crate::protocol::{FieldValue, OwnedFieldValue};
use crate::schema::{DataKind, FieldDescriptor};
use crate::stream::{Direction, ParsedMessage, StreamContext, StreamParseResult, StreamParser};
use crate::tls::{extract_tls13_inner_content_type, KeyLog, TlsSession, TlsVersion, Direction as TlsDirection};

/// Standard TLS ports.
const TLS_PORTS: &[u16] = &[
    443,   // HTTPS
    8443,  // HTTPS alternate
    993,   // IMAPS
    995,   // POP3S
    465,   // SMTPS (submission)
    636,   // LDAPS
    853,   // DNS over TLS
    5061,  // SIP over TLS
    14433, // Test port (used by testdata/tls/)
];

/// Check if a port is commonly used for TLS.
fn is_tls_port(port: u16) -> bool {
    TLS_PORTS.contains(&port)
}

/// Per-connection TLS state.
struct ConnectionTlsState {
    /// TLS session for decryption
    session: TlsSession,
    /// Buffer for incomplete TLS records
    buffer: BytesMut,
    /// Whether handshake is complete
    handshake_complete: bool,
    /// Track if we've seen ChangeCipherSpec (TLS 1.2)
    change_cipher_spec_seen: bool,
}

impl ConnectionTlsState {
    fn new(keylog: Arc<KeyLog>) -> Self {
        Self {
            session: TlsSession::new(keylog),
            buffer: BytesMut::new(),
            handshake_complete: false,
            change_cipher_spec_seen: false,
        }
    }
}

/// TLS stream parser with decryption support.
///
/// When constructed with a `KeyLog`, this parser will attempt to decrypt
/// TLS application data and return it via `StreamParseResult::Transform`
/// for further parsing by child protocol parsers (e.g., HTTP/2).
pub struct DecryptingTlsStreamParser {
    /// KeyLog for looking up TLS session keys
    keylog: Arc<KeyLog>,
    /// Per-connection TLS state
    sessions: Arc<Mutex<HashMap<u64, ConnectionTlsState>>>,
}

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

    /// Get or create TLS state for a connection.
    fn get_or_create_state(&self, connection_id: u64) -> ConnectionTlsState {
        let mut sessions = self.sessions.lock().unwrap();
        sessions
            .entry(connection_id)
            .or_insert_with(|| ConnectionTlsState::new(Arc::clone(&self.keylog)))
            .clone_state()
    }

    /// Update state after processing.
    fn update_state(&self, connection_id: u64, state: ConnectionTlsState) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(connection_id, state);
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

    /// Process a TLS handshake message.
    fn process_handshake(
        state: &mut ConnectionTlsState,
        handshake: &TlsMessageHandshake,
        _direction: Direction,
        fields: &mut HashMap<&'static str, OwnedFieldValue>,
    ) {
        match handshake {
            TlsMessageHandshake::ClientHello(ch) => {
                // Extract client_random
                let mut client_random = [0u8; 32];
                client_random.copy_from_slice(ch.random);
                state.session.process_client_hello(client_random);

                fields.insert(
                    "handshake_type",
                    FieldValue::Str("ClientHello"),
                );

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
                                                    FieldValue::OwnedString(CompactString::new(sni)),
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
                                    if !protocols.is_empty() {
                                        fields.insert(
                                            "alpn",
                                            FieldValue::OwnedString(CompactString::new(
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
                let version = if let Some(ext_data) = &sh.ext {
                    detect_tls13_from_extensions(ext_data).unwrap_or_else(|| {
                        TlsVersion::from_wire(sh.version.0).unwrap_or(TlsVersion::Tls12)
                    })
                } else {
                    TlsVersion::from_wire(sh.version.0).unwrap_or(TlsVersion::Tls12)
                };

                // Try to establish keys (may fail if keys not in keylog)
                let _ = state
                    .session
                    .process_server_hello(server_random, cipher_suite, version);

                fields.insert(
                    "handshake_type",
                    FieldValue::Str("ServerHello"),
                );
                fields.insert(
                    "cipher_suite",
                    FieldValue::UInt16(cipher_suite),
                );

                if let Some(name) = state.session.cipher_suite_name() {
                    fields.insert(
                        "cipher_suite_name",
                        FieldValue::OwnedString(CompactString::new(name)),
                    );
                }
            }

            _ => {
                // Other handshake messages don't affect our state
            }
        }
    }

    /// Process TLS 1.3 encrypted handshake messages.
    ///
    /// Parses the decrypted handshake data to detect Finished messages
    /// and update the session state machine.
    fn process_encrypted_handshake(
        state: &mut ConnectionTlsState,
        handshake_data: &[u8],
        direction: Direction,
        fields: &mut HashMap<&'static str, OwnedFieldValue>,
    ) {
        // Parse handshake message header (type + length)
        if handshake_data.len() < 4 {
            return;
        }

        let hs_type = handshake_data[0];
        let _hs_len = u32::from_be_bytes([0, handshake_data[1], handshake_data[2], handshake_data[3]]) as usize;

        let hs_type_name = match hs_type {
            1 => "ClientHello",
            2 => "ServerHello",
            4 => "NewSessionTicket",
            8 => "EncryptedExtensions",
            11 => "Certificate",
            13 => "CertificateRequest",
            15 => "CertificateVerify",
            20 => "Finished",
            24 => "KeyUpdate",
            _ => "Unknown",
        };

        fields.insert(
            "encrypted_hs_type",
            FieldValue::OwnedString(CompactString::new(hs_type_name)),
        );

        // Handle Finished message - this signals key transition
        if hs_type == 20 {
            // Finished message
            match direction {
                Direction::ToClient => {
                    // Server finished
                    state.session.mark_server_finished();
                    fields.insert(
                        "hs_finished",
                        FieldValue::Str("server"),
                    );
                }
                Direction::ToServer => {
                    // Client finished - this triggers transition to application data
                    state.session.mark_client_finished();
                    state.handshake_complete = true;
                    fields.insert(
                        "hs_finished",
                        FieldValue::Str("client"),
                    );
                }
            }
        }
    }
}

/// Detect TLS 1.3 from ServerHello extensions.
fn detect_tls13_from_extensions(ext_data: &[u8]) -> Option<TlsVersion> {
    if let Ok((_, extensions)) = parse_tls_extensions(ext_data) {
        for ext in extensions {
            if let TlsExtension::SupportedVersions(versions) = ext {
                // Check if any version is TLS 1.3 (0x0304)
                for v in versions {
                    if v.0 == 0x0304 {
                        return Some(TlsVersion::Tls13);
                    }
                }
            }
        }
    }
    None
}

impl ConnectionTlsState {
    /// Clone state for processing (needed due to borrow checker)
    fn clone_state(&self) -> Self {
        // We can't truly clone TlsSession, so we create a lightweight view
        // For now, we'll use a different approach - keep state in Arc<Mutex<>>
        // and modify in place
        panic!("clone_state should not be called - use Arc<Mutex<>> directly")
    }
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

        // Append new data to buffer
        state.buffer.extend_from_slice(data);

        let mut messages = Vec::new();
        let mut decrypted_data = Vec::new();
        let mut total_consumed = 0;

        // Process complete TLS records
        loop {
            if state.buffer.len() < 5 {
                break; // Need at least record header
            }

            // Parse record header
            let content_type = state.buffer[0];
            let version = u16::from_be_bytes([state.buffer[1], state.buffer[2]]);
            let length = u16::from_be_bytes([state.buffer[3], state.buffer[4]]) as usize;
            let record_len = 5 + length;

            if state.buffer.len() < record_len {
                break; // Incomplete record
            }

            // Extract record payload
            let record_data = state.buffer[..record_len].to_vec();
            let payload = &record_data[5..];

            let mut fields = HashMap::new();
            fields.insert(
                "version",
                FieldValue::OwnedString(CompactString::new(version_name(version))),
            );

            match content_type {
                22 => {
                    // Handshake
                    fields.insert("record_type", FieldValue::Str("Handshake"));

                    // Parse handshake using tls-parser
                    if let Ok((_, record)) = parse_tls_plaintext(&record_data) {
                        for msg in &record.msg {
                            if let TlsMessage::Handshake(hs) = msg {
                                Self::process_handshake(
                                    state,
                                    hs,
                                    context.direction,
                                    &mut fields,
                                );
                            }
                        }
                    }
                }

                23 => {
                    // ApplicationData (in TLS 1.3, this can also be encrypted handshake)
                    fields.insert(
                        "record_type",
                        FieldValue::Str("ApplicationData"),
                    );

                    // Try to decrypt if session is ready
                    if state.session.can_decrypt() {
                        let tls_dir = Self::to_tls_direction(context.direction);
                        match state.session.decrypt_record(tls_dir, content_type, payload) {
                            Ok(plaintext) => {
                                // For TLS 1.3, extract the inner content type
                                if state.session.is_tls13_handshake_phase() {
                                    // During handshake phase, process inner content
                                    if let Some((inner_type, inner_data)) = extract_tls13_inner_content_type(&plaintext) {
                                        fields.insert(
                                            "inner_content_type",
                                            FieldValue::UInt8(inner_type),
                                        );

                                        if inner_type == 22 {
                                            // Inner handshake message
                                            Self::process_encrypted_handshake(
                                                state,
                                                inner_data,
                                                context.direction,
                                                &mut fields,
                                            );
                                        } else if inner_type == 23 {
                                            // Actual application data during handshake (rare)
                                            decrypted_data.extend_from_slice(inner_data);
                                        }
                                    }
                                } else {
                                    // In application data mode, extract inner content for TLS 1.3
                                    // or use directly for TLS 1.2
                                    let version = state.session.handshake().effective_version();
                                    if version == Some(TlsVersion::Tls13) {
                                        if let Some((inner_type, inner_data)) = extract_tls13_inner_content_type(&plaintext) {
                                            if inner_type == 23 {
                                                decrypted_data.extend_from_slice(inner_data);
                                            }
                                            // Handle post-handshake messages (NewSessionTicket, etc.)
                                            else if inner_type == 22 {
                                                fields.insert(
                                                    "inner_content_type",
                                                    FieldValue::UInt8(inner_type),
                                                );
                                            }
                                        }
                                    } else {
                                        // TLS 1.2 - plaintext is the actual data
                                        decrypted_data.extend_from_slice(&plaintext);
                                    }
                                }

                                fields.insert(
                                    "decrypted_length",
                                    FieldValue::UInt64(plaintext.len() as u64),
                                );
                            }
                            Err(e) => {
                                // Decryption failed - log but continue
                                fields.insert(
                                    "decrypt_error",
                                    FieldValue::OwnedString(CompactString::new(e.to_string())),
                                );
                            }
                        }
                    } else {
                        fields.insert(
                            "encrypted_length",
                            FieldValue::UInt16(length as u16),
                        );
                    }
                }

                20 => {
                    // ChangeCipherSpec
                    fields.insert(
                        "record_type",
                        FieldValue::Str("ChangeCipherSpec"),
                    );
                    state.change_cipher_spec_seen = true;
                }

                21 => {
                    // Alert
                    fields.insert("record_type", FieldValue::Str("Alert"));
                    if payload.len() >= 2 {
                        fields.insert("alert_level", FieldValue::UInt8(payload[0]));
                        fields.insert(
                            "alert_description",
                            FieldValue::UInt8(payload[1]),
                        );
                    }
                }

                _ => {
                    // Unknown content type
                    fields.insert(
                        "record_type",
                        FieldValue::OwnedString(CompactString::new(format!("Unknown({})", content_type))),
                    );
                }
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

            // Consume this record from buffer
            state.buffer = state.buffer.split_off(record_len);
            total_consumed += record_len;
        }

        // Decide what to return
        if !decrypted_data.is_empty() {
            // We have decrypted data - transform to child protocol
            // Guess child protocol based on ALPN or default to http2
            let child_protocol = "http2"; // TODO: detect from ALPN

            // Return first TLS message as metadata, transform for child parsing
            let metadata = if !messages.is_empty() {
                Some(messages.remove(0))
            } else {
                None
            };

            StreamParseResult::Transform {
                child_protocol,
                child_data: decrypted_data,
                bytes_consumed: total_consumed,
                metadata,
            }
        } else if !messages.is_empty() {
            // Have TLS messages but no decrypted data
            StreamParseResult::Complete {
                messages,
                bytes_consumed: total_consumed,
            }
        } else if total_consumed == 0 {
            // No complete records yet
            StreamParseResult::NeedMore {
                minimum_bytes: Some(5), // At least record header
            }
        } else {
            StreamParseResult::Complete {
                messages: vec![],
                bytes_consumed: total_consumed,
            }
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

/// Get human-readable TLS version name.
fn version_name(version: u16) -> &'static str {
    match version {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "Unknown",
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
            22,   // Handshake
            3, 3, // TLS 1.2
            0, 44, // Length (44 bytes)
            1,    // ClientHello type
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
            23,   // ApplicationData
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
            21,   // Alert
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
                    Some(&FieldValue::UInt8(1))
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
        let mut data = vec![
            // First record (ChangeCipherSpec)
            20, 3, 3, 0, 1, 1,
            // Second record (ApplicationData)
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

    #[test]
    fn test_version_name() {
        assert_eq!(version_name(0x0301), "TLS 1.0");
        assert_eq!(version_name(0x0303), "TLS 1.2");
        assert_eq!(version_name(0x0304), "TLS 1.3");
        assert_eq!(version_name(0x0000), "Unknown");
    }
}
