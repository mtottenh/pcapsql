use std::collections::HashMap;

use compact_str::CompactString;

use crate::protocol::{FieldValue, OwnedFieldValue};
use crate::schema::{DataKind, FieldDescriptor};
use crate::stream::{ParsedMessage, StreamContext, StreamParseResult, StreamParser};

/// TLS content types.
#[allow(dead_code)]
mod content_type {
    pub const CHANGE_CIPHER_SPEC: u8 = 20;
    pub const ALERT: u8 = 21;
    pub const HANDSHAKE: u8 = 22;
    pub const APPLICATION_DATA: u8 = 23;
}

/// TLS handshake types.
#[allow(dead_code)]
mod handshake_type {
    pub const CLIENT_HELLO: u8 = 1;
    pub const SERVER_HELLO: u8 = 2;
    pub const CERTIFICATE: u8 = 11;
    pub const SERVER_KEY_EXCHANGE: u8 = 12;
    pub const CERTIFICATE_REQUEST: u8 = 13;
    pub const SERVER_HELLO_DONE: u8 = 14;
    pub const CERTIFICATE_VERIFY: u8 = 15;
    pub const CLIENT_KEY_EXCHANGE: u8 = 16;
    pub const FINISHED: u8 = 20;
}

/// TLS stream parser (metadata extraction only, no decryption).
#[derive(Debug, Clone, Copy, Default)]
pub struct TlsStreamParser;

impl TlsStreamParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse a TLS record header.
    fn parse_record_header(data: &[u8]) -> Option<(u8, u16, u16)> {
        if data.len() < 5 {
            return None;
        }
        let content_type = data[0];
        let version = u16::from_be_bytes([data[1], data[2]]);
        let length = u16::from_be_bytes([data[3], data[4]]);
        Some((content_type, version, length))
    }

    /// Extract SNI from ClientHello extension.
    fn extract_sni(extensions: &[u8]) -> Option<String> {
        let mut pos = 0;
        while pos + 4 <= extensions.len() {
            let ext_type = u16::from_be_bytes([extensions[pos], extensions[pos + 1]]);
            let ext_len = u16::from_be_bytes([extensions[pos + 2], extensions[pos + 3]]) as usize;
            pos += 4;

            if pos + ext_len > extensions.len() {
                break;
            }

            if ext_type == 0 {
                // SNI extension
                let ext_data = &extensions[pos..pos + ext_len];
                if ext_data.len() >= 5 {
                    let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
                    if ext_data.len() >= 5 + name_len {
                        if let Ok(sni) = std::str::from_utf8(&ext_data[5..5 + name_len]) {
                            return Some(sni.to_string());
                        }
                    }
                }
            }

            pos += ext_len;
        }
        None
    }

    /// Extract ALPN from extensions.
    fn extract_alpn(extensions: &[u8]) -> Option<String> {
        let mut pos = 0;
        while pos + 4 <= extensions.len() {
            let ext_type = u16::from_be_bytes([extensions[pos], extensions[pos + 1]]);
            let ext_len = u16::from_be_bytes([extensions[pos + 2], extensions[pos + 3]]) as usize;
            pos += 4;

            if pos + ext_len > extensions.len() {
                break;
            }

            if ext_type == 16 {
                // ALPN extension
                let ext_data = &extensions[pos..pos + ext_len];
                if ext_data.len() >= 3 {
                    let proto_len = ext_data[2] as usize;
                    if ext_data.len() >= 3 + proto_len {
                        if let Ok(alpn) = std::str::from_utf8(&ext_data[3..3 + proto_len]) {
                            return Some(alpn.to_string());
                        }
                    }
                }
            }

            pos += ext_len;
        }
        None
    }

    /// Parse ClientHello message.
    fn parse_client_hello(&self, data: &[u8]) -> HashMap<&'static str, OwnedFieldValue> {
        let mut fields = HashMap::new();
        fields.insert(
            "handshake_type",
            FieldValue::Str("ClientHello"),
        );

        if data.len() < 38 {
            return fields;
        }

        // Client version (2 bytes)
        let version = u16::from_be_bytes([data[0], data[1]]);
        fields.insert("client_version", FieldValue::UInt16(version));

        // Skip random (32 bytes) and session ID
        let mut pos = 34;
        if pos >= data.len() {
            return fields;
        }
        let session_id_len = data[pos] as usize;
        pos += 1 + session_id_len;

        // Cipher suites
        if pos + 2 > data.len() {
            return fields;
        }
        let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if pos + cipher_suites_len > data.len() {
            return fields;
        }
        let cipher_count = cipher_suites_len / 2;
        fields.insert(
            "cipher_suite_count",
            FieldValue::UInt16(cipher_count as u16),
        );
        pos += cipher_suites_len;

        // Skip compression methods
        if pos >= data.len() {
            return fields;
        }
        let comp_len = data[pos] as usize;
        pos += 1 + comp_len;

        // Extensions
        if pos + 2 > data.len() {
            return fields;
        }
        let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if pos + ext_len <= data.len() {
            let extensions = &data[pos..pos + ext_len];
            if let Some(sni) = Self::extract_sni(extensions) {
                fields.insert("sni", FieldValue::OwnedString(CompactString::new(sni)));
            }
            if let Some(alpn) = Self::extract_alpn(extensions) {
                fields.insert("alpn", FieldValue::OwnedString(CompactString::new(alpn)));
            }
        }

        fields
    }

    /// Parse ServerHello message.
    fn parse_server_hello(&self, data: &[u8]) -> HashMap<&'static str, OwnedFieldValue> {
        let mut fields = HashMap::new();
        fields.insert(
            "handshake_type",
            FieldValue::Str("ServerHello"),
        );

        if data.len() < 38 {
            return fields;
        }

        // Server version
        let version = u16::from_be_bytes([data[0], data[1]]);
        fields.insert("server_version", FieldValue::UInt16(version));

        // Skip random (32 bytes) and session ID
        let mut pos = 34;
        if pos >= data.len() {
            return fields;
        }
        let session_id_len = data[pos] as usize;
        pos += 1 + session_id_len;

        // Selected cipher suite
        if pos + 2 <= data.len() {
            let cipher = u16::from_be_bytes([data[pos], data[pos + 1]]);
            fields.insert("cipher_suite", FieldValue::UInt16(cipher));
            fields.insert(
                "cipher_suite_name",
                FieldValue::OwnedString(CompactString::new(cipher_suite_name(cipher))),
            );
        }

        fields
    }

    /// Get TLS version name.
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
}

fn cipher_suite_name(id: u16) -> String {
    match id {
        0x1301 => "TLS_AES_128_GCM_SHA256".to_string(),
        0x1302 => "TLS_AES_256_GCM_SHA384".to_string(),
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256".to_string(),
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
        _ => format!("0x{id:04x}"),
    }
}

impl StreamParser for TlsStreamParser {
    fn name(&self) -> &'static str {
        "tls"
    }

    fn display_name(&self) -> &'static str {
        "TLS"
    }

    fn can_parse_stream(&self, context: &StreamContext) -> bool {
        context.dst_port == 443 || context.src_port == 443
    }

    fn parse_stream(&self, data: &[u8], context: &StreamContext) -> StreamParseResult {
        // Parse TLS record header
        let (content_type, version, length) = match Self::parse_record_header(data) {
            Some(header) => header,
            None => {
                return StreamParseResult::NeedMore {
                    minimum_bytes: Some(5),
                }
            }
        };

        let record_len = 5 + length as usize;
        if data.len() < record_len {
            return StreamParseResult::NeedMore {
                minimum_bytes: Some(record_len),
            };
        }

        let mut fields = HashMap::new();
        fields.insert(
            "version",
            FieldValue::Str(Self::version_name(version)),
        );
        fields.insert("version_raw", FieldValue::UInt16(version));

        match content_type {
            content_type::HANDSHAKE => {
                let handshake_data = &data[5..record_len];
                if handshake_data.len() >= 4 {
                    let hs_type = handshake_data[0];
                    let hs_len = ((handshake_data[1] as usize) << 16)
                        | ((handshake_data[2] as usize) << 8)
                        | (handshake_data[3] as usize);

                    if handshake_data.len() >= 4 + hs_len {
                        let hs_body = &handshake_data[4..4 + hs_len];

                        let hs_fields = match hs_type {
                            handshake_type::CLIENT_HELLO => self.parse_client_hello(hs_body),
                            handshake_type::SERVER_HELLO => self.parse_server_hello(hs_body),
                            _ => {
                                let mut f = HashMap::new();
                                f.insert(
                                    "handshake_type_id",
                                    FieldValue::UInt8(hs_type),
                                );
                                f
                            }
                        };

                        fields.extend(hs_fields);
                    }
                }

                fields.insert(
                    "record_type",
                    FieldValue::Str("Handshake"),
                );
            }

            content_type::APPLICATION_DATA => {
                fields.insert(
                    "record_type",
                    FieldValue::Str("ApplicationData"),
                );
                fields.insert("encrypted_length", FieldValue::UInt16(length));
            }

            content_type::ALERT => {
                fields.insert(
                    "record_type",
                    FieldValue::Str("Alert"),
                );
            }

            content_type::CHANGE_CIPHER_SPEC => {
                fields.insert(
                    "record_type",
                    FieldValue::Str("ChangeCipherSpec"),
                );
            }

            _ => {
                return StreamParseResult::NotThisProtocol;
            }
        }

        let message = ParsedMessage {
            protocol: "tls",
            connection_id: context.connection_id,
            message_id: context.messages_parsed as u32,
            direction: context.direction,
            frame_number: 0,
            fields,
        };

        StreamParseResult::Complete {
            messages: vec![message],
            bytes_consumed: record_len,
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
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::Direction;
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

    // Test 1: TLS record parsing
    #[test]
    fn test_record_header() {
        let header = TlsStreamParser::parse_record_header(&[22, 3, 3, 0, 5]);
        assert_eq!(header, Some((22, 0x0303, 5)));
    }

    // Test 2: ClientHello parsing (simplified)
    #[test]
    fn test_client_hello_parsing() {
        let parser = TlsStreamParser::new();

        // Build ClientHello body first to calculate lengths
        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&[3, 3]); // Version
        hs_body.extend_from_slice(&[0u8; 32]); // Random
        hs_body.push(0); // Session ID length
        hs_body.extend_from_slice(&[0, 2, 0, 0]); // Cipher suites length (2) + 1 suite
        hs_body.push(1); // Compression methods length
        hs_body.push(0); // null compression
        hs_body.extend_from_slice(&[0, 0]); // Extensions length

        let hs_len = hs_body.len();
        let record_len = 1 + 3 + hs_len; // type + length + body

        let mut record = vec![
            22,                          // Handshake
            3, 3,                        // TLS 1.2
            (record_len >> 8) as u8,     // Length high
            (record_len & 0xff) as u8,   // Length low
            1,                           // ClientHello
            0,                           // Handshake length high
            (hs_len >> 8) as u8,         // Handshake length mid
            (hs_len & 0xff) as u8,       // Handshake length low
        ];
        record.extend_from_slice(&hs_body);

        let result = parser.parse_stream(&record, &test_context());
        match result {
            StreamParseResult::Complete { messages, .. } => {
                assert!(messages[0].fields.contains_key("handshake_type"));
            }
            _ => panic!("Expected Complete"),
        }
    }

    // Test 3: ServerHello parsing
    #[test]
    fn test_server_hello() {
        let parser = TlsStreamParser::new();

        // Build ServerHello body first to calculate lengths
        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&[3, 3]); // Version
        hs_body.extend_from_slice(&[0u8; 32]); // Random
        hs_body.push(0); // Session ID length
        hs_body.extend_from_slice(&[0xc0, 0x2f]); // Cipher suite
        hs_body.push(0); // Compression

        let hs_len = hs_body.len();
        let record_len = 1 + 3 + hs_len; // type + length + body

        let mut record = vec![
            22,                          // Handshake
            3, 3,                        // TLS 1.2
            (record_len >> 8) as u8,     // Length high
            (record_len & 0xff) as u8,   // Length low
            2,                           // ServerHello
            0,                           // Handshake length high
            (hs_len >> 8) as u8,         // Handshake length mid
            (hs_len & 0xff) as u8,       // Handshake length low
        ];
        record.extend_from_slice(&hs_body);

        let mut ctx = test_context();
        ctx.direction = Direction::ToClient;

        let result = parser.parse_stream(&record, &ctx);
        match result {
            StreamParseResult::Complete { messages, .. } => {
                assert!(messages[0].fields.contains_key("cipher_suite"));
            }
            _ => panic!("Expected Complete"),
        }
    }

    // Test 4: Certificate record
    #[test]
    fn test_certificate_record() {
        let parser = TlsStreamParser::new();

        let record = vec![
            22, 3, 3, 0, 4, // Handshake record, 4 bytes
            11, // Certificate type
            0, 0, 0, // Length 0 (empty cert for test)
        ];

        let result = parser.parse_stream(&record, &test_context());
        match result {
            StreamParseResult::Complete { .. } => {}
            _ => panic!("Expected Complete"),
        }
    }

    // Test 5: Incomplete record (NeedMore)
    #[test]
    fn test_incomplete_record() {
        let parser = TlsStreamParser::new();

        // Record says 100 bytes but we only have 10
        let record = vec![22, 3, 3, 0, 100, 1, 2, 3, 4, 5];

        let result = parser.parse_stream(&record, &test_context());
        match result {
            StreamParseResult::NeedMore { minimum_bytes } => {
                assert_eq!(minimum_bytes, Some(105)); // 5 header + 100 payload
            }
            _ => panic!("Expected NeedMore"),
        }
    }

    // Test 6: Application data record
    #[test]
    fn test_application_data() {
        let parser = TlsStreamParser::new();

        let record = vec![
            23, // ApplicationData
            3, 3, // TLS 1.2
            0, 10, // Length
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, // Encrypted data
        ];

        let result = parser.parse_stream(&record, &test_context());
        match result {
            StreamParseResult::Complete {
                messages,
                bytes_consumed,
            } => {
                assert_eq!(bytes_consumed, 15);
                assert_eq!(
                    messages[0].fields.get("record_type"),
                    Some(&FieldValue::Str("ApplicationData"))
                );
            }
            _ => panic!("Expected Complete"),
        }
    }
}
