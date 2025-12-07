//! TLS protocol parser.
//!
//! Parses TLS (Transport Layer Security) handshake records, particularly
//! Client Hello messages for SNI extraction and cipher suite analysis.

use std::collections::HashMap;

use super::{FieldValue, ParseContext, ParseResult, Protocol};
use crate::schema::{DataKind, FieldDescriptor};

/// TLS/HTTPS port.
pub const TLS_PORT: u16 = 443;

/// TLS record types.
mod record_type {
    pub const CHANGE_CIPHER_SPEC: u8 = 20;
    pub const ALERT: u8 = 21;
    pub const HANDSHAKE: u8 = 22;
    pub const APPLICATION_DATA: u8 = 23;
}

/// TLS handshake types.
mod handshake_type {
    pub const CLIENT_HELLO: u8 = 1;
    pub const SERVER_HELLO: u8 = 2;
    pub const CERTIFICATE: u8 = 11;
    pub const SERVER_KEY_EXCHANGE: u8 = 12;
    pub const SERVER_HELLO_DONE: u8 = 14;
    pub const CLIENT_KEY_EXCHANGE: u8 = 16;
    pub const FINISHED: u8 = 20;
}

/// TLS extension types.
mod extension_type {
    pub const SERVER_NAME: u16 = 0;
    pub const SUPPORTED_VERSIONS: u16 = 43;
}

/// TLS protocol parser.
#[derive(Debug, Clone, Copy)]
pub struct TlsProtocol;

impl Protocol for TlsProtocol {
    fn name(&self) -> &'static str {
        "tls"
    }

    fn display_name(&self) -> &'static str {
        "TLS"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        let src_port = context.hint("src_port");
        let dst_port = context.hint("dst_port");

        // Check for TLS port 443
        match (src_port, dst_port) {
            (Some(443), _) | (_, Some(443)) => Some(50),
            _ => None,
        }
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        // TLS record header is 5 bytes: type (1) + version (2) + length (2)
        if data.len() < 5 {
            return ParseResult::error("TLS record too short".to_string(), data);
        }

        let mut fields = HashMap::new();

        // Parse TLS record header
        let record_type = data[0];
        fields.insert("record_type", FieldValue::UInt8(record_type));

        let version_major = data[1];
        let version_minor = data[2];
        let version_str = format_tls_version(version_major, version_minor);
        fields.insert("version", FieldValue::String(version_str));

        let record_length = u16::from_be_bytes([data[3], data[4]]) as usize;

        // Check if we have the full record
        if data.len() < 5 + record_length {
            return ParseResult::partial(
                fields,
                &data[5..],
                "TLS record truncated".to_string(),
            );
        }

        let record_data = &data[5..5 + record_length];

        // Parse handshake records
        if record_type == record_type::HANDSHAKE && !record_data.is_empty() {
            parse_tls_handshake(record_data, &mut fields);
        }

        let remaining = &data[5 + record_length..];
        ParseResult::success(fields, remaining, HashMap::new())
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            FieldDescriptor::new("tls.record_type", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("tls.version", DataKind::String).set_nullable(true),
            FieldDescriptor::new("tls.handshake_type", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("tls.sni", DataKind::String).set_nullable(true),
            FieldDescriptor::new("tls.cipher_suites", DataKind::String).set_nullable(true),
            FieldDescriptor::new("tls.selected_cipher", DataKind::String).set_nullable(true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        &[]
    }
}

/// Format TLS version from major.minor bytes.
fn format_tls_version(major: u8, minor: u8) -> String {
    match (major, minor) {
        (3, 0) => "SSL 3.0".to_string(),
        (3, 1) => "TLS 1.0".to_string(),
        (3, 2) => "TLS 1.1".to_string(),
        (3, 3) => "TLS 1.2".to_string(),
        (3, 4) => "TLS 1.3".to_string(),
        _ => format!("Unknown ({}.{})", major, minor),
    }
}

/// Parse a TLS handshake message.
fn parse_tls_handshake(data: &[u8], fields: &mut HashMap<&'static str, FieldValue>) {
    if data.len() < 4 {
        return;
    }

    let handshake_type = data[0];
    fields.insert("handshake_type", FieldValue::UInt8(handshake_type));

    // Handshake length (3 bytes)
    let handshake_len =
        ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | (data[3] as usize);

    if data.len() < 4 + handshake_len {
        return;
    }

    let handshake_data = &data[4..4 + handshake_len];

    match handshake_type {
        handshake_type::CLIENT_HELLO => {
            parse_client_hello(handshake_data, fields);
        }
        handshake_type::SERVER_HELLO => {
            parse_server_hello(handshake_data, fields);
        }
        _ => {}
    }
}

/// Parse a Client Hello message.
fn parse_client_hello(data: &[u8], fields: &mut HashMap<&'static str, FieldValue>) {
    if data.len() < 38 {
        return;
    }

    // Skip version (2 bytes) and random (32 bytes)
    let mut offset = 34;

    // Session ID length (1 byte) + session ID
    if offset >= data.len() {
        return;
    }
    let session_id_len = data[offset] as usize;
    offset += 1 + session_id_len;

    // Cipher suites length (2 bytes)
    if offset + 2 > data.len() {
        return;
    }
    let cipher_suites_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    // Parse cipher suites
    if offset + cipher_suites_len <= data.len() {
        let cipher_data = &data[offset..offset + cipher_suites_len];
        let cipher_names: Vec<String> = cipher_data
            .chunks(2)
            .filter(|chunk| chunk.len() == 2)
            .take(10) // Limit to first 10 cipher suites
            .map(|chunk| {
                let id = u16::from_be_bytes([chunk[0], chunk[1]]);
                format_cipher_suite(id)
            })
            .collect();

        if !cipher_names.is_empty() {
            fields.insert("cipher_suites", FieldValue::String(cipher_names.join(",")));
        }
    }
    offset += cipher_suites_len;

    // Compression methods length (1 byte) + compression methods
    if offset >= data.len() {
        return;
    }
    let compression_len = data[offset] as usize;
    offset += 1 + compression_len;

    // Extensions length (2 bytes)
    if offset + 2 > data.len() {
        return;
    }
    let extensions_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    // Parse extensions
    if offset + extensions_len <= data.len() {
        parse_extensions(&data[offset..offset + extensions_len], fields);
    }
}

/// Parse a Server Hello message.
fn parse_server_hello(data: &[u8], fields: &mut HashMap<&'static str, FieldValue>) {
    if data.len() < 38 {
        return;
    }

    // Skip version (2 bytes) and random (32 bytes)
    let mut offset = 34;

    // Session ID length (1 byte) + session ID
    if offset >= data.len() {
        return;
    }
    let session_id_len = data[offset] as usize;
    offset += 1 + session_id_len;

    // Selected cipher suite (2 bytes)
    if offset + 2 > data.len() {
        return;
    }
    let cipher_id = u16::from_be_bytes([data[offset], data[offset + 1]]);
    fields.insert(
        "selected_cipher",
        FieldValue::String(format_cipher_suite(cipher_id)),
    );
}

/// Parse TLS extensions and extract SNI.
fn parse_extensions(data: &[u8], fields: &mut HashMap<&'static str, FieldValue>) {
    let mut offset = 0;

    while offset + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        if offset + ext_len > data.len() {
            break;
        }

        let ext_data = &data[offset..offset + ext_len];

        if ext_type == extension_type::SERVER_NAME {
            if let Some(sni) = parse_sni_extension(ext_data) {
                fields.insert("sni", FieldValue::String(sni));
            }
        }

        offset += ext_len;
    }
}

/// Parse the SNI extension and extract the server name.
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    // SNI extension format:
    // - Server Name List Length (2 bytes)
    // - Server Name Type (1 byte) - 0 = hostname
    // - Server Name Length (2 bytes)
    // - Server Name (variable)

    if data.len() < 5 {
        return None;
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return None;
    }

    let mut offset = 2;

    while offset + 3 <= data.len() {
        let name_type = data[offset];
        let name_len = u16::from_be_bytes([data[offset + 1], data[offset + 2]]) as usize;
        offset += 3;

        if offset + name_len > data.len() {
            break;
        }

        if name_type == 0 {
            // Hostname
            if let Ok(hostname) = std::str::from_utf8(&data[offset..offset + name_len]) {
                return Some(hostname.to_string());
            }
        }

        offset += name_len;
    }

    None
}

/// Format a cipher suite ID as a readable name.
fn format_cipher_suite(id: u16) -> String {
    match id {
        0x0000 => "TLS_NULL_WITH_NULL_NULL".to_string(),
        0x002F => "TLS_RSA_WITH_AES_128_CBC_SHA".to_string(),
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA".to_string(),
        0x003C => "TLS_RSA_WITH_AES_128_CBC_SHA256".to_string(),
        0x003D => "TLS_RSA_WITH_AES_256_CBC_SHA256".to_string(),
        0x009C => "TLS_RSA_WITH_AES_128_GCM_SHA256".to_string(),
        0x009D => "TLS_RSA_WITH_AES_256_GCM_SHA384".to_string(),
        0xC009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA".to_string(),
        0xC00A => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA".to_string(),
        0xC013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA".to_string(),
        0xC014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA".to_string(),
        0xC02B => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string(),
        0xC02C => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".to_string(),
        0xC02F => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
        0xC030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
        0x1301 => "TLS_AES_128_GCM_SHA256".to_string(),
        0x1302 => "TLS_AES_256_GCM_SHA384".to_string(),
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256".to_string(),
        _ => format!("0x{:04X}", id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a minimal TLS Client Hello with SNI.
    fn create_tls_client_hello() -> Vec<u8> {
        let mut packet = Vec::new();

        // TLS Record Header
        packet.push(record_type::HANDSHAKE); // Content type
        packet.push(0x03); // Version major (TLS 1.2)
        packet.push(0x03); // Version minor

        // We'll calculate length later
        let length_pos = packet.len();
        packet.push(0x00); // Length high byte (placeholder)
        packet.push(0x00); // Length low byte (placeholder)

        let handshake_start = packet.len();

        // Handshake Header
        packet.push(handshake_type::CLIENT_HELLO); // Type
        packet.push(0x00); // Length (3 bytes, placeholder)
        packet.push(0x00);
        packet.push(0x00);

        let hello_start = packet.len();

        // Client Hello body
        packet.push(0x03); // Version major
        packet.push(0x03); // Version minor

        // Random (32 bytes)
        packet.extend_from_slice(&[0u8; 32]);

        // Session ID (0 length)
        packet.push(0x00);

        // Cipher Suites (6 bytes = 3 suites)
        packet.push(0x00);
        packet.push(0x06);
        packet.extend_from_slice(&0xC02Fu16.to_be_bytes()); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        packet.extend_from_slice(&0xC030u16.to_be_bytes()); // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        packet.extend_from_slice(&0x1301u16.to_be_bytes()); // TLS_AES_128_GCM_SHA256

        // Compression methods (1 = null)
        packet.push(0x01);
        packet.push(0x00);

        // Extensions
        let extensions_len_pos = packet.len();
        packet.push(0x00); // Extensions length (placeholder)
        packet.push(0x00);

        let extensions_start = packet.len();

        // SNI Extension (type 0)
        packet.extend_from_slice(&0u16.to_be_bytes()); // Extension type

        let hostname = b"www.example.com";
        let sni_ext_len = 2 + 1 + 2 + hostname.len(); // list_len + type + name_len + name
        packet.extend_from_slice(&(sni_ext_len as u16).to_be_bytes()); // Extension length

        // SNI List
        let sni_list_len = 1 + 2 + hostname.len(); // type + name_len + name
        packet.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        packet.push(0x00); // Name type = hostname
        packet.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        packet.extend_from_slice(hostname);

        // Fix up lengths
        let extensions_len = packet.len() - extensions_start;
        packet[extensions_len_pos] = (extensions_len >> 8) as u8;
        packet[extensions_len_pos + 1] = (extensions_len & 0xFF) as u8;

        let hello_len = packet.len() - hello_start;
        packet[handshake_start + 1] = ((hello_len >> 16) & 0xFF) as u8;
        packet[handshake_start + 2] = ((hello_len >> 8) & 0xFF) as u8;
        packet[handshake_start + 3] = (hello_len & 0xFF) as u8;

        let record_len = packet.len() - handshake_start;
        packet[length_pos] = (record_len >> 8) as u8;
        packet[length_pos + 1] = (record_len & 0xFF) as u8;

        packet
    }

    /// Create a minimal TLS Server Hello.
    fn create_tls_server_hello() -> Vec<u8> {
        let mut packet = Vec::new();

        // TLS Record Header
        packet.push(record_type::HANDSHAKE);
        packet.push(0x03); // Version major
        packet.push(0x03); // Version minor

        let length_pos = packet.len();
        packet.push(0x00);
        packet.push(0x00);

        let handshake_start = packet.len();

        // Handshake Header
        packet.push(handshake_type::SERVER_HELLO);
        packet.push(0x00);
        packet.push(0x00);
        packet.push(0x00);

        let hello_start = packet.len();

        // Server Hello body
        packet.push(0x03); // Version major
        packet.push(0x03); // Version minor

        // Random (32 bytes)
        packet.extend_from_slice(&[0u8; 32]);

        // Session ID (0 length)
        packet.push(0x00);

        // Selected cipher suite
        packet.extend_from_slice(&0xC02Fu16.to_be_bytes()); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

        // Compression method
        packet.push(0x00);

        // Fix up lengths
        let hello_len = packet.len() - hello_start;
        packet[handshake_start + 1] = ((hello_len >> 16) & 0xFF) as u8;
        packet[handshake_start + 2] = ((hello_len >> 8) & 0xFF) as u8;
        packet[handshake_start + 3] = (hello_len & 0xFF) as u8;

        let record_len = packet.len() - handshake_start;
        packet[length_pos] = (record_len >> 8) as u8;
        packet[length_pos + 1] = (record_len & 0xFF) as u8;

        packet
    }

    #[test]
    fn test_can_parse_tls_by_port() {
        let parser = TlsProtocol;

        // Without hint
        let ctx1 = ParseContext::new(1);
        assert!(parser.can_parse(&ctx1).is_none());

        // With dst_port 443
        let mut ctx2 = ParseContext::new(1);
        ctx2.hints.insert("dst_port", 443);
        assert!(parser.can_parse(&ctx2).is_some());

        // With src_port 443
        let mut ctx3 = ParseContext::new(1);
        ctx3.hints.insert("src_port", 443);
        assert!(parser.can_parse(&ctx3).is_some());
    }

    #[test]
    fn test_parse_tls_client_hello() {
        let packet = create_tls_client_hello();

        let parser = TlsProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("dst_port", 443);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("record_type"),
            Some(&FieldValue::UInt8(record_type::HANDSHAKE))
        );
        assert_eq!(
            result.get("version"),
            Some(&FieldValue::String("TLS 1.2".to_string()))
        );
        assert_eq!(
            result.get("handshake_type"),
            Some(&FieldValue::UInt8(handshake_type::CLIENT_HELLO))
        );
    }

    #[test]
    fn test_parse_tls_server_hello() {
        let packet = create_tls_server_hello();

        let parser = TlsProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("src_port", 443);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("handshake_type"),
            Some(&FieldValue::UInt8(handshake_type::SERVER_HELLO))
        );
        assert_eq!(
            result.get("selected_cipher"),
            Some(&FieldValue::String(
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string()
            ))
        );
    }

    #[test]
    fn test_extract_sni() {
        let packet = create_tls_client_hello();

        let parser = TlsProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("dst_port", 443);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("sni"),
            Some(&FieldValue::String("www.example.com".to_string()))
        );
    }

    #[test]
    fn test_tls_version_detection() {
        assert_eq!(format_tls_version(3, 0), "SSL 3.0");
        assert_eq!(format_tls_version(3, 1), "TLS 1.0");
        assert_eq!(format_tls_version(3, 2), "TLS 1.1");
        assert_eq!(format_tls_version(3, 3), "TLS 1.2");
        assert_eq!(format_tls_version(3, 4), "TLS 1.3");
    }

    #[test]
    fn test_tls_schema_fields() {
        let parser = TlsProtocol;
        let fields = parser.schema_fields();

        assert!(!fields.is_empty());

        let field_names: Vec<&str> = fields.iter().map(|f| f.name).collect();
        assert!(field_names.contains(&"tls.record_type"));
        assert!(field_names.contains(&"tls.version"));
        assert!(field_names.contains(&"tls.sni"));
        assert!(field_names.contains(&"tls.cipher_suites"));
    }

    #[test]
    fn test_tls_too_short() {
        let short_packet = vec![0x16, 0x03, 0x03]; // Only 3 bytes

        let parser = TlsProtocol;
        let context = ParseContext::new(1);

        let result = parser.parse(&short_packet, &context);

        assert!(!result.is_ok());
    }
}
