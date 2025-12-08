//! QUIC protocol parser.
//!
//! Parses QUIC transport protocol headers. QUIC encrypts most data,
//! so this parser focuses on what's visible in cleartext: connection IDs,
//! version, and packet type information.

use smallvec::SmallVec;

use super::{FieldValue, ParseContext, ParseResult, Protocol};
use crate::schema::{DataKind, FieldDescriptor};

/// QUIC versions.
mod version {
    pub const VERSION_NEGOTIATION: u32 = 0x00000000;
    pub const QUIC_V1: u32 = 0x00000001;
    pub const QUIC_V2: u32 = 0x6b3343cf;
    pub const DRAFT_29: u32 = 0xff00001d;
    pub const DRAFT_32: u32 = 0xff000020;
    pub const DRAFT_34: u32 = 0xff000022;
}

/// Long header packet types.
mod long_packet_type {
    pub const INITIAL: u8 = 0x0;
    pub const ZERO_RTT: u8 = 0x1;
    pub const HANDSHAKE: u8 = 0x2;
    pub const RETRY: u8 = 0x3;
}

/// QUIC protocol parser.
#[derive(Debug, Clone, Copy)]
pub struct QuicProtocol;

impl Protocol for QuicProtocol {
    fn name(&self) -> &'static str {
        "quic"
    }

    fn display_name(&self) -> &'static str {
        "QUIC"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        // Must be UDP
        let parent = context.parent_protocol;
        if parent != Some("udp") {
            return None;
        }

        // Common QUIC ports
        let src_port = context.hint("src_port");
        let dst_port = context.hint("dst_port");

        match (src_port, dst_port) {
            (Some(443), _) | (_, Some(443)) => Some(40),
            (Some(8443), _) | (_, Some(8443)) => Some(40),
            _ => None,
        }
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        let mut fields = SmallVec::new();

        if data.is_empty() {
            return ParseResult::error("QUIC packet empty".to_string(), data);
        }

        let first_byte = data[0];

        // Check header form bit (bit 7)
        let is_long_header = (first_byte & 0x80) != 0;

        if is_long_header {
            fields.push(("header_form", FieldValue::String("long".to_string())));
            parse_long_header(data, &mut fields)
        } else {
            fields.push(("header_form", FieldValue::String("short".to_string())));
            parse_short_header(data, &mut fields)
        }
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            FieldDescriptor::new("quic.header_form", DataKind::String).set_nullable(true),
            FieldDescriptor::new("quic.long_packet_type", DataKind::String).set_nullable(true),
            FieldDescriptor::new("quic.version", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("quic.version_name", DataKind::String).set_nullable(true),
            FieldDescriptor::new("quic.dcid_length", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("quic.dcid", DataKind::String).set_nullable(true),
            FieldDescriptor::new("quic.scid_length", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("quic.scid", DataKind::String).set_nullable(true),
            FieldDescriptor::new("quic.token_length", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("quic.packet_length", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("quic.spin_bit", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("quic.key_phase", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("quic.sni", DataKind::String).set_nullable(true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        &[]
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &["udp"]
    }
}

/// Parse QUIC long header.
fn parse_long_header<'a>(
    data: &'a [u8],
    fields: &mut SmallVec<[(&'static str, FieldValue); 16]>,
) -> ParseResult<'a> {
    // Long Header format:
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+
    // |1|1|T T|X X X X|
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                         Version (32)                          |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |DCID Len|      Destination Connection ID (0..160)            ...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |SCID Len|      Source Connection ID (0..160)                 ...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    if data.len() < 6 {
        return ParseResult::error("QUIC long header too short".to_string(), data);
    }

    let first_byte = data[0];

    // Fixed bit should be 1 (bit 6)
    let fixed_bit = (first_byte & 0x40) != 0;
    if !fixed_bit {
        return ParseResult::error("QUIC fixed bit not set".to_string(), data);
    }

    // Packet type (bits 4-5)
    let packet_type = (first_byte >> 4) & 0x03;
    let packet_type_name = match packet_type {
        long_packet_type::INITIAL => "Initial",
        long_packet_type::ZERO_RTT => "0-RTT",
        long_packet_type::HANDSHAKE => "Handshake",
        long_packet_type::RETRY => "Retry",
        _ => "Unknown",
    };
    fields.push((
        "long_packet_type",
        FieldValue::String(packet_type_name.to_string()),
    ));

    // Version (4 bytes)
    let quic_version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    fields.push(("version", FieldValue::UInt32(quic_version)));
    fields.push((
        "version_name",
        FieldValue::String(format_version(quic_version)),
    ));

    // DCID Length
    let dcid_len = data[5] as usize;
    fields.push(("dcid_length", FieldValue::UInt8(dcid_len as u8)));

    let mut offset = 6;

    // Destination Connection ID
    if offset + dcid_len > data.len() {
        return ParseResult::partial(
            fields.clone(),
            &data[offset..],
            "QUIC DCID truncated".to_string(),
        );
    }
    if dcid_len > 0 {
        let dcid = &data[offset..offset + dcid_len];
        fields.push(("dcid", FieldValue::String(hex_encode(dcid))));
    }
    offset += dcid_len;

    // SCID Length
    if offset >= data.len() {
        return ParseResult::partial(
            fields.clone(),
            &data[offset..],
            "QUIC SCID length missing".to_string(),
        );
    }
    let scid_len = data[offset] as usize;
    fields.push(("scid_length", FieldValue::UInt8(scid_len as u8)));
    offset += 1;

    // Source Connection ID
    if offset + scid_len > data.len() {
        return ParseResult::partial(
            fields.clone(),
            &data[offset..],
            "QUIC SCID truncated".to_string(),
        );
    }
    if scid_len > 0 {
        let scid = &data[offset..offset + scid_len];
        fields.push(("scid", FieldValue::String(hex_encode(scid))));
    }
    offset += scid_len;

    // For Initial packets, try to parse token and extract SNI from CRYPTO frame
    if packet_type == long_packet_type::INITIAL && offset < data.len() {
        parse_initial_packet(&data[offset..], fields);
    }

    ParseResult::success(fields.clone(), &[], SmallVec::new())
}

/// Parse QUIC short header.
fn parse_short_header<'a>(
    data: &'a [u8],
    fields: &mut SmallVec<[(&'static str, FieldValue); 16]>,
) -> ParseResult<'a> {
    // Short Header format:
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+
    // |0|1|S|R|R|K|P P|
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                Destination Connection ID (0..160)           ...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    if data.is_empty() {
        return ParseResult::error("QUIC short header empty".to_string(), data);
    }

    let first_byte = data[0];

    // Fixed bit should be 1 (bit 6)
    let fixed_bit = (first_byte & 0x40) != 0;
    if !fixed_bit {
        return ParseResult::error("QUIC fixed bit not set".to_string(), data);
    }

    // Spin bit (bit 5)
    let spin_bit = (first_byte & 0x20) != 0;
    fields.push(("spin_bit", FieldValue::Bool(spin_bit)));

    // Key phase (bit 2)
    let key_phase = (first_byte & 0x04) != 0;
    fields.push(("key_phase", FieldValue::Bool(key_phase)));

    // Note: DCID length is not in the short header - it must be known from context
    // For now, we can only note that this is a short header packet

    ParseResult::success(fields.clone(), &[], SmallVec::new())
}

/// Parse Initial packet payload to extract token and potentially SNI.
fn parse_initial_packet(data: &[u8], fields: &mut SmallVec<[(&'static str, FieldValue); 16]>) {
    // Initial packet has:
    // - Token Length (variable-length integer)
    // - Token
    // - Length (variable-length integer)
    // - Packet Number (1-4 bytes, encrypted)
    // - Payload (encrypted, contains CRYPTO frame with TLS ClientHello)

    if data.is_empty() {
        return;
    }

    // Parse token length (variable-length integer)
    let (token_len, consumed) = match parse_varint(data) {
        Some(v) => v,
        None => return,
    };

    fields.push(("token_length", FieldValue::UInt32(token_len as u32)));

    let mut offset = consumed;

    // Skip token
    if offset + token_len > data.len() {
        return;
    }
    offset += token_len;

    // Parse packet length (variable-length integer)
    if offset >= data.len() {
        return;
    }
    let (packet_len, consumed) = match parse_varint(&data[offset..]) {
        Some(v) => v,
        None => return,
    };

    fields.push(("packet_length", FieldValue::UInt32(packet_len as u32)));
    offset += consumed;

    // The rest is encrypted - we'd need to derive keys to parse further
    // For the Initial packet, the encryption key is derived from the DCID,
    // but implementing full QUIC decryption is beyond scope here.

    // Try to extract SNI from unencrypted CRYPTO frame in Initial packets
    // This is a best-effort attempt - may not work for all implementations
    if offset < data.len() {
        try_extract_sni(&data[offset..], fields);
    }
}

/// Try to extract SNI from potentially unencrypted Initial packet payload.
/// This is a heuristic that looks for patterns typical of TLS ClientHello.
fn try_extract_sni(data: &[u8], fields: &mut SmallVec<[(&'static str, FieldValue); 16]>) {
    // Look for SNI extension pattern in the data
    // SNI extension has type 0x0000, followed by length, then name type, name length, and name

    // Search for the pattern: 0x00 0x00 (SNI type) followed by reasonable lengths
    for i in 0..data.len().saturating_sub(10) {
        // Check for SNI extension type (0x0000)
        if data[i] == 0x00 && data[i + 1] == 0x00 {
            // Extension length
            if i + 4 > data.len() {
                continue;
            }
            let ext_len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
            if ext_len == 0 || ext_len > 256 || i + 4 + ext_len > data.len() {
                continue;
            }

            // Server name list length
            if i + 6 > data.len() {
                continue;
            }
            let list_len = u16::from_be_bytes([data[i + 4], data[i + 5]]) as usize;
            if list_len == 0 || list_len > ext_len {
                continue;
            }

            // Name type (0 = hostname)
            if i + 7 > data.len() || data[i + 6] != 0x00 {
                continue;
            }

            // Name length
            if i + 9 > data.len() {
                continue;
            }
            let name_len = u16::from_be_bytes([data[i + 7], data[i + 8]]) as usize;
            if name_len == 0 || name_len > 255 || i + 9 + name_len > data.len() {
                continue;
            }

            // Extract hostname
            if let Ok(hostname) = std::str::from_utf8(&data[i + 9..i + 9 + name_len]) {
                // Validate it looks like a hostname
                if hostname
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
                    && hostname.contains('.')
                {
                    fields.push(("sni", FieldValue::String(hostname.to_string())));
                    return;
                }
            }
        }
    }
}

/// Parse a QUIC variable-length integer.
/// Returns (value, bytes_consumed) or None if invalid.
fn parse_varint(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }

    let first = data[0];
    let prefix = first >> 6;

    match prefix {
        0 => {
            // 1 byte, 6 bits
            Some(((first & 0x3F) as usize, 1))
        }
        1 => {
            // 2 bytes, 14 bits
            if data.len() < 2 {
                return None;
            }
            let value = (((first & 0x3F) as usize) << 8) | (data[1] as usize);
            Some((value, 2))
        }
        2 => {
            // 4 bytes, 30 bits
            if data.len() < 4 {
                return None;
            }
            let value = (((first & 0x3F) as usize) << 24)
                | ((data[1] as usize) << 16)
                | ((data[2] as usize) << 8)
                | (data[3] as usize);
            Some((value, 4))
        }
        3 => {
            // 8 bytes, 62 bits
            if data.len() < 8 {
                return None;
            }
            let value = (((first & 0x3F) as usize) << 56)
                | ((data[1] as usize) << 48)
                | ((data[2] as usize) << 40)
                | ((data[3] as usize) << 32)
                | ((data[4] as usize) << 24)
                | ((data[5] as usize) << 16)
                | ((data[6] as usize) << 8)
                | (data[7] as usize);
            Some((value, 8))
        }
        _ => None,
    }
}

/// Format QUIC version as a readable name.
fn format_version(ver: u32) -> String {
    match ver {
        version::VERSION_NEGOTIATION => "Version Negotiation".to_string(),
        version::QUIC_V1 => "QUIC v1".to_string(),
        version::QUIC_V2 => "QUIC v2".to_string(),
        version::DRAFT_29 => "Draft-29".to_string(),
        version::DRAFT_32 => "Draft-32".to_string(),
        version::DRAFT_34 => "Draft-34".to_string(),
        v if (v & 0xff000000) == 0xff000000 => {
            format!("Draft-{}", v & 0xff)
        }
        _ => format!("0x{:08x}", ver),
    }
}

/// Encode bytes as hex string.
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a QUIC Initial packet (long header).
    fn create_quic_initial(dcid: &[u8], scid: &[u8], version: u32) -> Vec<u8> {
        let mut packet = Vec::new();

        // First byte: Form=1, Fixed=1, Type=00 (Initial), Reserved + Packet Number Length
        packet.push(0xC0 | 0x00);

        // Version
        packet.extend_from_slice(&version.to_be_bytes());

        // DCID Length + DCID
        packet.push(dcid.len() as u8);
        packet.extend_from_slice(dcid);

        // SCID Length + SCID
        packet.push(scid.len() as u8);
        packet.extend_from_slice(scid);

        // Token Length (0)
        packet.push(0x00);

        // Packet Length (varint, e.g., 100 bytes)
        packet.push(0x40); // 2-byte varint prefix
        packet.push(0x64); // 100

        // Some payload data (would be encrypted in real QUIC)
        packet.extend(std::iter::repeat(0u8).take(100));

        packet
    }

    /// Create a QUIC Handshake packet (long header).
    fn create_quic_handshake(dcid: &[u8], scid: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();

        // First byte: Form=1, Fixed=1, Type=10 (Handshake)
        packet.push(0xC0 | 0x20);

        // Version (QUIC v1)
        packet.extend_from_slice(&version::QUIC_V1.to_be_bytes());

        // DCID Length + DCID
        packet.push(dcid.len() as u8);
        packet.extend_from_slice(dcid);

        // SCID Length + SCID
        packet.push(scid.len() as u8);
        packet.extend_from_slice(scid);

        // Packet Length (varint)
        packet.push(0x40);
        packet.push(0x32); // 50

        // Payload
        packet.extend(std::iter::repeat(0u8).take(50));

        packet
    }

    /// Create a QUIC short header packet.
    fn create_quic_short(dcid: &[u8], spin: bool, key_phase: bool) -> Vec<u8> {
        let mut packet = Vec::new();

        // First byte: Form=0, Fixed=1, Spin, Reserved, Key Phase, PN Length
        let mut first = 0x40;
        if spin {
            first |= 0x20;
        }
        if key_phase {
            first |= 0x04;
        }
        packet.push(first);

        // DCID (length known from context, we just include it)
        packet.extend_from_slice(dcid);

        // Some encrypted payload
        packet.extend(std::iter::repeat(0u8).take(20));

        packet
    }

    #[test]
    fn test_can_parse_quic() {
        let parser = QuicProtocol;

        // Not UDP
        let ctx1 = ParseContext::new(1);
        assert!(parser.can_parse(&ctx1).is_none());

        // UDP but wrong port
        let mut ctx2 = ParseContext::new(1);
        ctx2.parent_protocol = Some("udp");
        ctx2.insert_hint("dst_port", 80);
        assert!(parser.can_parse(&ctx2).is_none());

        // UDP on port 443
        let mut ctx3 = ParseContext::new(1);
        ctx3.parent_protocol = Some("udp");
        ctx3.insert_hint("dst_port", 443);
        assert!(parser.can_parse(&ctx3).is_some());
    }

    #[test]
    fn test_quic_detection_long_header() {
        let dcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let scid = [0x11, 0x12, 0x13, 0x14];
        let packet = create_quic_initial(&dcid, &scid, version::QUIC_V1);

        let parser = QuicProtocol;
        let mut context = ParseContext::new(1);
        context.parent_protocol = Some("udp");
        context.insert_hint("dst_port", 443);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("header_form"),
            Some(&FieldValue::String("long".to_string()))
        );
    }

    #[test]
    fn test_quic_detection_short_header() {
        let dcid = [0x01, 0x02, 0x03, 0x04];
        let packet = create_quic_short(&dcid, false, false);

        let parser = QuicProtocol;
        let mut context = ParseContext::new(1);
        context.parent_protocol = Some("udp");
        context.insert_hint("dst_port", 443);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("header_form"),
            Some(&FieldValue::String("short".to_string()))
        );
    }

    #[test]
    fn test_quic_version_parsing() {
        let dcid = [0x01, 0x02, 0x03, 0x04];
        let scid = [0x11, 0x12];
        let packet = create_quic_initial(&dcid, &scid, version::QUIC_V1);

        let parser = QuicProtocol;
        let context = ParseContext::new(1);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("version"),
            Some(&FieldValue::UInt32(version::QUIC_V1))
        );
        assert_eq!(
            result.get("version_name"),
            Some(&FieldValue::String("QUIC v1".to_string()))
        );
    }

    #[test]
    fn test_quic_initial_packet_parsing() {
        let dcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let scid = [0x11, 0x12, 0x13, 0x14];
        let packet = create_quic_initial(&dcid, &scid, version::QUIC_V1);

        let parser = QuicProtocol;
        let context = ParseContext::new(1);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("long_packet_type"),
            Some(&FieldValue::String("Initial".to_string()))
        );
    }

    #[test]
    fn test_quic_handshake_packet_parsing() {
        let dcid = [0x01, 0x02, 0x03, 0x04];
        let scid = [0x11, 0x12];
        let packet = create_quic_handshake(&dcid, &scid);

        let parser = QuicProtocol;
        let context = ParseContext::new(1);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("long_packet_type"),
            Some(&FieldValue::String("Handshake".to_string()))
        );
    }

    #[test]
    fn test_quic_dcid_extraction() {
        let dcid = [0xaa, 0xbb, 0xcc, 0xdd];
        let scid = [0x11, 0x22];
        let packet = create_quic_initial(&dcid, &scid, version::QUIC_V1);

        let parser = QuicProtocol;
        let context = ParseContext::new(1);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("dcid_length"), Some(&FieldValue::UInt8(4)));
        assert_eq!(
            result.get("dcid"),
            Some(&FieldValue::String("aabbccdd".to_string()))
        );
    }

    #[test]
    fn test_quic_scid_extraction() {
        let dcid = [0x01, 0x02];
        let scid = [0xee, 0xff, 0x00, 0x11];
        let packet = create_quic_initial(&dcid, &scid, version::QUIC_V1);

        let parser = QuicProtocol;
        let context = ParseContext::new(1);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("scid_length"), Some(&FieldValue::UInt8(4)));
        assert_eq!(
            result.get("scid"),
            Some(&FieldValue::String("eeff0011".to_string()))
        );
    }

    #[test]
    fn test_quic_version_negotiation_detection() {
        let dcid = [0x01, 0x02, 0x03, 0x04];
        let scid = [0x11, 0x12];
        let packet = create_quic_initial(&dcid, &scid, version::VERSION_NEGOTIATION);

        let parser = QuicProtocol;
        let context = ParseContext::new(1);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("version"),
            Some(&FieldValue::UInt32(version::VERSION_NEGOTIATION))
        );
        assert_eq!(
            result.get("version_name"),
            Some(&FieldValue::String("Version Negotiation".to_string()))
        );
    }

    #[test]
    fn test_quic_unknown_version_handling() {
        let dcid = [0x01, 0x02];
        let scid = [0x11, 0x12];
        let unknown_version = 0xdeadbeef;
        let packet = create_quic_initial(&dcid, &scid, unknown_version);

        let parser = QuicProtocol;
        let context = ParseContext::new(1);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("version"),
            Some(&FieldValue::UInt32(unknown_version))
        );
        assert_eq!(
            result.get("version_name"),
            Some(&FieldValue::String("0xdeadbeef".to_string()))
        );
    }

    #[test]
    fn test_quic_short_header_spin_bit() {
        let dcid = [0x01, 0x02, 0x03, 0x04];
        let packet = create_quic_short(&dcid, true, false);

        let parser = QuicProtocol;
        let context = ParseContext::new(1);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("spin_bit"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("key_phase"), Some(&FieldValue::Bool(false)));
    }

    #[test]
    fn test_quic_short_header_key_phase() {
        let dcid = [0x01, 0x02, 0x03, 0x04];
        let packet = create_quic_short(&dcid, false, true);

        let parser = QuicProtocol;
        let context = ParseContext::new(1);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("spin_bit"), Some(&FieldValue::Bool(false)));
        assert_eq!(result.get("key_phase"), Some(&FieldValue::Bool(true)));
    }

    #[test]
    fn test_quic_schema_fields() {
        let parser = QuicProtocol;
        let fields = parser.schema_fields();

        assert!(!fields.is_empty());

        let field_names: Vec<&str> = fields.iter().map(|f| f.name).collect();
        assert!(field_names.contains(&"quic.header_form"));
        assert!(field_names.contains(&"quic.version"));
        assert!(field_names.contains(&"quic.dcid"));
        assert!(field_names.contains(&"quic.scid"));
        assert!(field_names.contains(&"quic.sni"));
    }

    #[test]
    fn test_varint_parsing() {
        // 1-byte varint
        assert_eq!(parse_varint(&[0x25]), Some((0x25, 1)));
        assert_eq!(parse_varint(&[0x00]), Some((0, 1)));

        // 2-byte varint (prefix 01)
        assert_eq!(parse_varint(&[0x40, 0x19]), Some((0x19, 2)));
        assert_eq!(parse_varint(&[0x7f, 0xff]), Some((0x3fff, 2)));

        // 4-byte varint (prefix 10)
        assert_eq!(
            parse_varint(&[0x80, 0x00, 0x00, 0x01]),
            Some((0x01, 4))
        );

        // Empty data
        assert_eq!(parse_varint(&[]), None);
    }

    #[test]
    fn test_version_formatting() {
        assert_eq!(format_version(version::QUIC_V1), "QUIC v1");
        assert_eq!(format_version(version::QUIC_V2), "QUIC v2");
        assert_eq!(format_version(version::VERSION_NEGOTIATION), "Version Negotiation");
        assert_eq!(format_version(0xff00001d), "Draft-29");
        assert_eq!(format_version(0x12345678), "0x12345678");
    }
}
