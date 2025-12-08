//! GTP (GPRS Tunneling Protocol) parser.
//!
//! GTP is a group of IP-based communications protocols used to carry
//! general packet radio service (GPRS) within GSM, UMTS, LTE, and 5G networks.
//!
//! 3GPP TS 29.060: GPRS Tunnelling Protocol (GTP) across the Gn and Gp interface
//! 3GPP TS 29.281: GPRS Tunnelling Protocol User Plane (GTPv1-U)
//! 3GPP TS 29.274: GPRS Tunnelling Protocol version 2 (GTPv2-C)

use compact_str::CompactString;
use smallvec::SmallVec;

use super::{FieldValue, ParseContext, ParseResult, Protocol};
use crate::schema::{DataKind, FieldDescriptor};

/// GTP-U (User Plane) UDP port.
pub const GTP_U_PORT: u16 = 2152;

/// GTP-C (Control Plane) UDP port.
pub const GTP_C_PORT: u16 = 2123;

/// Maximum extension headers to parse (safety limit).
const MAX_EXTENSION_HEADERS: usize = 16;

/// GTP message types.
pub mod message_type {
    pub const ECHO_REQUEST: u8 = 1;
    pub const ECHO_RESPONSE: u8 = 2;
    pub const ERROR_INDICATION: u8 = 26;
    pub const SUPPORTED_EXTENSION_HEADERS_NOTIFICATION: u8 = 31;
    pub const END_MARKER: u8 = 254;
    pub const G_PDU: u8 = 255;
}

/// GTP extension header types (3GPP TS 29.281).
pub mod extension_header_type {
    pub const NO_MORE: u8 = 0x00;
    pub const MBMS_SUPPORT_INDICATION: u8 = 0x01;
    pub const MS_INFO_CHANGE_REPORTING: u8 = 0x02;
    pub const SERVICE_CLASS_INDICATOR: u8 = 0x20;
    pub const UDP_PORT: u8 = 0x40;
    pub const RAN_CONTAINER: u8 = 0x81;
    pub const LONG_PDCP_PDU_NUMBER: u8 = 0x82;
    pub const XW_RAN_CONTAINER: u8 = 0x83;
    pub const NR_RAN_CONTAINER: u8 = 0x84;
    pub const PDU_SESSION_CONTAINER: u8 = 0x85;
    pub const PDCP_PDU_NUMBER: u8 = 0xC0;
}

/// Get the name of a GTP extension header type.
fn extension_header_type_name(ext_type: u8) -> &'static str {
    match ext_type {
        extension_header_type::NO_MORE => "No More",
        extension_header_type::MBMS_SUPPORT_INDICATION => "MBMS Support Indication",
        extension_header_type::MS_INFO_CHANGE_REPORTING => "MS Info Change Reporting",
        extension_header_type::SERVICE_CLASS_INDICATOR => "Service Class Indicator",
        extension_header_type::UDP_PORT => "UDP Port",
        extension_header_type::RAN_CONTAINER => "RAN Container",
        extension_header_type::LONG_PDCP_PDU_NUMBER => "Long PDCP PDU Number",
        extension_header_type::XW_RAN_CONTAINER => "Xw RAN Container",
        extension_header_type::NR_RAN_CONTAINER => "NR RAN Container",
        extension_header_type::PDU_SESSION_CONTAINER => "PDU Session Container",
        extension_header_type::PDCP_PDU_NUMBER => "PDCP PDU Number",
        _ => "Unknown",
    }
}

/// GTP protocol parser.
#[derive(Debug, Clone, Copy)]
pub struct GtpProtocol;

impl Protocol for GtpProtocol {
    fn name(&self) -> &'static str {
        "gtp"
    }

    fn display_name(&self) -> &'static str {
        "GTP"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        // Match when UDP dst_port hint equals GTP-U or GTP-C port
        match context.hint("dst_port") {
            Some(port) if port == GTP_U_PORT as u64 => Some(100),
            Some(port) if port == GTP_C_PORT as u64 => Some(100),
            _ => None,
        }
    }

    fn parse<'a>(&self, data: &'a [u8], context: &ParseContext) -> ParseResult<'a> {
        // Minimum GTP header is 8 bytes (without optional fields)
        if data.len() < 8 {
            return ParseResult::error("GTP header too short".to_string(), data);
        }

        let mut fields = SmallVec::new();

        // Byte 0: Flags
        // Bits 7-5: Version (1 for GTPv1, 2 for GTPv2)
        // Bit 4: PT (Protocol Type: 1 = GTP, 0 = GTP')
        // Bit 3: Reserved (*) / P flag (Piggyback) for GTPv2
        // Bit 2: E (Extension Header flag) / T flag (TEID present) for GTPv2
        // Bit 1: S (Sequence number flag)
        // Bit 0: PN (N-PDU number flag)
        let flags = data[0];
        let version = (flags >> 5) & 0x07;
        fields.push(("version", FieldValue::UInt8(version)));

        // Handle GTPv2-C differently
        if version == 2 {
            return self.parse_gtpv2(data, context);
        }

        // GTPv1 parsing
        let protocol_type = (flags >> 4) & 0x01;
        let extension_header_flag = (flags >> 2) & 0x01 == 1;
        let sequence_flag = (flags >> 1) & 0x01 == 1;
        let npdu_flag = flags & 0x01 == 1;

        fields.push(("protocol_type", FieldValue::UInt8(protocol_type)));

        // Byte 1: Message Type
        let message_type = data[1];
        fields.push(("message_type", FieldValue::UInt8(message_type)));

        // Bytes 2-3: Length (excludes mandatory header)
        let length = u16::from_be_bytes([data[2], data[3]]);
        fields.push(("length", FieldValue::UInt16(length)));

        // Bytes 4-7: TEID (Tunnel Endpoint Identifier)
        let teid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        fields.push(("teid", FieldValue::UInt32(teid)));

        let mut offset = 8;

        // If any of the E, S, or PN flags are set, there are 4 more bytes
        if extension_header_flag || sequence_flag || npdu_flag {
            if data.len() < offset + 4 {
                return ParseResult::error("GTP: optional header fields missing".to_string(), data);
            }

            // Bytes 8-9: Sequence Number
            if sequence_flag {
                let sequence = u16::from_be_bytes([data[offset], data[offset + 1]]);
                fields.push(("sequence", FieldValue::UInt16(sequence)));
            }
            offset += 2;

            // Byte 10: N-PDU Number
            if npdu_flag {
                fields.push(("npdu", FieldValue::UInt8(data[offset])));
            }
            offset += 1;

            // Byte 11: Next Extension Header Type
            let mut next_ext_type = data[offset];
            offset += 1;

            // Parse extension headers if present
            if extension_header_flag && next_ext_type != 0 {
                let mut ext_headers = Vec::new();
                let mut ext_count = 0u8;

                while next_ext_type != extension_header_type::NO_MORE
                    && offset < data.len()
                    && ext_count < MAX_EXTENSION_HEADERS as u8
                {
                    // Extension header length (in 4-byte units, including length and next_type fields)
                    if offset >= data.len() {
                        break;
                    }
                    let ext_len_units = data[offset] as usize;
                    let ext_len = ext_len_units * 4;

                    if ext_len == 0 || offset + ext_len > data.len() {
                        // Invalid extension header, stop parsing
                        break;
                    }

                    // Store the extension header type name
                    ext_headers.push(format!(
                        "{}(0x{:02X})",
                        extension_header_type_name(next_ext_type),
                        next_ext_type
                    ));

                    // Next extension header type is at the last byte of this extension
                    next_ext_type = data[offset + ext_len - 1];
                    offset += ext_len;
                    ext_count += 1;
                }

                if !ext_headers.is_empty() {
                    fields.push((
                        "extension_headers",
                        FieldValue::OwnedString(CompactString::new(ext_headers.join(","))),
                    ));
                    fields.push(("extension_header_count", FieldValue::UInt8(ext_count)));
                }
            }
        }

        // Set up child hints
        let mut child_hints = SmallVec::new();

        // For G-PDU (type 255), the payload is user data (usually IP)
        if message_type == message_type::G_PDU && offset < data.len() {
            let first_byte = data[offset];
            let ip_version = (first_byte >> 4) & 0x0F;

            match ip_version {
                4 => {
                    child_hints.push(("ethertype", 0x0800u64)); // IPv4
                    child_hints.push(("ip_version", 4u64));
                }
                6 => {
                    child_hints.push(("ethertype", 0x86DDu64)); // IPv6
                    child_hints.push(("ip_version", 6u64));
                }
                _ => {}
            }
        }

        // Also check if this is GTP-U or GTP-C for context
        if let Some(port) = context.hint("dst_port") {
            if port == GTP_U_PORT as u64 {
                child_hints.push(("gtp_plane", 1u64)); // User plane
            } else if port == GTP_C_PORT as u64 {
                child_hints.push(("gtp_plane", 0u64)); // Control plane
            }
        }

        ParseResult::success(fields, &data[offset..], child_hints)
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            // Common fields
            FieldDescriptor::new("gtp.version", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("gtp.message_type", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("gtp.length", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("gtp.teid", DataKind::UInt32).set_nullable(true),
            // GTPv1 fields
            FieldDescriptor::new("gtp.protocol_type", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("gtp.sequence", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("gtp.npdu", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("gtp.extension_headers", DataKind::String).set_nullable(true),
            FieldDescriptor::new("gtp.extension_header_count", DataKind::UInt8).set_nullable(true),
            // GTPv2-C fields
            FieldDescriptor::new("gtp.piggyback", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("gtp.teid_present", DataKind::Bool).set_nullable(true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        // GTP-U encapsulates IP packets
        &["ipv4", "ipv6"]
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &["udp"] // GTP runs over UDP ports 2123, 2152
    }
}

impl GtpProtocol {
    /// Parse GTPv2-C header (3GPP TS 29.274).
    ///
    /// GTPv2-C Header Format:
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |Version|  P  |T|  Spare  |      Message Type                  |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                         Length                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                TEID (if T=1)                                  |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |          Sequence Number                      |    Spare     |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    fn parse_gtpv2<'a>(&self, data: &'a [u8], context: &ParseContext) -> ParseResult<'a> {
        if data.len() < 8 {
            return ParseResult::error("GTPv2 header too short".to_string(), data);
        }

        let mut fields = SmallVec::new();

        let flags = data[0];
        let version = (flags >> 5) & 0x07;
        let piggyback = (flags >> 4) & 0x01 == 1;
        let teid_present = (flags >> 3) & 0x01 == 1;

        fields.push(("version", FieldValue::UInt8(version)));
        fields.push(("piggyback", FieldValue::Bool(piggyback)));
        fields.push(("teid_present", FieldValue::Bool(teid_present)));

        // Byte 1: Message Type
        let message_type = data[1];
        fields.push(("message_type", FieldValue::UInt8(message_type)));

        // Bytes 2-3: Length (includes optional TEID + SeqNo)
        let length = u16::from_be_bytes([data[2], data[3]]);
        fields.push(("length", FieldValue::UInt16(length)));

        let mut offset = 4;

        // TEID is present if T flag is set
        if teid_present {
            if data.len() < offset + 4 {
                return ParseResult::error("GTPv2: missing TEID field".to_string(), data);
            }
            let teid = u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
            fields.push(("teid", FieldValue::UInt32(teid)));
            offset += 4;
        }

        // Sequence Number (3 bytes) + Spare (1 byte)
        if data.len() < offset + 4 {
            return ParseResult::error("GTPv2: missing sequence number".to_string(), data);
        }
        let sequence = ((data[offset] as u32) << 16)
            | ((data[offset + 1] as u32) << 8)
            | (data[offset + 2] as u32);
        fields.push(("sequence", FieldValue::UInt32(sequence)));
        offset += 4;

        // Set up child hints for GTP-C
        let mut child_hints = SmallVec::new();
        if let Some(port) = context.hint("dst_port") {
            if port == GTP_C_PORT as u64 {
                child_hints.push(("gtp_plane", 0u64)); // Control plane
            }
        }

        ParseResult::success(fields, &data[offset..], child_hints)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a minimal GTPv1 header.
    fn create_gtp_header(
        message_type: u8,
        teid: u32,
        payload_len: u16,
        sequence: Option<u16>,
    ) -> Vec<u8> {
        let mut header = Vec::new();

        // Flags: Version 1, PT=1 (GTP), optional S flag
        let mut flags = 0x30u8; // Version 1, PT=1
        if sequence.is_some() {
            flags |= 0x02; // S flag
        }
        header.push(flags);

        // Message type
        header.push(message_type);

        // Length
        let len = if sequence.is_some() {
            payload_len + 4 // Add 4 for optional fields
        } else {
            payload_len
        };
        header.extend_from_slice(&len.to_be_bytes());

        // TEID
        header.extend_from_slice(&teid.to_be_bytes());

        // Optional fields if S flag is set
        if let Some(seq) = sequence {
            header.extend_from_slice(&seq.to_be_bytes());
            header.push(0); // N-PDU
            header.push(0); // Next Extension Header Type
        }

        header
    }

    // Test 1: can_parse with GTP-U port
    #[test]
    fn test_can_parse_with_gtp_u_port() {
        let parser = GtpProtocol;

        // Without hint
        let ctx1 = ParseContext::new(1);
        assert!(parser.can_parse(&ctx1).is_none());

        // With wrong port
        let mut ctx2 = ParseContext::new(1);
        ctx2.insert_hint("dst_port", 80);
        assert!(parser.can_parse(&ctx2).is_none());

        // With GTP-U port
        let mut ctx3 = ParseContext::new(1);
        ctx3.insert_hint("dst_port", 2152);
        assert!(parser.can_parse(&ctx3).is_some());
        assert_eq!(parser.can_parse(&ctx3), Some(100));
    }

    // Test 2: can_parse with GTP-C port
    #[test]
    fn test_can_parse_with_gtp_c_port() {
        let parser = GtpProtocol;

        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 2123);

        assert!(parser.can_parse(&context).is_some());
        assert_eq!(parser.can_parse(&context), Some(100));
    }

    // Test 3: GTPv1 header parsing
    #[test]
    fn test_gtpv1_header_parsing() {
        let header = create_gtp_header(message_type::G_PDU, 0x12345678, 0, None);

        let parser = GtpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 2152);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("version"), Some(&FieldValue::UInt8(1)));
        assert_eq!(result.get("protocol_type"), Some(&FieldValue::UInt8(1)));
        assert_eq!(result.get("message_type"), Some(&FieldValue::UInt8(255)));
    }

    // Test 4: TEID extraction
    #[test]
    fn test_teid_extraction() {
        let parser = GtpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 2152);

        // Test various TEID values
        let test_teids = [0u32, 1, 0x12345678, 0xFFFFFFFF];

        for teid in test_teids {
            let header = create_gtp_header(message_type::G_PDU, teid, 0, None);
            let result = parser.parse(&header, &context);

            assert!(result.is_ok());
            assert_eq!(result.get("teid"), Some(&FieldValue::UInt32(teid)));
        }
    }

    // Test 5: Message type parsing
    #[test]
    fn test_message_type_parsing() {
        let parser = GtpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 2152);

        let test_types = [
            message_type::ECHO_REQUEST,
            message_type::ECHO_RESPONSE,
            message_type::ERROR_INDICATION,
            message_type::G_PDU,
        ];

        for msg_type in test_types {
            let header = create_gtp_header(msg_type, 0x1234, 0, None);
            let result = parser.parse(&header, &context);

            assert!(result.is_ok());
            assert_eq!(result.get("message_type"), Some(&FieldValue::UInt8(msg_type)));
        }
    }

    // Test 6: Optional sequence number
    #[test]
    fn test_optional_sequence_number() {
        let parser = GtpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 2152);

        // With sequence number
        let header = create_gtp_header(message_type::G_PDU, 0x1234, 0, Some(0xABCD));
        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("sequence"), Some(&FieldValue::UInt16(0xABCD)));
    }

    // Test 7: G-PDU child protocol detection
    #[test]
    fn test_gpdu_child_protocol_detection() {
        let parser = GtpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 2152);

        // G-PDU with IPv4 payload
        let mut data_ipv4 = create_gtp_header(message_type::G_PDU, 0x1234, 20, None);
        data_ipv4.extend_from_slice(&[0x45, 0x00, 0x00, 0x14]); // IPv4 header start

        let result_ipv4 = parser.parse(&data_ipv4, &context);
        assert!(result_ipv4.is_ok());
        assert_eq!(result_ipv4.hint("ethertype"), Some(0x0800u64));
        assert_eq!(result_ipv4.hint("ip_version"), Some(4u64));

        // G-PDU with IPv6 payload
        let mut data_ipv6 = create_gtp_header(message_type::G_PDU, 0x1234, 40, None);
        data_ipv6.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // IPv6 header start

        let result_ipv6 = parser.parse(&data_ipv6, &context);
        assert!(result_ipv6.is_ok());
        assert_eq!(result_ipv6.hint("ethertype"), Some(0x86DDu64));
        assert_eq!(result_ipv6.hint("ip_version"), Some(6u64));
    }

    // Test 8: Too short header
    #[test]
    fn test_gtp_too_short() {
        let parser = GtpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 2152);

        let short_header = [0x30, 0xFF, 0x00, 0x00]; // Only 4 bytes
        let result = parser.parse(&short_header, &context);

        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }

    // Test 9: Length field
    #[test]
    fn test_length_field() {
        let parser = GtpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 2152);

        let mut header = create_gtp_header(message_type::G_PDU, 0x1234, 100, None);
        // Add 100 bytes of payload
        header.extend(vec![0u8; 100]);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("length"), Some(&FieldValue::UInt16(100)));
        assert_eq!(result.remaining.len(), 100);
    }

    // Test 10: Schema fields
    #[test]
    fn test_gtp_schema_fields() {
        let parser = GtpProtocol;
        let fields = parser.schema_fields();

        assert!(!fields.is_empty());
        let field_names: Vec<&str> = fields.iter().map(|f| f.name).collect();
        assert!(field_names.contains(&"gtp.version"));
        assert!(field_names.contains(&"gtp.protocol_type"));
        assert!(field_names.contains(&"gtp.message_type"));
        assert!(field_names.contains(&"gtp.length"));
        assert!(field_names.contains(&"gtp.teid"));
        assert!(field_names.contains(&"gtp.sequence"));
    }

    // Test 11: GTP' (Protocol Type = 0)
    #[test]
    fn test_gtp_prime() {
        let parser = GtpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 2152);

        // GTP' header (PT = 0)
        let header = vec![
            0x20, // Version 1, PT=0 (GTP')
            0x01, // Echo Request
            0x00, 0x04, // Length
            0x00, 0x00, 0x00, 0x01, // TEID
        ];

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("protocol_type"), Some(&FieldValue::UInt8(0)));
    }

    // Test 12: Extension header parsing - single extension
    #[test]
    fn test_extension_header_single() {
        let parser = GtpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 2152);

        // GTPv1 with E flag set and one extension header
        let header = vec![
            0x34, // Version 1, PT=1, E=1
            message_type::G_PDU,
            0x00, 0x0C, // Length (includes optional fields + ext header)
            0x00, 0x00, 0x00, 0x01, // TEID
            0x00, 0x00, // Sequence (not present but field exists)
            0x00, // N-PDU
            extension_header_type::PDCP_PDU_NUMBER, // Next ext header type
            // Extension header: PDCP PDU Number
            0x01, // Length = 1 * 4 = 4 bytes
            0x12, 0x34, // PDCP PDU Number data
            extension_header_type::NO_MORE, // No more extensions
        ];

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("extension_header_count"), Some(&FieldValue::UInt8(1)));

        if let Some(FieldValue::OwnedString(ext)) = result.get("extension_headers") {
            assert!(ext.contains("PDCP PDU Number"));
            assert!(ext.contains("0xC0"));
        } else {
            panic!("Expected extension_headers field");
        }
    }

    // Test 13: Extension header parsing - multiple extensions (chain)
    #[test]
    fn test_extension_header_chain() {
        let parser = GtpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 2152);

        // GTPv1 with multiple chained extension headers
        let header = vec![
            0x34, // Version 1, PT=1, E=1
            message_type::G_PDU,
            0x00, 0x14, // Length
            0x00, 0x00, 0x00, 0x01, // TEID
            0x00, 0x00, // Sequence
            0x00, // N-PDU
            extension_header_type::UDP_PORT, // First ext header type
            // Extension header 1: UDP Port (type 0x40)
            0x01, // Length = 4 bytes
            0x08, 0x68, // UDP port 2152
            extension_header_type::PDU_SESSION_CONTAINER, // Next ext
            // Extension header 2: PDU Session Container (type 0x85)
            0x01, // Length = 4 bytes
            0x01, 0x00, // PDU session data
            extension_header_type::NO_MORE, // End of chain
        ];

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("extension_header_count"), Some(&FieldValue::UInt8(2)));

        if let Some(FieldValue::OwnedString(ext)) = result.get("extension_headers") {
            assert!(ext.contains("UDP Port"));
            assert!(ext.contains("PDU Session Container"));
        } else {
            panic!("Expected extension_headers field");
        }
    }

    // Test 14: Extension header limit (max 16)
    #[test]
    fn test_extension_header_max_limit() {
        let parser = GtpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 2152);

        // Build a header with 20 extension headers (exceeds limit of 16)
        let mut header = vec![
            0x34, // Version 1, PT=1, E=1
            message_type::G_PDU,
            0x00, 0x60, // Length (large)
            0x00, 0x00, 0x00, 0x01, // TEID
            0x00, 0x00, // Sequence
            0x00, // N-PDU
            extension_header_type::UDP_PORT, // First ext header type
        ];

        // Add 20 extension headers
        for i in 0..20 {
            header.push(0x01); // Length = 4 bytes
            header.push((i & 0xFF) as u8); // Data byte 1
            header.push(((i >> 8) & 0xFF) as u8); // Data byte 2
            if i < 19 {
                header.push(extension_header_type::UDP_PORT); // Chain to next
            } else {
                header.push(extension_header_type::NO_MORE); // End
            }
        }

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        // Should be capped at MAX_EXTENSION_HEADERS (16)
        if let Some(FieldValue::UInt8(count)) = result.get("extension_header_count") {
            assert!(*count <= 16, "Extension header count should be capped at 16");
        }
    }

    // Test 15: GTPv2-C basic parsing
    #[test]
    fn test_gtpv2_basic_parsing() {
        let parser = GtpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 2123);

        // GTPv2-C header with TEID present
        let header = vec![
            0x48, // Version 2, P=0, T=1
            0x20, // Create Session Request (type 32)
            0x00, 0x0C, // Length
            0xAB, 0xCD, 0xEF, 0x12, // TEID
            0x00, 0x01, 0x23, // Sequence Number (291)
            0x00, // Spare
        ];

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("version"), Some(&FieldValue::UInt8(2)));
        assert_eq!(result.get("teid_present"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("teid"), Some(&FieldValue::UInt32(0xABCDEF12)));
        assert_eq!(result.get("message_type"), Some(&FieldValue::UInt8(0x20)));
    }

    // Test 16: GTPv2-C without TEID (T=0)
    #[test]
    fn test_gtpv2_no_teid() {
        let parser = GtpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 2123);

        // GTPv2-C header without TEID (T=0)
        let header = vec![
            0x40, // Version 2, P=0, T=0
            0x01, // Echo Request
            0x00, 0x08, // Length
            0x00, 0x00, 0x01, // Sequence Number
            0x00, // Spare
        ];

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("version"), Some(&FieldValue::UInt8(2)));
        assert_eq!(result.get("teid_present"), Some(&FieldValue::Bool(false)));
        assert!(result.get("teid").is_none()); // No TEID field
    }

    // Test 17: GTPv2-C with Piggybacked message (P=1)
    #[test]
    fn test_gtpv2_piggyback() {
        let parser = GtpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 2123);

        // GTPv2-C header with Piggyback flag
        let header = vec![
            0x58, // Version 2, P=1, T=1
            0x21, // Create Session Response
            0x00, 0x0C, // Length
            0x12, 0x34, 0x56, 0x78, // TEID
            0x00, 0x00, 0x01, // Sequence Number
            0x00, // Spare
        ];

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("piggyback"), Some(&FieldValue::Bool(true)));
    }

    // Test 18: GTPv2-C sequence number (24-bit)
    #[test]
    fn test_gtpv2_sequence_number() {
        let parser = GtpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 2123);

        // GTPv2-C with specific sequence number
        let header = vec![
            0x48, // Version 2, P=0, T=1
            0x22, // Modify Bearer Request
            0x00, 0x0C, // Length
            0x00, 0x00, 0x00, 0x01, // TEID
            0xAB, 0xCD, 0xEF, // Sequence Number = 0xABCDEF
            0x00, // Spare
        ];

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        // Sequence is stored as UInt32 for GTPv2 (24-bit value)
        assert_eq!(result.get("sequence"), Some(&FieldValue::UInt32(0xABCDEF)));
    }

    // Test 19: GTPv1 N-PDU number flag
    #[test]
    fn test_gtpv1_npdu_flag() {
        let parser = GtpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 2152);

        // GTPv1 with PN flag set
        let header = vec![
            0x31, // Version 1, PT=1, PN=1
            message_type::G_PDU,
            0x00, 0x08, // Length
            0x00, 0x00, 0x00, 0x01, // TEID
            0x00, 0x00, // Sequence
            0x42, // N-PDU Number = 66
            0x00, // Next extension header type
        ];

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("npdu"), Some(&FieldValue::UInt8(0x42)));
    }

    // Test 20: Extension header type names
    #[test]
    fn test_extension_header_type_names() {
        // Test the extension_header_type_name function via parsing
        let parser = GtpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 2152);

        let test_cases = [
            (extension_header_type::RAN_CONTAINER, "RAN Container"),
            (extension_header_type::NR_RAN_CONTAINER, "NR RAN Container"),
            (extension_header_type::LONG_PDCP_PDU_NUMBER, "Long PDCP PDU Number"),
        ];

        for (ext_type, expected_name) in test_cases {
            let header = vec![
                0x34, // Version 1, PT=1, E=1
                message_type::G_PDU,
                0x00, 0x0C, // Length
                0x00, 0x00, 0x00, 0x01, // TEID
                0x00, 0x00, // Sequence
                0x00, // N-PDU
                ext_type, // Extension header type
                0x01, // Length = 4 bytes
                0x00, 0x00, // Data
                extension_header_type::NO_MORE, // End
            ];

            let result = parser.parse(&header, &context);
            assert!(result.is_ok());

            if let Some(FieldValue::OwnedString(ext)) = result.get("extension_headers") {
                assert!(ext.contains(expected_name), "Expected '{}' in '{}'", expected_name, ext);
            } else {
                panic!("Expected extension_headers field");
            }
        }
    }

    // Test 21: GTPv2-C message types
    #[test]
    fn test_gtpv2_message_types() {
        let parser = GtpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 2123);

        // Common GTPv2-C message types
        let test_types: [(u8, &str); 6] = [
            (1, "Echo Request"),
            (2, "Echo Response"),
            (32, "Create Session Request"),
            (33, "Create Session Response"),
            (34, "Modify Bearer Request"),
            (35, "Modify Bearer Response"),
        ];

        for (msg_type, _name) in test_types {
            let header = vec![
                0x48, // Version 2, P=0, T=1
                msg_type,
                0x00, 0x0C, // Length
                0x00, 0x00, 0x00, 0x01, // TEID
                0x00, 0x00, 0x01, // Sequence
                0x00, // Spare
            ];

            let result = parser.parse(&header, &context);
            assert!(result.is_ok());
            assert_eq!(result.get("message_type"), Some(&FieldValue::UInt8(msg_type)));
        }
    }

    // Test 22: GTPv1 with all optional flags
    #[test]
    fn test_gtpv1_all_optional_flags() {
        let parser = GtpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 2152);

        // GTPv1 with E, S, and PN flags all set
        let header = vec![
            0x37, // Version 1, PT=1, E=1, S=1, PN=1
            message_type::G_PDU,
            0x00, 0x10, // Length
            0x12, 0x34, 0x56, 0x78, // TEID
            0xAB, 0xCD, // Sequence Number
            0x42, // N-PDU Number
            extension_header_type::UDP_PORT, // Next extension header
            0x01, // Ext length = 4 bytes
            0x08, 0x68, // UDP port data
            extension_header_type::NO_MORE,
        ];

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("teid"), Some(&FieldValue::UInt32(0x12345678)));
        assert_eq!(result.get("sequence"), Some(&FieldValue::UInt16(0xABCD)));
        assert_eq!(result.get("npdu"), Some(&FieldValue::UInt8(0x42)));
        assert_eq!(result.get("extension_header_count"), Some(&FieldValue::UInt8(1)));
    }
}
