//! GRE (Generic Routing Encapsulation) protocol parser.
//!
//! GRE is a tunneling protocol that can encapsulate a wide variety of
//! network layer protocols inside virtual point-to-point links.
//!
//! RFC 2784: Generic Routing Encapsulation (GRE)
//! RFC 2890: Key and Sequence Number Extensions to GRE
//! RFC 2637: Point-to-Point Tunneling Protocol (PPTP) - Enhanced GRE (Version 1)

use smallvec::SmallVec;

use super::{FieldValue, ParseContext, ParseResult, Protocol, TunnelType};
use crate::schema::{DataKind, FieldDescriptor};

/// IP protocol number for GRE.
pub const IP_PROTOCOL_GRE: u8 = 47;

/// GRE version numbers.
pub mod gre_version {
    /// Standard GRE (RFC 2784/2890).
    pub const STANDARD: u8 = 0;
    /// Enhanced GRE for PPTP (RFC 2637).
    pub const PPTP_ENHANCED: u8 = 1;
}

/// Calculate internet checksum over data.
/// Returns the checksum value (0 indicates valid checksum when computed over data including checksum field).
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    // Sum 16-bit words
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    // Handle odd byte
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// GRE protocol parser.
#[derive(Debug, Clone, Copy)]
pub struct GreProtocol;

impl Protocol for GreProtocol {
    fn name(&self) -> &'static str {
        "gre"
    }

    fn display_name(&self) -> &'static str {
        "GRE"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        // Match when IP protocol hint equals 47
        match context.hint("ip_protocol") {
            Some(proto) if proto == IP_PROTOCOL_GRE as u64 => Some(100),
            _ => None,
        }
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        // Minimum GRE header is 4 bytes (flags/version + protocol type)
        if data.len() < 4 {
            return ParseResult::error("GRE header too short".to_string(), data);
        }

        let mut fields = SmallVec::new();
        let mut offset = 0;

        // First 2 bytes: Flags and Version
        // Bit 0: Checksum present (C)
        // Bit 1: Reserved (R) - must be 0
        // Bit 2: Key present (K)
        // Bit 3: Sequence number present (S)
        // Bits 4: Strict source route (s)
        // Bits 5-7: Recursion control (Recur)
        // Bits 8-12: Flags (A in bit 8, rest reserved)
        // Bits 13-15: Version (0 for GRE, 1 for enhanced GRE)
        let flags = u16::from_be_bytes([data[0], data[1]]);

        let checksum_present = (flags & 0x8000) != 0;
        let key_present = (flags & 0x2000) != 0;
        let sequence_present = (flags & 0x1000) != 0;
        let version = (flags & 0x0007) as u8;

        fields.push(("checksum_present", FieldValue::Bool(checksum_present)));
        fields.push(("key_present", FieldValue::Bool(key_present)));
        fields.push(("sequence_present", FieldValue::Bool(sequence_present)));
        fields.push(("version", FieldValue::UInt8(version)));

        // Version validation (RFC 2784: Version MUST be 0, RFC 2637: Version 1 for PPTP)
        let version_valid =
            version == gre_version::STANDARD || version == gre_version::PPTP_ENHANCED;
        fields.push(("version_valid", FieldValue::Bool(version_valid)));

        // Add version name for convenience
        let version_name = match version {
            gre_version::STANDARD => "Standard",
            gre_version::PPTP_ENHANCED => "PPTP-Enhanced",
            _ => "Unknown",
        };
        fields.push(("version_name", FieldValue::Str(version_name)));

        offset += 2;

        // Next 2 bytes: Protocol Type (EtherType of encapsulated protocol)
        let protocol_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        fields.push(("protocol", FieldValue::UInt16(protocol_type)));
        offset += 2;

        // Track header length for checksum verification
        let header_start = 0;

        // Optional fields based on flags

        // Checksum and Reserved (4 bytes if C bit set)
        if checksum_present {
            if data.len() < offset + 4 {
                return ParseResult::error("GRE: missing checksum field".to_string(), data);
            }
            let checksum = u16::from_be_bytes([data[offset], data[offset + 1]]);
            fields.push(("checksum", FieldValue::UInt16(checksum)));

            // Calculate the end of GRE header + payload for checksum verification
            // GRE checksum covers the GRE header and payload
            // To verify: compute checksum over entire packet (with checksum field included)
            // Result should be 0 if valid
            let computed = internet_checksum(data);
            let checksum_valid = computed == 0;
            fields.push(("checksum_valid", FieldValue::Bool(checksum_valid)));

            // Reserved field (offset) is at offset+2..offset+4, typically ignored
            offset += 4;
        }

        // Key (4 bytes if K bit set)
        let mut key_value: Option<u32> = None;
        if key_present {
            if data.len() < offset + 4 {
                return ParseResult::error("GRE: missing key field".to_string(), data);
            }
            let key = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            fields.push(("key", FieldValue::UInt32(key)));
            key_value = Some(key);
            offset += 4;
        }

        // Sequence Number (4 bytes if S bit set)
        if sequence_present {
            if data.len() < offset + 4 {
                return ParseResult::error("GRE: missing sequence field".to_string(), data);
            }
            let sequence = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            fields.push(("sequence", FieldValue::UInt32(sequence)));
            offset += 4;
        }

        // Store header length
        fields.push((
            "header_length",
            FieldValue::UInt8((offset - header_start) as u8),
        ));

        // Set up child hints for the encapsulated protocol
        let mut child_hints = SmallVec::new();
        child_hints.push(("ethertype", protocol_type as u64));

        // If key is present, pass it as a hint for tunneling context
        if let Some(key) = key_value {
            child_hints.push(("gre_key", key as u64));
        }

        // Common ethertypes in GRE:
        // ethertype::IPV4 = IPv4
        // ethertype::IPV6 = IPv6
        // 0x6558 = Transparent Ethernet Bridging (for NVGRE)
        // 0x880B = PPP

        // Signal tunnel boundary for encapsulation tracking
        child_hints.push(("tunnel_type", TunnelType::Gre as u64));
        // Use GRE key as tunnel ID if present
        if let Some(key) = key_value {
            child_hints.push(("tunnel_id", key as u64));
        }

        ParseResult::success(fields, &data[offset..], child_hints)
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            FieldDescriptor::new("gre.checksum_present", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("gre.key_present", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("gre.sequence_present", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("gre.version", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("gre.version_valid", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("gre.version_name", DataKind::String).set_nullable(true),
            FieldDescriptor::new("gre.protocol", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("gre.checksum", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("gre.checksum_valid", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("gre.key", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("gre.sequence", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("gre.header_length", DataKind::UInt8).set_nullable(true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        // GRE can encapsulate many protocols
        &["ipv4", "ipv6", "ethernet"]
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &["ipv4", "ipv6"] // GRE runs over IPv4/IPv6 (IP protocol 47)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ethernet::ethertype;

    /// Create a minimal GRE header with just flags and protocol type.
    fn create_gre_header(checksum: bool, key: bool, sequence: bool, protocol: u16) -> Vec<u8> {
        let mut header = Vec::new();

        // Build flags word
        let mut flags: u16 = 0;
        if checksum {
            flags |= 0x8000;
        }
        if key {
            flags |= 0x2000;
        }
        if sequence {
            flags |= 0x1000;
        }
        // Version = 0

        header.extend_from_slice(&flags.to_be_bytes());
        header.extend_from_slice(&protocol.to_be_bytes());

        header
    }

    // Test 1: can_parse with IP protocol 47
    #[test]
    fn test_can_parse_with_ip_protocol_47() {
        let parser = GreProtocol;

        // Without hint
        let ctx1 = ParseContext::new(1);
        assert!(parser.can_parse(&ctx1).is_none());

        // With wrong IP protocol
        let mut ctx2 = ParseContext::new(1);
        ctx2.insert_hint("ip_protocol", 6); // TCP
        assert!(parser.can_parse(&ctx2).is_none());

        // With GRE IP protocol
        let mut ctx3 = ParseContext::new(1);
        ctx3.insert_hint("ip_protocol", 47);
        assert!(parser.can_parse(&ctx3).is_some());
        assert_eq!(parser.can_parse(&ctx3), Some(100));
    }

    // Test 2: Basic GRE header parsing (no optional fields)
    #[test]
    fn test_basic_gre_header_parsing() {
        let mut header = create_gre_header(false, false, false, ethertype::IPV4); // IPv4
                                                                                  // Add some payload
        header.extend_from_slice(&[0x45, 0x00, 0x00, 0x28]);

        let parser = GreProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 47);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("checksum_present"),
            Some(&FieldValue::Bool(false))
        );
        assert_eq!(result.get("key_present"), Some(&FieldValue::Bool(false)));
        assert_eq!(
            result.get("sequence_present"),
            Some(&FieldValue::Bool(false))
        );
        assert_eq!(result.get("version"), Some(&FieldValue::UInt8(0)));
        assert_eq!(
            result.get("protocol"),
            Some(&FieldValue::UInt16(ethertype::IPV4))
        );

        // Should not have optional fields
        assert!(result.get("checksum").is_none());
        assert!(result.get("key").is_none());
        assert!(result.get("sequence").is_none());

        // Remaining should be the payload
        assert_eq!(result.remaining.len(), 4);
    }

    // Test 3: GRE with checksum
    #[test]
    fn test_gre_with_checksum() {
        let mut header = create_gre_header(true, false, false, ethertype::IPV4);
        // Add checksum (2 bytes) and reserved (2 bytes)
        header.extend_from_slice(&[0xAB, 0xCD, 0x00, 0x00]);
        // Add payload
        header.extend_from_slice(&[0x45, 0x00]);

        let parser = GreProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 47);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("checksum_present"),
            Some(&FieldValue::Bool(true))
        );
        assert_eq!(result.get("checksum"), Some(&FieldValue::UInt16(0xABCD)));
        assert_eq!(result.remaining.len(), 2);
    }

    // Test 4: GRE with key
    #[test]
    fn test_gre_with_key() {
        let mut header = create_gre_header(false, true, false, ethertype::IPV4);
        // Add key (4 bytes)
        header.extend_from_slice(&[0x00, 0x01, 0x02, 0x03]);
        // Add payload
        header.extend_from_slice(&[0x45, 0x00]);

        let parser = GreProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 47);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("key_present"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("key"), Some(&FieldValue::UInt32(0x00010203)));
        assert_eq!(result.hint("gre_key"), Some(0x00010203u64));
        assert_eq!(result.remaining.len(), 2);
    }

    // Test 5: GRE with sequence number
    #[test]
    fn test_gre_with_sequence() {
        let mut header = create_gre_header(false, false, true, ethertype::IPV4);
        // Add sequence number (4 bytes)
        header.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        // Add payload
        header.extend_from_slice(&[0x45, 0x00]);

        let parser = GreProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 47);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("sequence_present"),
            Some(&FieldValue::Bool(true))
        );
        assert_eq!(
            result.get("sequence"),
            Some(&FieldValue::UInt32(0xDEADBEEF))
        );
        assert_eq!(result.remaining.len(), 2);
    }

    // Test 6: GRE with all optional fields
    #[test]
    fn test_gre_with_all_optional_fields() {
        let mut header = create_gre_header(true, true, true, ethertype::IPV6); // IPv6
                                                                               // Add checksum and reserved
        header.extend_from_slice(&[0x12, 0x34, 0x00, 0x00]);
        // Add key
        header.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        // Add sequence
        header.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        // Add payload
        header.extend_from_slice(&[0x60, 0x00]);

        let parser = GreProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 47);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("checksum_present"),
            Some(&FieldValue::Bool(true))
        );
        assert_eq!(result.get("key_present"), Some(&FieldValue::Bool(true)));
        assert_eq!(
            result.get("sequence_present"),
            Some(&FieldValue::Bool(true))
        );
        assert_eq!(result.get("checksum"), Some(&FieldValue::UInt16(0x1234)));
        assert_eq!(result.get("key"), Some(&FieldValue::UInt32(0xAABBCCDD)));
        assert_eq!(result.get("sequence"), Some(&FieldValue::UInt32(1)));
        assert_eq!(
            result.get("protocol"),
            Some(&FieldValue::UInt16(ethertype::IPV6))
        );
        assert_eq!(result.remaining.len(), 2);
    }

    // Test 7: Child protocol hint (ethertype)
    #[test]
    fn test_child_protocol_hint_ethertype() {
        // Test IPv4 ethertype
        let header_ipv4 = create_gre_header(false, false, false, ethertype::IPV4);
        let parser = GreProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 47);

        let result = parser.parse(&header_ipv4, &context);
        assert!(result.is_ok());
        assert_eq!(result.hint("ethertype"), Some(ethertype::IPV4 as u64));

        // Test IPv6 ethertype
        let header_ipv6 = create_gre_header(false, false, false, ethertype::IPV6);
        let result = parser.parse(&header_ipv6, &context);
        assert!(result.is_ok());
        assert_eq!(result.hint("ethertype"), Some(ethertype::IPV6 as u64));

        // Test Transparent Ethernet Bridging
        let header_teb = create_gre_header(false, false, false, 0x6558);
        let result = parser.parse(&header_teb, &context);
        assert!(result.is_ok());
        assert_eq!(result.hint("ethertype"), Some(0x6558u64));
    }

    // Test 8: Too short header
    #[test]
    fn test_gre_too_short() {
        let short_header = [0x00, 0x00]; // Only 2 bytes

        let parser = GreProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 47);

        let result = parser.parse(&short_header, &context);
        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }

    // Test 9: Missing optional fields when flags are set
    #[test]
    fn test_gre_missing_key_field() {
        let header = create_gre_header(false, true, false, ethertype::IPV4); // Key flag set but no key data

        let parser = GreProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 47);

        let result = parser.parse(&header, &context);
        assert!(!result.is_ok());
        assert!(result.error.unwrap().contains("missing key field"));
    }

    // Test 10: Schema fields
    #[test]
    fn test_gre_schema_fields() {
        let parser = GreProtocol;
        let fields = parser.schema_fields();

        assert!(!fields.is_empty());
        let field_names: Vec<&str> = fields.iter().map(|f| f.name).collect();
        assert!(field_names.contains(&"gre.checksum_present"));
        assert!(field_names.contains(&"gre.key_present"));
        assert!(field_names.contains(&"gre.sequence_present"));
        assert!(field_names.contains(&"gre.version"));
        assert!(field_names.contains(&"gre.protocol"));
        assert!(field_names.contains(&"gre.checksum"));
        assert!(field_names.contains(&"gre.key"));
        assert!(field_names.contains(&"gre.sequence"));
    }

    // Test 11: Version 0 (Standard GRE) validation
    #[test]
    fn test_version_0_standard_gre() {
        let parser = GreProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 47);

        // Standard GRE with version 0
        let header = create_gre_header(false, false, false, ethertype::IPV4);
        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("version"),
            Some(&FieldValue::UInt8(gre_version::STANDARD))
        );
        assert_eq!(result.get("version_valid"), Some(&FieldValue::Bool(true)));
        assert_eq!(
            result.get("version_name"),
            Some(&FieldValue::Str("Standard"))
        );
    }

    // Test 12: Version 1 (PPTP Enhanced GRE) validation
    #[test]
    fn test_version_1_pptp_enhanced() {
        let parser = GreProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 47);

        // Create PPTP Enhanced GRE (version 1) - manual construction
        let mut header = Vec::new();
        let flags: u16 = 0x0001; // Version 1
        header.extend_from_slice(&flags.to_be_bytes());
        header.extend_from_slice(&0x880Bu16.to_be_bytes()); // PPP protocol

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("version"),
            Some(&FieldValue::UInt8(gre_version::PPTP_ENHANCED))
        );
        assert_eq!(result.get("version_valid"), Some(&FieldValue::Bool(true)));
        assert_eq!(
            result.get("version_name"),
            Some(&FieldValue::Str("PPTP-Enhanced"))
        );
    }

    // Test 13: Invalid version (version 2-7)
    #[test]
    fn test_invalid_version() {
        let parser = GreProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 47);

        // Test versions 2-7 (all invalid)
        for version in 2..=7u16 {
            let mut header = Vec::new();
            let flags: u16 = version; // Version in bits 0-2
            header.extend_from_slice(&flags.to_be_bytes());
            header.extend_from_slice(&ethertype::IPV4.to_be_bytes());

            let result = parser.parse(&header, &context);

            assert!(result.is_ok()); // Still parses (lenient)
            assert_eq!(
                result.get("version"),
                Some(&FieldValue::UInt8(version as u8))
            );
            assert_eq!(result.get("version_valid"), Some(&FieldValue::Bool(false)));
            assert_eq!(
                result.get("version_name"),
                Some(&FieldValue::Str("Unknown"))
            );
        }
    }

    // Test 14: Checksum verification - valid checksum
    #[test]
    fn test_checksum_valid() {
        let parser = GreProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 47);

        // Create GRE header with checksum flag
        let mut packet = Vec::new();
        let flags: u16 = 0x8000; // Checksum present
        packet.extend_from_slice(&flags.to_be_bytes());
        packet.extend_from_slice(&ethertype::IPV4.to_be_bytes()); // IPv4

        // Placeholder for checksum and reserved (will be filled)
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // checksum + reserved

        // Add some payload
        packet.extend_from_slice(&[0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00]);

        // Calculate checksum (set checksum field to 0 first)
        let checksum = internet_checksum(&packet);

        // Insert correct checksum
        packet[4] = (checksum >> 8) as u8;
        packet[5] = (checksum & 0xFF) as u8;

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("checksum_present"),
            Some(&FieldValue::Bool(true))
        );
        assert_eq!(result.get("checksum_valid"), Some(&FieldValue::Bool(true)));
    }

    // Test 15: Checksum verification - invalid checksum
    #[test]
    fn test_checksum_invalid() {
        let parser = GreProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 47);

        // Create GRE header with wrong checksum
        let mut packet = Vec::new();
        let flags: u16 = 0x8000; // Checksum present
        packet.extend_from_slice(&flags.to_be_bytes());
        packet.extend_from_slice(&ethertype::IPV4.to_be_bytes());

        // Wrong checksum (0xABCD instead of correct value)
        packet.extend_from_slice(&[0xAB, 0xCD, 0x00, 0x00]);

        // Add payload
        packet.extend_from_slice(&[0x45, 0x00, 0x00, 0x28]);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok()); // Still parses (lenient)
        assert_eq!(
            result.get("checksum_present"),
            Some(&FieldValue::Bool(true))
        );
        assert_eq!(result.get("checksum_valid"), Some(&FieldValue::Bool(false)));
    }

    // Test 16: Header length calculation
    #[test]
    fn test_header_length() {
        let parser = GreProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 47);

        // Minimal header (4 bytes)
        let header_min = create_gre_header(false, false, false, ethertype::IPV4);
        let result = parser.parse(&header_min, &context);
        assert!(result.is_ok());
        assert_eq!(result.get("header_length"), Some(&FieldValue::UInt8(4)));

        // With checksum (4 + 4 = 8 bytes)
        let mut header_chk = create_gre_header(true, false, false, ethertype::IPV4);
        header_chk.extend_from_slice(&[0x00; 4]); // checksum + reserved
        let result = parser.parse(&header_chk, &context);
        assert!(result.is_ok());
        assert_eq!(result.get("header_length"), Some(&FieldValue::UInt8(8)));

        // With key (4 + 4 = 8 bytes)
        let mut header_key = create_gre_header(false, true, false, ethertype::IPV4);
        header_key.extend_from_slice(&[0x00; 4]); // key
        let result = parser.parse(&header_key, &context);
        assert!(result.is_ok());
        assert_eq!(result.get("header_length"), Some(&FieldValue::UInt8(8)));

        // With sequence (4 + 4 = 8 bytes)
        let mut header_seq = create_gre_header(false, false, true, ethertype::IPV4);
        header_seq.extend_from_slice(&[0x00; 4]); // sequence
        let result = parser.parse(&header_seq, &context);
        assert!(result.is_ok());
        assert_eq!(result.get("header_length"), Some(&FieldValue::UInt8(8)));

        // All optional fields (4 + 4 + 4 + 4 = 16 bytes)
        let mut header_all = create_gre_header(true, true, true, ethertype::IPV4);
        header_all.extend_from_slice(&[0x00; 4]); // checksum + reserved
        header_all.extend_from_slice(&[0x00; 4]); // key
        header_all.extend_from_slice(&[0x00; 4]); // sequence
        let result = parser.parse(&header_all, &context);
        assert!(result.is_ok());
        assert_eq!(result.get("header_length"), Some(&FieldValue::UInt8(16)));
    }

    // Test 17: Schema fields include new version and checksum validation fields
    #[test]
    fn test_schema_fields_complete() {
        let parser = GreProtocol;
        let fields = parser.schema_fields();

        let field_names: Vec<&str> = fields.iter().map(|f| f.name).collect();
        assert!(field_names.contains(&"gre.checksum_present"));
        assert!(field_names.contains(&"gre.key_present"));
        assert!(field_names.contains(&"gre.sequence_present"));
        assert!(field_names.contains(&"gre.version"));
        assert!(field_names.contains(&"gre.version_valid"));
        assert!(field_names.contains(&"gre.version_name"));
        assert!(field_names.contains(&"gre.protocol"));
        assert!(field_names.contains(&"gre.checksum"));
        assert!(field_names.contains(&"gre.checksum_valid"));
        assert!(field_names.contains(&"gre.key"));
        assert!(field_names.contains(&"gre.sequence"));
        assert!(field_names.contains(&"gre.header_length"));
    }

    // Test 18: internet_checksum function directly
    #[test]
    fn test_internet_checksum_function() {
        // Test with known data
        // Simple test: checksum of all zeros should be 0xFFFF
        let zeros = [0u8; 10];
        assert_eq!(internet_checksum(&zeros), 0xFFFF);

        // Test with 0xFFFF (ones complement of 0)
        let ffff = [0xFF, 0xFF];
        assert_eq!(internet_checksum(&ffff), 0x0000);

        // Test odd length data
        let odd = [0x01, 0x02, 0x03];
        let _cksum = internet_checksum(&odd);
        // Just verify it doesn't panic

        // Test checksum verification: original data + checksum should give 0
        let mut test_data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        let initial_sum = internet_checksum(&test_data);
        // Add the checksum to the data
        test_data.push((initial_sum >> 8) as u8);
        test_data.push((initial_sum & 0xFF) as u8);
        // Now checksum should be 0
        assert_eq!(internet_checksum(&test_data), 0);
    }

    // Test 19: Missing checksum field when flag set
    #[test]
    fn test_gre_missing_checksum_field() {
        let parser = GreProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 47);

        // Checksum flag set but no checksum data
        let header = create_gre_header(true, false, false, ethertype::IPV4);

        let result = parser.parse(&header, &context);
        assert!(!result.is_ok());
        assert!(result.error.unwrap().contains("missing checksum field"));
    }

    // Test 20: Missing sequence field when flag set
    #[test]
    fn test_gre_missing_sequence_field() {
        let parser = GreProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 47);

        // Sequence flag set but no sequence data
        let header = create_gre_header(false, false, true, ethertype::IPV4);

        let result = parser.parse(&header, &context);
        assert!(!result.is_ok());
        assert!(result.error.unwrap().contains("missing sequence field"));
    }
}
