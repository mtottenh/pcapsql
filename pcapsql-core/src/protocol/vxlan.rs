//! VXLAN (Virtual Extensible LAN) protocol parser.
//!
//! VXLAN is a network virtualization technology that attempts to address
//! the scalability problems associated with large cloud computing deployments.
//!
//! RFC 7348: Virtual eXtensible Local Area Network (VXLAN)

use std::collections::HashMap;

use super::{FieldValue, ParseContext, ParseResult, Protocol};
use crate::schema::{DataKind, FieldDescriptor};

/// Standard VXLAN UDP destination port.
pub const VXLAN_PORT: u16 = 4789;

/// VXLAN protocol parser.
#[derive(Debug, Clone, Copy)]
pub struct VxlanProtocol;

impl Protocol for VxlanProtocol {
    fn name(&self) -> &'static str {
        "vxlan"
    }

    fn display_name(&self) -> &'static str {
        "VXLAN"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        // Match when UDP dst_port hint equals 4789
        match context.hint("dst_port") {
            Some(port) if port == VXLAN_PORT as u64 => Some(100),
            _ => None,
        }
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        // VXLAN header is 8 bytes
        if data.len() < 8 {
            return ParseResult::error("VXLAN header too short".to_string(), data);
        }

        let mut fields = HashMap::new();

        // Byte 0: Flags
        // Bit 3 (I flag): Must be 1 to indicate valid VNI per RFC 7348
        // Bits 0-2, 4-7: Reserved (must be 0)
        let flags = data[0];
        let i_flag = (flags & 0x08) != 0;

        fields.insert("flags", FieldValue::UInt8(flags));

        // RFC 7348: I flag MUST be set to 1 for valid VNI
        // Store the validity for analysis (lenient parsing - still decode even if invalid)
        fields.insert("i_flag_valid", FieldValue::Bool(i_flag));

        // Check if reserved bits are zero (for strict validation)
        let reserved_flags_zero = (flags & 0xF7) == 0;
        fields.insert("flags_valid", FieldValue::Bool(reserved_flags_zero && i_flag));

        // Bytes 1-3: Reserved (should be 0)
        // We skip validation as some implementations may use these

        // Bytes 4-6: VNI (24-bit VXLAN Network Identifier)
        let vni = ((data[4] as u32) << 16) | ((data[5] as u32) << 8) | (data[6] as u32);
        fields.insert("vni", FieldValue::UInt32(vni));

        // Byte 7: Reserved (should be 0)

        // Calculate inner frame length
        let inner_frame_len = data.len() - 8;
        if inner_frame_len > 0 {
            fields.insert("inner_frame_length", FieldValue::UInt32(inner_frame_len as u32));
        }

        // Set up child hints for the inner Ethernet frame
        let mut child_hints = HashMap::new();

        // VXLAN encapsulates Ethernet frames, so set link_type to Ethernet
        child_hints.insert("link_type", 1u64); // DLT_EN10MB = Ethernet

        ParseResult::success(fields, &data[8..], child_hints)
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            FieldDescriptor::new("vxlan.flags", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("vxlan.vni", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("vxlan.i_flag_valid", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("vxlan.flags_valid", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("vxlan.inner_frame_length", DataKind::UInt32).set_nullable(true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        // VXLAN encapsulates Ethernet frames
        &["ethernet"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a VXLAN header with the given VNI.
    fn create_vxlan_header(vni: u32, i_flag: bool) -> [u8; 8] {
        let mut header = [0u8; 8];

        // Flags byte - I flag is bit 3
        if i_flag {
            header[0] = 0x08;
        }

        // VNI in bytes 4-6 (24-bit)
        header[4] = ((vni >> 16) & 0xFF) as u8;
        header[5] = ((vni >> 8) & 0xFF) as u8;
        header[6] = (vni & 0xFF) as u8;

        header
    }

    // Test 1: can_parse with UDP port 4789
    #[test]
    fn test_can_parse_with_udp_port_4789() {
        let parser = VxlanProtocol;

        // Without hint
        let ctx1 = ParseContext::new(1);
        assert!(parser.can_parse(&ctx1).is_none());

        // With wrong port
        let mut ctx2 = ParseContext::new(1);
        ctx2.hints.insert("dst_port", 80);
        assert!(parser.can_parse(&ctx2).is_none());

        // With VXLAN port
        let mut ctx3 = ParseContext::new(1);
        ctx3.hints.insert("dst_port", 4789);
        assert!(parser.can_parse(&ctx3).is_some());
        assert_eq!(parser.can_parse(&ctx3), Some(100));
    }

    // Test 2: VNI extraction
    #[test]
    fn test_vni_extraction() {
        let parser = VxlanProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("dst_port", 4789);

        // Test various VNI values
        let test_vnis = [0u32, 1, 100, 1000, 0xFFFFFF]; // Max is 24-bit

        for vni in test_vnis {
            let header = create_vxlan_header(vni, true);
            let result = parser.parse(&header, &context);

            assert!(result.is_ok());
            assert_eq!(result.get("vni"), Some(&FieldValue::UInt32(vni)));
        }
    }

    // Test 3: Flags parsing
    #[test]
    fn test_flags_parsing() {
        let parser = VxlanProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("dst_port", 4789);

        // With I flag set
        let header_with_i = create_vxlan_header(100, true);
        let result = parser.parse(&header_with_i, &context);
        assert!(result.is_ok());
        assert_eq!(result.get("flags"), Some(&FieldValue::UInt8(0x08)));

        // Without I flag (should still parse)
        let header_without_i = create_vxlan_header(100, false);
        let result = parser.parse(&header_without_i, &context);
        assert!(result.is_ok());
        assert_eq!(result.get("flags"), Some(&FieldValue::UInt8(0x00)));
    }

    // Test 4: I flag validation
    #[test]
    fn test_i_flag_validation() {
        let parser = VxlanProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("dst_port", 4789);

        // Valid VXLAN with I flag set
        let valid_header = create_vxlan_header(12345, true);
        let result = parser.parse(&valid_header, &context);
        assert!(result.is_ok());

        // VXLAN without I flag - should still parse (lenient)
        let no_i_header = create_vxlan_header(12345, false);
        let result = parser.parse(&no_i_header, &context);
        assert!(result.is_ok());
    }

    // Test 5: Inner Ethernet frame detection
    #[test]
    fn test_inner_ethernet_frame_detection() {
        let parser = VxlanProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("dst_port", 4789);

        let mut data = Vec::new();
        data.extend_from_slice(&create_vxlan_header(100, true));
        // Add inner Ethernet frame (at least 14 bytes)
        data.extend_from_slice(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Dst MAC
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Src MAC
            0x08, 0x00, // EtherType (IPv4)
        ]);

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.remaining.len(), 14); // Inner Ethernet header
        assert_eq!(result.child_hints.get("link_type"), Some(&1u64));
    }

    // Test 6: Child protocol hint
    #[test]
    fn test_child_protocol_hint() {
        let parser = VxlanProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("dst_port", 4789);

        let header = create_vxlan_header(42, true);
        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        // Should set link_type hint for Ethernet
        assert_eq!(result.child_hints.get("link_type"), Some(&1u64));
    }

    // Test 7: Too short header
    #[test]
    fn test_vxlan_too_short() {
        let parser = VxlanProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("dst_port", 4789);

        let short_header = [0x08, 0x00, 0x00, 0x00]; // Only 4 bytes
        let result = parser.parse(&short_header, &context);

        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }

    // Test 8: VNI with payload
    #[test]
    fn test_vni_with_payload() {
        let parser = VxlanProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("dst_port", 4789);

        let mut data = Vec::new();
        data.extend_from_slice(&create_vxlan_header(999999, true));
        // Add some payload
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("vni"), Some(&FieldValue::UInt32(999999)));
        assert_eq!(result.remaining.len(), 4);
    }

    // Test 9: Schema fields
    #[test]
    fn test_vxlan_schema_fields() {
        let parser = VxlanProtocol;
        let fields = parser.schema_fields();

        assert!(!fields.is_empty());
        let field_names: Vec<&str> = fields.iter().map(|f| f.name).collect();
        assert!(field_names.contains(&"vxlan.flags"));
        assert!(field_names.contains(&"vxlan.vni"));
    }

    // Test 10: Specific VNI values
    #[test]
    fn test_specific_vni_values() {
        let parser = VxlanProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("dst_port", 4789);

        // Common VNI values
        let header1 = create_vxlan_header(1, true);
        let result = parser.parse(&header1, &context);
        assert!(result.is_ok());
        assert_eq!(result.get("vni"), Some(&FieldValue::UInt32(1)));

        // Max VNI (24-bit)
        let header2 = create_vxlan_header(0xFFFFFF, true);
        let result = parser.parse(&header2, &context);
        assert!(result.is_ok());
        assert_eq!(result.get("vni"), Some(&FieldValue::UInt32(0xFFFFFF)));
    }

    // Test 11: i_flag_valid field
    #[test]
    fn test_i_flag_valid_field() {
        let parser = VxlanProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("dst_port", 4789);

        // With I flag set (valid)
        let valid_header = create_vxlan_header(100, true);
        let result = parser.parse(&valid_header, &context);
        assert!(result.is_ok());
        assert_eq!(result.get("i_flag_valid"), Some(&FieldValue::Bool(true)));

        // Without I flag (invalid per RFC)
        let invalid_header = create_vxlan_header(100, false);
        let result = parser.parse(&invalid_header, &context);
        assert!(result.is_ok()); // Still parses (lenient)
        assert_eq!(result.get("i_flag_valid"), Some(&FieldValue::Bool(false)));
    }

    // Test 12: flags_valid field (checks reserved bits too)
    #[test]
    fn test_flags_valid_field() {
        let parser = VxlanProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("dst_port", 4789);

        // Valid: I flag set, reserved bits zero
        let valid_header = create_vxlan_header(100, true); // flags = 0x08
        let result = parser.parse(&valid_header, &context);
        assert!(result.is_ok());
        assert_eq!(result.get("flags_valid"), Some(&FieldValue::Bool(true)));

        // Invalid: I flag not set
        let no_i_header = create_vxlan_header(100, false); // flags = 0x00
        let result = parser.parse(&no_i_header, &context);
        assert!(result.is_ok());
        assert_eq!(result.get("flags_valid"), Some(&FieldValue::Bool(false)));
    }

    // Test 13: flags_valid with reserved bits set
    #[test]
    fn test_flags_valid_reserved_bits() {
        let parser = VxlanProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("dst_port", 4789);

        // Header with reserved bits set (bit 0 set in addition to I flag)
        let mut header = [0u8; 8];
        header[0] = 0x09; // I flag (0x08) + bit 0 (0x01)
        header[4] = 0x00;
        header[5] = 0x00;
        header[6] = 0x64; // VNI = 100

        let result = parser.parse(&header, &context);
        assert!(result.is_ok());
        // Should be invalid because reserved bit is set
        assert_eq!(result.get("flags_valid"), Some(&FieldValue::Bool(false)));
        // But i_flag_valid should still be true
        assert_eq!(result.get("i_flag_valid"), Some(&FieldValue::Bool(true)));
    }

    // Test 14: inner_frame_length field
    #[test]
    fn test_inner_frame_length_field() {
        let parser = VxlanProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("dst_port", 4789);

        // VXLAN header only (no inner frame)
        let header_only = create_vxlan_header(100, true);
        let result = parser.parse(&header_only, &context);
        assert!(result.is_ok());
        // No inner frame length when there's no payload
        assert!(result.get("inner_frame_length").is_none());

        // With inner Ethernet frame (14 bytes minimum)
        let mut with_frame = Vec::new();
        with_frame.extend_from_slice(&create_vxlan_header(100, true));
        with_frame.extend_from_slice(&[0u8; 14]); // Minimum Ethernet header
        let result = parser.parse(&with_frame, &context);
        assert!(result.is_ok());
        assert_eq!(result.get("inner_frame_length"), Some(&FieldValue::UInt32(14)));

        // With larger inner frame
        let mut with_payload = Vec::new();
        with_payload.extend_from_slice(&create_vxlan_header(100, true));
        with_payload.extend_from_slice(&[0u8; 1500]); // Full MTU
        let result = parser.parse(&with_payload, &context);
        assert!(result.is_ok());
        assert_eq!(result.get("inner_frame_length"), Some(&FieldValue::UInt32(1500)));
    }

    // Test 15: Various VNI values with validation
    #[test]
    fn test_vni_range() {
        let parser = VxlanProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("dst_port", 4789);

        let test_cases = [
            (0, "zero VNI"),
            (1, "minimum VNI"),
            (4096, "common tenant VNI"),
            (100000, "large VNI"),
            (0xFFFFFF, "maximum VNI (24-bit)"),
        ];

        for (vni, _desc) in test_cases {
            let header = create_vxlan_header(vni, true);
            let result = parser.parse(&header, &context);
            assert!(result.is_ok());
            assert_eq!(result.get("vni"), Some(&FieldValue::UInt32(vni)));
        }
    }

    // Test 16: Schema fields include new fields
    #[test]
    fn test_schema_fields_complete() {
        let parser = VxlanProtocol;
        let fields = parser.schema_fields();

        let field_names: Vec<&str> = fields.iter().map(|f| f.name).collect();
        assert!(field_names.contains(&"vxlan.flags"));
        assert!(field_names.contains(&"vxlan.vni"));
        assert!(field_names.contains(&"vxlan.i_flag_valid"));
        assert!(field_names.contains(&"vxlan.flags_valid"));
        assert!(field_names.contains(&"vxlan.inner_frame_length"));
    }
}
