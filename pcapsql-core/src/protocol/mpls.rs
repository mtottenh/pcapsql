//! MPLS (Multi-Protocol Label Switching) protocol parser.
//!
//! MPLS provides a mechanism for label switching that can transport multiple
//! types of traffic at high speed.
//!
//! RFC 3031: Multiprotocol Label Switching Architecture
//! RFC 3032: MPLS Label Stack Encoding

use std::collections::HashMap;

use super::{FieldValue, ParseContext, ParseResult, Protocol};
use crate::schema::{DataKind, FieldDescriptor};

/// EtherType for MPLS Unicast.
pub const ETHERTYPE_MPLS_UNICAST: u16 = 0x8847;

/// EtherType for MPLS Multicast.
pub const ETHERTYPE_MPLS_MULTICAST: u16 = 0x8848;

/// Maximum label stack depth (RFC compliance safety limit).
const MAX_LABEL_STACK_DEPTH: u8 = 16;

/// Special/reserved MPLS label values (RFC 3032).
pub mod special_label {
    /// IPv4 Explicit NULL Label - Used for PHP (Penultimate Hop Popping).
    pub const IPV4_EXPLICIT_NULL: u32 = 0;
    /// Router Alert Label - Delivers packet to router control plane.
    pub const ROUTER_ALERT: u32 = 1;
    /// IPv6 Explicit NULL Label.
    pub const IPV6_EXPLICIT_NULL: u32 = 2;
    /// Implicit NULL Label - Used in signaling, never appears on wire.
    pub const IMPLICIT_NULL: u32 = 3;
    /// Entropy Label Indicator (RFC 6790).
    pub const ENTROPY_LABEL_INDICATOR: u32 = 7;
    /// GAL (Generic Associated Channel Label) (RFC 5586).
    pub const GAL: u32 = 13;
    /// OAM Alert Label (RFC 3429).
    pub const OAM_ALERT: u32 = 14;
    /// Extension Label (RFC 7274).
    pub const EXTENSION: u32 = 15;
}

/// Get the name of a special/reserved MPLS label.
fn special_label_name(label: u32) -> Option<&'static str> {
    match label {
        special_label::IPV4_EXPLICIT_NULL => Some("IPv4-Explicit-NULL"),
        special_label::ROUTER_ALERT => Some("Router-Alert"),
        special_label::IPV6_EXPLICIT_NULL => Some("IPv6-Explicit-NULL"),
        special_label::IMPLICIT_NULL => Some("Implicit-NULL"),
        special_label::ENTROPY_LABEL_INDICATOR => Some("ELI"),
        special_label::GAL => Some("GAL"),
        special_label::OAM_ALERT => Some("OAM-Alert"),
        special_label::EXTENSION => Some("Extension"),
        4..=6 | 8..=12 => Some("Reserved"),
        _ => None,
    }
}

/// MPLS protocol parser.
#[derive(Debug, Clone, Copy)]
pub struct MplsProtocol;

impl Protocol for MplsProtocol {
    fn name(&self) -> &'static str {
        "mpls"
    }

    fn display_name(&self) -> &'static str {
        "MPLS"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        // Match when ethertype hint equals MPLS unicast or multicast
        match context.hint("ethertype") {
            Some(et) if et == ETHERTYPE_MPLS_UNICAST as u64 => Some(100),
            Some(et) if et == ETHERTYPE_MPLS_MULTICAST as u64 => Some(100),
            _ => None,
        }
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        // Each MPLS label stack entry is 4 bytes
        if data.len() < 4 {
            return ParseResult::error("MPLS: label stack entry too short".to_string(), data);
        }

        let mut fields = HashMap::new();
        let mut offset = 0;
        let mut stack_depth = 0u8;
        let mut labels = Vec::new();
        let mut bottom_of_stack = false;

        // Parse all labels in the stack
        // Each label is 4 bytes:
        // - Label: 20 bits
        // - TC (Traffic Class): 3 bits
        // - S (Bottom of Stack): 1 bit
        // - TTL: 8 bits
        let mut top_label = 0u32;
        let mut top_tc = 0u8;
        let mut top_ttl = 0u8;
        let mut has_special_label = false;
        let mut special_label_str: Option<String> = None;

        while !bottom_of_stack && offset + 4 <= data.len() {
            // Check stack depth limit for safety
            if stack_depth >= MAX_LABEL_STACK_DEPTH {
                return ParseResult::error(
                    format!("MPLS: label stack too deep (max {})", MAX_LABEL_STACK_DEPTH),
                    data,
                );
            }

            let label_entry = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);

            let label = (label_entry >> 12) & 0xFFFFF; // Top 20 bits
            let tc = ((label_entry >> 9) & 0x07) as u8; // Next 3 bits
            bottom_of_stack = (label_entry >> 8) & 0x01 == 1; // Next 1 bit
            let ttl = (label_entry & 0xFF) as u8; // Bottom 8 bits

            // Store first (top) label values for the fields
            if stack_depth == 0 {
                top_label = label;
                top_tc = tc;
                top_ttl = ttl;

                // Check if top label is a special/reserved label
                if label <= 15 {
                    has_special_label = true;
                    special_label_str = special_label_name(label).map(|s| s.to_string());
                }
            }

            // Track if any label in stack is reserved
            if label <= 15 && !has_special_label {
                has_special_label = true;
            }

            labels.push(label.to_string());
            stack_depth += 1;
            offset += 4;
        }

        if stack_depth == 0 {
            return ParseResult::error("MPLS: no labels found".to_string(), data);
        }

        fields.insert("label", FieldValue::UInt32(top_label));
        fields.insert("tc", FieldValue::UInt8(top_tc));
        fields.insert("bottom", FieldValue::Bool(bottom_of_stack));
        fields.insert("ttl", FieldValue::UInt8(top_ttl));
        fields.insert("stack_depth", FieldValue::UInt8(stack_depth));
        fields.insert("labels", FieldValue::String(labels.join(",")));

        // Add special label fields
        fields.insert("is_reserved_label", FieldValue::Bool(has_special_label));
        if let Some(name) = special_label_str {
            fields.insert("special_label_name", FieldValue::String(name));
        }

        // Set up child hints
        let mut child_hints = HashMap::new();

        // After the bottom of stack, we need to detect the inner protocol
        // by looking at the first nibble of the payload
        if bottom_of_stack && offset < data.len() {
            let first_byte = data[offset];
            let version = (first_byte >> 4) & 0x0F;

            match version {
                4 => {
                    child_hints.insert("ethertype", 0x0800u64); // IPv4
                    child_hints.insert("ip_version", 4u64);
                }
                6 => {
                    child_hints.insert("ethertype", 0x86DDu64); // IPv6
                    child_hints.insert("ip_version", 6u64);
                }
                _ => {
                    // Unknown inner protocol, could be Ethernet or other
                    // Check if it might be Ethernet (looking for valid MAC prefix)
                }
            }
        }

        ParseResult::success(fields, &data[offset..], child_hints)
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            FieldDescriptor::new("mpls.label", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("mpls.tc", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("mpls.bottom", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("mpls.ttl", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("mpls.stack_depth", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("mpls.labels", DataKind::String).set_nullable(true),
            FieldDescriptor::new("mpls.is_reserved_label", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("mpls.special_label_name", DataKind::String).set_nullable(true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        &["ipv4", "ipv6", "ethernet"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create an MPLS label stack entry.
    fn create_mpls_label(label: u32, tc: u8, bottom: bool, ttl: u8) -> [u8; 4] {
        let entry = ((label & 0xFFFFF) << 12)
            | ((tc as u32 & 0x07) << 9)
            | ((bottom as u32) << 8)
            | (ttl as u32 & 0xFF);
        entry.to_be_bytes()
    }

    // Test 1: can_parse with MPLS ethertype
    #[test]
    fn test_can_parse_with_mpls_ethertype() {
        let parser = MplsProtocol;

        // Without hint
        let ctx1 = ParseContext::new(1);
        assert!(parser.can_parse(&ctx1).is_none());

        // With IPv4 ethertype
        let mut ctx2 = ParseContext::new(1);
        ctx2.hints.insert("ethertype", 0x0800);
        assert!(parser.can_parse(&ctx2).is_none());

        // With MPLS unicast ethertype
        let mut ctx3 = ParseContext::new(1);
        ctx3.hints.insert("ethertype", 0x8847);
        assert!(parser.can_parse(&ctx3).is_some());

        // With MPLS multicast ethertype
        let mut ctx4 = ParseContext::new(1);
        ctx4.hints.insert("ethertype", 0x8848);
        assert!(parser.can_parse(&ctx4).is_some());
    }

    // Test 2: Single label parsing
    #[test]
    fn test_single_label_parsing() {
        let mut data = Vec::new();
        // Label 1000, TC 3, Bottom=true, TTL 64
        data.extend_from_slice(&create_mpls_label(1000, 3, true, 64));
        // Add IPv4 header start (version 4)
        data.extend_from_slice(&[0x45, 0x00, 0x00, 0x28]);

        let parser = MplsProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ethertype", 0x8847);

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("label"), Some(&FieldValue::UInt32(1000)));
        assert_eq!(result.get("tc"), Some(&FieldValue::UInt8(3)));
        assert_eq!(result.get("bottom"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("ttl"), Some(&FieldValue::UInt8(64)));
        assert_eq!(result.get("stack_depth"), Some(&FieldValue::UInt8(1)));
        assert_eq!(result.get("labels"), Some(&FieldValue::String("1000".to_string())));
        assert_eq!(result.remaining.len(), 4);
    }

    // Test 3: Label stack (multiple labels)
    #[test]
    fn test_label_stack_multiple_labels() {
        let mut data = Vec::new();
        // First label: 100, TC 0, Bottom=false, TTL 255
        data.extend_from_slice(&create_mpls_label(100, 0, false, 255));
        // Second label: 200, TC 1, Bottom=false, TTL 254
        data.extend_from_slice(&create_mpls_label(200, 1, false, 254));
        // Third label (bottom): 300, TC 2, Bottom=true, TTL 253
        data.extend_from_slice(&create_mpls_label(300, 2, true, 253));
        // Add IPv4 header
        data.extend_from_slice(&[0x45, 0x00]);

        let parser = MplsProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ethertype", 0x8847);

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        // Top label should be 100
        assert_eq!(result.get("label"), Some(&FieldValue::UInt32(100)));
        // TC of top label
        assert_eq!(result.get("tc"), Some(&FieldValue::UInt8(0)));
        // TTL of top label
        assert_eq!(result.get("ttl"), Some(&FieldValue::UInt8(255)));
        // Stack depth should be 3
        assert_eq!(result.get("stack_depth"), Some(&FieldValue::UInt8(3)));
        // Labels string
        assert_eq!(result.get("labels"), Some(&FieldValue::String("100,200,300".to_string())));
        // Bottom flag reflects the last label
        assert_eq!(result.get("bottom"), Some(&FieldValue::Bool(true)));
    }

    // Test 4: TC field extraction
    #[test]
    fn test_tc_field_extraction() {
        // Test all TC values (0-7)
        for tc in 0u8..=7 {
            let data = create_mpls_label(500, tc, true, 128);

            let parser = MplsProtocol;
            let mut context = ParseContext::new(1);
            context.hints.insert("ethertype", 0x8847);

            let result = parser.parse(&data, &context);

            assert!(result.is_ok());
            assert_eq!(result.get("tc"), Some(&FieldValue::UInt8(tc)));
        }
    }

    // Test 5: Bottom of stack detection
    #[test]
    fn test_bottom_of_stack_detection() {
        // Single label with bottom=true
        let data1 = create_mpls_label(100, 0, true, 64);
        let parser = MplsProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ethertype", 0x8847);

        let result1 = parser.parse(&data1, &context);
        assert!(result1.is_ok());
        assert_eq!(result1.get("bottom"), Some(&FieldValue::Bool(true)));
        assert_eq!(result1.get("stack_depth"), Some(&FieldValue::UInt8(1)));

        // Two labels, only second has bottom=true
        let mut data2 = Vec::new();
        data2.extend_from_slice(&create_mpls_label(100, 0, false, 64));
        data2.extend_from_slice(&create_mpls_label(200, 0, true, 63));

        let result2 = parser.parse(&data2, &context);
        assert!(result2.is_ok());
        assert_eq!(result2.get("stack_depth"), Some(&FieldValue::UInt8(2)));
    }

    // Test 6: TTL extraction
    #[test]
    fn test_ttl_extraction() {
        // Test various TTL values
        for ttl in [0u8, 1, 64, 128, 254, 255] {
            let data = create_mpls_label(100, 0, true, ttl);

            let parser = MplsProtocol;
            let mut context = ParseContext::new(1);
            context.hints.insert("ethertype", 0x8847);

            let result = parser.parse(&data, &context);

            assert!(result.is_ok());
            assert_eq!(result.get("ttl"), Some(&FieldValue::UInt8(ttl)));
        }
    }

    // Test 7: Child protocol detection (IPv4 vs IPv6)
    #[test]
    fn test_child_protocol_detection() {
        let parser = MplsProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ethertype", 0x8847);

        // IPv4 inner (version nibble = 4)
        let mut data_ipv4 = Vec::new();
        data_ipv4.extend_from_slice(&create_mpls_label(100, 0, true, 64));
        data_ipv4.extend_from_slice(&[0x45, 0x00, 0x00, 0x28]); // IPv4 header start

        let result_ipv4 = parser.parse(&data_ipv4, &context);
        assert!(result_ipv4.is_ok());
        assert_eq!(result_ipv4.child_hints.get("ethertype"), Some(&0x0800u64));
        assert_eq!(result_ipv4.child_hints.get("ip_version"), Some(&4u64));

        // IPv6 inner (version nibble = 6)
        let mut data_ipv6 = Vec::new();
        data_ipv6.extend_from_slice(&create_mpls_label(100, 0, true, 64));
        data_ipv6.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // IPv6 header start

        let result_ipv6 = parser.parse(&data_ipv6, &context);
        assert!(result_ipv6.is_ok());
        assert_eq!(result_ipv6.child_hints.get("ethertype"), Some(&0x86DDu64));
        assert_eq!(result_ipv6.child_hints.get("ip_version"), Some(&6u64));
    }

    // Test 8: Too short data
    #[test]
    fn test_mpls_too_short() {
        let short_data = [0x00, 0x01, 0x02]; // Only 3 bytes

        let parser = MplsProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ethertype", 0x8847);

        let result = parser.parse(&short_data, &context);
        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }

    // Test 9: Maximum label value (20-bit: 0xFFFFF = 1048575)
    #[test]
    fn test_max_label_value() {
        let data = create_mpls_label(0xFFFFF, 7, true, 255);

        let parser = MplsProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ethertype", 0x8847);

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("label"), Some(&FieldValue::UInt32(0xFFFFF)));
        assert_eq!(result.get("tc"), Some(&FieldValue::UInt8(7)));
        assert_eq!(result.get("ttl"), Some(&FieldValue::UInt8(255)));
    }

    // Test 10: Schema fields
    #[test]
    fn test_mpls_schema_fields() {
        let parser = MplsProtocol;
        let fields = parser.schema_fields();

        assert!(!fields.is_empty());
        let field_names: Vec<&str> = fields.iter().map(|f| f.name).collect();
        assert!(field_names.contains(&"mpls.label"));
        assert!(field_names.contains(&"mpls.tc"));
        assert!(field_names.contains(&"mpls.bottom"));
        assert!(field_names.contains(&"mpls.ttl"));
        assert!(field_names.contains(&"mpls.stack_depth"));
        assert!(field_names.contains(&"mpls.labels"));
    }

    // Test 11: Special label recognition - IPv4 Explicit NULL
    #[test]
    fn test_special_label_ipv4_explicit_null() {
        let parser = MplsProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ethertype", 0x8847);

        // Label 0 = IPv4 Explicit NULL
        let mut data = Vec::new();
        data.extend_from_slice(&create_mpls_label(special_label::IPV4_EXPLICIT_NULL, 0, true, 64));
        data.extend_from_slice(&[0x45, 0x00]); // IPv4 payload

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("label"), Some(&FieldValue::UInt32(0)));
        assert_eq!(result.get("is_reserved_label"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("special_label_name"), Some(&FieldValue::String("IPv4-Explicit-NULL".to_string())));
    }

    // Test 12: Special label recognition - Router Alert
    #[test]
    fn test_special_label_router_alert() {
        let parser = MplsProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ethertype", 0x8847);

        // Label 1 = Router Alert
        let data = create_mpls_label(special_label::ROUTER_ALERT, 0, true, 64);

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("label"), Some(&FieldValue::UInt32(1)));
        assert_eq!(result.get("is_reserved_label"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("special_label_name"), Some(&FieldValue::String("Router-Alert".to_string())));
    }

    // Test 13: Special label recognition - IPv6 Explicit NULL
    #[test]
    fn test_special_label_ipv6_explicit_null() {
        let parser = MplsProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ethertype", 0x8847);

        // Label 2 = IPv6 Explicit NULL
        let mut data = Vec::new();
        data.extend_from_slice(&create_mpls_label(special_label::IPV6_EXPLICIT_NULL, 0, true, 64));
        data.extend_from_slice(&[0x60, 0x00]); // IPv6 payload

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("label"), Some(&FieldValue::UInt32(2)));
        assert_eq!(result.get("is_reserved_label"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("special_label_name"), Some(&FieldValue::String("IPv6-Explicit-NULL".to_string())));
    }

    // Test 14: All special/reserved labels
    #[test]
    fn test_all_special_labels() {
        let parser = MplsProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ethertype", 0x8847);

        let test_cases = [
            (special_label::IPV4_EXPLICIT_NULL, "IPv4-Explicit-NULL"),
            (special_label::ROUTER_ALERT, "Router-Alert"),
            (special_label::IPV6_EXPLICIT_NULL, "IPv6-Explicit-NULL"),
            (special_label::IMPLICIT_NULL, "Implicit-NULL"),
            (special_label::ENTROPY_LABEL_INDICATOR, "ELI"),
            (special_label::GAL, "GAL"),
            (special_label::OAM_ALERT, "OAM-Alert"),
            (special_label::EXTENSION, "Extension"),
        ];

        for (label, expected_name) in test_cases {
            let data = create_mpls_label(label, 0, true, 64);
            let result = parser.parse(&data, &context);

            assert!(result.is_ok());
            assert_eq!(result.get("is_reserved_label"), Some(&FieldValue::Bool(true)));
            assert_eq!(result.get("special_label_name"), Some(&FieldValue::String(expected_name.to_string())));
        }
    }

    // Test 15: Reserved labels (4-6, 8-12)
    #[test]
    fn test_reserved_labels() {
        let parser = MplsProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ethertype", 0x8847);

        // Labels 4-6 and 8-12 are reserved
        for label in [4u32, 5, 6, 8, 9, 10, 11, 12] {
            let data = create_mpls_label(label, 0, true, 64);
            let result = parser.parse(&data, &context);

            assert!(result.is_ok());
            assert_eq!(result.get("is_reserved_label"), Some(&FieldValue::Bool(true)));
            assert_eq!(result.get("special_label_name"), Some(&FieldValue::String("Reserved".to_string())));
        }
    }

    // Test 16: Non-reserved label has no special name
    #[test]
    fn test_normal_label_not_reserved() {
        let parser = MplsProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ethertype", 0x8847);

        // Labels >= 16 are normal labels
        let data = create_mpls_label(16, 0, true, 64);
        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("is_reserved_label"), Some(&FieldValue::Bool(false)));
        assert!(result.get("special_label_name").is_none());

        // Test a more typical label value
        let data2 = create_mpls_label(1000, 0, true, 64);
        let result2 = parser.parse(&data2, &context);

        assert!(result2.is_ok());
        assert_eq!(result2.get("is_reserved_label"), Some(&FieldValue::Bool(false)));
        assert!(result2.get("special_label_name").is_none());
    }

    // Test 17: Stack depth limit (16 labels)
    #[test]
    fn test_stack_depth_limit() {
        let parser = MplsProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ethertype", 0x8847);

        // Create exactly 16 labels (should pass)
        let mut data_16 = Vec::new();
        for i in 0..15 {
            data_16.extend_from_slice(&create_mpls_label(100 + i, 0, false, 64));
        }
        data_16.extend_from_slice(&create_mpls_label(115, 0, true, 64)); // Bottom

        let result_16 = parser.parse(&data_16, &context);
        assert!(result_16.is_ok());
        assert_eq!(result_16.get("stack_depth"), Some(&FieldValue::UInt8(16)));

        // Create 17 labels (should fail - exceeds MAX_LABEL_STACK_DEPTH)
        let mut data_17 = Vec::new();
        for i in 0..16 {
            data_17.extend_from_slice(&create_mpls_label(100 + i, 0, false, 64));
        }
        data_17.extend_from_slice(&create_mpls_label(116, 0, true, 64)); // Would be 17th

        let result_17 = parser.parse(&data_17, &context);
        assert!(!result_17.is_ok());
        assert!(result_17.error.as_ref().unwrap().contains("too deep"));
    }

    // Test 18: Label stack with special label in the middle
    #[test]
    fn test_special_label_in_stack() {
        let parser = MplsProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ethertype", 0x8847);

        // Stack: [1000, Router Alert (1), 2000]
        let mut data = Vec::new();
        data.extend_from_slice(&create_mpls_label(1000, 0, false, 64));
        data.extend_from_slice(&create_mpls_label(special_label::ROUTER_ALERT, 0, false, 63));
        data.extend_from_slice(&create_mpls_label(2000, 0, true, 62));

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        // Top label is not special
        assert_eq!(result.get("label"), Some(&FieldValue::UInt32(1000)));
        // But stack contains a reserved label
        assert_eq!(result.get("is_reserved_label"), Some(&FieldValue::Bool(true)));
        // special_label_name is None because top label isn't special
        assert!(result.get("special_label_name").is_none());
    }

    // Test 19: Schema fields include new reserved label fields
    #[test]
    fn test_schema_fields_complete() {
        let parser = MplsProtocol;
        let fields = parser.schema_fields();

        let field_names: Vec<&str> = fields.iter().map(|f| f.name).collect();
        assert!(field_names.contains(&"mpls.label"));
        assert!(field_names.contains(&"mpls.tc"));
        assert!(field_names.contains(&"mpls.bottom"));
        assert!(field_names.contains(&"mpls.ttl"));
        assert!(field_names.contains(&"mpls.stack_depth"));
        assert!(field_names.contains(&"mpls.labels"));
        assert!(field_names.contains(&"mpls.is_reserved_label"));
        assert!(field_names.contains(&"mpls.special_label_name"));
    }
}
