//! IEEE 802.1Q VLAN tag parser.

use smallvec::SmallVec;

use super::ethernet::ethertype;
use super::{FieldValue, ParseContext, ParseResult, Protocol};
use crate::schema::{DataKind, FieldDescriptor};

/// 802.1Q VLAN tag parser.
#[derive(Debug, Clone, Copy)]
pub struct VlanProtocol;

impl Protocol for VlanProtocol {
    fn name(&self) -> &'static str {
        "vlan"
    }

    fn display_name(&self) -> &'static str {
        "802.1Q VLAN"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        // Check for VLAN ethertype (0x8100) or QinQ (0x88A8)
        match context.hint("ethertype") {
            Some(etype) if etype == ethertype::VLAN as u64 => Some(100),
            Some(etype) if etype == ethertype::QINQ as u64 => Some(100),
            _ => None,
        }
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        // VLAN tag is 4 bytes total, but the TPID (2 bytes) was already
        // consumed by the Ethernet parser, so we just have TCI (2 bytes)
        // and the inner EtherType (2 bytes).
        if data.len() < 4 {
            return ParseResult::error("VLAN tag too short".to_string(), data);
        }

        let mut fields = SmallVec::new();

        // TCI (Tag Control Information) - 2 bytes
        let tci = u16::from_be_bytes([data[0], data[1]]);

        // PCP (Priority Code Point) - bits 13-15 (3 bits)
        let priority = (tci >> 13) & 0x07;
        fields.push(("priority", FieldValue::UInt8(priority as u8)));

        // DEI (Drop Eligible Indicator) - bit 12 (1 bit)
        let dei = (tci >> 12) & 0x01;
        fields.push(("dei", FieldValue::Bool(dei != 0)));

        // VID (VLAN Identifier) - bits 0-11 (12 bits)
        let vlan_id = tci & 0x0FFF;
        fields.push(("vlan_id", FieldValue::UInt16(vlan_id)));

        // Inner EtherType - 2 bytes
        let inner_ethertype = u16::from_be_bytes([data[2], data[3]]);
        fields.push(("inner_ethertype", FieldValue::UInt16(inner_ethertype)));

        // Set up child hints for the next layer
        let mut child_hints = SmallVec::new();
        child_hints.push(("ethertype", inner_ethertype as u64));
        child_hints.push(("vlan_id", vlan_id as u64));

        // VLAN tag is 4 bytes
        ParseResult::success(fields, &data[4..], child_hints)
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            FieldDescriptor::new("vlan.vlan_id", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("vlan.priority", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("vlan.dei", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("vlan.inner_ethertype", DataKind::UInt16).set_nullable(true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        &["ipv4", "ipv6", "arp", "vlan"]
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &["ethernet", "vlan"] // Can follow Ethernet or another VLAN (QinQ)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a VLAN tag with the given parameters.
    fn create_vlan_tag(vlan_id: u16, priority: u8, dei: bool, inner_ethertype: u16) -> Vec<u8> {
        let mut tag = Vec::with_capacity(4);

        // Build TCI
        let tci = ((priority as u16 & 0x07) << 13) | ((dei as u16) << 12) | (vlan_id & 0x0FFF);

        tag.extend_from_slice(&tci.to_be_bytes());
        tag.extend_from_slice(&inner_ethertype.to_be_bytes());

        tag
    }

    #[test]
    fn test_parse_vlan_basic() {
        // VLAN ID 100, Priority 0, DEI false, inner ethertype IPv4
        let tag = create_vlan_tag(100, 0, false, ethertype::IPV4);

        let parser = VlanProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ethertype", ethertype::VLAN as u64);
        context.parent_protocol = Some("ethernet");

        let result = parser.parse(&tag, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("vlan_id"), Some(&FieldValue::UInt16(100)));
        assert_eq!(result.get("priority"), Some(&FieldValue::UInt8(0)));
        assert_eq!(result.get("dei"), Some(&FieldValue::Bool(false)));
        assert_eq!(
            result.get("inner_ethertype"),
            Some(&FieldValue::UInt16(ethertype::IPV4))
        );
    }

    #[test]
    fn test_parse_vlan_with_priority() {
        // VLAN ID 200, Priority 5, DEI true, inner ethertype IPv6
        let tag = create_vlan_tag(200, 5, true, ethertype::IPV6);

        let parser = VlanProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ethertype", ethertype::VLAN as u64);
        context.parent_protocol = Some("ethernet");

        let result = parser.parse(&tag, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("vlan_id"), Some(&FieldValue::UInt16(200)));
        assert_eq!(result.get("priority"), Some(&FieldValue::UInt8(5)));
        assert_eq!(result.get("dei"), Some(&FieldValue::Bool(true)));
        assert_eq!(
            result.get("inner_ethertype"),
            Some(&FieldValue::UInt16(ethertype::IPV6))
        );
    }

    #[test]
    fn test_parse_vlan_max_id() {
        // Max VLAN ID (4095), max priority (7)
        let tag = create_vlan_tag(4095, 7, true, ethertype::IPV4);

        let parser = VlanProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ethertype", ethertype::VLAN as u64);

        let result = parser.parse(&tag, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("vlan_id"), Some(&FieldValue::UInt16(4095)));
        assert_eq!(result.get("priority"), Some(&FieldValue::UInt8(7)));
    }

    #[test]
    fn test_can_parse_vlan() {
        let parser = VlanProtocol;

        // Without hint
        let ctx1 = ParseContext::new(1);
        assert!(parser.can_parse(&ctx1).is_none());

        // With VLAN ethertype
        let mut ctx2 = ParseContext::new(1);
        ctx2.insert_hint("ethertype", ethertype::VLAN as u64);
        assert!(parser.can_parse(&ctx2).is_some());

        // With QinQ ethertype
        let mut ctx3 = ParseContext::new(1);
        ctx3.insert_hint("ethertype", ethertype::QINQ as u64);
        assert!(parser.can_parse(&ctx3).is_some());

        // With different ethertype
        let mut ctx4 = ParseContext::new(1);
        ctx4.insert_hint("ethertype", ethertype::IPV4 as u64);
        assert!(parser.can_parse(&ctx4).is_none());
    }

    #[test]
    fn test_parse_vlan_too_short() {
        let short_tag = [0x00, 0x64]; // Only 2 bytes

        let parser = VlanProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ethertype", ethertype::VLAN as u64);

        let result = parser.parse(&short_tag, &context);

        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }

    #[test]
    fn test_vlan_child_hints() {
        // VLAN ID 42, inner ethertype IPv4
        let tag = create_vlan_tag(42, 3, false, ethertype::IPV4);

        let parser = VlanProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ethertype", ethertype::VLAN as u64);

        let result = parser.parse(&tag, &context);

        assert!(result.is_ok());
        assert_eq!(result.hint("ethertype"), Some(ethertype::IPV4 as u64));
        assert_eq!(result.hint("vlan_id"), Some(42u64));
    }

    #[test]
    fn test_vlan_with_payload() {
        let mut data = create_vlan_tag(100, 0, false, ethertype::IPV4);
        // Add some payload (IPv4 header start)
        data.extend_from_slice(&[0x45, 0x00, 0x00, 0x28]);

        let parser = VlanProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ethertype", ethertype::VLAN as u64);

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.remaining.len(), 4); // IPv4 header bytes
        assert_eq!(result.remaining[0], 0x45); // IPv4 version/IHL
    }

    #[test]
    fn test_vlan_schema_fields() {
        let parser = VlanProtocol;
        let fields = parser.schema_fields();

        assert!(!fields.is_empty());

        let field_names: Vec<&str> = fields.iter().map(|f| f.name).collect();
        assert!(field_names.contains(&"vlan.vlan_id"));
        assert!(field_names.contains(&"vlan.priority"));
        assert!(field_names.contains(&"vlan.dei"));
        assert!(field_names.contains(&"vlan.inner_ethertype"));
    }
}
