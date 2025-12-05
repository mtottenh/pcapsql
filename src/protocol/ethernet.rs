//! Ethernet II protocol parser.

use std::collections::HashMap;

use arrow::datatypes::{DataType, Field};
use etherparse::Ethernet2HeaderSlice;

use super::{FieldValue, ParseContext, ParseResult, Protocol};

/// Link type constant for Ethernet.
pub const LINKTYPE_ETHERNET: u16 = 1;

/// Well-known EtherTypes.
pub mod ethertype {
    pub const IPV4: u16 = 0x0800;
    pub const ARP: u16 = 0x0806;
    pub const VLAN: u16 = 0x8100;
    pub const IPV6: u16 = 0x86DD;
}

/// Ethernet II protocol parser.
#[derive(Debug, Clone, Copy)]
pub struct EthernetProtocol;

impl Protocol for EthernetProtocol {
    fn name(&self) -> &'static str {
        "ethernet"
    }

    fn display_name(&self) -> &'static str {
        "Ethernet II"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        // Parse Ethernet at the root level for Ethernet link type
        if context.is_root() && context.link_type == LINKTYPE_ETHERNET {
            Some(100)
        } else {
            None
        }
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        match Ethernet2HeaderSlice::from_slice(data) {
            Ok(eth) => {
                let mut fields = HashMap::new();

                fields.insert("src_mac", FieldValue::mac(&eth.source()));
                fields.insert("dst_mac", FieldValue::mac(&eth.destination()));
                fields.insert("ethertype", FieldValue::UInt16(eth.ether_type().0));

                let mut child_hints = HashMap::new();
                child_hints.insert("ethertype", eth.ether_type().0 as u64);

                let header_len = eth.slice().len();
                ParseResult::success(fields, &data[header_len..], child_hints)
            }
            Err(e) => ParseResult::error(format!("Ethernet parse error: {e}"), data),
        }
    }

    fn schema_fields(&self) -> Vec<Field> {
        vec![
            Field::new("eth.src_mac", DataType::FixedSizeBinary(6), true),
            Field::new("eth.dst_mac", DataType::FixedSizeBinary(6), true),
            Field::new("eth.ethertype", DataType::UInt16, true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        &["ipv4", "ipv6", "arp", "vlan"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ethernet() {
        // Sample Ethernet frame: dst MAC, src MAC, ethertype (0x0800 = IPv4)
        let frame = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst: broadcast
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
            0x08, 0x00, // ethertype: IPv4
            0x45, 0x00, // IPv4 header start (payload)
        ];

        let parser = EthernetProtocol;
        let context = ParseContext::new(LINKTYPE_ETHERNET);
        let result = parser.parse(&frame, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("ethertype"),
            Some(&FieldValue::UInt16(ethertype::IPV4))
        );
        assert_eq!(result.remaining.len(), 2); // IPv4 header bytes
        assert_eq!(result.child_hints.get("ethertype"), Some(&0x0800u64));
    }

    #[test]
    fn test_parse_ethernet_ipv6() {
        let frame = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // src
            0x86, 0xdd, // ethertype: IPv6
        ];

        let parser = EthernetProtocol;
        let context = ParseContext::new(LINKTYPE_ETHERNET);
        let result = parser.parse(&frame, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("ethertype"),
            Some(&FieldValue::UInt16(ethertype::IPV6))
        );
        assert_eq!(result.child_hints.get("ethertype"), Some(&0x86DDu64));
    }

    #[test]
    fn test_parse_ethernet_arp() {
        let frame = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst: broadcast
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
            0x08, 0x06, // ethertype: ARP
            0x00, 0x01, // ARP start
        ];

        let parser = EthernetProtocol;
        let context = ParseContext::new(LINKTYPE_ETHERNET);
        let result = parser.parse(&frame, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("ethertype"),
            Some(&FieldValue::UInt16(ethertype::ARP))
        );
    }

    #[test]
    fn test_can_parse_only_at_root() {
        let parser = EthernetProtocol;

        // At root with Ethernet link type
        let root_ctx = ParseContext::new(LINKTYPE_ETHERNET);
        assert!(parser.can_parse(&root_ctx).is_some());

        // At root with non-Ethernet link type
        let other_ctx = ParseContext::new(113); // Linux cooked capture
        assert!(parser.can_parse(&other_ctx).is_none());

        // Not at root
        let mut child_ctx = ParseContext::new(LINKTYPE_ETHERNET);
        child_ctx.parent_protocol = Some("something");
        assert!(parser.can_parse(&child_ctx).is_none());
    }

    #[test]
    fn test_parse_ethernet_too_short() {
        let short_frame = [0xff, 0xff, 0xff, 0xff, 0xff]; // Only 5 bytes

        let parser = EthernetProtocol;
        let context = ParseContext::new(LINKTYPE_ETHERNET);
        let result = parser.parse(&short_frame, &context);

        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }

    #[test]
    fn test_mac_address_extraction() {
        let frame = [
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, // dst
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, // src
            0x08, 0x00, // ethertype
        ];

        let parser = EthernetProtocol;
        let context = ParseContext::new(LINKTYPE_ETHERNET);
        let result = parser.parse(&frame, &context);

        assert!(result.is_ok());

        // Check MAC addresses are properly extracted
        let src_mac = result.get("src_mac").unwrap();
        let dst_mac = result.get("dst_mac").unwrap();

        assert!(src_mac.as_string().is_some());
        assert!(dst_mac.as_string().is_some());
    }
}
