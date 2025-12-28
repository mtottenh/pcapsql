//! Ethernet II protocol parser.

use smallvec::SmallVec;

use etherparse::Ethernet2HeaderSlice;

use super::{FieldValue, ParseContext, ParseResult, Protocol};
use crate::schema::{DataKind, FieldDescriptor};

/// Link type constant for Ethernet.
pub const LINKTYPE_ETHERNET: u16 = 1;

/// Well-known EtherType values (IEEE 802).
#[allow(dead_code)]
pub mod ethertype {
    // Common protocols
    pub const IPV4: u16 = 0x0800;
    pub const ARP: u16 = 0x0806;
    pub const WAKE_ON_LAN: u16 = 0x0842;
    pub const RARP: u16 = 0x8035;
    pub const VLAN: u16 = 0x8100;
    pub const IPV6: u16 = 0x86DD;
    pub const QINQ: u16 = 0x88A8;

    // Streaming/AV protocols
    pub const AVTP: u16 = 0x22F0;
    pub const SRP: u16 = 0x22EA;
    pub const TRILL: u16 = 0x22F3;

    // Legacy protocols
    pub const DEC_MOP_RC: u16 = 0x6002;
    pub const DECNET: u16 = 0x6003;
    pub const DEC_LAT: u16 = 0x6004;
    pub const APPLETALK: u16 = 0x809B;
    pub const AARP: u16 = 0x80F3;
    pub const IPX: u16 = 0x8137;
    pub const QNX_QNET: u16 = 0x8204;

    // Link layer protocols
    pub const SLPP: u16 = 0x8102;
    pub const VLACP: u16 = 0x8103;
    pub const FLOW_CONTROL: u16 = 0x8808;
    pub const LACP: u16 = 0x8809;
    pub const LLDP: u16 = 0x88CC;

    // MPLS
    pub const MPLS: u16 = 0x8847;
    pub const MPLS_MULTICAST: u16 = 0x8848;

    // PPPoE
    pub const PPPOE_DISCOVERY: u16 = 0x8863;
    pub const PPPOE_SESSION: u16 = 0x8864;

    // Industrial protocols
    pub const COBRANET: u16 = 0x8819;
    pub const PROFINET: u16 = 0x8892;
    pub const HYPERSCSI: u16 = 0x889A;
    pub const ATA_OVER_ETHERNET: u16 = 0x88A2;
    pub const ETHERCAT: u16 = 0x88A4;
    pub const POWERLINK: u16 = 0x88AB;
    pub const GOOSE: u16 = 0x88B8;
    pub const GSE: u16 = 0x88B9;
    pub const SV: u16 = 0x88BA;
    pub const SERCOS_III: u16 = 0x88CD;
    pub const MRP: u16 = 0x88E3;
    pub const PRP: u16 = 0x88FB;
    pub const HSR: u16 = 0x892F;

    // Security protocols
    pub const EAP_OVER_LAN: u16 = 0x888E;
    pub const MACSEC: u16 = 0x88E5;

    // Provider bridging
    pub const PBB: u16 = 0x88E7;

    // Time protocols
    pub const PTP: u16 = 0x88F7;

    // Network management
    pub const HOMEPLUG_MME: u16 = 0x887B;
    pub const HOMEPLUG_AV_MME: u16 = 0x88E1;
    pub const MIKROTIK_ROMON: u16 = 0x88BF;
    pub const NC_SI: u16 = 0x88F8;
    pub const CFM_OAM: u16 = 0x8902;

    // Storage protocols
    pub const FCOE: u16 = 0x8906;
    pub const FCOE_INIT: u16 = 0x8914;
    pub const ROCE: u16 = 0x8915;

    // Other
    pub const WSMP: u16 = 0x88DC;
    pub const TTE: u16 = 0x891D;
    pub const ECTP: u16 = 0x9000;
    pub const QINQ_OLD: u16 = 0x9100;
    pub const VERITAS_LLT: u16 = 0xCAFE;
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
            return Some(100);
        }

        // Also parse inside tunnels when link_type hint is set to Ethernet
        // This allows parsing inner Ethernet frames inside VXLAN, etc.
        if let Some(link_type) = context.hint("link_type") {
            if link_type == LINKTYPE_ETHERNET as u64 {
                return Some(100);
            }
        }

        None
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        match Ethernet2HeaderSlice::from_slice(data) {
            Ok(eth) => {
                let mut fields = SmallVec::new();

                fields.push(("src_mac", FieldValue::mac(&eth.source())));
                fields.push(("dst_mac", FieldValue::mac(&eth.destination())));
                fields.push(("ethertype", FieldValue::UInt16(eth.ether_type().0)));

                let mut child_hints = SmallVec::new();
                child_hints.push(("ethertype", eth.ether_type().0 as u64));

                let header_len = eth.slice().len();
                ParseResult::success(fields, &data[header_len..], child_hints)
            }
            Err(e) => ParseResult::error(format!("Ethernet parse error: {e}"), data),
        }
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            FieldDescriptor::mac_field("eth.src_mac").set_nullable(true),
            FieldDescriptor::mac_field("eth.dst_mac").set_nullable(true),
            FieldDescriptor::new("eth.ethertype", DataKind::UInt16).set_nullable(true),
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
        assert_eq!(result.hint("ethertype"), Some(ethertype::IPV4 as u64));
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
        assert_eq!(result.hint("ethertype"), Some(ethertype::IPV6 as u64));
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
