//! Linux SLL2 (Sockaddr Link Layer version 2) protocol parser.
//!
//! Parses the second-generation Linux cooked capture header
//! (LINKTYPE_LINUX_SLL2 = 276). libpcap >= 1.10 writes SLL2 by default for
//! `tcpdump -i any`, so this is the most common link type on modern Linux
//! hosts. Compared to SLL (113) the header grows to 20 bytes and gains the
//! interface index of the capturing interface.
//!
//! Layout (all multi-byte fields big-endian):
//!
//! | Offset | Size | Field                       |
//! |--------|------|-----------------------------|
//! | 0      | 2    | protocol type (ethertype)   |
//! | 2      | 2    | reserved (MBZ)              |
//! | 4      | 4    | interface index             |
//! | 8      | 2    | ARPHRD_ type                |
//! | 10     | 1    | packet type                 |
//! | 11     | 1    | link-layer address length   |
//! | 12     | 8    | link-layer address          |

use smallvec::SmallVec;

use super::linux_sll::{arphrd, arphrd_name, packet_type_name};
use super::{FieldValue, ParseContext, ParseGate, ParseResult, Protocol};
use crate::schema::{DataKind, FieldDescriptor};

/// PCAP link type for Linux SLL2 captures.
pub const LINKTYPE_LINUX_SLL2: u16 = 276;

/// Linux SLL2 header length in bytes.
pub const LINUX_SLL2_HEADER_LEN: usize = 20;

/// Linux SLL2 protocol parser.
///
/// Parses the 20-byte cooked capture header and routes to child protocols
/// the same way [`super::LinuxSllProtocol`] does: an `ethertype` hint for
/// Ethernet-like interfaces, a `netlink_family` hint for netlink sockets.
#[derive(Debug, Clone, Copy)]
pub struct Sll2Protocol;

impl Protocol for Sll2Protocol {
    fn name(&self) -> &'static str {
        "sll2"
    }

    fn display_name(&self) -> &'static str {
        "Linux SLL2"
    }

    fn parse_gates(&self) -> &'static [ParseGate] {
        &[ParseGate::Root]
    }

    fn child_hint_keys(&self) -> Option<&'static [&'static str]> {
        Some(&[
            "ethertype",
            "is_netlink",
            "netlink_family",
            "sll_arphrd",
            "sll_protocol",
        ])
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        if context.is_root() && context.link_type == LINKTYPE_LINUX_SLL2 {
            return Some(100);
        }
        None
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        if data.len() < LINUX_SLL2_HEADER_LEN {
            return ParseResult::error(
                format!("Linux SLL2 header too short: {} bytes", data.len()),
                data,
            );
        }

        let protocol = u16::from_be_bytes([data[0], data[1]]);
        let interface_index = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let arphrd_type = u16::from_be_bytes([data[8], data[9]]);
        let pkt_type = data[10];
        let addr_len = data[11];

        let mut fields = SmallVec::new();
        fields.push(("protocol", FieldValue::UInt16(protocol)));
        fields.push(("interface_index", FieldValue::UInt32(interface_index)));
        fields.push(("arphrd_type", FieldValue::UInt16(arphrd_type)));
        fields.push(("arphrd_name", FieldValue::Str(arphrd_name(arphrd_type))));
        fields.push(("packet_type", FieldValue::UInt8(pkt_type)));
        fields.push((
            "packet_type_name",
            FieldValue::Str(packet_type_name(pkt_type as u16)),
        ));
        fields.push(("addr_len", FieldValue::UInt8(addr_len)));

        let valid_addr_len = (addr_len as usize).min(8);
        if valid_addr_len > 0 {
            fields.push(("addr", FieldValue::Bytes(&data[12..12 + valid_addr_len])));
        }

        let remaining = &data[LINUX_SLL2_HEADER_LEN..];

        // Per the LINKTYPE_LINUX_SLL2 spec the protocol field is an ethertype
        // for every ARPHRD type except NETLINK (netlink family), IPGRE (GRE
        // protocol type), IEEE80211_RADIOTAP and FRAD (field not meaningful).
        // `tcpdump -i any` hosts routinely carry tun/ppp/sit interfaces
        // (ARPHRD_NONE, PPP, SIT, RAWIP, ...), so the default arm must route
        // to IP.
        let mut child_hints = SmallVec::new();
        child_hints.push(("sll_arphrd", arphrd_type as u64));
        match arphrd_type {
            arphrd::NETLINK => {
                child_hints.push(("netlink_family", protocol as u64));
                child_hints.push(("is_netlink", 1u64));
            }
            arphrd::IPGRE | arphrd::IEEE80211_RADIOTAP | arphrd::FRAD => {
                child_hints.push(("sll_protocol", protocol as u64));
            }
            _ => {
                child_hints.push(("ethertype", protocol as u64));
            }
        }

        ParseResult::success(fields, remaining, child_hints)
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            FieldDescriptor::new("sll2.protocol", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("sll2.interface_index", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("sll2.arphrd_type", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("sll2.arphrd_name", DataKind::String).set_nullable(true),
            FieldDescriptor::new("sll2.packet_type", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("sll2.packet_type_name", DataKind::String).set_nullable(true),
            FieldDescriptor::new("sll2.addr_len", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("sll2.addr", DataKind::Binary).set_nullable(true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        // Ethernet is never a child here: the cooked header replaces it and
        // the protocol field carries the ethertype directly.
        &["netlink", "ipv4", "ipv6", "arp"]
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &[] // Root protocol - no dependencies
    }
}

#[cfg(test)]
mod tests {
    use super::super::linux_sll::packet_type;
    use super::*;

    /// Build an SLL2 header (big-endian) followed by `payload`.
    fn sll2_header(
        protocol: u16,
        ifindex: u32,
        arphrd_type: u16,
        pkt_type: u8,
        addr_len: u8,
        addr: [u8; 8],
        payload: &[u8],
    ) -> Vec<u8> {
        let mut h = Vec::with_capacity(20 + payload.len());
        h.extend_from_slice(&protocol.to_be_bytes());
        h.extend_from_slice(&[0, 0]);
        h.extend_from_slice(&ifindex.to_be_bytes());
        h.extend_from_slice(&arphrd_type.to_be_bytes());
        h.push(pkt_type);
        h.push(addr_len);
        h.extend_from_slice(&addr);
        h.extend_from_slice(payload);
        h
    }

    #[test]
    fn can_parse_only_at_root_with_sll2_link_type() {
        let parser = Sll2Protocol;
        assert_eq!(
            parser.can_parse(&ParseContext::new(LINKTYPE_LINUX_SLL2)),
            Some(100)
        );
        assert!(parser.can_parse(&ParseContext::new(1)).is_none());
        assert!(parser.can_parse(&ParseContext::new(113)).is_none());
        let mut nested = ParseContext::new(LINKTYPE_LINUX_SLL2);
        nested.parent_protocol = Some("something");
        assert!(parser.can_parse(&nested).is_none());
    }

    #[test]
    fn parse_ethernet_like_header() {
        let data = sll2_header(
            0x0800,
            7,
            arphrd::ETHER,
            packet_type::OUTGOING as u8,
            6,
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0, 0],
            &[0xAA, 0xBB],
        );
        let result = Sll2Protocol.parse(&data, &ParseContext::new(LINKTYPE_LINUX_SLL2));
        assert!(result.is_ok());
        assert_eq!(result.get("protocol"), Some(&FieldValue::UInt16(0x0800)));
        assert_eq!(result.get("interface_index"), Some(&FieldValue::UInt32(7)));
        assert_eq!(
            result.get("arphrd_type"),
            Some(&FieldValue::UInt16(arphrd::ETHER))
        );
        assert_eq!(result.get("arphrd_name"), Some(&FieldValue::Str("ETHER")));
        assert_eq!(result.get("packet_type"), Some(&FieldValue::UInt8(4)));
        assert_eq!(
            result.get("packet_type_name"),
            Some(&FieldValue::Str("OUTGOING"))
        );
        assert_eq!(result.get("addr_len"), Some(&FieldValue::UInt8(6)));
        assert_eq!(
            result.get("addr"),
            Some(&FieldValue::Bytes(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        );
        assert_eq!(result.hint("ethertype"), Some(0x0800));
        assert_eq!(result.remaining, &[0xAA, 0xBB]);
    }

    #[test]
    fn parse_netlink_header_sets_netlink_hints() {
        let data = sll2_header(
            0,
            0,
            arphrd::NETLINK,
            packet_type::HOST as u8,
            0,
            [0; 8],
            &[],
        );
        let result = Sll2Protocol.parse(&data, &ParseContext::new(LINKTYPE_LINUX_SLL2));
        assert!(result.is_ok());
        assert_eq!(result.get("arphrd_name"), Some(&FieldValue::Str("NETLINK")));
        assert!(result.get("addr").is_none());
        assert_eq!(result.hint("is_netlink"), Some(1));
        assert_eq!(result.hint("netlink_family"), Some(0));
        assert!(result.hint("ethertype").is_none());
    }

    /// tun/ppp/sit interfaces report ARPHRD types the parser does not name;
    /// the protocol field is still an ethertype and IP must be reachable.
    #[test]
    fn unknown_arphrd_still_routes_by_ethertype() {
        for arphrd_type in [
            0xFFFEu16, /* NONE (tun) */
            512,       /* PPP */
            776,       /* SIT */
            519,       /* RAWIP */
        ] {
            let data = sll2_header(0x0800, 5, arphrd_type, 0, 0, [0; 8], &[]);
            let result = Sll2Protocol.parse(&data, &ParseContext::new(LINKTYPE_LINUX_SLL2));
            assert!(result.is_ok());
            assert_eq!(
                result.hint("ethertype"),
                Some(0x0800),
                "arphrd {arphrd_type}"
            );
            assert_eq!(result.hint("sll_arphrd"), Some(arphrd_type as u64));
        }
        // GRE / radiotap / frame relay: the field is not an ethertype.
        for arphrd_type in [arphrd::IPGRE, arphrd::IEEE80211_RADIOTAP, arphrd::FRAD] {
            let data = sll2_header(0x0800, 5, arphrd_type, 0, 0, [0; 8], &[]);
            let result = Sll2Protocol.parse(&data, &ParseContext::new(LINKTYPE_LINUX_SLL2));
            assert!(result.hint("ethertype").is_none(), "arphrd {arphrd_type}");
            assert_eq!(result.hint("sll_protocol"), Some(0x0800));
        }
    }

    /// End to end through the registry: an SLL2 frame from a tun interface
    /// (ARPHRD_NONE) parses sll2 -> ipv4 -> udp.
    #[test]
    fn parse_packet_reaches_ip_through_sll2() {
        use super::super::{default_registry, parse_packet, ParseScope};
        let udp = [0x9C, 0x40, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]; // 40000 -> 53, len 8
        let mut ip = vec![0x45, 0x00, 0x00, 28, 0, 1, 0x40, 0, 64, 17, 0, 0];
        ip.extend_from_slice(&[10, 0, 0, 1, 8, 8, 8, 8]);
        ip.extend_from_slice(&udp);
        let frame = sll2_header(0x0800, 3, 0xFFFE, 4, 0, [0; 8], &ip);
        let registry = default_registry();
        let layers: Vec<&str> =
            parse_packet(&registry, LINKTYPE_LINUX_SLL2, &frame, &ParseScope::full())
                .iter()
                .map(|(n, _)| *n)
                .collect();
        assert_eq!(layers, ["sll2", "ipv4", "udp"]);
        // Scoped to udp only: pruning must still walk through the cooked header.
        let scoped = ParseScope::for_tables(&["udp"], &registry);
        let layers: Vec<&str> = parse_packet(&registry, LINKTYPE_LINUX_SLL2, &frame, &scoped)
            .iter()
            .map(|(n, _)| *n)
            .collect();
        assert_eq!(layers, ["sll2", "ipv4", "udp"]);
    }

    /// Netlink accepts the v2 cooked header as its parent.
    #[test]
    fn netlink_accepts_sll2_parent() {
        use super::super::{NetlinkProtocol, Protocol};
        let mut ctx = ParseContext::new(LINKTYPE_LINUX_SLL2);
        ctx.parent_protocol = Some("sll2");
        ctx.insert_hint("is_netlink", 1);
        assert_eq!(NetlinkProtocol.can_parse(&ctx), Some(100));
    }

    #[test]
    fn short_header_is_an_error() {
        let result = Sll2Protocol.parse(&[0u8; 19], &ParseContext::new(LINKTYPE_LINUX_SLL2));
        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }

    #[test]
    fn addr_len_is_clamped_to_eight_bytes() {
        let data = sll2_header(0x86DD, 1, arphrd::ETHER, 0, 200, [1; 8], &[]);
        let result = Sll2Protocol.parse(&data, &ParseContext::new(LINKTYPE_LINUX_SLL2));
        assert!(result.is_ok());
        assert_eq!(result.get("addr"), Some(&FieldValue::Bytes(&[1; 8])));
    }

    #[test]
    fn schema_fields_are_prefixed() {
        let names: Vec<&str> = Sll2Protocol
            .schema_fields()
            .iter()
            .map(|f| f.name)
            .collect();
        assert_eq!(
            names,
            [
                "sll2.protocol",
                "sll2.interface_index",
                "sll2.arphrd_type",
                "sll2.arphrd_name",
                "sll2.packet_type",
                "sll2.packet_type_name",
                "sll2.addr_len",
                "sll2.addr",
            ]
        );
    }
}
