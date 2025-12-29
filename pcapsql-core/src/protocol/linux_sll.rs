//! Linux SLL (Sockaddr Link Layer) protocol parser.
//!
//! Parses Linux cooked capture headers (LINKTYPE_LINUX_SLL = 113).
//! This format is used when capturing on the "any" interface or for
//! protocols that don't have a native link-layer header.

use smallvec::SmallVec;

use super::{FieldValue, ParseContext, ParseResult, Protocol};
use crate::schema::{DataKind, FieldDescriptor};

/// PCAP link type for Linux SLL captures.
pub const LINKTYPE_LINUX_SLL: u16 = 113;

/// Linux SLL header length in bytes.
pub const LINUX_SLL_HEADER_LEN: usize = 16;

/// ARPHRD types (link layer hardware types).
pub mod arphrd {
    pub const ETHER: u16 = 1;
    pub const LOOPBACK: u16 = 772;
    pub const FRAD: u16 = 770;
    pub const IPGRE: u16 = 778;
    pub const IEEE80211_RADIOTAP: u16 = 803;
    pub const IP6GRE: u16 = 823;
    pub const NETLINK: u16 = 824;
}

/// Packet type values.
pub mod packet_type {
    pub const HOST: u16 = 0; // Packet was sent to us
    pub const BROADCAST: u16 = 1; // Broadcast by another host
    pub const MULTICAST: u16 = 2; // Multicast by another host
    pub const OTHERHOST: u16 = 3; // Sent to someone else
    pub const OUTGOING: u16 = 4; // Sent by us
}

/// Get the name of a packet type.
fn packet_type_name(pkt_type: u16) -> &'static str {
    match pkt_type {
        packet_type::HOST => "HOST",
        packet_type::BROADCAST => "BROADCAST",
        packet_type::MULTICAST => "MULTICAST",
        packet_type::OTHERHOST => "OTHERHOST",
        packet_type::OUTGOING => "OUTGOING",
        _ => "UNKNOWN",
    }
}

/// Get the name of an ARPHRD type.
fn arphrd_name(arphrd: u16) -> &'static str {
    match arphrd {
        arphrd::ETHER => "ETHER",
        arphrd::LOOPBACK => "LOOPBACK",
        arphrd::FRAD => "FRAD",
        arphrd::IPGRE => "IPGRE",
        arphrd::IEEE80211_RADIOTAP => "IEEE80211_RADIOTAP",
        arphrd::IP6GRE => "IP6GRE",
        arphrd::NETLINK => "NETLINK",
        _ => "UNKNOWN",
    }
}

/// Linux SLL protocol parser.
///
/// Parses the 16-byte Linux cooked capture header and routes to
/// appropriate child protocols based on the ARPHRD type and protocol field.
#[derive(Debug, Clone, Copy)]
pub struct LinuxSllProtocol;

impl Protocol for LinuxSllProtocol {
    fn name(&self) -> &'static str {
        "linux_sll"
    }

    fn display_name(&self) -> &'static str {
        "Linux SLL"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        // Only parse at root level with LINKTYPE_LINUX_SLL
        if context.is_root() && context.link_type == LINKTYPE_LINUX_SLL {
            return Some(100);
        }
        None
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        // Linux SLL header is 16 bytes minimum
        if data.len() < LINUX_SLL_HEADER_LEN {
            return ParseResult::error(
                format!("Linux SLL header too short: {} bytes", data.len()),
                data,
            );
        }

        let mut fields = SmallVec::new();

        // Parse header fields (all big-endian)
        let pkt_type = u16::from_be_bytes([data[0], data[1]]);
        let arphrd_type = u16::from_be_bytes([data[2], data[3]]);
        let addr_len = u16::from_be_bytes([data[4], data[5]]);
        // addr is bytes 6-13 (8 bytes, but only addr_len are valid)
        let protocol = u16::from_be_bytes([data[14], data[15]]);

        fields.push(("packet_type", FieldValue::UInt16(pkt_type)));
        fields.push((
            "packet_type_name",
            FieldValue::Str(packet_type_name(pkt_type)),
        ));
        fields.push(("arphrd_type", FieldValue::UInt16(arphrd_type)));
        fields.push(("arphrd_name", FieldValue::Str(arphrd_name(arphrd_type))));
        fields.push(("addr_len", FieldValue::UInt16(addr_len)));

        // Extract the valid portion of the link-layer address
        let valid_addr_len = (addr_len as usize).min(8);
        if valid_addr_len > 0 {
            let addr_slice = &data[6..6 + valid_addr_len];
            fields.push(("addr", FieldValue::Bytes(addr_slice)));
        }

        fields.push(("protocol", FieldValue::UInt16(protocol)));

        // Calculate remaining payload
        let remaining = &data[LINUX_SLL_HEADER_LEN..];

        // Set child hints based on ARPHRD type
        let mut child_hints = SmallVec::new();

        match arphrd_type {
            arphrd::NETLINK => {
                // For netlink, protocol field is the netlink family
                child_hints.push(("sll_arphrd", arphrd::NETLINK as u64));
                child_hints.push(("netlink_family", protocol as u64));
                child_hints.push(("is_netlink", 1u64));
            }
            arphrd::ETHER | arphrd::LOOPBACK => {
                // For ethernet-like, protocol is the ethertype
                child_hints.push(("sll_arphrd", arphrd_type as u64));
                child_hints.push(("ethertype", protocol as u64));
            }
            _ => {
                child_hints.push(("sll_arphrd", arphrd_type as u64));
                child_hints.push(("sll_protocol", protocol as u64));
            }
        }

        ParseResult::success(fields, remaining, child_hints)
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            FieldDescriptor::new("linux_sll.packet_type", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("linux_sll.packet_type_name", DataKind::String).set_nullable(true),
            FieldDescriptor::new("linux_sll.arphrd_type", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("linux_sll.arphrd_name", DataKind::String).set_nullable(true),
            FieldDescriptor::new("linux_sll.addr_len", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("linux_sll.addr", DataKind::Binary).set_nullable(true),
            FieldDescriptor::new("linux_sll.protocol", DataKind::UInt16).set_nullable(true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        &["netlink", "ethernet", "ipv4", "ipv6"]
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &[] // Root protocol - no dependencies
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a Linux SLL header (big-endian).
    fn create_sll_header(
        pkt_type: u16,
        arphrd: u16,
        addr_len: u16,
        addr: [u8; 8],
        protocol: u16,
    ) -> Vec<u8> {
        let mut header = Vec::with_capacity(16);
        header.extend_from_slice(&pkt_type.to_be_bytes());
        header.extend_from_slice(&arphrd.to_be_bytes());
        header.extend_from_slice(&addr_len.to_be_bytes());
        header.extend_from_slice(&addr);
        header.extend_from_slice(&protocol.to_be_bytes());
        header
    }

    // ==========================================================================
    // Test 1: can_parse returns Some for root context with LINKTYPE_LINUX_SLL
    // ==========================================================================
    #[test]
    fn test_can_parse_linux_sll_at_root() {
        let parser = LinuxSllProtocol;
        let ctx = ParseContext::new(LINKTYPE_LINUX_SLL);

        assert!(parser.can_parse(&ctx).is_some());
        assert_eq!(parser.can_parse(&ctx), Some(100));
    }

    // ==========================================================================
    // Test 2: can_parse returns None for other link types
    // ==========================================================================
    #[test]
    fn test_cannot_parse_ethernet() {
        let parser = LinuxSllProtocol;
        let ctx = ParseContext::new(1); // Ethernet LINKTYPE

        assert!(parser.can_parse(&ctx).is_none());
    }

    // ==========================================================================
    // Test 3: can_parse returns None when not at root
    // ==========================================================================
    #[test]
    fn test_cannot_parse_when_not_root() {
        let parser = LinuxSllProtocol;
        let mut ctx = ParseContext::new(LINKTYPE_LINUX_SLL);
        ctx.parent_protocol = Some("something");

        assert!(parser.can_parse(&ctx).is_none());
    }

    // ==========================================================================
    // Test 4: Parse basic SLL header with ethernet
    // ==========================================================================
    #[test]
    fn test_parse_sll_ethernet() {
        let header = create_sll_header(
            packet_type::HOST,
            arphrd::ETHER,
            6,
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00],
            0x0800, // IPv4
        );
        let parser = LinuxSllProtocol;
        let ctx = ParseContext::new(LINKTYPE_LINUX_SLL);

        let result = parser.parse(&header, &ctx);

        assert!(result.is_ok());
        assert_eq!(result.get("packet_type"), Some(&FieldValue::UInt16(0)));
        assert_eq!(
            result.get("packet_type_name"),
            Some(&FieldValue::Str("HOST"))
        );
        assert_eq!(
            result.get("arphrd_type"),
            Some(&FieldValue::UInt16(arphrd::ETHER))
        );
        assert_eq!(result.get("arphrd_name"), Some(&FieldValue::Str("ETHER")));
        assert_eq!(result.get("protocol"), Some(&FieldValue::UInt16(0x0800)));
    }

    // ==========================================================================
    // Test 5: Parse SLL header with netlink
    // ==========================================================================
    #[test]
    fn test_parse_sll_netlink() {
        let header = create_sll_header(
            packet_type::OUTGOING,
            arphrd::NETLINK,
            0,
            [0; 8],
            0, // NETLINK_ROUTE
        );
        let parser = LinuxSllProtocol;
        let ctx = ParseContext::new(LINKTYPE_LINUX_SLL);

        let result = parser.parse(&header, &ctx);

        assert!(result.is_ok());
        assert_eq!(
            result.get("arphrd_type"),
            Some(&FieldValue::UInt16(arphrd::NETLINK))
        );
        assert_eq!(result.get("arphrd_name"), Some(&FieldValue::Str("NETLINK")));

        // Check child hints for netlink
        assert!(result
            .child_hints
            .iter()
            .any(|(k, v)| *k == "is_netlink" && *v == 1));
        assert!(result
            .child_hints
            .iter()
            .any(|(k, v)| *k == "netlink_family" && *v == 0));
    }

    // ==========================================================================
    // Test 6: Header too short
    // ==========================================================================
    #[test]
    fn test_parse_sll_header_too_short() {
        let short_data = vec![0u8; 10]; // Less than 16 bytes
        let parser = LinuxSllProtocol;
        let ctx = ParseContext::new(LINKTYPE_LINUX_SLL);

        let result = parser.parse(&short_data, &ctx);

        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }

    // ==========================================================================
    // Test 7: Packet type name resolution
    // ==========================================================================
    #[test]
    fn test_packet_type_names() {
        assert_eq!(packet_type_name(packet_type::HOST), "HOST");
        assert_eq!(packet_type_name(packet_type::BROADCAST), "BROADCAST");
        assert_eq!(packet_type_name(packet_type::MULTICAST), "MULTICAST");
        assert_eq!(packet_type_name(packet_type::OTHERHOST), "OTHERHOST");
        assert_eq!(packet_type_name(packet_type::OUTGOING), "OUTGOING");
        assert_eq!(packet_type_name(99), "UNKNOWN");
    }

    // ==========================================================================
    // Test 8: ARPHRD name resolution
    // ==========================================================================
    #[test]
    fn test_arphrd_names() {
        assert_eq!(arphrd_name(arphrd::ETHER), "ETHER");
        assert_eq!(arphrd_name(arphrd::NETLINK), "NETLINK");
        assert_eq!(arphrd_name(arphrd::LOOPBACK), "LOOPBACK");
        assert_eq!(arphrd_name(999), "UNKNOWN");
    }

    // ==========================================================================
    // Test 9: Schema fields are complete
    // ==========================================================================
    #[test]
    fn test_linux_sll_schema_fields() {
        let parser = LinuxSllProtocol;
        let fields = parser.schema_fields();

        let field_names: Vec<&str> = fields.iter().map(|f| f.name).collect();

        assert!(field_names.contains(&"linux_sll.packet_type"));
        assert!(field_names.contains(&"linux_sll.packet_type_name"));
        assert!(field_names.contains(&"linux_sll.arphrd_type"));
        assert!(field_names.contains(&"linux_sll.arphrd_name"));
        assert!(field_names.contains(&"linux_sll.addr_len"));
        assert!(field_names.contains(&"linux_sll.addr"));
        assert!(field_names.contains(&"linux_sll.protocol"));
    }

    // ==========================================================================
    // Test 10: Child protocols declaration
    // ==========================================================================
    #[test]
    fn test_linux_sll_child_protocols() {
        let parser = LinuxSllProtocol;
        let children = parser.child_protocols();

        assert!(children.contains(&"netlink"));
        assert!(children.contains(&"ethernet"));
    }

    // ==========================================================================
    // Test 11: No dependencies (root protocol)
    // ==========================================================================
    #[test]
    fn test_linux_sll_no_dependencies() {
        let parser = LinuxSllProtocol;
        let deps = parser.dependencies();

        assert!(deps.is_empty());
    }

    // ==========================================================================
    // Test 12: Remaining data after header
    // ==========================================================================
    #[test]
    fn test_remaining_data() {
        let mut data = create_sll_header(packet_type::HOST, arphrd::NETLINK, 0, [0; 8], 0);
        // Add some payload
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);

        let parser = LinuxSllProtocol;
        let ctx = ParseContext::new(LINKTYPE_LINUX_SLL);

        let result = parser.parse(&data, &ctx);

        assert!(result.is_ok());
        assert_eq!(result.remaining.len(), 4);
        assert_eq!(result.remaining, &[0x01, 0x02, 0x03, 0x04]);
    }
}
