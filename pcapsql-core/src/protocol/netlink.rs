//! Netlink protocol parser.
//!
//! Parses Linux Netlink messages from LINKTYPE_NETLINK (253) captures.
//! This is the base parser that handles the common netlink header and
//! sets hints for family-specific child parsers (rtnetlink, nfnetlink, etc.).

use smallvec::SmallVec;

use super::{FieldValue, ParseContext, ParseResult, Protocol};
use crate::schema::{DataKind, FieldDescriptor};

// Re-export constants from netlink-packet-core for use elsewhere
pub use netlink_packet_core::constants::{NLM_F_ACK, NLM_F_ECHO, NLM_F_MULTIPART, NLM_F_REQUEST};

// Message type constants from netlink-packet-core
pub use netlink_packet_core::{NLMSG_DONE, NLMSG_ERROR, NLMSG_NOOP, NLMSG_OVERRUN};

/// Netlink header length in bytes.
pub const NETLINK_HEADER_LEN: usize = 16;

/// PCAP link type for Netlink captures.
pub const LINKTYPE_NETLINK: u16 = 253;

/// Netlink protocol families.
pub mod family {
    pub const ROUTE: u8 = 0;
    pub const UNUSED: u8 = 1;
    pub const USERSOCK: u8 = 2;
    pub const FIREWALL: u8 = 3;
    pub const SOCK_DIAG: u8 = 4;
    pub const NFLOG: u8 = 5;
    pub const XFRM: u8 = 6;
    pub const SELINUX: u8 = 7;
    pub const ISCSI: u8 = 8;
    pub const AUDIT: u8 = 9;
    pub const FIB_LOOKUP: u8 = 10;
    pub const CONNECTOR: u8 = 11;
    pub const NETFILTER: u8 = 12;
    pub const IP6_FW: u8 = 13;
    pub const DNRTMSG: u8 = 14;
    pub const KOBJECT_UEVENT: u8 = 15;
    pub const GENERIC: u8 = 16;
    pub const SCSITRANSPORT: u8 = 18;
    pub const ECRYPTFS: u8 = 19;
    pub const RDMA: u8 = 20;
    pub const CRYPTO: u8 = 21;
}

/// Get the name of a netlink family.
fn family_name(family: u8) -> &'static str {
    match family {
        family::ROUTE => "ROUTE",
        family::USERSOCK => "USERSOCK",
        family::FIREWALL => "FIREWALL",
        family::SOCK_DIAG => "SOCK_DIAG",
        family::NFLOG => "NFLOG",
        family::XFRM => "XFRM",
        family::SELINUX => "SELINUX",
        family::ISCSI => "ISCSI",
        family::AUDIT => "AUDIT",
        family::FIB_LOOKUP => "FIB_LOOKUP",
        family::CONNECTOR => "CONNECTOR",
        family::NETFILTER => "NETFILTER",
        family::IP6_FW => "IP6_FW",
        family::DNRTMSG => "DNRTMSG",
        family::KOBJECT_UEVENT => "KOBJECT_UEVENT",
        family::GENERIC => "GENERIC",
        family::SCSITRANSPORT => "SCSITRANSPORT",
        family::ECRYPTFS => "ECRYPTFS",
        family::RDMA => "RDMA",
        family::CRYPTO => "CRYPTO",
        _ => "UNKNOWN",
    }
}

/// Get the name of a netlink message type.
fn msg_type_name(msg_type: u16) -> &'static str {
    match msg_type {
        NLMSG_NOOP => "NLMSG_NOOP",
        NLMSG_ERROR => "NLMSG_ERROR",
        NLMSG_DONE => "NLMSG_DONE",
        NLMSG_OVERRUN => "NLMSG_OVERRUN",
        _ => "PROTOCOL_SPECIFIC",
    }
}

/// Netlink protocol parser.
///
/// Parses the base 16-byte netlink header and sets hints for
/// family-specific child protocols.
#[derive(Debug, Clone, Copy)]
pub struct NetlinkProtocol;

impl Protocol for NetlinkProtocol {
    fn name(&self) -> &'static str {
        "netlink"
    }

    fn display_name(&self) -> &'static str {
        "Netlink"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        // Parse at root level with LINKTYPE_NETLINK
        if context.is_root() && context.link_type == LINKTYPE_NETLINK {
            return Some(100);
        }

        // Also parse when parent is linux_sll with ARPHRD_NETLINK
        if context.parent_protocol == Some("linux_sll") && context.hint("is_netlink") == Some(1) {
            return Some(100);
        }

        None
    }

    fn parse<'a>(&self, data: &'a [u8], context: &ParseContext) -> ParseResult<'a> {
        // Netlink header is 16 bytes minimum
        if data.len() < NETLINK_HEADER_LEN {
            return ParseResult::error(
                format!("Netlink message too short: {} bytes", data.len()),
                data,
            );
        }

        let mut fields = SmallVec::new();

        // Parse netlink header (little-endian!)
        let msg_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let msg_type = u16::from_le_bytes([data[4], data[5]]);
        let msg_flags = u16::from_le_bytes([data[6], data[7]]);
        let msg_seq = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let msg_pid = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);

        fields.push(("msg_len", FieldValue::UInt32(msg_len)));
        fields.push(("msg_type", FieldValue::UInt16(msg_type)));
        fields.push(("msg_flags", FieldValue::UInt16(msg_flags)));
        fields.push(("msg_seq", FieldValue::UInt32(msg_seq)));
        fields.push(("msg_pid", FieldValue::UInt32(msg_pid)));

        // Message type name
        fields.push(("msg_type_name", FieldValue::Str(msg_type_name(msg_type))));

        // Flag extraction using crate constants
        let is_request = (msg_flags & NLM_F_REQUEST) != 0;
        let is_multipart = (msg_flags & NLM_F_MULTIPART) != 0;
        let is_ack = (msg_flags & NLM_F_ACK) != 0;
        let is_echo = (msg_flags & NLM_F_ECHO) != 0;

        fields.push(("is_request", FieldValue::Bool(is_request)));
        fields.push(("is_multipart", FieldValue::Bool(is_multipart)));
        fields.push(("is_ack", FieldValue::Bool(is_ack)));
        fields.push(("is_echo", FieldValue::Bool(is_echo)));

        // Get the netlink family from context hint (set by PCAP reader or cooked header)
        // Default to ROUTE if not specified
        let nl_family = context
            .hint("netlink_family")
            .map(|f| f as u8)
            .unwrap_or(family::ROUTE);

        fields.push(("family", FieldValue::UInt8(nl_family)));
        fields.push(("family_name", FieldValue::Str(family_name(nl_family))));

        // Calculate remaining payload
        let payload_start = NETLINK_HEADER_LEN;
        let payload_len = (msg_len as usize).saturating_sub(NETLINK_HEADER_LEN);
        let remaining = if payload_start + payload_len <= data.len() {
            &data[payload_start..payload_start + payload_len]
        } else {
            &data[payload_start..]
        };

        // Set hints for child protocols
        let mut child_hints = SmallVec::new();
        child_hints.push(("netlink_family", nl_family as u64));
        child_hints.push(("netlink_msg_type", msg_type as u64));

        ParseResult::success(fields, remaining, child_hints)
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            FieldDescriptor::new("netlink.msg_len", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("netlink.msg_type", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("netlink.msg_flags", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("netlink.msg_seq", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("netlink.msg_pid", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("netlink.msg_type_name", DataKind::String).set_nullable(true),
            FieldDescriptor::new("netlink.is_request", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("netlink.is_multipart", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("netlink.is_ack", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("netlink.is_echo", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("netlink.family", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("netlink.family_name", DataKind::String).set_nullable(true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        &["rtnetlink"]
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &[] // Root protocol - no dependencies
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a netlink header (little-endian).
    fn create_netlink_header(
        msg_len: u32,
        msg_type: u16,
        flags: u16,
        seq: u32,
        pid: u32,
    ) -> Vec<u8> {
        let mut header = Vec::with_capacity(16);
        header.extend_from_slice(&msg_len.to_le_bytes());
        header.extend_from_slice(&msg_type.to_le_bytes());
        header.extend_from_slice(&flags.to_le_bytes());
        header.extend_from_slice(&seq.to_le_bytes());
        header.extend_from_slice(&pid.to_le_bytes());
        header
    }

    // ==========================================================================
    // Test 1: can_parse returns Some for root context with LINKTYPE_NETLINK
    // ==========================================================================
    #[test]
    fn test_can_parse_netlink_at_root() {
        let parser = NetlinkProtocol;
        let ctx = ParseContext::new(LINKTYPE_NETLINK);

        assert!(parser.can_parse(&ctx).is_some());
        assert_eq!(parser.can_parse(&ctx), Some(100));
    }

    // ==========================================================================
    // Test 2: can_parse returns None for non-netlink link types
    // ==========================================================================
    #[test]
    fn test_cannot_parse_ethernet() {
        let parser = NetlinkProtocol;
        let ctx = ParseContext::new(1); // Ethernet LINKTYPE

        assert!(parser.can_parse(&ctx).is_none());
    }

    // ==========================================================================
    // Test 3: can_parse returns None when not at root
    // ==========================================================================
    #[test]
    fn test_cannot_parse_when_not_root() {
        let parser = NetlinkProtocol;
        let mut ctx = ParseContext::new(LINKTYPE_NETLINK);
        ctx.parent_protocol = Some("something");

        assert!(parser.can_parse(&ctx).is_none());
    }

    // ==========================================================================
    // Test 4: Parse basic netlink header
    // ==========================================================================
    #[test]
    fn test_parse_netlink_header_basic() {
        let header = create_netlink_header(32, 16, NLM_F_REQUEST, 1, 1234);
        let parser = NetlinkProtocol;
        let ctx = ParseContext::new(LINKTYPE_NETLINK);

        let result = parser.parse(&header, &ctx);

        assert!(result.is_ok());
        assert_eq!(result.get("msg_len"), Some(&FieldValue::UInt32(32)));
        assert_eq!(result.get("msg_type"), Some(&FieldValue::UInt16(16)));
        assert_eq!(
            result.get("msg_flags"),
            Some(&FieldValue::UInt16(NLM_F_REQUEST))
        );
        assert_eq!(result.get("msg_seq"), Some(&FieldValue::UInt32(1)));
        assert_eq!(result.get("msg_pid"), Some(&FieldValue::UInt32(1234)));
    }

    // ==========================================================================
    // Test 5: Header too short
    // ==========================================================================
    #[test]
    fn test_parse_netlink_header_too_short() {
        let short_data = vec![0u8; 10]; // Less than 16 bytes
        let parser = NetlinkProtocol;
        let ctx = ParseContext::new(LINKTYPE_NETLINK);

        let result = parser.parse(&short_data, &ctx);

        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }

    // ==========================================================================
    // Test 6: Reserved message types (NLMSG_DONE)
    // ==========================================================================
    #[test]
    fn test_parse_nlmsg_done() {
        let header = create_netlink_header(16, NLMSG_DONE, 0, 1, 0);
        let parser = NetlinkProtocol;
        let ctx = ParseContext::new(LINKTYPE_NETLINK);

        let result = parser.parse(&header, &ctx);

        assert!(result.is_ok());
        assert_eq!(
            result.get("msg_type_name"),
            Some(&FieldValue::Str("NLMSG_DONE"))
        );
    }

    // ==========================================================================
    // Test 7: Request flag detection
    // ==========================================================================
    #[test]
    fn test_request_flag() {
        let header = create_netlink_header(16, 16, NLM_F_REQUEST, 1, 0);
        let parser = NetlinkProtocol;
        let ctx = ParseContext::new(LINKTYPE_NETLINK);

        let result = parser.parse(&header, &ctx);

        assert!(result.is_ok());
        assert_eq!(result.get("is_request"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("is_multipart"), Some(&FieldValue::Bool(false)));
    }

    // ==========================================================================
    // Test 8: Multipart message flag detection
    // ==========================================================================
    #[test]
    fn test_multipart_message_flag() {
        let header = create_netlink_header(32, 16, NLM_F_MULTIPART, 1, 0);
        let parser = NetlinkProtocol;
        let ctx = ParseContext::new(LINKTYPE_NETLINK);

        let result = parser.parse(&header, &ctx);

        assert!(result.is_ok());
        assert_eq!(result.get("is_multipart"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("is_request"), Some(&FieldValue::Bool(false)));
    }

    // ==========================================================================
    // Test 9: Combined flags
    // ==========================================================================
    #[test]
    fn test_combined_flags() {
        let flags = NLM_F_REQUEST | NLM_F_MULTIPART | NLM_F_ACK;
        let header = create_netlink_header(16, 16, flags, 1, 0);
        let parser = NetlinkProtocol;
        let ctx = ParseContext::new(LINKTYPE_NETLINK);

        let result = parser.parse(&header, &ctx);

        assert!(result.is_ok());
        assert_eq!(result.get("is_request"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("is_multipart"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("is_ack"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("is_echo"), Some(&FieldValue::Bool(false)));
    }

    // ==========================================================================
    // Test 10: Child hints for rtnetlink parser
    // ==========================================================================
    #[test]
    fn test_child_hints_for_rtnetlink() {
        let header = create_netlink_header(32, 16, 0, 1, 0);
        let parser = NetlinkProtocol;
        let mut ctx = ParseContext::new(LINKTYPE_NETLINK);
        ctx.insert_hint("netlink_family", family::ROUTE as u64);

        let result = parser.parse(&header, &ctx);

        assert!(result.is_ok());
        // Check child hints are set
        assert!(result
            .child_hints
            .iter()
            .any(|(k, v)| *k == "netlink_family" && *v == family::ROUTE as u64));
        assert!(result
            .child_hints
            .iter()
            .any(|(k, v)| *k == "netlink_msg_type" && *v == 16));
    }

    // ==========================================================================
    // Test 11: Family name resolution
    // ==========================================================================
    #[test]
    fn test_family_name_route() {
        let header = create_netlink_header(16, 16, 0, 1, 0);
        let parser = NetlinkProtocol;
        let mut ctx = ParseContext::new(LINKTYPE_NETLINK);
        ctx.insert_hint("netlink_family", family::ROUTE as u64);

        let result = parser.parse(&header, &ctx);

        assert!(result.is_ok());
        assert_eq!(
            result.get("family"),
            Some(&FieldValue::UInt8(family::ROUTE))
        );
        assert_eq!(result.get("family_name"), Some(&FieldValue::Str("ROUTE")));
    }

    // ==========================================================================
    // Test 12: Schema fields are complete
    // ==========================================================================
    #[test]
    fn test_netlink_schema_fields() {
        let parser = NetlinkProtocol;
        let fields = parser.schema_fields();

        let field_names: Vec<&str> = fields.iter().map(|f| f.name).collect();

        assert!(field_names.contains(&"netlink.msg_len"));
        assert!(field_names.contains(&"netlink.msg_type"));
        assert!(field_names.contains(&"netlink.msg_flags"));
        assert!(field_names.contains(&"netlink.msg_seq"));
        assert!(field_names.contains(&"netlink.msg_pid"));
        assert!(field_names.contains(&"netlink.msg_type_name"));
        assert!(field_names.contains(&"netlink.is_request"));
        assert!(field_names.contains(&"netlink.is_multipart"));
        assert!(field_names.contains(&"netlink.family"));
        assert!(field_names.contains(&"netlink.family_name"));
    }

    // ==========================================================================
    // Test 13: Child protocols declaration
    // ==========================================================================
    #[test]
    fn test_netlink_child_protocols() {
        let parser = NetlinkProtocol;
        let children = parser.child_protocols();

        assert!(children.contains(&"rtnetlink"));
    }

    // ==========================================================================
    // Test 14: No dependencies (root protocol)
    // ==========================================================================
    #[test]
    fn test_netlink_no_dependencies() {
        let parser = NetlinkProtocol;
        let deps = parser.dependencies();

        assert!(deps.is_empty());
    }

    // ==========================================================================
    // Test 15: parse_packet integration - netlink is selected for LINKTYPE_NETLINK
    // ==========================================================================
    #[test]
    fn test_parse_packet_selects_netlink() {
        use crate::protocol::{default_registry, parse_packet};

        let registry = default_registry();
        let header = create_netlink_header(32, 16, NLM_F_REQUEST, 1, 1234);

        // Parse with link_type 253 (LINKTYPE_NETLINK)
        let results = parse_packet(&registry, LINKTYPE_NETLINK, &header);

        // Should find netlink protocol
        assert!(
            !results.is_empty(),
            "parse_packet should return at least one protocol"
        );

        let protocol_names: Vec<&str> = results.iter().map(|(name, _)| *name).collect();
        assert!(
            protocol_names.contains(&"netlink"),
            "parse_packet should select 'netlink' for LINKTYPE_NETLINK, got: {:?}",
            protocol_names
        );

        // Verify netlink result has expected fields
        let (_, netlink_result) = results.iter().find(|(name, _)| *name == "netlink").unwrap();
        assert_eq!(
            netlink_result.get("msg_type"),
            Some(&FieldValue::UInt16(16))
        );
        assert_eq!(
            netlink_result.get("is_request"),
            Some(&FieldValue::Bool(true))
        );
    }
}
