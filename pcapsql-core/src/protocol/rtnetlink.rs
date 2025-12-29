//! RTNetlink protocol parser.
//!
//! Parses NETLINK_ROUTE (family 0) messages from Linux Netlink captures.
//! Handles link, address, and route messages using netlink-packet-route.

use compact_str::CompactString;
use smallvec::SmallVec;

use super::netlink::family as netlink_family;
use super::{FieldValue, ParseContext, ParseResult, Protocol};
use crate::schema::{DataKind, FieldDescriptor};

/// RTNetlink message type constants.
pub mod msg_type {
    pub const RTM_NEWLINK: u16 = 16;
    pub const RTM_DELLINK: u16 = 17;
    pub const RTM_GETLINK: u16 = 18;
    pub const RTM_SETLINK: u16 = 19;
    pub const RTM_NEWADDR: u16 = 20;
    pub const RTM_DELADDR: u16 = 21;
    pub const RTM_GETADDR: u16 = 22;
    pub const RTM_NEWROUTE: u16 = 24;
    pub const RTM_DELROUTE: u16 = 25;
    pub const RTM_GETROUTE: u16 = 26;
    pub const RTM_NEWNEIGH: u16 = 28;
    pub const RTM_DELNEIGH: u16 = 29;
    pub const RTM_GETNEIGH: u16 = 30;
}

/// Get the name of an RTNetlink message type.
fn msg_type_name(msg_type: u16) -> &'static str {
    match msg_type {
        msg_type::RTM_NEWLINK => "RTM_NEWLINK",
        msg_type::RTM_DELLINK => "RTM_DELLINK",
        msg_type::RTM_GETLINK => "RTM_GETLINK",
        msg_type::RTM_SETLINK => "RTM_SETLINK",
        msg_type::RTM_NEWADDR => "RTM_NEWADDR",
        msg_type::RTM_DELADDR => "RTM_DELADDR",
        msg_type::RTM_GETADDR => "RTM_GETADDR",
        msg_type::RTM_NEWROUTE => "RTM_NEWROUTE",
        msg_type::RTM_DELROUTE => "RTM_DELROUTE",
        msg_type::RTM_GETROUTE => "RTM_GETROUTE",
        msg_type::RTM_NEWNEIGH => "RTM_NEWNEIGH",
        msg_type::RTM_DELNEIGH => "RTM_DELNEIGH",
        msg_type::RTM_GETNEIGH => "RTM_GETNEIGH",
        _ => "UNKNOWN",
    }
}

/// RTNetlink protocol parser.
///
/// Parses routing netlink messages including link, address, and route operations.
#[derive(Debug, Clone, Copy)]
pub struct RtnetlinkProtocol;

impl Protocol for RtnetlinkProtocol {
    fn name(&self) -> &'static str {
        "rtnetlink"
    }

    fn display_name(&self) -> &'static str {
        "RTNetlink"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        // Only parse when parent is netlink and family is ROUTE (0)
        if context.parent_protocol == Some("netlink") {
            if let Some(family) = context.hint("netlink_family") {
                if family == netlink_family::ROUTE as u64 {
                    return Some(100);
                }
            }
        }
        None
    }

    fn parse<'a>(&self, data: &'a [u8], context: &ParseContext) -> ParseResult<'a> {
        let mut fields = SmallVec::new();

        // Get the message type from parent netlink hints
        let nl_msg_type = context
            .hint("netlink_msg_type")
            .map(|t| t as u16)
            .unwrap_or(0);

        fields.push(("msg_type", FieldValue::UInt16(nl_msg_type)));
        fields.push(("msg_type_name", FieldValue::Str(msg_type_name(nl_msg_type))));

        // Parse based on message type range
        match nl_msg_type {
            // Link messages (RTM_NEWLINK, RTM_DELLINK, RTM_GETLINK, RTM_SETLINK)
            16..=19 => {
                parse_link_header(data, &mut fields);
            }
            // Address messages (RTM_NEWADDR, RTM_DELADDR, RTM_GETADDR)
            20..=22 => {
                parse_addr_header(data, &mut fields);
            }
            // Route messages (RTM_NEWROUTE, RTM_DELROUTE, RTM_GETROUTE)
            24..=26 => {
                parse_route_header(data, &mut fields);
            }
            _ => {
                // Unknown message type - just record the type
            }
        }

        // RTNetlink is a terminal protocol (no child protocols)
        ParseResult::success(fields, &[], SmallVec::new())
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            // Common fields
            FieldDescriptor::new("rtnetlink.msg_type", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("rtnetlink.msg_type_name", DataKind::String).set_nullable(true),
            // Link message fields
            FieldDescriptor::new("rtnetlink.link_index", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("rtnetlink.link_type", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("rtnetlink.link_flags", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("rtnetlink.if_name", DataKind::String).set_nullable(true),
            FieldDescriptor::new("rtnetlink.mtu", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::mac_field("rtnetlink.hw_addr").set_nullable(true),
            // Address message fields
            FieldDescriptor::new("rtnetlink.addr_family", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("rtnetlink.addr_family_name", DataKind::String).set_nullable(true),
            FieldDescriptor::new("rtnetlink.prefix_len", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("rtnetlink.addr_index", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("rtnetlink.address", DataKind::String).set_nullable(true),
            FieldDescriptor::new("rtnetlink.local_addr", DataKind::String).set_nullable(true),
            // Route message fields
            FieldDescriptor::new("rtnetlink.route_family", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("rtnetlink.dst_prefix_len", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("rtnetlink.src_prefix_len", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("rtnetlink.route_table", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("rtnetlink.route_protocol", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("rtnetlink.route_scope", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("rtnetlink.route_type", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("rtnetlink.destination", DataKind::String).set_nullable(true),
            FieldDescriptor::new("rtnetlink.gateway", DataKind::String).set_nullable(true),
            FieldDescriptor::new("rtnetlink.oif_index", DataKind::UInt32).set_nullable(true),
        ]
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &["netlink"]
    }
}

/// Link message header offsets (struct ifinfomsg).
#[allow(dead_code)]
mod link_header {
    pub const FAMILY_OFFSET: usize = 0;
    pub const TYPE_OFFSET: usize = 2;
    pub const INDEX_OFFSET: usize = 4;
    pub const FLAGS_OFFSET: usize = 8;
    pub const CHANGE_OFFSET: usize = 12;
    pub const MIN_LEN: usize = 16;
}

/// Address message header offsets (struct ifaddrmsg).
#[allow(dead_code)]
mod addr_header {
    pub const FAMILY_OFFSET: usize = 0;
    pub const PREFIXLEN_OFFSET: usize = 1;
    pub const FLAGS_OFFSET: usize = 2;
    pub const SCOPE_OFFSET: usize = 3;
    pub const INDEX_OFFSET: usize = 4;
    pub const MIN_LEN: usize = 8;
}

/// Route message header offsets (struct rtmsg).
#[allow(dead_code)]
mod route_header {
    pub const FAMILY_OFFSET: usize = 0;
    pub const DST_LEN_OFFSET: usize = 1;
    pub const SRC_LEN_OFFSET: usize = 2;
    pub const TOS_OFFSET: usize = 3;
    pub const TABLE_OFFSET: usize = 4;
    pub const PROTOCOL_OFFSET: usize = 5;
    pub const SCOPE_OFFSET: usize = 6;
    pub const TYPE_OFFSET: usize = 7;
    pub const MIN_LEN: usize = 12;
}

/// Parse link message header fields.
fn parse_link_header(data: &[u8], fields: &mut SmallVec<[(&'static str, FieldValue); 16]>) {
    if data.len() < link_header::MIN_LEN {
        return;
    }

    let link_type = u16::from_le_bytes([
        data[link_header::TYPE_OFFSET],
        data[link_header::TYPE_OFFSET + 1],
    ]);
    let index = u32::from_le_bytes([
        data[link_header::INDEX_OFFSET],
        data[link_header::INDEX_OFFSET + 1],
        data[link_header::INDEX_OFFSET + 2],
        data[link_header::INDEX_OFFSET + 3],
    ]);
    let flags = u32::from_le_bytes([
        data[link_header::FLAGS_OFFSET],
        data[link_header::FLAGS_OFFSET + 1],
        data[link_header::FLAGS_OFFSET + 2],
        data[link_header::FLAGS_OFFSET + 3],
    ]);

    fields.push(("link_index", FieldValue::UInt32(index)));
    fields.push(("link_type", FieldValue::UInt16(link_type)));
    fields.push(("link_flags", FieldValue::UInt32(flags)));

    // Parse attributes (TLV format after header)
    parse_link_attributes(&data[link_header::MIN_LEN..], fields);
}

/// Parse link attributes in TLV format.
fn parse_link_attributes(mut data: &[u8], fields: &mut SmallVec<[(&'static str, FieldValue); 16]>) {
    // Netlink TLV: 2 bytes len, 2 bytes type, then value (padded to 4 bytes)
    while data.len() >= 4 {
        let attr_len = u16::from_le_bytes([data[0], data[1]]) as usize;
        let attr_type = u16::from_le_bytes([data[2], data[3]]);

        if attr_len < 4 || attr_len > data.len() {
            break;
        }

        let value = &data[4..attr_len];

        match attr_type {
            // IFLA_IFNAME = 3
            3 => {
                if let Ok(name) = std::str::from_utf8(value.strip_suffix(&[0]).unwrap_or(value)) {
                    fields.push(("if_name", FieldValue::OwnedString(CompactString::new(name))));
                }
            }
            // IFLA_MTU = 4
            4 if value.len() >= 4 => {
                let mtu = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                fields.push(("mtu", FieldValue::UInt32(mtu)));
            }
            // IFLA_ADDRESS = 1 (hardware address)
            1 if value.len() == 6 => {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(value);
                fields.push(("hw_addr", FieldValue::MacAddr(mac)));
            }
            _ => {}
        }

        // Move to next attribute (4-byte aligned)
        let padded_len = (attr_len + 3) & !3;
        if padded_len > data.len() {
            break;
        }
        data = &data[padded_len..];
    }
}

/// Parse address message header fields.
fn parse_addr_header(data: &[u8], fields: &mut SmallVec<[(&'static str, FieldValue); 16]>) {
    if data.len() < addr_header::MIN_LEN {
        return;
    }

    let family = data[addr_header::FAMILY_OFFSET];
    let prefix_len = data[addr_header::PREFIXLEN_OFFSET];
    let index = u32::from_le_bytes([
        data[addr_header::INDEX_OFFSET],
        data[addr_header::INDEX_OFFSET + 1],
        data[addr_header::INDEX_OFFSET + 2],
        data[addr_header::INDEX_OFFSET + 3],
    ]);

    fields.push(("addr_family", FieldValue::UInt8(family)));
    fields.push((
        "addr_family_name",
        FieldValue::Str(match family {
            2 => "IPv4",  // AF_INET
            10 => "IPv6", // AF_INET6
            _ => "Unknown",
        }),
    ));
    fields.push(("prefix_len", FieldValue::UInt8(prefix_len)));
    fields.push(("addr_index", FieldValue::UInt32(index)));

    // Parse attributes
    parse_addr_attributes(&data[addr_header::MIN_LEN..], family, fields);
}

/// Parse address attributes in TLV format.
fn parse_addr_attributes(
    mut data: &[u8],
    family: u8,
    fields: &mut SmallVec<[(&'static str, FieldValue); 16]>,
) {
    while data.len() >= 4 {
        let attr_len = u16::from_le_bytes([data[0], data[1]]) as usize;
        let attr_type = u16::from_le_bytes([data[2], data[3]]);

        if attr_len < 4 || attr_len > data.len() {
            break;
        }

        let value = &data[4..attr_len];

        match attr_type {
            // IFA_ADDRESS = 1
            1 => {
                if let Some(addr_str) = format_ip_address(value, family) {
                    fields.push((
                        "address",
                        FieldValue::OwnedString(CompactString::new(&addr_str)),
                    ));
                }
            }
            // IFA_LOCAL = 2
            2 => {
                if let Some(addr_str) = format_ip_address(value, family) {
                    fields.push((
                        "local_addr",
                        FieldValue::OwnedString(CompactString::new(&addr_str)),
                    ));
                }
            }
            _ => {}
        }

        let padded_len = (attr_len + 3) & !3;
        if padded_len > data.len() {
            break;
        }
        data = &data[padded_len..];
    }
}

/// Format an IP address from bytes.
fn format_ip_address(value: &[u8], family: u8) -> Option<String> {
    match family {
        2 if value.len() == 4 => {
            // AF_INET (IPv4)
            Some(format!(
                "{}.{}.{}.{}",
                value[0], value[1], value[2], value[3]
            ))
        }
        10 if value.len() == 16 => {
            // AF_INET6 (IPv6)
            use std::net::Ipv6Addr;
            let addr = Ipv6Addr::new(
                u16::from_be_bytes([value[0], value[1]]),
                u16::from_be_bytes([value[2], value[3]]),
                u16::from_be_bytes([value[4], value[5]]),
                u16::from_be_bytes([value[6], value[7]]),
                u16::from_be_bytes([value[8], value[9]]),
                u16::from_be_bytes([value[10], value[11]]),
                u16::from_be_bytes([value[12], value[13]]),
                u16::from_be_bytes([value[14], value[15]]),
            );
            Some(addr.to_string())
        }
        _ => None,
    }
}

/// Parse route message header fields.
fn parse_route_header(data: &[u8], fields: &mut SmallVec<[(&'static str, FieldValue); 16]>) {
    if data.len() < route_header::MIN_LEN {
        return;
    }

    let family = data[route_header::FAMILY_OFFSET];
    let dst_len = data[route_header::DST_LEN_OFFSET];
    let src_len = data[route_header::SRC_LEN_OFFSET];
    let table = data[route_header::TABLE_OFFSET];
    let protocol = data[route_header::PROTOCOL_OFFSET];
    let scope = data[route_header::SCOPE_OFFSET];
    let route_type = data[route_header::TYPE_OFFSET];

    fields.push(("route_family", FieldValue::UInt8(family)));
    fields.push(("dst_prefix_len", FieldValue::UInt8(dst_len)));
    fields.push(("src_prefix_len", FieldValue::UInt8(src_len)));
    fields.push(("route_table", FieldValue::UInt8(table)));
    fields.push(("route_protocol", FieldValue::UInt8(protocol)));
    fields.push(("route_scope", FieldValue::UInt8(scope)));
    fields.push(("route_type", FieldValue::UInt8(route_type)));

    // Parse attributes
    parse_route_attributes(&data[route_header::MIN_LEN..], family, fields);
}

/// Parse route attributes in TLV format.
fn parse_route_attributes(
    mut data: &[u8],
    family: u8,
    fields: &mut SmallVec<[(&'static str, FieldValue); 16]>,
) {
    while data.len() >= 4 {
        let attr_len = u16::from_le_bytes([data[0], data[1]]) as usize;
        let attr_type = u16::from_le_bytes([data[2], data[3]]);

        if attr_len < 4 || attr_len > data.len() {
            break;
        }

        let value = &data[4..attr_len];

        match attr_type {
            // RTA_DST = 1
            1 => {
                if let Some(addr_str) = format_ip_address(value, family) {
                    fields.push((
                        "destination",
                        FieldValue::OwnedString(CompactString::new(&addr_str)),
                    ));
                }
            }
            // RTA_GATEWAY = 5
            5 => {
                if let Some(addr_str) = format_ip_address(value, family) {
                    fields.push((
                        "gateway",
                        FieldValue::OwnedString(CompactString::new(&addr_str)),
                    ));
                }
            }
            // RTA_OIF = 4
            4 if value.len() >= 4 => {
                let oif = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                fields.push(("oif_index", FieldValue::UInt32(oif)));
            }
            _ => {}
        }

        let padded_len = (attr_len + 3) & !3;
        if padded_len > data.len() {
            break;
        }
        data = &data[padded_len..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::netlink::LINKTYPE_NETLINK;

    /// Helper to create rtnetlink context.
    fn make_rtnetlink_context(msg_type: u16) -> ParseContext {
        let mut ctx = ParseContext::new(LINKTYPE_NETLINK);
        ctx.parent_protocol = Some("netlink");
        ctx.insert_hint("netlink_family", netlink_family::ROUTE as u64);
        ctx.insert_hint("netlink_msg_type", msg_type as u64);
        ctx
    }

    // ==========================================================================
    // Test 1: can_parse with netlink_family=0 hint
    // ==========================================================================
    #[test]
    fn test_can_parse_rtnetlink() {
        let parser = RtnetlinkProtocol;
        let ctx = make_rtnetlink_context(msg_type::RTM_NEWLINK);

        assert!(parser.can_parse(&ctx).is_some());
        assert_eq!(parser.can_parse(&ctx), Some(100));
    }

    // ==========================================================================
    // Test 2: cannot parse without proper hints
    // ==========================================================================
    #[test]
    fn test_cannot_parse_without_family_hint() {
        let parser = RtnetlinkProtocol;
        let ctx = ParseContext::new(LINKTYPE_NETLINK);

        assert!(parser.can_parse(&ctx).is_none());
    }

    // ==========================================================================
    // Test 3: cannot parse with wrong family
    // ==========================================================================
    #[test]
    fn test_cannot_parse_wrong_family() {
        let parser = RtnetlinkProtocol;
        let mut ctx = ParseContext::new(LINKTYPE_NETLINK);
        ctx.parent_protocol = Some("netlink");
        ctx.insert_hint("netlink_family", netlink_family::NETFILTER as u64);

        assert!(parser.can_parse(&ctx).is_none());
    }

    // ==========================================================================
    // Test 4: Parse RTM_NEWLINK message type extraction
    // ==========================================================================
    #[test]
    fn test_parse_rtm_newlink_type() {
        let parser = RtnetlinkProtocol;
        let ctx = make_rtnetlink_context(msg_type::RTM_NEWLINK);

        // Empty data - just tests message type extraction from hints
        let result = parser.parse(&[], &ctx);

        assert!(result.is_ok());
        assert_eq!(
            result.get("msg_type"),
            Some(&FieldValue::UInt16(msg_type::RTM_NEWLINK))
        );
        assert_eq!(
            result.get("msg_type_name"),
            Some(&FieldValue::Str("RTM_NEWLINK"))
        );
    }

    // ==========================================================================
    // Test 5: Parse RTM_NEWADDR message type extraction
    // ==========================================================================
    #[test]
    fn test_parse_rtm_newaddr_type() {
        let parser = RtnetlinkProtocol;
        let ctx = make_rtnetlink_context(msg_type::RTM_NEWADDR);

        let result = parser.parse(&[], &ctx);

        assert!(result.is_ok());
        assert_eq!(
            result.get("msg_type_name"),
            Some(&FieldValue::Str("RTM_NEWADDR"))
        );
    }

    // ==========================================================================
    // Test 6: Parse RTM_NEWROUTE message type extraction
    // ==========================================================================
    #[test]
    fn test_parse_rtm_newroute_type() {
        let parser = RtnetlinkProtocol;
        let ctx = make_rtnetlink_context(msg_type::RTM_NEWROUTE);

        let result = parser.parse(&[], &ctx);

        assert!(result.is_ok());
        assert_eq!(
            result.get("msg_type_name"),
            Some(&FieldValue::Str("RTM_NEWROUTE"))
        );
    }

    // ==========================================================================
    // Test 7: Schema fields complete
    // ==========================================================================
    #[test]
    fn test_rtnetlink_schema_fields() {
        let parser = RtnetlinkProtocol;
        let fields = parser.schema_fields();

        let field_names: Vec<&str> = fields.iter().map(|f| f.name).collect();

        // Common fields
        assert!(field_names.contains(&"rtnetlink.msg_type"));
        assert!(field_names.contains(&"rtnetlink.msg_type_name"));

        // Link fields
        assert!(field_names.contains(&"rtnetlink.link_index"));
        assert!(field_names.contains(&"rtnetlink.link_type"));
        assert!(field_names.contains(&"rtnetlink.link_flags"));
        assert!(field_names.contains(&"rtnetlink.if_name"));
        assert!(field_names.contains(&"rtnetlink.mtu"));
        assert!(field_names.contains(&"rtnetlink.hw_addr"));

        // Address fields
        assert!(field_names.contains(&"rtnetlink.addr_family"));
        assert!(field_names.contains(&"rtnetlink.prefix_len"));
        assert!(field_names.contains(&"rtnetlink.address"));

        // Route fields
        assert!(field_names.contains(&"rtnetlink.route_family"));
        assert!(field_names.contains(&"rtnetlink.dst_prefix_len"));
        assert!(field_names.contains(&"rtnetlink.destination"));
        assert!(field_names.contains(&"rtnetlink.gateway"));
        assert!(field_names.contains(&"rtnetlink.oif_index"));
    }

    // ==========================================================================
    // Test 8: Dependencies declaration
    // ==========================================================================
    #[test]
    fn test_rtnetlink_dependencies() {
        let parser = RtnetlinkProtocol;
        let deps = parser.dependencies();

        assert!(deps.contains(&"netlink"));
    }

    // ==========================================================================
    // Test 9: Unknown message type handling
    // ==========================================================================
    #[test]
    fn test_unknown_message_type() {
        let parser = RtnetlinkProtocol;
        let ctx = make_rtnetlink_context(999);

        let result = parser.parse(&[], &ctx);

        assert!(result.is_ok());
        assert_eq!(
            result.get("msg_type_name"),
            Some(&FieldValue::Str("UNKNOWN"))
        );
    }

    // ==========================================================================
    // Test 10: RTNetlink is terminal protocol (no remaining data)
    // ==========================================================================
    #[test]
    fn test_rtnetlink_is_terminal() {
        let parser = RtnetlinkProtocol;
        let ctx = make_rtnetlink_context(msg_type::RTM_NEWLINK);

        let result = parser.parse(&[0u8; 32], &ctx);

        assert!(result.is_ok());
        assert!(result.remaining.is_empty());
        assert!(result.child_hints.is_empty());
    }
}
