//! ICMPv6 protocol parser with NDP and MLD support.

use std::net::Ipv6Addr;

use compact_str::CompactString;
use smallvec::SmallVec;

use super::{FieldValue, ParseContext, ParseResult, Protocol};
use crate::schema::{DataKind, FieldDescriptor};

/// IP protocol number for ICMPv6.
pub const IP_PROTO_ICMPV6: u8 = 58;

/// ICMPv6 type constants.
pub mod icmpv6_type {
    // Error messages
    pub const DESTINATION_UNREACHABLE: u8 = 1;
    pub const PACKET_TOO_BIG: u8 = 2;
    pub const TIME_EXCEEDED: u8 = 3;
    pub const PARAMETER_PROBLEM: u8 = 4;

    // Informational messages
    pub const ECHO_REQUEST: u8 = 128;
    pub const ECHO_REPLY: u8 = 129;

    // MLD messages
    pub const MLD_QUERY: u8 = 130;
    pub const MLDV1_REPORT: u8 = 131;
    pub const MLDV1_DONE: u8 = 132;
    pub const MLDV2_REPORT: u8 = 143;

    // NDP messages
    pub const ROUTER_SOLICITATION: u8 = 133;
    pub const ROUTER_ADVERTISEMENT: u8 = 134;
    pub const NEIGHBOR_SOLICITATION: u8 = 135;
    pub const NEIGHBOR_ADVERTISEMENT: u8 = 136;
    pub const REDIRECT: u8 = 137;
}

/// NDP option type constants.
pub mod ndp_option {
    pub const SOURCE_LINK_LAYER_ADDR: u8 = 1;
    pub const TARGET_LINK_LAYER_ADDR: u8 = 2;
    pub const PREFIX_INFO: u8 = 3;
    pub const MTU: u8 = 5;
}

/// ICMPv6 protocol parser.
#[derive(Debug, Clone, Copy)]
pub struct Icmpv6Protocol;

impl Protocol for Icmpv6Protocol {
    fn name(&self) -> &'static str {
        "icmpv6"
    }

    fn display_name(&self) -> &'static str {
        "ICMPv6"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        // Match when IPv6 next_header equals 58 (ICMPv6)
        match context.hint("ip_protocol") {
            Some(proto) if proto == IP_PROTO_ICMPV6 as u64 => {
                // Only parse for IPv6
                match context.hint("ip_version") {
                    Some(6) => Some(100),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        // ICMPv6 header is at least 4 bytes
        if data.len() < 4 {
            return ParseResult::error(
                format!("ICMPv6 header too short: {} bytes", data.len()),
                data,
            );
        }

        let mut fields = SmallVec::new();

        let icmpv6_type = data[0];
        let icmpv6_code = data[1];
        let checksum = u16::from_be_bytes([data[2], data[3]]);

        fields.push(("type", FieldValue::UInt8(icmpv6_type)));
        fields.push(("code", FieldValue::UInt8(icmpv6_code)));
        fields.push(("checksum", FieldValue::UInt16(checksum)));

        // Add type name
        let type_name = get_type_name(icmpv6_type);
        fields.push(("type_name", FieldValue::Str(type_name)));

        // Parse type-specific fields
        let consumed = match icmpv6_type {
            icmpv6_type::ECHO_REQUEST | icmpv6_type::ECHO_REPLY => {
                parse_echo(&data[4..], &mut fields)
            }
            icmpv6_type::PACKET_TOO_BIG => parse_packet_too_big(&data[4..], &mut fields),
            icmpv6_type::PARAMETER_PROBLEM => parse_parameter_problem(&data[4..], &mut fields),
            icmpv6_type::DESTINATION_UNREACHABLE | icmpv6_type::TIME_EXCEEDED => {
                // These have 4 bytes of unused data before the invoking packet
                if data.len() >= 8 {
                    8
                } else {
                    4
                }
            }
            // NDP messages
            icmpv6_type::ROUTER_SOLICITATION => parse_router_solicitation(&data[4..], &mut fields),
            icmpv6_type::ROUTER_ADVERTISEMENT => {
                parse_router_advertisement(&data[4..], &mut fields)
            }
            icmpv6_type::NEIGHBOR_SOLICITATION => {
                parse_neighbor_solicitation(&data[4..], &mut fields)
            }
            icmpv6_type::NEIGHBOR_ADVERTISEMENT => {
                parse_neighbor_advertisement(&data[4..], &mut fields)
            }
            icmpv6_type::REDIRECT => parse_redirect(&data[4..], &mut fields),
            // MLD messages
            icmpv6_type::MLD_QUERY | icmpv6_type::MLDV1_REPORT | icmpv6_type::MLDV1_DONE => {
                parse_mldv1(&data[4..], &mut fields)
            }
            icmpv6_type::MLDV2_REPORT => parse_mldv2_report(&data[4..], &mut fields),
            _ => 4, // Just consume the header
        };

        ParseResult::success(fields, &data[consumed..], SmallVec::new())
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            // Core ICMPv6 fields
            FieldDescriptor::new("icmpv6.type", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("icmpv6.code", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("icmpv6.checksum", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("icmpv6.type_name", DataKind::String).set_nullable(true),
            // Echo request/reply
            FieldDescriptor::new("icmpv6.echo_id", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("icmpv6.echo_seq", DataKind::UInt16).set_nullable(true),
            // Packet Too Big
            FieldDescriptor::new("icmpv6.mtu", DataKind::UInt32).set_nullable(true),
            // Parameter Problem
            FieldDescriptor::new("icmpv6.pointer", DataKind::UInt32).set_nullable(true),
            // NDP common
            FieldDescriptor::new("icmpv6.ndp_target_address", DataKind::String).set_nullable(true),
            // Router Advertisement
            FieldDescriptor::new("icmpv6.ndp_cur_hop_limit", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("icmpv6.ndp_managed_flag", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("icmpv6.ndp_other_flag", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("icmpv6.ndp_router_lifetime", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("icmpv6.ndp_reachable_time", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("icmpv6.ndp_retrans_timer", DataKind::UInt32).set_nullable(true),
            // Neighbor Advertisement
            FieldDescriptor::new("icmpv6.ndp_router_flag", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("icmpv6.ndp_solicited_flag", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("icmpv6.ndp_override_flag", DataKind::Bool).set_nullable(true),
            // NDP Options
            FieldDescriptor::new("icmpv6.ndp_source_mac", DataKind::String).set_nullable(true),
            FieldDescriptor::new("icmpv6.ndp_target_mac", DataKind::String).set_nullable(true),
            FieldDescriptor::new("icmpv6.ndp_prefix", DataKind::String).set_nullable(true),
            FieldDescriptor::new("icmpv6.ndp_prefix_length", DataKind::UInt8).set_nullable(true),
            // MLD
            FieldDescriptor::new("icmpv6.mld_max_response_delay", DataKind::UInt16)
                .set_nullable(true),
            FieldDescriptor::new("icmpv6.mld_multicast_address", DataKind::String)
                .set_nullable(true),
            FieldDescriptor::new("icmpv6.mld_num_group_records", DataKind::UInt16)
                .set_nullable(true),
        ]
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &["ipv6"]
    }
}

/// Get ICMPv6 type name.
fn get_type_name(icmpv6_type: u8) -> &'static str {
    match icmpv6_type {
        icmpv6_type::DESTINATION_UNREACHABLE => "Destination Unreachable",
        icmpv6_type::PACKET_TOO_BIG => "Packet Too Big",
        icmpv6_type::TIME_EXCEEDED => "Time Exceeded",
        icmpv6_type::PARAMETER_PROBLEM => "Parameter Problem",
        icmpv6_type::ECHO_REQUEST => "Echo Request",
        icmpv6_type::ECHO_REPLY => "Echo Reply",
        icmpv6_type::MLD_QUERY => "MLD Query",
        icmpv6_type::MLDV1_REPORT => "MLDv1 Report",
        icmpv6_type::MLDV1_DONE => "MLDv1 Done",
        icmpv6_type::MLDV2_REPORT => "MLDv2 Report",
        icmpv6_type::ROUTER_SOLICITATION => "Router Solicitation",
        icmpv6_type::ROUTER_ADVERTISEMENT => "Router Advertisement",
        icmpv6_type::NEIGHBOR_SOLICITATION => "Neighbor Solicitation",
        icmpv6_type::NEIGHBOR_ADVERTISEMENT => "Neighbor Advertisement",
        icmpv6_type::REDIRECT => "Redirect",
        _ => "Unknown",
    }
}

/// Parse Echo Request/Reply (types 128/129).
fn parse_echo(data: &[u8], fields: &mut SmallVec<[(&'static str, FieldValue); 16]>) -> usize {
    if data.len() < 4 {
        return 4;
    }
    let id = u16::from_be_bytes([data[0], data[1]]);
    let seq = u16::from_be_bytes([data[2], data[3]]);
    fields.push(("echo_id", FieldValue::UInt16(id)));
    fields.push(("echo_seq", FieldValue::UInt16(seq)));
    8 // 4 bytes header + 4 bytes echo data
}

/// Parse Packet Too Big (type 2).
fn parse_packet_too_big(
    data: &[u8],
    fields: &mut SmallVec<[(&'static str, FieldValue); 16]>,
) -> usize {
    if data.len() < 4 {
        return 4;
    }
    let mtu = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    fields.push(("mtu", FieldValue::UInt32(mtu)));
    8 // 4 bytes header + 4 bytes MTU
}

/// Parse Parameter Problem (type 4).
fn parse_parameter_problem(
    data: &[u8],
    fields: &mut SmallVec<[(&'static str, FieldValue); 16]>,
) -> usize {
    if data.len() < 4 {
        return 4;
    }
    let pointer = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    fields.push(("pointer", FieldValue::UInt32(pointer)));
    8 // 4 bytes header + 4 bytes pointer
}

/// Parse Router Solicitation (type 133).
fn parse_router_solicitation(
    data: &[u8],
    fields: &mut SmallVec<[(&'static str, FieldValue); 16]>,
) -> usize {
    // Router Solicitation has 4 bytes reserved, then options
    if data.len() < 4 {
        return 4;
    }
    let mut offset = 4; // Skip reserved bytes
    parse_ndp_options(&data[4..], fields);
    offset += data.len().saturating_sub(4);
    4 + offset.min(data.len())
}

/// Parse Router Advertisement (type 134).
fn parse_router_advertisement(
    data: &[u8],
    fields: &mut SmallVec<[(&'static str, FieldValue); 16]>,
) -> usize {
    // RA has 12 bytes of fixed data after the ICMPv6 header
    if data.len() < 12 {
        return 4 + data.len();
    }

    let cur_hop_limit = data[0];
    let flags = data[1];
    let router_lifetime = u16::from_be_bytes([data[2], data[3]]);
    let reachable_time = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let retrans_timer = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    fields.push(("ndp_cur_hop_limit", FieldValue::UInt8(cur_hop_limit)));
    fields.push(("ndp_managed_flag", FieldValue::Bool((flags & 0x80) != 0)));
    fields.push(("ndp_other_flag", FieldValue::Bool((flags & 0x40) != 0)));
    fields.push(("ndp_router_lifetime", FieldValue::UInt16(router_lifetime)));
    fields.push(("ndp_reachable_time", FieldValue::UInt32(reachable_time)));
    fields.push(("ndp_retrans_timer", FieldValue::UInt32(retrans_timer)));

    // Parse options
    if data.len() > 12 {
        parse_ndp_options(&data[12..], fields);
    }

    4 + data.len()
}

/// Parse Neighbor Solicitation (type 135).
fn parse_neighbor_solicitation(
    data: &[u8],
    fields: &mut SmallVec<[(&'static str, FieldValue); 16]>,
) -> usize {
    // NS has 4 bytes reserved + 16 bytes target address
    if data.len() < 20 {
        return 4 + data.len();
    }

    // Skip 4 bytes reserved
    let target = format_ipv6(&data[4..20]);
    fields.push((
        "ndp_target_address",
        FieldValue::OwnedString(CompactString::new(target)),
    ));

    // Parse options
    if data.len() > 20 {
        parse_ndp_options(&data[20..], fields);
    }

    4 + data.len()
}

/// Parse Neighbor Advertisement (type 136).
fn parse_neighbor_advertisement(
    data: &[u8],
    fields: &mut SmallVec<[(&'static str, FieldValue); 16]>,
) -> usize {
    // NA has 4 bytes flags + 16 bytes target address
    if data.len() < 20 {
        return 4 + data.len();
    }

    let flags = data[0];
    fields.push(("ndp_router_flag", FieldValue::Bool((flags & 0x80) != 0)));
    fields.push(("ndp_solicited_flag", FieldValue::Bool((flags & 0x40) != 0)));
    fields.push(("ndp_override_flag", FieldValue::Bool((flags & 0x20) != 0)));

    let target = format_ipv6(&data[4..20]);
    fields.push((
        "ndp_target_address",
        FieldValue::OwnedString(CompactString::new(target)),
    ));

    // Parse options
    if data.len() > 20 {
        parse_ndp_options(&data[20..], fields);
    }

    4 + data.len()
}

/// Parse Redirect (type 137).
fn parse_redirect(data: &[u8], fields: &mut SmallVec<[(&'static str, FieldValue); 16]>) -> usize {
    // Redirect has 4 bytes reserved + 16 bytes target + 16 bytes destination
    if data.len() < 36 {
        return 4 + data.len();
    }

    // Skip 4 bytes reserved
    let target = format_ipv6(&data[4..20]);
    fields.push((
        "ndp_target_address",
        FieldValue::OwnedString(CompactString::new(target)),
    ));

    // Parse options
    if data.len() > 36 {
        parse_ndp_options(&data[36..], fields);
    }

    4 + data.len()
}

/// Parse NDP options (TLV format).
fn parse_ndp_options(data: &[u8], fields: &mut SmallVec<[(&'static str, FieldValue); 16]>) {
    let mut offset = 0;

    while offset + 2 <= data.len() {
        let opt_type = data[offset];
        let opt_len = data[offset + 1] as usize * 8; // Length is in units of 8 bytes

        if opt_len == 0 || offset + opt_len > data.len() {
            break;
        }

        match opt_type {
            ndp_option::SOURCE_LINK_LAYER_ADDR => {
                if opt_len >= 8 {
                    let mac = format_mac(&data[offset + 2..offset + 8]);
                    fields.push((
                        "ndp_source_mac",
                        FieldValue::OwnedString(CompactString::new(mac)),
                    ));
                }
            }
            ndp_option::TARGET_LINK_LAYER_ADDR => {
                if opt_len >= 8 {
                    let mac = format_mac(&data[offset + 2..offset + 8]);
                    fields.push((
                        "ndp_target_mac",
                        FieldValue::OwnedString(CompactString::new(mac)),
                    ));
                }
            }
            ndp_option::PREFIX_INFO => {
                // Prefix Information option is 32 bytes
                if opt_len >= 32 {
                    let prefix_len = data[offset + 2];
                    let prefix = format_ipv6(&data[offset + 16..offset + 32]);
                    fields.push(("ndp_prefix_length", FieldValue::UInt8(prefix_len)));
                    fields.push((
                        "ndp_prefix",
                        FieldValue::OwnedString(CompactString::new(prefix)),
                    ));
                }
            }
            ndp_option::MTU => {
                if opt_len >= 8 {
                    let mtu = u32::from_be_bytes([
                        data[offset + 4],
                        data[offset + 5],
                        data[offset + 6],
                        data[offset + 7],
                    ]);
                    fields.push(("mtu", FieldValue::UInt32(mtu)));
                }
            }
            _ => {
                // Unknown option, skip it
            }
        }

        offset += opt_len;
    }
}

/// Parse MLDv1 message (types 130, 131, 132).
fn parse_mldv1(data: &[u8], fields: &mut SmallVec<[(&'static str, FieldValue); 16]>) -> usize {
    // MLDv1 has 2 bytes max response delay + 2 bytes reserved + 16 bytes multicast address
    if data.len() < 20 {
        return 4 + data.len();
    }

    let max_response_delay = u16::from_be_bytes([data[0], data[1]]);
    fields.push((
        "mld_max_response_delay",
        FieldValue::UInt16(max_response_delay),
    ));

    // Skip 2 bytes reserved
    let multicast_addr = format_ipv6(&data[4..20]);
    fields.push((
        "mld_multicast_address",
        FieldValue::OwnedString(CompactString::new(multicast_addr)),
    ));

    4 + 20 // header + MLDv1 message body
}

/// Parse MLDv2 Report (type 143).
fn parse_mldv2_report(
    data: &[u8],
    fields: &mut SmallVec<[(&'static str, FieldValue); 16]>,
) -> usize {
    // MLDv2 Report has 2 bytes reserved + 2 bytes number of group records
    if data.len() < 4 {
        return 4 + data.len();
    }

    // Skip 2 bytes reserved
    let num_group_records = u16::from_be_bytes([data[2], data[3]]);
    fields.push((
        "mld_num_group_records",
        FieldValue::UInt16(num_group_records),
    ));

    4 + data.len() // Consume all remaining data
}

/// Format an IPv6 address from bytes.
fn format_ipv6(bytes: &[u8]) -> String {
    if bytes.len() >= 16 {
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes[..16]);
        Ipv6Addr::from(arr).to_string()
    } else {
        "::".to_string()
    }
}

/// Format a MAC address from bytes.
fn format_mac(bytes: &[u8]) -> String {
    if bytes.len() >= 6 {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_context_icmpv6() -> ParseContext {
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", IP_PROTO_ICMPV6 as u64);
        context.insert_hint("ip_version", 6);
        context
    }

    #[test]
    fn test_can_parse_with_icmpv6() {
        let parser = Icmpv6Protocol;
        let context = create_context_icmpv6();
        assert!(parser.can_parse(&context).is_some());
    }

    #[test]
    fn test_cannot_parse_without_ipv6() {
        let parser = Icmpv6Protocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", IP_PROTO_ICMPV6 as u64);
        context.insert_hint("ip_version", 4);
        assert!(parser.can_parse(&context).is_none());
    }

    #[test]
    fn test_cannot_parse_without_hint() {
        let parser = Icmpv6Protocol;
        let context = ParseContext::new(1);
        assert!(parser.can_parse(&context).is_none());
    }

    #[test]
    fn test_parse_echo_request() {
        let parser = Icmpv6Protocol;
        let context = create_context_icmpv6();

        // ICMPv6 Echo Request
        let data = [
            0x80, // Type: Echo Request (128)
            0x00, // Code: 0
            0x12, 0x34, // Checksum
            0x00, 0x01, // Identifier: 1
            0x00, 0x02, // Sequence: 2
        ];

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("type"), Some(&FieldValue::UInt8(128)));
        assert_eq!(result.get("code"), Some(&FieldValue::UInt8(0)));
        assert_eq!(result.get("echo_id"), Some(&FieldValue::UInt16(1)));
        assert_eq!(result.get("echo_seq"), Some(&FieldValue::UInt16(2)));
        assert_eq!(
            result.get("type_name"),
            Some(&FieldValue::Str("Echo Request"))
        );
    }

    #[test]
    fn test_parse_echo_reply() {
        let parser = Icmpv6Protocol;
        let context = create_context_icmpv6();

        let data = [
            0x81, // Type: Echo Reply (129)
            0x00, // Code: 0
            0xab, 0xcd, // Checksum
            0x12, 0x34, // Identifier: 0x1234
            0x00, 0x0a, // Sequence: 10
        ];

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("type"), Some(&FieldValue::UInt8(129)));
        assert_eq!(result.get("echo_id"), Some(&FieldValue::UInt16(0x1234)));
        assert_eq!(result.get("echo_seq"), Some(&FieldValue::UInt16(10)));
        assert_eq!(
            result.get("type_name"),
            Some(&FieldValue::Str("Echo Reply"))
        );
    }

    #[test]
    fn test_parse_destination_unreachable() {
        let parser = Icmpv6Protocol;
        let context = create_context_icmpv6();

        let data = [
            0x01, // Type: Destination Unreachable (1)
            0x04, // Code: Port Unreachable
            0x00, 0x00, // Checksum
            0x00, 0x00, 0x00, 0x00, // Unused
        ];

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("type"), Some(&FieldValue::UInt8(1)));
        assert_eq!(result.get("code"), Some(&FieldValue::UInt8(4)));
        assert_eq!(
            result.get("type_name"),
            Some(&FieldValue::Str("Destination Unreachable"))
        );
    }

    #[test]
    fn test_parse_packet_too_big() {
        let parser = Icmpv6Protocol;
        let context = create_context_icmpv6();

        let data = [
            0x02, // Type: Packet Too Big (2)
            0x00, // Code: 0
            0x00, 0x00, // Checksum
            0x00, 0x00, 0x05, 0xdc, // MTU: 1500
        ];

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("type"), Some(&FieldValue::UInt8(2)));
        assert_eq!(result.get("mtu"), Some(&FieldValue::UInt32(1500)));
        assert_eq!(
            result.get("type_name"),
            Some(&FieldValue::Str("Packet Too Big"))
        );
    }

    #[test]
    fn test_parse_time_exceeded() {
        let parser = Icmpv6Protocol;
        let context = create_context_icmpv6();

        let data = [
            0x03, // Type: Time Exceeded (3)
            0x00, // Code: Hop limit exceeded
            0x00, 0x00, // Checksum
            0x00, 0x00, 0x00, 0x00, // Unused
        ];

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("type"), Some(&FieldValue::UInt8(3)));
        assert_eq!(
            result.get("type_name"),
            Some(&FieldValue::Str("Time Exceeded"))
        );
    }

    #[test]
    fn test_parse_parameter_problem() {
        let parser = Icmpv6Protocol;
        let context = create_context_icmpv6();

        let data = [
            0x04, // Type: Parameter Problem (4)
            0x02, // Code: Unrecognized next header
            0x00, 0x00, // Checksum
            0x00, 0x00, 0x00, 0x28, // Pointer: 40
        ];

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("type"), Some(&FieldValue::UInt8(4)));
        assert_eq!(result.get("code"), Some(&FieldValue::UInt8(2)));
        assert_eq!(result.get("pointer"), Some(&FieldValue::UInt32(40)));
        assert_eq!(
            result.get("type_name"),
            Some(&FieldValue::Str("Parameter Problem"))
        );
    }

    #[test]
    fn test_parse_too_short() {
        let parser = Icmpv6Protocol;
        let context = create_context_icmpv6();

        let data = [0x80, 0x00]; // Only 2 bytes

        let result = parser.parse(&data, &context);

        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }

    #[test]
    fn test_schema_fields() {
        let parser = Icmpv6Protocol;
        let fields = parser.schema_fields();

        assert!(!fields.is_empty());
        assert!(fields.iter().any(|f| f.name == "icmpv6.type"));
        assert!(fields.iter().any(|f| f.name == "icmpv6.code"));
        assert!(fields.iter().any(|f| f.name == "icmpv6.checksum"));
        assert!(fields.iter().any(|f| f.name == "icmpv6.echo_id"));
        assert!(fields.iter().any(|f| f.name == "icmpv6.mtu"));
    }

    // NDP Tests

    #[test]
    fn test_parse_router_solicitation() {
        let parser = Icmpv6Protocol;
        let context = create_context_icmpv6();

        // Router Solicitation with Source Link-Layer Address option
        let mut data = vec![
            0x85, // Type: Router Solicitation (133)
            0x00, // Code: 0
            0x00, 0x00, // Checksum
            0x00, 0x00, 0x00, 0x00, // Reserved
            // Source Link-Layer Address option
            0x01, // Type: 1
            0x01, // Length: 1 (8 bytes)
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // MAC
        ];

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("type"), Some(&FieldValue::UInt8(133)));
        assert_eq!(
            result.get("type_name"),
            Some(&FieldValue::Str("Router Solicitation"))
        );
        // For constructed strings like MAC addresses, we need to compare with OwnedString
        match result.get("ndp_source_mac") {
            Some(FieldValue::OwnedString(s)) if s.as_str() == "00:11:22:33:44:55" => {}
            other => panic!(
                "Expected OwnedString(\"00:11:22:33:44:55\"), got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_parse_router_advertisement() {
        let parser = Icmpv6Protocol;
        let context = create_context_icmpv6();

        let data = [
            0x86, // Type: Router Advertisement (134)
            0x00, // Code: 0
            0x00, 0x00, // Checksum
            0x40, // Cur Hop Limit: 64
            0xc0, // Flags: M=1, O=1
            0x07, 0x08, // Router Lifetime: 1800
            0x00, 0x00, 0x00, 0x00, // Reachable Time: 0
            0x00, 0x00, 0x00, 0x00, // Retrans Timer: 0
        ];

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("type"), Some(&FieldValue::UInt8(134)));
        assert_eq!(
            result.get("ndp_cur_hop_limit"),
            Some(&FieldValue::UInt8(64))
        );
        assert_eq!(
            result.get("ndp_managed_flag"),
            Some(&FieldValue::Bool(true))
        );
        assert_eq!(result.get("ndp_other_flag"), Some(&FieldValue::Bool(true)));
        assert_eq!(
            result.get("ndp_router_lifetime"),
            Some(&FieldValue::UInt16(1800))
        );
    }

    #[test]
    fn test_parse_router_advertisement_flags() {
        let parser = Icmpv6Protocol;
        let context = create_context_icmpv6();

        // Test with only M flag set
        let data = [
            0x86, 0x00, 0x00, 0x00, 0x40, 0x80, // M=1, O=0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let result = parser.parse(&data, &context);
        assert_eq!(
            result.get("ndp_managed_flag"),
            Some(&FieldValue::Bool(true))
        );
        assert_eq!(result.get("ndp_other_flag"), Some(&FieldValue::Bool(false)));

        // Test with only O flag set
        let data2 = [
            0x86, 0x00, 0x00, 0x00, 0x40, 0x40, // M=0, O=1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let result2 = parser.parse(&data2, &context);
        assert_eq!(
            result2.get("ndp_managed_flag"),
            Some(&FieldValue::Bool(false))
        );
        assert_eq!(result2.get("ndp_other_flag"), Some(&FieldValue::Bool(true)));
    }

    #[test]
    fn test_parse_neighbor_solicitation() {
        let parser = Icmpv6Protocol;
        let context = create_context_icmpv6();

        // NS for 2001:db8::1
        let data = [
            0x87, // Type: Neighbor Solicitation (135)
            0x00, // Code: 0
            0x00, 0x00, // Checksum
            0x00, 0x00, 0x00, 0x00, // Reserved
            // Target Address: 2001:db8::1
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("type"), Some(&FieldValue::UInt8(135)));
        match result.get("ndp_target_address") {
            Some(FieldValue::OwnedString(s)) if s.as_str() == "2001:db8::1" => {}
            other => panic!("Expected OwnedString(\"2001:db8::1\"), got {:?}", other),
        }
    }

    #[test]
    fn test_parse_neighbor_advertisement() {
        let parser = Icmpv6Protocol;
        let context = create_context_icmpv6();

        // NA with R=1, S=1, O=0
        let data = [
            0x88, // Type: Neighbor Advertisement (136)
            0x00, // Code: 0
            0x00, 0x00, // Checksum
            0xc0, 0x00, 0x00, 0x00, // Flags: R=1, S=1, O=0
            // Target Address: 2001:db8::1
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("type"), Some(&FieldValue::UInt8(136)));
        assert_eq!(result.get("ndp_router_flag"), Some(&FieldValue::Bool(true)));
        assert_eq!(
            result.get("ndp_solicited_flag"),
            Some(&FieldValue::Bool(true))
        );
        assert_eq!(
            result.get("ndp_override_flag"),
            Some(&FieldValue::Bool(false))
        );
        match result.get("ndp_target_address") {
            Some(FieldValue::OwnedString(s)) if s.as_str() == "2001:db8::1" => {}
            other => panic!("Expected OwnedString(\"2001:db8::1\"), got {:?}", other),
        }
    }

    #[test]
    fn test_parse_neighbor_advertisement_flags() {
        let parser = Icmpv6Protocol;
        let context = create_context_icmpv6();

        // Test with O flag set
        let data = [
            0x88, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, // R=0, S=0, O=1
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];

        let result = parser.parse(&data, &context);
        assert_eq!(
            result.get("ndp_router_flag"),
            Some(&FieldValue::Bool(false))
        );
        assert_eq!(
            result.get("ndp_solicited_flag"),
            Some(&FieldValue::Bool(false))
        );
        assert_eq!(
            result.get("ndp_override_flag"),
            Some(&FieldValue::Bool(true))
        );
    }

    #[test]
    fn test_parse_redirect() {
        let parser = Icmpv6Protocol;
        let context = create_context_icmpv6();

        let mut data = vec![
            0x89, // Type: Redirect (137)
            0x00, // Code: 0
            0x00, 0x00, // Checksum
            0x00, 0x00, 0x00, 0x00, // Reserved
        ];
        // Target Address (16 bytes)
        data.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // Destination Address (16 bytes)
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("type"), Some(&FieldValue::UInt8(137)));
        match result.get("ndp_target_address") {
            Some(FieldValue::OwnedString(s)) if s.as_str() == "fe80::1" => {}
            other => panic!("Expected OwnedString(\"fe80::1\"), got {:?}", other),
        }
    }

    #[test]
    fn test_parse_source_link_layer_option() {
        let parser = Icmpv6Protocol;
        let context = create_context_icmpv6();

        let mut data = vec![
            0x87, 0x00, 0x00, 0x00, // NS header
            0x00, 0x00, 0x00, 0x00, // Reserved
        ];
        // Target address
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // Source Link-Layer option
        data.extend_from_slice(&[0x01, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        match result.get("ndp_source_mac") {
            Some(FieldValue::OwnedString(s)) if s.as_str() == "aa:bb:cc:dd:ee:ff" => {}
            other => panic!(
                "Expected OwnedString(\"aa:bb:cc:dd:ee:ff\"), got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_parse_target_link_layer_option() {
        let parser = Icmpv6Protocol;
        let context = create_context_icmpv6();

        let mut data = vec![
            0x88, 0x00, 0x00, 0x00, // NA header
            0x60, 0x00, 0x00, 0x00, // Flags
        ];
        // Target address
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // Target Link-Layer option
        data.extend_from_slice(&[0x02, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        match result.get("ndp_target_mac") {
            Some(FieldValue::OwnedString(s)) if s.as_str() == "11:22:33:44:55:66" => {}
            other => panic!(
                "Expected OwnedString(\"11:22:33:44:55:66\"), got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_parse_prefix_info_option() {
        let parser = Icmpv6Protocol;
        let context = create_context_icmpv6();

        let mut data = vec![
            0x86, 0x00, 0x00, 0x00, // RA header
            0x40, 0x00, // Cur Hop Limit, Flags
            0x00, 0x00, // Router Lifetime
            0x00, 0x00, 0x00, 0x00, // Reachable Time
            0x00, 0x00, 0x00, 0x00, // Retrans Timer
        ];
        // Prefix Information option (32 bytes)
        data.extend_from_slice(&[
            0x03, 0x04, // Type=3, Len=4 (32 bytes)
            0x40, // Prefix length: 64
            0xc0, // Flags: L=1, A=1
            0x00, 0x00, 0x00, 0x00, // Valid lifetime
            0x00, 0x00, 0x00, 0x00, // Preferred lifetime
            0x00, 0x00, 0x00, 0x00, // Reserved
            // Prefix: 2001:db8::
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]);

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("ndp_prefix_length"),
            Some(&FieldValue::UInt8(64))
        );
        match result.get("ndp_prefix") {
            Some(FieldValue::OwnedString(s)) if s.as_str() == "2001:db8::" => {}
            other => panic!("Expected OwnedString(\"2001:db8::\"), got {:?}", other),
        }
    }

    // MLD Tests

    #[test]
    fn test_parse_mld_query() {
        let parser = Icmpv6Protocol;
        let context = create_context_icmpv6();

        let mut data = vec![
            0x82, // Type: MLD Query (130)
            0x00, // Code: 0
            0x00, 0x00, // Checksum
            0x27, 0x10, // Max Response Delay: 10000ms
            0x00, 0x00, // Reserved
        ];
        // Multicast Address (all-nodes: ff02::1)
        data.extend_from_slice(&[0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("type"), Some(&FieldValue::UInt8(130)));
        assert_eq!(
            result.get("mld_max_response_delay"),
            Some(&FieldValue::UInt16(10000))
        );
        match result.get("mld_multicast_address") {
            Some(FieldValue::OwnedString(s)) if s.as_str() == "ff02::1" => {}
            other => panic!("Expected OwnedString(\"ff02::1\"), got {:?}", other),
        }
    }

    #[test]
    fn test_parse_mldv1_report() {
        let parser = Icmpv6Protocol;
        let context = create_context_icmpv6();

        let mut data = vec![
            0x83, // Type: MLDv1 Report (131)
            0x00, // Code: 0
            0x00, 0x00, // Checksum
            0x00, 0x00, // Max Response Delay: 0
            0x00, 0x00, // Reserved
        ];
        // Multicast Address
        data.extend_from_slice(&[0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12]);

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("type"), Some(&FieldValue::UInt8(131)));
        assert_eq!(
            result.get("type_name"),
            Some(&FieldValue::Str("MLDv1 Report"))
        );
    }

    #[test]
    fn test_parse_mldv1_done() {
        let parser = Icmpv6Protocol;
        let context = create_context_icmpv6();

        let mut data = vec![
            0x84, // Type: MLDv1 Done (132)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        // Multicast Address
        data.extend_from_slice(&[0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12]);

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("type"), Some(&FieldValue::UInt8(132)));
        assert_eq!(
            result.get("type_name"),
            Some(&FieldValue::Str("MLDv1 Done"))
        );
    }

    #[test]
    fn test_parse_mldv2_report() {
        let parser = Icmpv6Protocol;
        let context = create_context_icmpv6();

        let data = [
            0x8f, // Type: MLDv2 Report (143)
            0x00, // Code: 0
            0x00, 0x00, // Checksum
            0x00, 0x00, // Reserved
            0x00, 0x03, // Number of Group Records: 3
        ];

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("type"), Some(&FieldValue::UInt8(143)));
        assert_eq!(
            result.get("mld_num_group_records"),
            Some(&FieldValue::UInt16(3))
        );
        assert_eq!(
            result.get("type_name"),
            Some(&FieldValue::Str("MLDv2 Report"))
        );
    }

    #[test]
    fn test_multicast_address_extraction() {
        let parser = Icmpv6Protocol;
        let context = create_context_icmpv6();

        // MLDv1 Query with ff02::16 (all-MLDv2-capable-routers)
        let mut data = vec![0x82, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00];
        data.extend_from_slice(&[0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x16]);

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        match result.get("mld_multicast_address") {
            Some(FieldValue::OwnedString(s)) if s.as_str() == "ff02::16" => {}
            other => panic!("Expected OwnedString(\"ff02::16\"), got {:?}", other),
        }
    }

    #[test]
    fn test_max_response_delay() {
        let parser = Icmpv6Protocol;
        let context = create_context_icmpv6();

        let mut data = vec![
            0x82, 0x00, 0x00, 0x00, 0x03, 0xe8, // Max Response Delay: 1000
            0x00, 0x00,
        ];
        data.extend_from_slice(&[0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("mld_max_response_delay"),
            Some(&FieldValue::UInt16(1000))
        );
    }
}
