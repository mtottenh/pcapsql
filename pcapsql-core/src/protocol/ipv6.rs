//! IPv6 protocol parser with extension header support.

use etherparse::Ipv6HeaderSlice;
use smallvec::SmallVec;

use super::ethernet::ethertype;
use super::{FieldValue, ParseContext, ParseResult, Protocol, TunnelType};
use crate::schema::{DataKind, FieldDescriptor};

/// IPv6 Next Header values for extension headers and encapsulation.
#[allow(dead_code)]
pub mod next_header {
    pub const HOP_BY_HOP: u8 = 0;
    /// IPv4 encapsulated in IPv6 (IP-in-IP)
    pub const IPIP: u8 = 4;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    /// IPv6 encapsulated in IPv6 (IPv6-in-IPv6)
    pub const IPV6_IN_IP: u8 = 41;
    pub const ROUTING: u8 = 43;
    pub const FRAGMENT: u8 = 44;
    pub const ESP: u8 = 50;
    pub const AH: u8 = 51;
    pub const ICMPV6: u8 = 58;
    pub const NO_NEXT_HEADER: u8 = 59;
    pub const DESTINATION: u8 = 60;
    pub const MOBILITY: u8 = 135;
}

/// Check if a next header value is an extension header.
fn is_extension_header(nh: u8) -> bool {
    matches!(
        nh,
        next_header::HOP_BY_HOP
            | next_header::ROUTING
            | next_header::FRAGMENT
            | next_header::DESTINATION
            | next_header::AH
            | next_header::MOBILITY
    )
}

/// IPv6 protocol parser.
#[derive(Debug, Clone, Copy)]
pub struct Ipv6Protocol;

impl Protocol for Ipv6Protocol {
    fn name(&self) -> &'static str {
        "ipv6"
    }

    fn display_name(&self) -> &'static str {
        "IPv6"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        match context.hint("ethertype") {
            Some(et) if et == ethertype::IPV6 as u64 => Some(100),
            _ => None,
        }
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        match Ipv6HeaderSlice::from_slice(data) {
            Ok(ipv6) => {
                let mut fields = SmallVec::new();

                fields.push(("version", FieldValue::UInt8(6)));
                fields.push(("traffic_class", FieldValue::UInt8(ipv6.traffic_class())));
                fields.push(("flow_label", FieldValue::UInt32(ipv6.flow_label().value())));
                fields.push(("payload_length", FieldValue::UInt16(ipv6.payload_length())));
                fields.push(("next_header", FieldValue::UInt8(ipv6.next_header().0)));
                fields.push(("hop_limit", FieldValue::UInt8(ipv6.hop_limit())));
                fields.push(("src_ip", FieldValue::ipv6(&ipv6.source())));
                fields.push(("dst_ip", FieldValue::ipv6(&ipv6.destination())));

                let base_header_len = ipv6.slice().len();
                let payload = &data[base_header_len..];
                let first_next_header = ipv6.next_header().0;

                // Parse extension headers
                let (final_next_header, ext_consumed, ext_fields) =
                    parse_extension_headers(first_next_header, payload);

                // Merge extension header fields
                for (k, v) in ext_fields {
                    fields.push((k, v));
                }

                let mut child_hints = SmallVec::new();
                child_hints.push(("ip_protocol", final_next_header as u64));
                child_hints.push(("ip_version", 6));

                // Check for IP-in-IP encapsulation
                if final_next_header == next_header::IPIP {
                    // IPv4 encapsulated in IPv6 - signal tunnel boundary
                    child_hints.push(("tunnel_type", TunnelType::Ip4InIp6 as u64));
                    // Set ethertype hint so inner IPv4 can be parsed
                    child_hints.push(("ethertype", ethertype::IPV4 as u64));
                } else if final_next_header == next_header::IPV6_IN_IP {
                    // IPv6 encapsulated in IPv6 - signal tunnel boundary
                    child_hints.push(("tunnel_type", TunnelType::Ip6InIp6 as u64));
                    // Set ethertype hint so inner IPv6 can be parsed
                    child_hints.push(("ethertype", ethertype::IPV6 as u64));
                }

                let total_consumed = base_header_len + ext_consumed;
                ParseResult::success(fields, &data[total_consumed..], child_hints)
            }
            Err(e) => ParseResult::error(format!("IPv6 parse error: {e}"), data),
        }
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            // Basic IPv6 header fields
            FieldDescriptor::new("ipv6.version", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("ipv6.traffic_class", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("ipv6.flow_label", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("ipv6.payload_length", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("ipv6.next_header", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("ipv6.hop_limit", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("ipv6.src_ip", DataKind::String).set_nullable(true),
            FieldDescriptor::new("ipv6.dst_ip", DataKind::String).set_nullable(true),
            // Extension header tracking
            FieldDescriptor::new("ipv6.ext_hop_by_hop", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("ipv6.ext_routing", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("ipv6.ext_fragment", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("ipv6.ext_destination", DataKind::Bool).set_nullable(true),
            // Fragment header fields
            FieldDescriptor::new("ipv6.frag_offset", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("ipv6.frag_more", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("ipv6.frag_id", DataKind::UInt32).set_nullable(true),
            // Routing header fields
            FieldDescriptor::new("ipv6.routing_type", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("ipv6.segments_left", DataKind::UInt8).set_nullable(true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        &["tcp", "udp", "icmpv6"]
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &["ethernet", "vlan", "mpls", "gre", "vxlan", "gtp"]
    }
}

/// Parse IPv6 extension headers and return (final_next_header, bytes_consumed, fields).
fn parse_extension_headers(
    first_nh: u8,
    data: &[u8],
) -> (u8, usize, SmallVec<[(&'static str, FieldValue); 16]>) {
    let mut fields = SmallVec::new();
    let mut offset = 0;
    let mut current_nh = first_nh;

    // Track which extension headers we've seen
    let mut has_hop_by_hop = false;
    let mut has_routing = false;
    let mut has_fragment = false;
    let mut has_destination = false;

    while is_extension_header(current_nh) && offset < data.len() {
        match current_nh {
            next_header::HOP_BY_HOP => {
                has_hop_by_hop = true;
                if let Some((next_nh, consumed)) = parse_generic_ext_header(&data[offset..]) {
                    current_nh = next_nh;
                    offset += consumed;
                } else {
                    break;
                }
            }
            next_header::ROUTING => {
                has_routing = true;
                if let Some((next_nh, consumed, routing_fields)) =
                    parse_routing_header(&data[offset..])
                {
                    for (k, v) in routing_fields {
                        fields.push((k, v));
                    }
                    current_nh = next_nh;
                    offset += consumed;
                } else {
                    break;
                }
            }
            next_header::FRAGMENT => {
                has_fragment = true;
                if let Some((next_nh, consumed, frag_fields)) =
                    parse_fragment_header(&data[offset..])
                {
                    for (k, v) in frag_fields {
                        fields.push((k, v));
                    }
                    current_nh = next_nh;
                    offset += consumed;
                } else {
                    break;
                }
            }
            next_header::DESTINATION => {
                has_destination = true;
                if let Some((next_nh, consumed)) = parse_generic_ext_header(&data[offset..]) {
                    current_nh = next_nh;
                    offset += consumed;
                } else {
                    break;
                }
            }
            next_header::AH => {
                // Authentication Header has different length calculation
                if let Some((next_nh, consumed)) = parse_ah_header(&data[offset..]) {
                    current_nh = next_nh;
                    offset += consumed;
                } else {
                    break;
                }
            }
            next_header::MOBILITY => {
                if let Some((next_nh, consumed)) = parse_generic_ext_header(&data[offset..]) {
                    current_nh = next_nh;
                    offset += consumed;
                } else {
                    break;
                }
            }
            _ => break,
        }
    }

    // Add extension header presence flags
    fields.push(("ext_hop_by_hop", FieldValue::Bool(has_hop_by_hop)));
    fields.push(("ext_routing", FieldValue::Bool(has_routing)));
    fields.push(("ext_fragment", FieldValue::Bool(has_fragment)));
    fields.push(("ext_destination", FieldValue::Bool(has_destination)));

    (current_nh, offset, fields)
}

/// Parse a generic extension header (Hop-by-Hop, Destination Options, Mobility).
/// Returns (next_header, bytes_consumed) or None if parsing fails.
fn parse_generic_ext_header(data: &[u8]) -> Option<(u8, usize)> {
    if data.len() < 2 {
        return None;
    }

    let next_header = data[0];
    let hdr_ext_len = data[1] as usize;
    // Length is in units of 8 octets, not including the first 8 octets
    let total_len = (hdr_ext_len + 1) * 8;

    if data.len() < total_len {
        return None;
    }

    Some((next_header, total_len))
}

/// Parse Fragment Header.
/// Returns (next_header, bytes_consumed, fields) or None if parsing fails.
fn parse_fragment_header(
    data: &[u8],
) -> Option<(u8, usize, SmallVec<[(&'static str, FieldValue); 16]>)> {
    // Fragment header is exactly 8 bytes
    if data.len() < 8 {
        return None;
    }

    let mut fields = SmallVec::new();

    let next_header = data[0];
    // data[1] is reserved
    let frag_offset_and_flags = u16::from_be_bytes([data[2], data[3]]);
    let frag_offset = frag_offset_and_flags >> 3; // Upper 13 bits
    let more_fragments = (frag_offset_and_flags & 0x0001) != 0; // Lowest bit is M flag
    let identification = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    fields.push(("frag_offset", FieldValue::UInt16(frag_offset)));
    fields.push(("frag_more", FieldValue::Bool(more_fragments)));
    fields.push(("frag_id", FieldValue::UInt32(identification)));

    Some((next_header, 8, fields))
}

/// Parse Routing Header.
/// Returns (next_header, bytes_consumed, fields) or None if parsing fails.
fn parse_routing_header(
    data: &[u8],
) -> Option<(u8, usize, SmallVec<[(&'static str, FieldValue); 16]>)> {
    if data.len() < 4 {
        return None;
    }

    let mut fields = SmallVec::new();

    let next_header = data[0];
    let hdr_ext_len = data[1] as usize;
    let routing_type = data[2];
    let segments_left = data[3];

    // Length is in units of 8 octets, not including the first 8 octets
    let total_len = (hdr_ext_len + 1) * 8;

    if data.len() < total_len {
        return None;
    }

    fields.push(("routing_type", FieldValue::UInt8(routing_type)));
    fields.push(("segments_left", FieldValue::UInt8(segments_left)));

    Some((next_header, total_len, fields))
}

/// Parse Authentication Header.
/// Returns (next_header, bytes_consumed) or None if parsing fails.
fn parse_ah_header(data: &[u8]) -> Option<(u8, usize)> {
    if data.len() < 8 {
        return None;
    }

    let next_header = data[0];
    let payload_len = data[1] as usize;
    // AH length = (payload_len + 2) * 4 bytes
    let total_len = (payload_len + 2) * 4;

    if data.len() < total_len {
        return None;
    }

    Some((next_header, total_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_ipv6_context() -> ParseContext {
        let mut context = ParseContext::new(1);
        context.insert_hint("ethertype", 0x86DD);
        context
    }

    #[test]
    fn test_parse_ipv6() {
        // IPv6 header (40 bytes) with TCP next header
        let header = [
            0x60, 0x00, 0x00, 0x00, // Version (6) + Traffic class + Flow label
            0x00, 0x14, // Payload length: 20
            0x06, // Next header: TCP
            0x40, // Hop limit: 64
            // Source: 2001:db8::1
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, // Destination: 2001:db8::2
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ];

        let parser = Ipv6Protocol;
        let context = create_ipv6_context();

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("version"), Some(&FieldValue::UInt8(6)));
        assert_eq!(result.get("hop_limit"), Some(&FieldValue::UInt8(64)));
        assert_eq!(result.get("next_header"), Some(&FieldValue::UInt8(6)));
        assert_eq!(result.hint("ip_protocol"), Some(6u64));
        assert_eq!(result.hint("ip_version"), Some(6u64));
    }

    #[test]
    fn test_can_parse_with_ipv6_ethertype() {
        let parser = Ipv6Protocol;

        // Without ethertype hint
        let context1 = ParseContext::new(1);
        assert!(parser.can_parse(&context1).is_none());

        // With IPv4 ethertype
        let mut context2 = ParseContext::new(1);
        context2.insert_hint("ethertype", 0x0800);
        assert!(parser.can_parse(&context2).is_none());

        // With IPv6 ethertype
        let mut context3 = ParseContext::new(1);
        context3.insert_hint("ethertype", 0x86DD);
        assert!(parser.can_parse(&context3).is_some());
    }

    #[test]
    fn test_parse_ipv6_with_udp() {
        // IPv6 header with UDP next header
        let header = [
            0x60, 0x0a, 0xbc, 0xde, // Version (6) + Traffic class (0x0a) + Flow label
            0x00, 0x08, // Payload length: 8 (UDP header)
            0x11, // Next header: UDP (17)
            0x80, // Hop limit: 128
            // Source: ::1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, // Destination: ::1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];

        let parser = Ipv6Protocol;
        let context = create_ipv6_context();

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("next_header"), Some(&FieldValue::UInt8(17)));
        assert_eq!(result.get("hop_limit"), Some(&FieldValue::UInt8(128)));
        assert_eq!(result.hint("ip_protocol"), Some(17u64));
    }

    #[test]
    fn test_parse_ipv6_too_short() {
        let short_data = [0x60, 0x00, 0x00, 0x00]; // Only 4 bytes

        let parser = Ipv6Protocol;
        let context = create_ipv6_context();

        let result = parser.parse(&short_data, &context);

        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }

    #[test]
    fn test_parse_hop_by_hop_options() {
        // IPv6 header with Hop-by-Hop options header followed by TCP
        let mut packet = vec![
            0x60, 0x00, 0x00, 0x00, // Version + Traffic class + Flow label
            0x00, 0x10, // Payload length: 16 (8 byte HBH + 8 byte TCP stub)
            0x00, // Next header: Hop-by-Hop (0)
            0x40, // Hop limit: 64
        ];
        // Source: ::1
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // Destination: ::2
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // Hop-by-Hop Options header (8 bytes)
        packet.extend_from_slice(&[
            0x06, // Next header: TCP
            0x00, // Length: 0 (8 bytes total)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
        ]);
        // TCP stub
        packet.extend_from_slice(&[0x00, 0x50, 0x00, 0x51, 0x00, 0x00, 0x00, 0x00]);

        let parser = Ipv6Protocol;
        let context = create_ipv6_context();

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("ext_hop_by_hop"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("ext_routing"), Some(&FieldValue::Bool(false)));
        assert_eq!(result.hint("ip_protocol"), Some(6u64)); // TCP
    }

    #[test]
    fn test_parse_routing_header() {
        // IPv6 header with Routing header followed by TCP
        let mut packet = vec![
            0x60, 0x00, 0x00, 0x00, // Version + Traffic class + Flow label
            0x00, 0x10, // Payload length
            0x2b, // Next header: Routing (43)
            0x40, // Hop limit: 64
        ];
        // Source: ::1
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // Destination: ::2
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // Routing header (8 bytes minimum)
        packet.extend_from_slice(&[
            0x06, // Next header: TCP
            0x00, // Length: 0 (8 bytes total)
            0x02, // Routing type: 2 (Type 2 Routing Header)
            0x01, // Segments left: 1
            0x00, 0x00, 0x00, 0x00, // Reserved/data
        ]);

        let parser = Ipv6Protocol;
        let context = create_ipv6_context();

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("ext_routing"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("routing_type"), Some(&FieldValue::UInt8(2)));
        assert_eq!(result.get("segments_left"), Some(&FieldValue::UInt8(1)));
        assert_eq!(result.hint("ip_protocol"), Some(6u64));
    }

    #[test]
    fn test_parse_fragment_header() {
        // IPv6 header with Fragment header followed by TCP
        let mut packet = vec![
            0x60, 0x00, 0x00, 0x00, // Version + Traffic class + Flow label
            0x00, 0x10, // Payload length
            0x2c, // Next header: Fragment (44)
            0x40, // Hop limit: 64
        ];
        // Source: ::1
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // Destination: ::2
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // Fragment header (8 bytes)
        packet.extend_from_slice(&[
            0x06, // Next header: TCP
            0x00, // Reserved
            0x00, 0x09, // Fragment Offset: 1 (8 bytes), M flag: 1
            0x12, 0x34, 0x56, 0x78, // Identification
        ]);

        let parser = Ipv6Protocol;
        let context = create_ipv6_context();

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("ext_fragment"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("frag_offset"), Some(&FieldValue::UInt16(1)));
        assert_eq!(result.get("frag_more"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("frag_id"), Some(&FieldValue::UInt32(0x12345678)));
    }

    #[test]
    fn test_parse_destination_options() {
        // IPv6 header with Destination Options header followed by TCP
        let mut packet = vec![
            0x60, 0x00, 0x00, 0x00, 0x00, 0x10, 0x3c, // Destination (60)
            0x40,
        ];
        // Source/Destination addresses
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // Destination Options header (8 bytes)
        packet.extend_from_slice(&[0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        let parser = Ipv6Protocol;
        let context = create_ipv6_context();

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("ext_destination"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.hint("ip_protocol"), Some(6u64));
    }

    #[test]
    fn test_parse_extension_header_chaining() {
        // IPv6 with Hop-by-Hop -> Routing -> Fragment -> TCP
        let mut packet = vec![
            0x60, 0x00, 0x00, 0x00, 0x00, 0x20, // Payload length: 32
            0x00, // Hop-by-Hop
            0x40, // Hop limit
        ];
        // Addresses
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // Hop-by-Hop (points to Routing)
        packet.extend_from_slice(&[0x2b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // Routing (points to Fragment)
        packet.extend_from_slice(&[0x2c, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]);
        // Fragment (points to TCP)
        packet.extend_from_slice(&[0x06, 0x00, 0x00, 0x00, 0xab, 0xcd, 0xef, 0x12]);

        let parser = Ipv6Protocol;
        let context = create_ipv6_context();

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("ext_hop_by_hop"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("ext_routing"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("ext_fragment"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.hint("ip_protocol"), Some(6u64));
    }

    #[test]
    fn test_fragment_offset_and_m_flag() {
        // Test fragment header with offset = 185 (1480/8) and M=0 (last fragment)
        let mut packet = vec![0x60, 0x00, 0x00, 0x00, 0x00, 0x10, 0x2c, 0x40];
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // Fragment header: offset=185 (0x0b9 << 3 = 0x05c8), M=0
        packet.extend_from_slice(&[0x06, 0x00, 0x05, 0xc8, 0x00, 0x00, 0x00, 0x01]);

        let parser = Ipv6Protocol;
        let context = create_ipv6_context();

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("frag_offset"), Some(&FieldValue::UInt16(185)));
        assert_eq!(result.get("frag_more"), Some(&FieldValue::Bool(false)));
    }

    #[test]
    fn test_segments_left_field() {
        let mut packet = vec![0x60, 0x00, 0x00, 0x00, 0x00, 0x10, 0x2b, 0x40];
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // Routing header with segments_left = 5
        packet.extend_from_slice(&[0x06, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00]);

        let parser = Ipv6Protocol;
        let context = create_ipv6_context();

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("segments_left"), Some(&FieldValue::UInt8(5)));
    }

    #[test]
    fn test_unknown_extension_header_skipping() {
        // When we hit an unknown next header value, we should stop parsing extensions
        let mut packet = vec![0x60, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x40];
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // Hop-by-Hop points to protocol 250 (unknown)
        packet.extend_from_slice(&[0xfa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        let parser = Ipv6Protocol;
        let context = create_ipv6_context();

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("ext_hop_by_hop"), Some(&FieldValue::Bool(true)));
        // Final protocol should be 250 (unknown)
        assert_eq!(result.hint("ip_protocol"), Some(250u64));
    }

    #[test]
    fn test_ipv4_in_ipv6_tunnel() {
        // IPv6 header with next_header=4 (IPv4 encapsulated in IPv6)
        let mut packet = vec![
            0x60, 0x00, 0x00, 0x00, // Version (6) + Traffic class + Flow label
            0x00, 0x14, // Payload length: 20 (inner IPv4 header)
            0x04, // Next header: IPIP (4) - IPv4 encapsulated
            0x40, // Hop limit: 64
        ];
        // Source: 2001:db8::1
        packet.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        // Destination: 2001:db8::2
        packet.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]);
        // Inner IPv4 header stub (first few bytes)
        packet.extend_from_slice(&[0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00]);

        let parser = Ipv6Protocol;
        let context = create_ipv6_context();

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("next_header"), Some(&FieldValue::UInt8(4)));
        // Should set ip_protocol hint for inner protocol
        assert_eq!(result.hint("ip_protocol"), Some(4u64));
        // Should set ethertype hint for IPv4 so inner IPv4 parser can match
        assert_eq!(result.hint("ethertype"), Some(0x0800u64));
        // Should indicate tunnel type
        assert_eq!(
            result.hint("tunnel_type"),
            Some(TunnelType::Ip4InIp6 as u64)
        );
    }

    #[test]
    fn test_ipv6_in_ipv6_tunnel() {
        // IPv6 header with next_header=41 (IPv6 encapsulated in IPv6)
        let mut packet = vec![
            0x60, 0x00, 0x00, 0x00, // Version (6) + Traffic class + Flow label
            0x00, 0x28, // Payload length: 40 (inner IPv6 header)
            0x29, // Next header: IPv6 (41) - IPv6 encapsulated
            0x40, // Hop limit: 64
        ];
        // Source: 2001:db8::1
        packet.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        // Destination: 2001:db8::2
        packet.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]);
        // Inner IPv6 header stub
        packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x40]);

        let parser = Ipv6Protocol;
        let context = create_ipv6_context();

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("next_header"), Some(&FieldValue::UInt8(41)));
        // Should set ip_protocol hint for inner protocol
        assert_eq!(result.hint("ip_protocol"), Some(41u64));
        // Should set ethertype hint for IPv6 so inner IPv6 parser can match
        assert_eq!(result.hint("ethertype"), Some(0x86DDu64));
        // Should indicate tunnel type
        assert_eq!(
            result.hint("tunnel_type"),
            Some(TunnelType::Ip6InIp6 as u64)
        );
    }
}
