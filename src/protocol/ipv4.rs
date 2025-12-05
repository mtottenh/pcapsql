//! IPv4 protocol parser.

use std::collections::HashMap;

use arrow::datatypes::{DataType, Field};
use etherparse::Ipv4HeaderSlice;

use super::ethernet::ethertype;
use super::{FieldValue, ParseContext, ParseResult, Protocol};

/// IPv4 protocol parser.
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Protocol;

impl Protocol for Ipv4Protocol {
    fn name(&self) -> &'static str {
        "ipv4"
    }

    fn display_name(&self) -> &'static str {
        "IPv4"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        match context.hint("ethertype") {
            Some(et) if et == ethertype::IPV4 as u64 => Some(100),
            _ => None,
        }
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        match Ipv4HeaderSlice::from_slice(data) {
            Ok(ipv4) => {
                let mut fields = HashMap::new();

                fields.insert("version", FieldValue::UInt8(4));
                fields.insert("ihl", FieldValue::UInt8(ipv4.ihl()));
                fields.insert("dscp", FieldValue::UInt8(ipv4.dcp().value()));
                fields.insert("ecn", FieldValue::UInt8(ipv4.ecn().value()));
                fields.insert("total_length", FieldValue::UInt16(ipv4.total_len()));
                fields.insert("identification", FieldValue::UInt16(ipv4.identification()));
                fields.insert("dont_fragment", FieldValue::Bool(ipv4.dont_fragment()));
                fields.insert("more_fragments", FieldValue::Bool(ipv4.more_fragments()));
                fields.insert("fragment_offset", FieldValue::UInt16(ipv4.fragments_offset().value()));
                fields.insert("ttl", FieldValue::UInt8(ipv4.ttl()));
                fields.insert("protocol", FieldValue::UInt8(ipv4.protocol().0));
                fields.insert("checksum", FieldValue::UInt16(ipv4.header_checksum()));
                fields.insert("src_ip", FieldValue::ipv4(&ipv4.source()));
                fields.insert("dst_ip", FieldValue::ipv4(&ipv4.destination()));

                let mut child_hints = HashMap::new();
                child_hints.insert("ip_protocol", ipv4.protocol().0 as u64);
                child_hints.insert("ip_version", 4);

                let header_len = ipv4.slice().len();
                ParseResult::success(fields, &data[header_len..], child_hints)
            }
            Err(e) => ParseResult::error(format!("IPv4 parse error: {e}"), data),
        }
    }

    fn schema_fields(&self) -> Vec<Field> {
        vec![
            Field::new("ipv4.version", DataType::UInt8, true),
            Field::new("ipv4.ihl", DataType::UInt8, true),
            Field::new("ipv4.dscp", DataType::UInt8, true),
            Field::new("ipv4.ecn", DataType::UInt8, true),
            Field::new("ipv4.total_length", DataType::UInt16, true),
            Field::new("ipv4.identification", DataType::UInt16, true),
            Field::new("ipv4.dont_fragment", DataType::Boolean, true),
            Field::new("ipv4.more_fragments", DataType::Boolean, true),
            Field::new("ipv4.fragment_offset", DataType::UInt16, true),
            Field::new("ipv4.ttl", DataType::UInt8, true),
            Field::new("ipv4.protocol", DataType::UInt8, true),
            Field::new("ipv4.checksum", DataType::UInt16, true),
            Field::new("ipv4.src_ip", DataType::Utf8, true),
            Field::new("ipv4.dst_ip", DataType::Utf8, true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        &["tcp", "udp", "icmp"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_parse_ipv4() {
        // Minimal IPv4 header (20 bytes) with TCP protocol
        let header = [
            0x45, // Version (4) + IHL (5)
            0x00, // DSCP + ECN
            0x00, 0x28, // Total length: 40
            0x00, 0x01, // Identification
            0x00, 0x00, // Flags + Fragment offset
            0x40, // TTL: 64
            0x06, // Protocol: TCP (6)
            0x00, 0x00, // Checksum (not validated)
            0xc0, 0xa8, 0x01, 0x01, // Src: 192.168.1.1
            0xc0, 0xa8, 0x01, 0x02, // Dst: 192.168.1.2
        ];

        let parser = Ipv4Protocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ethertype", 0x0800);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("ttl"), Some(&FieldValue::UInt8(64)));
        assert_eq!(result.get("protocol"), Some(&FieldValue::UInt8(6)));
        assert_eq!(result.child_hints.get("ip_protocol"), Some(&6u64));
    }

    #[test]
    fn test_parse_ipv4_udp() {
        let header = [
            0x45, // Version (4) + IHL (5)
            0x00, // DSCP + ECN
            0x00, 0x1c, // Total length: 28
            0x12, 0x34, // Identification
            0x40, 0x00, // Don't fragment, offset 0
            0x80, // TTL: 128
            0x11, // Protocol: UDP (17)
            0x00, 0x00, // Checksum
            0x0a, 0x00, 0x00, 0x01, // Src: 10.0.0.1
            0x0a, 0x00, 0x00, 0x02, // Dst: 10.0.0.2
        ];

        let parser = Ipv4Protocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ethertype", 0x0800);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("ttl"), Some(&FieldValue::UInt8(128)));
        assert_eq!(result.get("protocol"), Some(&FieldValue::UInt8(17)));
        assert_eq!(result.get("dont_fragment"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.child_hints.get("ip_protocol"), Some(&17u64));
    }

    #[test]
    fn test_parse_ipv4_icmp() {
        let header = [
            0x45, // Version (4) + IHL (5)
            0x00, // DSCP + ECN
            0x00, 0x54, // Total length: 84
            0x00, 0x00, // Identification
            0x00, 0x00, // Flags + Fragment offset
            0x40, // TTL: 64
            0x01, // Protocol: ICMP (1)
            0x00, 0x00, // Checksum
            0x08, 0x08, 0x08, 0x08, // Src: 8.8.8.8
            0xc0, 0xa8, 0x01, 0x01, // Dst: 192.168.1.1
        ];

        let parser = Ipv4Protocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ethertype", 0x0800);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("protocol"), Some(&FieldValue::UInt8(1)));
        assert_eq!(result.child_hints.get("ip_protocol"), Some(&1u64));
    }

    #[test]
    fn test_parse_ipv4_with_payload() {
        let packet = [
            0x45, // Version (4) + IHL (5)
            0x00, // DSCP + ECN
            0x00, 0x28, // Total length: 40
            0x00, 0x01, // Identification
            0x00, 0x00, // Flags + Fragment offset
            0x40, // TTL: 64
            0x06, // Protocol: TCP
            0x00, 0x00, // Checksum
            0xc0, 0xa8, 0x01, 0x01, // Src
            0xc0, 0xa8, 0x01, 0x02, // Dst
            // TCP header (payload)
            0x00, 0x50, 0x1f, 0x90, 0x00, 0x00, 0x00, 0x01,
        ];

        let parser = Ipv4Protocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ethertype", 0x0800);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.remaining.len(), 8); // TCP header bytes
    }

    #[test]
    fn test_can_parse_ipv4() {
        let parser = Ipv4Protocol;

        // Without hint
        let ctx1 = ParseContext::new(1);
        assert!(parser.can_parse(&ctx1).is_none());

        // With IPv6 ethertype
        let mut ctx2 = ParseContext::new(1);
        ctx2.hints.insert("ethertype", 0x86DD);
        assert!(parser.can_parse(&ctx2).is_none());

        // With IPv4 ethertype
        let mut ctx3 = ParseContext::new(1);
        ctx3.hints.insert("ethertype", 0x0800);
        assert!(parser.can_parse(&ctx3).is_some());
    }

    #[test]
    fn test_parse_ipv4_too_short() {
        let short_header = [0x45, 0x00, 0x00, 0x28]; // Only 4 bytes

        let parser = Ipv4Protocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ethertype", 0x0800);

        let result = parser.parse(&short_header, &context);

        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }

    #[test]
    fn test_ipv4_ip_addresses() {
        let header = [
            0x45, 0x00, 0x00, 0x14, // Version, IHL, Length
            0x00, 0x00, 0x00, 0x00, // ID, Flags, Offset
            0x40, 0x06, 0x00, 0x00, // TTL, Protocol, Checksum
            0x7f, 0x00, 0x00, 0x01, // Src: 127.0.0.1
            0x0a, 0x0b, 0x0c, 0x0d, // Dst: 10.11.12.13
        ];

        let parser = Ipv4Protocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ethertype", 0x0800);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("src_ip"),
            Some(&FieldValue::IpAddr(IpAddr::V4(
                "127.0.0.1".parse().unwrap()
            )))
        );
        assert_eq!(
            result.get("dst_ip"),
            Some(&FieldValue::IpAddr(IpAddr::V4(
                "10.11.12.13".parse().unwrap()
            )))
        );
    }

    #[test]
    fn test_ipv4_fragment_flags() {
        let header = [
            0x45, 0x00, 0x00, 0x14, // Version, IHL, Length
            0x12, 0x34, // Identification
            0x20, 0x00, // More fragments flag set
            0x40, 0x06, 0x00, 0x00, // TTL, Protocol, Checksum
            0xc0, 0xa8, 0x01, 0x01, // Src
            0xc0, 0xa8, 0x01, 0x02, // Dst
        ];

        let parser = Ipv4Protocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ethertype", 0x0800);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("more_fragments"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("dont_fragment"), Some(&FieldValue::Bool(false)));
        assert_eq!(result.get("identification"), Some(&FieldValue::UInt16(0x1234)));
    }

    #[test]
    fn test_ipv4_child_hints() {
        let header = [
            0x45, 0x00, 0x00, 0x14,
            0x00, 0x00, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00, // Protocol: TCP (6)
            0xc0, 0xa8, 0x01, 0x01,
            0xc0, 0xa8, 0x01, 0x02,
        ];

        let parser = Ipv4Protocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ethertype", 0x0800);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.child_hints.get("ip_protocol"), Some(&6u64));
        assert_eq!(result.child_hints.get("ip_version"), Some(&4u64));
    }
}
