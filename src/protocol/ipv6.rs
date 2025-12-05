//! IPv6 protocol parser.

use std::collections::HashMap;

use arrow::datatypes::{DataType, Field};
use etherparse::Ipv6HeaderSlice;

use super::ethernet::ethertype;
use super::{FieldValue, ParseContext, ParseResult, Protocol};

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
                let mut fields = HashMap::new();

                fields.insert("version", FieldValue::UInt8(6));
                fields.insert("traffic_class", FieldValue::UInt8(ipv6.traffic_class()));
                fields.insert("flow_label", FieldValue::UInt32(ipv6.flow_label().value()));
                fields.insert("payload_length", FieldValue::UInt16(ipv6.payload_length()));
                fields.insert("next_header", FieldValue::UInt8(ipv6.next_header().0));
                fields.insert("hop_limit", FieldValue::UInt8(ipv6.hop_limit()));
                fields.insert("src_ip", FieldValue::ipv6(&ipv6.source()));
                fields.insert("dst_ip", FieldValue::ipv6(&ipv6.destination()));

                let mut child_hints = HashMap::new();
                child_hints.insert("ip_protocol", ipv6.next_header().0 as u64);
                child_hints.insert("ip_version", 6);

                let header_len = ipv6.slice().len();
                ParseResult::success(fields, &data[header_len..], child_hints)
            }
            Err(e) => ParseResult::error(format!("IPv6 parse error: {e}"), data),
        }
    }

    fn schema_fields(&self) -> Vec<Field> {
        vec![
            Field::new("ipv6.version", DataType::UInt8, true),
            Field::new("ipv6.traffic_class", DataType::UInt8, true),
            Field::new("ipv6.flow_label", DataType::UInt32, true),
            Field::new("ipv6.payload_length", DataType::UInt16, true),
            Field::new("ipv6.next_header", DataType::UInt8, true),
            Field::new("ipv6.hop_limit", DataType::UInt8, true),
            Field::new("ipv6.src_ip", DataType::Utf8, true),
            Field::new("ipv6.dst_ip", DataType::Utf8, true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        &["tcp", "udp", "icmpv6"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv6() {
        // IPv6 header (40 bytes) with TCP next header
        let header = [
            0x60, 0x00, 0x00, 0x00, // Version (6) + Traffic class + Flow label
            0x00, 0x14, // Payload length: 20
            0x06, // Next header: TCP
            0x40, // Hop limit: 64
            // Source: 2001:db8::1
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            // Destination: 2001:db8::2
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ];

        let parser = Ipv6Protocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ethertype", 0x86DD);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("version"), Some(&FieldValue::UInt8(6)));
        assert_eq!(result.get("hop_limit"), Some(&FieldValue::UInt8(64)));
        assert_eq!(result.get("next_header"), Some(&FieldValue::UInt8(6)));
        assert_eq!(result.child_hints.get("ip_protocol"), Some(&6u64));
        assert_eq!(result.child_hints.get("ip_version"), Some(&6u64));
    }

    #[test]
    fn test_can_parse_with_ipv6_ethertype() {
        let parser = Ipv6Protocol;
        let mut context = ParseContext::new(1);

        // Without ethertype hint
        assert!(parser.can_parse(&context).is_none());

        // With IPv4 ethertype
        context.hints.insert("ethertype", 0x0800);
        assert!(parser.can_parse(&context).is_none());

        // With IPv6 ethertype
        context.hints.insert("ethertype", 0x86DD);
        assert!(parser.can_parse(&context).is_some());
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
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            // Destination: ::1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];

        let parser = Ipv6Protocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ethertype", 0x86DD);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("next_header"), Some(&FieldValue::UInt8(17)));
        assert_eq!(result.get("hop_limit"), Some(&FieldValue::UInt8(128)));
        assert_eq!(result.child_hints.get("ip_protocol"), Some(&17u64));
    }

    #[test]
    fn test_parse_ipv6_too_short() {
        let short_data = [0x60, 0x00, 0x00, 0x00]; // Only 4 bytes

        let parser = Ipv6Protocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ethertype", 0x86DD);

        let result = parser.parse(&short_data, &context);

        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }
}
