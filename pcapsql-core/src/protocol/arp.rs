//! ARP protocol parser.

use smallvec::SmallVec;

use super::ethernet::ethertype;
use super::{FieldValue, ParseContext, ParseResult, Protocol};
use crate::schema::{DataKind, FieldDescriptor};

/// ARP operation codes.
pub mod operation {
    pub const REQUEST: u16 = 1;
    pub const REPLY: u16 = 2;
}

/// ARP protocol parser.
#[derive(Debug, Clone, Copy)]
pub struct ArpProtocol;

impl Protocol for ArpProtocol {
    fn name(&self) -> &'static str {
        "arp"
    }

    fn display_name(&self) -> &'static str {
        "ARP"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        match context.hint("ethertype") {
            Some(et) if et == ethertype::ARP as u64 => Some(100),
            _ => None,
        }
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        // ARP for Ethernet/IPv4 is 28 bytes
        if data.len() < 28 {
            return ParseResult::error(format!("ARP packet too short: {} bytes", data.len()), data);
        }

        let mut fields = SmallVec::new();

        let hardware_type = u16::from_be_bytes([data[0], data[1]]);
        let protocol_type = u16::from_be_bytes([data[2], data[3]]);
        let hardware_size = data[4];
        let protocol_size = data[5];
        let operation = u16::from_be_bytes([data[6], data[7]]);

        fields.push(("hardware_type", FieldValue::UInt16(hardware_type)));
        fields.push(("protocol_type", FieldValue::UInt16(protocol_type)));
        fields.push(("hardware_size", FieldValue::UInt8(hardware_size)));
        fields.push(("protocol_size", FieldValue::UInt8(protocol_size)));
        fields.push(("operation", FieldValue::UInt16(operation)));

        // Operation name for convenience (zero-copy static string)
        let operation_name = match operation {
            operation::REQUEST => "Request",
            operation::REPLY => "Reply",
            _ => "Unknown",
        };
        fields.push(("operation_name", FieldValue::Str(operation_name)));

        // For Ethernet/IPv4 ARP (most common case)
        if hardware_type == 1
            && protocol_type == ethertype::IPV4
            && hardware_size == 6
            && protocol_size == 4
        {
            fields.push(("sender_mac", FieldValue::mac(&data[8..14])));
            fields.push(("sender_ip", FieldValue::ipv4(&data[14..18])));
            fields.push(("target_mac", FieldValue::mac(&data[18..24])));
            fields.push(("target_ip", FieldValue::ipv4(&data[24..28])));
        }

        // ARP doesn't have payload protocols
        ParseResult::success(fields, &data[28..], SmallVec::new())
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            FieldDescriptor::new("arp.hardware_type", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("arp.protocol_type", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("arp.hardware_size", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("arp.protocol_size", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("arp.operation", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("arp.operation_name", DataKind::String).set_nullable(true),
            FieldDescriptor::mac_field("arp.sender_mac").set_nullable(true),
            FieldDescriptor::new("arp.sender_ip", DataKind::String).set_nullable(true),
            FieldDescriptor::mac_field("arp.target_mac").set_nullable(true),
            FieldDescriptor::new("arp.target_ip", DataKind::String).set_nullable(true),
        ]
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &["ethernet", "vlan"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_parse_arp_request() {
        // ARP Request for 192.168.1.2 from 192.168.1.1
        let packet = [
            0x00, 0x01, // Hardware type: Ethernet
            0x08, 0x00, // Protocol type: IPv4
            0x06, // Hardware size: 6
            0x04, // Protocol size: 4
            0x00, 0x01, // Operation: Request
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Sender MAC
            0xc0, 0xa8, 0x01, 0x01, // Sender IP: 192.168.1.1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC (unknown)
            0xc0, 0xa8, 0x01, 0x02, // Target IP: 192.168.1.2
        ];

        let parser = ArpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ethertype", ethertype::ARP as u64);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("operation"), Some(&FieldValue::UInt16(1)));
        assert_eq!(
            result.get("sender_ip"),
            Some(&FieldValue::IpAddr(IpAddr::V4(
                "192.168.1.1".parse().unwrap()
            )))
        );
        assert_eq!(
            result.get("operation_name"),
            Some(&FieldValue::Str("Request"))
        );
    }

    #[test]
    fn test_parse_arp_reply() {
        let packet = [
            0x00, 0x01, // Hardware type: Ethernet
            0x08, 0x00, // Protocol type: IPv4
            0x06, // Hardware size: 6
            0x04, // Protocol size: 4
            0x00, 0x02, // Operation: Reply
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Sender MAC
            0x0a, 0x00, 0x00, 0x01, // Sender IP: 10.0.0.1
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Target MAC
            0x0a, 0x00, 0x00, 0x02, // Target IP: 10.0.0.2
        ];

        let parser = ArpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ethertype", ethertype::ARP as u64);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("operation"),
            Some(&FieldValue::UInt16(operation::REPLY))
        );
        assert_eq!(
            result.get("operation_name"),
            Some(&FieldValue::Str("Reply"))
        );
        assert_eq!(
            result.get("sender_ip"),
            Some(&FieldValue::IpAddr(IpAddr::V4("10.0.0.1".parse().unwrap())))
        );
        assert_eq!(
            result.get("target_ip"),
            Some(&FieldValue::IpAddr(IpAddr::V4("10.0.0.2".parse().unwrap())))
        );
    }

    #[test]
    fn test_can_parse_arp() {
        let parser = ArpProtocol;

        // Without hint
        let ctx1 = ParseContext::new(1);
        assert!(parser.can_parse(&ctx1).is_none());

        // With IPv4 ethertype
        let mut ctx2 = ParseContext::new(1);
        ctx2.insert_hint("ethertype", ethertype::IPV4 as u64);
        assert!(parser.can_parse(&ctx2).is_none());

        // With ARP ethertype
        let mut ctx3 = ParseContext::new(1);
        ctx3.insert_hint("ethertype", ethertype::ARP as u64);
        assert!(parser.can_parse(&ctx3).is_some());
    }

    #[test]
    fn test_parse_arp_too_short() {
        let short_packet = [0x00, 0x01, 0x08, 0x00]; // Only 4 bytes

        let parser = ArpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ethertype", ethertype::ARP as u64);

        let result = parser.parse(&short_packet, &context);

        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }

    #[test]
    fn test_arp_hardware_and_protocol_types() {
        let packet = [
            0x00, 0x01, // Hardware type: Ethernet (1)
            0x08, 0x00, // Protocol type: IPv4 (0x0800)
            0x06, // Hardware size: 6
            0x04, // Protocol size: 4
            0x00, 0x01, // Operation: Request
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Sender MAC
            0xc0, 0xa8, 0x01, 0x01, // Sender IP
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC
            0xc0, 0xa8, 0x01, 0x02, // Target IP
        ];

        let parser = ArpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ethertype", ethertype::ARP as u64);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("hardware_type"), Some(&FieldValue::UInt16(1)));
        assert_eq!(
            result.get("protocol_type"),
            Some(&FieldValue::UInt16(ethertype::IPV4))
        );
        assert_eq!(result.get("hardware_size"), Some(&FieldValue::UInt8(6)));
        assert_eq!(result.get("protocol_size"), Some(&FieldValue::UInt8(4)));
    }

    #[test]
    fn test_arp_no_payload() {
        let packet = [
            0x00, 0x01, // Hardware type: Ethernet
            0x08, 0x00, // Protocol type: IPv4
            0x06, // Hardware size: 6
            0x04, // Protocol size: 4
            0x00, 0x01, // Operation: Request
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Sender MAC
            0xc0, 0xa8, 0x01, 0x01, // Sender IP
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC
            0xc0, 0xa8, 0x01, 0x02, // Target IP
        ];

        let parser = ArpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ethertype", ethertype::ARP as u64);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        // ARP doesn't have child protocols
        assert!(result.child_hints.is_empty());
        assert!(result.remaining.is_empty());
    }
}
