//! ICMP protocol parser.

use smallvec::SmallVec;

use super::{FieldValue, ParseContext, ParseResult, Protocol};
use crate::schema::{DataKind, FieldDescriptor};

/// IP protocol number for ICMP.
pub const IP_PROTO_ICMP: u8 = 1;

/// ICMP type constants.
pub mod icmp_type {
    pub const ECHO_REPLY: u8 = 0;
    pub const DESTINATION_UNREACHABLE: u8 = 3;
    pub const SOURCE_QUENCH: u8 = 4;
    pub const REDIRECT: u8 = 5;
    pub const ECHO_REQUEST: u8 = 8;
    pub const TIME_EXCEEDED: u8 = 11;
    pub const PARAMETER_PROBLEM: u8 = 12;
    pub const TIMESTAMP_REQUEST: u8 = 13;
    pub const TIMESTAMP_REPLY: u8 = 14;
}

/// ICMP protocol parser.
#[derive(Debug, Clone, Copy)]
pub struct IcmpProtocol;

impl Protocol for IcmpProtocol {
    fn name(&self) -> &'static str {
        "icmp"
    }

    fn display_name(&self) -> &'static str {
        "ICMP"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        match context.hint("ip_protocol") {
            Some(proto) if proto == IP_PROTO_ICMP as u64 => Some(100),
            _ => None,
        }
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        // ICMP header is at least 8 bytes
        if data.len() < 8 {
            return ParseResult::error(
                format!("ICMP header too short: {} bytes", data.len()),
                data,
            );
        }

        let mut fields = SmallVec::new();

        let icmp_type = data[0];
        let icmp_code = data[1];
        let checksum = u16::from_be_bytes([data[2], data[3]]);

        fields.push(("type", FieldValue::UInt8(icmp_type)));
        fields.push(("code", FieldValue::UInt8(icmp_code)));
        fields.push(("checksum", FieldValue::UInt16(checksum)));

        // Type-specific fields (bytes 4-7)
        match icmp_type {
            icmp_type::ECHO_REQUEST | icmp_type::ECHO_REPLY => {
                let identifier = u16::from_be_bytes([data[4], data[5]]);
                let sequence = u16::from_be_bytes([data[6], data[7]]);
                fields.push(("identifier", FieldValue::UInt16(identifier)));
                fields.push(("sequence", FieldValue::UInt16(sequence)));
            }
            icmp_type::DESTINATION_UNREACHABLE => {
                // Next-hop MTU for "fragmentation needed" (code 4)
                if icmp_code == 4 && data.len() >= 8 {
                    let mtu = u16::from_be_bytes([data[6], data[7]]);
                    fields.push(("next_hop_mtu", FieldValue::UInt16(mtu)));
                }
            }
            icmp_type::REDIRECT => {
                if data.len() >= 8 {
                    fields.push(("gateway", FieldValue::ipv4(&data[4..8])));
                }
            }
            _ => {
                // Store the 4 bytes as a generic field
                let rest = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                fields.push(("rest_of_header", FieldValue::UInt32(rest)));
            }
        }

        // Add type name for convenience
        let type_name = match icmp_type {
            icmp_type::ECHO_REPLY => "Echo Reply",
            icmp_type::DESTINATION_UNREACHABLE => "Destination Unreachable",
            icmp_type::SOURCE_QUENCH => "Source Quench",
            icmp_type::REDIRECT => "Redirect",
            icmp_type::ECHO_REQUEST => "Echo Request",
            icmp_type::TIME_EXCEEDED => "Time Exceeded",
            icmp_type::PARAMETER_PROBLEM => "Parameter Problem",
            icmp_type::TIMESTAMP_REQUEST => "Timestamp Request",
            icmp_type::TIMESTAMP_REPLY => "Timestamp Reply",
            _ => "Unknown",
        };
        fields.push(("type_name", FieldValue::String(type_name.to_string())));

        // ICMP doesn't have child protocols typically
        ParseResult::success(fields, &data[8..], SmallVec::new())
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            FieldDescriptor::new("icmp.type", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("icmp.code", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("icmp.checksum", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("icmp.type_name", DataKind::String).set_nullable(true),
            FieldDescriptor::new("icmp.identifier", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("icmp.sequence", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("icmp.next_hop_mtu", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("icmp.gateway", DataKind::String).set_nullable(true),
        ]
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &["ipv4"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_icmp_echo_request() {
        // ICMP Echo Request
        let header = [
            0x08, // Type: Echo Request
            0x00, // Code: 0
            0x00, 0x00, // Checksum
            0x00, 0x01, // Identifier: 1
            0x00, 0x02, // Sequence: 2
        ];

        let parser = IcmpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 1);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("type"), Some(&FieldValue::UInt8(8)));
        assert_eq!(result.get("identifier"), Some(&FieldValue::UInt16(1)));
        assert_eq!(result.get("sequence"), Some(&FieldValue::UInt16(2)));
        assert_eq!(
            result.get("type_name"),
            Some(&FieldValue::String("Echo Request".to_string()))
        );
    }

    #[test]
    fn test_parse_icmp_echo_reply() {
        let header = [
            0x00, // Type: Echo Reply
            0x00, // Code: 0
            0xab, 0xcd, // Checksum
            0x12, 0x34, // Identifier: 0x1234
            0x00, 0x0a, // Sequence: 10
        ];

        let parser = IcmpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 1);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("type"),
            Some(&FieldValue::UInt8(icmp_type::ECHO_REPLY))
        );
        assert_eq!(result.get("identifier"), Some(&FieldValue::UInt16(0x1234)));
        assert_eq!(result.get("sequence"), Some(&FieldValue::UInt16(10)));
        assert_eq!(
            result.get("type_name"),
            Some(&FieldValue::String("Echo Reply".to_string()))
        );
    }

    #[test]
    fn test_parse_icmp_destination_unreachable() {
        let header = [
            0x03, // Type: Destination Unreachable
            0x01, // Code: Host Unreachable
            0x00, 0x00, // Checksum
            0x00, 0x00, 0x00, 0x00, // Unused
        ];

        let parser = IcmpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 1);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("type"),
            Some(&FieldValue::UInt8(icmp_type::DESTINATION_UNREACHABLE))
        );
        assert_eq!(result.get("code"), Some(&FieldValue::UInt8(1)));
        assert_eq!(
            result.get("type_name"),
            Some(&FieldValue::String("Destination Unreachable".to_string()))
        );
    }

    #[test]
    fn test_parse_icmp_time_exceeded() {
        let header = [
            0x0b, // Type: Time Exceeded
            0x00, // Code: TTL exceeded
            0x00, 0x00, // Checksum
            0x00, 0x00, 0x00, 0x00, // Unused
        ];

        let parser = IcmpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 1);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("type"),
            Some(&FieldValue::UInt8(icmp_type::TIME_EXCEEDED))
        );
        assert_eq!(
            result.get("type_name"),
            Some(&FieldValue::String("Time Exceeded".to_string()))
        );
    }

    #[test]
    fn test_can_parse_icmp() {
        let parser = IcmpProtocol;

        // Without hint
        let ctx1 = ParseContext::new(1);
        assert!(parser.can_parse(&ctx1).is_none());

        // With TCP protocol
        let mut ctx2 = ParseContext::new(1);
        ctx2.insert_hint("ip_protocol", 6);
        assert!(parser.can_parse(&ctx2).is_none());

        // With ICMP protocol
        let mut ctx3 = ParseContext::new(1);
        ctx3.insert_hint("ip_protocol", 1);
        assert!(parser.can_parse(&ctx3).is_some());
    }

    #[test]
    fn test_parse_icmp_too_short() {
        let short_header = [0x08, 0x00, 0x00]; // Only 3 bytes

        let parser = IcmpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 1);

        let result = parser.parse(&short_header, &context);

        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }

    #[test]
    fn test_icmp_with_payload() {
        let packet = [
            0x08, // Type: Echo Request
            0x00, // Code: 0
            0x00, 0x00, // Checksum
            0x00, 0x01, // Identifier
            0x00, 0x01, // Sequence
            // Payload data
            0xde, 0xad, 0xbe, 0xef,
        ];

        let parser = IcmpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 1);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.remaining.len(), 4); // Payload bytes
    }
}
