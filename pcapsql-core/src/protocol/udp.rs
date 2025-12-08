//! UDP protocol parser.

use std::collections::HashSet;

use smallvec::SmallVec;

use etherparse::UdpHeaderSlice;

use super::{FieldValue, ParseContext, ParseResult, Protocol};
use crate::schema::{DataKind, FieldDescriptor};

/// IP protocol number for UDP.
pub const IP_PROTO_UDP: u8 = 17;

/// UDP protocol parser.
#[derive(Debug, Clone, Copy)]
pub struct UdpProtocol;

impl Protocol for UdpProtocol {
    fn name(&self) -> &'static str {
        "udp"
    }

    fn display_name(&self) -> &'static str {
        "UDP"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        match context.hint("ip_protocol") {
            Some(proto) if proto == IP_PROTO_UDP as u64 => Some(100),
            _ => None,
        }
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        match UdpHeaderSlice::from_slice(data) {
            Ok(udp) => {
                let mut fields = SmallVec::new();

                fields.push(("src_port", FieldValue::UInt16(udp.source_port())));
                fields.push(("dst_port", FieldValue::UInt16(udp.destination_port())));
                fields.push(("length", FieldValue::UInt16(udp.length())));
                fields.push(("checksum", FieldValue::UInt16(udp.checksum())));

                let mut child_hints = SmallVec::new();
                child_hints.push(("src_port", udp.source_port() as u64));
                child_hints.push(("dst_port", udp.destination_port() as u64));
                child_hints.push(("transport", 17)); // UDP

                // UDP header is always 8 bytes
                ParseResult::success(fields, &data[8..], child_hints)
            }
            Err(e) => ParseResult::error(format!("UDP parse error: {e}"), data),
        }
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            FieldDescriptor::new("udp.src_port", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("udp.dst_port", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("udp.length", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("udp.checksum", DataKind::UInt16).set_nullable(true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        &["dns", "dhcp", "ntp"]
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &["ipv4", "ipv6"]
    }

    fn parse_projected<'a>(
        &self,
        data: &'a [u8],
        _context: &ParseContext,
        fields: Option<&HashSet<String>>,
    ) -> ParseResult<'a> {
        // If no projection, use full parse
        let fields = match fields {
            None => return self.parse(data, _context),
            Some(f) if f.is_empty() => return self.parse(data, _context),
            Some(f) => f,
        };

        match UdpHeaderSlice::from_slice(data) {
            Ok(udp) => {
                let mut result_fields = SmallVec::new();

                // Always extract ports for child hints
                let src_port = udp.source_port();
                let dst_port = udp.destination_port();

                // Only insert requested fields
                if fields.contains("src_port") {
                    result_fields.push(("src_port", FieldValue::UInt16(src_port)));
                }
                if fields.contains("dst_port") {
                    result_fields.push(("dst_port", FieldValue::UInt16(dst_port)));
                }
                if fields.contains("length") {
                    result_fields.push(("length", FieldValue::UInt16(udp.length())));
                }
                if fields.contains("checksum") {
                    result_fields.push(("checksum", FieldValue::UInt16(udp.checksum())));
                }

                let mut child_hints = SmallVec::new();
                child_hints.push(("src_port", src_port as u64));
                child_hints.push(("dst_port", dst_port as u64));
                child_hints.push(("transport", 17)); // UDP

                // UDP header is always 8 bytes
                ParseResult::success(result_fields, &data[8..], child_hints)
            }
            Err(e) => ParseResult::error(format!("UDP parse error: {e}"), data),
        }
    }

    fn cheap_fields(&self) -> &'static [&'static str] {
        // All UDP fields come from the fixed 8-byte header
        &["src_port", "dst_port", "length", "checksum"]
    }

    fn expensive_fields(&self) -> &'static [&'static str] {
        // UDP has no expensive fields
        &[]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_udp() {
        // UDP header (8 bytes)
        let header = [
            0x00, 0x35, // Src port: 53 (DNS)
            0xc0, 0x00, // Dst port: 49152
            0x00, 0x20, // Length: 32
            0x00, 0x00, // Checksum
            // Payload would follow
            0xde, 0xad, 0xbe, 0xef,
        ];

        let parser = UdpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 17);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("src_port"), Some(&FieldValue::UInt16(53)));
        assert_eq!(result.get("dst_port"), Some(&FieldValue::UInt16(49152)));
        assert_eq!(result.get("length"), Some(&FieldValue::UInt16(32)));
        assert_eq!(result.remaining.len(), 4); // Payload bytes
    }

    #[test]
    fn test_parse_udp_dns_query() {
        let header = [
            0xc3, 0x50, // Src port: 50000
            0x00, 0x35, // Dst port: 53 (DNS)
            0x00, 0x1c, // Length: 28
            0xab, 0xcd, // Checksum
            // DNS query payload (simplified)
            0x12, 0x34, 0x01, 0x00,
        ];

        let parser = UdpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 17);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("src_port"), Some(&FieldValue::UInt16(50000)));
        assert_eq!(result.get("dst_port"), Some(&FieldValue::UInt16(53)));
        assert_eq!(result.hint("dst_port"), Some(53u64));
    }

    #[test]
    fn test_parse_udp_dhcp() {
        let header = [
            0x00, 0x44, // Src port: 68 (DHCP client)
            0x00, 0x43, // Dst port: 67 (DHCP server)
            0x01, 0x00, // Length: 256
            0x00, 0x00, // Checksum
        ];

        let parser = UdpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 17);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("src_port"), Some(&FieldValue::UInt16(68)));
        assert_eq!(result.get("dst_port"), Some(&FieldValue::UInt16(67)));
    }

    #[test]
    fn test_can_parse_udp() {
        let parser = UdpProtocol;

        // Without hint
        let ctx1 = ParseContext::new(1);
        assert!(parser.can_parse(&ctx1).is_none());

        // With TCP protocol
        let mut ctx2 = ParseContext::new(1);
        ctx2.insert_hint("ip_protocol", 6);
        assert!(parser.can_parse(&ctx2).is_none());

        // With UDP protocol
        let mut ctx3 = ParseContext::new(1);
        ctx3.insert_hint("ip_protocol", 17);
        assert!(parser.can_parse(&ctx3).is_some());
    }

    #[test]
    fn test_parse_udp_too_short() {
        let short_header = [0x00, 0x35, 0xc0, 0x00]; // Only 4 bytes

        let parser = UdpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 17);

        let result = parser.parse(&short_header, &context);

        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }

    #[test]
    fn test_udp_child_hints() {
        let header = [
            0x12, 0x34, // Src port: 4660
            0x56, 0x78, // Dst port: 22136
            0x00, 0x10, // Length: 16
            0x00, 0x00, // Checksum
        ];

        let parser = UdpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 17);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.hint("src_port"), Some(4660u64));
        assert_eq!(result.hint("dst_port"), Some(22136u64));
        assert_eq!(result.hint("transport"), Some(17u64));
    }

    #[test]
    fn test_udp_minimal_header() {
        // Exactly 8 bytes (minimum valid UDP)
        let header = [
            0x00, 0x50, // Src port: 80
            0x00, 0x51, // Dst port: 81
            0x00, 0x08, // Length: 8 (header only)
            0x00, 0x00, // Checksum
        ];

        let parser = UdpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 17);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("length"), Some(&FieldValue::UInt16(8)));
        assert!(result.remaining.is_empty());
    }

    #[test]
    fn test_udp_projected_parsing_ports_only() {
        let header = [
            0x00, 0x35, // Src port: 53 (DNS)
            0xc0, 0x00, // Dst port: 49152
            0x00, 0x20, // Length: 32
            0xab, 0xcd, // Checksum
        ];

        let parser = UdpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 17);

        // Project to only ports
        let fields: HashSet<String> = ["src_port", "dst_port"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let result = parser.parse_projected(&header, &context, Some(&fields));

        assert!(result.is_ok());
        // Requested fields are present
        assert_eq!(result.get("src_port"), Some(&FieldValue::UInt16(53)));
        assert_eq!(result.get("dst_port"), Some(&FieldValue::UInt16(49152)));
        // Unrequested fields are NOT present
        assert!(result.get("length").is_none());
        assert!(result.get("checksum").is_none());
        // Child hints are still populated
        assert_eq!(result.hint("src_port"), Some(53u64));
        assert_eq!(result.hint("dst_port"), Some(49152u64));
    }
}
