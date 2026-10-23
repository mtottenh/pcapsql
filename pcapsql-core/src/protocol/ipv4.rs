//! IPv4 protocol parser.

use smallvec::SmallVec;

use etherparse::Ipv4HeaderSlice;

use super::ethernet::ethertype;
use super::{FieldValue, ParseContext, ParseResult, Protocol, TunnelType};
use crate::schema::{DataKind, FieldDescriptor};

/// IP protocol numbers for IP-in-IP encapsulation.
mod ip_in_ip_protocol {
    /// IPv4 encapsulated in IP (IPIP)
    pub const IPIP: u8 = 4;
    /// IPv6 encapsulated in IP
    pub const IPV6_IN_IP: u8 = 41;
}

/// Differentiated Services Code Point (DSCP) values.
///
/// DSCP is a 6-bit field in the IP header that enables Quality of Service (QoS)
/// classification. Values are defined in RFC 2474, RFC 2597 (AF), RFC 3246 (EF),
/// RFC 5865 (VA), and RFC 8622 (LE).
pub mod dscp {
    // Class Selector (CS) - RFC 2474
    /// Best Effort / Default (CS0) - DSCP 0
    pub const CS0: u8 = 0;
    /// Class Selector 1 - DSCP 8
    pub const CS1: u8 = 8;
    /// Class Selector 2 - DSCP 16
    pub const CS2: u8 = 16;
    /// Class Selector 3 - DSCP 24
    pub const CS3: u8 = 24;
    /// Class Selector 4 - DSCP 32
    pub const CS4: u8 = 32;
    /// Class Selector 5 - DSCP 40
    pub const CS5: u8 = 40;
    /// Class Selector 6 - DSCP 48
    pub const CS6: u8 = 48;
    /// Class Selector 7 - DSCP 56
    pub const CS7: u8 = 56;

    // Assured Forwarding (AF) - RFC 2597
    // AFxy where x=class (1-4), y=drop precedence (1-3)
    /// Assured Forwarding 11 (low drop) - DSCP 10
    pub const AF11: u8 = 10;
    /// Assured Forwarding 12 (medium drop) - DSCP 12
    pub const AF12: u8 = 12;
    /// Assured Forwarding 13 (high drop) - DSCP 14
    pub const AF13: u8 = 14;
    /// Assured Forwarding 21 (low drop) - DSCP 18
    pub const AF21: u8 = 18;
    /// Assured Forwarding 22 (medium drop) - DSCP 20
    pub const AF22: u8 = 20;
    /// Assured Forwarding 23 (high drop) - DSCP 22
    pub const AF23: u8 = 22;
    /// Assured Forwarding 31 (low drop) - DSCP 26
    pub const AF31: u8 = 26;
    /// Assured Forwarding 32 (medium drop) - DSCP 28
    pub const AF32: u8 = 28;
    /// Assured Forwarding 33 (high drop) - DSCP 30
    pub const AF33: u8 = 30;
    /// Assured Forwarding 41 (low drop) - DSCP 34
    pub const AF41: u8 = 34;
    /// Assured Forwarding 42 (medium drop) - DSCP 36
    pub const AF42: u8 = 36;
    /// Assured Forwarding 43 (high drop) - DSCP 38
    pub const AF43: u8 = 38;

    // Special purpose PHBs
    /// Expedited Forwarding (EF) - RFC 3246 - DSCP 46
    pub const EF: u8 = 46;
    /// Voice Admit - RFC 5865 - DSCP 44
    pub const VA: u8 = 44;
    /// Lower Effort (LE) - RFC 8622 - DSCP 1
    pub const LE: u8 = 1;

    /// Convert DSCP value to human-readable name.
    pub fn to_name(value: u8) -> &'static str {
        match value & 0x3F {
            CS0 => "CS0/BE",
            CS1 => "CS1",
            CS2 => "CS2",
            CS3 => "CS3",
            CS4 => "CS4",
            CS5 => "CS5",
            CS6 => "CS6",
            CS7 => "CS7",
            AF11 => "AF11",
            AF12 => "AF12",
            AF13 => "AF13",
            AF21 => "AF21",
            AF22 => "AF22",
            AF23 => "AF23",
            AF31 => "AF31",
            AF32 => "AF32",
            AF33 => "AF33",
            AF41 => "AF41",
            AF42 => "AF42",
            AF43 => "AF43",
            EF => "EF",
            VA => "VA",
            LE => "LE",
            _ => "", // Return empty string for unknown, caller can format
        }
    }
}

/// Explicit Congestion Notification (ECN) values.
///
/// ECN is a 2-bit field in the IP header that provides end-to-end congestion
/// notification without dropping packets. Defined in RFC 3168.
pub mod ecn {
    /// Not ECN-Capable Transport
    pub const NOT_ECT: u8 = 0;
    /// ECN Capable Transport (1)
    pub const ECT1: u8 = 1;
    /// ECN Capable Transport (0)
    pub const ECT0: u8 = 2;
    /// Congestion Experienced
    pub const CE: u8 = 3;

    /// Convert ECN value to human-readable name.
    pub fn to_name(value: u8) -> &'static str {
        match value & 0x03 {
            NOT_ECT => "Not-ECT",
            ECT1 => "ECT(1)",
            ECT0 => "ECT(0)",
            CE => "CE",
            _ => unreachable!(),
        }
    }
}

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
                let mut fields = SmallVec::new();

                fields.push(("version", FieldValue::UInt8(4)));
                fields.push(("ihl", FieldValue::UInt8(ipv4.ihl())));
                fields.push(("dscp", FieldValue::UInt8(ipv4.dcp().value())));
                fields.push(("ecn", FieldValue::UInt8(ipv4.ecn().value())));
                fields.push(("total_length", FieldValue::UInt16(ipv4.total_len())));
                fields.push(("identification", FieldValue::UInt16(ipv4.identification())));
                fields.push(("dont_fragment", FieldValue::Bool(ipv4.dont_fragment())));
                fields.push(("more_fragments", FieldValue::Bool(ipv4.more_fragments())));
                fields.push((
                    "fragment_offset",
                    FieldValue::UInt16(ipv4.fragments_offset().value()),
                ));
                fields.push(("ttl", FieldValue::UInt8(ipv4.ttl())));
                fields.push(("protocol", FieldValue::UInt8(ipv4.protocol().0)));
                fields.push(("checksum", FieldValue::UInt16(ipv4.header_checksum())));
                fields.push(("src_ip", FieldValue::ipv4(&ipv4.source())));
                fields.push(("dst_ip", FieldValue::ipv4(&ipv4.destination())));

                let mut child_hints = SmallVec::new();
                let protocol = ipv4.protocol().0;
                child_hints.push(("ip_protocol", protocol as u64));
                child_hints.push(("ip_version", 4));

                // Check for IP-in-IP encapsulation
                if protocol == ip_in_ip_protocol::IPIP {
                    // IPv4 encapsulated in IPv4 - signal tunnel boundary
                    child_hints.push(("tunnel_type", TunnelType::IpInIp as u64));
                    // Also set ethertype hint so inner IPv4 can be parsed
                    child_hints.push(("ethertype", ethertype::IPV4 as u64));
                } else if protocol == ip_in_ip_protocol::IPV6_IN_IP {
                    // IPv6 encapsulated in IPv4 - signal tunnel boundary
                    child_hints.push(("tunnel_type", TunnelType::Ip6InIp as u64));
                    // Also set ethertype hint so inner IPv6 can be parsed
                    child_hints.push(("ethertype", ethertype::IPV6 as u64));
                }

                let header_len = ipv4.slice().len();
                ParseResult::success(fields, &data[header_len..], child_hints)
            }
            Err(e) => ParseResult::error(format!("IPv4 parse error: {e}"), data),
        }
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            FieldDescriptor::new("ipv4.version", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("ipv4.ihl", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("ipv4.dscp", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("ipv4.ecn", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("ipv4.total_length", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("ipv4.identification", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("ipv4.dont_fragment", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("ipv4.more_fragments", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("ipv4.fragment_offset", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("ipv4.ttl", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("ipv4.protocol", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("ipv4.checksum", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("ipv4.src_ip", DataKind::String).set_nullable(true),
            FieldDescriptor::new("ipv4.dst_ip", DataKind::String).set_nullable(true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        &["tcp", "udp", "icmp"]
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &["ethernet", "vlan", "mpls", "gre", "vxlan", "gtp"]
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
        context.insert_hint("ethertype", ethertype::IPV4 as u64);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("ttl"), Some(&FieldValue::UInt8(64)));
        assert_eq!(result.get("protocol"), Some(&FieldValue::UInt8(6)));
        assert_eq!(result.hint("ip_protocol"), Some(6u64));
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
        context.insert_hint("ethertype", ethertype::IPV4 as u64);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("ttl"), Some(&FieldValue::UInt8(128)));
        assert_eq!(result.get("protocol"), Some(&FieldValue::UInt8(17)));
        assert_eq!(result.get("dont_fragment"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.hint("ip_protocol"), Some(17u64));
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
        context.insert_hint("ethertype", ethertype::IPV4 as u64);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("protocol"), Some(&FieldValue::UInt8(1)));
        assert_eq!(result.hint("ip_protocol"), Some(1u64));
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
        context.insert_hint("ethertype", ethertype::IPV4 as u64);

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
        ctx2.insert_hint("ethertype", ethertype::IPV6 as u64);
        assert!(parser.can_parse(&ctx2).is_none());

        // With IPv4 ethertype
        let mut ctx3 = ParseContext::new(1);
        ctx3.insert_hint("ethertype", ethertype::IPV4 as u64);
        assert!(parser.can_parse(&ctx3).is_some());
    }

    #[test]
    fn test_parse_ipv4_too_short() {
        let short_header = [0x45, 0x00, 0x00, 0x28]; // Only 4 bytes

        let parser = Ipv4Protocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ethertype", ethertype::IPV4 as u64);

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
        context.insert_hint("ethertype", ethertype::IPV4 as u64);

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
        context.insert_hint("ethertype", ethertype::IPV4 as u64);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("more_fragments"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("dont_fragment"), Some(&FieldValue::Bool(false)));
        assert_eq!(
            result.get("identification"),
            Some(&FieldValue::UInt16(0x1234))
        );
    }

    #[test]
    fn test_ipv4_child_hints() {
        let header = [
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00,
            0x00, // Protocol: TCP (6)
            0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02,
        ];

        let parser = Ipv4Protocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ethertype", ethertype::IPV4 as u64);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.hint("ip_protocol"), Some(6u64));
        assert_eq!(result.hint("ip_version"), Some(4u64));
    }
}
