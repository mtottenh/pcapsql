//! Test utilities for protocol parsing.
//!
//! Provides builders for constructing test packets and helper functions
//! for validating parse results.

use super::{FieldValue, ParseContext, ParseResult};

/// Builder for constructing Ethernet frames.
#[derive(Debug, Clone)]
pub struct EthernetBuilder {
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    ethertype: u16,
    payload: Vec<u8>,
}

impl Default for EthernetBuilder {
    fn default() -> Self {
        Self {
            src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            dst_mac: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ethertype: 0x0800, // IPv4
            payload: Vec::new(),
        }
    }
}

impl EthernetBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn src_mac(mut self, mac: [u8; 6]) -> Self {
        self.src_mac = mac;
        self
    }

    pub fn dst_mac(mut self, mac: [u8; 6]) -> Self {
        self.dst_mac = mac;
        self
    }

    pub fn ethertype(mut self, ethertype: u16) -> Self {
        self.ethertype = ethertype;
        self
    }

    pub fn ipv4(self) -> Self {
        self.ethertype(0x0800)
    }

    pub fn ipv6(self) -> Self {
        self.ethertype(0x86DD)
    }

    pub fn arp(self) -> Self {
        self.ethertype(0x0806)
    }

    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    pub fn build(self) -> Vec<u8> {
        let mut frame = Vec::with_capacity(14 + self.payload.len());
        frame.extend_from_slice(&self.dst_mac);
        frame.extend_from_slice(&self.src_mac);
        frame.extend_from_slice(&self.ethertype.to_be_bytes());
        frame.extend_from_slice(&self.payload);
        frame
    }
}

/// Builder for constructing IPv4 headers.
#[derive(Debug, Clone)]
pub struct Ipv4Builder {
    version_ihl: u8,
    dscp_ecn: u8,
    total_length: u16,
    identification: u16,
    flags_fragment: u16,
    ttl: u8,
    protocol: u8,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    payload: Vec<u8>,
}

impl Default for Ipv4Builder {
    fn default() -> Self {
        Self {
            version_ihl: 0x45, // Version 4, IHL 5 (20 bytes)
            dscp_ecn: 0x00,
            total_length: 20, // Will be updated on build
            identification: 0x0001,
            flags_fragment: 0x0000,
            ttl: 64,
            protocol: 6, // TCP
            src_ip: [192, 168, 1, 1],
            dst_ip: [192, 168, 1, 2],
            payload: Vec::new(),
        }
    }
}

impl Ipv4Builder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn protocol(mut self, protocol: u8) -> Self {
        self.protocol = protocol;
        self
    }

    pub fn tcp(self) -> Self {
        self.protocol(6)
    }

    pub fn udp(self) -> Self {
        self.protocol(17)
    }

    pub fn icmp(self) -> Self {
        self.protocol(1)
    }

    pub fn src_ip(mut self, ip: [u8; 4]) -> Self {
        self.src_ip = ip;
        self
    }

    pub fn dst_ip(mut self, ip: [u8; 4]) -> Self {
        self.dst_ip = ip;
        self
    }

    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    pub fn build(self) -> Vec<u8> {
        let total_length = 20 + self.payload.len() as u16;
        let mut header = Vec::with_capacity(20 + self.payload.len());

        header.push(self.version_ihl);
        header.push(self.dscp_ecn);
        header.extend_from_slice(&total_length.to_be_bytes());
        header.extend_from_slice(&self.identification.to_be_bytes());
        header.extend_from_slice(&self.flags_fragment.to_be_bytes());
        header.push(self.ttl);
        header.push(self.protocol);
        header.extend_from_slice(&[0x00, 0x00]); // Checksum (not calculated)
        header.extend_from_slice(&self.src_ip);
        header.extend_from_slice(&self.dst_ip);
        header.extend_from_slice(&self.payload);

        header
    }
}

/// Builder for constructing TCP headers.
#[derive(Debug, Clone)]
pub struct TcpBuilder {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    data_offset: u8,
    flags: u8,
    window: u16,
    payload: Vec<u8>,
}

impl Default for TcpBuilder {
    fn default() -> Self {
        Self {
            src_port: 12345,
            dst_port: 80,
            seq: 1,
            ack: 0,
            data_offset: 5, // 20 bytes
            flags: 0x02,    // SYN
            window: 65535,
            payload: Vec::new(),
        }
    }
}

impl TcpBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn src_port(mut self, port: u16) -> Self {
        self.src_port = port;
        self
    }

    pub fn dst_port(mut self, port: u16) -> Self {
        self.dst_port = port;
        self
    }

    pub fn seq(mut self, seq: u32) -> Self {
        self.seq = seq;
        self
    }

    pub fn ack_num(mut self, ack: u32) -> Self {
        self.ack = ack;
        self
    }

    pub fn flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    pub fn syn(self) -> Self {
        self.flags(0x02)
    }

    pub fn syn_ack(self) -> Self {
        self.flags(0x12)
    }

    pub fn ack(self) -> Self {
        self.flags(0x10)
    }

    pub fn fin(self) -> Self {
        self.flags(0x01)
    }

    pub fn rst(self) -> Self {
        self.flags(0x04)
    }

    pub fn psh_ack(self) -> Self {
        self.flags(0x18)
    }

    pub fn window(mut self, window: u16) -> Self {
        self.window = window;
        self
    }

    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    pub fn build(self) -> Vec<u8> {
        let mut header = Vec::with_capacity(20 + self.payload.len());

        header.extend_from_slice(&self.src_port.to_be_bytes());
        header.extend_from_slice(&self.dst_port.to_be_bytes());
        header.extend_from_slice(&self.seq.to_be_bytes());
        header.extend_from_slice(&self.ack.to_be_bytes());
        header.push((self.data_offset << 4) | 0x00); // Data offset + reserved
        header.push(self.flags);
        header.extend_from_slice(&self.window.to_be_bytes());
        header.extend_from_slice(&[0x00, 0x00]); // Checksum
        header.extend_from_slice(&[0x00, 0x00]); // Urgent pointer
        header.extend_from_slice(&self.payload);

        header
    }
}

/// Builder for constructing UDP headers.
#[derive(Debug, Clone)]
pub struct UdpBuilder {
    src_port: u16,
    dst_port: u16,
    payload: Vec<u8>,
}

impl Default for UdpBuilder {
    fn default() -> Self {
        Self {
            src_port: 12345,
            dst_port: 53,
            payload: Vec::new(),
        }
    }
}

impl UdpBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn src_port(mut self, port: u16) -> Self {
        self.src_port = port;
        self
    }

    pub fn dst_port(mut self, port: u16) -> Self {
        self.dst_port = port;
        self
    }

    pub fn dns(self) -> Self {
        self.dst_port(53)
    }

    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    pub fn build(self) -> Vec<u8> {
        let length = 8 + self.payload.len() as u16;
        let mut header = Vec::with_capacity(8 + self.payload.len());

        header.extend_from_slice(&self.src_port.to_be_bytes());
        header.extend_from_slice(&self.dst_port.to_be_bytes());
        header.extend_from_slice(&length.to_be_bytes());
        header.extend_from_slice(&[0x00, 0x00]); // Checksum
        header.extend_from_slice(&self.payload);

        header
    }
}

/// Builder for constructing ICMP packets.
#[derive(Debug, Clone)]
pub struct IcmpBuilder {
    icmp_type: u8,
    code: u8,
    rest: [u8; 4],
    payload: Vec<u8>,
}

impl Default for IcmpBuilder {
    fn default() -> Self {
        Self {
            icmp_type: 8, // Echo request
            code: 0,
            rest: [0x00, 0x01, 0x00, 0x01], // ID=1, Seq=1
            payload: Vec::new(),
        }
    }
}

impl IcmpBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn echo_request(mut self) -> Self {
        self.icmp_type = 8;
        self.code = 0;
        self
    }

    pub fn echo_reply(mut self) -> Self {
        self.icmp_type = 0;
        self.code = 0;
        self
    }

    pub fn destination_unreachable(mut self, code: u8) -> Self {
        self.icmp_type = 3;
        self.code = code;
        self
    }

    pub fn identifier(mut self, id: u16) -> Self {
        let bytes = id.to_be_bytes();
        self.rest[0] = bytes[0];
        self.rest[1] = bytes[1];
        self
    }

    pub fn sequence(mut self, seq: u16) -> Self {
        let bytes = seq.to_be_bytes();
        self.rest[2] = bytes[0];
        self.rest[3] = bytes[1];
        self
    }

    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    pub fn build(self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(8 + self.payload.len());

        packet.push(self.icmp_type);
        packet.push(self.code);
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&self.rest);
        packet.extend_from_slice(&self.payload);

        packet
    }
}

/// Build a complete Ethernet/IPv4/TCP packet.
pub fn build_tcp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    flags: u8,
) -> Vec<u8> {
    let tcp = TcpBuilder::new()
        .src_port(src_port)
        .dst_port(dst_port)
        .flags(flags)
        .build();

    let ipv4 = Ipv4Builder::new()
        .src_ip(src_ip)
        .dst_ip(dst_ip)
        .tcp()
        .payload(tcp)
        .build();

    EthernetBuilder::new().ipv4().payload(ipv4).build()
}

/// Build a complete Ethernet/IPv4/UDP packet.
pub fn build_udp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: Vec<u8>,
) -> Vec<u8> {
    let udp = UdpBuilder::new()
        .src_port(src_port)
        .dst_port(dst_port)
        .payload(payload)
        .build();

    let ipv4 = Ipv4Builder::new()
        .src_ip(src_ip)
        .dst_ip(dst_ip)
        .udp()
        .payload(udp)
        .build();

    EthernetBuilder::new().ipv4().payload(ipv4).build()
}

/// Build a complete Ethernet/IPv4/ICMP echo request.
pub fn build_icmp_echo_request(src_ip: [u8; 4], dst_ip: [u8; 4], id: u16, seq: u16) -> Vec<u8> {
    let icmp = IcmpBuilder::new()
        .echo_request()
        .identifier(id)
        .sequence(seq)
        .build();

    let ipv4 = Ipv4Builder::new()
        .src_ip(src_ip)
        .dst_ip(dst_ip)
        .icmp()
        .payload(icmp)
        .build();

    EthernetBuilder::new().ipv4().payload(ipv4).build()
}

/// Helper to assert a field value equals expected.
pub fn assert_field_eq(result: &ParseResult, field: &str, expected: &FieldValue) {
    let actual = result
        .get(field)
        .unwrap_or_else(|| panic!("Field '{}' not found in result", field));
    assert_eq!(
        actual, expected,
        "Field '{}' mismatch: expected {:?}, got {:?}",
        field, expected, actual
    );
}

/// Helper to assert a field is present.
pub fn assert_field_present(result: &ParseResult, field: &str) {
    assert!(
        result.get(field).is_some(),
        "Field '{}' not found in result",
        field
    );
}

/// Helper to assert parsing succeeded.
pub fn assert_parse_ok(result: &ParseResult) {
    assert!(
        result.is_ok(),
        "Parse failed: {:?}",
        result.error.as_ref().unwrap()
    );
}

/// Create a default parse context for Ethernet.
pub fn ethernet_context() -> ParseContext {
    ParseContext::new(1) // LINKTYPE_ETHERNET
}

/// Create a parse context with IPv4 hint.
pub fn ipv4_context() -> ParseContext {
    let mut ctx = ParseContext::new(1);
    ctx.insert_hint("ethertype", 0x0800);
    ctx.parent_protocol = Some("ethernet");
    ctx
}

/// Create a parse context with TCP hint.
pub fn tcp_context() -> ParseContext {
    let mut ctx = ParseContext::new(1);
    ctx.insert_hint("ip_protocol", 6);
    ctx.parent_protocol = Some("ipv4");
    ctx
}

/// Create a parse context with UDP hint.
pub fn udp_context() -> ParseContext {
    let mut ctx = ParseContext::new(1);
    ctx.insert_hint("ip_protocol", 17);
    ctx.parent_protocol = Some("ipv4");
    ctx
}

/// Create a parse context with ICMP hint.
pub fn icmp_context() -> ParseContext {
    let mut ctx = ParseContext::new(1);
    ctx.insert_hint("ip_protocol", 1);
    ctx.parent_protocol = Some("ipv4");
    ctx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethernet_builder() {
        let frame = EthernetBuilder::new()
            .src_mac([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
            .dst_mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
            .ethertype(0x0800)
            .payload(vec![0x45, 0x00])
            .build();

        assert_eq!(frame.len(), 16); // 14 header + 2 payload
        assert_eq!(&frame[0..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // dst
        assert_eq!(&frame[6..12], &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // src
        assert_eq!(&frame[12..14], &[0x08, 0x00]); // ethertype
    }

    #[test]
    fn test_ipv4_builder() {
        let packet = Ipv4Builder::new()
            .src_ip([10, 0, 0, 1])
            .dst_ip([10, 0, 0, 2])
            .ttl(128)
            .tcp()
            .build();

        assert_eq!(packet.len(), 20);
        assert_eq!(packet[0], 0x45); // Version + IHL
        assert_eq!(packet[8], 128); // TTL
        assert_eq!(packet[9], 6); // Protocol (TCP)
    }

    #[test]
    fn test_tcp_builder() {
        let segment = TcpBuilder::new()
            .src_port(443)
            .dst_port(54321)
            .syn()
            .build();

        assert_eq!(segment.len(), 20);
        assert_eq!(&segment[0..2], &443u16.to_be_bytes());
        assert_eq!(&segment[2..4], &54321u16.to_be_bytes());
        assert_eq!(segment[13], 0x02); // SYN flag
    }

    #[test]
    fn test_build_tcp_packet() {
        let packet = build_tcp_packet(
            [192, 168, 1, 100],
            [192, 168, 1, 200],
            12345,
            80,
            0x02, // SYN
        );

        // Should be Ethernet (14) + IPv4 (20) + TCP (20) = 54 bytes
        assert_eq!(packet.len(), 54);
    }
}
