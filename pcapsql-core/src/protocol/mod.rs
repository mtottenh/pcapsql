//! Protocol parsing framework.
//!
//! This module provides:
//! - [`Protocol`] trait for implementing parsers
//! - [`ProtocolRegistry`] for managing registered parsers
//! - Built-in parsers for 17 common protocols
//!
//! ## Supported Protocols
//!
//! | Layer | Protocols |
//! |-------|-----------|
//! | Link | Ethernet, VLAN (802.1Q) |
//! | Network | IPv4, IPv6, ARP, ICMP, ICMPv6 |
//! | Transport | TCP, UDP |
//! | Application | DNS, DHCP, NTP, HTTP, TLS, SSH, QUIC |
//!
//! ## Example
//!
//! ```rust
//! use pcapsql_core::protocol::{default_registry, parse_packet};
//!
//! let registry = default_registry();
//! // Ethernet frame with IP/TCP
//! let packet_data: &[u8] = &[
//!     // Ethernet header (14 bytes)
//!     0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // dst mac
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // src mac
//!     0x08, 0x00,                          // ethertype (IPv4)
//!     // Minimal IPv4 header would follow...
//! ];
//!
//! let results = parse_packet(&registry, 1, packet_data); // 1 = Ethernet
//! for (name, result) in results {
//!     println!("Parsed {}: {:?}", name, result.fields.keys().collect::<Vec<_>>());
//! }
//! ```

mod context;
mod field;
mod registry;

// Protocol implementations
mod arp;
mod dhcp;
mod dns;
mod ethernet;
mod http;
mod icmp;
mod icmpv6;
mod ipv4;
mod ipv6;
mod ntp;
mod quic;
mod ssh;
mod tcp;
mod tls;
mod udp;
mod vlan;

// Test utilities (only compiled for tests)
#[cfg(test)]
pub mod test_utils;

pub use context::{ParseContext, ParseResult};
pub use field::FieldValue;
pub use registry::{BuiltinProtocol, PayloadMode, Protocol, ProtocolRegistry};

// Re-export protocol implementations
pub use arp::ArpProtocol;
pub use dhcp::DhcpProtocol;
pub use dns::DnsProtocol;
pub use ethernet::EthernetProtocol;
pub use http::HttpProtocol;
pub use icmp::IcmpProtocol;
pub use icmpv6::Icmpv6Protocol;
pub use ipv4::Ipv4Protocol;
pub use ipv6::Ipv6Protocol;
pub use ntp::NtpProtocol;
pub use quic::QuicProtocol;
pub use ssh::SshProtocol;
pub use tcp::TcpProtocol;
pub use tls::TlsProtocol;
pub use udp::UdpProtocol;
pub use vlan::VlanProtocol;

/// Create a registry with all built-in protocol parsers.
pub fn default_registry() -> ProtocolRegistry {
    let mut registry = ProtocolRegistry::new();

    // Layer 2
    registry.register(EthernetProtocol);
    registry.register(ArpProtocol);
    registry.register(VlanProtocol);

    // Layer 3
    registry.register(Ipv4Protocol);
    registry.register(Ipv6Protocol);

    // Layer 4
    registry.register(TcpProtocol);
    registry.register(UdpProtocol);
    registry.register(IcmpProtocol);
    registry.register(Icmpv6Protocol);

    // Application layer
    registry.register(DnsProtocol);
    registry.register(DhcpProtocol);
    registry.register(NtpProtocol);
    registry.register(HttpProtocol);
    registry.register(TlsProtocol);
    registry.register(SshProtocol);
    registry.register(QuicProtocol);

    registry
}

/// Parse a packet through all protocol layers.
pub fn parse_packet<'a>(
    registry: &ProtocolRegistry,
    link_type: u16,
    data: &'a [u8],
) -> Vec<(&'static str, ParseResult<'a>)> {
    let mut results = Vec::new();
    let mut context = ParseContext::new(link_type);
    let mut remaining = data;

    while !remaining.is_empty() {
        if let Some(parser) = registry.find_parser(&context) {
            let result = parser.parse(remaining, &context);

            // Update context for next layer
            context.parent_protocol = Some(parser.name());
            context.hints = result.child_hints.clone();
            context.offset += remaining.len() - result.remaining.len();

            let should_stop = result.error.is_some();
            remaining = result.remaining;

            results.push((parser.name(), result));

            if should_stop {
                break;
            }
        } else {
            break;
        }
    }

    results
}

#[cfg(test)]
mod payload_mode_tests {
    use super::*;

    // Test 1: Default payload mode is Chain
    #[test]
    fn test_default_payload_mode() {
        // Most protocols should default to Chain
        let eth = EthernetProtocol;
        assert_eq!(eth.payload_mode(), PayloadMode::Chain);

        let ipv4 = Ipv4Protocol;
        assert_eq!(ipv4.payload_mode(), PayloadMode::Chain);

        let udp = UdpProtocol;
        assert_eq!(udp.payload_mode(), PayloadMode::Chain);
    }

    // Test 2: TCP returns Stream mode
    #[test]
    fn test_tcp_stream_mode() {
        let tcp = TcpProtocol;
        assert_eq!(tcp.payload_mode(), PayloadMode::Stream);
    }

    // Test 3: TCP child_protocols is empty
    #[test]
    fn test_tcp_no_child_protocols() {
        let tcp = TcpProtocol;
        assert!(tcp.child_protocols().is_empty());
    }

    // Test 4: PayloadMode enum values
    #[test]
    fn test_payload_mode_values() {
        assert_ne!(PayloadMode::Chain, PayloadMode::Stream);
        assert_ne!(PayloadMode::Stream, PayloadMode::None);
        assert_ne!(PayloadMode::Chain, PayloadMode::None);
    }
}
