//! Protocol parsing module.
//!
//! This module provides:
//! - Core `Protocol` trait for implementing parsers
//! - `ProtocolRegistry` for managing registered parsers
//! - Built-in parsers for common protocols

mod context;
mod field;
mod registry;

// Protocol implementations
mod arp;
mod dns;
mod ethernet;
mod icmp;
mod ipv4;
mod ipv6;
mod tcp;
mod udp;
mod vlan;

// Test utilities (only compiled for tests)
#[cfg(test)]
pub mod test_utils;

pub use context::{ParseContext, ParseResult};
pub use field::FieldValue;
pub use registry::{BuiltinProtocol, Protocol, ProtocolRegistry};

// Re-export protocol implementations
pub use arp::ArpProtocol;
pub use dns::DnsProtocol;
pub use ethernet::EthernetProtocol;
pub use icmp::IcmpProtocol;
pub use ipv4::Ipv4Protocol;
pub use ipv6::Ipv6Protocol;
pub use tcp::TcpProtocol;
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

    // Application layer
    registry.register(DnsProtocol);

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
