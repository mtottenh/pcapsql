//! Protocol parsing framework.
//!
//! This module provides:
//! - [`Protocol`] trait for implementing parsers
//! - [`ProtocolRegistry`] for managing registered parsers
//! - Built-in parsers for common protocols
//!
//! ## Supported Protocols
//!
//! | Layer | Protocols |
//! |-------|-----------|
//! | Link | Ethernet, VLAN (802.1Q) |
//! | Network | IPv4, IPv6, ARP, ICMP, ICMPv6 |
//! | Transport | TCP, UDP |
//! | Application | DNS, DHCP, NTP, TLS, SSH, QUIC |
//!
//! Note: HTTP is parsed via TCP stream reassembly (see `stream::parsers::http`).
//!
//! ## Example
//!
//! ```rust
//! use pcapsql_core::protocol::{default_registry, parse_packet, ParseScope};
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
//! let results = parse_packet(&registry, 1, packet_data, &ParseScope::full());
//! for (name, result) in results {
//!     let field_names: Vec<_> = result.fields.iter().map(|(k, _)| *k).collect();
//!     println!("Parsed {}: {:?}", name, field_names);
//! }
//! ```

mod context;
mod field;
mod projection;
mod pruning;
mod registry;

// Protocol implementations
mod arp;
mod bgp;
mod dhcp;
mod dns;
mod ethernet;
mod gre;
mod gtp;
mod icmp;
mod icmpv6;
mod ipsec;
mod ipv4;
mod ipv6;
mod linux_sll;
mod mpls;
mod netlink;
mod ntp;
mod ospf;
mod quic;
mod rtnetlink;
mod ssh;
mod tcp;
mod tls;
mod udp;
mod vlan;
mod vxlan;

// Test utilities (only compiled for tests)
#[cfg(test)]
pub mod test_utils;

pub use context::{FieldEntry, HintEntry, ParseContext, ParseResult, TunnelLayer, TunnelType};
pub use field::{FieldValue, OwnedFieldValue};
pub use projection::{chain_fields_for_protocol, merge_with_chain_fields, ProjectionConfig};
pub use pruning::{compute_required_protocols, should_continue_parsing, should_run_parser};
pub use registry::{BuiltinProtocol, PayloadMode, Protocol, ProtocolRegistry};

// Re-export protocol implementations
pub use arp::ArpProtocol;
pub use bgp::BgpProtocol;
pub use dhcp::DhcpProtocol;
pub use dns::DnsProtocol;
pub use ethernet::EthernetProtocol;
pub use gre::GreProtocol;
pub use gtp::GtpProtocol;
pub use icmp::IcmpProtocol;
pub use icmpv6::Icmpv6Protocol;
pub use ipsec::IpsecProtocol;
pub use ipv4::Ipv4Protocol;
pub use ipv6::Ipv6Protocol;
pub use linux_sll::LinuxSllProtocol;
pub use mpls::MplsProtocol;
pub use netlink::NetlinkProtocol;
pub use ntp::NtpProtocol;
pub use ospf::OspfProtocol;
pub use quic::QuicProtocol;
pub use rtnetlink::RtnetlinkProtocol;
pub use ssh::SshProtocol;
pub use tcp::TcpProtocol;
pub use tls::TlsProtocol;
pub use udp::UdpProtocol;
pub use vlan::VlanProtocol;
pub use vxlan::VxlanProtocol;

// Re-export protocol constants for use in UDFs and other crates
pub use bgp::{message_type as bgp_message_type, origin_type as bgp_origin_type};
pub use dns::{rcode, record_type};
pub use ethernet::ethertype;
pub use gtp::message_type as gtp_message_type;
pub use icmp::{
    dest_unreachable_code as icmp_dest_unreachable_code, icmp_type,
    parameter_problem_code as icmp_parameter_problem_code, redirect_code as icmp_redirect_code,
    time_exceeded_code as icmp_time_exceeded_code,
};
pub use icmpv6::{
    dest_unreachable_code as icmpv6_dest_unreachable_code, icmpv6_type,
    parameter_problem_code as icmpv6_parameter_problem_code,
    time_exceeded_code as icmpv6_time_exceeded_code,
};
pub use ipv6::next_header;
pub use netlink::family as netlink_family;
pub use ntp::{mode as ntp_mode, stratum as ntp_stratum};
pub use ospf::{lsa_type as ospf_lsa_type, packet_type as ospf_packet_type};
pub use tls::{record_type as tls_record_type, version as tls_version};

/// Create a registry with all built-in protocol parsers.
pub fn default_registry() -> ProtocolRegistry {
    let mut registry = ProtocolRegistry::new();

    // Layer 2
    registry.register(EthernetProtocol);
    registry.register(LinuxSllProtocol);
    registry.register(ArpProtocol);
    registry.register(VlanProtocol);
    registry.register(MplsProtocol);

    // Layer 3
    registry.register(Ipv4Protocol);
    registry.register(Ipv6Protocol);

    // Layer 4
    registry.register(TcpProtocol);
    registry.register(UdpProtocol);
    registry.register(IcmpProtocol);
    registry.register(Icmpv6Protocol);

    // Tunneling protocols (higher priority than application protocols)
    registry.register(GreProtocol);
    registry.register(VxlanProtocol);
    registry.register(GtpProtocol);
    registry.register(IpsecProtocol);

    // Routing protocols
    registry.register(BgpProtocol);
    registry.register(OspfProtocol);

    // Application layer
    // Note: HTTP is parsed via TCP stream reassembly (see stream::parsers::http)
    registry.register(DnsProtocol);
    registry.register(DhcpProtocol);
    registry.register(NtpProtocol);
    registry.register(TlsProtocol);
    registry.register(SshProtocol);
    registry.register(QuicProtocol);

    // Netlink protocols (Linux kernel-userspace)
    registry.register(NetlinkProtocol);
    registry.register(RtnetlinkProtocol);

    registry
}

use std::collections::{HashMap, HashSet};

/// What a parse pass should extract: which protocols to run and which
/// fields to materialize per protocol.
///
/// Built once per query (or [`ParseScope::full`] for unscoped parsing) and
/// passed to [`parse_packet`] for every packet. Pruning stops the protocol
/// walk as soon as everything required has been seen; projection limits the
/// fields individual parsers extract.
#[derive(Clone, Debug, Default)]
pub struct ParseScope {
    /// Protocols to parse, including their dependency closure. `None` parses
    /// every matching protocol.
    required: Option<HashSet<String>>,
    /// Per-protocol field projections. Protocols absent from the map are
    /// parsed with all fields.
    projections: HashMap<String, HashSet<String>>,
}

impl ParseScope {
    /// Parse every protocol with every field (the unscoped default).
    pub fn full() -> Self {
        Self::default()
    }

    /// Parse only the given tables' protocols plus their dependency closure
    /// (via [`compute_required_protocols`]). Unknown table names (pseudo
    /// tables such as `frames`) are tolerated: they require no parsing.
    pub fn for_tables(queried_tables: &[&str], registry: &ProtocolRegistry) -> Self {
        Self {
            required: Some(compute_required_protocols(queried_tables, registry)),
            projections: HashMap::new(),
        }
    }

    /// Restrict the fields extracted for one protocol.
    pub fn with_projection(mut self, protocol: impl Into<String>, fields: HashSet<String>) -> Self {
        self.projections.insert(protocol.into(), fields);
        self
    }

    /// True when nothing is pruned or projected.
    pub fn is_full(&self) -> bool {
        self.required.is_none() && self.projections.is_empty()
    }
}

/// Parse a packet through its protocol layers, scoped by `scope`.
///
/// With [`ParseScope::full`] every matching protocol is parsed with all
/// fields. A scoped parse prunes the protocol walk (stopping once all
/// required protocols have been seen, and never descending into branches
/// that cannot reach one) and projects fields within parsers that support
/// it. Intermediate layers on the path to a required protocol are still
/// returned — they may be needed for joins.
///
/// For tunneled traffic, encapsulation depth and tunnel context are tracked;
/// each ParseResult carries encap_depth, tunnel_type, and tunnel_id.
pub fn parse_packet<'a>(
    registry: &ProtocolRegistry,
    link_type: u16,
    data: &'a [u8],
    scope: &ParseScope,
) -> Vec<(&'static str, ParseResult<'a>)> {
    // Typical packet has 3-4 protocol layers (Eth/IP/TCP/App);
    // tunneled packets may have more (up to ~8 for deep encapsulation).
    let mut results = Vec::with_capacity(8);
    let mut parsed_protocols: Vec<&str> = Vec::new();
    let mut context = ParseContext::new(link_type);
    let mut remaining = data;

    while !remaining.is_empty() {
        if let Some(required) = &scope.required {
            // Stop once every required protocol has been parsed.
            if !should_continue_parsing(&parsed_protocols, required) {
                break;
            }
        }

        let Some(parser) = registry.find_parser(&context) else {
            break;
        };
        let name = parser.name();

        if let Some(required) = &scope.required {
            // Never descend into a branch that cannot reach a required
            // protocol.
            if !should_run_parser(name, required, registry) {
                break;
            }
            parsed_protocols.push(name);
        }

        let mut result = if scope.projections.is_empty() {
            parser.parse(remaining, &context)
        } else {
            parser.parse_projected(remaining, &context, scope.projections.get(name))
        };

        // Set encapsulation context on the result BEFORE updating context;
        // this captures the encap state when this protocol was parsed.
        result.set_encap_context(&context);

        // A tunnel boundary updates context for the inner layers.
        if let Some(tunnel_type_val) = result.hint("tunnel_type") {
            let tunnel_id = result.hint("tunnel_id");
            context.push_tunnel(TunnelType::from_u64(tunnel_type_val), tunnel_id);
        }

        // Update context for the next layer.
        context.parent_protocol = Some(name);
        context.hints = result.child_hints.clone();
        context.offset += remaining.len() - result.remaining.len();

        let should_stop = result.error.is_some();
        remaining = result.remaining;

        results.push((name, result));

        if should_stop {
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
