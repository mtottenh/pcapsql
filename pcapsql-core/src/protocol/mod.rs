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

/// Parse a packet through all protocol layers.
///
/// For tunneled traffic, this function tracks encapsulation depth and tunnel context.
/// Each ParseResult includes encap_depth, tunnel_type, and tunnel_id fields that indicate
/// whether the protocol was parsed inside a tunnel and which tunnel it was in.
pub fn parse_packet<'a>(
    registry: &ProtocolRegistry,
    link_type: u16,
    data: &'a [u8],
) -> Vec<(&'static str, ParseResult<'a>)> {
    // Typical packet has 3-4 protocol layers (Eth/IP/TCP/App)
    // Tunneled packets may have more (up to 8 layers for complex encapsulation)
    let mut results = Vec::with_capacity(8);
    let mut context = ParseContext::new(link_type);
    let mut remaining = data;

    while !remaining.is_empty() {
        if let Some(parser) = registry.find_parser(&context) {
            let mut result = parser.parse(remaining, &context);

            // Set encapsulation context on the result BEFORE updating context
            // This captures the encap state when this protocol was parsed
            result.set_encap_context(&context);

            // Check if this protocol's child hints indicate a tunnel boundary
            // If so, update context for the next layer (inner protocols)
            if let Some(tunnel_type_val) = result.hint("tunnel_type") {
                let tunnel_id = result.hint("tunnel_id");
                context.push_tunnel(TunnelType::from_u64(tunnel_type_val), tunnel_id);
            }

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

/// Parse a packet with protocol pruning.
///
/// Only parses protocols in the `required` set and their dependencies.
/// This can significantly reduce CPU usage for selective queries.
///
/// # Arguments
///
/// * `registry` - Protocol registry containing parser definitions
/// * `link_type` - Link layer type (e.g., 1 for Ethernet)
/// * `data` - Raw packet bytes
/// * `required` - Set of protocol names needed for the query
///
/// # Returns
///
/// Vector of (protocol_name, parse_result) pairs for protocols in the required set.
/// Protocols parsed but not in the required set (i.e., intermediate layers) are
/// still included as they may be needed for correct result interpretation.
///
/// # Example
///
/// ```rust,ignore
/// use std::collections::HashSet;
/// use pcapsql_core::protocol::{default_registry, parse_packet_pruned};
///
/// let registry = default_registry();
/// let required: HashSet<String> = ["tcp"].iter().map(|s| s.to_string()).collect();
///
/// let results = parse_packet_pruned(&registry, 1, &packet_data, &required);
/// // Will parse Ethernet, IPv4/IPv6, TCP but skip DNS, HTTP, TLS, etc.
/// ```
pub fn parse_packet_pruned<'a>(
    registry: &ProtocolRegistry,
    link_type: u16,
    data: &'a [u8],
    required: &HashSet<String>,
) -> Vec<(&'static str, ParseResult<'a>)> {
    // If no required set or empty, fall back to full parsing
    if required.is_empty() {
        return parse_packet(registry, link_type, data);
    }

    // Typical packet has 3-4 protocol layers
    let mut results = Vec::with_capacity(4);
    let mut parsed_protocols: Vec<&str> = Vec::with_capacity(4);
    let mut context = ParseContext::new(link_type);
    let mut remaining = data;

    while !remaining.is_empty() {
        // Check if we have everything we need
        if !should_continue_parsing(&parsed_protocols, required) {
            break;
        }

        // Find next parser
        let parser = match registry.find_parser(&context) {
            Some(p) => p,
            None => break,
        };

        let name = parser.name();

        // Check if we should run this parser
        if !should_run_parser(name, required, registry) {
            // Skip this parser - we don't need it or anything it produces
            break;
        }

        // Parse
        let mut result = parser.parse(remaining, &context);
        parsed_protocols.push(name);

        // Set encapsulation context on the result BEFORE updating context
        result.set_encap_context(&context);

        // Check if this protocol's child hints indicate a tunnel boundary
        if let Some(tunnel_type_val) = result.hint("tunnel_type") {
            let tunnel_id = result.hint("tunnel_id");
            context.push_tunnel(TunnelType::from_u64(tunnel_type_val), tunnel_id);
        }

        // Update context for next layer
        context.parent_protocol = Some(name);
        context.hints = result.child_hints.clone();
        context.offset += remaining.len() - result.remaining.len();

        let should_stop = result.error.is_some() || result.remaining.is_empty();
        remaining = result.remaining;

        // Always add to results - we may need intermediate layers for joins
        results.push((name, result));

        if should_stop {
            break;
        }
    }

    results
}

/// Parse a packet with field projection.
///
/// Uses `parse_projected()` for each protocol, only extracting the fields
/// in the projection config. This can significantly reduce CPU usage when
/// queries only need a subset of fields.
///
/// # Arguments
///
/// * `registry` - Protocol registry containing parser definitions
/// * `link_type` - Link layer type (e.g., 1 for Ethernet)
/// * `data` - Raw packet bytes
/// * `projections` - Per-protocol field projections (protocol name -> field names)
///
/// # Returns
///
/// Vector of (protocol_name, parse_result) pairs. Parse results only contain
/// the fields that were requested in the projection config.
///
/// # Example
///
/// ```rust,ignore
/// use std::collections::{HashMap, HashSet};
/// use pcapsql_core::protocol::{default_registry, parse_packet_projected};
///
/// let registry = default_registry();
///
/// // Only extract ports from TCP
/// let mut projections = HashMap::new();
/// projections.insert("tcp", ["src_port", "dst_port"].iter().map(|s| s.to_string()).collect());
///
/// let results = parse_packet_projected(&registry, 1, &packet_data, &projections);
/// ```
pub fn parse_packet_projected<'a>(
    registry: &ProtocolRegistry,
    link_type: u16,
    data: &'a [u8],
    projections: &HashMap<String, HashSet<String>>,
) -> Vec<(&'static str, ParseResult<'a>)> {
    // If no projections, fall back to full parsing
    if projections.is_empty() {
        return parse_packet(registry, link_type, data);
    }

    // Typical packet has 3-4 protocol layers
    let mut results = Vec::with_capacity(4);
    let mut context = ParseContext::new(link_type);
    let mut remaining = data;

    while !remaining.is_empty() {
        if let Some(parser) = registry.find_parser(&context) {
            let name = parser.name();

            // Get projection for this protocol, if any
            let projection = projections.get(name);

            // Use projected parsing if projection is configured
            let mut result = parser.parse_projected(remaining, &context, projection);

            // Set encapsulation context on the result BEFORE updating context
            result.set_encap_context(&context);

            // Check if this protocol's child hints indicate a tunnel boundary
            if let Some(tunnel_type_val) = result.hint("tunnel_type") {
                let tunnel_id = result.hint("tunnel_id");
                context.push_tunnel(TunnelType::from_u64(tunnel_type_val), tunnel_id);
            }

            // Update context for next layer
            context.parent_protocol = Some(name);
            context.hints = result.child_hints.clone();
            context.offset += remaining.len() - result.remaining.len();

            let should_stop = result.error.is_some();
            remaining = result.remaining;

            results.push((name, result));

            if should_stop {
                break;
            }
        } else {
            break;
        }
    }

    results
}

/// Parse a packet with both protocol pruning and field projection.
///
/// This combines the benefits of both optimizations:
/// - Protocol pruning skips parsing protocols not needed for the query
/// - Field projection only extracts needed fields within parsed protocols
///
/// # Arguments
///
/// * `registry` - Protocol registry containing parser definitions
/// * `link_type` - Link layer type (e.g., 1 for Ethernet)
/// * `data` - Raw packet bytes
/// * `required` - Set of protocol names needed for the query (for pruning)
/// * `projections` - Per-protocol field projections
///
/// # Returns
///
/// Vector of (protocol_name, parse_result) pairs.
pub fn parse_packet_pruned_projected<'a>(
    registry: &ProtocolRegistry,
    link_type: u16,
    data: &'a [u8],
    required: &HashSet<String>,
    projections: &HashMap<String, HashSet<String>>,
) -> Vec<(&'static str, ParseResult<'a>)> {
    // If no pruning or projection, fall back to full parsing
    if required.is_empty() && projections.is_empty() {
        return parse_packet(registry, link_type, data);
    }

    // If only pruning, use pruned parsing
    if projections.is_empty() {
        return parse_packet_pruned(registry, link_type, data, required);
    }

    // If only projection, use projected parsing
    if required.is_empty() {
        return parse_packet_projected(registry, link_type, data, projections);
    }

    // Combined pruning and projection
    // Typical packet has 3-4 protocol layers
    let mut results = Vec::with_capacity(4);
    let mut parsed_protocols: Vec<&str> = Vec::with_capacity(4);
    let mut context = ParseContext::new(link_type);
    let mut remaining = data;

    while !remaining.is_empty() {
        // Check if we have everything we need (pruning)
        if !should_continue_parsing(&parsed_protocols, required) {
            break;
        }

        // Find next parser
        let parser = match registry.find_parser(&context) {
            Some(p) => p,
            None => break,
        };

        let name = parser.name();

        // Check if we should run this parser (pruning)
        if !should_run_parser(name, required, registry) {
            break;
        }

        // Get projection for this protocol, if any
        let projection = projections.get(name);

        // Parse with projection
        let mut result = parser.parse_projected(remaining, &context, projection);
        parsed_protocols.push(name);

        // Set encapsulation context on the result BEFORE updating context
        result.set_encap_context(&context);

        // Check if this protocol's child hints indicate a tunnel boundary
        if let Some(tunnel_type_val) = result.hint("tunnel_type") {
            let tunnel_id = result.hint("tunnel_id");
            context.push_tunnel(TunnelType::from_u64(tunnel_type_val), tunnel_id);
        }

        // Update context for next layer
        context.parent_protocol = Some(name);
        context.hints = result.child_hints.clone();
        context.offset += remaining.len() - result.remaining.len();

        let should_stop = result.error.is_some() || result.remaining.is_empty();
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
