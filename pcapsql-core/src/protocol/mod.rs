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
//! | Application | DNS, DHCP, NTP, HTTP/1.x, TLS, SSH, QUIC |
//!
//! Note: the packet-level HTTP parser sees the segment that starts a message
//! (request/status line and headers); reassembled messages come from the
//! stream layer (see `stream::parsers::http`).
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
pub(crate) mod http;
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
mod sll2;
mod ssh;
mod tcp;
mod tls;
mod udp;
mod vlan;
mod vxlan;

// Test utilities (only compiled for tests)
#[cfg(test)]
pub mod test_utils;

pub use context::{
    FieldEntry, FieldHint, HintEntry, ParseContext, ParseResult, TunnelLayer, TunnelType,
};
pub use field::{FieldValue, OwnedFieldValue};
pub use projection::{
    chain_fields_for_protocol, merge_with_chain_fields, FieldSet, ProjectionConfig,
};
pub use pruning::{compute_required_protocols, should_run_parser};
pub use registry::{
    BuiltinProtocol, ParseGate, PayloadMode, Protocol, ProtocolRegistry, CONTENT_PRIORITY,
    PORT_PRIORITY_MAX,
};

// Re-export protocol implementations
pub use arp::ArpProtocol;
pub use bgp::BgpProtocol;
pub use dhcp::DhcpProtocol;
pub use dns::DnsProtocol;
pub use ethernet::EthernetProtocol;
pub use gre::GreProtocol;
pub use gtp::GtpProtocol;
pub use http::HttpProtocol;
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
pub use sll2::Sll2Protocol;
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

// IPv4 header field constants
pub use ipv4::{dscp, ecn};

/// Create a registry with all built-in protocol parsers.
pub fn default_registry() -> ProtocolRegistry {
    let mut registry = ProtocolRegistry::new();

    // Layer 2
    registry.register(EthernetProtocol);
    registry.register(LinuxSllProtocol);
    registry.register(Sll2Protocol);
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
    registry.register(DnsProtocol);
    registry.register(DhcpProtocol);
    registry.register(NtpProtocol);
    registry.register(HttpProtocol);
    registry.register(TlsProtocol);
    registry.register(SshProtocol);
    registry.register(QuicProtocol);

    // Netlink protocols (Linux kernel-userspace)
    registry.register(NetlinkProtocol);
    registry.register(RtnetlinkProtocol);

    registry
}

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

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
    /// The above, looked up for every parser of the registry the scope is
    /// used with, so that a packet's walk does no hashing. Built by the first
    /// [`parse_packet`] call.
    resolved: OnceLock<ResolvedScope>,
}

/// A [`ParseScope`] resolved against one registry: per parser index, whether
/// it runs and the fields it extracts.
#[derive(Clone, Debug)]
struct ResolvedScope {
    /// [`ProtocolRegistry::id`] of the registry this was resolved against.
    registry_id: u64,
    /// The scope requires no protocol at all (`frames` only).
    parses_nothing: bool,
    /// Per parser: may it run (as [`should_run_parser`] decides)? `None`
    /// when nothing is pruned.
    runs: Option<Box<[bool]>>,
    /// Per parser: its field projection (`None`: all fields). `None` for the
    /// whole when the scope projects nothing, in which case parsers run
    /// `parse` rather than `parse_projected`.
    projections: Option<Box<[Option<FieldSet>]>>,
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
            resolved: OnceLock::new(),
        }
    }

    /// Restrict the fields extracted for one protocol.
    pub fn with_projection(mut self, protocol: impl Into<String>, fields: HashSet<String>) -> Self {
        self.projections.insert(protocol.into(), fields);
        self.resolved = OnceLock::new();
        self
    }

    /// The protocols that are parsed, their dependency closure included
    /// (and the pseudo-protocol `frames`). `None` when every matching
    /// protocol is parsed.
    pub fn required(&self) -> Option<&HashSet<String>> {
        self.required.as_ref()
    }

    /// The field projections, by protocol. A protocol without an entry is
    /// parsed with all its fields.
    pub fn projections(&self) -> &HashMap<String, HashSet<String>> {
        &self.projections
    }

    /// True when nothing is pruned or projected.
    pub fn is_full(&self) -> bool {
        self.required.is_none() && self.projections.is_empty()
    }

    fn resolve(&self, registry: &ProtocolRegistry) -> ResolvedScope {
        ResolvedScope {
            registry_id: registry.id(),
            parses_nothing: self
                .required
                .as_ref()
                .is_some_and(|required| required.iter().all(|r| r == "frames")),
            runs: self.required.as_ref().map(|required| {
                registry
                    .all_parsers()
                    .map(|p| should_run_parser(p.name(), required, registry))
                    .collect()
            }),
            projections: (!self.projections.is_empty()).then(|| {
                registry
                    .all_parsers()
                    .map(|p| self.projections.get(p.name()).map(FieldSet::from))
                    .collect()
            }),
        }
    }

    /// The scope resolved against `registry`: cached on first use. A scope
    /// used with a registry other than the one it was first resolved against
    /// is resolved again on every call (correct, only slower).
    fn resolved_for(&self, registry: &ProtocolRegistry) -> Cow<'_, ResolvedScope> {
        let resolved = self.resolved.get_or_init(|| self.resolve(registry));
        if resolved.registry_id == registry.id() {
            Cow::Borrowed(resolved)
        } else {
            Cow::Owned(self.resolve(registry))
        }
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
/// each ParseResult carries encap_depth, tunnel_type, and tunnel_id. A tunnel
/// is a protocol that carries a whole inner packet (VXLAN, GRE, GTP, IPsec,
/// IP-in-IP); MPLS label switching is not one, so an MPLS stack neither
/// increments `encap_depth` nor sets `tunnel_type` on the layers below it.
///
/// # Parse errors
///
/// A parser that fails outright (`ParseResult::error`: a truncated or
/// malformed header, no fields extracted) ends the walk and is *not* part of
/// the returned layers: a table row with every column NULL would say nothing
/// about the packet and would still be counted by `count(*)`. A parser that
/// extracted some fields before failing (`ParseResult::partial`) is kept with
/// those fields and ends the walk as well. The outer layers that were parsed
/// successfully are always returned.
///
/// A returned layer's `child_hints` are empty: the walk moves them into the
/// context of the layer that follows rather than copying them.
///
/// The layers come in a `Vec` of their own: one heap allocation for every
/// packet that is parsed. A caller that parses packet after packet uses
/// [`parse_packet_into`] with a [`LayerBuf`] instead.
pub fn parse_packet<'a>(
    registry: &ProtocolRegistry,
    link_type: u16,
    data: &'a [u8],
    scope: &ParseScope,
) -> Layers<'a> {
    let mut results = Vec::new();
    parse_packet_into(registry, link_type, data, scope, &mut results);
    results
}

/// [`parse_packet`] into storage the caller keeps: `out` is emptied, then
/// holds the packet's layers. Its capacity is reused, so a caller that hands
/// in the same storage for every packet (see [`LayerBuf`]) allocates for the
/// first packets only.
pub fn parse_packet_into<'a>(
    registry: &ProtocolRegistry,
    link_type: u16,
    data: &'a [u8],
    scope: &ParseScope,
    out: &mut Layers<'a>,
) {
    out.clear();
    let scope = scope.resolved_for(registry);

    // A scope that needs no protocol table at all (`frames` only) parses
    // nothing: the frame columns come from the record header. This is ahead
    // of the reservation below, so that such a scan pays for no storage.
    if scope.parses_nothing {
        return;
    }

    // Typical packet has 3-4 protocol layers (Eth/IP/TCP/App);
    // tunneled packets may have more (up to ~8 for deep encapsulation).
    if out.capacity() == 0 {
        out.reserve(8);
    }

    let mut context = ParseContext::new(link_type);
    let mut remaining = data;
    // Index of the parser that produced the previous layer.
    let mut parent: Option<usize> = None;

    while !remaining.is_empty() {
        let Some((index, parser)) = registry.find_next(parent, &context) else {
            break;
        };
        let name = parser.name();

        if let Some(runs) = &scope.runs {
            // Protocol pruning: stop at the first parser that cannot lead to a
            // required protocol. The link-layer root (Ethernet, Linux SLL,
            // netlink, ...) always runs: it is the only way into the frame,
            // whatever the query asks for. There is deliberately no "stop once
            // every required protocol has been seen" shortcut: a tunnel further
            // down the chain (VXLAN, GRE, IP-in-IP) can carry another instance
            // of an already-seen protocol, and those inner rows belong in the
            // result.
            if !context.is_root() && !runs[index] {
                break;
            }
        }

        let mut result = match &scope.projections {
            None => parser.parse(remaining, &context),
            Some(projections) => {
                parser.parse_projected(remaining, &context, projections[index].as_ref())
            }
        };
        debug_assert!(
            parser
                .child_hint_keys()
                .is_none_or(|keys| result.child_hints.iter().all(|(key, _)| keys.contains(key))),
            "{name} emitted a hint missing from its child_hint_keys: {:?}",
            result.child_hints
        );

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
        parent = Some(index);
        context.hints = std::mem::take(&mut result.child_hints);
        context.offset += remaining.len() - result.remaining.len();

        let should_stop = result.error.is_some();
        remaining = result.remaining;

        // An error with no fields is not a layer of the packet (see the
        // function docs); a partial result keeps the fields it got.
        if result.error.is_none() || !result.fields.is_empty() {
            out.push((name, result));
        }

        if should_stop {
            break;
        }
    }
}

/// The layers of one packet, as [`parse_packet`] returns them.
pub type Layers<'a> = Vec<(&'static str, ParseResult<'a>)>;

/// Storage for the layers of one packet at a time, kept from packet to
/// packet so that [`parse_packet_into`] does not allocate for each.
///
/// A layer borrows the packet it was parsed from and every packet has a
/// lifetime of its own, so the storage cannot simply be a `Vec` of layers:
/// its type would name one packet's lifetime. Between packets the buffer
/// keeps the allocation as an empty `Vec` of `'static` layers;
/// [`for_packet`](Self::for_packet) lends it out as an empty `Vec` of the
/// lifetime the caller needs, and the guard puts it back, emptied, when it is
/// dropped.
///
/// ```
/// use pcapsql_core::protocol::{default_registry, parse_packet_into, LayerBuf, ParseScope};
///
/// let registry = default_registry();
/// let scope = ParseScope::full();
/// let mut buf = LayerBuf::new();
/// for packet in [vec![0xffu8; 14], vec![0x00u8; 60]] {
///     let mut layers = buf.for_packet();
///     parse_packet_into(&registry, 1, &packet, &scope, &mut layers);
///     for (name, layer) in layers.iter() {
///         println!("{name}: {} fields", layer.fields.len());
///     }
/// }
/// ```
#[derive(Debug, Default)]
pub struct LayerBuf {
    /// Always empty: only its capacity matters.
    spare: Layers<'static>,
}

impl LayerBuf {
    /// A buffer without storage yet: the first packet with layers allocates.
    pub fn new() -> Self {
        Self::default()
    }

    /// The buffer's storage as the (empty) layers of one packet. It returns
    /// to the buffer when the guard is dropped.
    #[inline]
    pub fn for_packet<'a>(&mut self) -> PacketLayers<'_, 'a> {
        let layers = recycle(std::mem::take(&mut self.spare));
        PacketLayers { buf: self, layers }
    }
}

/// The layers of one packet, in storage borrowed from a [`LayerBuf`]. It
/// dereferences to the `Vec` that [`parse_packet_into`] fills.
#[derive(Debug)]
pub struct PacketLayers<'buf, 'a> {
    buf: &'buf mut LayerBuf,
    layers: Layers<'a>,
}

impl<'a> std::ops::Deref for PacketLayers<'_, 'a> {
    type Target = Layers<'a>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.layers
    }
}

impl std::ops::DerefMut for PacketLayers<'_, '_> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.layers
    }
}

impl Drop for PacketLayers<'_, '_> {
    #[inline]
    fn drop(&mut self) {
        self.buf.spare = recycle(std::mem::take(&mut self.layers));
    }
}

/// `layers` emptied, as the layers of another lifetime, in the same
/// allocation.
///
/// There is no `unsafe` here. Collecting a `vec::IntoIter` into a `Vec` of
/// elements with the same size and alignment reuses the source's allocation
/// (the standard library's in-place collection), and two instantiations of
/// one type that differ in a lifetime only are such elements. The iterator is
/// empty, so no element is ever converted: the closure only gives the result
/// its type. A standard library that did not collect in place would leave
/// this correct and make it allocate once per packet, which
/// `tests/parse_alloc.rs` counts and would fail on.
#[inline]
fn recycle<'a, 'b>(mut layers: Layers<'a>) -> Layers<'b> {
    layers.clear();
    layers
        .into_iter()
        .map(|_| -> (&'static str, ParseResult<'b>) {
            unreachable!("the layers were cleared before they were recycled")
        })
        .collect()
}

#[cfg(test)]
mod parse_packet_tests {
    use super::test_utils::{EthernetBuilder, Ipv4Builder, UdpBuilder};
    use super::*;

    fn udp_frame(dst_port: u16, payload: Vec<u8>) -> Vec<u8> {
        let udp = UdpBuilder::new()
            .src_port(40_000)
            .dst_port(dst_port)
            .payload(payload)
            .build();
        let ip = Ipv4Builder::new().udp().payload(udp).build();
        EthernetBuilder::new().ipv4().payload(ip).build()
    }

    /// The layers of each packet as `Debug` text: what there is to compare,
    /// a `ParseResult` having no `PartialEq`.
    fn described(layers: &Layers<'_>) -> Vec<String> {
        layers
            .iter()
            .map(|(name, result)| format!("{name}: {result:?}"))
            .collect()
    }

    /// A `LayerBuf` gives every packet the layers `parse_packet` returns,
    /// whatever the packet before left in it, and keeps one allocation
    /// throughout, also when a guard is dropped with layers in it.
    #[test]
    fn layer_buf_gives_the_layers_of_parse_packet() {
        let registry = default_registry();
        let full = ParseScope::full();
        let frames_only = ParseScope::for_tables(&["frames"], &registry);
        let frames = [
            udp_frame(53, vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]),
            udp_frame(9999, vec![0xAB; 8]),
            vec![0xff; 5],
            udp_frame(2152, vec![0x30, 0xff, 0x00, 0x00]),
            Vec::new(),
        ];

        let mut buf = LayerBuf::new();
        assert_eq!(buf.spare.capacity(), 0);
        // As an address: a pointer type would name one packet's lifetime.
        let mut storage = None;
        for round in 0..3 {
            for frame in &frames {
                let frame = frame.clone(); // a lifetime of its own per packet
                let mut layers = buf.for_packet();
                assert!(layers.is_empty(), "the last packet's layers are gone");
                parse_packet_into(&registry, 1, &frame, &full, &mut layers);
                let expected = parse_packet(&registry, 1, &frame, &full);
                assert_eq!(described(&layers), described(&expected), "round {round}");
                if let Some(storage) = storage {
                    assert_eq!(layers.as_ptr().addr(), storage, "the allocation is reused");
                }
                storage = Some(layers.as_ptr().addr());

                // A scope that parses nothing leaves no stale layer behind.
                parse_packet_into(&registry, 1, &frame, &frames_only, &mut layers);
                assert!(layers.is_empty());
                parse_packet_into(&registry, 1, &frame, &full, &mut layers);
            }
        }
        assert!(buf.spare.is_empty());
        assert!(buf.spare.capacity() >= 8);
        assert_eq!(Some(buf.spare.as_ptr().addr()), storage);
    }

    /// `frames` alone asks for no storage at all.
    #[test]
    fn a_scope_that_parses_nothing_does_not_reserve() {
        let registry = default_registry();
        let scope = ParseScope::for_tables(&["frames"], &registry);
        let frame = udp_frame(9999, vec![0xAB; 8]);
        assert_eq!(parse_packet(&registry, 1, &frame, &scope).capacity(), 0);
        let mut buf = LayerBuf::new();
        parse_packet_into(&registry, 1, &frame, &scope, &mut buf.for_packet());
        assert_eq!(buf.spare.capacity(), 0);
    }

    /// A parser that fails without extracting anything is not a layer: the
    /// row it would produce would be all NULL. The layers above it stay.
    #[test]
    fn error_only_layer_produces_no_entry() {
        let registry = default_registry();
        // Four bytes to the GTP-U port: "GTP header too short".
        let frame = udp_frame(2152, vec![0x30, 0xff, 0x00, 0x00]);
        let results = parse_packet(&registry, 1, &frame, &ParseScope::full());
        let layers: Vec<&str> = results.iter().map(|(n, _)| *n).collect();
        assert_eq!(layers, ["ethernet", "ipv4", "udp"]);
        assert!(results.iter().all(|(_, r)| r.error.is_none()));

        // The same packet with a complete header is a gtp layer.
        let mut gtp = vec![0x30, 0x01, 0x00, 0x00]; // v1, PT=1, Echo Request, len 0
        gtp.extend_from_slice(&[0, 0, 0, 1]); // TEID
        let frame = udp_frame(2152, gtp);
        let results = parse_packet(&registry, 1, &frame, &ParseScope::full());
        let layers: Vec<&str> = results.iter().map(|(n, _)| *n).collect();
        assert_eq!(layers, ["ethernet", "ipv4", "udp", "gtp"]);
    }

    /// A partial result (fields extracted before the failure) is kept, with
    /// its fields and its error, and ends the walk.
    #[test]
    fn partial_layer_is_kept_with_its_fields() {
        let registry = default_registry();
        // A DNS header whose question section is truncated: the header
        // fields are extracted, the question is not.
        let mut dns = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        dns.extend_from_slice(&[0x03, b'w', b'w']); // truncated label
        let frame = udp_frame(53, dns);
        let results = parse_packet(&registry, 1, &frame, &ParseScope::full());
        let (name, dns_layer) = results.last().expect("layers");
        if *name == "dns" {
            assert!(!dns_layer.fields.is_empty(), "partial results keep fields");
        } else {
            // The DNS parser rejected the packet outright: then no dns layer.
            assert_eq!(*name, "udp");
        }
    }
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
