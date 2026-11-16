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
//! use pcapsql_core::protocol::{default_registry, parse_packet, ParseBuf, ParseScope};
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
//! let mut buf = ParseBuf::new();
//! let layers = parse_packet(&registry, 1, packet_data, &ParseScope::full(), &mut buf);
//! for layer in layers.iter() {
//!     let field_names: Vec<_> = layer.fields().iter().map(|(k, _)| *k).collect();
//!     println!("Parsed {}: {:?}", layer.name(), field_names);
//! }
//! ```

mod context;
mod field;
mod layers;
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

pub use context::{FieldEntry, HintKey, Hints, ParseContext, TunnelLayer, TunnelType};
pub use field::FieldValue;
pub use layers::{
    FieldHint, FieldSink, LayerRef, ListBuilder, PacketLayers, ParseBuf, Parsed, Status,
    TextBuilder,
};
pub use projection::{
    chain_fields_for_protocol, merge_with_chain_fields, FieldSet, ProjectionConfig,
};
pub(crate) use projection::{field_list, ParserField};
pub use pruning::{compute_required_protocols, should_run_parser};
pub use registry::{
    BuiltinProtocol, Cond, Dispatch, DispatchRule, PayloadMode, Protocol, ProtocolRegistry,
    CONTENT_PRIORITY, PORT_PRIORITY_MAX,
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
    /// Per parser: the fields it extracts, resolved against its field list
    /// (`None`: all of them, with `parse` rather than `parse_projected`).
    /// `None` for the whole when the scope projects nothing.
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

    /// Restrict the fields extracted for one protocol to `fields`. With no
    /// field, the protocol's layers are parsed for what the layers after
    /// them need and carry no field. A protocol whose parser has no field
    /// list ([`Protocol::field_names`]) has no projected parse: its layers
    /// carry every field, whatever the projection.
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
    /// parsed with all its fields, and so is one whose parser has no field
    /// list, whatever its entry; the scope a scan plan compiles gives those
    /// no entry.
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
                    .map(|p| {
                        let names = self.projections.get(p.name())?;
                        project(p.field_names(), names)
                    })
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

/// The fields `names` of a parser with the field list `fields`, for its
/// projected parse; `None` when its full parse gives the same: it has no
/// projected parse (no list), or every field of the list is asked for.
fn project(fields: &[&str], names: &HashSet<String>) -> Option<FieldSet> {
    if fields.is_empty() || fields.len() > FieldSet::CAPACITY {
        return None;
    }
    let set = FieldSet::resolve(fields, names);
    (set != FieldSet::all_of(fields.len())).then_some(set)
}

/// Parse a packet through its protocol layers, scoped by `scope`, into the
/// storage of `buf`.
///
/// With [`ParseScope::full`] every matching protocol is parsed with all
/// fields. A scoped parse prunes the protocol walk (never descending into
/// branches that cannot reach a required protocol) and projects fields within
/// parsers that support it. Intermediate layers on the path to a required
/// protocol are still returned — they may be needed for joins.
///
/// For tunneled traffic, encapsulation depth and tunnel context are tracked;
/// each layer carries its `encap_depth`, `tunnel_type` and `tunnel_id`. A
/// tunnel is a protocol that carries a whole inner packet (VXLAN, GRE, GTP,
/// IPsec, IP-in-IP); MPLS label switching is not one, so an MPLS stack
/// neither increments `encap_depth` nor sets `tunnel_type` on the layers
/// below it.
///
/// # Parse errors
///
/// A parser that fails outright ([`Status::Error`]: a truncated or malformed
/// header) ends the walk and is *not* part of the returned layers: a table
/// row with every column NULL would say nothing about the packet and would
/// still be counted by `count(*)`. A parser that extracted some fields before
/// failing ([`Status::Partial`]) is kept with those fields and ends the walk
/// as well. The outer layers that were parsed successfully are always
/// returned.
///
/// # Storage
///
/// The layers live in `buf` and borrow it: they are read before the next
/// packet is parsed into the same buffer. A caller that parses packet after
/// packet keeps one [`ParseBuf`], and after the first packets nothing is
/// allocated.
#[inline]
pub fn parse_packet<'buf, 'a>(
    registry: &ProtocolRegistry,
    link_type: u16,
    data: &'a [u8],
    scope: &ParseScope,
    buf: &'buf mut ParseBuf,
) -> PacketLayers<'buf, 'a>
where
    'buf: 'a,
{
    let mut layers = buf.for_packet();
    walk(registry, link_type, data, scope, &mut layers);
    layers
}

/// The walk of [`parse_packet`]: append the layers of `data` to `out`.
fn walk<'a>(
    registry: &ProtocolRegistry,
    link_type: u16,
    data: &'a [u8],
    scope: &ParseScope,
    out: &mut PacketLayers<'_, 'a>,
) {
    let scope = scope.resolved_for(registry);

    // A scope that needs no protocol table at all (`frames` only) parses
    // nothing: the frame columns come from the record header.
    if scope.parses_nothing {
        return;
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

        // The layer is recorded with the encapsulation state it was parsed
        // in, before the context moves on. An error with no fields is not a
        // layer of the packet (see the function docs); a partial result keeps
        // the fields it got.
        let projection = match &scope.projections {
            None => None,
            Some(projections) => projections[index],
        };
        let parsed = out.parse_layer(parser, remaining, &context, projection);
        debug_assert!(
            parser.child_hint_keys().is_none_or(|keys| parsed
                .child_hints
                .iter()
                .all(|(key, _)| keys.contains(&key))),
            "{name} emitted a hint missing from its child_hint_keys: {:?}",
            parsed.child_hints
        );
        if !parsed.is_ok() {
            break;
        }

        // A tunnel boundary updates context for the inner layers.
        if let Some(tunnel_type_val) = parsed.hint(HintKey::TunnelType) {
            let tunnel_id = parsed.hint(HintKey::TunnelId);
            context.push_tunnel(TunnelType::from_u64(tunnel_type_val), tunnel_id);
        }

        // Update context for the next layer.
        context.parent_protocol = Some(name);
        parent = Some(index);
        context.hints = parsed.child_hints;
        context.offset += remaining.len() - parsed.remaining.len();
        remaining = parsed.remaining;
    }
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

    /// The layers of a packet as `Debug` text.
    fn described(layers: &PacketLayers<'_, '_>) -> Vec<String> {
        layers.iter().map(|layer| format!("{layer:?}")).collect()
    }

    /// A `ParseBuf` gives every packet the layers a fresh buffer gives it,
    /// whatever the packet before left in it, and keeps its allocations
    /// throughout.
    #[test]
    fn parse_buf_is_reused_from_packet_to_packet() {
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

        let mut buf = ParseBuf::new();
        // As addresses: a pointer type would name one packet's lifetime.
        let mut storage = None;
        for round in 0..3 {
            for frame in &frames {
                let frame = frame.clone(); // a lifetime of its own per packet
                let mut fresh = ParseBuf::new();
                let expected = described(&parse_packet(&registry, 1, &frame, &full, &mut fresh));
                let layers = parse_packet(&registry, 1, &frame, &full, &mut buf);
                assert_eq!(described(&layers), expected, "round {round}");
                let at = layers.storage();
                if let Some(storage) = storage {
                    assert_eq!(at, storage, "the allocations are reused");
                }
                storage = Some(at);
                drop(layers);

                // A scope that parses nothing leaves no stale layer behind.
                assert!(parse_packet(&registry, 1, &frame, &frames_only, &mut buf).is_empty());
            }
        }
        let (fields, layers) = buf.capacity();
        assert!(
            fields >= 8 && layers >= 4,
            "{fields} fields, {layers} layers"
        );
    }

    /// `frames` alone asks for no storage at all.
    #[test]
    fn a_scope_that_parses_nothing_does_not_reserve() {
        let registry = default_registry();
        let scope = ParseScope::for_tables(&["frames"], &registry);
        let frame = udp_frame(9999, vec![0xAB; 8]);
        let mut buf = ParseBuf::new();
        assert!(parse_packet(&registry, 1, &frame, &scope, &mut buf).is_empty());
        assert_eq!(buf.capacity(), (0, 0));
    }

    /// A parser that fails without extracting anything is not a layer: the
    /// row it would produce would be all NULL. The layers above it stay.
    #[test]
    fn error_only_layer_produces_no_entry() {
        let registry = default_registry();
        let mut buf = ParseBuf::new();
        // Four bytes to the GTP-U port: "GTP header too short".
        let frame = udp_frame(2152, vec![0x30, 0xff, 0x00, 0x00]);
        let layers = parse_packet(&registry, 1, &frame, &ParseScope::full(), &mut buf);
        assert_eq!(
            layers.names().collect::<Vec<_>>(),
            ["ethernet", "ipv4", "udp"]
        );
        assert!(layers.iter().all(|layer| layer.error().is_none()));
        drop(layers);

        // The same packet with a complete header is a gtp layer.
        let mut gtp = vec![0x30, 0x01, 0x00, 0x00]; // v1, PT=1, Echo Request, len 0
        gtp.extend_from_slice(&[0, 0, 0, 1]); // TEID
        let frame = udp_frame(2152, gtp);
        let layers = parse_packet(&registry, 1, &frame, &ParseScope::full(), &mut buf);
        assert_eq!(
            layers.names().collect::<Vec<_>>(),
            ["ethernet", "ipv4", "udp", "gtp"]
        );
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
        let mut buf = ParseBuf::new();
        let layers = parse_packet(&registry, 1, &frame, &ParseScope::full(), &mut buf);
        let dns_layer = layers.last().expect("layers");
        if dns_layer.name() == "dns" {
            assert!(
                !dns_layer.fields().is_empty(),
                "partial results keep fields"
            );
            assert!(dns_layer.error().is_some());
        } else {
            // The DNS parser rejected the packet outright: then no dns layer.
            assert_eq!(dns_layer.name(), "udp");
        }
    }

    /// A hand-built layer reads like a parsed one, and a hinted lookup
    /// follows a field that moves.
    #[test]
    fn hinted_get_follows_the_field() {
        let mut buf = ParseBuf::new();
        let mut layers = buf.for_packet();
        let row = |layers: &mut PacketLayers<'_, '_>, names: &[&'static str]| {
            let fields: Vec<_> = names
                .iter()
                .enumerate()
                .map(|(i, n)| (*n, FieldValue::UInt16(i as u16)))
                .collect();
            layers.push_layer(LayerRef::new("udp", &fields));
        };
        row(&mut layers, &["src_port", "dst_port", "length"]);
        // The field moved (a projected parse, or another parser's layout).
        row(&mut layers, &["dst_port", "length"]);
        // Absent.
        row(&mut layers, &["length"]);
        let (a, b, c) = (
            layers.get(0).unwrap(),
            layers.get(1).unwrap(),
            layers.get(2).unwrap(),
        );
        assert_eq!(a.fields().len(), 3);
        assert_eq!(b.fields()[0].0, "dst_port");

        let mut hint = FieldHint::default();
        let one = FieldValue::UInt16(1);
        let zero = FieldValue::UInt16(0);
        assert_eq!(a.get_hinted("dst_port", &mut hint), Some(&one));
        assert_eq!(a.get_hinted("dst_port", &mut hint), Some(&one));
        assert_eq!(b.get_hinted("dst_port", &mut hint), Some(&zero));
        // Absent: None, and the hint stays.
        assert_eq!(c.get_hinted("dst_port", &mut hint), None);
        assert_eq!(b.get_hinted("dst_port", &mut hint), Some(&zero));
        assert_eq!(a.get_hinted("dst_port", &mut hint), Some(&one));
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
