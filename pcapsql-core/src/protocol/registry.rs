//! Protocol registry for managing parsers.

use std::collections::HashSet;

use crate::schema::FieldDescriptor;

use super::{
    ArpProtocol, BgpProtocol, DhcpProtocol, DnsProtocol, EthernetProtocol, GreProtocol,
    GtpProtocol, IcmpProtocol, Icmpv6Protocol, IpsecProtocol, Ipv4Protocol, Ipv6Protocol,
    MplsProtocol, NtpProtocol, OspfProtocol, ParseContext, ParseResult, QuicProtocol, SshProtocol,
    TcpProtocol, TlsProtocol, UdpProtocol, VlanProtocol, VxlanProtocol,
};

/// How a protocol's remaining bytes should be handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadMode {
    /// Continue with parse_packet() loop (default).
    /// Remaining bytes are passed to child protocol parsers.
    Chain,

    /// Route payload to StreamManager for reassembly.
    /// Used by TCP - application protocols are parsed from reassembled streams.
    Stream,

    /// No payload / terminal protocol.
    /// Parsing stops after this protocol.
    None,
}

/// Core trait all protocol parsers must implement.
pub trait Protocol: Send + Sync {
    /// Unique identifier for this protocol (e.g., "tcp", "dns").
    fn name(&self) -> &'static str;

    /// Human-readable display name.
    fn display_name(&self) -> &'static str {
        self.name()
    }

    /// Check if this parser can handle the given context.
    /// Returns a priority score (higher = more specific match).
    /// Returns `None` if this parser cannot handle the context.
    fn can_parse(&self, context: &ParseContext) -> Option<u32>;

    /// Parse bytes into structured fields.
    fn parse<'a>(&self, data: &'a [u8], context: &ParseContext) -> ParseResult<'a>;

    /// Return the schema fields this protocol produces.
    fn schema_fields(&self) -> Vec<FieldDescriptor>;

    /// Protocols that might follow this one.
    fn child_protocols(&self) -> &[&'static str] {
        &[]
    }

    /// How should remaining bytes be handled after parsing?
    ///
    /// - `Chain`: Continue parsing with child protocols (default)
    /// - `Stream`: Route to StreamManager for TCP reassembly
    /// - `None`: Stop parsing (terminal protocol)
    fn payload_mode(&self) -> PayloadMode {
        PayloadMode::Chain
    }

    /// Protocols that must be parsed before this one can be reached.
    ///
    /// Used for protocol pruning optimization - when a query only needs
    /// certain protocols, we can skip parsing protocols not in the
    /// transitive dependency chain.
    ///
    /// Returns a list of protocol names that could appear in the parse
    /// chain before this protocol (e.g., TCP depends on ipv4, ipv6).
    fn dependencies(&self) -> &'static [&'static str] {
        &[] // Default: no dependencies (link layer protocols)
    }

    /// Parse with field projection - only extract requested fields.
    ///
    /// If `fields` is None, extract all fields (default behavior).
    /// If `fields` is Some, only extract fields in the set.
    ///
    /// Note: `frame_number` and `timestamp` are always available from
    /// the packet metadata, not from parsing.
    ///
    /// The default implementation ignores projection and calls `parse()`.
    /// Protocols can override this to skip expensive field extraction.
    fn parse_projected<'a>(
        &self,
        data: &'a [u8],
        context: &ParseContext,
        _fields: Option<&HashSet<String>>,
    ) -> ParseResult<'a> {
        // Default: ignore projection, parse everything
        self.parse(data, context)
    }

    /// Returns fields that are "cheap" to extract (header fields parsed anyway).
    ///
    /// These fields come from the basic header parse that must happen
    /// regardless of projection. Used to decide if projection is worthwhile.
    fn cheap_fields(&self) -> &'static [&'static str] {
        &[] // Default: no fields are marked as cheap
    }

    /// Returns fields that are "expensive" to extract.
    ///
    /// These fields require additional parsing beyond the basic header,
    /// such as variable-length options, compressed data, or string parsing.
    fn expensive_fields(&self) -> &'static [&'static str] {
        &[] // Default: no fields are marked as expensive
    }
}

/// Enum of all built-in protocol parsers.
///
/// This enables static dispatch (no vtable overhead) for all built-in protocols.
/// The compiler can inline match arms and optimize branch prediction.
#[derive(Debug, Clone, Copy)]
pub enum BuiltinProtocol {
    Ethernet(EthernetProtocol),
    Arp(ArpProtocol),
    Vlan(VlanProtocol),
    Mpls(MplsProtocol),
    Ipv4(Ipv4Protocol),
    Ipv6(Ipv6Protocol),
    Tcp(TcpProtocol),
    Udp(UdpProtocol),
    Icmp(IcmpProtocol),
    Icmpv6(Icmpv6Protocol),
    Gre(GreProtocol),
    Vxlan(VxlanProtocol),
    Gtp(GtpProtocol),
    Ipsec(IpsecProtocol),
    Bgp(BgpProtocol),
    Ospf(OspfProtocol),
    Dns(DnsProtocol),
    Dhcp(DhcpProtocol),
    Ntp(NtpProtocol),
    Tls(TlsProtocol),
    Ssh(SshProtocol),
    Quic(QuicProtocol),
}

/// Macro to delegate Protocol trait methods to inner types.
macro_rules! delegate_protocol {
    ($self:expr, $method:ident $(, $arg:expr)*) => {
        match $self {
            BuiltinProtocol::Ethernet(p) => p.$method($($arg),*),
            BuiltinProtocol::Arp(p) => p.$method($($arg),*),
            BuiltinProtocol::Vlan(p) => p.$method($($arg),*),
            BuiltinProtocol::Mpls(p) => p.$method($($arg),*),
            BuiltinProtocol::Ipv4(p) => p.$method($($arg),*),
            BuiltinProtocol::Ipv6(p) => p.$method($($arg),*),
            BuiltinProtocol::Tcp(p) => p.$method($($arg),*),
            BuiltinProtocol::Udp(p) => p.$method($($arg),*),
            BuiltinProtocol::Icmp(p) => p.$method($($arg),*),
            BuiltinProtocol::Icmpv6(p) => p.$method($($arg),*),
            BuiltinProtocol::Gre(p) => p.$method($($arg),*),
            BuiltinProtocol::Vxlan(p) => p.$method($($arg),*),
            BuiltinProtocol::Gtp(p) => p.$method($($arg),*),
            BuiltinProtocol::Ipsec(p) => p.$method($($arg),*),
            BuiltinProtocol::Bgp(p) => p.$method($($arg),*),
            BuiltinProtocol::Ospf(p) => p.$method($($arg),*),
            BuiltinProtocol::Dns(p) => p.$method($($arg),*),
            BuiltinProtocol::Dhcp(p) => p.$method($($arg),*),
            BuiltinProtocol::Ntp(p) => p.$method($($arg),*),
            BuiltinProtocol::Tls(p) => p.$method($($arg),*),
            BuiltinProtocol::Ssh(p) => p.$method($($arg),*),
            BuiltinProtocol::Quic(p) => p.$method($($arg),*),
        }
    };
}

impl Protocol for BuiltinProtocol {
    #[inline]
    fn name(&self) -> &'static str {
        delegate_protocol!(self, name)
    }

    #[inline]
    fn display_name(&self) -> &'static str {
        delegate_protocol!(self, display_name)
    }

    #[inline]
    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        delegate_protocol!(self, can_parse, context)
    }

    #[inline]
    fn parse<'a>(&self, data: &'a [u8], context: &ParseContext) -> ParseResult<'a> {
        delegate_protocol!(self, parse, data, context)
    }

    #[inline]
    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        delegate_protocol!(self, schema_fields)
    }

    #[inline]
    fn child_protocols(&self) -> &[&'static str] {
        delegate_protocol!(self, child_protocols)
    }

    #[inline]
    fn payload_mode(&self) -> PayloadMode {
        delegate_protocol!(self, payload_mode)
    }

    #[inline]
    fn dependencies(&self) -> &'static [&'static str] {
        delegate_protocol!(self, dependencies)
    }

    #[inline]
    fn parse_projected<'a>(
        &self,
        data: &'a [u8],
        context: &ParseContext,
        fields: Option<&HashSet<String>>,
    ) -> ParseResult<'a> {
        delegate_protocol!(self, parse_projected, data, context, fields)
    }

    #[inline]
    fn cheap_fields(&self) -> &'static [&'static str] {
        delegate_protocol!(self, cheap_fields)
    }

    #[inline]
    fn expensive_fields(&self) -> &'static [&'static str] {
        delegate_protocol!(self, expensive_fields)
    }
}

/// Conversion traits for ergonomic registration.
impl From<EthernetProtocol> for BuiltinProtocol {
    fn from(p: EthernetProtocol) -> Self {
        BuiltinProtocol::Ethernet(p)
    }
}

impl From<ArpProtocol> for BuiltinProtocol {
    fn from(p: ArpProtocol) -> Self {
        BuiltinProtocol::Arp(p)
    }
}

impl From<VlanProtocol> for BuiltinProtocol {
    fn from(p: VlanProtocol) -> Self {
        BuiltinProtocol::Vlan(p)
    }
}

impl From<MplsProtocol> for BuiltinProtocol {
    fn from(p: MplsProtocol) -> Self {
        BuiltinProtocol::Mpls(p)
    }
}

impl From<Ipv4Protocol> for BuiltinProtocol {
    fn from(p: Ipv4Protocol) -> Self {
        BuiltinProtocol::Ipv4(p)
    }
}

impl From<Ipv6Protocol> for BuiltinProtocol {
    fn from(p: Ipv6Protocol) -> Self {
        BuiltinProtocol::Ipv6(p)
    }
}

impl From<TcpProtocol> for BuiltinProtocol {
    fn from(p: TcpProtocol) -> Self {
        BuiltinProtocol::Tcp(p)
    }
}

impl From<UdpProtocol> for BuiltinProtocol {
    fn from(p: UdpProtocol) -> Self {
        BuiltinProtocol::Udp(p)
    }
}

impl From<IcmpProtocol> for BuiltinProtocol {
    fn from(p: IcmpProtocol) -> Self {
        BuiltinProtocol::Icmp(p)
    }
}

impl From<Icmpv6Protocol> for BuiltinProtocol {
    fn from(p: Icmpv6Protocol) -> Self {
        BuiltinProtocol::Icmpv6(p)
    }
}

impl From<GreProtocol> for BuiltinProtocol {
    fn from(p: GreProtocol) -> Self {
        BuiltinProtocol::Gre(p)
    }
}

impl From<VxlanProtocol> for BuiltinProtocol {
    fn from(p: VxlanProtocol) -> Self {
        BuiltinProtocol::Vxlan(p)
    }
}

impl From<GtpProtocol> for BuiltinProtocol {
    fn from(p: GtpProtocol) -> Self {
        BuiltinProtocol::Gtp(p)
    }
}

impl From<IpsecProtocol> for BuiltinProtocol {
    fn from(p: IpsecProtocol) -> Self {
        BuiltinProtocol::Ipsec(p)
    }
}

impl From<BgpProtocol> for BuiltinProtocol {
    fn from(p: BgpProtocol) -> Self {
        BuiltinProtocol::Bgp(p)
    }
}

impl From<OspfProtocol> for BuiltinProtocol {
    fn from(p: OspfProtocol) -> Self {
        BuiltinProtocol::Ospf(p)
    }
}

impl From<DnsProtocol> for BuiltinProtocol {
    fn from(p: DnsProtocol) -> Self {
        BuiltinProtocol::Dns(p)
    }
}

impl From<DhcpProtocol> for BuiltinProtocol {
    fn from(p: DhcpProtocol) -> Self {
        BuiltinProtocol::Dhcp(p)
    }
}

impl From<NtpProtocol> for BuiltinProtocol {
    fn from(p: NtpProtocol) -> Self {
        BuiltinProtocol::Ntp(p)
    }
}

impl From<TlsProtocol> for BuiltinProtocol {
    fn from(p: TlsProtocol) -> Self {
        BuiltinProtocol::Tls(p)
    }
}

impl From<SshProtocol> for BuiltinProtocol {
    fn from(p: SshProtocol) -> Self {
        BuiltinProtocol::Ssh(p)
    }
}

impl From<QuicProtocol> for BuiltinProtocol {
    fn from(p: QuicProtocol) -> Self {
        BuiltinProtocol::Quic(p)
    }
}

/// Registry for protocol parsers with priority-based selection.
///
/// Uses static dispatch via enum for all built-in protocols,
/// avoiding vtable overhead and enabling compiler optimizations.
#[derive(Debug, Clone)]
pub struct ProtocolRegistry {
    parsers: Vec<BuiltinProtocol>,
}

impl ProtocolRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            parsers: Vec::new(),
        }
    }

    /// Register a protocol parser.
    pub fn register<P: Into<BuiltinProtocol>>(&mut self, parser: P) {
        self.parsers.push(parser.into());
    }

    /// Find the best parser for the given context.
    #[inline]
    pub fn find_parser(&self, context: &ParseContext) -> Option<&BuiltinProtocol> {
        self.parsers
            .iter()
            .filter_map(|p| p.can_parse(context).map(|priority| (p, priority)))
            .max_by_key(|(_, priority)| *priority)
            .map(|(parser, _)| parser)
    }

    /// Get all registered parsers.
    pub fn all_parsers(&self) -> impl Iterator<Item = &BuiltinProtocol> {
        self.parsers.iter()
    }

    /// Get a parser by name.
    pub fn get_parser(&self, name: &str) -> Option<&BuiltinProtocol> {
        self.parsers.iter().find(|p| p.name() == name)
    }

    /// Build combined schema from all parsers.
    pub fn combined_schema(&self) -> Vec<FieldDescriptor> {
        let mut fields = Vec::new();
        for parser in &self.parsers {
            fields.extend(parser.schema_fields());
        }
        fields
    }

    /// Get the number of registered parsers.
    pub fn len(&self) -> usize {
        self.parsers.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.parsers.is_empty()
    }
}

impl Default for ProtocolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_protocol_size() {
        // Ensure the enum is reasonably sized (no large variants bloating it)
        let size = std::mem::size_of::<BuiltinProtocol>();
        // All our protocols are zero-sized unit structs, so enum is just the discriminant
        assert!(size <= 8, "BuiltinProtocol is {} bytes, expected <= 8", size);
    }

    #[test]
    fn test_registry_static_dispatch() {
        let mut registry = ProtocolRegistry::new();
        registry.register(EthernetProtocol);
        registry.register(Ipv4Protocol);
        registry.register(TcpProtocol);

        assert_eq!(registry.len(), 3);

        // Test that we can find parsers
        let ctx = ParseContext::new(1); // Ethernet link type
        let parser = registry.find_parser(&ctx);
        assert!(parser.is_some());
        assert_eq!(parser.unwrap().name(), "ethernet");
    }

    #[test]
    fn test_get_parser_by_name() {
        let mut registry = ProtocolRegistry::new();
        registry.register(TcpProtocol);
        registry.register(UdpProtocol);

        assert!(registry.get_parser("tcp").is_some());
        assert!(registry.get_parser("udp").is_some());
        assert!(registry.get_parser("unknown").is_none());
    }
}
