//! Protocol registry for managing parsers.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::schema::FieldDescriptor;

use super::{
    ArpProtocol, BgpProtocol, DhcpProtocol, DnsProtocol, EthernetProtocol, FieldSet, GreProtocol,
    GtpProtocol, HttpProtocol, IcmpProtocol, Icmpv6Protocol, IpsecProtocol, Ipv4Protocol,
    Ipv6Protocol, LinuxSllProtocol, MplsProtocol, NetlinkProtocol, NtpProtocol, OspfProtocol,
    ParseContext, ParseResult, QuicProtocol, RtnetlinkProtocol, Sll2Protocol, SshProtocol,
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

/// The highest priority a parser may return from port numbers alone.
///
/// A port is a guess: any service can run on any port, and nothing but the
/// number says the bytes are this protocol. Parsers that match on
/// `src_port`/`dst_port` (DNS, NTP, DHCP, BGP, TLS, SSH, ...) return this
/// or less, so that a parser with a positive content signal always wins
/// (see [`CONTENT_PRIORITY`]). Enforced by a registry test.
pub const PORT_PRIORITY_MAX: u32 = 100;

/// Priority for a parser whose parent layer sniffed the payload and
/// recognised this protocol's message start (TCP sets `http_payload` for an
/// HTTP/1.x request or status line). Above [`PORT_PRIORITY_MAX`], so content
/// outranks a port guess: plaintext HTTP to port 8443 is parsed as `http`,
/// not reported as a `tls` error row.
pub const CONTENT_PRIORITY: u32 = 200;

// On a tie the registry runs the parser registered later in
// `default_registry()` (`find_parser` uses `max_by_key`, which keeps the last
// maximum): TCP 53 -> 179 is DNS, not BGP; UDP 53 -> 123 is NTP, not DNS.

const _: () = assert!(CONTENT_PRIORITY > PORT_PRIORITY_MAX);

/// A condition [`Protocol::can_parse`] needs before it can return `Some`.
///
/// The registry uses a parser's gates to skip it where it cannot match: a
/// parser gated on `Hint("ethertype")` is only asked after a layer that can
/// emit an `ethertype` hint (see [`Protocol::child_hint_keys`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseGate {
    /// The context is the packet's first layer (`ParseContext::is_root`).
    Root,
    /// The context carries this hint key.
    Hint(&'static str),
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
    /// Returns a priority score (higher = more specific match); the registry
    /// runs the candidate with the highest score. A match on port numbers
    /// alone returns at most [`PORT_PRIORITY_MAX`]; a match the parent layer
    /// confirmed by looking at the payload returns [`CONTENT_PRIORITY`].
    /// Returns `None` if this parser cannot handle the context.
    fn can_parse(&self, context: &ParseContext) -> Option<u32>;

    /// The conditions `can_parse` needs: it returns `None` unless at least
    /// one of them holds. Empty (the default) promises nothing, and the
    /// parser is asked after every layer.
    fn parse_gates(&self) -> &'static [ParseGate] {
        &[]
    }

    /// Every hint key this parser may put in `ParseResult::child_hints`.
    /// `None` (the default) means unknown: every parser is asked after this
    /// one. A key missing from the list hides the parsers gated on it, so the
    /// list must be complete (debug builds check each result against it).
    fn child_hint_keys(&self) -> Option<&'static [&'static str]> {
        None
    }

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
        _fields: Option<&FieldSet>,
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
    LinuxSll(LinuxSllProtocol),
    Sll2(Sll2Protocol),
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
    Http(HttpProtocol),
    Tls(TlsProtocol),
    Ssh(SshProtocol),
    Quic(QuicProtocol),
    Netlink(NetlinkProtocol),
    Rtnetlink(RtnetlinkProtocol),
}

/// Macro to delegate Protocol trait methods to inner types.
macro_rules! delegate_protocol {
    ($self:expr, $method:ident $(, $arg:expr)*) => {
        match $self {
            BuiltinProtocol::Ethernet(p) => p.$method($($arg),*),
            BuiltinProtocol::LinuxSll(p) => p.$method($($arg),*),
            BuiltinProtocol::Sll2(p) => p.$method($($arg),*),
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
            BuiltinProtocol::Http(p) => p.$method($($arg),*),
            BuiltinProtocol::Tls(p) => p.$method($($arg),*),
            BuiltinProtocol::Ssh(p) => p.$method($($arg),*),
            BuiltinProtocol::Quic(p) => p.$method($($arg),*),
            BuiltinProtocol::Netlink(p) => p.$method($($arg),*),
            BuiltinProtocol::Rtnetlink(p) => p.$method($($arg),*),
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
    fn parse_gates(&self) -> &'static [ParseGate] {
        delegate_protocol!(self, parse_gates)
    }

    #[inline]
    fn child_hint_keys(&self) -> Option<&'static [&'static str]> {
        delegate_protocol!(self, child_hint_keys)
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
        fields: Option<&FieldSet>,
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

impl From<LinuxSllProtocol> for BuiltinProtocol {
    fn from(p: LinuxSllProtocol) -> Self {
        BuiltinProtocol::LinuxSll(p)
    }
}

impl From<Sll2Protocol> for BuiltinProtocol {
    fn from(p: Sll2Protocol) -> Self {
        BuiltinProtocol::Sll2(p)
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

impl From<HttpProtocol> for BuiltinProtocol {
    fn from(p: HttpProtocol) -> Self {
        BuiltinProtocol::Http(p)
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

impl From<NetlinkProtocol> for BuiltinProtocol {
    fn from(p: NetlinkProtocol) -> Self {
        BuiltinProtocol::Netlink(p)
    }
}

impl From<RtnetlinkProtocol> for BuiltinProtocol {
    fn from(p: RtnetlinkProtocol) -> Self {
        BuiltinProtocol::Rtnetlink(p)
    }
}

/// Registry for protocol parsers with priority-based selection.
///
/// Uses static dispatch via enum for all built-in protocols,
/// avoiding vtable overhead and enabling compiler optimizations.
///
/// Besides the parsers, the registry keeps, per parser, the candidates for
/// the layer that follows it: the parsers whose [`Protocol::parse_gates`] the
/// hints it emits ([`Protocol::child_hint_keys`]) can satisfy. The parse loop
/// asks only those (a handful) instead of every registered parser.
#[derive(Debug, Clone)]
pub struct ProtocolRegistry {
    parsers: Vec<BuiltinProtocol>,
    /// Indices into `parsers` of the parsers that can match a packet's first
    /// layer, ascending.
    root_candidates: Vec<usize>,
    /// For each parser (by index), the indices of the parsers that can match
    /// the layer after it, ascending.
    child_candidates: Vec<Vec<usize>>,
    /// Changes whenever the parser list does, so that a [`ParseScope`]
    /// resolved against one registry can tell it is being used with another.
    ///
    /// [`ParseScope`]: super::ParseScope
    id: u64,
}

fn next_registry_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

impl ProtocolRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            parsers: Vec::new(),
            root_candidates: Vec::new(),
            child_candidates: Vec::new(),
            id: next_registry_id(),
        }
    }

    /// Register a protocol parser.
    pub fn register<P: Into<BuiltinProtocol>>(&mut self, parser: P) {
        self.parsers.push(parser.into());
        self.index_candidates();
        self.id = next_registry_id();
    }

    /// Recompute the candidate lists from the parsers' gates and hint keys.
    fn index_candidates(&mut self) {
        let can_follow = |parser: &BuiltinProtocol, parent: Option<&BuiltinProtocol>| {
            let gates = parser.parse_gates();
            if gates.is_empty() {
                return true;
            }
            gates.iter().any(|gate| match (gate, parent) {
                (ParseGate::Root, None) => true,
                (ParseGate::Root, Some(_)) => false,
                // The first layer's context carries no hints.
                (ParseGate::Hint(_), None) => false,
                (ParseGate::Hint(key), Some(parent)) => match parent.child_hint_keys() {
                    None => true,
                    Some(keys) => keys.contains(key),
                },
            })
        };
        let candidates = |parent: Option<&BuiltinProtocol>| -> Vec<usize> {
            (0..self.parsers.len())
                .filter(|&i| can_follow(&self.parsers[i], parent))
                .collect()
        };
        self.root_candidates = candidates(None);
        self.child_candidates = self.parsers.iter().map(|p| candidates(Some(p))).collect();
    }

    /// Find the best parser for the given context.
    ///
    /// Asks every registered parser; the parse loop uses the candidate lists
    /// instead (`find_next`), which make the same choice.
    #[inline]
    pub fn find_parser(&self, context: &ParseContext) -> Option<&BuiltinProtocol> {
        self.find_index(context).map(|i| &self.parsers[i])
    }

    fn find_index(&self, context: &ParseContext) -> Option<usize> {
        self.parsers
            .iter()
            .enumerate()
            .filter_map(|(i, p)| p.can_parse(context).map(|priority| (i, priority)))
            .max_by_key(|(_, priority)| *priority)
            .map(|(i, _)| i)
    }

    /// The parser for the layer after the parser at index `parent` (`None`:
    /// the packet's first layer), with its index.
    ///
    /// The same choice as [`find_parser`](Self::find_parser): the highest
    /// priority wins and, on a tie, the parser registered last (the
    /// candidates are in registration order, and `>=` keeps the later one,
    /// as `max_by_key` does).
    #[inline]
    pub(crate) fn find_next(
        &self,
        parent: Option<usize>,
        context: &ParseContext,
    ) -> Option<(usize, &BuiltinProtocol)> {
        let candidates = match parent {
            None => &self.root_candidates,
            Some(i) => &self.child_candidates[i],
        };
        let mut best: Option<(usize, u32)> = None;
        for &i in candidates {
            if let Some(priority) = self.parsers[i].can_parse(context) {
                match best {
                    Some((_, best_priority)) if priority < best_priority => {}
                    _ => best = Some((i, priority)),
                }
            }
        }
        debug_assert_eq!(
            best.map(|(i, _)| i),
            self.find_index(context),
            "candidate lists disagree with a full scan after {:?}",
            parent.map(|i| self.parsers[i].name())
        );
        best.map(|(i, _)| (i, &self.parsers[i]))
    }

    /// Identifies this registry's parser list (see the `id` field).
    pub(crate) fn id(&self) -> u64 {
        self.id
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
        assert!(
            size <= 8,
            "BuiltinProtocol is {} bytes, expected <= 8",
            size
        );
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

    /// The candidate lists choose what a scan of every parser chooses, for
    /// contexts built from each parent's hint keys with values that select
    /// the various children (ethertypes, IP protocols, well-known ports).
    #[test]
    fn candidate_lists_match_a_full_scan() {
        let registry = crate::protocol::default_registry();
        let values: [u64; 24] = [
            0, 1, 2, 4, 6, 17, 41, 47, 50, 51, 58, 89, 22, 53, 67, 68, 123, 179, 443, 2152, 4789,
            0x0800, 0x86dd, 0x8100,
        ];
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut matched = 0;
        for (parent_index, parent) in registry.all_parsers().enumerate() {
            let keys = parent
                .child_hint_keys()
                .expect("built-ins declare their hints");
            for _ in 0..2000 {
                let mut ctx = ParseContext::new(1);
                ctx.parent_protocol = Some(parent.name());
                for key in keys {
                    if next() % 4 != 0 {
                        let value = values[(next() % values.len() as u64) as usize];
                        ctx.insert_hint(key, value);
                    }
                }
                let indexed = registry.find_next(Some(parent_index), &ctx).map(|(i, _)| i);
                assert_eq!(
                    indexed,
                    registry.find_index(&ctx),
                    "after {}",
                    parent.name()
                );
                matched += indexed.is_some() as usize;
            }
        }
        assert!(matched > 1000, "the contexts should select children");
        for link_type in [0u16, 1, 113, 253, 276] {
            let ctx = ParseContext::new(link_type);
            let indexed = registry.find_next(None, &ctx).map(|(i, _)| i);
            assert_eq!(indexed, registry.find_index(&ctx), "link type {link_type}");
        }
        // The point of the lists: few candidates per layer.
        let after_ethernet = &registry.child_candidates[0];
        assert!(after_ethernet.len() < registry.len() / 2);
    }

    /// No parser claims a transport payload from its ports alone with a
    /// priority a content-sniffed match could not beat. Every port, both
    /// directions, both transports, no payload hints.
    #[test]
    fn port_only_matches_stay_below_content_priority() {
        let registry = crate::protocol::default_registry();
        for transport in [6u64, 17] {
            let parent = if transport == 6 { "tcp" } else { "udp" };
            for port in 0..=u16::MAX as u64 {
                for (src, dst) in [(port, 40000), (40000, port)] {
                    let mut ctx = ParseContext::new(1);
                    ctx.parent_protocol = Some(parent);
                    ctx.insert_hint("src_port", src);
                    ctx.insert_hint("dst_port", dst);
                    ctx.insert_hint("transport", transport);
                    for parser in registry.all_parsers() {
                        if let Some(priority) = parser.can_parse(&ctx) {
                            assert!(
                                priority <= PORT_PRIORITY_MAX,
                                "{} claims {parent} {src}->{dst} at {priority} from ports alone",
                                parser.name()
                            );
                        }
                    }
                }
            }
        }
    }
}
