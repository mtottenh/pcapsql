//! Protocol registry for managing parsers.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::schema::FieldDescriptor;

use super::{
    ArpProtocol, BgpProtocol, DhcpProtocol, DnsProtocol, EthernetProtocol, FieldSet, GreProtocol,
    GtpProtocol, HintKey, Hints, HttpProtocol, IcmpProtocol, Icmpv6Protocol, IpsecProtocol,
    Ipv4Protocol, Ipv6Protocol, LinuxSllProtocol, MplsProtocol, NetlinkProtocol, NtpProtocol,
    OspfProtocol, ParseContext, ParseResult, QuicProtocol, RtnetlinkProtocol, Sll2Protocol,
    SshProtocol, TcpProtocol, TlsProtocol, UdpProtocol, VlanProtocol, VxlanProtocol,
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

/// One condition of a [`DispatchRule`], on the hints the parent layer left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cond {
    /// The hint is set, to one of these values.
    Hint(HintKey, &'static [u64]),
    /// The source port or the destination port ([`HintKey::SrcPort`],
    /// [`HintKey::DstPort`]) is one of these values.
    Port(&'static [u64]),
}

impl Cond {
    /// The parent transport is TCP (as `ParseContext::over_tcp`).
    pub const OVER_TCP: Cond = Cond::Hint(HintKey::Transport, &[6]);
    /// The parent transport is UDP (as `ParseContext::over_udp`).
    pub const OVER_UDP: Cond = Cond::Hint(HintKey::Transport, &[17]);
    /// The parent transport is TCP or UDP.
    pub const OVER_TCP_OR_UDP: Cond = Cond::Hint(HintKey::Transport, &[6, 17]);

    #[inline]
    fn holds(&self, hints: &Hints) -> bool {
        let among = |key: HintKey, values: &[u64]| {
            hints.get(key).is_some_and(|value| values.contains(&value))
        };
        match *self {
            Cond::Hint(key, values) => among(key, values),
            Cond::Port(values) => {
                among(HintKey::SrcPort, values) || among(HintKey::DstPort, values)
            }
        }
    }

    /// Whether the condition can hold after a parser that emits `keys`
    /// (`None`: any key).
    fn possible_after(&self, keys: Option<&[HintKey]>) -> bool {
        let emitted = |key: &HintKey| keys.is_none_or(|keys| keys.contains(key));
        match self {
            Cond::Hint(key, _) => emitted(key),
            Cond::Port(_) => emitted(&HintKey::SrcPort) || emitted(&HintKey::DstPort),
        }
    }
}

/// One way for a parser to match a layer: see [`Dispatch::Exact`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchRule {
    /// The packet's first layer (`ParseContext::is_root`), in a capture of
    /// this link type.
    Root {
        /// The capture's link type.
        link_type: u16,
        /// What `can_parse` returns for the match.
        priority: u32,
    },
    /// A layer whose context carries hints for which every condition holds.
    Hints {
        /// When not empty: the parent layer (`ParseContext::parent_protocol`)
        /// is one of these parsers.
        after: &'static [&'static str],
        /// The conditions, of which there is at least one. The registry
        /// looks a layer's parser up by the first, so that is the most
        /// selective one (a port rather than the transport).
        all: &'static [Cond],
        /// What `can_parse` returns for the match.
        priority: u32,
    },
}

impl DispatchRule {
    /// A [`DispatchRule::Hints`] after any parser.
    pub const fn hints(all: &'static [Cond], priority: u32) -> Self {
        DispatchRule::Hints {
            after: &[],
            all,
            priority,
        }
    }

    fn matches(&self, context: &ParseContext) -> Option<u32> {
        match *self {
            DispatchRule::Root {
                link_type,
                priority,
            } => (context.is_root() && context.link_type == link_type).then_some(priority),
            DispatchRule::Hints {
                after,
                all,
                priority,
            } => {
                let parent_ok = after.is_empty()
                    || context
                        .parent_protocol
                        .is_some_and(|parent| after.contains(&parent));
                (parent_ok && all.iter().all(|cond| cond.holds(&context.hints))).then_some(priority)
            }
        }
    }
}

/// How the registry finds out whether a parser handles a layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dispatch {
    /// [`Protocol::can_parse`] is exactly these rules: it returns the highest
    /// priority among the rules that match the context and `None` when none
    /// does. The registry puts the rules in tables keyed by hint and value
    /// and does not call `can_parse` in the parse loop. Debug builds check
    /// every choice the tables make against a scan of every parser's
    /// `can_parse`.
    Exact(&'static [DispatchRule]),
    /// `can_parse` decides something rules cannot say; the registry calls it
    /// for every layer.
    Probe,
}

impl Dispatch {
    /// What the rules say `can_parse` returns for `context`; `None` for
    /// [`Dispatch::Probe`], which says nothing.
    pub fn evaluate(&self, context: &ParseContext) -> Option<Option<u32>> {
        match self {
            Dispatch::Exact(rules) => {
                Some(rules.iter().filter_map(|rule| rule.matches(context)).max())
            }
            Dispatch::Probe => None,
        }
    }
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

    /// `can_parse` as rules the registry can put in a table, when it is
    /// nothing but a match on the link type or on hint values. The default,
    /// [`Dispatch::Probe`], has the registry call `can_parse` for every
    /// layer.
    fn dispatch(&self) -> Dispatch {
        Dispatch::Probe
    }

    /// Every hint key this parser may put in `ParseResult::child_hints`.
    /// `None` (the default) means unknown: every rule is kept for the layer
    /// after this one. A key missing from the list hides the parsers whose
    /// rules need it, so the list must be complete (debug builds check each
    /// result against it).
    fn child_hint_keys(&self) -> Option<&'static [HintKey]> {
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
    fn dispatch(&self) -> Dispatch {
        delegate_protocol!(self, dispatch)
    }

    #[inline]
    fn child_hint_keys(&self) -> Option<&'static [HintKey]> {
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

/// A rule of a parser, filed under one value of the hint its first
/// condition is on.
#[derive(Debug, Clone, Copy)]
struct TableEntry {
    value: u64,
    /// Index of the parser in the registry.
    parser: usize,
    priority: u32,
    /// The rule's other conditions.
    rest: &'static [Cond],
}

/// The parsers that can follow one parser (or start a packet).
#[derive(Debug, Clone, Default)]
struct NextLayer {
    /// Per hint key that a rule starts with: the entries, ascending by
    /// value.
    tables: Vec<(HintKey, Vec<TableEntry>)>,
    /// Indices of the [`Dispatch::Probe`] parsers, which are asked.
    probes: Vec<usize>,
}

/// A parser that starts the packets of one link type.
#[derive(Debug, Clone, Copy)]
struct RootEntry {
    link_type: u16,
    parser: usize,
    priority: u32,
}

/// Registry for protocol parsers with priority-based selection.
///
/// Uses static dispatch via enum for all built-in protocols,
/// avoiding vtable overhead and enabling compiler optimizations.
///
/// Besides the parsers, the registry keeps their [`Dispatch`] rules in
/// tables: for a packet's first layer by link type, and per parser, for the
/// layer that follows it, by hint key and value (only the rules whose hints
/// that parser can emit, see [`Protocol::child_hint_keys`]). The parse loop
/// looks the next parser up there, and calls `can_parse` only for the
/// parsers without rules.
#[derive(Debug, Clone)]
pub struct ProtocolRegistry {
    parsers: Vec<BuiltinProtocol>,
    /// The parsers with a [`DispatchRule::Root`], one entry per rule.
    roots: Vec<RootEntry>,
    /// For a packet's first layer: no tables (its context has no hints),
    /// the probe parsers only.
    root: NextLayer,
    /// For each parser (by index), what can follow it.
    children: Vec<NextLayer>,
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

/// The better of two candidates: the higher priority and, on a tie, the
/// parser registered later (what `max_by_key` over the parsers in
/// registration order gives).
#[inline]
fn offer(best: &mut Option<(u32, usize)>, priority: u32, parser: usize) {
    if best.is_none_or(|best| (priority, parser) >= best) {
        *best = Some((priority, parser));
    }
}

impl ProtocolRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            parsers: Vec::new(),
            roots: Vec::new(),
            root: NextLayer::default(),
            children: Vec::new(),
            id: next_registry_id(),
        }
    }

    /// Register a protocol parser.
    ///
    /// # Panics
    ///
    /// When the parser's [`Dispatch`] has a hint rule without a condition.
    pub fn register<P: Into<BuiltinProtocol>>(&mut self, parser: P) {
        self.parsers.push(parser.into());
        self.index_dispatch();
        self.id = next_registry_id();
    }

    /// Recompute the dispatch tables from the parsers' rules and hint keys.
    fn index_dispatch(&mut self) {
        self.index_dispatch_with(|_, parser| parser.dispatch());
    }

    /// [`index_dispatch`](Self::index_dispatch) with the dispatch of each
    /// parser (by index) as `dispatch_of` gives it.
    fn index_dispatch_with(&mut self, dispatch_of: impl Fn(usize, &BuiltinProtocol) -> Dispatch) {
        let dispatch_of = |i: usize| dispatch_of(i, &self.parsers[i]);
        let probes: Vec<usize> = (0..self.parsers.len())
            .filter(|&i| dispatch_of(i) == Dispatch::Probe)
            .collect();
        let rules = |i: usize| match dispatch_of(i) {
            Dispatch::Exact(rules) => rules,
            Dispatch::Probe => &[],
        };

        let mut roots = Vec::new();
        for parser in 0..self.parsers.len() {
            for rule in rules(parser) {
                if let DispatchRule::Root {
                    link_type,
                    priority,
                } = *rule
                {
                    roots.push(RootEntry {
                        link_type,
                        parser,
                        priority,
                    });
                }
            }
        }

        let after = |parent: &BuiltinProtocol| {
            let keys = parent.child_hint_keys();
            let mut tables: Vec<(HintKey, Vec<TableEntry>)> = Vec::new();
            for (parser, protocol) in self.parsers.iter().enumerate() {
                for rule in rules(parser) {
                    let DispatchRule::Hints {
                        after,
                        all,
                        priority,
                    } = *rule
                    else {
                        continue;
                    };
                    let (first, rest) = all.split_first().unwrap_or_else(|| {
                        panic!("{}: a hint rule needs a condition", protocol.name())
                    });
                    let follows = after.is_empty() || after.contains(&parent.name());
                    if !follows || !all.iter().all(|cond| cond.possible_after(keys)) {
                        continue;
                    }
                    let (index_keys, values): (&[HintKey], &[u64]) = match first {
                        Cond::Hint(key, values) => (std::slice::from_ref(key), values),
                        Cond::Port(values) => (&[HintKey::SrcPort, HintKey::DstPort], values),
                    };
                    for &key in index_keys {
                        if !Cond::Hint(key, values).possible_after(keys) {
                            continue;
                        }
                        let position =
                            tables
                                .iter()
                                .position(|(k, _)| *k == key)
                                .unwrap_or_else(|| {
                                    tables.push((key, Vec::new()));
                                    tables.len() - 1
                                });
                        tables[position]
                            .1
                            .extend(values.iter().map(|&value| TableEntry {
                                value,
                                parser,
                                priority,
                                rest,
                            }));
                    }
                }
            }
            for (_, entries) in &mut tables {
                entries.sort_by_key(|entry| entry.value);
            }
            NextLayer {
                tables,
                probes: probes.clone(),
            }
        };
        let children = self.parsers.iter().map(after).collect();

        self.roots = roots;
        self.root = NextLayer {
            tables: Vec::new(),
            probes,
        };
        self.children = children;
    }

    /// Find the best parser for the given context.
    ///
    /// Asks every registered parser; the parse loop uses the dispatch tables
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
    /// the packet's first layer, whose context has no hints), with its
    /// index.
    ///
    /// The same choice as [`find_parser`](Self::find_parser): the highest
    /// priority wins and, on a tie, the parser registered last. Debug builds
    /// check it against `find_parser`'s scan.
    #[inline]
    pub(crate) fn find_next(
        &self,
        parent: Option<usize>,
        context: &ParseContext,
    ) -> Option<(usize, &BuiltinProtocol)> {
        let mut best: Option<(u32, usize)> = None;
        let next = match parent {
            None => {
                for root in &self.roots {
                    if root.link_type == context.link_type {
                        offer(&mut best, root.priority, root.parser);
                    }
                }
                &self.root
            }
            Some(parent) => &self.children[parent],
        };
        for (key, entries) in &next.tables {
            let Some(value) = context.hints.get(*key) else {
                continue;
            };
            let start = entries.partition_point(|entry| entry.value < value);
            for entry in entries[start..]
                .iter()
                .take_while(|entry| entry.value == value)
            {
                if entry.rest.iter().all(|cond| cond.holds(&context.hints)) {
                    offer(&mut best, entry.priority, entry.parser);
                }
            }
        }
        for &parser in &next.probes {
            if let Some(priority) = self.parsers[parser].can_parse(context) {
                offer(&mut best, priority, parser);
            }
        }
        debug_assert_eq!(
            best.map(|(_, parser)| parser),
            self.find_index(context),
            "the dispatch tables disagree with a full scan after {:?}",
            parent.map(|i| self.parsers[i].name())
        );
        best.map(|(_, parser)| (parser, &self.parsers[parser]))
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

    /// The contexts the dispatch tests draw from: per parent, its hint keys
    /// with values that select the various children (ethertypes, IP
    /// protocols, link types, well-known ports), each key left out one time
    /// in four.
    fn contexts_after(parent: &BuiltinProtocol, count: usize) -> Vec<ParseContext> {
        let values: [u64; 32] = [
            0, 1, 2, 4, 6, 17, 41, 47, 50, 51, 58, 89, 22, 53, 67, 68, 80, 123, 179, 443, 2123,
            2152, 4789, 8443, 0x0800, 0x86dd, 0x8100, 0x0806, 0x8847, 0x8848, 0x88a8, 0x6558,
        ];
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15 ^ parent.name().len() as u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let keys = parent
            .child_hint_keys()
            .expect("built-ins declare their hints");
        (0..count)
            .map(|_| {
                let mut ctx = ParseContext::new(1);
                ctx.parent_protocol = Some(parent.name());
                for &key in keys {
                    if next() % 4 != 0 {
                        // The keys with few meaningful values draw from
                        // those, so that conjunctions are met often.
                        let values: &[u64] = match key {
                            HintKey::Transport => &[6, 17, 1],
                            HintKey::IpVersion => &[4, 6],
                            HintKey::IsNetlink | HintKey::HttpPayload => &[0, 1],
                            _ => &values,
                        };
                        let value = values[(next() % values.len() as u64) as usize];
                        ctx.insert_hint(key, value);
                    }
                }
                ctx
            })
            .collect()
    }

    /// The dispatch tables choose what a scan of every parser chooses, for
    /// contexts built from each parent's hint keys and for the link types.
    #[test]
    fn dispatch_tables_match_a_full_scan() {
        let registry = crate::protocol::default_registry();
        let mut matched = 0;
        for (parent_index, parent) in registry.all_parsers().enumerate() {
            for ctx in contexts_after(parent, 4000) {
                let indexed = registry.find_next(Some(parent_index), &ctx).map(|(i, _)| i);
                assert_eq!(
                    indexed,
                    registry.find_index(&ctx),
                    "after {}: {ctx:?}",
                    parent.name()
                );
                matched += indexed.is_some() as usize;
            }
        }
        assert!(matched > 2000, "the contexts should select children");
        for link_type in [0u16, 1, 101, 113, 253, 276] {
            let ctx = ParseContext::new(link_type);
            let indexed = registry.find_next(None, &ctx).map(|(i, _)| i);
            assert_eq!(indexed, registry.find_index(&ctx), "link type {link_type}");
        }
        // The point of the tables: nothing is asked. Every built-in is a
        // match on hints, and after Ethernet there is one table to look in.
        assert!(registry.root.probes.is_empty());
        let after_ethernet = &registry.children[0];
        assert_eq!(after_ethernet.tables.len(), 1);
        assert_eq!(after_ethernet.tables[0].0, HintKey::EtherType);
    }

    /// A parser's rules are its `can_parse`: for every built-in, over the
    /// contexts of every parent (so with other parsers' hints, and with and
    /// without its own), at the root of every link type, and for hints in a
    /// context without a parent.
    #[test]
    fn dispatch_rules_are_can_parse() {
        let registry = crate::protocol::default_registry();
        let mut contexts: Vec<ParseContext> = registry
            .all_parsers()
            .flat_map(|parent| contexts_after(parent, 2000))
            .collect();
        let orphans: Vec<ParseContext> = contexts
            .iter()
            .step_by(7)
            .map(|ctx| ParseContext {
                parent_protocol: None,
                ..ctx.clone()
            })
            .collect();
        contexts.extend(orphans);
        contexts.extend([0u16, 1, 101, 113, 253, 276].map(ParseContext::new));
        for parser in registry.all_parsers() {
            let dispatch = parser.dispatch();
            let mut matched = 0;
            for ctx in &contexts {
                let expected = parser.can_parse(ctx);
                assert_eq!(
                    dispatch.evaluate(ctx),
                    Some(expected),
                    "{}: {ctx:?}",
                    parser.name()
                );
                matched += expected.is_some() as usize;
            }
            assert!(matched > 0, "{} never matched", parser.name());
        }
    }

    /// A parser without rules is asked, after every layer and at the root,
    /// and competes with the tables' candidates on priority and order.
    #[test]
    fn probe_parsers_are_asked() {
        let mut registry = ProtocolRegistry::new();
        registry.register(EthernetProtocol);
        registry.register(Ipv4Protocol);
        registry.register(Ipv6Protocol);
        registry.index_dispatch_with(|i, parser| match i {
            1 => Dispatch::Probe,
            _ => parser.dispatch(),
        });
        assert_eq!(registry.root.probes, [1]);
        assert_eq!(registry.children[0].probes, [1]);
        // IPv6 is still in the table after Ethernet; IPv4 is not.
        let entries = &registry.children[0].tables[0].1;
        assert!(entries.iter().all(|entry| entry.parser == 2));

        let mut ctx = ParseContext::new(1);
        assert_eq!(registry.find_next(None, &ctx).map(|(i, _)| i), Some(0));
        ctx.parent_protocol = Some("ethernet");
        ctx.insert_hint(HintKey::EtherType, 0x0800);
        assert_eq!(registry.find_next(Some(0), &ctx).map(|(i, _)| i), Some(1));
        ctx.set_hint(HintKey::EtherType, 0x86dd);
        assert_eq!(registry.find_next(Some(0), &ctx).map(|(i, _)| i), Some(2));
        ctx.set_hint(HintKey::EtherType, 0x0806);
        assert_eq!(registry.find_next(Some(0), &ctx).map(|(i, _)| i), None);
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
                    ctx.insert_hint(HintKey::SrcPort, src);
                    ctx.insert_hint(HintKey::DstPort, dst);
                    ctx.insert_hint(HintKey::Transport, transport);
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
