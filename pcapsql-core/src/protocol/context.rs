//! The context a layer is parsed in, and the hints layers leave each other.

use smallvec::SmallVec;

use super::FieldValue;

/// A field of a layer: (field_name, value).
/// Field names are always static strings (protocol-defined).
/// The lifetime parameter ties the value to the packet/buffer data.
pub type FieldEntry<'data> = (&'static str, FieldValue<'data>);

/// A hint a parser leaves for the layer that follows it.
///
/// The keys are a closed set, so that a context's hints are an array indexed
/// by key ([`Hints`]) and a parser's match on them can be put in a table
/// ([`Dispatch`](super::Dispatch)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum HintKey {
    /// The EtherType of the payload.
    EtherType,
    /// The IP protocol number (IPv6: the last next-header) of the payload.
    IpProtocol,
    /// The IP version of the enclosing header (4 or 6).
    IpVersion,
    /// The transport source port.
    SrcPort,
    /// The transport destination port.
    DstPort,
    /// The IP protocol number of the transport: 6 (TCP) or 17 (UDP).
    Transport,
    /// 1 when the TCP payload starts an HTTP/1.x message.
    HttpPayload,
    /// The [`TunnelType`] this layer opens, as its number.
    TunnelType,
    /// The identifier of the tunnel this layer opens (VNI, GRE key, TEID).
    TunnelId,
    /// The link type of an encapsulated frame.
    LinkType,
    /// The GRE key.
    GreKey,
    /// The GTP plane: 1 user, 0 control.
    GtpPlane,
    /// The VLAN identifier.
    VlanId,
    /// The ARPHRD type of a Linux cooked capture header.
    SllArphrd,
    /// The protocol field of a Linux cooked capture header that is not an
    /// EtherType.
    SllProtocol,
    /// 1 when a Linux cooked capture header carries netlink.
    IsNetlink,
    /// The netlink family.
    NetlinkFamily,
    /// The netlink message type.
    NetlinkMsgType,
}

impl HintKey {
    /// The number of keys.
    pub const COUNT: usize = 18;

    /// Every key, in declaration order.
    pub const ALL: [HintKey; Self::COUNT] = [
        HintKey::EtherType,
        HintKey::IpProtocol,
        HintKey::IpVersion,
        HintKey::SrcPort,
        HintKey::DstPort,
        HintKey::Transport,
        HintKey::HttpPayload,
        HintKey::TunnelType,
        HintKey::TunnelId,
        HintKey::LinkType,
        HintKey::GreKey,
        HintKey::GtpPlane,
        HintKey::VlanId,
        HintKey::SllArphrd,
        HintKey::SllProtocol,
        HintKey::IsNetlink,
        HintKey::NetlinkFamily,
        HintKey::NetlinkMsgType,
    ];

    /// The key's name, as it was written when hints were keyed by string.
    pub fn name(self) -> &'static str {
        match self {
            HintKey::EtherType => "ethertype",
            HintKey::IpProtocol => "ip_protocol",
            HintKey::IpVersion => "ip_version",
            HintKey::SrcPort => "src_port",
            HintKey::DstPort => "dst_port",
            HintKey::Transport => "transport",
            HintKey::HttpPayload => "http_payload",
            HintKey::TunnelType => "tunnel_type",
            HintKey::TunnelId => "tunnel_id",
            HintKey::LinkType => "link_type",
            HintKey::GreKey => "gre_key",
            HintKey::GtpPlane => "gtp_plane",
            HintKey::VlanId => "vlan_id",
            HintKey::SllArphrd => "sll_arphrd",
            HintKey::SllProtocol => "sll_protocol",
            HintKey::IsNetlink => "is_netlink",
            HintKey::NetlinkFamily => "netlink_family",
            HintKey::NetlinkMsgType => "netlink_msg_type",
        }
    }
}

// `ALL` is in declaration order: a key's number is its index.
const _: () = {
    let mut i = 0;
    while i < HintKey::COUNT {
        assert!(HintKey::ALL[i] as usize == i);
        i += 1;
    }
};

/// The hints of one layer: at most one value per [`HintKey`].
///
/// A bit per key says whether it is set and the values are indexed by key,
/// so a lookup is a bit test and a load: no search, no string compare.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Hints {
    set: u32,
    values: [u64; HintKey::COUNT],
}

impl Hints {
    /// No hints.
    #[inline]
    pub const fn new() -> Self {
        Self {
            set: 0,
            values: [0; HintKey::COUNT],
        }
    }

    /// The value of `key`, if it is set.
    #[inline]
    pub fn get(&self, key: HintKey) -> Option<u64> {
        if self.contains(key) {
            Some(self.values[key as usize])
        } else {
            None
        }
    }

    /// Whether `key` is set.
    #[inline]
    pub fn contains(&self, key: HintKey) -> bool {
        self.set & (1 << key as u32) != 0
    }

    /// Set `key` unless it is set already: the first value given for a key
    /// stays.
    #[inline]
    pub fn insert(&mut self, key: HintKey, value: u64) {
        if !self.contains(key) {
            self.set(key, value);
        }
    }

    /// Set `key`, replacing its value if it has one.
    #[inline]
    pub fn set(&mut self, key: HintKey, value: u64) {
        self.set |= 1 << key as u32;
        self.values[key as usize] = value;
    }

    /// Remove every hint.
    #[inline]
    pub fn clear(&mut self) {
        self.set = 0;
    }

    /// The number of keys that are set.
    #[inline]
    pub fn len(&self) -> usize {
        self.set.count_ones() as usize
    }

    /// Whether no key is set.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.set == 0
    }

    /// The hints that are set, in key order.
    pub fn iter(&self) -> impl Iterator<Item = (HintKey, u64)> + '_ {
        HintKey::ALL
            .into_iter()
            .filter_map(|key| self.get(key).map(|value| (key, value)))
    }
}

impl std::fmt::Debug for Hints {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map()
            .entries(self.iter().map(|(key, value)| (key.name(), value)))
            .finish()
    }
}

/// Type of encapsulating tunnel protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum TunnelType {
    /// No tunnel encapsulation (outer layer).
    #[default]
    None = 0,
    /// VXLAN encapsulation.
    Vxlan = 1,
    /// GRE encapsulation.
    Gre = 2,
    /// GTP (GPRS Tunneling Protocol) encapsulation.
    Gtp = 3,
    /// MPLS. Kept for the numbering and `as_str()`, but never produced: an
    /// MPLS label stack is not treated as a tunnel (see the `mpls` module).
    Mpls = 4,
    /// IPv4-in-IPv4 encapsulation (IP protocol 4 in IPv4).
    IpInIp = 5,
    /// IPv6-in-IPv4 encapsulation (IP protocol 41 in IPv4).
    Ip6InIp = 6,
    /// IPsec encapsulation.
    Ipsec = 7,
    /// IPv4-in-IPv6 encapsulation (next header 4 in IPv6).
    Ip4InIp6 = 8,
    /// IPv6-in-IPv6 encapsulation (next header 41 in IPv6).
    Ip6InIp6 = 9,
}

impl TunnelType {
    /// Convert a u64 value (from hints) to TunnelType.
    pub fn from_u64(value: u64) -> Self {
        match value {
            0 => TunnelType::None,
            1 => TunnelType::Vxlan,
            2 => TunnelType::Gre,
            3 => TunnelType::Gtp,
            4 => TunnelType::Mpls,
            5 => TunnelType::IpInIp,
            6 => TunnelType::Ip6InIp,
            7 => TunnelType::Ipsec,
            8 => TunnelType::Ip4InIp6,
            9 => TunnelType::Ip6InIp6,
            _ => TunnelType::None,
        }
    }

    /// Convert TunnelType to a string representation.
    pub fn as_str(&self) -> Option<&'static str> {
        match self {
            TunnelType::None => None,
            TunnelType::Vxlan => Some("vxlan"),
            TunnelType::Gre => Some("gre"),
            TunnelType::Gtp => Some("gtp"),
            TunnelType::Mpls => Some("mpls"),
            TunnelType::IpInIp => Some("ipinip"),
            TunnelType::Ip6InIp => Some("ip6inip"),
            TunnelType::Ipsec => Some("ipsec"),
            TunnelType::Ip4InIp6 => Some("ip4inip6"),
            TunnelType::Ip6InIp6 => Some("ip6inip6"),
        }
    }
}

/// Information about a single tunnel encapsulation layer.
#[derive(Debug, Clone, Copy, Default)]
pub struct TunnelLayer {
    /// Type of tunnel at this layer.
    pub tunnel_type: TunnelType,
    /// Tunnel identifier (VNI, GRE key, TEID, MPLS label, etc.).
    /// None if the tunnel type doesn't have an identifier.
    pub tunnel_id: Option<u64>,
    /// Byte offset where this tunnel started in the packet.
    pub offset: usize,
}

/// Context passed through the parsing chain.
#[derive(Debug, Clone)]
pub struct ParseContext {
    /// Link type from PCAP header (e.g., 1 = Ethernet).
    pub link_type: u16,

    /// Parent protocol that identified this protocol.
    pub parent_protocol: Option<&'static str>,

    /// The hints the parent layer left (e.g., ethertype, IP protocol number).
    pub hints: Hints,

    /// Offset into the original packet where this protocol's data starts.
    pub offset: usize,

    /// Current encapsulation depth (0 = outer/no tunnel, 1+ = inside tunnel).
    pub encap_depth: u8,

    /// Stack of enclosing tunnel layers (innermost last).
    /// Typical tunneled traffic has 1-2 layers; SmallVec<4> handles deeper nesting.
    pub tunnel_stack: SmallVec<[TunnelLayer; 4]>,
}

impl ParseContext {
    /// Create a new parse context for a packet with the given link type.
    pub fn new(link_type: u16) -> Self {
        Self {
            link_type,
            parent_protocol: None,
            hints: Hints::new(),
            offset: 0,
            encap_depth: 0,
            tunnel_stack: SmallVec::new(),
        }
    }

    /// Push a new tunnel layer onto the stack and increment encap_depth.
    pub fn push_tunnel(&mut self, tunnel_type: TunnelType, tunnel_id: Option<u64>) {
        self.tunnel_stack.push(TunnelLayer {
            tunnel_type,
            tunnel_id,
            offset: self.offset,
        });
        self.encap_depth = self.encap_depth.saturating_add(1);
    }

    /// Get the innermost (current) tunnel layer, if any.
    pub fn current_tunnel(&self) -> Option<&TunnelLayer> {
        self.tunnel_stack.last()
    }

    /// Get the innermost tunnel type, if inside a tunnel.
    pub fn current_tunnel_type(&self) -> TunnelType {
        self.tunnel_stack
            .last()
            .map(|t| t.tunnel_type)
            .unwrap_or(TunnelType::None)
    }

    /// Get the innermost tunnel ID, if inside a tunnel with an ID.
    pub fn current_tunnel_id(&self) -> Option<u64> {
        self.tunnel_stack.last().and_then(|t| t.tunnel_id)
    }

    /// Get a hint value by key.
    #[inline]
    pub fn hint(&self, key: HintKey) -> Option<u64> {
        self.hints.get(key)
    }

    /// Insert a hint value; a key that is set already keeps its value.
    /// Use `set_hint()` to update an existing hint.
    #[inline]
    pub fn insert_hint(&mut self, key: HintKey, value: u64) {
        self.hints.insert(key, value);
    }

    /// Set a hint value (updates existing or adds).
    #[inline]
    pub fn set_hint(&mut self, key: HintKey, value: u64) {
        self.hints.set(key, value);
    }

    /// Clear all hints (for context reuse).
    #[inline]
    pub fn clear_hints(&mut self) {
        self.hints.clear();
    }

    /// Check if we're at the start of the packet (no parent protocol).
    pub fn is_root(&self) -> bool {
        self.parent_protocol.is_none()
    }

    /// Whether the parent transport is TCP (`transport` hint 6).
    ///
    /// Port-based parsers check this before claiming a segment: the ports a
    /// TCP service and a UDP service use overlap, and a parser for one
    /// transport misparses the other's payload.
    #[inline]
    pub fn over_tcp(&self) -> bool {
        self.hint(HintKey::Transport) == Some(super::tcp::IP_PROTO_TCP as u64)
    }

    /// Whether the parent transport is UDP (`transport` hint 17).
    #[inline]
    pub fn over_udp(&self) -> bool {
        self.hint(HintKey::Transport) == Some(super::udp::IP_PROTO_UDP as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ethernet::ethertype;

    #[test]
    fn test_tunnel_type_conversions() {
        assert_eq!(TunnelType::from_u64(0), TunnelType::None);
        assert_eq!(TunnelType::from_u64(1), TunnelType::Vxlan);
        assert_eq!(TunnelType::from_u64(2), TunnelType::Gre);
        assert_eq!(TunnelType::from_u64(3), TunnelType::Gtp);
        assert_eq!(TunnelType::from_u64(4), TunnelType::Mpls);
        assert_eq!(TunnelType::from_u64(5), TunnelType::IpInIp);
        assert_eq!(TunnelType::from_u64(6), TunnelType::Ip6InIp);
        assert_eq!(TunnelType::from_u64(7), TunnelType::Ipsec);
        assert_eq!(TunnelType::from_u64(99), TunnelType::None); // Unknown

        assert_eq!(TunnelType::None.as_str(), None);
        assert_eq!(TunnelType::Vxlan.as_str(), Some("vxlan"));
        assert_eq!(TunnelType::Gre.as_str(), Some("gre"));
        assert_eq!(TunnelType::Gtp.as_str(), Some("gtp"));
        assert_eq!(TunnelType::IpInIp.as_str(), Some("ipinip"));
    }

    #[test]
    fn test_context_encap_tracking() {
        let mut ctx = ParseContext::new(1);
        assert_eq!(ctx.encap_depth, 0);
        assert_eq!(ctx.current_tunnel_type(), TunnelType::None);
        assert_eq!(ctx.current_tunnel_id(), None);

        // Push a VXLAN tunnel
        ctx.push_tunnel(TunnelType::Vxlan, Some(100));
        assert_eq!(ctx.encap_depth, 1);
        assert_eq!(ctx.current_tunnel_type(), TunnelType::Vxlan);
        assert_eq!(ctx.current_tunnel_id(), Some(100));

        // Push an IP-in-IP tunnel (nested)
        ctx.push_tunnel(TunnelType::IpInIp, None);
        assert_eq!(ctx.encap_depth, 2);
        assert_eq!(ctx.current_tunnel_type(), TunnelType::IpInIp);
        assert_eq!(ctx.current_tunnel_id(), None);

        // Verify tunnel stack
        assert_eq!(ctx.tunnel_stack.len(), 2);
        assert_eq!(ctx.tunnel_stack[0].tunnel_type, TunnelType::Vxlan);
        assert_eq!(ctx.tunnel_stack[1].tunnel_type, TunnelType::IpInIp);
    }

    #[test]
    fn test_context_hint_access() {
        let mut ctx = ParseContext::new(1);
        ctx.insert_hint(HintKey::IpProtocol, 6);
        ctx.insert_hint(HintKey::DstPort, 80);

        assert_eq!(ctx.hint(HintKey::IpProtocol), Some(6));
        assert_eq!(ctx.hint(HintKey::DstPort), Some(80));
        assert_eq!(ctx.hint(HintKey::SrcPort), None);
    }

    #[test]
    fn test_context_set_hint_update() {
        let mut ctx = ParseContext::new(1);
        ctx.set_hint(HintKey::IpProtocol, 6);
        ctx.set_hint(HintKey::IpProtocol, 17); // Update existing

        assert_eq!(ctx.hint(HintKey::IpProtocol), Some(17));
        assert_eq!(ctx.hints.len(), 1); // No duplicates
    }

    #[test]
    fn test_context_set_hint_insert() {
        let mut ctx = ParseContext::new(1);
        ctx.set_hint(HintKey::IpProtocol, 6);
        ctx.set_hint(HintKey::DstPort, 80); // Insert new

        assert_eq!(ctx.hint(HintKey::IpProtocol), Some(6));
        assert_eq!(ctx.hint(HintKey::DstPort), Some(80));
        assert_eq!(ctx.hints.len(), 2);
    }

    #[test]
    fn test_context_clear_hints() {
        let mut ctx = ParseContext::new(1);
        ctx.insert_hint(HintKey::IpProtocol, 6);
        ctx.insert_hint(HintKey::DstPort, 80);

        ctx.clear_hints();

        assert_eq!(ctx.hints.len(), 0);
        assert_eq!(ctx.hint(HintKey::IpProtocol), None);
    }

    #[test]
    fn hints_hold_one_value_per_key() {
        let mut hints = Hints::new();
        assert!(hints.is_empty());
        for (i, key) in HintKey::ALL.into_iter().enumerate() {
            assert_eq!(hints.get(key), None);
            hints.insert(key, i as u64 + 100);
            // The first value stays; `set` replaces it.
            hints.insert(key, 7);
            assert_eq!(hints.get(key), Some(i as u64 + 100));
        }
        assert_eq!(hints.len(), HintKey::COUNT);
        hints.set(HintKey::EtherType, ethertype::IPV4 as u64);
        assert_eq!(hints.get(HintKey::EtherType), Some(0x0800));
        assert_eq!(hints.get(HintKey::NetlinkMsgType), Some(117));
        assert_eq!(
            hints.iter().map(|(key, _)| key).collect::<Vec<_>>(),
            HintKey::ALL
        );
        hints.clear();
        assert!(hints.is_empty());
        assert_eq!(hints.get(HintKey::EtherType), None);
        assert_eq!(hints.iter().count(), 0);
    }
}
