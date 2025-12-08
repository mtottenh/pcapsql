//! Parse context and result types.

use smallvec::SmallVec;

use super::FieldValue;

/// Field entry for parse results: (field_name, value).
/// Field names are always static strings (protocol-defined).
/// The lifetime parameter ties the value to the packet/buffer data.
pub type FieldEntry<'data> = (&'static str, FieldValue<'data>);

/// Hint entry for child protocol detection: (hint_name, value).
pub type HintEntry = (&'static str, u64);

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
    /// MPLS encapsulation.
    Mpls = 4,
    /// IPv4-in-IP encapsulation (IP protocol 4).
    IpInIp = 5,
    /// IPv6-in-IP encapsulation (IP protocol 41).
    Ip6InIp = 6,
    /// IPsec encapsulation.
    Ipsec = 7,
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

    /// Protocol-specific hints (e.g., ethertype, IP protocol number).
    /// Uses SmallVec for consistency with ParseResult. Typically 2-4 entries.
    pub hints: SmallVec<[HintEntry; 4]>,

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
            hints: SmallVec::new(),
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
        self.tunnel_stack.last().map(|t| t.tunnel_type).unwrap_or(TunnelType::None)
    }

    /// Get the innermost tunnel ID, if inside a tunnel with an ID.
    pub fn current_tunnel_id(&self) -> Option<u64> {
        self.tunnel_stack.last().and_then(|t| t.tunnel_id)
    }

    /// Get a hint value by key (linear search, but N is small).
    #[inline]
    pub fn hint(&self, key: &str) -> Option<u64> {
        self.hints.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
    }

    /// Insert a hint value (appends, may create duplicates).
    /// Use `set_hint()` if you need to update an existing hint.
    #[inline]
    pub fn insert_hint(&mut self, key: &'static str, value: u64) {
        self.hints.push((key, value));
    }

    /// Set a hint value (updates existing or appends).
    #[inline]
    pub fn set_hint(&mut self, key: &'static str, value: u64) {
        if let Some(entry) = self.hints.iter_mut().find(|(k, _)| *k == key) {
            entry.1 = value;
        } else {
            self.hints.push((key, value));
        }
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
}

/// Result of parsing a protocol layer.
///
/// Uses SmallVec for inline storage to avoid HashMap allocation overhead.
/// Most protocols have <16 fields and <4 child hints, so these fit inline.
///
/// The lifetime parameter `'data` ties the result to the packet/buffer data,
/// allowing zero-copy parsing where field values reference the packet directly.
#[derive(Debug, Clone)]
pub struct ParseResult<'data> {
    /// Extracted field values. Most protocols have <16 fields.
    /// Field values may reference the packet data (zero-copy).
    pub fields: SmallVec<[FieldEntry<'data>; 16]>,

    /// Remaining unparsed bytes (payload for next layer).
    pub remaining: &'data [u8],

    /// Hints for child protocol identification. Typically 2-4 entries.
    pub child_hints: SmallVec<[HintEntry; 4]>,

    /// Parse error if partial parsing occurred.
    pub error: Option<String>,

    /// Encapsulation depth when this protocol was parsed (0 = outer layer).
    pub encap_depth: u8,

    /// Type of the innermost enclosing tunnel (if inside a tunnel).
    pub tunnel_type: TunnelType,

    /// Identifier of the innermost enclosing tunnel (VNI, GRE key, TEID, etc.).
    pub tunnel_id: Option<u64>,
}

impl<'data> ParseResult<'data> {
    /// Create a successful parse result.
    ///
    /// Note: `encap_depth`, `tunnel_type`, and `tunnel_id` default to 0/None.
    /// These are populated by the parse loop from the ParseContext after parsing.
    pub fn success(
        fields: SmallVec<[FieldEntry<'data>; 16]>,
        remaining: &'data [u8],
        child_hints: SmallVec<[HintEntry; 4]>,
    ) -> Self {
        Self {
            fields,
            remaining,
            child_hints,
            error: None,
            encap_depth: 0,
            tunnel_type: TunnelType::None,
            tunnel_id: None,
        }
    }

    /// Create an error parse result.
    pub fn error(error: String, remaining: &'data [u8]) -> Self {
        Self {
            fields: SmallVec::new(),
            remaining,
            child_hints: SmallVec::new(),
            error: Some(error),
            encap_depth: 0,
            tunnel_type: TunnelType::None,
            tunnel_id: None,
        }
    }

    /// Create a result with partial fields and an error.
    pub fn partial(
        fields: SmallVec<[FieldEntry<'data>; 16]>,
        remaining: &'data [u8],
        error: String,
    ) -> Self {
        Self {
            fields,
            remaining,
            child_hints: SmallVec::new(),
            error: Some(error),
            encap_depth: 0,
            tunnel_type: TunnelType::None,
            tunnel_id: None,
        }
    }

    /// Set encapsulation context from a ParseContext.
    pub fn set_encap_context(&mut self, ctx: &ParseContext) {
        self.encap_depth = ctx.encap_depth;
        self.tunnel_type = ctx.current_tunnel_type();
        self.tunnel_id = ctx.current_tunnel_id();
    }

    /// Get a field value by name (linear search, but N is small).
    pub fn get(&self, name: &str) -> Option<&FieldValue<'data>> {
        self.fields.iter().find(|(k, _)| *k == name).map(|(_, v)| v)
    }

    /// Get a child hint value by name.
    pub fn hint(&self, name: &str) -> Option<u64> {
        self.child_hints
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| *v)
    }

    /// Check if parsing was successful.
    pub fn is_ok(&self) -> bool {
        self.error.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_parse_result_encap_context() {
        let mut ctx = ParseContext::new(1);
        ctx.push_tunnel(TunnelType::Gtp, Some(0x12345678));

        let mut result = ParseResult::success(SmallVec::new(), &[], SmallVec::new());
        assert_eq!(result.encap_depth, 0);
        assert_eq!(result.tunnel_type, TunnelType::None);
        assert_eq!(result.tunnel_id, None);

        result.set_encap_context(&ctx);
        assert_eq!(result.encap_depth, 1);
        assert_eq!(result.tunnel_type, TunnelType::Gtp);
        assert_eq!(result.tunnel_id, Some(0x12345678));
    }

    #[test]
    fn test_context_hint_access() {
        let mut ctx = ParseContext::new(1);
        ctx.insert_hint("ip_protocol", 6);
        ctx.insert_hint("dst_port", 80);

        assert_eq!(ctx.hint("ip_protocol"), Some(6));
        assert_eq!(ctx.hint("dst_port"), Some(80));
        assert_eq!(ctx.hint("nonexistent"), None);
    }

    #[test]
    fn test_context_set_hint_update() {
        let mut ctx = ParseContext::new(1);
        ctx.set_hint("ip_protocol", 6);
        ctx.set_hint("ip_protocol", 17); // Update existing

        assert_eq!(ctx.hint("ip_protocol"), Some(17));
        assert_eq!(ctx.hints.len(), 1); // No duplicates
    }

    #[test]
    fn test_context_set_hint_insert() {
        let mut ctx = ParseContext::new(1);
        ctx.set_hint("ip_protocol", 6);
        ctx.set_hint("dst_port", 80); // Insert new

        assert_eq!(ctx.hint("ip_protocol"), Some(6));
        assert_eq!(ctx.hint("dst_port"), Some(80));
        assert_eq!(ctx.hints.len(), 2);
    }

    #[test]
    fn test_context_clear_hints() {
        let mut ctx = ParseContext::new(1);
        ctx.insert_hint("ip_protocol", 6);
        ctx.insert_hint("dst_port", 80);

        ctx.clear_hints();

        assert_eq!(ctx.hints.len(), 0);
        assert_eq!(ctx.hint("ip_protocol"), None);
    }

    #[test]
    fn test_hint_count_stays_inline() {
        let mut ctx = ParseContext::new(1);
        ctx.insert_hint("ethertype", 0x0800);
        ctx.insert_hint("ip_protocol", 6);
        ctx.insert_hint("src_port", 12345);
        ctx.insert_hint("dst_port", 80);

        // Should stay inline (no heap allocation) with 4 entries
        assert!(!ctx.hints.spilled());
    }

    #[test]
    fn test_parse_result_success() {
        let mut fields = SmallVec::new();
        fields.push(("src_port", FieldValue::UInt16(80)));

        let mut hints = SmallVec::new();
        hints.push(("transport", 6u64));

        let result = ParseResult::success(fields, &[], hints);

        assert!(result.is_ok());
        assert_eq!(result.get("src_port"), Some(&FieldValue::UInt16(80)));
        assert_eq!(result.hint("transport"), Some(6));
    }

    #[test]
    fn test_parse_result_error() {
        let result = ParseResult::error("test error".to_string(), &[1, 2, 3]);

        assert!(!result.is_ok());
        assert_eq!(result.error, Some("test error".to_string()));
        assert_eq!(result.remaining, &[1, 2, 3]);
    }
}
