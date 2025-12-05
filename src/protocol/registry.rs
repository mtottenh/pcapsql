//! Protocol registry for managing parsers.

use arrow::datatypes::Field;

use super::{
    ArpProtocol, DnsProtocol, EthernetProtocol, IcmpProtocol, Ipv4Protocol, Ipv6Protocol,
    ParseContext, ParseResult, TcpProtocol, UdpProtocol, VlanProtocol,
};

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

    /// Return the Arrow schema fields this protocol produces.
    fn schema_fields(&self) -> Vec<Field>;

    /// Protocols that might follow this one.
    fn child_protocols(&self) -> &[&'static str] {
        &[]
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
    Ipv4(Ipv4Protocol),
    Ipv6(Ipv6Protocol),
    Tcp(TcpProtocol),
    Udp(UdpProtocol),
    Icmp(IcmpProtocol),
    Dns(DnsProtocol),
}

/// Macro to delegate Protocol trait methods to inner types.
macro_rules! delegate_protocol {
    ($self:expr, $method:ident $(, $arg:expr)*) => {
        match $self {
            BuiltinProtocol::Ethernet(p) => p.$method($($arg),*),
            BuiltinProtocol::Arp(p) => p.$method($($arg),*),
            BuiltinProtocol::Vlan(p) => p.$method($($arg),*),
            BuiltinProtocol::Ipv4(p) => p.$method($($arg),*),
            BuiltinProtocol::Ipv6(p) => p.$method($($arg),*),
            BuiltinProtocol::Tcp(p) => p.$method($($arg),*),
            BuiltinProtocol::Udp(p) => p.$method($($arg),*),
            BuiltinProtocol::Icmp(p) => p.$method($($arg),*),
            BuiltinProtocol::Dns(p) => p.$method($($arg),*),
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
    fn schema_fields(&self) -> Vec<Field> {
        delegate_protocol!(self, schema_fields)
    }

    #[inline]
    fn child_protocols(&self) -> &[&'static str] {
        delegate_protocol!(self, child_protocols)
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

impl From<DnsProtocol> for BuiltinProtocol {
    fn from(p: DnsProtocol) -> Self {
        BuiltinProtocol::Dns(p)
    }
}

/// Registry for protocol parsers with priority-based selection.
///
/// Uses static dispatch via enum for all built-in protocols,
/// avoiding vtable overhead and enabling compiler optimizations.
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
    pub fn combined_schema(&self) -> Vec<Field> {
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
