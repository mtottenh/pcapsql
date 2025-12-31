//! AST types for BPF filter expressions.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Direction qualifier for host/port filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Match source only
    Src,
    /// Match destination only
    Dst,
    /// Match either source or destination (default)
    SrcOrDst,
}

impl Default for Direction {
    fn default() -> Self {
        Direction::SrcOrDst
    }
}

/// Protocol type for protocol filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmp6,
    Arp,
    /// IPv4
    Ip,
    /// IPv6
    Ip6,
}

impl Protocol {
    /// Returns the protocol name as used in SQL table names.
    pub fn table_name(&self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Icmp => "icmp",
            Protocol::Icmp6 => "icmp6",
            Protocol::Arp => "arp",
            Protocol::Ip => "ipv4",
            Protocol::Ip6 => "ipv6",
        }
    }

    /// Returns true if this is a transport protocol (has ports).
    pub fn has_ports(&self) -> bool {
        matches!(self, Protocol::Tcp | Protocol::Udp)
    }
}

/// Network address (IPv4 or IPv6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpAddress {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl IpAddress {
    /// Returns true if this is an IPv4 address.
    pub fn is_v4(&self) -> bool {
        matches!(self, IpAddress::V4(_))
    }

    /// Returns true if this is an IPv6 address.
    pub fn is_v6(&self) -> bool {
        matches!(self, IpAddress::V6(_))
    }
}

impl std::fmt::Display for IpAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpAddress::V4(addr) => write!(f, "{}", addr),
            IpAddress::V6(addr) => write!(f, "{}", addr),
        }
    }
}

/// CIDR network specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cidr {
    pub address: IpAddress,
    pub prefix_len: u8,
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}

/// Primitive filter expression.
#[derive(Debug, Clone, PartialEq)]
pub enum Primitive {
    /// Protocol filter: tcp, udp, icmp, etc.
    Protocol(Protocol),

    /// Host filter: host 1.2.3.4, src host ::1
    Host {
        direction: Direction,
        address: IpAddress,
    },

    /// Port filter: port 80, dst tcp port 443
    Port {
        direction: Direction,
        /// Optional protocol qualifier (tcp or udp)
        protocol: Option<Protocol>,
        port: u16,
    },

    /// Port range filter: portrange 80-90
    PortRange {
        direction: Direction,
        /// Optional protocol qualifier (tcp or udp)
        protocol: Option<Protocol>,
        start: u16,
        end: u16,
    },

    /// Network CIDR filter: net 10.0.0.0/8
    Net { direction: Direction, cidr: Cidr },

    /// IP protocol number: proto 6 (TCP), proto 17 (UDP)
    Proto(u8),
}

/// Boolean expression combining primitives.
#[derive(Debug, Clone, PartialEq)]
pub enum BpfExpr {
    /// A primitive filter
    Primitive(Primitive),
    /// Logical NOT
    Not(Box<BpfExpr>),
    /// Logical AND
    And(Box<BpfExpr>, Box<BpfExpr>),
    /// Logical OR
    Or(Box<BpfExpr>, Box<BpfExpr>),
}

impl BpfExpr {
    /// Create a NOT expression.
    pub fn not(expr: BpfExpr) -> Self {
        BpfExpr::Not(Box::new(expr))
    }

    /// Create an AND expression.
    pub fn and(left: BpfExpr, right: BpfExpr) -> Self {
        BpfExpr::And(Box::new(left), Box::new(right))
    }

    /// Create an OR expression.
    pub fn or(left: BpfExpr, right: BpfExpr) -> Self {
        BpfExpr::Or(Box::new(left), Box::new(right))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direction_default() {
        assert_eq!(Direction::default(), Direction::SrcOrDst);
    }

    #[test]
    fn test_protocol_table_name() {
        assert_eq!(Protocol::Tcp.table_name(), "tcp");
        assert_eq!(Protocol::Udp.table_name(), "udp");
        assert_eq!(Protocol::Ip.table_name(), "ipv4");
        assert_eq!(Protocol::Ip6.table_name(), "ipv6");
    }

    #[test]
    fn test_protocol_has_ports() {
        assert!(Protocol::Tcp.has_ports());
        assert!(Protocol::Udp.has_ports());
        assert!(!Protocol::Icmp.has_ports());
        assert!(!Protocol::Ip.has_ports());
    }

    #[test]
    fn test_ip_address_display() {
        let v4 = IpAddress::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(v4.to_string(), "192.168.1.1");

        let v6 = IpAddress::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(v6.to_string(), "2001:db8::1");
    }

    #[test]
    fn test_cidr_display() {
        let cidr = Cidr {
            address: IpAddress::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix_len: 8,
        };
        assert_eq!(cidr.to_string(), "10.0.0.0/8");
    }

    #[test]
    fn test_bpf_expr_constructors() {
        let tcp = BpfExpr::Primitive(Primitive::Protocol(Protocol::Tcp));
        let port80 = BpfExpr::Primitive(Primitive::Port {
            direction: Direction::SrcOrDst,
            protocol: None,
            port: 80,
        });

        let and_expr = BpfExpr::and(tcp.clone(), port80.clone());
        assert!(matches!(and_expr, BpfExpr::And(_, _)));

        let or_expr = BpfExpr::or(tcp.clone(), port80.clone());
        assert!(matches!(or_expr, BpfExpr::Or(_, _)));

        let not_expr = BpfExpr::not(tcp);
        assert!(matches!(not_expr, BpfExpr::Not(_)));
    }
}
