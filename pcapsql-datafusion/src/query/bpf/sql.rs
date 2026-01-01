//! SQL WHERE clause generation from BPF AST.

use super::ast::{BpfExpr, Cidr, Direction, IpAddress, Primitive, Protocol};

/// Result of translating a BPF filter to SQL.
#[derive(Debug, Clone)]
pub struct SqlFilter {
    /// SQL WHERE clause fragment (without "WHERE" keyword)
    pub where_clause: String,
}

impl SqlFilter {
    /// Generate SQL from a BPF expression.
    pub fn from_expr(expr: &BpfExpr) -> Self {
        SqlFilter {
            where_clause: expr_to_sql(expr),
        }
    }
}

/// Convert a BPF expression to SQL.
fn expr_to_sql(expr: &BpfExpr) -> String {
    match expr {
        BpfExpr::Primitive(prim) => primitive_to_sql(prim),
        BpfExpr::Not(inner) => {
            let inner_sql = expr_to_sql(inner);
            format!("NOT ({inner_sql})")
        }
        BpfExpr::And(left, right) => {
            let left_sql = expr_to_sql(left);
            let right_sql = expr_to_sql(right);
            format!("({left_sql}) AND ({right_sql})")
        }
        BpfExpr::Or(left, right) => {
            let left_sql = expr_to_sql(left);
            let right_sql = expr_to_sql(right);
            format!("({left_sql}) OR ({right_sql})")
        }
    }
}

/// Convert a primitive filter to SQL.
fn primitive_to_sql(prim: &Primitive) -> String {
    match prim {
        Primitive::Protocol(proto) => protocol_to_sql(proto),
        Primitive::Host { direction, address } => host_to_sql(*direction, address),
        Primitive::Port {
            direction,
            protocol,
            port,
        } => port_to_sql(*direction, *protocol, *port),
        Primitive::PortRange {
            direction,
            protocol,
            start,
            end,
        } => portrange_to_sql(*direction, *protocol, *start, *end),
        Primitive::Net { direction, cidr } => net_to_sql(*direction, cidr),
        Primitive::Proto(num) => format!("protocol = {num}"),
    }
}

/// Convert protocol filter to SQL.
fn protocol_to_sql(proto: &Protocol) -> String {
    // Use frame_number existence check for protocol tables
    format!("{}.frame_number IS NOT NULL", proto.table_name())
}

/// Convert host filter to SQL.
fn host_to_sql(direction: Direction, address: &IpAddress) -> String {
    let (table, udf) = match address {
        IpAddress::V4(_) => ("ipv4", "ip4"),
        IpAddress::V6(_) => ("ipv6", "ip6"),
    };

    let addr_str = address.to_string();

    match direction {
        Direction::Src => format!("{table}.src_ip = {udf}('{addr_str}')"),
        Direction::Dst => format!("{table}.dst_ip = {udf}('{addr_str}')"),
        Direction::SrcOrDst => {
            format!(
                "({table}.src_ip = {udf}('{addr_str}') OR {table}.dst_ip = {udf}('{addr_str}'))"
            )
        }
    }
}

/// Convert port filter to SQL.
fn port_to_sql(direction: Direction, protocol: Option<Protocol>, port: u16) -> String {
    match protocol {
        Some(proto) if proto.has_ports() => {
            // Specific protocol
            let table = proto.table_name();
            match direction {
                Direction::Src => format!("{table}.src_port = {port}"),
                Direction::Dst => format!("{table}.dst_port = {port}"),
                Direction::SrcOrDst => {
                    format!("({table}.src_port = {port} OR {table}.dst_port = {port})")
                }
            }
        }
        _ => {
            // No protocol specified - match both TCP and UDP
            let tcp = port_to_sql(direction, Some(Protocol::Tcp), port);
            let udp = port_to_sql(direction, Some(Protocol::Udp), port);
            format!("({tcp}) OR ({udp})")
        }
    }
}

/// Convert port range filter to SQL.
fn portrange_to_sql(
    direction: Direction,
    protocol: Option<Protocol>,
    start: u16,
    end: u16,
) -> String {
    match protocol {
        Some(proto) if proto.has_ports() => {
            let table = proto.table_name();
            match direction {
                Direction::Src => {
                    format!("{table}.src_port BETWEEN {start} AND {end}")
                }
                Direction::Dst => {
                    format!("{table}.dst_port BETWEEN {start} AND {end}")
                }
                Direction::SrcOrDst => {
                    format!("({table}.src_port BETWEEN {start} AND {end}) OR ({table}.dst_port BETWEEN {start} AND {end})")
                }
            }
        }
        _ => {
            // No protocol specified - match both TCP and UDP
            let tcp = portrange_to_sql(direction, Some(Protocol::Tcp), start, end);
            let udp = portrange_to_sql(direction, Some(Protocol::Udp), start, end);
            format!("({tcp}) OR ({udp})")
        }
    }
}

/// Convert net (CIDR) filter to SQL.
fn net_to_sql(direction: Direction, cidr: &Cidr) -> String {
    let (table, udf) = match &cidr.address {
        IpAddress::V4(_) => ("ipv4", "ip_in_cidr"),
        IpAddress::V6(_) => ("ipv6", "ip6_in_cidr"),
    };

    let cidr_str = cidr.to_string();

    match direction {
        Direction::Src => format!("{udf}({table}.src_ip, '{cidr_str}')"),
        Direction::Dst => format!("{udf}({table}.dst_ip, '{cidr_str}')"),
        Direction::SrcOrDst => {
            format!("{udf}({table}.src_ip, '{cidr_str}') OR {udf}({table}.dst_ip, '{cidr_str}')")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::bpf::parser::parse_filter;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_sql_tcp() {
        let filter = SqlFilter::from_expr(&BpfExpr::Primitive(Primitive::Protocol(Protocol::Tcp)));
        assert_eq!(filter.where_clause, "tcp.frame_number IS NOT NULL");
    }

    #[test]
    fn test_sql_udp() {
        let filter = SqlFilter::from_expr(&BpfExpr::Primitive(Primitive::Protocol(Protocol::Udp)));
        assert_eq!(filter.where_clause, "udp.frame_number IS NOT NULL");
    }

    #[test]
    fn test_sql_host_ipv4() {
        let filter = SqlFilter::from_expr(&BpfExpr::Primitive(Primitive::Host {
            direction: Direction::SrcOrDst,
            address: IpAddress::V4(Ipv4Addr::new(192, 168, 1, 1)),
        }));
        assert_eq!(
            filter.where_clause,
            "(ipv4.src_ip = ip4('192.168.1.1') OR ipv4.dst_ip = ip4('192.168.1.1'))"
        );
    }

    #[test]
    fn test_sql_src_host() {
        let filter = SqlFilter::from_expr(&BpfExpr::Primitive(Primitive::Host {
            direction: Direction::Src,
            address: IpAddress::V4(Ipv4Addr::new(10, 0, 0, 1)),
        }));
        assert_eq!(filter.where_clause, "ipv4.src_ip = ip4('10.0.0.1')");
    }

    #[test]
    fn test_sql_host_ipv6() {
        let filter = SqlFilter::from_expr(&BpfExpr::Primitive(Primitive::Host {
            direction: Direction::SrcOrDst,
            address: IpAddress::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        }));
        assert_eq!(
            filter.where_clause,
            "(ipv6.src_ip = ip6('::1') OR ipv6.dst_ip = ip6('::1'))"
        );
    }

    #[test]
    fn test_sql_port() {
        let filter = SqlFilter::from_expr(&BpfExpr::Primitive(Primitive::Port {
            direction: Direction::SrcOrDst,
            protocol: None,
            port: 80,
        }));
        assert_eq!(
            filter.where_clause,
            "((tcp.src_port = 80 OR tcp.dst_port = 80)) OR ((udp.src_port = 80 OR udp.dst_port = 80))"
        );
    }

    #[test]
    fn test_sql_tcp_port() {
        let filter = SqlFilter::from_expr(&BpfExpr::Primitive(Primitive::Port {
            direction: Direction::SrcOrDst,
            protocol: Some(Protocol::Tcp),
            port: 443,
        }));
        assert_eq!(
            filter.where_clause,
            "(tcp.src_port = 443 OR tcp.dst_port = 443)"
        );
    }

    #[test]
    fn test_sql_src_port() {
        let filter = SqlFilter::from_expr(&BpfExpr::Primitive(Primitive::Port {
            direction: Direction::Src,
            protocol: Some(Protocol::Tcp),
            port: 22,
        }));
        assert_eq!(filter.where_clause, "tcp.src_port = 22");
    }

    #[test]
    fn test_sql_portrange() {
        let filter = SqlFilter::from_expr(&BpfExpr::Primitive(Primitive::PortRange {
            direction: Direction::SrcOrDst,
            protocol: Some(Protocol::Tcp),
            start: 80,
            end: 90,
        }));
        assert_eq!(
            filter.where_clause,
            "(tcp.src_port BETWEEN 80 AND 90) OR (tcp.dst_port BETWEEN 80 AND 90)"
        );
    }

    #[test]
    fn test_sql_net_ipv4() {
        let filter = SqlFilter::from_expr(&BpfExpr::Primitive(Primitive::Net {
            direction: Direction::SrcOrDst,
            cidr: Cidr {
                address: IpAddress::V4(Ipv4Addr::new(10, 0, 0, 0)),
                prefix_len: 8,
            },
        }));
        assert_eq!(
            filter.where_clause,
            "ip_in_cidr(ipv4.src_ip, '10.0.0.0/8') OR ip_in_cidr(ipv4.dst_ip, '10.0.0.0/8')"
        );
    }

    #[test]
    fn test_sql_src_net() {
        let filter = SqlFilter::from_expr(&BpfExpr::Primitive(Primitive::Net {
            direction: Direction::Src,
            cidr: Cidr {
                address: IpAddress::V4(Ipv4Addr::new(192, 168, 0, 0)),
                prefix_len: 16,
            },
        }));
        assert_eq!(
            filter.where_clause,
            "ip_in_cidr(ipv4.src_ip, '192.168.0.0/16')"
        );
    }

    #[test]
    fn test_sql_net_ipv6() {
        let filter = SqlFilter::from_expr(&BpfExpr::Primitive(Primitive::Net {
            direction: Direction::SrcOrDst,
            cidr: Cidr {
                address: IpAddress::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
                prefix_len: 32,
            },
        }));
        assert_eq!(
            filter.where_clause,
            "ip6_in_cidr(ipv6.src_ip, '2001:db8::/32') OR ip6_in_cidr(ipv6.dst_ip, '2001:db8::/32')"
        );
    }

    #[test]
    fn test_sql_proto() {
        let filter = SqlFilter::from_expr(&BpfExpr::Primitive(Primitive::Proto(6)));
        assert_eq!(filter.where_clause, "protocol = 6");
    }

    #[test]
    fn test_sql_and() {
        let expr = parse_filter("tcp and port 80").unwrap();
        let filter = SqlFilter::from_expr(&expr);
        assert!(filter.where_clause.contains("AND"));
        assert!(filter.where_clause.contains("tcp.frame_number IS NOT NULL"));
    }

    #[test]
    fn test_sql_or() {
        let expr = parse_filter("tcp or udp").unwrap();
        let filter = SqlFilter::from_expr(&expr);
        assert!(filter.where_clause.contains("OR"));
    }

    #[test]
    fn test_sql_not() {
        let expr = parse_filter("not port 22").unwrap();
        let filter = SqlFilter::from_expr(&expr);
        assert!(filter.where_clause.starts_with("NOT"));
    }

    #[test]
    fn test_sql_complex() {
        let expr = parse_filter("tcp port 80 and host 192.168.1.1").unwrap();
        let filter = SqlFilter::from_expr(&expr);
        assert!(filter.where_clause.contains("AND"));
        assert!(filter.where_clause.contains("tcp.src_port = 80"));
        assert!(filter.where_clause.contains("ip4('192.168.1.1')"));
    }

    #[test]
    fn test_sql_not_port() {
        let expr = parse_filter("host 10.0.0.1 and not port 22").unwrap();
        let filter = SqlFilter::from_expr(&expr);
        assert!(filter.where_clause.contains("AND"));
        assert!(filter.where_clause.contains("NOT"));
        assert!(filter.where_clause.contains("ip4('10.0.0.1')"));
    }
}
