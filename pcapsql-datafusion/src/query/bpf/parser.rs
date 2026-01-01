//! BPF filter parser using nom.
//!
//! Grammar (operator precedence: NOT > AND > OR):
//! ```text
//! filter     = expr
//! expr       = term (("or") term)*
//! term       = factor (("and") factor)*
//! factor     = "not" factor | "(" expr ")" | primitive
//! primitive  = protocol | host | port | portrange | net | proto
//! ```

use std::net::{Ipv4Addr, Ipv6Addr};

use nom::{
    branch::alt,
    bytes::complete::{tag_no_case, take_while1},
    character::complete::{char, digit1, multispace0, multispace1},
    combinator::{all_consuming, map, map_res, opt, recognize, value},
    multi::many0,
    sequence::{delimited, pair, preceded, separated_pair, terminated, tuple},
    IResult,
};

use super::ast::{BpfExpr, Cidr, Direction, IpAddress, Primitive, Protocol};
use super::error::BpfError;

/// Parse a complete BPF filter expression.
pub fn parse_filter(input: &str) -> Result<BpfExpr, BpfError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(BpfError::EmptyFilter);
    }

    match all_consuming(preceded(multispace0, expr))(input) {
        Ok((_, expr)) => Ok(expr),
        Err(e) => Err(BpfError::parse_error(format!("{e}"))),
    }
}

// =============================================================================
// Expression Parsers (handle operator precedence)
// =============================================================================

/// Parse an expression (OR level - lowest precedence).
fn expr(input: &str) -> IResult<&str, BpfExpr> {
    let (input, first) = term(input)?;
    let (input, rest) = many0(preceded(
        delimited(multispace0, tag_no_case("or"), multispace1),
        term,
    ))(input)?;

    let result = rest.into_iter().fold(first, BpfExpr::or);
    Ok((input, result))
}

/// Parse a term (AND level).
fn term(input: &str) -> IResult<&str, BpfExpr> {
    let (input, first) = factor(input)?;
    let (input, rest) = many0(preceded(
        delimited(multispace0, tag_no_case("and"), multispace1),
        factor,
    ))(input)?;

    let result = rest.into_iter().fold(first, BpfExpr::and);
    Ok((input, result))
}

/// Parse a factor (NOT and parentheses).
fn factor(input: &str) -> IResult<&str, BpfExpr> {
    alt((not_expr, paren_expr, primitive_expr))(input)
}

/// Parse NOT expression.
fn not_expr(input: &str) -> IResult<&str, BpfExpr> {
    let (input, _) = tag_no_case("not")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, expr) = factor(input)?;
    Ok((input, BpfExpr::negate(expr)))
}

/// Parse parenthesized expression.
fn paren_expr(input: &str) -> IResult<&str, BpfExpr> {
    delimited(
        pair(char('('), multispace0),
        expr,
        pair(multispace0, char(')')),
    )(input)
}

/// Parse a primitive expression.
fn primitive_expr(input: &str) -> IResult<&str, BpfExpr> {
    map(primitive, BpfExpr::Primitive)(input)
}

// =============================================================================
// Primitive Parsers
// =============================================================================

/// Parse any primitive filter.
fn primitive(input: &str) -> IResult<&str, Primitive> {
    alt((
        proto_filter,
        net_filter,
        portrange_filter,
        port_filter,
        host_filter,
        protocol_filter,
    ))(input)
}

/// Parse protocol filter: tcp, udp, icmp, etc.
fn protocol_filter(input: &str) -> IResult<&str, Primitive> {
    map(protocol, Primitive::Protocol)(input)
}

/// Parse a protocol keyword.
fn protocol(input: &str) -> IResult<&str, Protocol> {
    alt((
        value(Protocol::Tcp, tag_no_case("tcp")),
        value(Protocol::Udp, tag_no_case("udp")),
        value(Protocol::Icmp6, tag_no_case("icmp6")),
        value(Protocol::Icmp, tag_no_case("icmp")),
        value(Protocol::Arp, tag_no_case("arp")),
        value(Protocol::Ip6, tag_no_case("ip6")),
        value(Protocol::Ip, tag_no_case("ip")),
    ))(input)
}

/// Parse host filter: [src|dst] host <address>
fn host_filter(input: &str) -> IResult<&str, Primitive> {
    let (input, dir) = opt(terminated(direction, multispace1))(input)?;
    let (input, _) = tag_no_case("host")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, addr) = ip_address(input)?;

    Ok((
        input,
        Primitive::Host {
            direction: dir.unwrap_or(Direction::SrcOrDst),
            address: addr,
        },
    ))
}

/// Parse port filter: [src|dst] [tcp|udp] port <number>
fn port_filter(input: &str) -> IResult<&str, Primitive> {
    let (input, dir) = opt(terminated(direction, multispace1))(input)?;
    let (input, proto) = opt(terminated(transport_protocol, multispace1))(input)?;
    let (input, _) = tag_no_case("port")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, port) = port_number(input)?;

    Ok((
        input,
        Primitive::Port {
            direction: dir.unwrap_or(Direction::SrcOrDst),
            protocol: proto,
            port,
        },
    ))
}

/// Parse port range filter: [src|dst] [tcp|udp] portrange <start>-<end>
fn portrange_filter(input: &str) -> IResult<&str, Primitive> {
    let (input, dir) = opt(terminated(direction, multispace1))(input)?;
    let (input, proto) = opt(terminated(transport_protocol, multispace1))(input)?;
    let (input, _) = tag_no_case("portrange")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, (start, end)) = separated_pair(port_number, char('-'), port_number)(input)?;

    Ok((
        input,
        Primitive::PortRange {
            direction: dir.unwrap_or(Direction::SrcOrDst),
            protocol: proto,
            start,
            end,
        },
    ))
}

/// Parse net filter: [src|dst] net <cidr>
fn net_filter(input: &str) -> IResult<&str, Primitive> {
    let (input, dir) = opt(terminated(direction, multispace1))(input)?;
    let (input, _) = tag_no_case("net")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, cidr) = cidr(input)?;

    Ok((
        input,
        Primitive::Net {
            direction: dir.unwrap_or(Direction::SrcOrDst),
            cidr,
        },
    ))
}

/// Parse proto filter: proto <number>
fn proto_filter(input: &str) -> IResult<&str, Primitive> {
    let (input, _) = tag_no_case("proto")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, num) = map_res(digit1, |s: &str| s.parse::<u8>())(input)?;

    Ok((input, Primitive::Proto(num)))
}

// =============================================================================
// Helper Parsers
// =============================================================================

/// Parse direction qualifier: src or dst
fn direction(input: &str) -> IResult<&str, Direction> {
    alt((
        value(Direction::Src, tag_no_case("src")),
        value(Direction::Dst, tag_no_case("dst")),
    ))(input)
}

/// Parse transport protocol qualifier: tcp or udp
fn transport_protocol(input: &str) -> IResult<&str, Protocol> {
    alt((
        value(Protocol::Tcp, tag_no_case("tcp")),
        value(Protocol::Udp, tag_no_case("udp")),
    ))(input)
}

/// Parse an IP address (IPv4 or IPv6).
fn ip_address(input: &str) -> IResult<&str, IpAddress> {
    alt((map(ipv6_addr, IpAddress::V6), map(ipv4_addr, IpAddress::V4)))(input)
}

/// Parse an IPv4 address.
fn ipv4_addr(input: &str) -> IResult<&str, Ipv4Addr> {
    let (input, addr_str) = recognize(tuple((
        digit1,
        char('.'),
        digit1,
        char('.'),
        digit1,
        char('.'),
        digit1,
    )))(input)?;

    match addr_str.parse::<Ipv4Addr>() {
        Ok(addr) => Ok((input, addr)),
        Err(_) => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::MapRes,
        ))),
    }
}

/// Parse an IPv6 address.
fn ipv6_addr(input: &str) -> IResult<&str, Ipv6Addr> {
    // IPv6 can contain hex digits, colons, and possibly dots (for v4-mapped)
    let (input, addr_str) =
        take_while1(|c: char| c.is_ascii_hexdigit() || c == ':' || c == '.')(input)?;

    // Must contain at least one colon to be IPv6
    if !addr_str.contains(':') {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }

    match addr_str.parse::<Ipv6Addr>() {
        Ok(addr) => Ok((input, addr)),
        Err(_) => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::MapRes,
        ))),
    }
}

/// Parse a CIDR notation: address/prefix
fn cidr(input: &str) -> IResult<&str, Cidr> {
    let (input, addr) = ip_address(input)?;
    let (input, _) = char('/')(input)?;
    let (input, prefix_len) = map_res(digit1, |s: &str| s.parse::<u8>())(input)?;

    // Validate prefix length
    let max_prefix = match &addr {
        IpAddress::V4(_) => 32,
        IpAddress::V6(_) => 128,
    };

    if prefix_len > max_prefix {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )));
    }

    Ok((
        input,
        Cidr {
            address: addr,
            prefix_len,
        },
    ))
}

/// Parse a port number (0-65535).
fn port_number(input: &str) -> IResult<&str, u16> {
    map_res(digit1, |s: &str| s.parse::<u16>())(input)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tcp() {
        let expr = parse_filter("tcp").unwrap();
        assert_eq!(expr, BpfExpr::Primitive(Primitive::Protocol(Protocol::Tcp)));
    }

    #[test]
    fn test_parse_udp() {
        let expr = parse_filter("udp").unwrap();
        assert_eq!(expr, BpfExpr::Primitive(Primitive::Protocol(Protocol::Udp)));
    }

    #[test]
    fn test_parse_icmp() {
        let expr = parse_filter("icmp").unwrap();
        assert_eq!(
            expr,
            BpfExpr::Primitive(Primitive::Protocol(Protocol::Icmp))
        );
    }

    #[test]
    fn test_parse_case_insensitive() {
        let expr1 = parse_filter("TCP").unwrap();
        let expr2 = parse_filter("Tcp").unwrap();
        let expr3 = parse_filter("tcp").unwrap();
        assert_eq!(expr1, expr2);
        assert_eq!(expr2, expr3);
    }

    #[test]
    fn test_parse_host_ipv4() {
        let expr = parse_filter("host 192.168.1.1").unwrap();
        assert_eq!(
            expr,
            BpfExpr::Primitive(Primitive::Host {
                direction: Direction::SrcOrDst,
                address: IpAddress::V4(Ipv4Addr::new(192, 168, 1, 1)),
            })
        );
    }

    #[test]
    fn test_parse_src_host() {
        let expr = parse_filter("src host 10.0.0.1").unwrap();
        assert_eq!(
            expr,
            BpfExpr::Primitive(Primitive::Host {
                direction: Direction::Src,
                address: IpAddress::V4(Ipv4Addr::new(10, 0, 0, 1)),
            })
        );
    }

    #[test]
    fn test_parse_dst_host() {
        let expr = parse_filter("dst host 10.0.0.2").unwrap();
        assert_eq!(
            expr,
            BpfExpr::Primitive(Primitive::Host {
                direction: Direction::Dst,
                address: IpAddress::V4(Ipv4Addr::new(10, 0, 0, 2)),
            })
        );
    }

    #[test]
    fn test_parse_host_ipv6() {
        let expr = parse_filter("host ::1").unwrap();
        assert_eq!(
            expr,
            BpfExpr::Primitive(Primitive::Host {
                direction: Direction::SrcOrDst,
                address: IpAddress::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            })
        );
    }

    #[test]
    fn test_parse_host_ipv6_full() {
        let expr = parse_filter("host 2001:db8::1").unwrap();
        assert_eq!(
            expr,
            BpfExpr::Primitive(Primitive::Host {
                direction: Direction::SrcOrDst,
                address: IpAddress::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            })
        );
    }

    #[test]
    fn test_parse_port() {
        let expr = parse_filter("port 80").unwrap();
        assert_eq!(
            expr,
            BpfExpr::Primitive(Primitive::Port {
                direction: Direction::SrcOrDst,
                protocol: None,
                port: 80,
            })
        );
    }

    #[test]
    fn test_parse_tcp_port() {
        let expr = parse_filter("tcp port 443").unwrap();
        assert_eq!(
            expr,
            BpfExpr::Primitive(Primitive::Port {
                direction: Direction::SrcOrDst,
                protocol: Some(Protocol::Tcp),
                port: 443,
            })
        );
    }

    #[test]
    fn test_parse_src_port() {
        let expr = parse_filter("src port 22").unwrap();
        assert_eq!(
            expr,
            BpfExpr::Primitive(Primitive::Port {
                direction: Direction::Src,
                protocol: None,
                port: 22,
            })
        );
    }

    #[test]
    fn test_parse_dst_tcp_port() {
        let expr = parse_filter("dst tcp port 8080").unwrap();
        assert_eq!(
            expr,
            BpfExpr::Primitive(Primitive::Port {
                direction: Direction::Dst,
                protocol: Some(Protocol::Tcp),
                port: 8080,
            })
        );
    }

    #[test]
    fn test_parse_portrange() {
        let expr = parse_filter("portrange 80-90").unwrap();
        assert_eq!(
            expr,
            BpfExpr::Primitive(Primitive::PortRange {
                direction: Direction::SrcOrDst,
                protocol: None,
                start: 80,
                end: 90,
            })
        );
    }

    #[test]
    fn test_parse_net_ipv4() {
        let expr = parse_filter("net 10.0.0.0/8").unwrap();
        assert_eq!(
            expr,
            BpfExpr::Primitive(Primitive::Net {
                direction: Direction::SrcOrDst,
                cidr: Cidr {
                    address: IpAddress::V4(Ipv4Addr::new(10, 0, 0, 0)),
                    prefix_len: 8,
                },
            })
        );
    }

    #[test]
    fn test_parse_src_net() {
        let expr = parse_filter("src net 192.168.0.0/16").unwrap();
        assert_eq!(
            expr,
            BpfExpr::Primitive(Primitive::Net {
                direction: Direction::Src,
                cidr: Cidr {
                    address: IpAddress::V4(Ipv4Addr::new(192, 168, 0, 0)),
                    prefix_len: 16,
                },
            })
        );
    }

    #[test]
    fn test_parse_net_ipv6() {
        let expr = parse_filter("net 2001:db8::/32").unwrap();
        assert_eq!(
            expr,
            BpfExpr::Primitive(Primitive::Net {
                direction: Direction::SrcOrDst,
                cidr: Cidr {
                    address: IpAddress::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
                    prefix_len: 32,
                },
            })
        );
    }

    #[test]
    fn test_parse_proto() {
        let expr = parse_filter("proto 6").unwrap();
        assert_eq!(expr, BpfExpr::Primitive(Primitive::Proto(6)));
    }

    #[test]
    fn test_parse_and() {
        let expr = parse_filter("tcp and port 80").unwrap();
        match expr {
            BpfExpr::And(left, right) => {
                assert_eq!(
                    *left,
                    BpfExpr::Primitive(Primitive::Protocol(Protocol::Tcp))
                );
                assert!(matches!(
                    *right,
                    BpfExpr::Primitive(Primitive::Port { port: 80, .. })
                ));
            }
            _ => panic!("Expected And expression"),
        }
    }

    #[test]
    fn test_parse_or() {
        let expr = parse_filter("tcp or udp").unwrap();
        match expr {
            BpfExpr::Or(left, right) => {
                assert_eq!(
                    *left,
                    BpfExpr::Primitive(Primitive::Protocol(Protocol::Tcp))
                );
                assert_eq!(
                    *right,
                    BpfExpr::Primitive(Primitive::Protocol(Protocol::Udp))
                );
            }
            _ => panic!("Expected Or expression"),
        }
    }

    #[test]
    fn test_parse_not() {
        let expr = parse_filter("not port 22").unwrap();
        match expr {
            BpfExpr::Not(inner) => {
                assert!(matches!(
                    *inner,
                    BpfExpr::Primitive(Primitive::Port { port: 22, .. })
                ));
            }
            _ => panic!("Expected Not expression"),
        }
    }

    #[test]
    fn test_parse_parentheses() {
        let expr = parse_filter("(tcp or udp) and port 80").unwrap();
        match expr {
            BpfExpr::And(left, right) => {
                assert!(matches!(*left, BpfExpr::Or(_, _)));
                assert!(matches!(
                    *right,
                    BpfExpr::Primitive(Primitive::Port { port: 80, .. })
                ));
            }
            _ => panic!("Expected And expression with Or left child"),
        }
    }

    #[test]
    fn test_parse_complex() {
        let expr = parse_filter("tcp port 80 and host 192.168.1.1").unwrap();
        match expr {
            BpfExpr::And(left, right) => {
                assert!(matches!(
                    *left,
                    BpfExpr::Primitive(Primitive::Port {
                        port: 80,
                        protocol: Some(Protocol::Tcp),
                        ..
                    })
                ));
                assert!(matches!(*right, BpfExpr::Primitive(Primitive::Host { .. })));
            }
            _ => panic!("Expected And expression"),
        }
    }

    #[test]
    fn test_parse_not_port() {
        let expr = parse_filter("host 10.0.0.1 and not port 22").unwrap();
        match expr {
            BpfExpr::And(left, right) => {
                assert!(matches!(*left, BpfExpr::Primitive(Primitive::Host { .. })));
                assert!(matches!(*right, BpfExpr::Not(_)));
            }
            _ => panic!("Expected And expression"),
        }
    }

    #[test]
    fn test_parse_precedence() {
        // AND has higher precedence than OR
        // "tcp or udp and port 80" should be parsed as "tcp or (udp and port 80)"
        let expr = parse_filter("tcp or udp and port 80").unwrap();
        match expr {
            BpfExpr::Or(left, right) => {
                assert_eq!(
                    *left,
                    BpfExpr::Primitive(Primitive::Protocol(Protocol::Tcp))
                );
                assert!(matches!(*right, BpfExpr::And(_, _)));
            }
            _ => panic!("Expected Or expression (AND has higher precedence)"),
        }
    }

    #[test]
    fn test_parse_whitespace() {
        let expr = parse_filter("  tcp   and   port  80  ").unwrap();
        assert!(matches!(expr, BpfExpr::And(_, _)));
    }

    #[test]
    fn test_parse_empty() {
        let result = parse_filter("");
        assert!(matches!(result, Err(BpfError::EmptyFilter)));
    }

    #[test]
    fn test_parse_whitespace_only() {
        let result = parse_filter("   ");
        assert!(matches!(result, Err(BpfError::EmptyFilter)));
    }

    #[test]
    fn test_parse_invalid() {
        let result = parse_filter("foobar");
        assert!(result.is_err());
    }
}
