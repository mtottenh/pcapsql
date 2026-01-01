//! BPF (Berkeley Packet Filter) filter syntax support.
//!
//! This module provides tcpdump-style BPF filter parsing and translation to SQL.
//!
//! # Example
//!
//! ```rust
//! use pcapsql_datafusion::query::bpf::parse_bpf_filter;
//!
//! let filter = parse_bpf_filter("tcp port 80 and host 192.168.1.1").unwrap();
//! println!("WHERE {}", filter.where_clause);
//! // Output: WHERE (tcp.src_port = 80 OR tcp.dst_port = 80) AND (ipv4.src_ip = ip4('192.168.1.1') OR ipv4.dst_ip = ip4('192.168.1.1'))
//! ```
//!
//! # Usage with Normalized Tables
//!
//! The generated SQL uses table-qualified column names (e.g., `tcp.src_port`, `ipv4.src_ip`).
//! For best results, use queries that JOIN the relevant protocol tables:
//!
//! ```bash
//! # Works: query JOINs tcp and ipv4 tables
//! pcapsql capture.pcap --filter "tcp port 80 and host 10.0.0.1" \
//!   -e "SELECT * FROM tcp JOIN ipv4 ON tcp.frame_number = ipv4.frame_number"
//!
//! # Works: simple protocol filter with single table
//! pcapsql capture.pcap --filter "tcp" -e "SELECT * FROM tcp"
//! ```
//!
//! # Supported Syntax
//!
//! ## Protocol filters
//! - `tcp`, `udp`, `icmp`, `icmp6`, `arp`, `ip`, `ip6`
//!
//! ## Host filters
//! - `host 192.168.1.1` - Match source or destination
//! - `src host 10.0.0.1` - Match source only
//! - `dst host ::1` - Match destination only (IPv6)
//!
//! ## Port filters
//! - `port 80` - Match TCP or UDP port
//! - `tcp port 443` - Match TCP port only
//! - `src port 22` - Match source port
//! - `dst udp port 53` - Match UDP destination port
//!
//! ## Port range filters
//! - `portrange 80-90` - Match port range
//! - `tcp portrange 1024-65535`
//!
//! ## Network filters
//! - `net 10.0.0.0/8` - Match CIDR network
//! - `src net 192.168.0.0/16`
//! - `net 2001:db8::/32` - IPv6 CIDR
//!
//! ## Protocol number filter
//! - `proto 6` - Match IP protocol number (6 = TCP)
//!
//! ## Boolean operators
//! - `and`, `&&` - Logical AND
//! - `or`, `||` - Logical OR
//! - `not`, `!` - Logical NOT
//! - Parentheses for grouping: `(tcp or udp) and port 80`

mod ast;
mod error;
mod parser;
mod sql;

pub use ast::{BpfExpr, Cidr, Direction, IpAddress, Primitive, Protocol};
pub use error::BpfError;
pub use parser::parse_filter;
pub use sql::SqlFilter;

/// Parse a BPF filter expression and convert it to SQL.
///
/// This is the main entry point for BPF filter support.
///
/// # Arguments
///
/// * `filter` - A tcpdump-style BPF filter expression
///
/// # Returns
///
/// A `SqlFilter` containing the SQL WHERE clause fragment.
///
/// # Errors
///
/// Returns `BpfError` if the filter expression is invalid.
///
/// # Example
///
/// ```rust
/// use pcapsql_datafusion::query::bpf::parse_bpf_filter;
///
/// let filter = parse_bpf_filter("tcp and port 80")?;
/// let query = format!("SELECT * FROM tcp WHERE {}", filter.where_clause);
/// # Ok::<(), pcapsql_datafusion::query::bpf::BpfError>(())
/// ```
pub fn parse_bpf_filter(filter: &str) -> Result<SqlFilter, BpfError> {
    let expr = parse_filter(filter)?;
    Ok(SqlFilter::from_expr(&expr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bpf_filter_tcp() {
        let filter = parse_bpf_filter("tcp").unwrap();
        assert_eq!(filter.where_clause, "tcp.frame_number IS NOT NULL");
    }

    #[test]
    fn test_parse_bpf_filter_host() {
        let filter = parse_bpf_filter("host 192.168.1.1").unwrap();
        assert!(filter.where_clause.contains("ip4('192.168.1.1')"));
    }

    #[test]
    fn test_parse_bpf_filter_complex() {
        let filter = parse_bpf_filter("tcp port 80 and host 10.0.0.1").unwrap();
        assert!(filter.where_clause.contains("AND"));
        assert!(filter.where_clause.contains("tcp"));
        assert!(filter.where_clause.contains("ip4('10.0.0.1')"));
    }

    #[test]
    fn test_parse_bpf_filter_error() {
        let result = parse_bpf_filter("invalid @#$ filter");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_bpf_filter_empty() {
        let result = parse_bpf_filter("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_bpf_filter_whitespace_only() {
        let result = parse_bpf_filter("   ");
        assert!(result.is_err());
    }
}
