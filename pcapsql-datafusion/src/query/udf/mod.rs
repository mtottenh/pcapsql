//! User-Defined Functions (UDFs) for network address and protocol operations.
//!
//! This module provides DataFusion UDFs for working with network data
//! stored in native binary formats:
//!
//! ## Address Functions
//!
//! - IPv4: `UInt32` (4 bytes, network byte order)
//! - IPv6: `FixedSizeBinary(16)` (16 bytes)
//! - MAC: `FixedSizeBinary(6)` (6 bytes)
//!
//! ### Conversion Functions
//!
//! - `ip4('192.168.1.1')` - Parse IPv4 string to UInt32
//! - `ip6('fe80::1')` - Parse IPv6 string to Binary(16)
//! - `mac('aa:bb:cc:dd:ee:ff')` - Parse MAC string to Binary(6)
//! - `ip4_to_string(ip)` - Convert UInt32 to IPv4 string
//! - `ip6_to_string(ip)` - Convert Binary(16) to IPv6 string
//! - `mac_to_string(mac)` - Convert Binary(6) to MAC string
//!
//! ### CIDR Matching Functions
//!
//! - `ip_in_cidr(ip, 'x.x.x.x/n')` - Check if IPv4 is in CIDR range
//! - `ip6_in_cidr(ip, 'xxxx::/n')` - Check if IPv6 is in CIDR prefix
//!
//! ## Protocol Functions
//!
//! ### TCP Flags
//!
//! - `tcp_flags_str(flags)` - Convert TCP flags bitmap to string (e.g., "SYN,ACK")
//! - `has_tcp_flag(flags, 'SYN')` - Check if specific flag is set
//!
//! ### DNS
//!
//! - `dns_type_name(type)` - Convert DNS type number to name (e.g., "A", "AAAA")
//! - `dns_rcode_name(rcode)` - Convert DNS response code to name (e.g., "NXDOMAIN")
//! - `dns_class_name(class)` - Convert DNS class to name (e.g., "IN")
//!
//! ### ICMP
//!
//! - `icmp_type_name(type)` - Convert ICMP type to name (e.g., "Echo Request")
//! - `icmpv6_type_name(type)` - Convert ICMPv6 type to name
//!
//! ### Protocol Numbers
//!
//! - `ip_proto_name(proto)` - Convert IP protocol number to name (e.g., "TCP", "UDP")
//! - `ethertype_name(type)` - Convert EtherType to name (e.g., "IPv4", "ARP")
//!
//! ## Utility Functions
//!
//! - `hex(binary)` - Convert binary data to hex string
//! - `unhex(string)` - Parse hex string to binary
//!
//! ## Example Queries
//!
//! ```sql
//! -- Exact match
//! SELECT * FROM ipv4 WHERE src_ip = ip4('192.168.1.1');
//!
//! -- CIDR matching
//! SELECT * FROM ipv4 WHERE ip_in_cidr(src_ip, '192.168.0.0/16');
//!
//! -- Range query
//! SELECT * FROM ipv4 WHERE src_ip BETWEEN ip4('10.0.0.0') AND ip4('10.0.0.255');
//!
//! -- Display with string conversion
//! SELECT ip4_to_string(src_ip) AS src, ip4_to_string(dst_ip) AS dst FROM ipv4;
//!
//! -- TCP flag analysis
//! SELECT * FROM tcp WHERE has_tcp_flag(flags, 'SYN');
//! SELECT tcp_flags_str(flags) AS flags FROM tcp;
//!
//! -- Protocol breakdown
//! SELECT ip_proto_name(protocol) AS proto, COUNT(*) FROM ipv4 GROUP BY protocol;
//! ```

mod dns;
mod hex;
mod icmp;
mod ipv4;
mod ipv6;
mod mac;
mod protocol;
mod tcp;

// Re-export address UDFs
pub use ipv4::{create_ip4_to_string_udf, create_ip4_udf, create_ip_in_cidr_udf};
pub use ipv6::{create_ip6_in_cidr_udf, create_ip6_to_string_udf, create_ip6_udf};
pub use mac::{create_mac_to_string_udf, create_mac_udf};

// Re-export protocol UDFs
pub use dns::{create_dns_class_name_udf, create_dns_rcode_name_udf, create_dns_type_name_udf};
pub use icmp::{create_icmp_type_name_udf, create_icmpv6_type_name_udf};
pub use protocol::{create_ethertype_name_udf, create_ip_proto_name_udf};
pub use tcp::{create_has_tcp_flag_udf, create_tcp_flags_str_udf};

// Re-export utility UDFs
pub use hex::{create_hex_udf, create_unhex_udf};

use crate::error::Error;
use datafusion::prelude::SessionContext;

/// Register all network address UDFs with the DataFusion context.
pub fn register_network_udfs(ctx: &SessionContext) -> Result<(), Error> {
    // IPv4 functions
    ctx.register_udf(create_ip4_udf());
    ctx.register_udf(create_ip4_to_string_udf());
    ctx.register_udf(create_ip_in_cidr_udf());

    // IPv6 functions
    ctx.register_udf(create_ip6_udf());
    ctx.register_udf(create_ip6_to_string_udf());
    ctx.register_udf(create_ip6_in_cidr_udf());

    // MAC functions
    ctx.register_udf(create_mac_udf());
    ctx.register_udf(create_mac_to_string_udf());

    Ok(())
}

/// Register protocol name/flag UDFs with the DataFusion context.
pub fn register_protocol_udfs(ctx: &SessionContext) -> Result<(), Error> {
    // TCP flags
    ctx.register_udf(create_tcp_flags_str_udf());
    ctx.register_udf(create_has_tcp_flag_udf());

    // DNS
    ctx.register_udf(create_dns_type_name_udf());
    ctx.register_udf(create_dns_rcode_name_udf());
    ctx.register_udf(create_dns_class_name_udf());

    // ICMP
    ctx.register_udf(create_icmp_type_name_udf());
    ctx.register_udf(create_icmpv6_type_name_udf());

    // Protocol numbers
    ctx.register_udf(create_ip_proto_name_udf());
    ctx.register_udf(create_ethertype_name_udf());

    Ok(())
}

/// Register utility UDFs with the DataFusion context.
pub fn register_utility_udfs(ctx: &SessionContext) -> Result<(), Error> {
    ctx.register_udf(create_hex_udf());
    ctx.register_udf(create_unhex_udf());
    Ok(())
}

/// Register ALL UDFs with the DataFusion context.
///
/// This is a convenience function that registers all network, protocol, and utility UDFs.
pub fn register_all_udfs(ctx: &SessionContext) -> Result<(), Error> {
    register_network_udfs(ctx)?;
    register_protocol_udfs(ctx)?;
    register_utility_udfs(ctx)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_network_udfs() {
        let ctx = SessionContext::new();
        register_network_udfs(&ctx).unwrap();
    }

    #[test]
    fn test_register_protocol_udfs() {
        let ctx = SessionContext::new();
        register_protocol_udfs(&ctx).unwrap();
    }

    #[test]
    fn test_register_utility_udfs() {
        let ctx = SessionContext::new();
        register_utility_udfs(&ctx).unwrap();
    }

    #[test]
    fn test_register_all_udfs() {
        let ctx = SessionContext::new();
        register_all_udfs(&ctx).unwrap();
    }
}
