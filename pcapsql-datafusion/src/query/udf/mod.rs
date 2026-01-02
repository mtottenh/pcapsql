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

mod datetime;
mod dns;
mod hex;
mod histogram;
mod icmp;
pub mod info;
mod ipv4;
mod ipv6;
mod mac;
mod protocol;
mod tcp;
mod time;

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

// Re-export datetime UDFs
pub use datetime::{
    create_date_udf, create_datetime_udf, create_epoch_ms_udf, create_epoch_udf,
    create_strftime_udf, create_time_udf,
};

// Re-export time UDFs
pub use time::{
    create_end_time_udf_eager, create_end_time_udf_lazy, create_relative_time_udf,
    create_start_time_udf,
};

// Re-export histogram UDAFs and UDFs
pub use histogram::{
    create_hdr_count_udf, create_hdr_histogram_udaf, create_hdr_max_udf, create_hdr_mean_udf,
    create_hdr_min_udf, create_hdr_percentile_udf, create_hdr_stdev_udf,
};

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

/// Register datetime formatting UDFs with the DataFusion context.
///
/// Provides functions for formatting and manipulating timestamps:
/// - `strftime(format, timestamp)` - Format using strftime codes
/// - `datetime(timestamp)` - ISO 8601 datetime string
/// - `date(timestamp)` - Extract date (YYYY-MM-DD)
/// - `time(timestamp)` - Extract time (HH:MM:SS.ffffff)
/// - `epoch(timestamp)` - Unix epoch seconds (Float64)
/// - `epoch_ms(timestamp)` - Unix epoch milliseconds (Int64)
pub fn register_datetime_udfs(ctx: &SessionContext) -> Result<(), Error> {
    ctx.register_udf(create_strftime_udf());
    ctx.register_udf(create_datetime_udf());
    ctx.register_udf(create_date_udf());
    ctx.register_udf(create_time_udf());
    ctx.register_udf(create_epoch_udf());
    ctx.register_udf(create_epoch_ms_udf());
    Ok(())
}

/// Register HdrHistogram UDAFs and UDFs with the DataFusion context.
///
/// Provides streaming histogram aggregation with constant memory footprint:
/// - `hdr_histogram(value)` - UDAF that builds histogram from streamed values
/// - `hdr_percentile(hist, p)` - Extract percentile from histogram
/// - `hdr_count/min/max/mean/stdev(hist)` - Extract statistics
pub fn register_histogram_udfs(ctx: &SessionContext) -> Result<(), Error> {
    // Aggregate function for building histograms
    ctx.register_udaf(create_hdr_histogram_udaf());

    // Scalar functions for extracting values
    ctx.register_udf(create_hdr_percentile_udf());
    ctx.register_udf(create_hdr_count_udf());
    ctx.register_udf(create_hdr_min_udf());
    ctx.register_udf(create_hdr_max_udf());
    ctx.register_udf(create_hdr_mean_udf());
    ctx.register_udf(create_hdr_stdev_udf());

    Ok(())
}

/// Register ALL UDFs with the DataFusion context.
///
/// This is a convenience function that registers all network, protocol, utility,
/// datetime, and histogram UDFs.
///
/// Note: Time UDFs are NOT included here because they require capture metadata.
/// Use `register_time_udfs_eager()` or `register_time_udfs_lazy()` separately.
pub fn register_all_udfs(ctx: &SessionContext) -> Result<(), Error> {
    register_network_udfs(ctx)?;
    register_protocol_udfs(ctx)?;
    register_utility_udfs(ctx)?;
    register_datetime_udfs(ctx)?;
    register_histogram_udfs(ctx)?;
    Ok(())
}

/// Register time UDFs with known timestamps (eager mode).
///
/// Used in in-memory mode where all packets have been loaded and
/// timestamps are already extracted from the frames table.
///
/// # Arguments
///
/// * `ctx` - DataFusion session context
/// * `start_us` - Capture start timestamp (microseconds since epoch)
/// * `end_us` - Capture end timestamp (microseconds since epoch)
pub fn register_time_udfs_eager(
    ctx: &SessionContext,
    start_us: i64,
    end_us: i64,
) -> Result<(), Error> {
    ctx.register_udf(create_start_time_udf(start_us));
    ctx.register_udf(create_end_time_udf_eager(end_us));
    ctx.register_udf(create_relative_time_udf(start_us));
    Ok(())
}

/// Register time UDFs with lazy end_time evaluation (streaming mode).
///
/// Used in streaming mode where we don't want to scan the entire file
/// upfront. The `end_time()` function will scan the file on first call
/// and cache the result.
///
/// # Arguments
///
/// * `ctx` - DataFusion session context
/// * `start_us` - Capture start timestamp (microseconds since epoch)
/// * `end_scan_fn` - Closure that scans for the last packet timestamp
pub fn register_time_udfs_lazy<F>(
    ctx: &SessionContext,
    start_us: i64,
    end_scan_fn: F,
) -> Result<(), Error>
where
    F: Fn() -> i64 + Send + Sync + 'static,
{
    ctx.register_udf(create_start_time_udf(start_us));
    ctx.register_udf(create_end_time_udf_lazy(end_scan_fn));
    ctx.register_udf(create_relative_time_udf(start_us));
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

    #[test]
    fn test_register_datetime_udfs() {
        let ctx = SessionContext::new();
        register_datetime_udfs(&ctx).unwrap();
    }

    #[test]
    fn test_register_time_udfs_eager() {
        let ctx = SessionContext::new();
        let start_us: i64 = 1_704_067_200_000_000;
        let end_us: i64 = 1_704_153_600_000_000;
        register_time_udfs_eager(&ctx, start_us, end_us).unwrap();
    }

    #[test]
    fn test_register_time_udfs_lazy() {
        let ctx = SessionContext::new();
        let start_us: i64 = 1_704_067_200_000_000;
        let end_us: i64 = 1_704_153_600_000_000;
        register_time_udfs_lazy(&ctx, start_us, move || end_us).unwrap();
    }
}
