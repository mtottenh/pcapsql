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
//! - `icmp_code_name(type, code)` - Convert ICMP type+code to detailed name (e.g., "Port Unreachable")
//! - `icmpv6_code_name(type, code)` - Convert ICMPv6 type+code to detailed name
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

mod bgp;
mod datetime;
mod dns;
mod gtp;
mod hex;
mod histogram;
mod icmp;
pub mod info;
mod ipv4;
mod ipv6;
mod mac;
mod ntp_proto;
mod ospf;
mod protocol;
mod tcp;
mod time;
mod tls_proto;

// Re-export address UDFs
pub use ipv4::{
    create_ip4_to_string_udf, create_ip4_udf, create_ip_in_cidr_udf, create_is_loopback_ip_udf,
    create_is_multicast_ip_udf, create_is_private_ip_udf,
};
pub use ipv6::{
    create_ip6_in_cidr_udf, create_ip6_to_string_udf, create_ip6_udf, create_is_link_local_ip6_udf,
    create_is_multicast_ip6_udf,
};
pub use mac::{
    create_mac_is_broadcast_udf, create_mac_is_local_udf, create_mac_is_multicast_udf,
    create_mac_to_string_udf, create_mac_udf,
};

// Re-export protocol UDFs
pub use bgp::{create_bgp_message_type_name_udf, create_bgp_origin_name_udf};
pub use dns::{create_dns_class_name_udf, create_dns_rcode_name_udf, create_dns_type_name_udf};
pub use gtp::create_gtp_message_type_name_udf;
pub use icmp::{
    create_icmp_code_name_udf, create_icmp_type_name_udf, create_icmpv6_code_name_udf,
    create_icmpv6_type_name_udf,
};
pub use ntp_proto::{create_ntp_mode_name_udf, create_ntp_stratum_name_udf};
pub use ospf::{create_ospf_lsa_type_name_udf, create_ospf_packet_type_name_udf};
pub use protocol::{
    create_dscp_name_udf, create_ecn_name_udf, create_ethertype_name_udf, create_ip_proto_name_udf,
};
pub use tcp::{create_has_tcp_flag_udf, create_tcp_flags_str_udf};
pub use tls_proto::{create_tls_record_type_name_udf, create_tls_version_name_udf};

// Re-export utility UDFs
pub use hex::{create_hex_udf, create_unhex_udf};

// Re-export datetime UDFs
pub use datetime::{
    create_date_udf, create_datetime_udf, create_epoch_ms_udf, create_epoch_udf,
    create_strftime_udf, create_time_udf,
};

// Re-export time UDFs
pub use time::{
    create_end_time_udf, create_relative_time_udf, create_start_time_udf, CaptureTimeRange,
};

// Re-export histogram UDAFs and UDFs
pub use histogram::{
    create_hdr_ascii_udf, create_hdr_buckets_udf, create_hdr_count_udf, create_hdr_histogram_udaf,
    create_hdr_max_udf, create_hdr_mean_udf, create_hdr_min_udf, create_hdr_percentile_udf,
    create_hdr_stdev_udf,
};

use crate::error::Error;
use arrow::array::{Array, StringArray};
use arrow::datatypes::DataType;
use datafusion::common::types::{
    logical_string, logical_uint16, logical_uint32, logical_uint64, logical_uint8, NativeType,
};
use datafusion::common::{DataFusionError, Result as DFResult};
use datafusion::logical_expr::{Coercion, Signature, TypeSignatureClass, Volatility};
use datafusion::prelude::SessionContext;

/// A signature whose unsigned-integer parameters accept any integer argument.
///
/// `Signature::exact([UInt8])` only matches a `UInt8` *column*: DataFusion
/// never widens or narrows an `Int64` literal to it, so `dscp_name(46)` would
/// fail to plan. Here each `UInt*` parameter is a coercible slot: an argument
/// of that exact type passes through, any other integer type (the `Int64` of
/// a literal, a `UInt32` column into a `UInt16` slot, …) is cast to it by the
/// planner, and a non-integer argument is still rejected at planning. The
/// cast is not range-checked: an integer that does not fit the parameter
/// (`dscp_name(300)`, `tcp_flags_str(70000)`, a negative value) plans and
/// then fails with a cast error, for a literal at optimization and for a
/// column at execution; NULL passes through as NULL.
///
/// A `Utf8` parameter accepts any string type. DataFusion keeps the
/// argument's physical string type (`Utf8`, `LargeUtf8`, or the `Utf8View`
/// that SQL `VARCHAR`/`TEXT` casts produce), so a body must read the
/// argument through [`string_arg`], which normalizes it to a `StringArray`.
pub(crate) fn coercible_signature(params: &[DataType], volatility: Volatility) -> Signature {
    let coercions = params
        .iter()
        .map(|param| match param {
            DataType::UInt8 => integer_slot(logical_uint8(), NativeType::UInt8),
            DataType::UInt16 => integer_slot(logical_uint16(), NativeType::UInt16),
            DataType::UInt32 => integer_slot(logical_uint32(), NativeType::UInt32),
            DataType::UInt64 => integer_slot(logical_uint64(), NativeType::UInt64),
            DataType::Utf8 => Coercion::new_exact(TypeSignatureClass::Native(logical_string())),
            other => unreachable!("coercible_signature: unsupported parameter type {other}"),
        })
        .collect();
    Signature::coercible(coercions, volatility)
}

/// A UDF's string argument as a `StringArray`, whatever string type the
/// planner delivered (`Utf8`, `LargeUtf8`, `Utf8View`); anything else is a
/// planning/execution error naming the UDF, never a panic.
pub(crate) fn string_arg(array: &arrow::array::ArrayRef, udf: &str) -> DFResult<StringArray> {
    let utf8 = match array.data_type() {
        DataType::Utf8 => array.clone(),
        DataType::LargeUtf8 | DataType::Utf8View => arrow::compute::cast(array, &DataType::Utf8)?,
        other => {
            return Err(DataFusionError::Plan(format!(
                "{udf}: expected a string argument, got {other}"
            )))
        }
    };
    utf8.as_any()
        .downcast_ref::<StringArray>()
        .cloned()
        .ok_or_else(|| {
            DataFusionError::Internal(format!("{udf}: cast to Utf8 produced {}", utf8.data_type()))
        })
}

fn integer_slot(
    desired: datafusion::common::types::LogicalTypeRef,
    cast_to: NativeType,
) -> Coercion {
    Coercion::new_implicit(
        TypeSignatureClass::Native(desired),
        vec![TypeSignatureClass::Integer],
        cast_to,
    )
}

/// Register all network address UDFs with the DataFusion context.
pub fn register_network_udfs(ctx: &SessionContext) -> Result<(), Error> {
    // IPv4 functions
    ctx.register_udf(create_ip4_udf());
    ctx.register_udf(create_ip4_to_string_udf());
    ctx.register_udf(create_ip_in_cidr_udf());
    ctx.register_udf(create_is_private_ip_udf());
    ctx.register_udf(create_is_multicast_ip_udf());
    ctx.register_udf(create_is_loopback_ip_udf());

    // IPv6 functions
    ctx.register_udf(create_ip6_udf());
    ctx.register_udf(create_ip6_to_string_udf());
    ctx.register_udf(create_ip6_in_cidr_udf());
    ctx.register_udf(create_is_link_local_ip6_udf());
    ctx.register_udf(create_is_multicast_ip6_udf());

    // MAC functions
    ctx.register_udf(create_mac_udf());
    ctx.register_udf(create_mac_to_string_udf());
    ctx.register_udf(create_mac_is_broadcast_udf());
    ctx.register_udf(create_mac_is_multicast_udf());
    ctx.register_udf(create_mac_is_local_udf());

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
    ctx.register_udf(create_icmp_code_name_udf());
    ctx.register_udf(create_icmpv6_code_name_udf());

    // Protocol numbers
    ctx.register_udf(create_ip_proto_name_udf());
    ctx.register_udf(create_ethertype_name_udf());

    // IP header fields
    ctx.register_udf(create_dscp_name_udf());
    ctx.register_udf(create_ecn_name_udf());

    // BGP
    ctx.register_udf(create_bgp_message_type_name_udf());
    ctx.register_udf(create_bgp_origin_name_udf());

    // OSPF
    ctx.register_udf(create_ospf_packet_type_name_udf());
    ctx.register_udf(create_ospf_lsa_type_name_udf());

    // GTP
    ctx.register_udf(create_gtp_message_type_name_udf());

    // NTP
    ctx.register_udf(create_ntp_mode_name_udf());
    ctx.register_udf(create_ntp_stratum_name_udf());

    // TLS
    ctx.register_udf(create_tls_version_name_udf());
    ctx.register_udf(create_tls_record_type_name_udf());

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
/// - `hdr_buckets(hist)` - Distribution as bucket rows (explode with UNNEST)
/// - `hdr_ascii(hist)` - Rendered ASCII histogram with cumulative %
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

    // Distribution rendering
    ctx.register_udf(create_hdr_buckets_udf());
    ctx.register_udf(create_hdr_ascii_udf());

    Ok(())
}

/// Register ALL UDFs with the DataFusion context.
///
/// This is a convenience function that registers all network, protocol, utility,
/// datetime, and histogram UDFs.
///
/// Note: Time UDFs are NOT included here because they require capture metadata.
/// Use `register_time_udfs()` separately (it needs the capture time range).
pub fn register_all_udfs(ctx: &SessionContext) -> Result<(), Error> {
    register_network_udfs(ctx)?;
    register_protocol_udfs(ctx)?;
    register_utility_udfs(ctx)?;
    register_datetime_udfs(ctx)?;
    register_histogram_udfs(ctx)?;
    Ok(())
}

/// Register the time UDFs bound to a shared [`CaptureTimeRange`].
///
/// The engine widens the range as parse passes observe packets; the UDFs
/// read it at invocation time, so values are correct for any query whose
/// execution follows a parse.
pub fn register_time_udfs(
    ctx: &SessionContext,
    range: std::sync::Arc<CaptureTimeRange>,
) -> Result<(), Error> {
    ctx.register_udf(create_start_time_udf(range.clone()));
    ctx.register_udf(create_end_time_udf(range.clone()));
    ctx.register_udf(create_relative_time_udf(range));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every UDF with an integer parameter plans with an integer literal
    /// (an `Int64`), with a NULL, and with a narrower/wider integer column
    /// type; a non-integer argument is still a planning error.
    #[tokio::test]
    async fn integer_udfs_accept_integer_literals() {
        use arrow::util::pretty::pretty_format_batches;
        let ctx = SessionContext::new();
        register_all_udfs(&ctx).unwrap();
        let calls = [
            ("dscp_name(46)", "EF"),
            ("ecn_name(1)", "ECT(1)"),
            ("gtp_message_type_name(1)", "Echo Request"),
            ("ip_proto_name(6)", "TCP"),
            ("ethertype_name(2048)", "IPv4"),
            ("tcp_flags_str(2)", "SYN"),
            ("has_tcp_flag(18, 'SYN')", "true"),
            ("icmp_type_name(8)", "Echo Request"),
            ("icmpv6_type_name(128)", "Echo Request"),
            ("dns_type_name(1)", "A"),
            ("dns_rcode_name(0)", "NOERROR"),
            ("dns_class_name(1)", "IN"),
            ("ospf_packet_type_name(1)", "Hello"),
            ("ntp_mode_name(3)", "Client"),
            ("tls_version_name(771)", "TLS 1.2"),
            ("tls_record_type_name(22)", "Handshake"),
            ("bgp_message_type_name(2)", "UPDATE"),
            ("ip4_to_string(3232235777)", "192.168.1.1"),
            ("is_private_ip(3232235777)", "true"),
            ("is_loopback_ip(2130706433)", "true"),
            ("ip_in_cidr(3232235777, '192.168.1.0/24')", "true"),
            // Two integer parameters, a cast column and a NULL.
            ("icmp_code_name(3, 1)", "Host Unreachable"),
            ("dscp_name(CAST(46 AS BIGINT))", "EF"),
            ("dscp_name(arrow_cast(46, 'UInt32'))", "EF"),
            ("dscp_name(NULL)", ""),
            // String parameters take every physical string type: SQL
            // VARCHAR/TEXT casts are Utf8View in DataFusion 51.
            ("has_tcp_flag(2, CAST('SYN' AS VARCHAR))", "true"),
            ("has_tcp_flag(2, CAST('SYN' AS TEXT))", "true"),
            ("has_tcp_flag(2, arrow_cast('SYN', 'LargeUtf8'))", "true"),
            ("has_tcp_flag(2, arrow_cast('SYN', 'Utf8View'))", "true"),
            (
                "ip_in_cidr(3232235777, CAST('192.168.1.0/24' AS VARCHAR))",
                "true",
            ),
            (
                "ip_in_cidr(3232235777, arrow_cast('192.168.1.0/24', 'LargeUtf8'))",
                "true",
            ),
            ("ip4(CAST('10.0.0.1' AS VARCHAR))", "167772161"),
            ("unhex(arrow_cast('0a', 'Utf8View'))", "0a"),
        ];
        for (call, want) in calls {
            let batches = ctx
                .sql(&format!("SELECT {call} AS v"))
                .await
                .unwrap_or_else(|e| panic!("{call}: plan: {e}"))
                .collect()
                .await
                .unwrap_or_else(|e| panic!("{call}: exec: {e}"));
            let out = pretty_format_batches(&batches).unwrap().to_string();
            assert!(out.contains(want), "{call}: expected {want:?} in\n{out}");
        }
        // Non-integer arguments are still rejected when planning.
        for call in [
            "dscp_name('x')",
            "ecn_name(1.5)",
            "gtp_message_type_name(TRUE)",
        ] {
            assert!(
                ctx.sql(&format!("SELECT {call}")).await.is_err(),
                "{call} must not plan"
            );
        }
    }

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
    fn test_register_time_udfs() {
        let ctx = SessionContext::new();
        let range = std::sync::Arc::new(CaptureTimeRange::new());
        range.record(1_000_000, 2_000_000);
        register_time_udfs(&ctx, range).unwrap();
    }
}
