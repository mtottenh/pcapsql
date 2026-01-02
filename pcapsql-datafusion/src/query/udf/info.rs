//! UDF metadata for documentation and introspection.
//!
//! Provides structured information about all available UDFs for
//! use in `--list-udfs` output and documentation generation.

/// Information about a User-Defined Function.
#[derive(Debug, Clone)]
pub struct UdfInfo {
    /// Function name as used in SQL.
    pub name: &'static str,
    /// Brief description of what the function does.
    pub description: &'static str,
    /// Function signature showing argument types.
    pub signature: &'static str,
    /// Return type.
    pub return_type: &'static str,
    /// Example usage.
    pub example: &'static str,
    /// Category for grouping in output.
    pub category: UdfCategory,
}

/// UDF categories for grouping in documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdfCategory {
    /// IP address conversion and matching.
    Address,
    /// Protocol field interpretation.
    Protocol,
    /// Date/time formatting.
    DateTime,
    /// Time relative to capture.
    CaptureTime,
    /// Histogram aggregation and extraction.
    Histogram,
    /// Binary/hex utilities.
    Utility,
}

impl UdfCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            UdfCategory::Address => "Address Functions",
            UdfCategory::Protocol => "Protocol Functions",
            UdfCategory::DateTime => "DateTime Functions",
            UdfCategory::CaptureTime => "Capture Time Functions",
            UdfCategory::Histogram => "Histogram Functions",
            UdfCategory::Utility => "Utility Functions",
        }
    }
}

/// Returns metadata for all available UDFs.
pub fn all_udfs() -> Vec<UdfInfo> {
    vec![
        // === Address Functions ===
        UdfInfo {
            name: "ip4",
            description: "Parse IPv4 address string to UInt32",
            signature: "ip4(string)",
            return_type: "UInt32",
            example: "ip4('192.168.1.1')",
            category: UdfCategory::Address,
        },
        UdfInfo {
            name: "ip4_to_string",
            description: "Convert UInt32 to IPv4 address string",
            signature: "ip4_to_string(uint32)",
            return_type: "String",
            example: "ip4_to_string(src_ip)",
            category: UdfCategory::Address,
        },
        UdfInfo {
            name: "ip_in_cidr",
            description: "Check if IPv4 address is in CIDR range",
            signature: "ip_in_cidr(uint32, string)",
            return_type: "Boolean",
            example: "ip_in_cidr(src_ip, '192.168.0.0/16')",
            category: UdfCategory::Address,
        },
        UdfInfo {
            name: "ip6",
            description: "Parse IPv6 address string to Binary(16)",
            signature: "ip6(string)",
            return_type: "Binary(16)",
            example: "ip6('fe80::1')",
            category: UdfCategory::Address,
        },
        UdfInfo {
            name: "ip6_to_string",
            description: "Convert Binary(16) to IPv6 address string",
            signature: "ip6_to_string(binary)",
            return_type: "String",
            example: "ip6_to_string(src_ip)",
            category: UdfCategory::Address,
        },
        UdfInfo {
            name: "ip6_in_cidr",
            description: "Check if IPv6 address is in CIDR prefix",
            signature: "ip6_in_cidr(binary, string)",
            return_type: "Boolean",
            example: "ip6_in_cidr(src_ip, '2001:db8::/32')",
            category: UdfCategory::Address,
        },
        UdfInfo {
            name: "mac",
            description: "Parse MAC address string to Binary(6)",
            signature: "mac(string)",
            return_type: "Binary(6)",
            example: "mac('aa:bb:cc:dd:ee:ff')",
            category: UdfCategory::Address,
        },
        UdfInfo {
            name: "mac_to_string",
            description: "Convert Binary(6) to MAC address string",
            signature: "mac_to_string(binary)",
            return_type: "String",
            example: "mac_to_string(src_mac)",
            category: UdfCategory::Address,
        },
        // === Protocol Functions ===
        UdfInfo {
            name: "tcp_flags_str",
            description: "Convert TCP flags bitmap to readable string",
            signature: "tcp_flags_str(uint16)",
            return_type: "String",
            example: "tcp_flags_str(tcp_flags) -> 'SYN,ACK'",
            category: UdfCategory::Protocol,
        },
        UdfInfo {
            name: "has_tcp_flag",
            description: "Check if specific TCP flag is set",
            signature: "has_tcp_flag(uint16, string)",
            return_type: "Boolean",
            example: "has_tcp_flag(tcp_flags, 'SYN')",
            category: UdfCategory::Protocol,
        },
        UdfInfo {
            name: "dns_type_name",
            description: "Convert DNS query type number to name",
            signature: "dns_type_name(uint16)",
            return_type: "String",
            example: "dns_type_name(query_type) -> 'A'",
            category: UdfCategory::Protocol,
        },
        UdfInfo {
            name: "dns_rcode_name",
            description: "Convert DNS response code to name",
            signature: "dns_rcode_name(uint8)",
            return_type: "String",
            example: "dns_rcode_name(rcode) -> 'NXDOMAIN'",
            category: UdfCategory::Protocol,
        },
        UdfInfo {
            name: "dns_class_name",
            description: "Convert DNS class number to name",
            signature: "dns_class_name(uint16)",
            return_type: "String",
            example: "dns_class_name(query_class) -> 'IN'",
            category: UdfCategory::Protocol,
        },
        UdfInfo {
            name: "icmp_type_name",
            description: "Convert ICMP type number to name",
            signature: "icmp_type_name(uint8)",
            return_type: "String",
            example: "icmp_type_name(icmp_type) -> 'Echo Request'",
            category: UdfCategory::Protocol,
        },
        UdfInfo {
            name: "icmpv6_type_name",
            description: "Convert ICMPv6 type number to name",
            signature: "icmpv6_type_name(uint8)",
            return_type: "String",
            example: "icmpv6_type_name(icmp_type) -> 'Router Solicitation'",
            category: UdfCategory::Protocol,
        },
        UdfInfo {
            name: "ip_proto_name",
            description: "Convert IP protocol number to name",
            signature: "ip_proto_name(uint8)",
            return_type: "String",
            example: "ip_proto_name(protocol) -> 'TCP'",
            category: UdfCategory::Protocol,
        },
        UdfInfo {
            name: "ethertype_name",
            description: "Convert EtherType number to name",
            signature: "ethertype_name(uint16)",
            return_type: "String",
            example: "ethertype_name(ethertype) -> 'IPv4'",
            category: UdfCategory::Protocol,
        },
        // === DateTime Functions ===
        UdfInfo {
            name: "strftime",
            description: "Format timestamp using strftime format codes",
            signature: "strftime(string, timestamp)",
            return_type: "String",
            example: "strftime('%Y-%m-%d %H:%M:%S', timestamp)",
            category: UdfCategory::DateTime,
        },
        UdfInfo {
            name: "datetime",
            description: "Format timestamp as ISO 8601 datetime",
            signature: "datetime(timestamp)",
            return_type: "String",
            example: "datetime(timestamp) -> '2024-01-15T10:30:00.000000'",
            category: UdfCategory::DateTime,
        },
        UdfInfo {
            name: "date",
            description: "Extract date from timestamp",
            signature: "date(timestamp)",
            return_type: "String",
            example: "date(timestamp) -> '2024-01-15'",
            category: UdfCategory::DateTime,
        },
        UdfInfo {
            name: "time",
            description: "Extract time from timestamp",
            signature: "time(timestamp)",
            return_type: "String",
            example: "time(timestamp) -> '10:30:00.000000'",
            category: UdfCategory::DateTime,
        },
        UdfInfo {
            name: "epoch",
            description: "Convert timestamp to Unix epoch seconds",
            signature: "epoch(timestamp)",
            return_type: "Float64",
            example: "epoch(timestamp) -> 1705314600.0",
            category: UdfCategory::DateTime,
        },
        UdfInfo {
            name: "epoch_ms",
            description: "Convert timestamp to Unix epoch milliseconds",
            signature: "epoch_ms(timestamp)",
            return_type: "Int64",
            example: "epoch_ms(timestamp) -> 1705314600000",
            category: UdfCategory::DateTime,
        },
        // === Capture Time Functions ===
        UdfInfo {
            name: "start_time",
            description: "Returns capture start timestamp",
            signature: "start_time()",
            return_type: "Timestamp",
            example: "start_time()",
            category: UdfCategory::CaptureTime,
        },
        UdfInfo {
            name: "end_time",
            description: "Returns capture end timestamp",
            signature: "end_time()",
            return_type: "Timestamp",
            example: "end_time()",
            category: UdfCategory::CaptureTime,
        },
        UdfInfo {
            name: "relative_time",
            description: "Seconds elapsed from capture start",
            signature: "relative_time(timestamp)",
            return_type: "Float64",
            example: "relative_time(timestamp) -> 1.234567",
            category: UdfCategory::CaptureTime,
        },
        // === Histogram Functions ===
        UdfInfo {
            name: "hdr_histogram",
            description: "Build histogram from values (aggregate)",
            signature: "hdr_histogram(numeric [, sigfigs])",
            return_type: "Binary",
            example: "hdr_histogram(length) or hdr_histogram(length, 3)",
            category: UdfCategory::Histogram,
        },
        UdfInfo {
            name: "hdr_percentile",
            description: "Extract percentile from histogram",
            signature: "hdr_percentile(binary, float64)",
            return_type: "Float64",
            example: "hdr_percentile(hist, 0.99) or hdr_percentile(hist, 99)",
            category: UdfCategory::Histogram,
        },
        UdfInfo {
            name: "hdr_count",
            description: "Get total sample count from histogram",
            signature: "hdr_count(binary)",
            return_type: "Int64",
            example: "hdr_count(hist)",
            category: UdfCategory::Histogram,
        },
        UdfInfo {
            name: "hdr_min",
            description: "Get minimum value from histogram",
            signature: "hdr_min(binary)",
            return_type: "Int64",
            example: "hdr_min(hist)",
            category: UdfCategory::Histogram,
        },
        UdfInfo {
            name: "hdr_max",
            description: "Get maximum value from histogram",
            signature: "hdr_max(binary)",
            return_type: "Int64",
            example: "hdr_max(hist)",
            category: UdfCategory::Histogram,
        },
        UdfInfo {
            name: "hdr_mean",
            description: "Get mean value from histogram",
            signature: "hdr_mean(binary)",
            return_type: "Float64",
            example: "hdr_mean(hist)",
            category: UdfCategory::Histogram,
        },
        UdfInfo {
            name: "hdr_stdev",
            description: "Get standard deviation from histogram",
            signature: "hdr_stdev(binary)",
            return_type: "Float64",
            example: "hdr_stdev(hist)",
            category: UdfCategory::Histogram,
        },
        // === Utility Functions ===
        UdfInfo {
            name: "hex",
            description: "Convert binary data to hex string",
            signature: "hex(binary)",
            return_type: "String",
            example: "hex(raw_data) -> '48656c6c6f'",
            category: UdfCategory::Utility,
        },
        UdfInfo {
            name: "unhex",
            description: "Parse hex string to binary",
            signature: "unhex(string)",
            return_type: "Binary",
            example: "unhex('48656c6c6f')",
            category: UdfCategory::Utility,
        },
    ]
}

/// Get UDFs grouped by category.
pub fn udfs_by_category() -> Vec<(UdfCategory, Vec<UdfInfo>)> {
    use UdfCategory::*;
    let categories = [Address, Protocol, DateTime, CaptureTime, Histogram, Utility];
    let all = all_udfs();

    categories
        .into_iter()
        .map(|cat| {
            let funcs: Vec<_> = all.iter().filter(|u| u.category == cat).cloned().collect();
            (cat, funcs)
        })
        .filter(|(_, funcs)| !funcs.is_empty())
        .collect()
}
