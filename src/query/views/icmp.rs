//! ICMP packets view definition.
//!
//! Joins frames, IPv4, and ICMP tables for convenient ICMP analysis.

use super::ViewDefinition;

/// ICMP packets view with IPv4 context.
///
/// This view joins:
/// - `frames` (timestamp)
/// - `ipv4` (src_ip, dst_ip, ttl)
/// - `icmp` (type, code, identifier, sequence)
pub fn icmp_packets_view() -> ViewDefinition {
    ViewDefinition {
        name: "icmp_packets",
        description: "ICMP messages with IPv4 context",
        sql: r#"
SELECT
    f.frame_number,
    f.timestamp,
    ip4.src_ip AS src_ip_v4,
    ip4.dst_ip AS dst_ip_v4,
    ip6.src_ip AS src_ip_v6,
    ip6.dst_ip AS dst_ip_v6,
    icmp.type,
    icmp.code,
    icmp.type_name,
    icmp.checksum,
    icmp.identifier,
    icmp.sequence,
    icmp.next_hop_mtu,
    icmp.gateway
FROM frames f
LEFT JOIN ipv4 ip4 ON f.frame_number = ip4.frame_number
LEFT JOIN ipv6 ip6 ON f.frame_number = ip6.frame_number
JOIN icmp ON f.frame_number = icmp.frame_number
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_packets_view() {
        let view = icmp_packets_view();
        assert_eq!(view.name, "icmp_packets");
        assert!(view.sql.contains("JOIN icmp"));
        assert!(view.sql.contains("type_name"));
    }
}
