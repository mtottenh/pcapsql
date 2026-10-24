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
    icmp.gateway,
    icmp.encap_depth,
    icmp.tunnel_type
FROM frames f
JOIN icmp ON f.frame_number = icmp.frame_number
LEFT JOIN ipv4 ip4 ON ip4.frame_number = icmp.frame_number AND ip4.encap_depth = icmp.encap_depth
LEFT JOIN ipv6 ip6 ON ip6.frame_number = icmp.frame_number AND ip6.encap_depth = icmp.encap_depth
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_packets_view() {
        let view = icmp_packets_view();
        // Layers join their anchor at the same encapsulation level.
        assert!(view.sql.contains("ip4.encap_depth = icmp.encap_depth"));
        assert_eq!(view.name, "icmp_packets");
        assert!(view.sql.contains("JOIN icmp"));
        assert!(view.sql.contains("type_name"));
    }
}
