//! MLD (Multicast Listener Discovery) packets view definition.
//!
//! Filters ICMPv6 packets to show only MLD messages (types 130, 131, 132, 143).

use super::ViewDefinition;

/// MLD packets view - subset of ICMPv6 for Multicast Listener Discovery.
///
/// MLD message types:
/// - 130: MLD Query
/// - 131: MLDv1 Report
/// - 132: MLDv1 Done
/// - 143: MLDv2 Report
///
/// This view joins:
/// - `frames` (timestamp)
/// - `ipv6` (src_ip, dst_ip, hop_limit)
/// - `icmpv6` (MLD-specific fields)
pub fn mld_packets_view() -> ViewDefinition {
    ViewDefinition {
        name: "mld_packets",
        description: "MLD messages (Multicast Listener Discovery queries and reports)",
        sql: r#"
SELECT
    f.frame_number,
    f.timestamp,
    ip6.src_ip,
    ip6.dst_ip,
    ip6.hop_limit,
    icmpv6.type,
    icmpv6.code,
    icmpv6.type_name,
    icmpv6.mld_max_response_delay,
    icmpv6.mld_multicast_address,
    icmpv6.mld_num_group_records,
    icmpv6.encap_depth,
    icmpv6.tunnel_type
FROM frames f
JOIN icmpv6 ON f.frame_number = icmpv6.frame_number
JOIN ipv6 ip6 ON ip6.frame_number = icmpv6.frame_number AND ip6.encap_depth = icmpv6.encap_depth
WHERE icmpv6.type IN (130, 131, 132, 143)
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mld_packets_view() {
        let view = mld_packets_view();
        // Layers join their anchor at the same encapsulation level.
        assert!(view.sql.contains("ip6.encap_depth = icmpv6.encap_depth"));
        assert_eq!(view.name, "mld_packets");
        assert!(view.sql.contains("JOIN icmpv6"));
        assert!(view
            .sql
            .contains("WHERE icmpv6.type IN (130, 131, 132, 143)"));
        assert!(view.sql.contains("mld_multicast_address"));
        assert!(view.sql.contains("mld_max_response_delay"));
    }
}
