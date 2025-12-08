//! NDP (Neighbor Discovery Protocol) packets view definition.
//!
//! Filters ICMPv6 packets to show only NDP messages (types 133-137).

use super::ViewDefinition;

/// NDP packets view - subset of ICMPv6 for Neighbor Discovery Protocol.
///
/// NDP message types:
/// - 133: Router Solicitation
/// - 134: Router Advertisement
/// - 135: Neighbor Solicitation
/// - 136: Neighbor Advertisement
/// - 137: Redirect
///
/// This view joins:
/// - `frames` (timestamp)
/// - `ipv6` (src_ip, dst_ip, hop_limit)
/// - `icmpv6` (NDP-specific fields)
pub fn ndp_packets_view() -> ViewDefinition {
    ViewDefinition {
        name: "ndp_packets",
        description: "NDP messages (Router/Neighbor Solicitation/Advertisement, Redirect)",
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
    icmpv6.ndp_target_address,
    icmpv6.ndp_cur_hop_limit,
    icmpv6.ndp_managed_flag,
    icmpv6.ndp_other_flag,
    icmpv6.ndp_router_lifetime,
    icmpv6.ndp_reachable_time,
    icmpv6.ndp_retrans_timer,
    icmpv6.ndp_router_flag,
    icmpv6.ndp_solicited_flag,
    icmpv6.ndp_override_flag,
    icmpv6.ndp_source_mac,
    icmpv6.ndp_target_mac,
    icmpv6.ndp_prefix,
    icmpv6.ndp_prefix_length
FROM frames f
JOIN ipv6 ip6 ON f.frame_number = ip6.frame_number
JOIN icmpv6 ON f.frame_number = icmpv6.frame_number
WHERE icmpv6.type IN (133, 134, 135, 136, 137)
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ndp_packets_view() {
        let view = ndp_packets_view();
        assert_eq!(view.name, "ndp_packets");
        assert!(view.sql.contains("JOIN icmpv6"));
        assert!(view.sql.contains("WHERE icmpv6.type IN (133, 134, 135, 136, 137)"));
        assert!(view.sql.contains("ndp_target_address"));
        assert!(view.sql.contains("ndp_router_flag"));
    }
}
