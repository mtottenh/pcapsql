//! ICMPv6 packets view definition.
//!
//! Joins frames, IPv6, and ICMPv6 tables for convenient ICMPv6 analysis.

use super::ViewDefinition;

/// ICMPv6 packets view with IPv6 context.
///
/// This view joins:
/// - `frames` (timestamp)
/// - `ipv6` (src_ip, dst_ip, hop_limit)
/// - `icmpv6` (type, code, NDP fields, MLD fields)
pub fn icmpv6_packets_view() -> ViewDefinition {
    ViewDefinition {
        name: "icmpv6_packets",
        description: "ICMPv6 messages with IPv6 context (including NDP and MLD)",
        sql: r#"
SELECT
    f.frame_number,
    f.timestamp,
    ip6.src_ip,
    ip6.dst_ip,
    icmpv6.type,
    icmpv6.code,
    icmpv6.type_name,
    icmpv6.checksum,
    icmpv6.echo_id,
    icmpv6.echo_seq,
    icmpv6.mtu,
    icmpv6.pointer,
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
    icmpv6.ndp_prefix_length,
    icmpv6.mld_max_response_delay,
    icmpv6.mld_multicast_address,
    icmpv6.mld_num_group_records
FROM frames f
JOIN ipv6 ip6 ON f.frame_number = ip6.frame_number
JOIN icmpv6 ON f.frame_number = icmpv6.frame_number
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmpv6_packets_view() {
        let view = icmpv6_packets_view();
        assert_eq!(view.name, "icmpv6_packets");
        assert!(view.sql.contains("JOIN icmpv6"));
        assert!(view.sql.contains("ndp_target_address"));
    }
}
