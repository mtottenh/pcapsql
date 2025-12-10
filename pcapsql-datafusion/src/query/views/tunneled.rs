//! Tunneled packets view definitions.
//!
//! Provides correlation between outer tunnel headers and inner encapsulated packets
//! for IP-in-IP, IPv6-in-IPv6, VXLAN, GRE, and similar tunneling protocols.
//!
//! Since IPv4 and IPv6 have incompatible address types, we provide:
//! - Specific views for each tunnel combination (ip4_in_ip6, ip6_in_ip6, etc.)
//! - A general tunneled_packets view with separate columns for each IP version

use super::ViewDefinition;

/// General tunneled packets view with all encapsulated traffic.
///
/// Uses LEFT JOINs to correlate inner packets with outer tunnel layers.
/// IPv4 and IPv6 addresses are kept in separate columns to preserve types.
/// Works for arbitrary nesting depths.
pub fn tunneled_packets_view() -> ViewDefinition {
    ViewDefinition {
        name: "tunneled_packets",
        description: "All tunneled packets with outer/inner layer correlation",
        sql: r#"
SELECT
    f.frame_number,
    f.timestamp,
    -- Inner IPv4 layer (if present)
    inner_v4.src_ip AS inner_src_ipv4,
    inner_v4.dst_ip AS inner_dst_ipv4,
    inner_v4.protocol AS inner_proto_v4,
    inner_v4.ttl AS inner_ttl,
    -- Inner IPv6 layer (if present)
    inner_v6.src_ip AS inner_src_ipv6,
    inner_v6.dst_ip AS inner_dst_ipv6,
    inner_v6.next_header AS inner_next_header,
    inner_v6.hop_limit AS inner_hop_limit,
    -- Tunnel metadata (from whichever inner layer exists)
    COALESCE(inner_v4.encap_depth, inner_v6.encap_depth) AS encap_depth,
    COALESCE(inner_v4.tunnel_type, inner_v6.tunnel_type) AS tunnel_type,
    COALESCE(inner_v4.tunnel_id, inner_v6.tunnel_id) AS tunnel_id,
    -- Outer IPv4 layer (tunnel endpoint, if IPv4-based tunnel)
    outer_v4.src_ip AS outer_src_ipv4,
    outer_v4.dst_ip AS outer_dst_ipv4,
    outer_v4.protocol AS outer_proto_v4,
    -- Outer IPv6 layer (tunnel endpoint, if IPv6-based tunnel)
    outer_v6.src_ip AS outer_src_ipv6,
    outer_v6.dst_ip AS outer_dst_ipv6,
    outer_v6.next_header AS outer_next_header
FROM frames f
-- Inner IPv4 (tunneled packets only)
LEFT JOIN ipv4 inner_v4
    ON f.frame_number = inner_v4.frame_number
    AND inner_v4.encap_depth > 0
-- Inner IPv6 (tunneled packets only)
LEFT JOIN ipv6 inner_v6
    ON f.frame_number = inner_v6.frame_number
    AND inner_v6.encap_depth > 0
-- Outer IPv4 (at depth one less than inner)
LEFT JOIN ipv4 outer_v4
    ON f.frame_number = outer_v4.frame_number
    AND outer_v4.encap_depth = COALESCE(inner_v4.encap_depth, inner_v6.encap_depth) - 1
-- Outer IPv6 (at depth one less than inner)
LEFT JOIN ipv6 outer_v6
    ON f.frame_number = outer_v6.frame_number
    AND outer_v6.encap_depth = COALESCE(inner_v4.encap_depth, inner_v6.encap_depth) - 1
WHERE
    -- At least one inner layer must exist
    inner_v4.frame_number IS NOT NULL OR inner_v6.frame_number IS NOT NULL
"#,
    }
}

/// IPv4-in-IPv6 tunneled packets view.
///
/// Specifically for IPv4 traffic encapsulated in IPv6 tunnels.
/// Correlates inner IPv4 with its immediate outer IPv6 tunnel layer.
pub fn ip4_in_ip6_view() -> ViewDefinition {
    ViewDefinition {
        name: "ip4_in_ip6",
        description: "IPv4 packets tunneled inside IPv6",
        sql: r#"
SELECT
    f.frame_number,
    f.timestamp,
    -- Outer IPv6 tunnel endpoints
    outer_v6.src_ip AS tunnel_src,
    outer_v6.dst_ip AS tunnel_dst,
    outer_v6.hop_limit AS tunnel_hop_limit,
    outer_v6.traffic_class AS tunnel_traffic_class,
    -- Inner IPv4 packet
    inner_v4.src_ip AS src_ip,
    inner_v4.dst_ip AS dst_ip,
    inner_v4.protocol,
    inner_v4.ttl,
    inner_v4.total_length,
    inner_v4.identification,
    inner_v4.dont_fragment,
    inner_v4.more_fragments,
    inner_v4.fragment_offset,
    inner_v4.encap_depth,
    inner_v4.tunnel_type
FROM frames f
JOIN ipv4 inner_v4
    ON f.frame_number = inner_v4.frame_number
    AND inner_v4.tunnel_type = 'ip4inip6'
JOIN ipv6 outer_v6
    ON f.frame_number = outer_v6.frame_number
    AND outer_v6.next_header = 4
    AND outer_v6.encap_depth = inner_v4.encap_depth - 1
"#,
    }
}

/// IPv6-in-IPv6 tunneled packets view.
///
/// Specifically for IPv6 traffic encapsulated in IPv6 tunnels.
/// Correlates inner IPv6 with its immediate outer IPv6 tunnel layer.
pub fn ip6_in_ip6_view() -> ViewDefinition {
    ViewDefinition {
        name: "ip6_in_ip6",
        description: "IPv6 packets tunneled inside IPv6",
        sql: r#"
SELECT
    f.frame_number,
    f.timestamp,
    -- Outer IPv6 tunnel endpoints
    outer_v6.src_ip AS tunnel_src,
    outer_v6.dst_ip AS tunnel_dst,
    outer_v6.hop_limit AS tunnel_hop_limit,
    outer_v6.traffic_class AS tunnel_traffic_class,
    -- Inner IPv6 packet
    inner_v6.src_ip AS src_ip,
    inner_v6.dst_ip AS dst_ip,
    inner_v6.next_header,
    inner_v6.hop_limit,
    inner_v6.payload_length,
    inner_v6.flow_label,
    inner_v6.encap_depth,
    inner_v6.tunnel_type
FROM frames f
JOIN ipv6 inner_v6
    ON f.frame_number = inner_v6.frame_number
    AND inner_v6.tunnel_type = 'ip6inip6'
JOIN ipv6 outer_v6
    ON f.frame_number = outer_v6.frame_number
    AND outer_v6.next_header = 41
    AND outer_v6.encap_depth = inner_v6.encap_depth - 1
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunneled_packets_view() {
        let view = tunneled_packets_view();
        assert_eq!(view.name, "tunneled_packets");
        assert!(view.sql.contains("tunnel_type"));
        assert!(view.sql.contains("encap_depth"));
        assert!(view.sql.contains("inner_src_ipv4"));
        assert!(view.sql.contains("inner_src_ipv6"));
    }

    #[test]
    fn test_ip4_in_ip6_view() {
        let view = ip4_in_ip6_view();
        assert_eq!(view.name, "ip4_in_ip6");
        assert!(view.sql.contains("ip4inip6"));
        assert!(view.sql.contains("tunnel_src"));
    }

    #[test]
    fn test_ip6_in_ip6_view() {
        let view = ip6_in_ip6_view();
        assert_eq!(view.name, "ip6_in_ip6");
        assert!(view.sql.contains("ip6inip6"));
    }
}
