//! DHCP packets view definition.
//!
//! Joins frames, IP, UDP, and DHCP tables for convenient DHCP analysis.

use super::ViewDefinition;

/// DHCP packets view with UDP and IP context.
///
/// This view joins:
/// - `frames` (timestamp)
/// - `ipv4` (src_ip, dst_ip)
/// - `udp` (ports)
/// - `dhcp` (BOOTP header and options)
pub fn dhcp_packets_view() -> ViewDefinition {
    ViewDefinition {
        name: "dhcp_packets",
        description: "DHCP messages with UDP/IP context",
        sql: r#"
SELECT
    f.frame_number,
    f.timestamp,
    ip4.src_ip AS src_ip_v4,
    ip4.dst_ip AS dst_ip_v4,
    ip6.src_ip AS src_ip_v6,
    ip6.dst_ip AS dst_ip_v6,
    udp.src_port,
    udp.dst_port,
    dhcp.op,
    dhcp.htype,
    dhcp.hlen,
    dhcp.hops,
    dhcp.xid,
    dhcp.secs,
    dhcp.flags,
    dhcp.ciaddr,
    dhcp.yiaddr,
    dhcp.siaddr,
    dhcp.giaddr,
    dhcp.chaddr,
    dhcp.message_type,
    dhcp.server_id,
    dhcp.lease_time,
    dhcp.subnet_mask,
    dhcp.router,
    dhcp.dns_servers,
    dhcp.encap_depth,
    dhcp.tunnel_type
FROM frames f
JOIN dhcp ON f.frame_number = dhcp.frame_number
LEFT JOIN ipv4 ip4 ON ip4.frame_number = dhcp.frame_number AND ip4.encap_depth = dhcp.encap_depth
LEFT JOIN ipv6 ip6 ON ip6.frame_number = dhcp.frame_number AND ip6.encap_depth = dhcp.encap_depth
JOIN udp ON udp.frame_number = dhcp.frame_number AND udp.encap_depth = dhcp.encap_depth
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcp_packets_view() {
        let view = dhcp_packets_view();
        // Layers join their anchor at the same encapsulation level.
        assert!(view.sql.contains("udp.encap_depth = dhcp.encap_depth"));
        assert_eq!(view.name, "dhcp_packets");
        assert!(view.sql.contains("JOIN dhcp"));
        assert!(view.sql.contains("message_type"));
        assert!(view.sql.contains("yiaddr"));
    }
}
