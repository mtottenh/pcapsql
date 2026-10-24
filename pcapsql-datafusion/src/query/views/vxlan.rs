//! VXLAN packets view definition.
//!
//! Joins frames, IPv4/IPv6, UDP, and VXLAN tables for convenient VXLAN analysis.

use super::ViewDefinition;

/// VXLAN packets view with UDP context.
///
/// This view joins:
/// - `frames` (timestamp)
/// - `ipv4` / `ipv6` (src_ip, dst_ip)
/// - `udp` (src_port, dst_port)
/// - `vxlan` (vni, flags)
pub fn vxlan_packets_view() -> ViewDefinition {
    ViewDefinition {
        name: "vxlan_packets",
        description: "VXLAN encapsulated frames with UDP/IP context",
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
    vxlan.flags,
    vxlan.vni,
    vxlan.encap_depth,
    vxlan.tunnel_type
FROM frames f
JOIN vxlan ON f.frame_number = vxlan.frame_number
LEFT JOIN ipv4 ip4 ON ip4.frame_number = vxlan.frame_number AND ip4.encap_depth = vxlan.encap_depth
LEFT JOIN ipv6 ip6 ON ip6.frame_number = vxlan.frame_number AND ip6.encap_depth = vxlan.encap_depth
JOIN udp ON udp.frame_number = vxlan.frame_number AND udp.encap_depth = vxlan.encap_depth
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vxlan_packets_view() {
        let view = vxlan_packets_view();
        // Layers join their anchor at the same encapsulation level.
        assert!(view.sql.contains("udp.encap_depth = vxlan.encap_depth"));
        assert_eq!(view.name, "vxlan_packets");
        assert!(view.sql.contains("JOIN vxlan"));
        assert!(view.sql.contains("vni"));
    }
}
