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
    vxlan.vni
FROM frames f
LEFT JOIN ipv4 ip4 ON f.frame_number = ip4.frame_number
LEFT JOIN ipv6 ip6 ON f.frame_number = ip6.frame_number
JOIN udp ON f.frame_number = udp.frame_number
JOIN vxlan ON f.frame_number = vxlan.frame_number
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vxlan_packets_view() {
        let view = vxlan_packets_view();
        assert_eq!(view.name, "vxlan_packets");
        assert!(view.sql.contains("JOIN vxlan"));
        assert!(view.sql.contains("vni"));
    }
}
