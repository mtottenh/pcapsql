//! BGP packets view definition.
//!
//! Joins frames, IPv4/IPv6, TCP, and BGP tables for convenient BGP analysis.

use super::ViewDefinition;

/// BGP packets view with TCP context.
///
/// This view joins:
/// - `frames` (timestamp)
/// - `ipv4` / `ipv6` (src_ip, dst_ip)
/// - `tcp` (src_port, dst_port)
/// - `bgp` (message_type, my_as, bgp_id)
pub fn bgp_packets_view() -> ViewDefinition {
    ViewDefinition {
        name: "bgp_packets",
        description: "BGP messages with TCP/IP context",
        sql: r#"
SELECT
    f.frame_number,
    f.timestamp,
    ip4.src_ip AS src_ip_v4,
    ip4.dst_ip AS dst_ip_v4,
    ip6.src_ip AS src_ip_v6,
    ip6.dst_ip AS dst_ip_v6,
    tcp.src_port,
    tcp.dst_port,
    bgp.message_type,
    bgp.message_type_name,
    bgp.length,
    bgp.version,
    bgp.my_as,
    bgp.hold_time,
    bgp.bgp_id,
    bgp.withdrawn_routes_len,
    bgp.path_attr_len
FROM frames f
LEFT JOIN ipv4 ip4 ON f.frame_number = ip4.frame_number
LEFT JOIN ipv6 ip6 ON f.frame_number = ip6.frame_number
JOIN tcp ON f.frame_number = tcp.frame_number
JOIN bgp ON f.frame_number = bgp.frame_number
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bgp_packets_view() {
        let view = bgp_packets_view();
        assert_eq!(view.name, "bgp_packets");
        assert!(view.sql.contains("JOIN bgp"));
        assert!(view.sql.contains("message_type_name"));
    }
}
