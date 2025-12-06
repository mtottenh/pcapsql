//! UDP packets view definition.
//!
//! Joins frames, ethernet, IP (v4/v6), and UDP tables for convenient UDP traffic analysis.

use super::ViewDefinition;

/// UDP packets view with frame metadata, MAC and IP addresses.
///
/// This view joins:
/// - `frames` (timestamp, length)
/// - `ethernet` (src_mac, dst_mac)
/// - `ipv4` or `ipv6` (src_ip, dst_ip)
/// - `udp` (ports, length, checksum)
pub fn udp_packets_view() -> ViewDefinition {
    ViewDefinition {
        name: "udp_packets",
        description: "UDP packets with IP addresses and frame metadata",
        sql: r#"
SELECT
    f.frame_number,
    f.timestamp,
    f.length,
    e.src_mac,
    e.dst_mac,
    ip4.src_ip AS src_ip_v4,
    ip4.dst_ip AS dst_ip_v4,
    ip6.src_ip AS src_ip_v6,
    ip6.dst_ip AS dst_ip_v6,
    udp.src_port,
    udp.dst_port,
    udp.length AS udp_length,
    udp.checksum
FROM frames f
LEFT JOIN ethernet e ON f.frame_number = e.frame_number
LEFT JOIN ipv4 ip4 ON f.frame_number = ip4.frame_number
LEFT JOIN ipv6 ip6 ON f.frame_number = ip6.frame_number
JOIN udp ON f.frame_number = udp.frame_number
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_packets_view() {
        let view = udp_packets_view();
        assert_eq!(view.name, "udp_packets");
        assert!(view.sql.contains("JOIN udp"));
        assert!(view.sql.contains("FROM frames"));
    }
}
