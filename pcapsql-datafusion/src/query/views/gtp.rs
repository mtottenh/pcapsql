//! GTP packets view definition.
//!
//! Joins frames, IPv4/IPv6, UDP, and GTP tables for convenient GTP analysis.

use super::ViewDefinition;

/// GTP packets view with UDP context.
///
/// This view joins:
/// - `frames` (timestamp)
/// - `ipv4` / `ipv6` (src_ip, dst_ip)
/// - `udp` (src_port, dst_port)
/// - `gtp` (teid, message_type, version)
pub fn gtp_packets_view() -> ViewDefinition {
    ViewDefinition {
        name: "gtp_packets",
        description: "GTP tunneled packets with UDP/IP context",
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
    gtp.version,
    gtp.protocol_type,
    gtp.message_type,
    gtp.length,
    gtp.teid,
    gtp.sequence
FROM frames f
LEFT JOIN ipv4 ip4 ON f.frame_number = ip4.frame_number
LEFT JOIN ipv6 ip6 ON f.frame_number = ip6.frame_number
JOIN udp ON f.frame_number = udp.frame_number
JOIN gtp ON f.frame_number = gtp.frame_number
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtp_packets_view() {
        let view = gtp_packets_view();
        assert_eq!(view.name, "gtp_packets");
        assert!(view.sql.contains("JOIN gtp"));
        assert!(view.sql.contains("teid"));
    }
}
