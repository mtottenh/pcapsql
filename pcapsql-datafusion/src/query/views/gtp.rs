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
    gtp.sequence,
    gtp.npdu,
    gtp.extension_headers,
    gtp.extension_header_count,
    gtp.piggyback,
    gtp.teid_present,
    gtp.encap_depth,
    gtp.tunnel_type
FROM frames f
JOIN gtp ON f.frame_number = gtp.frame_number
LEFT JOIN ipv4 ip4 ON ip4.frame_number = gtp.frame_number AND ip4.encap_depth = gtp.encap_depth
LEFT JOIN ipv6 ip6 ON ip6.frame_number = gtp.frame_number AND ip6.encap_depth = gtp.encap_depth
JOIN udp ON udp.frame_number = gtp.frame_number AND udp.encap_depth = gtp.encap_depth
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtp_packets_view() {
        let view = gtp_packets_view();
        // Layers join their anchor at the same encapsulation level.
        assert!(view.sql.contains("udp.encap_depth = gtp.encap_depth"));
        assert_eq!(view.name, "gtp_packets");
        assert!(view.sql.contains("JOIN gtp"));
        assert!(view.sql.contains("teid"));
        assert!(view.sql.contains("gtp.extension_headers,"));
    }
}
