//! NTP packets view definition.
//!
//! Joins frames, IP, UDP, and NTP tables for convenient NTP analysis.

use super::ViewDefinition;

/// NTP packets view with UDP and IP context.
///
/// This view joins:
/// - `frames` (timestamp)
/// - `ipv4` or `ipv6` (src_ip, dst_ip)
/// - `udp` (ports)
/// - `ntp` (version, mode, timestamps)
pub fn ntp_packets_view() -> ViewDefinition {
    ViewDefinition {
        name: "ntp_packets",
        description: "NTP messages with UDP/IP context",
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
    ntp.version,
    ntp.mode,
    ntp.leap_indicator,
    ntp.stratum,
    ntp.poll,
    ntp.precision,
    ntp.root_delay,
    ntp.root_dispersion,
    ntp.reference_id,
    ntp.reference_ts,
    ntp.origin_ts,
    ntp.receive_ts,
    ntp.transmit_ts,
    ntp.encap_depth,
    ntp.tunnel_type
FROM frames f
JOIN ntp ON f.frame_number = ntp.frame_number
LEFT JOIN ipv4 ip4 ON ip4.frame_number = ntp.frame_number AND ip4.encap_depth = ntp.encap_depth
LEFT JOIN ipv6 ip6 ON ip6.frame_number = ntp.frame_number AND ip6.encap_depth = ntp.encap_depth
JOIN udp ON udp.frame_number = ntp.frame_number AND udp.encap_depth = ntp.encap_depth
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntp_packets_view() {
        let view = ntp_packets_view();
        // Layers join their anchor at the same encapsulation level.
        assert!(view.sql.contains("udp.encap_depth = ntp.encap_depth"));
        assert_eq!(view.name, "ntp_packets");
        assert!(view.sql.contains("JOIN ntp"));
        assert!(view.sql.contains("stratum"));
    }
}
