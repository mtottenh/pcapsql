//! QUIC packets view definition.
//!
//! Joins frames, IP, UDP, and QUIC tables for convenient QUIC analysis.

use super::ViewDefinition;

/// QUIC packets view with UDP and IP context.
///
/// This view joins:
/// - `frames` (timestamp)
/// - `ipv4` or `ipv6` (src_ip, dst_ip)
/// - `udp` (ports)
/// - `quic` (header info, connection IDs, version)
pub fn quic_packets_view() -> ViewDefinition {
    ViewDefinition {
        name: "quic_packets",
        description: "QUIC packets with UDP/IP context",
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
    quic.header_form,
    quic.long_packet_type,
    quic.version,
    quic.version_name,
    quic.dcid_length,
    quic.dcid,
    quic.scid_length,
    quic.scid,
    quic.token_length,
    quic.packet_length,
    quic.spin_bit,
    quic.key_phase,
    quic.sni
FROM frames f
LEFT JOIN ipv4 ip4 ON f.frame_number = ip4.frame_number
LEFT JOIN ipv6 ip6 ON f.frame_number = ip6.frame_number
JOIN udp ON f.frame_number = udp.frame_number
JOIN quic ON f.frame_number = quic.frame_number
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_packets_view() {
        let view = quic_packets_view();
        assert_eq!(view.name, "quic_packets");
        assert!(view.sql.contains("JOIN quic"));
        assert!(view.sql.contains("version_name"));
        assert!(view.sql.contains("dcid"));
    }
}
