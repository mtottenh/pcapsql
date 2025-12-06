//! TCP packets view definition.
//!
//! Joins frames, ethernet, IP (v4/v6), and TCP tables for convenient TCP traffic analysis.

use super::ViewDefinition;

/// TCP packets view with frame metadata, MAC and IP addresses.
///
/// This view joins:
/// - `frames` (timestamp, length)
/// - `ethernet` (src_mac, dst_mac)
/// - `ipv4` or `ipv6` (src_ip, dst_ip, ttl/hop_limit)
/// - `tcp` (ports, flags, seq, ack, window)
pub fn tcp_packets_view() -> ViewDefinition {
    ViewDefinition {
        name: "tcp_packets",
        description: "TCP packets with IP addresses and frame metadata",
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
    COALESCE(ip4.ttl, ip6.hop_limit) AS ttl,
    tcp.src_port,
    tcp.dst_port,
    tcp.seq,
    tcp.ack,
    tcp.flags,
    tcp.window,
    tcp.checksum,
    tcp.urgent_ptr
FROM frames f
LEFT JOIN ethernet e ON f.frame_number = e.frame_number
LEFT JOIN ipv4 ip4 ON f.frame_number = ip4.frame_number
LEFT JOIN ipv6 ip6 ON f.frame_number = ip6.frame_number
JOIN tcp ON f.frame_number = tcp.frame_number
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_packets_view() {
        let view = tcp_packets_view();
        assert_eq!(view.name, "tcp_packets");
        assert!(view.sql.contains("JOIN tcp"));
        assert!(view.sql.contains("FROM frames"));
    }
}
