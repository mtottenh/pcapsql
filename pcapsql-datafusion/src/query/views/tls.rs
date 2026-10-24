//! TLS packets view definition.
//!
//! Joins frames, IP, TCP, and TLS tables for convenient TLS analysis.

use super::ViewDefinition;

/// TLS packets view with TCP and IP context.
///
/// This view joins:
/// - `frames` (timestamp)
/// - `ipv4` or `ipv6` (src_ip, dst_ip)
/// - `tcp` (ports, flags)
/// - `tls` (handshake details, SNI)
pub fn tls_packets_view() -> ViewDefinition {
    ViewDefinition {
        name: "tls_packets",
        description: "TLS records with TCP/IP context",
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
    tcp.flags AS tcp_flags,
    tls.record_type,
    tls.version,
    tls.handshake_type,
    tls.sni,
    tls.cipher_suites,
    tls.selected_cipher,
    tls.encap_depth,
    tls.tunnel_type
FROM frames f
JOIN tls ON f.frame_number = tls.frame_number
LEFT JOIN ipv4 ip4 ON ip4.frame_number = tls.frame_number AND ip4.encap_depth = tls.encap_depth
LEFT JOIN ipv6 ip6 ON ip6.frame_number = tls.frame_number AND ip6.encap_depth = tls.encap_depth
JOIN tcp ON tcp.frame_number = tls.frame_number AND tcp.encap_depth = tls.encap_depth
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_packets_view() {
        let view = tls_packets_view();
        // Layers join their anchor at the same encapsulation level.
        assert!(view.sql.contains("tcp.encap_depth = tls.encap_depth"));
        assert_eq!(view.name, "tls_packets");
        assert!(view.sql.contains("JOIN tls"));
        assert!(view.sql.contains("sni"));
    }
}
