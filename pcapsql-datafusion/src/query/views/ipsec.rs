//! IPsec packets view definition.
//!
//! Joins frames, IPv4/IPv6, and IPsec tables for convenient IPsec analysis.

use super::ViewDefinition;

/// IPsec packets view with IP context.
///
/// This view joins:
/// - `frames` (timestamp)
/// - `ipv4` / `ipv6` (src_ip, dst_ip)
/// - `ipsec` (protocol, spi, sequence)
pub fn ipsec_packets_view() -> ViewDefinition {
    ViewDefinition {
        name: "ipsec_packets",
        description: "IPsec (ESP/AH) packets with IP context",
        sql: r#"
SELECT
    f.frame_number,
    f.timestamp,
    ip4.src_ip AS src_ip_v4,
    ip4.dst_ip AS dst_ip_v4,
    ip6.src_ip AS src_ip_v6,
    ip6.dst_ip AS dst_ip_v6,
    ipsec.protocol,
    ipsec.spi,
    ipsec.sequence,
    ipsec.ah_next_header,
    ipsec.ah_icv_length,
    ipsec.encap_depth,
    ipsec.tunnel_type
FROM frames f
JOIN ipsec ON f.frame_number = ipsec.frame_number
LEFT JOIN ipv4 ip4 ON ip4.frame_number = ipsec.frame_number AND ip4.encap_depth = ipsec.encap_depth
LEFT JOIN ipv6 ip6 ON ip6.frame_number = ipsec.frame_number AND ip6.encap_depth = ipsec.encap_depth
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipsec_packets_view() {
        let view = ipsec_packets_view();
        // Layers join their anchor at the same encapsulation level.
        assert!(view.sql.contains("ip4.encap_depth = ipsec.encap_depth"));
        assert_eq!(view.name, "ipsec_packets");
        assert!(view.sql.contains("JOIN ipsec"));
        assert!(view.sql.contains("spi"));
    }
}
