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
    ipsec.ah_icv_length
FROM frames f
LEFT JOIN ipv4 ip4 ON f.frame_number = ip4.frame_number
LEFT JOIN ipv6 ip6 ON f.frame_number = ip6.frame_number
JOIN ipsec ON f.frame_number = ipsec.frame_number
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipsec_packets_view() {
        let view = ipsec_packets_view();
        assert_eq!(view.name, "ipsec_packets");
        assert!(view.sql.contains("JOIN ipsec"));
        assert!(view.sql.contains("spi"));
    }
}
