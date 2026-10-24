//! GRE packets view definition.
//!
//! Joins frames, IPv4/IPv6, and GRE tables for convenient GRE tunnel analysis.

use super::ViewDefinition;

/// GRE packets view with IP context.
///
/// This view joins:
/// - `frames` (timestamp)
/// - `ipv4` / `ipv6` (src_ip, dst_ip)
/// - `gre` (key, protocol, sequence)
pub fn gre_packets_view() -> ViewDefinition {
    ViewDefinition {
        name: "gre_packets",
        description: "GRE tunneled packets with IP context",
        sql: r#"
SELECT
    f.frame_number,
    f.timestamp,
    ip4.src_ip AS src_ip_v4,
    ip4.dst_ip AS dst_ip_v4,
    ip6.src_ip AS src_ip_v6,
    ip6.dst_ip AS dst_ip_v6,
    gre.version,
    gre.protocol,
    gre.checksum_present,
    gre.key_present,
    gre.sequence_present,
    gre.key,
    gre.sequence,
    gre.checksum,
    gre.encap_depth,
    gre.tunnel_type
FROM frames f
JOIN gre ON f.frame_number = gre.frame_number
LEFT JOIN ipv4 ip4 ON ip4.frame_number = gre.frame_number AND ip4.encap_depth = gre.encap_depth
LEFT JOIN ipv6 ip6 ON ip6.frame_number = gre.frame_number AND ip6.encap_depth = gre.encap_depth
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gre_packets_view() {
        let view = gre_packets_view();
        // Layers join their anchor at the same encapsulation level.
        assert!(view.sql.contains("ip4.encap_depth = gre.encap_depth"));
        assert_eq!(view.name, "gre_packets");
        assert!(view.sql.contains("JOIN gre"));
        assert!(view.sql.contains("key"));
    }
}
