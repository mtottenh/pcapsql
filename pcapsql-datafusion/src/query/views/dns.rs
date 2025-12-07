//! DNS packets view definition.
//!
//! Joins frames, IP, transport (UDP/TCP), and DNS tables with transport detection.

use super::ViewDefinition;

/// DNS packets view with transport detection (UDP/TCP/DoT/DoH).
///
/// This view joins:
/// - `frames` (timestamp)
/// - `ipv4` or `ipv6` (src_ip, dst_ip)
/// - `tcp` or `udp` (ports)
/// - `tls` (for DoT detection)
/// - `http` (for DoH detection)
/// - `dns` (query details)
pub fn dns_packets_view() -> ViewDefinition {
    ViewDefinition {
        name: "dns_packets",
        description: "DNS queries and responses with transport detection (UDP/TCP/DoT/DoH)",
        sql: r#"
SELECT
    f.frame_number,
    f.timestamp,
    ip4.src_ip AS src_ip_v4,
    ip4.dst_ip AS dst_ip_v4,
    ip6.src_ip AS src_ip_v6,
    ip6.dst_ip AS dst_ip_v6,
    COALESCE(tcp.src_port, udp.src_port) AS src_port,
    COALESCE(tcp.dst_port, udp.dst_port) AS dst_port,
    CASE
        WHEN http.frame_number IS NOT NULL THEN 'DoH'
        WHEN tls.frame_number IS NOT NULL THEN 'DoT'
        WHEN tcp.frame_number IS NOT NULL THEN 'TCP'
        ELSE 'UDP'
    END AS transport,
    dns.transaction_id,
    dns.is_query,
    dns.opcode,
    dns.is_authoritative,
    dns.is_truncated,
    dns.recursion_desired,
    dns.recursion_available,
    dns.response_code,
    dns.query_count,
    dns.answer_count,
    dns.authority_count,
    dns.additional_count,
    dns.query_name,
    dns.query_type,
    dns.query_class
FROM frames f
LEFT JOIN ipv4 ip4 ON f.frame_number = ip4.frame_number
LEFT JOIN ipv6 ip6 ON f.frame_number = ip6.frame_number
LEFT JOIN tcp ON f.frame_number = tcp.frame_number
LEFT JOIN udp ON f.frame_number = udp.frame_number
LEFT JOIN tls ON f.frame_number = tls.frame_number
LEFT JOIN http ON f.frame_number = http.frame_number
JOIN dns ON f.frame_number = dns.frame_number
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_packets_view() {
        let view = dns_packets_view();
        assert_eq!(view.name, "dns_packets");
        assert!(view.sql.contains("JOIN dns"));
        assert!(view.sql.contains("query_name"));
        assert!(view.sql.contains("transport"));
    }
}
