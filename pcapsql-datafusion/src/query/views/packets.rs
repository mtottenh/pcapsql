//! Unified packets view definition.
//!
//! Provides a flattened view similar to the original `packets` table for
//! backward compatibility and convenience queries across all protocol layers.

use super::ViewDefinition;

/// Unified packets view with common fields from all layers.
///
/// This view joins multiple protocol tables to provide a flattened view
/// similar to the original single-table design. Useful for:
/// - Backward compatibility with existing queries
/// - Quick overview queries across all traffic
/// - Filtering by common fields without specifying exact protocol tables
pub fn packets_view() -> ViewDefinition {
    ViewDefinition {
        name: "packets",
        description: "Unified view of all packets with common fields from each layer",
        sql: r#"
SELECT
    f.frame_number,
    f.timestamp,
    f.length,
    f.original_length,
    -- Ethernet
    e.src_mac AS eth_src,
    e.dst_mac AS eth_dst,
    e.ethertype AS eth_type,
    -- ARP
    arp.operation AS arp_operation,
    arp.sender_ip AS arp_sender_ip,
    arp.target_ip AS arp_target_ip,
    arp.sender_mac AS arp_sender_mac,
    arp.target_mac AS arp_target_mac,
    -- IP layer (separate v4/v6)
    COALESCE(ip4.version, ip6.version) AS ip_version,
    ip4.src_ip AS src_ip_v4,
    ip4.dst_ip AS dst_ip_v4,
    ip6.src_ip AS src_ip_v6,
    ip6.dst_ip AS dst_ip_v6,
    COALESCE(ip4.ttl, ip6.hop_limit) AS ip_ttl,
    COALESCE(ip4.protocol, ip6.next_header) AS ip_protocol,
    -- Transport layer (coalesced TCP/UDP)
    COALESCE(tcp.src_port, udp.src_port) AS src_port,
    COALESCE(tcp.dst_port, udp.dst_port) AS dst_port,
    -- Protocol indicator
    CASE
        WHEN tcp.frame_number IS NOT NULL THEN 'TCP'
        WHEN udp.frame_number IS NOT NULL THEN 'UDP'
        WHEN icmp.frame_number IS NOT NULL THEN 'ICMP'
        WHEN arp.frame_number IS NOT NULL THEN 'ARP'
        ELSE NULL
    END AS protocol,
    -- TCP specific
    tcp.seq AS tcp_seq,
    tcp.ack AS tcp_ack,
    tcp.flags AS tcp_flags,
    -- ICMP specific
    icmp.type AS icmp_type,
    icmp.code AS icmp_code,
    -- DNS
    dns.query_name AS dns_query_name,
    dns.query_type AS dns_query_type,
    dns.is_query AS dns_is_query,
    -- TLS
    tls.version AS tls_version,
    tls.sni AS tls_sni,
    tls.handshake_type AS tls_handshake_type,
    -- HTTP
    http.method AS http_method,
    http.uri AS http_uri,
    http.status_code AS http_status_code,
    http.host AS http_host,
    -- DHCP
    dhcp.message_type AS dhcp_message_type,
    dhcp.chaddr AS dhcp_client_mac,
    -- NTP
    ntp.version AS ntp_version,
    ntp.mode AS ntp_mode,
    ntp.stratum AS ntp_stratum
FROM frames f
LEFT JOIN ethernet e ON f.frame_number = e.frame_number
LEFT JOIN arp ON f.frame_number = arp.frame_number
LEFT JOIN ipv4 ip4 ON f.frame_number = ip4.frame_number
LEFT JOIN ipv6 ip6 ON f.frame_number = ip6.frame_number
LEFT JOIN tcp ON f.frame_number = tcp.frame_number
LEFT JOIN udp ON f.frame_number = udp.frame_number
LEFT JOIN icmp ON f.frame_number = icmp.frame_number
LEFT JOIN dns ON f.frame_number = dns.frame_number
LEFT JOIN tls ON f.frame_number = tls.frame_number
LEFT JOIN http ON f.frame_number = http.frame_number
LEFT JOIN dhcp ON f.frame_number = dhcp.frame_number
LEFT JOIN ntp ON f.frame_number = ntp.frame_number
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packets_view() {
        let view = packets_view();
        assert_eq!(view.name, "packets");
        assert!(view.sql.contains("FROM frames"));
        assert!(view.sql.contains("src_ip"));
        assert!(view.sql.contains("dst_ip"));
        assert!(view.sql.contains("protocol"));
    }
}
