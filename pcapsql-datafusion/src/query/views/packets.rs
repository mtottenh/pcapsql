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
    net.eth_src,
    net.eth_dst,
    net.eth_type,
    -- ARP
    net.arp_operation,
    net.arp_sender_ip,
    net.arp_target_ip,
    net.arp_sender_mac,
    net.arp_target_mac,
    -- IP layer (separate v4/v6)
    COALESCE(net.ip4_version, net.ip6_version) AS ip_version,
    net.ip4_src_ip AS src_ip_v4,
    net.ip4_dst_ip AS dst_ip_v4,
    net.ip6_src_ip AS src_ip_v6,
    net.ip6_dst_ip AS dst_ip_v6,
    COALESCE(net.ip4_ttl, net.ip6_hop_limit) AS ip_ttl,
    COALESCE(net.ip4_protocol, net.ip6_next_header) AS ip_protocol,
    -- Transport layer (coalesced TCP/UDP)
    COALESCE(tcp.src_port, udp.src_port) AS src_port,
    COALESCE(tcp.dst_port, udp.dst_port) AS dst_port,
    -- Protocol indicator
    CASE
        WHEN tcp.frame_number IS NOT NULL THEN 'TCP'
        WHEN udp.frame_number IS NOT NULL THEN 'UDP'
        WHEN icmp.frame_number IS NOT NULL THEN 'ICMP'
        WHEN net.arp_operation IS NOT NULL THEN 'ARP'
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
    ntp.stratum AS ntp_stratum,
    -- Encapsulation level of this row's headers
    COALESCE(net.encap_depth, arrow_cast(0, 'UInt8')) AS encap_depth,
    net.tunnel_type
FROM frames f
-- One row per encapsulation level of the frame. A level is a depth at which
-- a network-layer header (IPv4, IPv6 or ARP) or a link-layer header
-- (Ethernet) sits; `net` lists them with a full join of those tables on
-- (frame_number, encap_depth). The parser emits at most one row of each per
-- level and one network header per level, so each level is one row. A frame
-- with none of them (a non-Ethernet link with no IP) is one row at depth 0.
-- Every other layer, transports included, is the one at the row's level.
LEFT JOIN (
    SELECT
        COALESCE(ip4.frame_number, ip6.frame_number, arp.frame_number, e.frame_number) AS frame_number,
        COALESCE(ip4.encap_depth, ip6.encap_depth, arp.encap_depth, e.encap_depth) AS encap_depth,
        COALESCE(ip4.tunnel_type, ip6.tunnel_type, arp.tunnel_type, e.tunnel_type) AS tunnel_type,
        e.src_mac AS eth_src,
        e.dst_mac AS eth_dst,
        e.ethertype AS eth_type,
        ip4.version AS ip4_version,
        ip4.src_ip AS ip4_src_ip,
        ip4.dst_ip AS ip4_dst_ip,
        ip4.ttl AS ip4_ttl,
        ip4.protocol AS ip4_protocol,
        ip6.version AS ip6_version,
        ip6.src_ip AS ip6_src_ip,
        ip6.dst_ip AS ip6_dst_ip,
        ip6.hop_limit AS ip6_hop_limit,
        ip6.next_header AS ip6_next_header,
        arp.operation AS arp_operation,
        arp.sender_ip AS arp_sender_ip,
        arp.target_ip AS arp_target_ip,
        arp.sender_mac AS arp_sender_mac,
        arp.target_mac AS arp_target_mac
    FROM ipv4 ip4
    FULL JOIN ipv6 ip6
        ON ip6.frame_number = ip4.frame_number AND ip6.encap_depth = ip4.encap_depth
    FULL JOIN arp
        ON arp.frame_number = COALESCE(ip4.frame_number, ip6.frame_number)
        AND arp.encap_depth = COALESCE(ip4.encap_depth, ip6.encap_depth)
    FULL JOIN ethernet e
        ON e.frame_number = COALESCE(ip4.frame_number, ip6.frame_number, arp.frame_number)
        AND e.encap_depth = COALESCE(ip4.encap_depth, ip6.encap_depth, arp.encap_depth)
) net ON net.frame_number = f.frame_number
LEFT JOIN tcp ON tcp.frame_number = f.frame_number
    AND tcp.encap_depth = COALESCE(net.encap_depth, arrow_cast(0, 'UInt8'))
LEFT JOIN udp ON udp.frame_number = f.frame_number
    AND udp.encap_depth = COALESCE(net.encap_depth, arrow_cast(0, 'UInt8'))
LEFT JOIN icmp ON icmp.frame_number = f.frame_number
    AND icmp.encap_depth = COALESCE(net.encap_depth, arrow_cast(0, 'UInt8'))
LEFT JOIN dns ON dns.frame_number = f.frame_number
    AND dns.encap_depth = COALESCE(net.encap_depth, arrow_cast(0, 'UInt8'))
LEFT JOIN tls ON tls.frame_number = f.frame_number
    AND tls.encap_depth = COALESCE(net.encap_depth, arrow_cast(0, 'UInt8'))
LEFT JOIN http ON http.frame_number = f.frame_number
    AND http.encap_depth = COALESCE(net.encap_depth, arrow_cast(0, 'UInt8'))
LEFT JOIN dhcp ON dhcp.frame_number = f.frame_number
    AND dhcp.encap_depth = COALESCE(net.encap_depth, arrow_cast(0, 'UInt8'))
LEFT JOIN ntp ON ntp.frame_number = f.frame_number
    AND ntp.encap_depth = COALESCE(net.encap_depth, arrow_cast(0, 'UInt8'))
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packets_view() {
        let view = packets_view();
        // Every layer is joined at the row's encapsulation level.
        assert!(view
            .sql
            .contains("tcp.encap_depth = COALESCE(net.encap_depth, arrow_cast(0, 'UInt8'))"));
        assert_eq!(view.name, "packets");
        assert!(view.sql.contains("FROM frames"));
        assert!(view.sql.contains("src_ip"));
        assert!(view.sql.contains("dst_ip"));
        assert!(view.sql.contains("protocol"));
    }
}
