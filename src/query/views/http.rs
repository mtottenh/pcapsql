//! HTTP packets view definition.
//!
//! Joins frames, IP, TCP, and HTTP tables for convenient HTTP analysis.

use super::ViewDefinition;

/// HTTP packets view with TCP and IP context.
///
/// This view joins:
/// - `frames` (timestamp)
/// - `ipv4` or `ipv6` (src_ip, dst_ip)
/// - `tcp` (ports)
/// - `http` (request/response details)
pub fn http_packets_view() -> ViewDefinition {
    ViewDefinition {
        name: "http_packets",
        description: "HTTP requests and responses with TCP/IP context",
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
    http.is_request,
    http.method,
    http.uri,
    http.version,
    http.status_code,
    http.status_text,
    http.host,
    http.content_type,
    http.content_length,
    http.user_agent,
    http.server
FROM frames f
LEFT JOIN ipv4 ip4 ON f.frame_number = ip4.frame_number
LEFT JOIN ipv6 ip6 ON f.frame_number = ip6.frame_number
JOIN tcp ON f.frame_number = tcp.frame_number
JOIN http ON f.frame_number = http.frame_number
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_packets_view() {
        let view = http_packets_view();
        assert_eq!(view.name, "http_packets");
        assert!(view.sql.contains("JOIN http"));
        assert!(view.sql.contains("method"));
        assert!(view.sql.contains("uri"));
    }
}
