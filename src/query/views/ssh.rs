//! SSH packets view definition.
//!
//! Joins frames, IP, TCP, and SSH tables for convenient SSH analysis.

use super::ViewDefinition;

/// SSH packets view with TCP and IP context.
///
/// This view joins:
/// - `frames` (timestamp)
/// - `ipv4` or `ipv6` (src_ip, dst_ip)
/// - `tcp` (ports)
/// - `ssh` (protocol identification, key exchange, auth)
pub fn ssh_packets_view() -> ViewDefinition {
    ViewDefinition {
        name: "ssh_packets",
        description: "SSH packets with TCP/IP context",
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
    ssh.protocol_version,
    ssh.software_version,
    ssh.comments,
    ssh.msg_type,
    ssh.msg_type_name,
    ssh.encrypted,
    ssh.kex_algorithms,
    ssh.host_key_algorithms,
    ssh.encryption_algorithms,
    ssh.mac_algorithms,
    ssh.compression_algorithms,
    ssh.auth_username,
    ssh.auth_service,
    ssh.auth_method,
    ssh.channel_type,
    ssh.channel_id
FROM frames f
LEFT JOIN ipv4 ip4 ON f.frame_number = ip4.frame_number
LEFT JOIN ipv6 ip6 ON f.frame_number = ip6.frame_number
JOIN tcp ON f.frame_number = tcp.frame_number
JOIN ssh ON f.frame_number = ssh.frame_number
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_packets_view() {
        let view = ssh_packets_view();
        assert_eq!(view.name, "ssh_packets");
        assert!(view.sql.contains("JOIN ssh"));
        assert!(view.sql.contains("software_version"));
        assert!(view.sql.contains("kex_algorithms"));
    }
}
