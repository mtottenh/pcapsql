//! OSPF packets view definition.
//!
//! Joins frames, IPv4, and OSPF tables for convenient OSPF analysis.

use super::ViewDefinition;

/// OSPF packets view with IPv4 context.
///
/// This view joins:
/// - `frames` (timestamp)
/// - `ipv4` (src_ip, dst_ip)
/// - `ospf` (router_id, area_id, message_type)
pub fn ospf_packets_view() -> ViewDefinition {
    ViewDefinition {
        name: "ospf_packets",
        description: "OSPF routing messages with IPv4 context",
        sql: r#"
SELECT
    f.frame_number,
    f.timestamp,
    ip4.src_ip,
    ip4.dst_ip,
    ospf.version,
    ospf.message_type,
    ospf.message_type_name,
    ospf.length,
    ospf.router_id,
    ospf.area_id,
    ospf.auth_type,
    ospf.hello_interval,
    ospf.dead_interval,
    ospf.designated_router,
    ospf.backup_dr
FROM frames f
JOIN ipv4 ip4 ON f.frame_number = ip4.frame_number
JOIN ospf ON f.frame_number = ospf.frame_number
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ospf_packets_view() {
        let view = ospf_packets_view();
        assert_eq!(view.name, "ospf_packets");
        assert!(view.sql.contains("JOIN ospf"));
        assert!(view.sql.contains("router_id"));
    }
}
