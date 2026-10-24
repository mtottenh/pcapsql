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
    ospf.backup_dr,
    ospf.neighbor_count,
    ospf.dd_interface_mtu,
    ospf.dd_options,
    ospf.dd_flags,
    ospf.dd_sequence,
    ospf.dd_lsa_count,
    ospf.lsu_lsa_count,
    ospf.lsa_ack_count,
    ospf.lsa_age,
    ospf.lsa_type,
    ospf.lsa_type_name,
    ospf.lsa_id,
    ospf.lsa_advertising_router,
    ospf.lsa_sequence,
    ospf.encap_depth,
    ospf.tunnel_type
FROM frames f
JOIN ospf ON f.frame_number = ospf.frame_number
JOIN ipv4 ip4 ON ip4.frame_number = ospf.frame_number AND ip4.encap_depth = ospf.encap_depth
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ospf_packets_view() {
        let view = ospf_packets_view();
        // Layers join their anchor at the same encapsulation level.
        assert!(view.sql.contains("ip4.encap_depth = ospf.encap_depth"));
        assert_eq!(view.name, "ospf_packets");
        assert!(view.sql.contains("JOIN ospf"));
        assert!(view.sql.contains("router_id"));
        assert!(view.sql.contains("ospf.lsa_advertising_router,"));
    }
}
