//! ARP packets view definition.
//!
//! Joins frames, ethernet, and ARP tables for convenient ARP analysis.

use super::ViewDefinition;

/// ARP packets view with frame and Ethernet context.
///
/// This view joins:
/// - `frames` (timestamp)
/// - `ethernet` (src/dst MAC)
/// - `arp` (ARP fields)
pub fn arp_packets_view() -> ViewDefinition {
    ViewDefinition {
        name: "arp_packets",
        description: "ARP requests and replies with Ethernet context",
        sql: r#"
SELECT
    f.frame_number,
    f.timestamp,
    e.src_mac,
    e.dst_mac,
    arp.hardware_type,
    arp.protocol_type,
    arp.hardware_size,
    arp.protocol_size,
    arp.operation,
    arp.sender_mac,
    arp.sender_ip,
    arp.target_mac,
    arp.target_ip
FROM frames f
LEFT JOIN ethernet e ON f.frame_number = e.frame_number
JOIN arp ON f.frame_number = arp.frame_number
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arp_packets_view() {
        let view = arp_packets_view();
        assert_eq!(view.name, "arp_packets");
        assert!(view.sql.contains("JOIN arp"));
        assert!(view.sql.contains("sender_ip"));
        assert!(view.sql.contains("target_ip"));
    }
}
