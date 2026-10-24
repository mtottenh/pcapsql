//! MPLS packets view definition.
//!
//! Joins frames, Ethernet, and MPLS tables for convenient MPLS analysis.

use super::ViewDefinition;

/// MPLS packets view with Ethernet context.
///
/// This view joins:
/// - `frames` (timestamp)
/// - `ethernet` (src_mac, dst_mac)
/// - `mpls` (label, tc, ttl, stack_depth)
pub fn mpls_packets_view() -> ViewDefinition {
    ViewDefinition {
        name: "mpls_packets",
        description: "MPLS labeled packets with Ethernet context",
        sql: r#"
SELECT
    f.frame_number,
    f.timestamp,
    eth.src_mac,
    eth.dst_mac,
    mpls.label,
    mpls.tc,
    mpls.bottom,
    mpls.ttl,
    mpls.stack_depth,
    mpls.labels,
    mpls.encap_depth,
    mpls.tunnel_type
FROM frames f
JOIN mpls ON f.frame_number = mpls.frame_number
JOIN ethernet eth ON eth.frame_number = mpls.frame_number AND eth.encap_depth = mpls.encap_depth
"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpls_packets_view() {
        let view = mpls_packets_view();
        // Layers join their anchor at the same encapsulation level.
        assert!(view.sql.contains("eth.encap_depth = mpls.encap_depth"));
        assert_eq!(view.name, "mpls_packets");
        assert!(view.sql.contains("JOIN mpls"));
        assert!(view.sql.contains("label"));
    }
}
