//! Special-purpose MPLS label names.

use crate::protocol::mpls_special_label as special_label;

/// The name of a special-purpose MPLS label (0-15, RFC 3032 and the IANA
/// registry), `Reserved` for one with no assignment; `None` for an ordinary
/// label (16 upwards).
pub fn mpls_special_label_name(label: u32) -> Option<&'static str> {
    match label {
        special_label::IPV4_EXPLICIT_NULL => Some("IPv4-Explicit-NULL"),
        special_label::ROUTER_ALERT => Some("Router-Alert"),
        special_label::IPV6_EXPLICIT_NULL => Some("IPv6-Explicit-NULL"),
        special_label::IMPLICIT_NULL => Some("Implicit-NULL"),
        special_label::ENTROPY_LABEL_INDICATOR => Some("ELI"),
        special_label::GAL => Some("GAL"),
        special_label::OAM_ALERT => Some("OAM-Alert"),
        special_label::EXTENSION => Some("Extension"),
        4..=6 | 8..=12 => Some("Reserved"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpls_special_label_name() {
        assert_eq!(mpls_special_label_name(0), Some("IPv4-Explicit-NULL"));
        assert_eq!(mpls_special_label_name(3), Some("Implicit-NULL"));
        assert_eq!(mpls_special_label_name(5), Some("Reserved"));
        assert_eq!(mpls_special_label_name(13), Some("GAL"));
        assert_eq!(mpls_special_label_name(15), Some("Extension"));
        assert_eq!(mpls_special_label_name(16), None);
        assert_eq!(mpls_special_label_name(1_048_575), None);
    }
}
