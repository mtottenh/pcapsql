//! BGP message type and ORIGIN attribute names.

use std::borrow::Cow;

use crate::protocol::{bgp_message_type as message_type, bgp_origin_type as origin_type};

/// Convert a BGP message type to its name; `Unknown (n)` otherwise.
pub fn bgp_message_type_name(msg_type: u8) -> Cow<'static, str> {
    match msg_type {
        message_type::OPEN => Cow::Borrowed("OPEN"),
        message_type::UPDATE => Cow::Borrowed("UPDATE"),
        message_type::NOTIFICATION => Cow::Borrowed("NOTIFICATION"),
        message_type::KEEPALIVE => Cow::Borrowed("KEEPALIVE"),
        message_type::ROUTE_REFRESH => Cow::Borrowed("ROUTE-REFRESH"),
        _ => Cow::Owned(format!("Unknown ({msg_type})")),
    }
}

/// Convert a BGP ORIGIN attribute value to its name; `Unknown (n)` otherwise.
pub fn bgp_origin_name(origin: u8) -> Cow<'static, str> {
    match origin {
        origin_type::IGP => Cow::Borrowed("IGP"),
        origin_type::EGP => Cow::Borrowed("EGP"),
        origin_type::INCOMPLETE => Cow::Borrowed("INCOMPLETE"),
        _ => Cow::Owned(format!("Unknown ({origin})")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bgp_message_type_name() {
        assert_eq!(bgp_message_type_name(message_type::OPEN), "OPEN");
        assert_eq!(bgp_message_type_name(message_type::UPDATE), "UPDATE");
        assert_eq!(
            bgp_message_type_name(message_type::NOTIFICATION),
            "NOTIFICATION"
        );
        assert_eq!(bgp_message_type_name(message_type::KEEPALIVE), "KEEPALIVE");
        assert_eq!(
            bgp_message_type_name(message_type::ROUTE_REFRESH),
            "ROUTE-REFRESH"
        );
        assert_eq!(bgp_message_type_name(99), "Unknown (99)");
    }

    #[test]
    fn test_bgp_origin_name() {
        assert_eq!(bgp_origin_name(origin_type::IGP), "IGP");
        assert_eq!(bgp_origin_name(origin_type::EGP), "EGP");
        assert_eq!(bgp_origin_name(origin_type::INCOMPLETE), "INCOMPLETE");
        assert_eq!(bgp_origin_name(3), "Unknown (3)");
    }
}
