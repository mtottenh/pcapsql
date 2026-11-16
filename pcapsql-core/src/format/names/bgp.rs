//! BGP message type, ORIGIN attribute, NOTIFICATION error code and capability
//! names.

use super::Name;

use crate::protocol::{
    bgp_capability_code as capability_code, bgp_error_code as error_code,
    bgp_message_type as message_type, bgp_origin_type as origin_type,
};

/// Convert a BGP message type to its name; `Unknown (n)` otherwise.
pub fn bgp_message_type_name(msg_type: u8) -> Name {
    match msg_type {
        message_type::OPEN => Name::fixed("OPEN"),
        message_type::UPDATE => Name::fixed("UPDATE"),
        message_type::NOTIFICATION => Name::fixed("NOTIFICATION"),
        message_type::KEEPALIVE => Name::fixed("KEEPALIVE"),
        message_type::ROUTE_REFRESH => Name::fixed("ROUTE-REFRESH"),
        _ => Name::unknown(msg_type),
    }
}

/// Convert a BGP ORIGIN attribute value to its name; `Unknown (n)` otherwise.
pub fn bgp_origin_name(origin: u8) -> Name {
    match origin {
        origin_type::IGP => Name::fixed("IGP"),
        origin_type::EGP => Name::fixed("EGP"),
        origin_type::INCOMPLETE => Name::fixed("INCOMPLETE"),
        _ => Name::unknown(origin),
    }
}

/// Convert a BGP NOTIFICATION error code to its name; `Unknown (n)`
/// otherwise.
pub fn bgp_error_code_name(code: u8) -> Name {
    match code {
        error_code::MESSAGE_HEADER_ERROR => Name::fixed("Message Header Error"),
        error_code::OPEN_MESSAGE_ERROR => Name::fixed("OPEN Message Error"),
        error_code::UPDATE_MESSAGE_ERROR => Name::fixed("UPDATE Message Error"),
        error_code::HOLD_TIMER_EXPIRED => Name::fixed("Hold Timer Expired"),
        error_code::FSM_ERROR => Name::fixed("Finite State Machine Error"),
        error_code::CEASE => Name::fixed("Cease"),
        error_code::ROUTE_REFRESH_ERROR => Name::fixed("ROUTE-REFRESH Message Error"),
        _ => Name::unknown(code),
    }
}

/// Convert a BGP capability code (an OPEN optional parameter, RFC 5492) to
/// its name; `Unknown (n)` otherwise.
pub fn bgp_capability_name(code: u8) -> Name {
    match code {
        capability_code::MULTIPROTOCOL => Name::fixed("MULTIPROTOCOL"),
        capability_code::ROUTE_REFRESH => Name::fixed("ROUTE_REFRESH"),
        capability_code::FOUR_OCTET_AS => Name::fixed("4-BYTE-AS"),
        capability_code::ADD_PATH => Name::fixed("ADD_PATH"),
        capability_code::ENHANCED_ROUTE_REFRESH => Name::fixed("ENHANCED_ROUTE_REFRESH"),
        _ => Name::unknown(code),
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

    #[test]
    fn test_bgp_error_code_name() {
        assert_eq!(bgp_error_code_name(1), "Message Header Error");
        assert_eq!(bgp_error_code_name(6), "Cease");
        assert_eq!(bgp_error_code_name(7), "ROUTE-REFRESH Message Error");
        assert_eq!(bgp_error_code_name(0), "Unknown (0)");
        assert_eq!(bgp_error_code_name(8), "Unknown (8)");
    }

    #[test]
    fn test_bgp_capability_name() {
        assert_eq!(bgp_capability_name(1), "MULTIPROTOCOL");
        assert_eq!(bgp_capability_name(65), "4-BYTE-AS");
        assert_eq!(bgp_capability_name(70), "ENHANCED_ROUTE_REFRESH");
        assert_eq!(bgp_capability_name(64), "Unknown (64)");
    }
}
