//! OSPF packet type and LSA type names.

use std::borrow::Cow;

use crate::protocol::{ospf_lsa_type as lsa_type, ospf_packet_type as packet_type};

/// Convert an OSPF packet type to its name; `Unknown (n)` otherwise.
pub fn ospf_packet_type_name(pkt_type: u8) -> Cow<'static, str> {
    match pkt_type {
        packet_type::HELLO => Cow::Borrowed("Hello"),
        packet_type::DATABASE_DESCRIPTION => Cow::Borrowed("Database Description"),
        packet_type::LINK_STATE_REQUEST => Cow::Borrowed("Link State Request"),
        packet_type::LINK_STATE_UPDATE => Cow::Borrowed("Link State Update"),
        packet_type::LINK_STATE_ACK => Cow::Borrowed("Link State Acknowledgment"),
        _ => Cow::Owned(format!("Unknown ({pkt_type})")),
    }
}

/// Convert an OSPF LSA type to its name; `Unknown (n)` otherwise.
pub fn ospf_lsa_type_name(ls_type: u8) -> Cow<'static, str> {
    match ls_type {
        lsa_type::ROUTER => Cow::Borrowed("Router-LSA"),
        lsa_type::NETWORK => Cow::Borrowed("Network-LSA"),
        lsa_type::SUMMARY_NETWORK => Cow::Borrowed("Summary-LSA-Network"),
        lsa_type::SUMMARY_ASBR => Cow::Borrowed("Summary-LSA-ASBR"),
        lsa_type::AS_EXTERNAL => Cow::Borrowed("AS-External-LSA"),
        lsa_type::GROUP_MEMBERSHIP => Cow::Borrowed("Group-Membership-LSA"),
        lsa_type::NSSA_EXTERNAL => Cow::Borrowed("NSSA-External-LSA"),
        lsa_type::EXTERNAL_ATTRIBUTES => Cow::Borrowed("External-Attributes-LSA"),
        lsa_type::OPAQUE_LINK => Cow::Borrowed("Opaque-Link-LSA"),
        lsa_type::OPAQUE_AREA => Cow::Borrowed("Opaque-Area-LSA"),
        lsa_type::OPAQUE_AS => Cow::Borrowed("Opaque-AS-LSA"),
        _ => Cow::Owned(format!("Unknown ({ls_type})")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ospf_packet_type_name() {
        assert_eq!(ospf_packet_type_name(packet_type::HELLO), "Hello");
        assert_eq!(
            ospf_packet_type_name(packet_type::DATABASE_DESCRIPTION),
            "Database Description"
        );
        assert_eq!(
            ospf_packet_type_name(packet_type::LINK_STATE_REQUEST),
            "Link State Request"
        );
        assert_eq!(
            ospf_packet_type_name(packet_type::LINK_STATE_UPDATE),
            "Link State Update"
        );
        assert_eq!(
            ospf_packet_type_name(packet_type::LINK_STATE_ACK),
            "Link State Acknowledgment"
        );
        assert_eq!(ospf_packet_type_name(99), "Unknown (99)");
    }

    #[test]
    fn test_ospf_lsa_type_name() {
        assert_eq!(ospf_lsa_type_name(lsa_type::ROUTER), "Router-LSA");
        assert_eq!(ospf_lsa_type_name(lsa_type::NETWORK), "Network-LSA");
        assert_eq!(ospf_lsa_type_name(lsa_type::AS_EXTERNAL), "AS-External-LSA");
        assert_eq!(
            ospf_lsa_type_name(lsa_type::NSSA_EXTERNAL),
            "NSSA-External-LSA"
        );
        assert_eq!(ospf_lsa_type_name(99), "Unknown (99)");
    }
}
