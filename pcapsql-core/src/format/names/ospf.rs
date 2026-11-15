//! OSPF packet type and LSA type names.

use super::Name;

use crate::protocol::{ospf_lsa_type as lsa_type, ospf_packet_type as packet_type};

/// Convert an OSPF packet type to its name; `Unknown (n)` otherwise.
pub fn ospf_packet_type_name(pkt_type: u8) -> Name {
    match pkt_type {
        packet_type::HELLO => Name::fixed("Hello"),
        packet_type::DATABASE_DESCRIPTION => Name::fixed("Database Description"),
        packet_type::LINK_STATE_REQUEST => Name::fixed("Link State Request"),
        packet_type::LINK_STATE_UPDATE => Name::fixed("Link State Update"),
        packet_type::LINK_STATE_ACK => Name::fixed("Link State Acknowledgment"),
        _ => Name::unknown(pkt_type),
    }
}

/// Convert an OSPF LSA type to its name; `Unknown (n)` otherwise.
pub fn ospf_lsa_type_name(ls_type: u8) -> Name {
    match ls_type {
        lsa_type::ROUTER => Name::fixed("Router-LSA"),
        lsa_type::NETWORK => Name::fixed("Network-LSA"),
        lsa_type::SUMMARY_NETWORK => Name::fixed("Summary-LSA-Network"),
        lsa_type::SUMMARY_ASBR => Name::fixed("Summary-LSA-ASBR"),
        lsa_type::AS_EXTERNAL => Name::fixed("AS-External-LSA"),
        lsa_type::GROUP_MEMBERSHIP => Name::fixed("Group-Membership-LSA"),
        lsa_type::NSSA_EXTERNAL => Name::fixed("NSSA-External-LSA"),
        lsa_type::EXTERNAL_ATTRIBUTES => Name::fixed("External-Attributes-LSA"),
        lsa_type::OPAQUE_LINK => Name::fixed("Opaque-Link-LSA"),
        lsa_type::OPAQUE_AREA => Name::fixed("Opaque-Area-LSA"),
        lsa_type::OPAQUE_AS => Name::fixed("Opaque-AS-LSA"),
        _ => Name::unknown(ls_type),
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
