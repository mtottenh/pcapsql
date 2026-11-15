//! ICMP and ICMPv6 type and code names.

use super::Name;

use crate::protocol::{
    icmp_dest_unreachable_code as dest_unreachable_code,
    icmp_parameter_problem_code as parameter_problem_code, icmp_redirect_code as redirect_code,
    icmp_time_exceeded_code as time_exceeded_code, icmp_type, icmpv6_dest_unreachable_code,
    icmpv6_parameter_problem_code, icmpv6_time_exceeded_code, icmpv6_type,
};

/// Convert ICMP type to human-readable name.
pub fn icmp_type_name(t: u8) -> Name {
    match t {
        icmp_type::ECHO_REPLY => Name::fixed("Echo Reply"),
        icmp_type::DESTINATION_UNREACHABLE => Name::fixed("Destination Unreachable"),
        icmp_type::SOURCE_QUENCH => Name::fixed("Source Quench"),
        icmp_type::REDIRECT => Name::fixed("Redirect"),
        6 => Name::fixed("Alternate Host Address"),
        icmp_type::ECHO_REQUEST => Name::fixed("Echo Request"),
        icmp_type::ROUTER_ADVERTISEMENT => Name::fixed("Router Advertisement"),
        icmp_type::ROUTER_SOLICITATION => Name::fixed("Router Solicitation"),
        icmp_type::TIME_EXCEEDED => Name::fixed("Time Exceeded"),
        icmp_type::PARAMETER_PROBLEM => Name::fixed("Parameter Problem"),
        icmp_type::TIMESTAMP_REQUEST => Name::fixed("Timestamp"),
        icmp_type::TIMESTAMP_REPLY => Name::fixed("Timestamp Reply"),
        icmp_type::INFO_REQUEST => Name::fixed("Information Request"),
        icmp_type::INFO_REPLY => Name::fixed("Information Reply"),
        icmp_type::ADDRESS_MASK_REQUEST => Name::fixed("Address Mask Request"),
        icmp_type::ADDRESS_MASK_REPLY => Name::fixed("Address Mask Reply"),
        30 => Name::fixed("Traceroute"),
        31 => Name::fixed("Datagram Conversion Error"),
        32 => Name::fixed("Mobile Host Redirect"),
        33 => Name::fixed("IPv6 Where-Are-You"),
        34 => Name::fixed("IPv6 I-Am-Here"),
        35 => Name::fixed("Mobile Registration Request"),
        36 => Name::fixed("Mobile Registration Reply"),
        37 => Name::fixed("Domain Name Request"),
        38 => Name::fixed("Domain Name Reply"),
        39 => Name::fixed("SKIP"),
        40 => Name::fixed("Photuris"),
        41 => Name::fixed("ICMP for Seamoby"),
        42 => Name::fixed("Extended Echo Request"),
        43 => Name::fixed("Extended Echo Reply"),
        _ => Name::numbered("Type ", t, ""),
    }
}

/// Convert ICMPv6 type to human-readable name.
pub fn icmpv6_type_name(t: u8) -> Name {
    match t {
        // Error messages (0-127)
        icmpv6_type::DESTINATION_UNREACHABLE => Name::fixed("Destination Unreachable"),
        icmpv6_type::PACKET_TOO_BIG => Name::fixed("Packet Too Big"),
        icmpv6_type::TIME_EXCEEDED => Name::fixed("Time Exceeded"),
        icmpv6_type::PARAMETER_PROBLEM => Name::fixed("Parameter Problem"),
        100 => Name::fixed("Private Experimentation"),
        101 => Name::fixed("Private Experimentation"),
        127 => Name::fixed("Reserved for Expansion"),

        // Informational messages (128-255)
        icmpv6_type::ECHO_REQUEST => Name::fixed("Echo Request"),
        icmpv6_type::ECHO_REPLY => Name::fixed("Echo Reply"),
        icmpv6_type::MLD_QUERY => Name::fixed("Multicast Listener Query"),
        icmpv6_type::MLDV1_REPORT => Name::fixed("Multicast Listener Report"),
        icmpv6_type::MLDV1_DONE => Name::fixed("Multicast Listener Done"),
        icmpv6_type::ROUTER_SOLICITATION => Name::fixed("Router Solicitation"),
        icmpv6_type::ROUTER_ADVERTISEMENT => Name::fixed("Router Advertisement"),
        icmpv6_type::NEIGHBOR_SOLICITATION => Name::fixed("Neighbor Solicitation"),
        icmpv6_type::NEIGHBOR_ADVERTISEMENT => Name::fixed("Neighbor Advertisement"),
        icmpv6_type::REDIRECT => Name::fixed("Redirect"),
        138 => Name::fixed("Router Renumbering"),
        139 => Name::fixed("ICMP Node Information Query"),
        140 => Name::fixed("ICMP Node Information Response"),
        141 => Name::fixed("Inverse Neighbor Discovery Solicitation"),
        142 => Name::fixed("Inverse Neighbor Discovery Advertisement"),
        icmpv6_type::MLDV2_REPORT => Name::fixed("Version 2 Multicast Listener Report"),
        144 => Name::fixed("Home Agent Address Discovery Request"),
        145 => Name::fixed("Home Agent Address Discovery Reply"),
        146 => Name::fixed("Mobile Prefix Solicitation"),
        147 => Name::fixed("Mobile Prefix Advertisement"),
        148 => Name::fixed("Certification Path Solicitation"),
        149 => Name::fixed("Certification Path Advertisement"),
        150 => Name::fixed("ICMP Experimental"),
        151 => Name::fixed("Multicast Router Advertisement"),
        152 => Name::fixed("Multicast Router Solicitation"),
        153 => Name::fixed("Multicast Router Termination"),
        154 => Name::fixed("FMIPv6"),
        155 => Name::fixed("RPL Control"),
        156 => Name::fixed("ILNPv6 Locator Update"),
        157 => Name::fixed("Duplicate Address Request"),
        158 => Name::fixed("Duplicate Address Confirmation"),
        159 => Name::fixed("MPL Control"),
        160 => Name::fixed("Extended Echo Request"),
        161 => Name::fixed("Extended Echo Reply"),
        200 => Name::fixed("Private Experimentation"),
        201 => Name::fixed("Private Experimentation"),
        255 => Name::fixed("Reserved for Expansion"),

        _ => Name::numbered("Type ", t, ""),
    }
}

/// Convert ICMP type+code to human-readable name.
pub fn icmp_code_name(t: u8, code: u8) -> Name {
    match t {
        // Destination Unreachable
        icmp_type::DESTINATION_UNREACHABLE => match code {
            dest_unreachable_code::NET_UNREACHABLE => Name::fixed("Network Unreachable"),
            dest_unreachable_code::HOST_UNREACHABLE => Name::fixed("Host Unreachable"),
            dest_unreachable_code::PROTOCOL_UNREACHABLE => Name::fixed("Protocol Unreachable"),
            dest_unreachable_code::PORT_UNREACHABLE => Name::fixed("Port Unreachable"),
            dest_unreachable_code::FRAGMENTATION_NEEDED => Name::fixed("Fragmentation Needed"),
            dest_unreachable_code::SOURCE_ROUTE_FAILED => Name::fixed("Source Route Failed"),
            dest_unreachable_code::DEST_NET_UNKNOWN => Name::fixed("Destination Network Unknown"),
            dest_unreachable_code::DEST_HOST_UNKNOWN => Name::fixed("Destination Host Unknown"),
            dest_unreachable_code::SOURCE_HOST_ISOLATED => Name::fixed("Source Host Isolated"),
            dest_unreachable_code::NET_ADMIN_PROHIBITED => {
                Name::fixed("Network Administratively Prohibited")
            }
            dest_unreachable_code::HOST_ADMIN_PROHIBITED => {
                Name::fixed("Host Administratively Prohibited")
            }
            dest_unreachable_code::NET_TOS_UNREACHABLE => {
                Name::fixed("Network Unreachable for TOS")
            }
            dest_unreachable_code::HOST_TOS_UNREACHABLE => Name::fixed("Host Unreachable for TOS"),
            dest_unreachable_code::COMM_ADMIN_PROHIBITED => {
                Name::fixed("Communication Administratively Prohibited")
            }
            dest_unreachable_code::HOST_PRECEDENCE_VIOLATION => {
                Name::fixed("Host Precedence Violation")
            }
            dest_unreachable_code::PRECEDENCE_CUTOFF => Name::fixed("Precedence Cutoff in Effect"),
            _ => Name::numbered("Destination Unreachable (code ", code, ")"),
        },
        // Redirect
        icmp_type::REDIRECT => match code {
            redirect_code::REDIRECT_NET => Name::fixed("Redirect for Network"),
            redirect_code::REDIRECT_HOST => Name::fixed("Redirect for Host"),
            redirect_code::REDIRECT_TOS_NET => Name::fixed("Redirect for TOS and Network"),
            redirect_code::REDIRECT_TOS_HOST => Name::fixed("Redirect for TOS and Host"),
            _ => Name::numbered("Redirect (code ", code, ")"),
        },
        // Time Exceeded
        icmp_type::TIME_EXCEEDED => match code {
            time_exceeded_code::TTL_EXCEEDED => Name::fixed("TTL Exceeded in Transit"),
            time_exceeded_code::FRAGMENT_REASSEMBLY_EXCEEDED => {
                Name::fixed("Fragment Reassembly Time Exceeded")
            }
            _ => Name::numbered("Time Exceeded (code ", code, ")"),
        },
        // Parameter Problem
        icmp_type::PARAMETER_PROBLEM => match code {
            parameter_problem_code::POINTER_ERROR => Name::fixed("Pointer Indicates Error"),
            parameter_problem_code::MISSING_REQUIRED_OPTION => {
                Name::fixed("Missing Required Option")
            }
            parameter_problem_code::BAD_LENGTH => Name::fixed("Bad Length"),
            _ => Name::numbered("Parameter Problem (code ", code, ")"),
        },
        // Echo Reply and Echo Request have code 0
        icmp_type::ECHO_REPLY | icmp_type::ECHO_REQUEST => {
            if code == 0 {
                Name::fixed("No Code")
            } else {
                Name::numbered("Code ", code, "")
            }
        }
        // Other types
        _ => {
            if code == 0 {
                Name::fixed("No Code")
            } else {
                Name::numbered("Code ", code, "")
            }
        }
    }
}

/// Convert ICMPv6 type+code to human-readable name.
pub fn icmpv6_code_name(t: u8, code: u8) -> Name {
    match t {
        // Destination Unreachable
        icmpv6_type::DESTINATION_UNREACHABLE => match code {
            icmpv6_dest_unreachable_code::NO_ROUTE => Name::fixed("No Route to Destination"),
            icmpv6_dest_unreachable_code::ADMIN_PROHIBITED => {
                Name::fixed("Administratively Prohibited")
            }
            icmpv6_dest_unreachable_code::BEYOND_SCOPE => {
                Name::fixed("Beyond Scope of Source Address")
            }
            icmpv6_dest_unreachable_code::ADDRESS_UNREACHABLE => Name::fixed("Address Unreachable"),
            icmpv6_dest_unreachable_code::PORT_UNREACHABLE => Name::fixed("Port Unreachable"),
            icmpv6_dest_unreachable_code::FAILED_POLICY => {
                Name::fixed("Source Address Failed Ingress/Egress Policy")
            }
            icmpv6_dest_unreachable_code::REJECT_ROUTE => {
                Name::fixed("Reject Route to Destination")
            }
            icmpv6_dest_unreachable_code::SOURCE_ROUTING_ERROR => {
                Name::fixed("Error in Source Routing Header")
            }
            _ => Name::numbered("Destination Unreachable (code ", code, ")"),
        },
        // Packet Too Big
        icmpv6_type::PACKET_TOO_BIG => Name::fixed("Packet Too Big"),
        // Time Exceeded
        icmpv6_type::TIME_EXCEEDED => match code {
            icmpv6_time_exceeded_code::HOP_LIMIT_EXCEEDED => {
                Name::fixed("Hop Limit Exceeded in Transit")
            }
            icmpv6_time_exceeded_code::FRAGMENT_REASSEMBLY_EXCEEDED => {
                Name::fixed("Fragment Reassembly Time Exceeded")
            }
            _ => Name::numbered("Time Exceeded (code ", code, ")"),
        },
        // Parameter Problem
        icmpv6_type::PARAMETER_PROBLEM => match code {
            icmpv6_parameter_problem_code::ERRONEOUS_HEADER => {
                Name::fixed("Erroneous Header Field")
            }
            icmpv6_parameter_problem_code::UNRECOGNIZED_NEXT_HEADER => {
                Name::fixed("Unrecognized Next Header")
            }
            icmpv6_parameter_problem_code::UNRECOGNIZED_OPTION => {
                Name::fixed("Unrecognized IPv6 Option")
            }
            _ => Name::numbered("Parameter Problem (code ", code, ")"),
        },
        // Echo Request/Reply
        icmpv6_type::ECHO_REQUEST | icmpv6_type::ECHO_REPLY => {
            if code == 0 {
                Name::fixed("No Code")
            } else {
                Name::numbered("Code ", code, "")
            }
        }
        // Router Renumbering (type 138)
        138 => match code {
            0 => Name::fixed("Router Renumbering Command"),
            1 => Name::fixed("Router Renumbering Result"),
            255 => Name::fixed("Sequence Number Reset"),
            _ => Name::numbered("Router Renumbering (code ", code, ")"),
        },
        // Node Information Query (type 139)
        139 => match code {
            0 => Name::fixed("NI Query for IPv6 Address"),
            1 => Name::fixed("NI Query for Name or Empty"),
            2 => Name::fixed("NI Query for IPv4 Address"),
            _ => Name::numbered("NI Query (code ", code, ")"),
        },
        // Node Information Response (type 140)
        140 => match code {
            0 => Name::fixed("NI Response Success"),
            1 => Name::fixed("NI Responder Refuses"),
            2 => Name::fixed("NI Unknown Query Type"),
            _ => Name::numbered("NI Response (code ", code, ")"),
        },
        // Other types
        _ => {
            if code == 0 {
                Name::fixed("No Code")
            } else {
                Name::numbered("Code ", code, "")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_type_name() {
        assert_eq!(icmp_type_name(icmp_type::ECHO_REPLY), "Echo Reply");
        assert_eq!(
            icmp_type_name(icmp_type::DESTINATION_UNREACHABLE),
            "Destination Unreachable"
        );
        assert_eq!(icmp_type_name(icmp_type::REDIRECT), "Redirect");
        assert_eq!(icmp_type_name(icmp_type::ECHO_REQUEST), "Echo Request");
        assert_eq!(
            icmp_type_name(icmp_type::ROUTER_ADVERTISEMENT),
            "Router Advertisement"
        );
        assert_eq!(
            icmp_type_name(icmp_type::ROUTER_SOLICITATION),
            "Router Solicitation"
        );
        assert_eq!(icmp_type_name(icmp_type::TIME_EXCEEDED), "Time Exceeded");
        assert_eq!(icmp_type_name(icmp_type::TIMESTAMP_REQUEST), "Timestamp");
        assert_eq!(
            icmp_type_name(icmp_type::TIMESTAMP_REPLY),
            "Timestamp Reply"
        );
        // Unknown type
        assert_eq!(icmp_type_name(99), "Type 99");
    }

    #[test]
    fn test_icmpv6_type_name() {
        // Error messages
        assert_eq!(
            icmpv6_type_name(icmpv6_type::DESTINATION_UNREACHABLE),
            "Destination Unreachable"
        );
        assert_eq!(
            icmpv6_type_name(icmpv6_type::PACKET_TOO_BIG),
            "Packet Too Big"
        );
        assert_eq!(
            icmpv6_type_name(icmpv6_type::TIME_EXCEEDED),
            "Time Exceeded"
        );
        assert_eq!(
            icmpv6_type_name(icmpv6_type::PARAMETER_PROBLEM),
            "Parameter Problem"
        );

        // Informational messages
        assert_eq!(icmpv6_type_name(icmpv6_type::ECHO_REQUEST), "Echo Request");
        assert_eq!(icmpv6_type_name(icmpv6_type::ECHO_REPLY), "Echo Reply");
        assert_eq!(
            icmpv6_type_name(icmpv6_type::MLD_QUERY),
            "Multicast Listener Query"
        );
        assert_eq!(
            icmpv6_type_name(icmpv6_type::MLDV1_REPORT),
            "Multicast Listener Report"
        );
        assert_eq!(
            icmpv6_type_name(icmpv6_type::ROUTER_SOLICITATION),
            "Router Solicitation"
        );
        assert_eq!(
            icmpv6_type_name(icmpv6_type::ROUTER_ADVERTISEMENT),
            "Router Advertisement"
        );
        assert_eq!(
            icmpv6_type_name(icmpv6_type::NEIGHBOR_SOLICITATION),
            "Neighbor Solicitation"
        );
        assert_eq!(
            icmpv6_type_name(icmpv6_type::NEIGHBOR_ADVERTISEMENT),
            "Neighbor Advertisement"
        );
        assert_eq!(icmpv6_type_name(icmpv6_type::REDIRECT), "Redirect");

        // Unknown type
        assert_eq!(icmpv6_type_name(99), "Type 99");
    }

    #[test]
    fn test_ndp_types() {
        // NDP message types
        assert_eq!(
            icmpv6_type_name(icmpv6_type::ROUTER_SOLICITATION),
            "Router Solicitation"
        );
        assert_eq!(
            icmpv6_type_name(icmpv6_type::ROUTER_ADVERTISEMENT),
            "Router Advertisement"
        );
        assert_eq!(
            icmpv6_type_name(icmpv6_type::NEIGHBOR_SOLICITATION),
            "Neighbor Solicitation"
        );
        assert_eq!(
            icmpv6_type_name(icmpv6_type::NEIGHBOR_ADVERTISEMENT),
            "Neighbor Advertisement"
        );
        assert_eq!(icmpv6_type_name(icmpv6_type::REDIRECT), "Redirect");
    }

    #[test]
    fn test_mld_types() {
        // MLD message types
        assert_eq!(
            icmpv6_type_name(icmpv6_type::MLD_QUERY),
            "Multicast Listener Query"
        );
        assert_eq!(
            icmpv6_type_name(icmpv6_type::MLDV1_REPORT),
            "Multicast Listener Report"
        );
        assert_eq!(
            icmpv6_type_name(icmpv6_type::MLDV1_DONE),
            "Multicast Listener Done"
        );
        assert_eq!(
            icmpv6_type_name(icmpv6_type::MLDV2_REPORT),
            "Version 2 Multicast Listener Report"
        );
    }
}
