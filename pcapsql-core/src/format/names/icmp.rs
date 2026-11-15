//! ICMP and ICMPv6 type and code names.

use std::borrow::Cow;

use crate::protocol::{
    icmp_dest_unreachable_code as dest_unreachable_code,
    icmp_parameter_problem_code as parameter_problem_code, icmp_redirect_code as redirect_code,
    icmp_time_exceeded_code as time_exceeded_code, icmp_type, icmpv6_dest_unreachable_code,
    icmpv6_parameter_problem_code, icmpv6_time_exceeded_code, icmpv6_type,
};

/// Convert ICMP type to human-readable name.
pub fn icmp_type_name(t: u8) -> Cow<'static, str> {
    match t {
        icmp_type::ECHO_REPLY => Cow::Borrowed("Echo Reply"),
        icmp_type::DESTINATION_UNREACHABLE => Cow::Borrowed("Destination Unreachable"),
        icmp_type::SOURCE_QUENCH => Cow::Borrowed("Source Quench"),
        icmp_type::REDIRECT => Cow::Borrowed("Redirect"),
        6 => Cow::Borrowed("Alternate Host Address"),
        icmp_type::ECHO_REQUEST => Cow::Borrowed("Echo Request"),
        icmp_type::ROUTER_ADVERTISEMENT => Cow::Borrowed("Router Advertisement"),
        icmp_type::ROUTER_SOLICITATION => Cow::Borrowed("Router Solicitation"),
        icmp_type::TIME_EXCEEDED => Cow::Borrowed("Time Exceeded"),
        icmp_type::PARAMETER_PROBLEM => Cow::Borrowed("Parameter Problem"),
        icmp_type::TIMESTAMP_REQUEST => Cow::Borrowed("Timestamp"),
        icmp_type::TIMESTAMP_REPLY => Cow::Borrowed("Timestamp Reply"),
        icmp_type::INFO_REQUEST => Cow::Borrowed("Information Request"),
        icmp_type::INFO_REPLY => Cow::Borrowed("Information Reply"),
        icmp_type::ADDRESS_MASK_REQUEST => Cow::Borrowed("Address Mask Request"),
        icmp_type::ADDRESS_MASK_REPLY => Cow::Borrowed("Address Mask Reply"),
        30 => Cow::Borrowed("Traceroute"),
        31 => Cow::Borrowed("Datagram Conversion Error"),
        32 => Cow::Borrowed("Mobile Host Redirect"),
        33 => Cow::Borrowed("IPv6 Where-Are-You"),
        34 => Cow::Borrowed("IPv6 I-Am-Here"),
        35 => Cow::Borrowed("Mobile Registration Request"),
        36 => Cow::Borrowed("Mobile Registration Reply"),
        37 => Cow::Borrowed("Domain Name Request"),
        38 => Cow::Borrowed("Domain Name Reply"),
        39 => Cow::Borrowed("SKIP"),
        40 => Cow::Borrowed("Photuris"),
        41 => Cow::Borrowed("ICMP for Seamoby"),
        42 => Cow::Borrowed("Extended Echo Request"),
        43 => Cow::Borrowed("Extended Echo Reply"),
        _ => Cow::Owned(format!("Type {t}")),
    }
}

/// Convert ICMPv6 type to human-readable name.
pub fn icmpv6_type_name(t: u8) -> Cow<'static, str> {
    match t {
        // Error messages (0-127)
        icmpv6_type::DESTINATION_UNREACHABLE => Cow::Borrowed("Destination Unreachable"),
        icmpv6_type::PACKET_TOO_BIG => Cow::Borrowed("Packet Too Big"),
        icmpv6_type::TIME_EXCEEDED => Cow::Borrowed("Time Exceeded"),
        icmpv6_type::PARAMETER_PROBLEM => Cow::Borrowed("Parameter Problem"),
        100 => Cow::Borrowed("Private Experimentation"),
        101 => Cow::Borrowed("Private Experimentation"),
        127 => Cow::Borrowed("Reserved for Expansion"),

        // Informational messages (128-255)
        icmpv6_type::ECHO_REQUEST => Cow::Borrowed("Echo Request"),
        icmpv6_type::ECHO_REPLY => Cow::Borrowed("Echo Reply"),
        icmpv6_type::MLD_QUERY => Cow::Borrowed("Multicast Listener Query"),
        icmpv6_type::MLDV1_REPORT => Cow::Borrowed("Multicast Listener Report"),
        icmpv6_type::MLDV1_DONE => Cow::Borrowed("Multicast Listener Done"),
        icmpv6_type::ROUTER_SOLICITATION => Cow::Borrowed("Router Solicitation"),
        icmpv6_type::ROUTER_ADVERTISEMENT => Cow::Borrowed("Router Advertisement"),
        icmpv6_type::NEIGHBOR_SOLICITATION => Cow::Borrowed("Neighbor Solicitation"),
        icmpv6_type::NEIGHBOR_ADVERTISEMENT => Cow::Borrowed("Neighbor Advertisement"),
        icmpv6_type::REDIRECT => Cow::Borrowed("Redirect"),
        138 => Cow::Borrowed("Router Renumbering"),
        139 => Cow::Borrowed("ICMP Node Information Query"),
        140 => Cow::Borrowed("ICMP Node Information Response"),
        141 => Cow::Borrowed("Inverse Neighbor Discovery Solicitation"),
        142 => Cow::Borrowed("Inverse Neighbor Discovery Advertisement"),
        icmpv6_type::MLDV2_REPORT => Cow::Borrowed("MLDv2 Multicast Listener Report"),
        144 => Cow::Borrowed("Home Agent Address Discovery Request"),
        145 => Cow::Borrowed("Home Agent Address Discovery Reply"),
        146 => Cow::Borrowed("Mobile Prefix Solicitation"),
        147 => Cow::Borrowed("Mobile Prefix Advertisement"),
        148 => Cow::Borrowed("Certification Path Solicitation"),
        149 => Cow::Borrowed("Certification Path Advertisement"),
        150 => Cow::Borrowed("ICMP Experimental"),
        151 => Cow::Borrowed("Multicast Router Advertisement"),
        152 => Cow::Borrowed("Multicast Router Solicitation"),
        153 => Cow::Borrowed("Multicast Router Termination"),
        154 => Cow::Borrowed("FMIPv6"),
        155 => Cow::Borrowed("RPL Control"),
        156 => Cow::Borrowed("ILNPv6 Locator Update"),
        157 => Cow::Borrowed("Duplicate Address Request"),
        158 => Cow::Borrowed("Duplicate Address Confirmation"),
        159 => Cow::Borrowed("MPL Control"),
        160 => Cow::Borrowed("Extended Echo Request"),
        161 => Cow::Borrowed("Extended Echo Reply"),
        200 => Cow::Borrowed("Private Experimentation"),
        201 => Cow::Borrowed("Private Experimentation"),
        255 => Cow::Borrowed("Reserved for Expansion"),

        _ => Cow::Owned(format!("Type {t}")),
    }
}

/// Convert ICMP type+code to human-readable name.
pub fn icmp_code_name(t: u8, code: u8) -> Cow<'static, str> {
    match t {
        // Destination Unreachable
        icmp_type::DESTINATION_UNREACHABLE => match code {
            dest_unreachable_code::NET_UNREACHABLE => Cow::Borrowed("Network Unreachable"),
            dest_unreachable_code::HOST_UNREACHABLE => Cow::Borrowed("Host Unreachable"),
            dest_unreachable_code::PROTOCOL_UNREACHABLE => Cow::Borrowed("Protocol Unreachable"),
            dest_unreachable_code::PORT_UNREACHABLE => Cow::Borrowed("Port Unreachable"),
            dest_unreachable_code::FRAGMENTATION_NEEDED => Cow::Borrowed("Fragmentation Needed"),
            dest_unreachable_code::SOURCE_ROUTE_FAILED => Cow::Borrowed("Source Route Failed"),
            dest_unreachable_code::DEST_NET_UNKNOWN => Cow::Borrowed("Destination Network Unknown"),
            dest_unreachable_code::DEST_HOST_UNKNOWN => Cow::Borrowed("Destination Host Unknown"),
            dest_unreachable_code::SOURCE_HOST_ISOLATED => Cow::Borrowed("Source Host Isolated"),
            dest_unreachable_code::NET_ADMIN_PROHIBITED => {
                Cow::Borrowed("Network Administratively Prohibited")
            }
            dest_unreachable_code::HOST_ADMIN_PROHIBITED => {
                Cow::Borrowed("Host Administratively Prohibited")
            }
            dest_unreachable_code::NET_TOS_UNREACHABLE => {
                Cow::Borrowed("Network Unreachable for TOS")
            }
            dest_unreachable_code::HOST_TOS_UNREACHABLE => {
                Cow::Borrowed("Host Unreachable for TOS")
            }
            dest_unreachable_code::COMM_ADMIN_PROHIBITED => {
                Cow::Borrowed("Communication Administratively Prohibited")
            }
            dest_unreachable_code::HOST_PRECEDENCE_VIOLATION => {
                Cow::Borrowed("Host Precedence Violation")
            }
            dest_unreachable_code::PRECEDENCE_CUTOFF => {
                Cow::Borrowed("Precedence Cutoff in Effect")
            }
            _ => Cow::Owned(format!("Destination Unreachable (code {code})")),
        },
        // Redirect
        icmp_type::REDIRECT => match code {
            redirect_code::REDIRECT_NET => Cow::Borrowed("Redirect for Network"),
            redirect_code::REDIRECT_HOST => Cow::Borrowed("Redirect for Host"),
            redirect_code::REDIRECT_TOS_NET => Cow::Borrowed("Redirect for TOS and Network"),
            redirect_code::REDIRECT_TOS_HOST => Cow::Borrowed("Redirect for TOS and Host"),
            _ => Cow::Owned(format!("Redirect (code {code})")),
        },
        // Time Exceeded
        icmp_type::TIME_EXCEEDED => match code {
            time_exceeded_code::TTL_EXCEEDED => Cow::Borrowed("TTL Exceeded in Transit"),
            time_exceeded_code::FRAGMENT_REASSEMBLY_EXCEEDED => {
                Cow::Borrowed("Fragment Reassembly Time Exceeded")
            }
            _ => Cow::Owned(format!("Time Exceeded (code {code})")),
        },
        // Parameter Problem
        icmp_type::PARAMETER_PROBLEM => match code {
            parameter_problem_code::POINTER_ERROR => Cow::Borrowed("Pointer Indicates Error"),
            parameter_problem_code::MISSING_REQUIRED_OPTION => {
                Cow::Borrowed("Missing Required Option")
            }
            parameter_problem_code::BAD_LENGTH => Cow::Borrowed("Bad Length"),
            _ => Cow::Owned(format!("Parameter Problem (code {code})")),
        },
        // Echo Reply and Echo Request have code 0
        icmp_type::ECHO_REPLY | icmp_type::ECHO_REQUEST => {
            if code == 0 {
                Cow::Borrowed("No Code")
            } else {
                Cow::Owned(format!("Code {code}"))
            }
        }
        // Other types
        _ => {
            if code == 0 {
                Cow::Borrowed("No Code")
            } else {
                Cow::Owned(format!("Code {code}"))
            }
        }
    }
}

/// Convert ICMPv6 type+code to human-readable name.
pub fn icmpv6_code_name(t: u8, code: u8) -> Cow<'static, str> {
    match t {
        // Destination Unreachable
        icmpv6_type::DESTINATION_UNREACHABLE => match code {
            icmpv6_dest_unreachable_code::NO_ROUTE => Cow::Borrowed("No Route to Destination"),
            icmpv6_dest_unreachable_code::ADMIN_PROHIBITED => {
                Cow::Borrowed("Administratively Prohibited")
            }
            icmpv6_dest_unreachable_code::BEYOND_SCOPE => {
                Cow::Borrowed("Beyond Scope of Source Address")
            }
            icmpv6_dest_unreachable_code::ADDRESS_UNREACHABLE => {
                Cow::Borrowed("Address Unreachable")
            }
            icmpv6_dest_unreachable_code::PORT_UNREACHABLE => Cow::Borrowed("Port Unreachable"),
            icmpv6_dest_unreachable_code::FAILED_POLICY => {
                Cow::Borrowed("Source Address Failed Ingress/Egress Policy")
            }
            icmpv6_dest_unreachable_code::REJECT_ROUTE => {
                Cow::Borrowed("Reject Route to Destination")
            }
            icmpv6_dest_unreachable_code::SOURCE_ROUTING_ERROR => {
                Cow::Borrowed("Error in Source Routing Header")
            }
            _ => Cow::Owned(format!("Destination Unreachable (code {code})")),
        },
        // Packet Too Big
        icmpv6_type::PACKET_TOO_BIG => Cow::Borrowed("Packet Too Big"),
        // Time Exceeded
        icmpv6_type::TIME_EXCEEDED => match code {
            icmpv6_time_exceeded_code::HOP_LIMIT_EXCEEDED => {
                Cow::Borrowed("Hop Limit Exceeded in Transit")
            }
            icmpv6_time_exceeded_code::FRAGMENT_REASSEMBLY_EXCEEDED => {
                Cow::Borrowed("Fragment Reassembly Time Exceeded")
            }
            _ => Cow::Owned(format!("Time Exceeded (code {code})")),
        },
        // Parameter Problem
        icmpv6_type::PARAMETER_PROBLEM => match code {
            icmpv6_parameter_problem_code::ERRONEOUS_HEADER => {
                Cow::Borrowed("Erroneous Header Field")
            }
            icmpv6_parameter_problem_code::UNRECOGNIZED_NEXT_HEADER => {
                Cow::Borrowed("Unrecognized Next Header")
            }
            icmpv6_parameter_problem_code::UNRECOGNIZED_OPTION => {
                Cow::Borrowed("Unrecognized IPv6 Option")
            }
            _ => Cow::Owned(format!("Parameter Problem (code {code})")),
        },
        // Echo Request/Reply
        icmpv6_type::ECHO_REQUEST | icmpv6_type::ECHO_REPLY => {
            if code == 0 {
                Cow::Borrowed("No Code")
            } else {
                Cow::Owned(format!("Code {code}"))
            }
        }
        // Router Renumbering (type 138)
        138 => match code {
            0 => Cow::Borrowed("Router Renumbering Command"),
            1 => Cow::Borrowed("Router Renumbering Result"),
            255 => Cow::Borrowed("Sequence Number Reset"),
            _ => Cow::Owned(format!("Router Renumbering (code {code})")),
        },
        // Node Information Query (type 139)
        139 => match code {
            0 => Cow::Borrowed("NI Query for IPv6 Address"),
            1 => Cow::Borrowed("NI Query for Name or Empty"),
            2 => Cow::Borrowed("NI Query for IPv4 Address"),
            _ => Cow::Owned(format!("NI Query (code {code})")),
        },
        // Node Information Response (type 140)
        140 => match code {
            0 => Cow::Borrowed("NI Response Success"),
            1 => Cow::Borrowed("NI Responder Refuses"),
            2 => Cow::Borrowed("NI Unknown Query Type"),
            _ => Cow::Owned(format!("NI Response (code {code})")),
        },
        // Other types
        _ => {
            if code == 0 {
                Cow::Borrowed("No Code")
            } else {
                Cow::Owned(format!("Code {code}"))
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
            "MLDv2 Multicast Listener Report"
        );
    }
}
