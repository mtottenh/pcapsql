//! Linux capture names: cooked-capture (SLL) packet types, ARPHRD hardware
//! types, address families, and netlink and rtnetlink message types.

use super::Name;

use netlink_packet_core::{NLMSG_DONE, NLMSG_ERROR, NLMSG_NOOP, NLMSG_OVERRUN};

use crate::protocol::{
    netlink_family as family, rtnetlink_msg_type as rtm, sll_arphrd as arphrd,
    sll_packet_type as packet_type,
};

/// Convert a cooked-capture packet type (`PACKET_*` of `if_packet.h`) to its
/// name; `Unknown (n)` otherwise.
pub fn sll_packet_type_name(pkt_type: u16) -> Name {
    match pkt_type {
        packet_type::HOST => Name::fixed("HOST"),
        packet_type::BROADCAST => Name::fixed("BROADCAST"),
        packet_type::MULTICAST => Name::fixed("MULTICAST"),
        packet_type::OTHERHOST => Name::fixed("OTHERHOST"),
        packet_type::OUTGOING => Name::fixed("OUTGOING"),
        _ => Name::unknown(pkt_type),
    }
}

/// Convert an ARPHRD hardware type (`ARPHRD_*` of `if_arp.h`) to its name;
/// `Unknown (n)` otherwise.
pub fn arphrd_name(hardware: u16) -> Name {
    match hardware {
        arphrd::ETHER => Name::fixed("ETHER"),
        arphrd::LOOPBACK => Name::fixed("LOOPBACK"),
        arphrd::FRAD => Name::fixed("FRAD"),
        arphrd::IPGRE => Name::fixed("IPGRE"),
        arphrd::IEEE80211_RADIOTAP => Name::fixed("IEEE80211_RADIOTAP"),
        arphrd::IP6GRE => Name::fixed("IP6GRE"),
        arphrd::NETLINK => Name::fixed("NETLINK"),
        _ => Name::unknown(hardware),
    }
}

/// Convert a Linux address family (`AF_*`) to the name of its protocol;
/// `Unknown (n)` otherwise.
pub fn address_family_name(af: u8) -> Name {
    match af {
        2 => Name::fixed("IPv4"),  // AF_INET
        10 => Name::fixed("IPv6"), // AF_INET6
        _ => Name::unknown(af),
    }
}

/// Convert a netlink family (`NETLINK_*`) to its name; `Unknown (n)`
/// otherwise.
pub fn netlink_family_name(nl_family: u8) -> Name {
    Name::fixed(match nl_family {
        family::ROUTE => "ROUTE",
        family::USERSOCK => "USERSOCK",
        family::FIREWALL => "FIREWALL",
        family::SOCK_DIAG => "SOCK_DIAG",
        family::NFLOG => "NFLOG",
        family::XFRM => "XFRM",
        family::SELINUX => "SELINUX",
        family::ISCSI => "ISCSI",
        family::AUDIT => "AUDIT",
        family::FIB_LOOKUP => "FIB_LOOKUP",
        family::CONNECTOR => "CONNECTOR",
        family::NETFILTER => "NETFILTER",
        family::IP6_FW => "IP6_FW",
        family::DNRTMSG => "DNRTMSG",
        family::KOBJECT_UEVENT => "KOBJECT_UEVENT",
        family::GENERIC => "GENERIC",
        family::SCSITRANSPORT => "SCSITRANSPORT",
        family::ECRYPTFS => "ECRYPTFS",
        family::RDMA => "RDMA",
        family::CRYPTO => "CRYPTO",
        _ => return Name::unknown(nl_family),
    })
}

/// The name of a netlink control message type (`NLMSG_*`), and
/// `PROTOCOL_SPECIFIC` for every other type: what it means is up to the
/// netlink family.
pub fn netlink_msg_type_name(msg_type: u16) -> &'static str {
    match msg_type {
        NLMSG_NOOP => "NLMSG_NOOP",
        NLMSG_ERROR => "NLMSG_ERROR",
        NLMSG_DONE => "NLMSG_DONE",
        NLMSG_OVERRUN => "NLMSG_OVERRUN",
        _ => "PROTOCOL_SPECIFIC",
    }
}

/// Convert an rtnetlink message type (`RTM_*`) to its name; `Unknown (n)`
/// otherwise.
pub fn rtnetlink_msg_type_name(msg_type: u16) -> Name {
    Name::fixed(match msg_type {
        rtm::RTM_NEWLINK => "RTM_NEWLINK",
        rtm::RTM_DELLINK => "RTM_DELLINK",
        rtm::RTM_GETLINK => "RTM_GETLINK",
        rtm::RTM_SETLINK => "RTM_SETLINK",
        rtm::RTM_NEWADDR => "RTM_NEWADDR",
        rtm::RTM_DELADDR => "RTM_DELADDR",
        rtm::RTM_GETADDR => "RTM_GETADDR",
        rtm::RTM_NEWROUTE => "RTM_NEWROUTE",
        rtm::RTM_DELROUTE => "RTM_DELROUTE",
        rtm::RTM_GETROUTE => "RTM_GETROUTE",
        rtm::RTM_NEWNEIGH => "RTM_NEWNEIGH",
        rtm::RTM_DELNEIGH => "RTM_DELNEIGH",
        rtm::RTM_GETNEIGH => "RTM_GETNEIGH",
        _ => return Name::unknown(msg_type),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sll_names() {
        assert_eq!(sll_packet_type_name(0), "HOST");
        assert_eq!(sll_packet_type_name(4), "OUTGOING");
        assert_eq!(sll_packet_type_name(5), "Unknown (5)");
        assert_eq!(arphrd_name(1), "ETHER");
        assert_eq!(arphrd_name(772), "LOOPBACK");
        assert_eq!(arphrd_name(824), "NETLINK");
        assert_eq!(arphrd_name(2), "Unknown (2)");
    }

    #[test]
    fn test_netlink_names() {
        assert_eq!(netlink_family_name(0), "ROUTE");
        assert_eq!(netlink_family_name(16), "GENERIC");
        assert_eq!(netlink_family_name(200), "Unknown (200)");
        assert_eq!(netlink_msg_type_name(3), "NLMSG_DONE");
        assert_eq!(netlink_msg_type_name(16), "PROTOCOL_SPECIFIC");
        assert_eq!(rtnetlink_msg_type_name(16), "RTM_NEWLINK");
        assert_eq!(rtnetlink_msg_type_name(30), "RTM_GETNEIGH");
        assert_eq!(rtnetlink_msg_type_name(99), "Unknown (99)");
        assert_eq!(address_family_name(2), "IPv4");
        assert_eq!(address_family_name(10), "IPv6");
        assert_eq!(address_family_name(17), "Unknown (17)");
    }
}
