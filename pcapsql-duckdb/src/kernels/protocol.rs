//! Protocol names and TCP flag helpers.

use pcapsql_core::protocol::{ethertype, rcode, record_type};

/// Format TCP flags as a comma-separated string.
pub fn format_tcp_flags(flags: u16) -> String {
    let mut result = Vec::new();

    if flags & 0x001 != 0 {
        result.push("FIN");
    }
    if flags & 0x002 != 0 {
        result.push("SYN");
    }
    if flags & 0x004 != 0 {
        result.push("RST");
    }
    if flags & 0x008 != 0 {
        result.push("PSH");
    }
    if flags & 0x010 != 0 {
        result.push("ACK");
    }
    if flags & 0x020 != 0 {
        result.push("URG");
    }
    if flags & 0x040 != 0 {
        result.push("ECE");
    }
    if flags & 0x080 != 0 {
        result.push("CWR");
    }
    if flags & 0x100 != 0 {
        result.push("NS");
    }

    if result.is_empty() {
        "NONE".to_string()
    } else {
        result.join(",")
    }
}

/// Check if a specific TCP flag is set.
pub fn check_tcp_flag(flags: u16, name: &str) -> bool {
    let mask = match name.to_uppercase().as_str() {
        "FIN" => 0x001,
        "SYN" => 0x002,
        "RST" => 0x004,
        "PSH" => 0x008,
        "ACK" => 0x010,
        "URG" => 0x020,
        "ECE" => 0x040,
        "CWR" => 0x080,
        "NS" => 0x100,
        _ => return false,
    };
    flags & mask != 0
}

/// Convert DNS type to string.
pub fn dns_type_to_string(qtype: u16) -> String {
    match qtype {
        record_type::A => "A".to_string(),
        record_type::NS => "NS".to_string(),
        record_type::CNAME => "CNAME".to_string(),
        record_type::SOA => "SOA".to_string(),
        record_type::PTR => "PTR".to_string(),
        record_type::MX => "MX".to_string(),
        record_type::TXT => "TXT".to_string(),
        record_type::AAAA => "AAAA".to_string(),
        record_type::SRV => "SRV".to_string(),
        35 => "NAPTR".to_string(),
        record_type::OPT => "OPT".to_string(),
        43 => "DS".to_string(),
        46 => "RRSIG".to_string(),
        47 => "NSEC".to_string(),
        48 => "DNSKEY".to_string(),
        52 => "TLSA".to_string(),
        65 => "HTTPS".to_string(),
        record_type::ANY => "ANY".to_string(),
        256 => "URI".to_string(),
        257 => "CAA".to_string(),
        _ => format!("TYPE{qtype}"),
    }
}

/// Convert DNS rcode to string.
pub fn dns_rcode_to_string(rcode_val: u16) -> String {
    match rcode_val as u8 {
        rcode::NOERROR => "NOERROR".to_string(),
        rcode::FORMERR => "FORMERR".to_string(),
        rcode::SERVFAIL => "SERVFAIL".to_string(),
        rcode::NXDOMAIN => "NXDOMAIN".to_string(),
        rcode::NOTIMP => "NOTIMP".to_string(),
        rcode::REFUSED => "REFUSED".to_string(),
        rcode::YXDOMAIN => "YXDOMAIN".to_string(),
        rcode::YXRRSET => "YXRRSET".to_string(),
        rcode::NXRRSET => "NXRRSET".to_string(),
        rcode::NOTAUTH => "NOTAUTH".to_string(),
        rcode::NOTZONE => "NOTZONE".to_string(),
        rcode::DSOTYPENI => "DSOTYPENI".to_string(),
        rcode::BADVERS => "BADVERS".to_string(),
        rcode::BADKEY => "BADKEY".to_string(),
        rcode::BADTIME => "BADTIME".to_string(),
        rcode::BADMODE => "BADMODE".to_string(),
        rcode::BADNAME => "BADNAME".to_string(),
        rcode::BADALG => "BADALG".to_string(),
        rcode::BADTRUNC => "BADTRUNC".to_string(),
        rcode::BADCOOKIE => "BADCOOKIE".to_string(),
        _ => format!("RCODE{rcode_val}"),
    }
}

/// Convert IP protocol number to string.
pub fn ip_proto_to_string(proto: u8) -> String {
    match proto {
        1 => "ICMP".to_string(),
        2 => "IGMP".to_string(),
        6 => "TCP".to_string(),
        17 => "UDP".to_string(),
        41 => "IPv6".to_string(),
        47 => "GRE".to_string(),
        50 => "ESP".to_string(),
        51 => "AH".to_string(),
        58 => "ICMPv6".to_string(),
        89 => "OSPF".to_string(),
        132 => "SCTP".to_string(),
        _ => format!("PROTO{proto}"),
    }
}

/// Convert EtherType to string.
pub fn ethertype_to_string(etype: u16) -> String {
    match etype {
        // Common protocols
        ethertype::IPV4 => "IPv4".to_string(),
        ethertype::ARP => "ARP".to_string(),
        ethertype::WAKE_ON_LAN => "Wake-on-LAN".to_string(),
        ethertype::RARP => "RARP".to_string(),
        ethertype::VLAN => "VLAN".to_string(),
        ethertype::IPV6 => "IPv6".to_string(),
        ethertype::QINQ => "QinQ".to_string(),
        // Streaming/AV protocols
        ethertype::AVTP => "AVTP".to_string(),
        ethertype::SRP => "SRP".to_string(),
        ethertype::TRILL => "TRILL".to_string(),
        // Legacy protocols
        ethertype::DEC_MOP_RC => "DEC-MOP-RC".to_string(),
        ethertype::DECNET => "DECnet".to_string(),
        ethertype::DEC_LAT => "DEC-LAT".to_string(),
        ethertype::APPLETALK => "AppleTalk".to_string(),
        ethertype::AARP => "AARP".to_string(),
        ethertype::IPX => "IPX".to_string(),
        ethertype::QNX_QNET => "QNX-Qnet".to_string(),
        // Link layer protocols
        ethertype::SLPP => "SLPP".to_string(),
        ethertype::VLACP => "VLACP".to_string(),
        ethertype::FLOW_CONTROL => "Flow-Control".to_string(),
        ethertype::LACP => "LACP".to_string(),
        ethertype::LLDP => "LLDP".to_string(),
        // MPLS
        ethertype::MPLS => "MPLS".to_string(),
        ethertype::MPLS_MULTICAST => "MPLS-MC".to_string(),
        // PPPoE
        ethertype::PPPOE_DISCOVERY => "PPPoE-Discovery".to_string(),
        ethertype::PPPOE_SESSION => "PPPoE-Session".to_string(),
        // Industrial protocols
        ethertype::COBRANET => "CobraNet".to_string(),
        ethertype::PROFINET => "PROFINET".to_string(),
        ethertype::HYPERSCSI => "HyperSCSI".to_string(),
        ethertype::ATA_OVER_ETHERNET => "AoE".to_string(),
        ethertype::ETHERCAT => "EtherCAT".to_string(),
        ethertype::POWERLINK => "POWERLINK".to_string(),
        ethertype::GOOSE => "GOOSE".to_string(),
        ethertype::GSE => "GSE".to_string(),
        ethertype::SV => "SV".to_string(),
        ethertype::SERCOS_III => "SERCOS-III".to_string(),
        ethertype::MRP => "MRP".to_string(),
        ethertype::PRP => "PRP".to_string(),
        ethertype::HSR => "HSR".to_string(),
        // Security protocols
        ethertype::EAP_OVER_LAN => "EAPoL".to_string(),
        ethertype::MACSEC => "MACsec".to_string(),
        // Provider bridging
        ethertype::PBB => "PBB".to_string(),
        // Time protocols
        ethertype::PTP => "PTP".to_string(),
        // Network management
        ethertype::HOMEPLUG_MME => "HomePlug-MME".to_string(),
        ethertype::HOMEPLUG_AV_MME => "HomePlug-AV-MME".to_string(),
        ethertype::MIKROTIK_ROMON => "MikroTik-RoMON".to_string(),
        ethertype::NC_SI => "NC-SI".to_string(),
        ethertype::CFM_OAM => "CFM-OAM".to_string(),
        // Storage protocols
        ethertype::FCOE => "FCoE".to_string(),
        ethertype::FCOE_INIT => "FCoE-Init".to_string(),
        ethertype::ROCE => "RoCE".to_string(),
        // Other
        ethertype::WSMP => "WSMP".to_string(),
        ethertype::TTE => "TTE".to_string(),
        ethertype::ECTP => "ECTP".to_string(),
        ethertype::QINQ_OLD => "QinQ-Old".to_string(),
        ethertype::VERITAS_LLT => "Veritas-LLT".to_string(),
        _ => format!("0x{etype:04X}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_flags() {
        assert_eq!(format_tcp_flags(0x002), "SYN");
        assert_eq!(format_tcp_flags(0x012), "SYN,ACK");
        assert_eq!(format_tcp_flags(0x014), "RST,ACK");
        assert_eq!(format_tcp_flags(0x000), "NONE");
    }

    #[test]
    fn test_check_tcp_flag() {
        assert!(check_tcp_flag(0x012, "SYN"));
        assert!(check_tcp_flag(0x012, "ACK"));
        assert!(!check_tcp_flag(0x012, "FIN"));
        assert!(check_tcp_flag(0x012, "syn")); // case insensitive
    }

    #[test]
    fn test_dns_type_name() {
        assert_eq!(dns_type_to_string(1), "A");
        assert_eq!(dns_type_to_string(28), "AAAA");
        assert_eq!(dns_type_to_string(999), "TYPE999");
    }

    #[test]
    fn test_dns_rcode_name() {
        assert_eq!(dns_rcode_to_string(0), "NOERROR");
        assert_eq!(dns_rcode_to_string(3), "NXDOMAIN");
        assert_eq!(dns_rcode_to_string(99), "RCODE99");
    }

    #[test]
    fn test_ip_proto_name() {
        assert_eq!(ip_proto_to_string(6), "TCP");
        assert_eq!(ip_proto_to_string(17), "UDP");
        assert_eq!(ip_proto_to_string(200), "PROTO200");
    }

    #[test]
    fn test_ethertype_name() {
        assert_eq!(ethertype_to_string(ethertype::IPV4), "IPv4");
        assert_eq!(ethertype_to_string(ethertype::IPV6), "IPv6");
        assert_eq!(ethertype_to_string(0x1234), "0x1234");
    }
}
