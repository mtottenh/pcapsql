//! IP protocol, EtherType, DSCP and ECN names.

use std::borrow::Cow;

use crate::protocol::{dscp, ecn, ethertype};

/// Convert IP protocol number to name.
pub fn ip_proto_name(proto: u8) -> Cow<'static, str> {
    match proto {
        0 => Cow::Borrowed("HOPOPT"),
        1 => Cow::Borrowed("ICMP"),
        2 => Cow::Borrowed("IGMP"),
        3 => Cow::Borrowed("GGP"),
        4 => Cow::Borrowed("IPv4"),
        5 => Cow::Borrowed("ST"),
        6 => Cow::Borrowed("TCP"),
        7 => Cow::Borrowed("CBT"),
        8 => Cow::Borrowed("EGP"),
        9 => Cow::Borrowed("IGP"),
        10 => Cow::Borrowed("BBN-RCC-MON"),
        11 => Cow::Borrowed("NVP-II"),
        12 => Cow::Borrowed("PUP"),
        13 => Cow::Borrowed("ARGUS"),
        14 => Cow::Borrowed("EMCON"),
        15 => Cow::Borrowed("XNET"),
        16 => Cow::Borrowed("CHAOS"),
        17 => Cow::Borrowed("UDP"),
        18 => Cow::Borrowed("MUX"),
        19 => Cow::Borrowed("DCN-MEAS"),
        20 => Cow::Borrowed("HMP"),
        21 => Cow::Borrowed("PRM"),
        22 => Cow::Borrowed("XNS-IDP"),
        23 => Cow::Borrowed("TRUNK-1"),
        24 => Cow::Borrowed("TRUNK-2"),
        25 => Cow::Borrowed("LEAF-1"),
        26 => Cow::Borrowed("LEAF-2"),
        27 => Cow::Borrowed("RDP"),
        28 => Cow::Borrowed("IRTP"),
        29 => Cow::Borrowed("ISO-TP4"),
        30 => Cow::Borrowed("NETBLT"),
        31 => Cow::Borrowed("MFE-NSP"),
        32 => Cow::Borrowed("MERIT-INP"),
        33 => Cow::Borrowed("DCCP"),
        34 => Cow::Borrowed("3PC"),
        35 => Cow::Borrowed("IDPR"),
        36 => Cow::Borrowed("XTP"),
        37 => Cow::Borrowed("DDP"),
        38 => Cow::Borrowed("IDPR-CMTP"),
        39 => Cow::Borrowed("TP++"),
        40 => Cow::Borrowed("IL"),
        41 => Cow::Borrowed("IPv6"),
        42 => Cow::Borrowed("SDRP"),
        43 => Cow::Borrowed("IPv6-Route"),
        44 => Cow::Borrowed("IPv6-Frag"),
        45 => Cow::Borrowed("IDRP"),
        46 => Cow::Borrowed("RSVP"),
        47 => Cow::Borrowed("GRE"),
        48 => Cow::Borrowed("DSR"),
        49 => Cow::Borrowed("BNA"),
        50 => Cow::Borrowed("ESP"),
        51 => Cow::Borrowed("AH"),
        52 => Cow::Borrowed("I-NLSP"),
        53 => Cow::Borrowed("SWIPE"),
        54 => Cow::Borrowed("NARP"),
        55 => Cow::Borrowed("MOBILE"),
        56 => Cow::Borrowed("TLSP"),
        57 => Cow::Borrowed("SKIP"),
        58 => Cow::Borrowed("ICMPv6"),
        59 => Cow::Borrowed("IPv6-NoNxt"),
        60 => Cow::Borrowed("IPv6-Opts"),
        62 => Cow::Borrowed("CFTP"),
        64 => Cow::Borrowed("SAT-EXPAK"),
        65 => Cow::Borrowed("KRYPTOLAN"),
        66 => Cow::Borrowed("RVD"),
        67 => Cow::Borrowed("IPPC"),
        69 => Cow::Borrowed("SAT-MON"),
        70 => Cow::Borrowed("VISA"),
        71 => Cow::Borrowed("IPCV"),
        72 => Cow::Borrowed("CPNX"),
        73 => Cow::Borrowed("CPHB"),
        74 => Cow::Borrowed("WSN"),
        75 => Cow::Borrowed("PVP"),
        76 => Cow::Borrowed("BR-SAT-MON"),
        77 => Cow::Borrowed("SUN-ND"),
        78 => Cow::Borrowed("WB-MON"),
        79 => Cow::Borrowed("WB-EXPAK"),
        80 => Cow::Borrowed("ISO-IP"),
        81 => Cow::Borrowed("VMTP"),
        82 => Cow::Borrowed("SECURE-VMTP"),
        83 => Cow::Borrowed("VINES"),
        84 => Cow::Borrowed("TTP/IPTM"),
        85 => Cow::Borrowed("NSFNET-IGP"),
        86 => Cow::Borrowed("DGP"),
        87 => Cow::Borrowed("TCF"),
        88 => Cow::Borrowed("EIGRP"),
        89 => Cow::Borrowed("OSPF"),
        90 => Cow::Borrowed("Sprite-RPC"),
        91 => Cow::Borrowed("LARP"),
        92 => Cow::Borrowed("MTP"),
        93 => Cow::Borrowed("AX.25"),
        94 => Cow::Borrowed("IPIP"),
        95 => Cow::Borrowed("MICP"),
        96 => Cow::Borrowed("SCC-SP"),
        97 => Cow::Borrowed("ETHERIP"),
        98 => Cow::Borrowed("ENCAP"),
        100 => Cow::Borrowed("GMTP"),
        101 => Cow::Borrowed("IFMP"),
        102 => Cow::Borrowed("PNNI"),
        103 => Cow::Borrowed("PIM"),
        104 => Cow::Borrowed("ARIS"),
        105 => Cow::Borrowed("SCPS"),
        106 => Cow::Borrowed("QNX"),
        107 => Cow::Borrowed("A/N"),
        108 => Cow::Borrowed("IPComp"),
        109 => Cow::Borrowed("SNP"),
        110 => Cow::Borrowed("Compaq-Peer"),
        111 => Cow::Borrowed("IPX-in-IP"),
        112 => Cow::Borrowed("VRRP"),
        113 => Cow::Borrowed("PGM"),
        115 => Cow::Borrowed("L2TP"),
        116 => Cow::Borrowed("DDX"),
        117 => Cow::Borrowed("IATP"),
        118 => Cow::Borrowed("STP"),
        119 => Cow::Borrowed("SRP"),
        120 => Cow::Borrowed("UTI"),
        121 => Cow::Borrowed("SMP"),
        122 => Cow::Borrowed("SM"),
        123 => Cow::Borrowed("PTP"),
        124 => Cow::Borrowed("ISIS"),
        125 => Cow::Borrowed("FIRE"),
        126 => Cow::Borrowed("CRTP"),
        127 => Cow::Borrowed("CRUDP"),
        128 => Cow::Borrowed("SSCOPMCE"),
        129 => Cow::Borrowed("IPLT"),
        130 => Cow::Borrowed("SPS"),
        131 => Cow::Borrowed("PIPE"),
        132 => Cow::Borrowed("SCTP"),
        133 => Cow::Borrowed("FC"),
        134 => Cow::Borrowed("RSVP-E2E-IGNORE"),
        135 => Cow::Borrowed("Mobility"),
        136 => Cow::Borrowed("UDPLite"),
        137 => Cow::Borrowed("MPLS-in-IP"),
        138 => Cow::Borrowed("manet"),
        139 => Cow::Borrowed("HIP"),
        140 => Cow::Borrowed("Shim6"),
        141 => Cow::Borrowed("WESP"),
        142 => Cow::Borrowed("ROHC"),
        143 => Cow::Borrowed("Ethernet"),
        253 => Cow::Borrowed("Experimentation"),
        254 => Cow::Borrowed("Experimentation"),
        _ => Cow::Owned(format!("Proto {proto}")),
    }
}

/// Convert EtherType to name.
pub fn ethertype_name(etype: u16) -> Cow<'static, str> {
    match etype {
        ethertype::IPV4 => Cow::Borrowed("IPv4"),
        ethertype::ARP => Cow::Borrowed("ARP"),
        ethertype::WAKE_ON_LAN => Cow::Borrowed("Wake-on-LAN"),
        ethertype::AVTP => Cow::Borrowed("AVTP"),
        ethertype::TRILL => Cow::Borrowed("IETF TRILL"),
        ethertype::SRP => Cow::Borrowed("SRP"),
        ethertype::DEC_MOP_RC => Cow::Borrowed("DEC MOP RC"),
        ethertype::DECNET => Cow::Borrowed("DECnet"),
        ethertype::DEC_LAT => Cow::Borrowed("DEC LAT"),
        ethertype::RARP => Cow::Borrowed("RARP"),
        ethertype::APPLETALK => Cow::Borrowed("AppleTalk"),
        ethertype::AARP => Cow::Borrowed("AARP"),
        ethertype::VLAN => Cow::Borrowed("VLAN"),
        ethertype::SLPP => Cow::Borrowed("SLPP"),
        ethertype::VLACP => Cow::Borrowed("VLACP"),
        ethertype::IPX => Cow::Borrowed("IPX"),
        ethertype::QNX_QNET => Cow::Borrowed("QNX Qnet"),
        ethertype::IPV6 => Cow::Borrowed("IPv6"),
        ethertype::FLOW_CONTROL => Cow::Borrowed("Flow Control"),
        ethertype::LACP => Cow::Borrowed("LACP"),
        ethertype::COBRANET => Cow::Borrowed("CobraNet"),
        ethertype::MPLS => Cow::Borrowed("MPLS"),
        ethertype::MPLS_MULTICAST => Cow::Borrowed("MPLS Multicast"),
        ethertype::PPPOE_DISCOVERY => Cow::Borrowed("PPPoE Discovery"),
        ethertype::PPPOE_SESSION => Cow::Borrowed("PPPoE Session"),
        ethertype::HOMEPLUG_MME => Cow::Borrowed("HomePlug 1.0 MME"),
        ethertype::EAP_OVER_LAN => Cow::Borrowed("EAP over LAN"),
        ethertype::PROFINET => Cow::Borrowed("PROFINET"),
        ethertype::HYPERSCSI => Cow::Borrowed("HyperSCSI"),
        ethertype::ATA_OVER_ETHERNET => Cow::Borrowed("ATA over Ethernet"),
        ethertype::ETHERCAT => Cow::Borrowed("EtherCAT"),
        ethertype::QINQ => Cow::Borrowed("QinQ"),
        ethertype::POWERLINK => Cow::Borrowed("Powerlink"),
        ethertype::GOOSE => Cow::Borrowed("GOOSE"),
        ethertype::GSE => Cow::Borrowed("GSE"),
        ethertype::SV => Cow::Borrowed("SV"),
        ethertype::MIKROTIK_ROMON => Cow::Borrowed("MikroTik RoMON"),
        ethertype::LLDP => Cow::Borrowed("LLDP"),
        ethertype::SERCOS_III => Cow::Borrowed("SERCOS III"),
        ethertype::WSMP => Cow::Borrowed("WSMP"),
        ethertype::HOMEPLUG_AV_MME => Cow::Borrowed("HomePlug AV MME"),
        ethertype::MRP => Cow::Borrowed("MRP"),
        ethertype::MACSEC => Cow::Borrowed("MACsec"),
        ethertype::PBB => Cow::Borrowed("PBB"),
        ethertype::PTP => Cow::Borrowed("PTP"),
        ethertype::NC_SI => Cow::Borrowed("NC-SI"),
        ethertype::PRP => Cow::Borrowed("PRP"),
        ethertype::CFM_OAM => Cow::Borrowed("CFM/OAM"),
        ethertype::FCOE => Cow::Borrowed("FCoE"),
        ethertype::FCOE_INIT => Cow::Borrowed("FCoE Init"),
        ethertype::ROCE => Cow::Borrowed("RoCE"),
        ethertype::TTE => Cow::Borrowed("TTE"),
        ethertype::HSR => Cow::Borrowed("HSR"),
        ethertype::ECTP => Cow::Borrowed("ECTP"),
        ethertype::QINQ_OLD => Cow::Borrowed("QinQ (old)"),
        ethertype::VERITAS_LLT => Cow::Borrowed("Veritas LLT"),
        _ => Cow::Owned(format!("0x{etype:04X}")),
    }
}

/// Convert DSCP (Differentiated Services Code Point) value to name per RFC 2474/4594.
///
/// Only the low six bits are looked at. A value with no standard name gives
/// `DSCP{n}`.
pub fn dscp_name(value: u8) -> Cow<'static, str> {
    // `dscp::to_name` returns an empty string for a value it does not know.
    let name = dscp::to_name(value);
    if name.is_empty() {
        Cow::Owned(format!("DSCP{}", value & 0x3F))
    } else {
        Cow::Borrowed(name)
    }
}

/// Convert ECN (Explicit Congestion Notification) value to name per RFC 3168.
///
/// Only the low two bits are looked at, so every input has a name.
pub fn ecn_name(value: u8) -> &'static str {
    ecn::to_name(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_proto_name() {
        assert_eq!(ip_proto_name(1), "ICMP");
        assert_eq!(ip_proto_name(2), "IGMP");
        assert_eq!(ip_proto_name(6), "TCP");
        assert_eq!(ip_proto_name(17), "UDP");
        assert_eq!(ip_proto_name(41), "IPv6");
        assert_eq!(ip_proto_name(47), "GRE");
        assert_eq!(ip_proto_name(50), "ESP");
        assert_eq!(ip_proto_name(51), "AH");
        assert_eq!(ip_proto_name(58), "ICMPv6");
        assert_eq!(ip_proto_name(89), "OSPF");
        assert_eq!(ip_proto_name(132), "SCTP");
        // Unknown protocol
        assert_eq!(ip_proto_name(200), "Proto 200");
    }

    #[test]
    fn test_ethertype_name() {
        assert_eq!(ethertype_name(0x0800), "IPv4");
        assert_eq!(ethertype_name(0x0806), "ARP");
        assert_eq!(ethertype_name(0x8100), "VLAN");
        assert_eq!(ethertype_name(0x86DD), "IPv6");
        assert_eq!(ethertype_name(0x8847), "MPLS");
        assert_eq!(ethertype_name(0x8848), "MPLS Multicast");
        assert_eq!(ethertype_name(0x88A8), "QinQ");
        assert_eq!(ethertype_name(0x88CC), "LLDP");
        assert_eq!(ethertype_name(0x88E5), "MACsec");
        // Unknown ethertype
        assert_eq!(ethertype_name(0x1234), "0x1234");
    }

    #[test]
    fn test_common_protocols() {
        // Most commonly seen protocols
        assert_eq!(ip_proto_name(1), "ICMP");
        assert_eq!(ip_proto_name(6), "TCP");
        assert_eq!(ip_proto_name(17), "UDP");
        assert_eq!(ip_proto_name(58), "ICMPv6");
    }

    #[test]
    fn test_common_ethertypes() {
        // Most commonly seen ethertypes
        assert_eq!(ethertype_name(0x0800), "IPv4");
        assert_eq!(ethertype_name(0x86DD), "IPv6");
        assert_eq!(ethertype_name(0x0806), "ARP");
        assert_eq!(ethertype_name(0x8100), "VLAN");
    }

    #[test]
    fn test_dscp_class_selector() {
        // Class Selector values using constants from pcapsql-core
        assert_eq!(dscp_name(dscp::CS0), "CS0/BE");
        assert_eq!(dscp_name(dscp::CS1), "CS1");
        assert_eq!(dscp_name(dscp::CS2), "CS2");
        assert_eq!(dscp_name(dscp::CS3), "CS3");
        assert_eq!(dscp_name(dscp::CS4), "CS4");
        assert_eq!(dscp_name(dscp::CS5), "CS5");
        assert_eq!(dscp_name(dscp::CS6), "CS6");
        assert_eq!(dscp_name(dscp::CS7), "CS7");
    }

    #[test]
    fn test_dscp_assured_forwarding() {
        // Assured Forwarding values using constants from pcapsql-core
        assert_eq!(dscp_name(dscp::AF11), "AF11");
        assert_eq!(dscp_name(dscp::AF12), "AF12");
        assert_eq!(dscp_name(dscp::AF13), "AF13");
        assert_eq!(dscp_name(dscp::AF21), "AF21");
        assert_eq!(dscp_name(dscp::AF22), "AF22");
        assert_eq!(dscp_name(dscp::AF23), "AF23");
        assert_eq!(dscp_name(dscp::AF31), "AF31");
        assert_eq!(dscp_name(dscp::AF32), "AF32");
        assert_eq!(dscp_name(dscp::AF33), "AF33");
        assert_eq!(dscp_name(dscp::AF41), "AF41");
        assert_eq!(dscp_name(dscp::AF42), "AF42");
        assert_eq!(dscp_name(dscp::AF43), "AF43");
    }

    #[test]
    fn test_dscp_special_values() {
        // Special PHBs using constants from pcapsql-core
        assert_eq!(dscp_name(dscp::EF), "EF");
        assert_eq!(dscp_name(dscp::VA), "VA");
        assert_eq!(dscp_name(dscp::LE), "LE");
        // Unknown value
        assert_eq!(dscp_name(2), "DSCP2");
        assert_eq!(dscp_name(63), "DSCP63");
    }

    #[test]
    fn test_ecn_values() {
        // ECN values using constants from pcapsql-core
        assert_eq!(ecn_name(ecn::NOT_ECT), "Not-ECT");
        assert_eq!(ecn_name(ecn::ECT1), "ECT(1)");
        assert_eq!(ecn_name(ecn::ECT0), "ECT(0)");
        assert_eq!(ecn_name(ecn::CE), "CE");
        // Values should be masked to 2 bits
        assert_eq!(ecn_name(4), "Not-ECT"); // 100 & 11 = 00
        assert_eq!(ecn_name(7), "CE"); // 111 & 11 = 11
    }
}
