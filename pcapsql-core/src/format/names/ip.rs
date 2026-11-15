//! IP protocol, EtherType, DSCP and ECN names.

use super::Name;

use crate::protocol::{dscp, ecn, ethertype};

/// Convert IP protocol number to name.
pub fn ip_proto_name(proto: u8) -> Name {
    match proto {
        0 => Name::fixed("HOPOPT"),
        1 => Name::fixed("ICMP"),
        2 => Name::fixed("IGMP"),
        3 => Name::fixed("GGP"),
        4 => Name::fixed("IPv4"),
        5 => Name::fixed("ST"),
        6 => Name::fixed("TCP"),
        7 => Name::fixed("CBT"),
        8 => Name::fixed("EGP"),
        9 => Name::fixed("IGP"),
        10 => Name::fixed("BBN-RCC-MON"),
        11 => Name::fixed("NVP-II"),
        12 => Name::fixed("PUP"),
        13 => Name::fixed("ARGUS"),
        14 => Name::fixed("EMCON"),
        15 => Name::fixed("XNET"),
        16 => Name::fixed("CHAOS"),
        17 => Name::fixed("UDP"),
        18 => Name::fixed("MUX"),
        19 => Name::fixed("DCN-MEAS"),
        20 => Name::fixed("HMP"),
        21 => Name::fixed("PRM"),
        22 => Name::fixed("XNS-IDP"),
        23 => Name::fixed("TRUNK-1"),
        24 => Name::fixed("TRUNK-2"),
        25 => Name::fixed("LEAF-1"),
        26 => Name::fixed("LEAF-2"),
        27 => Name::fixed("RDP"),
        28 => Name::fixed("IRTP"),
        29 => Name::fixed("ISO-TP4"),
        30 => Name::fixed("NETBLT"),
        31 => Name::fixed("MFE-NSP"),
        32 => Name::fixed("MERIT-INP"),
        33 => Name::fixed("DCCP"),
        34 => Name::fixed("3PC"),
        35 => Name::fixed("IDPR"),
        36 => Name::fixed("XTP"),
        37 => Name::fixed("DDP"),
        38 => Name::fixed("IDPR-CMTP"),
        39 => Name::fixed("TP++"),
        40 => Name::fixed("IL"),
        41 => Name::fixed("IPv6"),
        42 => Name::fixed("SDRP"),
        43 => Name::fixed("IPv6-Route"),
        44 => Name::fixed("IPv6-Frag"),
        45 => Name::fixed("IDRP"),
        46 => Name::fixed("RSVP"),
        47 => Name::fixed("GRE"),
        48 => Name::fixed("DSR"),
        49 => Name::fixed("BNA"),
        50 => Name::fixed("ESP"),
        51 => Name::fixed("AH"),
        52 => Name::fixed("I-NLSP"),
        53 => Name::fixed("SWIPE"),
        54 => Name::fixed("NARP"),
        55 => Name::fixed("MOBILE"),
        56 => Name::fixed("TLSP"),
        57 => Name::fixed("SKIP"),
        58 => Name::fixed("ICMPv6"),
        59 => Name::fixed("IPv6-NoNxt"),
        60 => Name::fixed("IPv6-Opts"),
        62 => Name::fixed("CFTP"),
        64 => Name::fixed("SAT-EXPAK"),
        65 => Name::fixed("KRYPTOLAN"),
        66 => Name::fixed("RVD"),
        67 => Name::fixed("IPPC"),
        69 => Name::fixed("SAT-MON"),
        70 => Name::fixed("VISA"),
        71 => Name::fixed("IPCV"),
        72 => Name::fixed("CPNX"),
        73 => Name::fixed("CPHB"),
        74 => Name::fixed("WSN"),
        75 => Name::fixed("PVP"),
        76 => Name::fixed("BR-SAT-MON"),
        77 => Name::fixed("SUN-ND"),
        78 => Name::fixed("WB-MON"),
        79 => Name::fixed("WB-EXPAK"),
        80 => Name::fixed("ISO-IP"),
        81 => Name::fixed("VMTP"),
        82 => Name::fixed("SECURE-VMTP"),
        83 => Name::fixed("VINES"),
        84 => Name::fixed("TTP/IPTM"),
        85 => Name::fixed("NSFNET-IGP"),
        86 => Name::fixed("DGP"),
        87 => Name::fixed("TCF"),
        88 => Name::fixed("EIGRP"),
        89 => Name::fixed("OSPF"),
        90 => Name::fixed("Sprite-RPC"),
        91 => Name::fixed("LARP"),
        92 => Name::fixed("MTP"),
        93 => Name::fixed("AX.25"),
        94 => Name::fixed("IPIP"),
        95 => Name::fixed("MICP"),
        96 => Name::fixed("SCC-SP"),
        97 => Name::fixed("ETHERIP"),
        98 => Name::fixed("ENCAP"),
        100 => Name::fixed("GMTP"),
        101 => Name::fixed("IFMP"),
        102 => Name::fixed("PNNI"),
        103 => Name::fixed("PIM"),
        104 => Name::fixed("ARIS"),
        105 => Name::fixed("SCPS"),
        106 => Name::fixed("QNX"),
        107 => Name::fixed("A/N"),
        108 => Name::fixed("IPComp"),
        109 => Name::fixed("SNP"),
        110 => Name::fixed("Compaq-Peer"),
        111 => Name::fixed("IPX-in-IP"),
        112 => Name::fixed("VRRP"),
        113 => Name::fixed("PGM"),
        115 => Name::fixed("L2TP"),
        116 => Name::fixed("DDX"),
        117 => Name::fixed("IATP"),
        118 => Name::fixed("STP"),
        119 => Name::fixed("SRP"),
        120 => Name::fixed("UTI"),
        121 => Name::fixed("SMP"),
        122 => Name::fixed("SM"),
        123 => Name::fixed("PTP"),
        124 => Name::fixed("ISIS"),
        125 => Name::fixed("FIRE"),
        126 => Name::fixed("CRTP"),
        127 => Name::fixed("CRUDP"),
        128 => Name::fixed("SSCOPMCE"),
        129 => Name::fixed("IPLT"),
        130 => Name::fixed("SPS"),
        131 => Name::fixed("PIPE"),
        132 => Name::fixed("SCTP"),
        133 => Name::fixed("FC"),
        134 => Name::fixed("RSVP-E2E-IGNORE"),
        135 => Name::fixed("Mobility"),
        136 => Name::fixed("UDPLite"),
        137 => Name::fixed("MPLS-in-IP"),
        138 => Name::fixed("manet"),
        139 => Name::fixed("HIP"),
        140 => Name::fixed("Shim6"),
        141 => Name::fixed("WESP"),
        142 => Name::fixed("ROHC"),
        143 => Name::fixed("Ethernet"),
        253 => Name::fixed("Experimentation"),
        254 => Name::fixed("Experimentation"),
        _ => Name::numbered("Proto ", proto, ""),
    }
}

/// Convert EtherType to name.
pub fn ethertype_name(etype: u16) -> Name {
    match etype {
        ethertype::IPV4 => Name::fixed("IPv4"),
        ethertype::ARP => Name::fixed("ARP"),
        ethertype::WAKE_ON_LAN => Name::fixed("Wake-on-LAN"),
        ethertype::AVTP => Name::fixed("AVTP"),
        ethertype::TRILL => Name::fixed("IETF TRILL"),
        ethertype::SRP => Name::fixed("SRP"),
        ethertype::DEC_MOP_RC => Name::fixed("DEC MOP RC"),
        ethertype::DECNET => Name::fixed("DECnet"),
        ethertype::DEC_LAT => Name::fixed("DEC LAT"),
        ethertype::RARP => Name::fixed("RARP"),
        ethertype::APPLETALK => Name::fixed("AppleTalk"),
        ethertype::AARP => Name::fixed("AARP"),
        ethertype::VLAN => Name::fixed("VLAN"),
        ethertype::SLPP => Name::fixed("SLPP"),
        ethertype::VLACP => Name::fixed("VLACP"),
        ethertype::IPX => Name::fixed("IPX"),
        ethertype::QNX_QNET => Name::fixed("QNX Qnet"),
        ethertype::IPV6 => Name::fixed("IPv6"),
        ethertype::FLOW_CONTROL => Name::fixed("Flow Control"),
        ethertype::LACP => Name::fixed("LACP"),
        ethertype::COBRANET => Name::fixed("CobraNet"),
        ethertype::MPLS => Name::fixed("MPLS"),
        ethertype::MPLS_MULTICAST => Name::fixed("MPLS Multicast"),
        ethertype::PPPOE_DISCOVERY => Name::fixed("PPPoE Discovery"),
        ethertype::PPPOE_SESSION => Name::fixed("PPPoE Session"),
        ethertype::HOMEPLUG_MME => Name::fixed("HomePlug 1.0 MME"),
        ethertype::EAP_OVER_LAN => Name::fixed("EAP over LAN"),
        ethertype::PROFINET => Name::fixed("PROFINET"),
        ethertype::HYPERSCSI => Name::fixed("HyperSCSI"),
        ethertype::ATA_OVER_ETHERNET => Name::fixed("ATA over Ethernet"),
        ethertype::ETHERCAT => Name::fixed("EtherCAT"),
        ethertype::QINQ => Name::fixed("QinQ"),
        ethertype::POWERLINK => Name::fixed("Powerlink"),
        ethertype::GOOSE => Name::fixed("GOOSE"),
        ethertype::GSE => Name::fixed("GSE"),
        ethertype::SV => Name::fixed("SV"),
        ethertype::MIKROTIK_ROMON => Name::fixed("MikroTik RoMON"),
        ethertype::LLDP => Name::fixed("LLDP"),
        ethertype::SERCOS_III => Name::fixed("SERCOS III"),
        ethertype::WSMP => Name::fixed("WSMP"),
        ethertype::HOMEPLUG_AV_MME => Name::fixed("HomePlug AV MME"),
        ethertype::MRP => Name::fixed("MRP"),
        ethertype::MACSEC => Name::fixed("MACsec"),
        ethertype::PBB => Name::fixed("PBB"),
        ethertype::PTP => Name::fixed("PTP"),
        ethertype::NC_SI => Name::fixed("NC-SI"),
        ethertype::PRP => Name::fixed("PRP"),
        ethertype::CFM_OAM => Name::fixed("CFM/OAM"),
        ethertype::FCOE => Name::fixed("FCoE"),
        ethertype::FCOE_INIT => Name::fixed("FCoE Init"),
        ethertype::ROCE => Name::fixed("RoCE"),
        ethertype::TTE => Name::fixed("TTE"),
        ethertype::HSR => Name::fixed("HSR"),
        ethertype::ECTP => Name::fixed("ECTP"),
        ethertype::QINQ_OLD => Name::fixed("QinQ (old)"),
        ethertype::VERITAS_LLT => Name::fixed("Veritas LLT"),
        _ => Name::upper_hex("0x", etype, 4),
    }
}

/// Convert DSCP (Differentiated Services Code Point) value to name per RFC 2474/4594.
///
/// Only the low six bits are looked at. A value with no standard name gives
/// `DSCP{n}`.
pub fn dscp_name(value: u8) -> Name {
    let value = value & 0x3F;
    Name::fixed(match value {
        dscp::CS0 => "CS0/BE",
        dscp::CS1 => "CS1",
        dscp::CS2 => "CS2",
        dscp::CS3 => "CS3",
        dscp::CS4 => "CS4",
        dscp::CS5 => "CS5",
        dscp::CS6 => "CS6",
        dscp::CS7 => "CS7",
        dscp::AF11 => "AF11",
        dscp::AF12 => "AF12",
        dscp::AF13 => "AF13",
        dscp::AF21 => "AF21",
        dscp::AF22 => "AF22",
        dscp::AF23 => "AF23",
        dscp::AF31 => "AF31",
        dscp::AF32 => "AF32",
        dscp::AF33 => "AF33",
        dscp::AF41 => "AF41",
        dscp::AF42 => "AF42",
        dscp::AF43 => "AF43",
        dscp::EF => "EF",
        dscp::VA => "VA",
        dscp::LE => "LE",
        _ => return Name::numbered("DSCP", value, ""),
    })
}

/// Convert ECN (Explicit Congestion Notification) value to name per RFC 3168.
///
/// Only the low two bits are looked at, so every input has a name.
pub fn ecn_name(value: u8) -> &'static str {
    match value & 0x03 {
        ecn::NOT_ECT => "Not-ECT",
        ecn::ECT1 => "ECT(1)",
        ecn::ECT0 => "ECT(0)",
        _ => "CE",
    }
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
