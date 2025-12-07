//! Protocol UDFs.
//!
//! Provides functions for converting IP protocol numbers and EtherTypes to human-readable names.

use std::sync::Arc;

use arrow::array::{Array, StringArray, UInt16Array, UInt8Array};
use arrow::datatypes::DataType;
use datafusion::common::Result as DFResult;
use datafusion::logical_expr::{ColumnarValue, ScalarUDF, ScalarUDFImpl, Signature, Volatility};

/// Create the `ip_proto_name()` UDF that converts IP protocol number to name.
///
/// # Example
/// ```sql
/// SELECT ip_proto_name(protocol) FROM ipv4;
/// -- Returns: "TCP", "UDP", "ICMP", "GRE", etc.
/// ```
pub fn create_ip_proto_name_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(IpProtoNameUdf::new())
}

/// Create the `ethertype_name()` UDF that converts EtherType to name.
///
/// # Example
/// ```sql
/// SELECT ethertype_name(ethertype) FROM ethernet;
/// -- Returns: "IPv4", "IPv6", "ARP", "VLAN", etc.
/// ```
pub fn create_ethertype_name_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(EthertypeNameUdf::new())
}

// ============================================================================
// ip_proto_name() UDF Implementation
// ============================================================================

#[derive(Debug)]
struct IpProtoNameUdf {
    signature: Signature,
}

impl IpProtoNameUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::UInt8], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for IpProtoNameUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "ip_proto_name"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Utf8)
    }

    fn invoke(&self, args: &[ColumnarValue]) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(args)?;
        let proto_values = args[0]
            .as_any()
            .downcast_ref::<UInt8Array>()
            .expect("ip_proto_name: expected uint8 array");

        let result: StringArray = proto_values
            .iter()
            .map(|opt| opt.map(ip_proto_to_name))
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

/// Convert IP protocol number to name.
fn ip_proto_to_name(proto: u8) -> String {
    match proto {
        0 => "HOPOPT".to_string(),
        1 => "ICMP".to_string(),
        2 => "IGMP".to_string(),
        3 => "GGP".to_string(),
        4 => "IPv4".to_string(),
        5 => "ST".to_string(),
        6 => "TCP".to_string(),
        7 => "CBT".to_string(),
        8 => "EGP".to_string(),
        9 => "IGP".to_string(),
        10 => "BBN-RCC-MON".to_string(),
        11 => "NVP-II".to_string(),
        12 => "PUP".to_string(),
        13 => "ARGUS".to_string(),
        14 => "EMCON".to_string(),
        15 => "XNET".to_string(),
        16 => "CHAOS".to_string(),
        17 => "UDP".to_string(),
        18 => "MUX".to_string(),
        19 => "DCN-MEAS".to_string(),
        20 => "HMP".to_string(),
        21 => "PRM".to_string(),
        22 => "XNS-IDP".to_string(),
        23 => "TRUNK-1".to_string(),
        24 => "TRUNK-2".to_string(),
        25 => "LEAF-1".to_string(),
        26 => "LEAF-2".to_string(),
        27 => "RDP".to_string(),
        28 => "IRTP".to_string(),
        29 => "ISO-TP4".to_string(),
        30 => "NETBLT".to_string(),
        31 => "MFE-NSP".to_string(),
        32 => "MERIT-INP".to_string(),
        33 => "DCCP".to_string(),
        34 => "3PC".to_string(),
        35 => "IDPR".to_string(),
        36 => "XTP".to_string(),
        37 => "DDP".to_string(),
        38 => "IDPR-CMTP".to_string(),
        39 => "TP++".to_string(),
        40 => "IL".to_string(),
        41 => "IPv6".to_string(),
        42 => "SDRP".to_string(),
        43 => "IPv6-Route".to_string(),
        44 => "IPv6-Frag".to_string(),
        45 => "IDRP".to_string(),
        46 => "RSVP".to_string(),
        47 => "GRE".to_string(),
        48 => "DSR".to_string(),
        49 => "BNA".to_string(),
        50 => "ESP".to_string(),
        51 => "AH".to_string(),
        52 => "I-NLSP".to_string(),
        53 => "SWIPE".to_string(),
        54 => "NARP".to_string(),
        55 => "MOBILE".to_string(),
        56 => "TLSP".to_string(),
        57 => "SKIP".to_string(),
        58 => "ICMPv6".to_string(),
        59 => "IPv6-NoNxt".to_string(),
        60 => "IPv6-Opts".to_string(),
        62 => "CFTP".to_string(),
        64 => "SAT-EXPAK".to_string(),
        65 => "KRYPTOLAN".to_string(),
        66 => "RVD".to_string(),
        67 => "IPPC".to_string(),
        69 => "SAT-MON".to_string(),
        70 => "VISA".to_string(),
        71 => "IPCV".to_string(),
        72 => "CPNX".to_string(),
        73 => "CPHB".to_string(),
        74 => "WSN".to_string(),
        75 => "PVP".to_string(),
        76 => "BR-SAT-MON".to_string(),
        77 => "SUN-ND".to_string(),
        78 => "WB-MON".to_string(),
        79 => "WB-EXPAK".to_string(),
        80 => "ISO-IP".to_string(),
        81 => "VMTP".to_string(),
        82 => "SECURE-VMTP".to_string(),
        83 => "VINES".to_string(),
        84 => "TTP/IPTM".to_string(),
        85 => "NSFNET-IGP".to_string(),
        86 => "DGP".to_string(),
        87 => "TCF".to_string(),
        88 => "EIGRP".to_string(),
        89 => "OSPF".to_string(),
        90 => "Sprite-RPC".to_string(),
        91 => "LARP".to_string(),
        92 => "MTP".to_string(),
        93 => "AX.25".to_string(),
        94 => "IPIP".to_string(),
        95 => "MICP".to_string(),
        96 => "SCC-SP".to_string(),
        97 => "ETHERIP".to_string(),
        98 => "ENCAP".to_string(),
        100 => "GMTP".to_string(),
        101 => "IFMP".to_string(),
        102 => "PNNI".to_string(),
        103 => "PIM".to_string(),
        104 => "ARIS".to_string(),
        105 => "SCPS".to_string(),
        106 => "QNX".to_string(),
        107 => "A/N".to_string(),
        108 => "IPComp".to_string(),
        109 => "SNP".to_string(),
        110 => "Compaq-Peer".to_string(),
        111 => "IPX-in-IP".to_string(),
        112 => "VRRP".to_string(),
        113 => "PGM".to_string(),
        115 => "L2TP".to_string(),
        116 => "DDX".to_string(),
        117 => "IATP".to_string(),
        118 => "STP".to_string(),
        119 => "SRP".to_string(),
        120 => "UTI".to_string(),
        121 => "SMP".to_string(),
        122 => "SM".to_string(),
        123 => "PTP".to_string(),
        124 => "ISIS".to_string(),
        125 => "FIRE".to_string(),
        126 => "CRTP".to_string(),
        127 => "CRUDP".to_string(),
        128 => "SSCOPMCE".to_string(),
        129 => "IPLT".to_string(),
        130 => "SPS".to_string(),
        131 => "PIPE".to_string(),
        132 => "SCTP".to_string(),
        133 => "FC".to_string(),
        134 => "RSVP-E2E-IGNORE".to_string(),
        135 => "Mobility".to_string(),
        136 => "UDPLite".to_string(),
        137 => "MPLS-in-IP".to_string(),
        138 => "manet".to_string(),
        139 => "HIP".to_string(),
        140 => "Shim6".to_string(),
        141 => "WESP".to_string(),
        142 => "ROHC".to_string(),
        143 => "Ethernet".to_string(),
        253 => "Experimentation".to_string(),
        254 => "Experimentation".to_string(),
        _ => format!("Proto {proto}"),
    }
}

// ============================================================================
// ethertype_name() UDF Implementation
// ============================================================================

#[derive(Debug)]
struct EthertypeNameUdf {
    signature: Signature,
}

impl EthertypeNameUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::UInt16], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for EthertypeNameUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "ethertype_name"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Utf8)
    }

    fn invoke(&self, args: &[ColumnarValue]) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(args)?;
        let ethertype_values = args[0]
            .as_any()
            .downcast_ref::<UInt16Array>()
            .expect("ethertype_name: expected uint16 array");

        let result: StringArray = ethertype_values
            .iter()
            .map(|opt| opt.map(ethertype_to_name))
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

/// Convert EtherType to name.
fn ethertype_to_name(ethertype: u16) -> String {
    match ethertype {
        0x0800 => "IPv4".to_string(),
        0x0806 => "ARP".to_string(),
        0x0842 => "Wake-on-LAN".to_string(),
        0x22F0 => "AVTP".to_string(),
        0x22F3 => "IETF TRILL".to_string(),
        0x22EA => "SRP".to_string(),
        0x6002 => "DEC MOP RC".to_string(),
        0x6003 => "DECnet".to_string(),
        0x6004 => "DEC LAT".to_string(),
        0x8035 => "RARP".to_string(),
        0x809B => "AppleTalk".to_string(),
        0x80F3 => "AARP".to_string(),
        0x8100 => "VLAN".to_string(),
        0x8102 => "SLPP".to_string(),
        0x8103 => "VLACP".to_string(),
        0x8137 => "IPX".to_string(),
        0x8204 => "QNX Qnet".to_string(),
        0x86DD => "IPv6".to_string(),
        0x8808 => "Flow Control".to_string(),
        0x8809 => "LACP".to_string(),
        0x8819 => "CobraNet".to_string(),
        0x8847 => "MPLS".to_string(),
        0x8848 => "MPLS Multicast".to_string(),
        0x8863 => "PPPoE Discovery".to_string(),
        0x8864 => "PPPoE Session".to_string(),
        0x887B => "HomePlug 1.0 MME".to_string(),
        0x888E => "EAP over LAN".to_string(),
        0x8892 => "PROFINET".to_string(),
        0x889A => "HyperSCSI".to_string(),
        0x88A2 => "ATA over Ethernet".to_string(),
        0x88A4 => "EtherCAT".to_string(),
        0x88A8 => "QinQ".to_string(),
        0x88AB => "Powerlink".to_string(),
        0x88B8 => "GOOSE".to_string(),
        0x88B9 => "GSE".to_string(),
        0x88BA => "SV".to_string(),
        0x88BF => "MikroTik RoMON".to_string(),
        0x88CC => "LLDP".to_string(),
        0x88CD => "SERCOS III".to_string(),
        0x88DC => "WSMP".to_string(),
        0x88E1 => "HomePlug AV MME".to_string(),
        0x88E3 => "MRP".to_string(),
        0x88E5 => "MACsec".to_string(),
        0x88E7 => "PBB".to_string(),
        0x88F7 => "PTP".to_string(),
        0x88F8 => "NC-SI".to_string(),
        0x88FB => "PRP".to_string(),
        0x8902 => "CFM/OAM".to_string(),
        0x8906 => "FCoE".to_string(),
        0x8914 => "FCoE Init".to_string(),
        0x8915 => "RoCE".to_string(),
        0x891D => "TTE".to_string(),
        0x892F => "HSR".to_string(),
        0x9000 => "ECTP".to_string(),
        0x9100 => "QinQ (old)".to_string(),
        0xCAFE => "Veritas LLT".to_string(),
        _ => format!("0x{ethertype:04X}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_proto_name() {
        assert_eq!(ip_proto_to_name(1), "ICMP");
        assert_eq!(ip_proto_to_name(2), "IGMP");
        assert_eq!(ip_proto_to_name(6), "TCP");
        assert_eq!(ip_proto_to_name(17), "UDP");
        assert_eq!(ip_proto_to_name(41), "IPv6");
        assert_eq!(ip_proto_to_name(47), "GRE");
        assert_eq!(ip_proto_to_name(50), "ESP");
        assert_eq!(ip_proto_to_name(51), "AH");
        assert_eq!(ip_proto_to_name(58), "ICMPv6");
        assert_eq!(ip_proto_to_name(89), "OSPF");
        assert_eq!(ip_proto_to_name(132), "SCTP");
        // Unknown protocol
        assert_eq!(ip_proto_to_name(200), "Proto 200");
    }

    #[test]
    fn test_ethertype_name() {
        assert_eq!(ethertype_to_name(0x0800), "IPv4");
        assert_eq!(ethertype_to_name(0x0806), "ARP");
        assert_eq!(ethertype_to_name(0x8100), "VLAN");
        assert_eq!(ethertype_to_name(0x86DD), "IPv6");
        assert_eq!(ethertype_to_name(0x8847), "MPLS");
        assert_eq!(ethertype_to_name(0x8848), "MPLS Multicast");
        assert_eq!(ethertype_to_name(0x88A8), "QinQ");
        assert_eq!(ethertype_to_name(0x88CC), "LLDP");
        assert_eq!(ethertype_to_name(0x88E5), "MACsec");
        // Unknown ethertype
        assert_eq!(ethertype_to_name(0x1234), "0x1234");
    }

    #[test]
    fn test_common_protocols() {
        // Most commonly seen protocols
        assert_eq!(ip_proto_to_name(1), "ICMP");
        assert_eq!(ip_proto_to_name(6), "TCP");
        assert_eq!(ip_proto_to_name(17), "UDP");
        assert_eq!(ip_proto_to_name(58), "ICMPv6");
    }

    #[test]
    fn test_common_ethertypes() {
        // Most commonly seen ethertypes
        assert_eq!(ethertype_to_name(0x0800), "IPv4");
        assert_eq!(ethertype_to_name(0x86DD), "IPv6");
        assert_eq!(ethertype_to_name(0x0806), "ARP");
        assert_eq!(ethertype_to_name(0x8100), "VLAN");
    }
}
