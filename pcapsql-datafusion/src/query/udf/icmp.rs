//! ICMP UDFs.
//!
//! Provides functions for converting ICMP and ICMPv6 type values to human-readable names.

use std::sync::Arc;

use arrow::array::{Array, StringArray, UInt8Array};
use arrow::datatypes::DataType;
use datafusion::common::Result as DFResult;
use datafusion::logical_expr::{
    ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, Volatility,
};

/// Create the `icmp_type_name()` UDF that converts ICMP type to human-readable name.
///
/// # Example
/// ```sql
/// SELECT icmp_type_name(type) FROM icmp;
/// -- Returns: "Echo Reply", "Echo Request", "Destination Unreachable", etc.
/// ```
pub fn create_icmp_type_name_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(IcmpTypeNameUdf::new())
}

/// Create the `icmpv6_type_name()` UDF that converts ICMPv6 type to name.
///
/// # Example
/// ```sql
/// SELECT icmpv6_type_name(type) FROM icmpv6;
/// ```
pub fn create_icmpv6_type_name_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(Icmpv6TypeNameUdf::new())
}

// ============================================================================
// icmp_type_name() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct IcmpTypeNameUdf {
    signature: Signature,
}

impl IcmpTypeNameUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::UInt8], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for IcmpTypeNameUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "icmp_type_name"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Utf8)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let type_values = args[0]
            .as_any()
            .downcast_ref::<UInt8Array>()
            .expect("icmp_type_name: expected uint8 array");

        let result: StringArray = type_values
            .iter()
            .map(|opt| opt.map(icmp_type_to_name))
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

/// Convert ICMP type to human-readable name.
fn icmp_type_to_name(icmp_type: u8) -> String {
    match icmp_type {
        0 => "Echo Reply".to_string(),
        3 => "Destination Unreachable".to_string(),
        4 => "Source Quench".to_string(),
        5 => "Redirect".to_string(),
        6 => "Alternate Host Address".to_string(),
        8 => "Echo Request".to_string(),
        9 => "Router Advertisement".to_string(),
        10 => "Router Solicitation".to_string(),
        11 => "Time Exceeded".to_string(),
        12 => "Parameter Problem".to_string(),
        13 => "Timestamp".to_string(),
        14 => "Timestamp Reply".to_string(),
        15 => "Information Request".to_string(),
        16 => "Information Reply".to_string(),
        17 => "Address Mask Request".to_string(),
        18 => "Address Mask Reply".to_string(),
        30 => "Traceroute".to_string(),
        31 => "Datagram Conversion Error".to_string(),
        32 => "Mobile Host Redirect".to_string(),
        33 => "IPv6 Where-Are-You".to_string(),
        34 => "IPv6 I-Am-Here".to_string(),
        35 => "Mobile Registration Request".to_string(),
        36 => "Mobile Registration Reply".to_string(),
        37 => "Domain Name Request".to_string(),
        38 => "Domain Name Reply".to_string(),
        39 => "SKIP".to_string(),
        40 => "Photuris".to_string(),
        41 => "ICMP for Seamoby".to_string(),
        42 => "Extended Echo Request".to_string(),
        43 => "Extended Echo Reply".to_string(),
        _ => format!("Type {icmp_type}"),
    }
}

// ============================================================================
// icmpv6_type_name() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct Icmpv6TypeNameUdf {
    signature: Signature,
}

impl Icmpv6TypeNameUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::UInt8], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for Icmpv6TypeNameUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "icmpv6_type_name"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Utf8)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let type_values = args[0]
            .as_any()
            .downcast_ref::<UInt8Array>()
            .expect("icmpv6_type_name: expected uint8 array");

        let result: StringArray = type_values
            .iter()
            .map(|opt| opt.map(icmpv6_type_to_name))
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

/// Convert ICMPv6 type to human-readable name.
fn icmpv6_type_to_name(icmp_type: u8) -> String {
    match icmp_type {
        // Error messages (0-127)
        1 => "Destination Unreachable".to_string(),
        2 => "Packet Too Big".to_string(),
        3 => "Time Exceeded".to_string(),
        4 => "Parameter Problem".to_string(),
        100 => "Private Experimentation".to_string(),
        101 => "Private Experimentation".to_string(),
        127 => "Reserved for Expansion".to_string(),

        // Informational messages (128-255)
        128 => "Echo Request".to_string(),
        129 => "Echo Reply".to_string(),
        130 => "Multicast Listener Query".to_string(),
        131 => "Multicast Listener Report".to_string(),
        132 => "Multicast Listener Done".to_string(),
        133 => "Router Solicitation".to_string(),
        134 => "Router Advertisement".to_string(),
        135 => "Neighbor Solicitation".to_string(),
        136 => "Neighbor Advertisement".to_string(),
        137 => "Redirect".to_string(),
        138 => "Router Renumbering".to_string(),
        139 => "ICMP Node Information Query".to_string(),
        140 => "ICMP Node Information Response".to_string(),
        141 => "Inverse Neighbor Discovery Solicitation".to_string(),
        142 => "Inverse Neighbor Discovery Advertisement".to_string(),
        143 => "MLDv2 Multicast Listener Report".to_string(),
        144 => "Home Agent Address Discovery Request".to_string(),
        145 => "Home Agent Address Discovery Reply".to_string(),
        146 => "Mobile Prefix Solicitation".to_string(),
        147 => "Mobile Prefix Advertisement".to_string(),
        148 => "Certification Path Solicitation".to_string(),
        149 => "Certification Path Advertisement".to_string(),
        150 => "ICMP Experimental".to_string(),
        151 => "Multicast Router Advertisement".to_string(),
        152 => "Multicast Router Solicitation".to_string(),
        153 => "Multicast Router Termination".to_string(),
        154 => "FMIPv6".to_string(),
        155 => "RPL Control".to_string(),
        156 => "ILNPv6 Locator Update".to_string(),
        157 => "Duplicate Address Request".to_string(),
        158 => "Duplicate Address Confirmation".to_string(),
        159 => "MPL Control".to_string(),
        160 => "Extended Echo Request".to_string(),
        161 => "Extended Echo Reply".to_string(),
        200 => "Private Experimentation".to_string(),
        201 => "Private Experimentation".to_string(),
        255 => "Reserved for Expansion".to_string(),

        _ => format!("Type {icmp_type}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_type_name() {
        assert_eq!(icmp_type_to_name(0), "Echo Reply");
        assert_eq!(icmp_type_to_name(3), "Destination Unreachable");
        assert_eq!(icmp_type_to_name(5), "Redirect");
        assert_eq!(icmp_type_to_name(8), "Echo Request");
        assert_eq!(icmp_type_to_name(9), "Router Advertisement");
        assert_eq!(icmp_type_to_name(10), "Router Solicitation");
        assert_eq!(icmp_type_to_name(11), "Time Exceeded");
        assert_eq!(icmp_type_to_name(13), "Timestamp");
        assert_eq!(icmp_type_to_name(14), "Timestamp Reply");
        // Unknown type
        assert_eq!(icmp_type_to_name(99), "Type 99");
    }

    #[test]
    fn test_icmpv6_type_name() {
        // Error messages
        assert_eq!(icmpv6_type_to_name(1), "Destination Unreachable");
        assert_eq!(icmpv6_type_to_name(2), "Packet Too Big");
        assert_eq!(icmpv6_type_to_name(3), "Time Exceeded");
        assert_eq!(icmpv6_type_to_name(4), "Parameter Problem");

        // Informational messages
        assert_eq!(icmpv6_type_to_name(128), "Echo Request");
        assert_eq!(icmpv6_type_to_name(129), "Echo Reply");
        assert_eq!(icmpv6_type_to_name(130), "Multicast Listener Query");
        assert_eq!(icmpv6_type_to_name(131), "Multicast Listener Report");
        assert_eq!(icmpv6_type_to_name(133), "Router Solicitation");
        assert_eq!(icmpv6_type_to_name(134), "Router Advertisement");
        assert_eq!(icmpv6_type_to_name(135), "Neighbor Solicitation");
        assert_eq!(icmpv6_type_to_name(136), "Neighbor Advertisement");
        assert_eq!(icmpv6_type_to_name(137), "Redirect");

        // Unknown type
        assert_eq!(icmpv6_type_to_name(99), "Type 99");
    }

    #[test]
    fn test_ndp_types() {
        // NDP message types (133-137)
        assert_eq!(icmpv6_type_to_name(133), "Router Solicitation");
        assert_eq!(icmpv6_type_to_name(134), "Router Advertisement");
        assert_eq!(icmpv6_type_to_name(135), "Neighbor Solicitation");
        assert_eq!(icmpv6_type_to_name(136), "Neighbor Advertisement");
        assert_eq!(icmpv6_type_to_name(137), "Redirect");
    }

    #[test]
    fn test_mld_types() {
        // MLD message types (130, 131, 132, 143)
        assert_eq!(icmpv6_type_to_name(130), "Multicast Listener Query");
        assert_eq!(icmpv6_type_to_name(131), "Multicast Listener Report");
        assert_eq!(icmpv6_type_to_name(132), "Multicast Listener Done");
        assert_eq!(icmpv6_type_to_name(143), "MLDv2 Multicast Listener Report");
    }
}
