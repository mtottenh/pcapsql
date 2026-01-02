//! ICMP UDFs.
//!
//! Provides functions for converting ICMP and ICMPv6 type values to human-readable names.
//! Uses protocol constants from pcapsql-core for consistency.

use std::sync::Arc;

use arrow::array::{Array, StringArray, UInt8Array};
use arrow::datatypes::DataType;
use datafusion::common::Result as DFResult;
use datafusion::logical_expr::{
    ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, Volatility,
};
use pcapsql_core::protocol::{
    icmp_dest_unreachable_code as dest_unreachable_code,
    icmp_parameter_problem_code as parameter_problem_code, icmp_redirect_code as redirect_code,
    icmp_time_exceeded_code as time_exceeded_code, icmp_type, icmpv6_dest_unreachable_code,
    icmpv6_parameter_problem_code, icmpv6_time_exceeded_code, icmpv6_type,
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

/// Create the `icmp_code_name()` UDF that converts ICMP type+code to human-readable name.
///
/// # Example
/// ```sql
/// SELECT icmp_code_name(type, code) FROM icmp;
/// -- Returns: "Network Unreachable", "Host Unreachable", "Port Unreachable", etc.
/// ```
pub fn create_icmp_code_name_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(IcmpCodeNameUdf::new())
}

/// Create the `icmpv6_code_name()` UDF that converts ICMPv6 type+code to name.
///
/// # Example
/// ```sql
/// SELECT icmpv6_code_name(type, code) FROM icmpv6;
/// -- Returns: "No Route to Destination", "Administratively Prohibited", etc.
/// ```
pub fn create_icmpv6_code_name_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(Icmpv6CodeNameUdf::new())
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
fn icmp_type_to_name(t: u8) -> String {
    match t {
        icmp_type::ECHO_REPLY => "Echo Reply".to_string(),
        icmp_type::DESTINATION_UNREACHABLE => "Destination Unreachable".to_string(),
        icmp_type::SOURCE_QUENCH => "Source Quench".to_string(),
        icmp_type::REDIRECT => "Redirect".to_string(),
        6 => "Alternate Host Address".to_string(),
        icmp_type::ECHO_REQUEST => "Echo Request".to_string(),
        icmp_type::ROUTER_ADVERTISEMENT => "Router Advertisement".to_string(),
        icmp_type::ROUTER_SOLICITATION => "Router Solicitation".to_string(),
        icmp_type::TIME_EXCEEDED => "Time Exceeded".to_string(),
        icmp_type::PARAMETER_PROBLEM => "Parameter Problem".to_string(),
        icmp_type::TIMESTAMP_REQUEST => "Timestamp".to_string(),
        icmp_type::TIMESTAMP_REPLY => "Timestamp Reply".to_string(),
        icmp_type::INFO_REQUEST => "Information Request".to_string(),
        icmp_type::INFO_REPLY => "Information Reply".to_string(),
        icmp_type::ADDRESS_MASK_REQUEST => "Address Mask Request".to_string(),
        icmp_type::ADDRESS_MASK_REPLY => "Address Mask Reply".to_string(),
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
        _ => format!("Type {t}"),
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
fn icmpv6_type_to_name(t: u8) -> String {
    match t {
        // Error messages (0-127)
        icmpv6_type::DESTINATION_UNREACHABLE => "Destination Unreachable".to_string(),
        icmpv6_type::PACKET_TOO_BIG => "Packet Too Big".to_string(),
        icmpv6_type::TIME_EXCEEDED => "Time Exceeded".to_string(),
        icmpv6_type::PARAMETER_PROBLEM => "Parameter Problem".to_string(),
        100 => "Private Experimentation".to_string(),
        101 => "Private Experimentation".to_string(),
        127 => "Reserved for Expansion".to_string(),

        // Informational messages (128-255)
        icmpv6_type::ECHO_REQUEST => "Echo Request".to_string(),
        icmpv6_type::ECHO_REPLY => "Echo Reply".to_string(),
        icmpv6_type::MLD_QUERY => "Multicast Listener Query".to_string(),
        icmpv6_type::MLDV1_REPORT => "Multicast Listener Report".to_string(),
        icmpv6_type::MLDV1_DONE => "Multicast Listener Done".to_string(),
        icmpv6_type::ROUTER_SOLICITATION => "Router Solicitation".to_string(),
        icmpv6_type::ROUTER_ADVERTISEMENT => "Router Advertisement".to_string(),
        icmpv6_type::NEIGHBOR_SOLICITATION => "Neighbor Solicitation".to_string(),
        icmpv6_type::NEIGHBOR_ADVERTISEMENT => "Neighbor Advertisement".to_string(),
        icmpv6_type::REDIRECT => "Redirect".to_string(),
        138 => "Router Renumbering".to_string(),
        139 => "ICMP Node Information Query".to_string(),
        140 => "ICMP Node Information Response".to_string(),
        141 => "Inverse Neighbor Discovery Solicitation".to_string(),
        142 => "Inverse Neighbor Discovery Advertisement".to_string(),
        icmpv6_type::MLDV2_REPORT => "MLDv2 Multicast Listener Report".to_string(),
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

        _ => format!("Type {t}"),
    }
}

// ============================================================================
// icmp_code_name() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct IcmpCodeNameUdf {
    signature: Signature,
}

impl IcmpCodeNameUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(
                vec![DataType::UInt8, DataType::UInt8],
                Volatility::Immutable,
            ),
        }
    }
}

impl ScalarUDFImpl for IcmpCodeNameUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "icmp_code_name"
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
            .expect("icmp_code_name: expected uint8 array for type");
        let code_values = args[1]
            .as_any()
            .downcast_ref::<UInt8Array>()
            .expect("icmp_code_name: expected uint8 array for code");

        let result: StringArray = type_values
            .iter()
            .zip(code_values.iter())
            .map(|(t, c)| match (t, c) {
                (Some(t), Some(c)) => Some(icmp_code_to_name(t, c)),
                _ => None,
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

/// Convert ICMP type+code to human-readable name.
fn icmp_code_to_name(t: u8, code: u8) -> String {
    match t {
        // Destination Unreachable
        icmp_type::DESTINATION_UNREACHABLE => match code {
            dest_unreachable_code::NET_UNREACHABLE => "Network Unreachable".to_string(),
            dest_unreachable_code::HOST_UNREACHABLE => "Host Unreachable".to_string(),
            dest_unreachable_code::PROTOCOL_UNREACHABLE => "Protocol Unreachable".to_string(),
            dest_unreachable_code::PORT_UNREACHABLE => "Port Unreachable".to_string(),
            dest_unreachable_code::FRAGMENTATION_NEEDED => "Fragmentation Needed".to_string(),
            dest_unreachable_code::SOURCE_ROUTE_FAILED => "Source Route Failed".to_string(),
            dest_unreachable_code::DEST_NET_UNKNOWN => "Destination Network Unknown".to_string(),
            dest_unreachable_code::DEST_HOST_UNKNOWN => "Destination Host Unknown".to_string(),
            dest_unreachable_code::SOURCE_HOST_ISOLATED => "Source Host Isolated".to_string(),
            dest_unreachable_code::NET_ADMIN_PROHIBITED => {
                "Network Administratively Prohibited".to_string()
            }
            dest_unreachable_code::HOST_ADMIN_PROHIBITED => {
                "Host Administratively Prohibited".to_string()
            }
            dest_unreachable_code::NET_TOS_UNREACHABLE => "Network Unreachable for TOS".to_string(),
            dest_unreachable_code::HOST_TOS_UNREACHABLE => "Host Unreachable for TOS".to_string(),
            dest_unreachable_code::COMM_ADMIN_PROHIBITED => {
                "Communication Administratively Prohibited".to_string()
            }
            dest_unreachable_code::HOST_PRECEDENCE_VIOLATION => {
                "Host Precedence Violation".to_string()
            }
            dest_unreachable_code::PRECEDENCE_CUTOFF => "Precedence Cutoff in Effect".to_string(),
            _ => format!("Destination Unreachable (code {code})"),
        },
        // Redirect
        icmp_type::REDIRECT => match code {
            redirect_code::REDIRECT_NET => "Redirect for Network".to_string(),
            redirect_code::REDIRECT_HOST => "Redirect for Host".to_string(),
            redirect_code::REDIRECT_TOS_NET => "Redirect for TOS and Network".to_string(),
            redirect_code::REDIRECT_TOS_HOST => "Redirect for TOS and Host".to_string(),
            _ => format!("Redirect (code {code})"),
        },
        // Time Exceeded
        icmp_type::TIME_EXCEEDED => match code {
            time_exceeded_code::TTL_EXCEEDED => "TTL Exceeded in Transit".to_string(),
            time_exceeded_code::FRAGMENT_REASSEMBLY_EXCEEDED => {
                "Fragment Reassembly Time Exceeded".to_string()
            }
            _ => format!("Time Exceeded (code {code})"),
        },
        // Parameter Problem
        icmp_type::PARAMETER_PROBLEM => match code {
            parameter_problem_code::POINTER_ERROR => "Pointer Indicates Error".to_string(),
            parameter_problem_code::MISSING_REQUIRED_OPTION => {
                "Missing Required Option".to_string()
            }
            parameter_problem_code::BAD_LENGTH => "Bad Length".to_string(),
            _ => format!("Parameter Problem (code {code})"),
        },
        // Echo Reply and Echo Request have code 0
        icmp_type::ECHO_REPLY | icmp_type::ECHO_REQUEST => {
            if code == 0 {
                "No Code".to_string()
            } else {
                format!("Code {code}")
            }
        }
        // Other types
        _ => {
            if code == 0 {
                "No Code".to_string()
            } else {
                format!("Code {code}")
            }
        }
    }
}

// ============================================================================
// icmpv6_code_name() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct Icmpv6CodeNameUdf {
    signature: Signature,
}

impl Icmpv6CodeNameUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(
                vec![DataType::UInt8, DataType::UInt8],
                Volatility::Immutable,
            ),
        }
    }
}

impl ScalarUDFImpl for Icmpv6CodeNameUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "icmpv6_code_name"
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
            .expect("icmpv6_code_name: expected uint8 array for type");
        let code_values = args[1]
            .as_any()
            .downcast_ref::<UInt8Array>()
            .expect("icmpv6_code_name: expected uint8 array for code");

        let result: StringArray = type_values
            .iter()
            .zip(code_values.iter())
            .map(|(t, c)| match (t, c) {
                (Some(t), Some(c)) => Some(icmpv6_code_to_name(t, c)),
                _ => None,
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

/// Convert ICMPv6 type+code to human-readable name.
fn icmpv6_code_to_name(t: u8, code: u8) -> String {
    match t {
        // Destination Unreachable
        icmpv6_type::DESTINATION_UNREACHABLE => match code {
            icmpv6_dest_unreachable_code::NO_ROUTE => "No Route to Destination".to_string(),
            icmpv6_dest_unreachable_code::ADMIN_PROHIBITED => {
                "Administratively Prohibited".to_string()
            }
            icmpv6_dest_unreachable_code::BEYOND_SCOPE => {
                "Beyond Scope of Source Address".to_string()
            }
            icmpv6_dest_unreachable_code::ADDRESS_UNREACHABLE => "Address Unreachable".to_string(),
            icmpv6_dest_unreachable_code::PORT_UNREACHABLE => "Port Unreachable".to_string(),
            icmpv6_dest_unreachable_code::FAILED_POLICY => {
                "Source Address Failed Ingress/Egress Policy".to_string()
            }
            icmpv6_dest_unreachable_code::REJECT_ROUTE => "Reject Route to Destination".to_string(),
            icmpv6_dest_unreachable_code::SOURCE_ROUTING_ERROR => {
                "Error in Source Routing Header".to_string()
            }
            _ => format!("Destination Unreachable (code {code})"),
        },
        // Packet Too Big
        icmpv6_type::PACKET_TOO_BIG => "Packet Too Big".to_string(),
        // Time Exceeded
        icmpv6_type::TIME_EXCEEDED => match code {
            icmpv6_time_exceeded_code::HOP_LIMIT_EXCEEDED => {
                "Hop Limit Exceeded in Transit".to_string()
            }
            icmpv6_time_exceeded_code::FRAGMENT_REASSEMBLY_EXCEEDED => {
                "Fragment Reassembly Time Exceeded".to_string()
            }
            _ => format!("Time Exceeded (code {code})"),
        },
        // Parameter Problem
        icmpv6_type::PARAMETER_PROBLEM => match code {
            icmpv6_parameter_problem_code::ERRONEOUS_HEADER => "Erroneous Header Field".to_string(),
            icmpv6_parameter_problem_code::UNRECOGNIZED_NEXT_HEADER => {
                "Unrecognized Next Header".to_string()
            }
            icmpv6_parameter_problem_code::UNRECOGNIZED_OPTION => {
                "Unrecognized IPv6 Option".to_string()
            }
            _ => format!("Parameter Problem (code {code})"),
        },
        // Echo Request/Reply
        icmpv6_type::ECHO_REQUEST | icmpv6_type::ECHO_REPLY => {
            if code == 0 {
                "No Code".to_string()
            } else {
                format!("Code {code}")
            }
        }
        // Router Renumbering (type 138)
        138 => match code {
            0 => "Router Renumbering Command".to_string(),
            1 => "Router Renumbering Result".to_string(),
            255 => "Sequence Number Reset".to_string(),
            _ => format!("Router Renumbering (code {code})"),
        },
        // Node Information Query (type 139)
        139 => match code {
            0 => "NI Query for IPv6 Address".to_string(),
            1 => "NI Query for Name or Empty".to_string(),
            2 => "NI Query for IPv4 Address".to_string(),
            _ => format!("NI Query (code {code})"),
        },
        // Node Information Response (type 140)
        140 => match code {
            0 => "NI Response Success".to_string(),
            1 => "NI Responder Refuses".to_string(),
            2 => "NI Unknown Query Type".to_string(),
            _ => format!("NI Response (code {code})"),
        },
        // Other types
        _ => {
            if code == 0 {
                "No Code".to_string()
            } else {
                format!("Code {code}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_type_name() {
        assert_eq!(icmp_type_to_name(icmp_type::ECHO_REPLY), "Echo Reply");
        assert_eq!(
            icmp_type_to_name(icmp_type::DESTINATION_UNREACHABLE),
            "Destination Unreachable"
        );
        assert_eq!(icmp_type_to_name(icmp_type::REDIRECT), "Redirect");
        assert_eq!(icmp_type_to_name(icmp_type::ECHO_REQUEST), "Echo Request");
        assert_eq!(
            icmp_type_to_name(icmp_type::ROUTER_ADVERTISEMENT),
            "Router Advertisement"
        );
        assert_eq!(
            icmp_type_to_name(icmp_type::ROUTER_SOLICITATION),
            "Router Solicitation"
        );
        assert_eq!(icmp_type_to_name(icmp_type::TIME_EXCEEDED), "Time Exceeded");
        assert_eq!(icmp_type_to_name(icmp_type::TIMESTAMP_REQUEST), "Timestamp");
        assert_eq!(
            icmp_type_to_name(icmp_type::TIMESTAMP_REPLY),
            "Timestamp Reply"
        );
        // Unknown type
        assert_eq!(icmp_type_to_name(99), "Type 99");
    }

    #[test]
    fn test_icmpv6_type_name() {
        // Error messages
        assert_eq!(
            icmpv6_type_to_name(icmpv6_type::DESTINATION_UNREACHABLE),
            "Destination Unreachable"
        );
        assert_eq!(
            icmpv6_type_to_name(icmpv6_type::PACKET_TOO_BIG),
            "Packet Too Big"
        );
        assert_eq!(
            icmpv6_type_to_name(icmpv6_type::TIME_EXCEEDED),
            "Time Exceeded"
        );
        assert_eq!(
            icmpv6_type_to_name(icmpv6_type::PARAMETER_PROBLEM),
            "Parameter Problem"
        );

        // Informational messages
        assert_eq!(
            icmpv6_type_to_name(icmpv6_type::ECHO_REQUEST),
            "Echo Request"
        );
        assert_eq!(icmpv6_type_to_name(icmpv6_type::ECHO_REPLY), "Echo Reply");
        assert_eq!(
            icmpv6_type_to_name(icmpv6_type::MLD_QUERY),
            "Multicast Listener Query"
        );
        assert_eq!(
            icmpv6_type_to_name(icmpv6_type::MLDV1_REPORT),
            "Multicast Listener Report"
        );
        assert_eq!(
            icmpv6_type_to_name(icmpv6_type::ROUTER_SOLICITATION),
            "Router Solicitation"
        );
        assert_eq!(
            icmpv6_type_to_name(icmpv6_type::ROUTER_ADVERTISEMENT),
            "Router Advertisement"
        );
        assert_eq!(
            icmpv6_type_to_name(icmpv6_type::NEIGHBOR_SOLICITATION),
            "Neighbor Solicitation"
        );
        assert_eq!(
            icmpv6_type_to_name(icmpv6_type::NEIGHBOR_ADVERTISEMENT),
            "Neighbor Advertisement"
        );
        assert_eq!(icmpv6_type_to_name(icmpv6_type::REDIRECT), "Redirect");

        // Unknown type
        assert_eq!(icmpv6_type_to_name(99), "Type 99");
    }

    #[test]
    fn test_ndp_types() {
        // NDP message types
        assert_eq!(
            icmpv6_type_to_name(icmpv6_type::ROUTER_SOLICITATION),
            "Router Solicitation"
        );
        assert_eq!(
            icmpv6_type_to_name(icmpv6_type::ROUTER_ADVERTISEMENT),
            "Router Advertisement"
        );
        assert_eq!(
            icmpv6_type_to_name(icmpv6_type::NEIGHBOR_SOLICITATION),
            "Neighbor Solicitation"
        );
        assert_eq!(
            icmpv6_type_to_name(icmpv6_type::NEIGHBOR_ADVERTISEMENT),
            "Neighbor Advertisement"
        );
        assert_eq!(icmpv6_type_to_name(icmpv6_type::REDIRECT), "Redirect");
    }

    #[test]
    fn test_mld_types() {
        // MLD message types
        assert_eq!(
            icmpv6_type_to_name(icmpv6_type::MLD_QUERY),
            "Multicast Listener Query"
        );
        assert_eq!(
            icmpv6_type_to_name(icmpv6_type::MLDV1_REPORT),
            "Multicast Listener Report"
        );
        assert_eq!(
            icmpv6_type_to_name(icmpv6_type::MLDV1_DONE),
            "Multicast Listener Done"
        );
        assert_eq!(
            icmpv6_type_to_name(icmpv6_type::MLDV2_REPORT),
            "MLDv2 Multicast Listener Report"
        );
    }
}
