//! Protocol UDFs.
//!
//! Provides functions for converting IP protocol numbers and EtherTypes to human-readable names.

use std::sync::Arc;

use arrow::array::{Array, StringArray, UInt16Array, UInt8Array};
use arrow::datatypes::DataType;
use datafusion::common::Result as DFResult;
use datafusion::logical_expr::{
    ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, Volatility,
};
use pcapsql_core::format::{dscp_name, ecn_name, ethertype_name, ip_proto_name};

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

/// Create the `dscp_name()` UDF that converts DSCP value to name.
///
/// # Example
/// ```sql
/// SELECT dscp_name(dscp) FROM ipv4;
/// -- Returns: "EF", "AF11", "CS0", "BE", etc.
/// ```
pub fn create_dscp_name_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(DscpNameUdf::new())
}

/// Create the `ecn_name()` UDF that converts ECN value to name.
///
/// # Example
/// ```sql
/// SELECT ecn_name(ecn) FROM ipv4;
/// -- Returns: "Not-ECT", "ECT(1)", "ECT(0)", "CE"
/// ```
pub fn create_ecn_name_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(EcnNameUdf::new())
}

// ============================================================================
// ip_proto_name() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct IpProtoNameUdf {
    signature: Signature,
}

impl IpProtoNameUdf {
    fn new() -> Self {
        Self {
            signature: super::coercible_signature(&[DataType::UInt8], Volatility::Immutable),
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

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let proto_values = args[0]
            .as_any()
            .downcast_ref::<UInt8Array>()
            .expect("ip_proto_name: expected uint8 array");

        let result: StringArray = proto_values
            .iter()
            .map(|opt| opt.map(ip_proto_name))
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// ethertype_name() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct EthertypeNameUdf {
    signature: Signature,
}

impl EthertypeNameUdf {
    fn new() -> Self {
        Self {
            signature: super::coercible_signature(&[DataType::UInt16], Volatility::Immutable),
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

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let ethertype_values = args[0]
            .as_any()
            .downcast_ref::<UInt16Array>()
            .expect("ethertype_name: expected uint16 array");

        let result: StringArray = ethertype_values
            .iter()
            .map(|opt| opt.map(ethertype_name))
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// dscp_name() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct DscpNameUdf {
    signature: Signature,
}

impl DscpNameUdf {
    fn new() -> Self {
        Self {
            signature: super::coercible_signature(&[DataType::UInt8], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for DscpNameUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "dscp_name"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Utf8)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let dscp_values = args[0]
            .as_any()
            .downcast_ref::<UInt8Array>()
            .expect("dscp_name: expected uint8 array");

        let result: StringArray = dscp_values.iter().map(|opt| opt.map(dscp_name)).collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// ecn_name() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct EcnNameUdf {
    signature: Signature,
}

impl EcnNameUdf {
    fn new() -> Self {
        Self {
            signature: super::coercible_signature(&[DataType::UInt8], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for EcnNameUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "ecn_name"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Utf8)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let ecn_values = args[0]
            .as_any()
            .downcast_ref::<UInt8Array>()
            .expect("ecn_name: expected uint8 array");

        let result: StringArray = ecn_values.iter().map(|opt| opt.map(ecn_name)).collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}
