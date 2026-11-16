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
use pcapsql_core::format::{icmp_code_name, icmp_type_name, icmpv6_code_name, icmpv6_type_name};

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
            signature: super::coercible_signature(&[DataType::UInt8], Volatility::Immutable),
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
            .map(|opt| opt.map(icmp_type_name))
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
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
            signature: super::coercible_signature(&[DataType::UInt8], Volatility::Immutable),
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
            .map(|opt| opt.map(icmpv6_type_name))
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
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
            signature: super::coercible_signature(
                &[DataType::UInt8, DataType::UInt8],
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
                (Some(t), Some(c)) => Some(icmp_code_name(t, c)),
                _ => None,
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
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
            signature: super::coercible_signature(
                &[DataType::UInt8, DataType::UInt8],
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
                (Some(t), Some(c)) => Some(icmpv6_code_name(t, c)),
                _ => None,
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}
