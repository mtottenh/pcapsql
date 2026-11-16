//! BGP protocol UDFs.
//!
//! Provides functions for converting BGP message types and path attributes to human-readable names.
//! Uses protocol constants from pcapsql-core for consistency.

use std::sync::Arc;

use arrow::array::{Array, StringArray, UInt8Array};
use arrow::datatypes::DataType;
use datafusion::common::Result as DFResult;
use datafusion::logical_expr::{
    ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, Volatility,
};
use pcapsql_core::format::{bgp_message_type_name, bgp_origin_name};

/// Create the `bgp_message_type_name()` UDF.
///
/// # Example
/// ```sql
/// SELECT bgp_message_type_name(message_type) FROM bgp;
/// -- Returns: "OPEN", "UPDATE", "NOTIFICATION", "KEEPALIVE", "ROUTE-REFRESH"
/// ```
pub fn create_bgp_message_type_name_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(BgpMessageTypeNameUdf::new())
}

/// Create the `bgp_origin_name()` UDF.
///
/// # Example
/// ```sql
/// SELECT bgp_origin_name(origin) FROM bgp WHERE origin IS NOT NULL;
/// -- Returns: "IGP", "EGP", "INCOMPLETE"
/// ```
pub fn create_bgp_origin_name_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(BgpOriginNameUdf::new())
}

// ============================================================================
// bgp_message_type_name() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct BgpMessageTypeNameUdf {
    signature: Signature,
}

impl BgpMessageTypeNameUdf {
    fn new() -> Self {
        Self {
            signature: super::coercible_signature(&[DataType::UInt8], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for BgpMessageTypeNameUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "bgp_message_type_name"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Utf8)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let values = args[0]
            .as_any()
            .downcast_ref::<UInt8Array>()
            .expect("bgp_message_type_name: expected uint8 array");

        let result: StringArray = values
            .iter()
            .map(|opt| opt.map(bgp_message_type_name))
            .collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// bgp_origin_name() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct BgpOriginNameUdf {
    signature: Signature,
}

impl BgpOriginNameUdf {
    fn new() -> Self {
        Self {
            signature: super::coercible_signature(&[DataType::UInt8], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for BgpOriginNameUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "bgp_origin_name"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Utf8)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let values = args[0]
            .as_any()
            .downcast_ref::<UInt8Array>()
            .expect("bgp_origin_name: expected uint8 array");

        let result: StringArray = values.iter().map(|opt| opt.map(bgp_origin_name)).collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}
