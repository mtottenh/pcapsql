//! GTP protocol UDFs.
//!
//! Provides functions for converting GTP message types to human-readable names.
//! Uses protocol constants from pcapsql-core for consistency.

use std::sync::Arc;

use arrow::array::{Array, StringArray, UInt8Array};
use arrow::datatypes::DataType;
use datafusion::common::Result as DFResult;
use datafusion::logical_expr::{
    ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, Volatility,
};
use pcapsql_core::format::gtp_message_type_name;

/// Create the `gtp_message_type_name()` UDF.
///
/// # Example
/// ```sql
/// SELECT gtp_message_type_name(message_type) FROM gtp;
/// -- Returns: "Echo Request", "Echo Response", "G-PDU", etc.
/// ```
pub fn create_gtp_message_type_name_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(GtpMessageTypeNameUdf::new())
}

// ============================================================================
// gtp_message_type_name() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct GtpMessageTypeNameUdf {
    signature: Signature,
}

impl GtpMessageTypeNameUdf {
    fn new() -> Self {
        Self {
            signature: super::coercible_signature(&[DataType::UInt8], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for GtpMessageTypeNameUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "gtp_message_type_name"
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
            .expect("gtp_message_type_name: expected uint8 array");

        let result: StringArray = values
            .iter()
            .map(|opt| opt.map(gtp_message_type_name))
            .collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}
