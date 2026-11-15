//! NTP protocol UDFs.
//!
//! Provides functions for converting NTP mode and stratum values to human-readable names.
//! Uses protocol constants from pcapsql-core for consistency.

use std::sync::Arc;

use arrow::array::{Array, StringArray, UInt8Array};
use arrow::datatypes::DataType;
use datafusion::common::Result as DFResult;
use datafusion::logical_expr::{
    ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, Volatility,
};
use pcapsql_core::format::{ntp_mode_name, ntp_stratum_name};

/// Create the `ntp_mode_name()` UDF.
///
/// # Example
/// ```sql
/// SELECT ntp_mode_name(mode) FROM ntp;
/// -- Returns: "Client", "Server", "Broadcast", etc.
/// ```
pub fn create_ntp_mode_name_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(NtpModeNameUdf::new())
}

/// Create the `ntp_stratum_name()` UDF.
///
/// # Example
/// ```sql
/// SELECT ntp_stratum_name(stratum) FROM ntp;
/// -- Returns: "Unspecified", "Primary Reference", "Secondary", etc.
/// ```
pub fn create_ntp_stratum_name_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(NtpStratumNameUdf::new())
}

// ============================================================================
// ntp_mode_name() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct NtpModeNameUdf {
    signature: Signature,
}

impl NtpModeNameUdf {
    fn new() -> Self {
        Self {
            signature: super::coercible_signature(&[DataType::UInt8], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for NtpModeNameUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "ntp_mode_name"
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
            .expect("ntp_mode_name: expected uint8 array");

        let result: StringArray = values
            .iter()
            .map(|opt| opt.map(|code| ntp_mode_name(code).into_cow()))
            .collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// ntp_stratum_name() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct NtpStratumNameUdf {
    signature: Signature,
}

impl NtpStratumNameUdf {
    fn new() -> Self {
        Self {
            signature: super::coercible_signature(&[DataType::UInt8], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for NtpStratumNameUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "ntp_stratum_name"
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
            .expect("ntp_stratum_name: expected uint8 array");

        let result: StringArray = values
            .iter()
            .map(|opt| opt.map(|code| ntp_stratum_name(code).into_cow()))
            .collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}
