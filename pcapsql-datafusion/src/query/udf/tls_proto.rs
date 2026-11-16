//! TLS protocol UDFs.
//!
//! Provides functions for converting TLS version and record types to human-readable names.
//! Uses protocol constants from pcapsql-core for consistency.

use std::sync::Arc;

use arrow::array::{Array, StringArray, UInt16Array, UInt8Array};
use arrow::datatypes::DataType;
use datafusion::common::Result as DFResult;
use datafusion::logical_expr::{
    ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, Volatility,
};
use pcapsql_core::format::{tls_record_type_name, tls_version_name};

/// Create the `tls_version_name()` UDF.
///
/// # Example
/// ```sql
/// SELECT tls_version_name(record_version) FROM tls;
/// -- Returns: "TLS 1.0", "TLS 1.2", "TLS 1.3", etc.
/// ```
pub fn create_tls_version_name_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(TlsVersionNameUdf::new())
}

/// Create the `tls_record_type_name()` UDF.
///
/// # Example
/// ```sql
/// SELECT tls_record_type_name(record_type) FROM tls;
/// -- Returns: "ChangeCipherSpec", "Alert", "Handshake", "ApplicationData"
/// ```
pub fn create_tls_record_type_name_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(TlsRecordTypeNameUdf::new())
}

// ============================================================================
// tls_version_name() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct TlsVersionNameUdf {
    signature: Signature,
}

impl TlsVersionNameUdf {
    fn new() -> Self {
        Self {
            signature: super::coercible_signature(&[DataType::UInt16], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for TlsVersionNameUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "tls_version_name"
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
            .downcast_ref::<UInt16Array>()
            .expect("tls_version_name: expected uint16 array");

        let result: StringArray = values
            .iter()
            .map(|opt| opt.map(|code| tls_version_name(code).into_cow()))
            .collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// tls_record_type_name() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct TlsRecordTypeNameUdf {
    signature: Signature,
}

impl TlsRecordTypeNameUdf {
    fn new() -> Self {
        Self {
            signature: super::coercible_signature(&[DataType::UInt8], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for TlsRecordTypeNameUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "tls_record_type_name"
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
            .expect("tls_record_type_name: expected uint8 array");

        let result: StringArray = values
            .iter()
            .map(|opt| opt.map(|code| tls_record_type_name(code).into_cow()))
            .collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}
