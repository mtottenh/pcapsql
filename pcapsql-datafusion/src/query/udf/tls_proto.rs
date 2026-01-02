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
use pcapsql_core::protocol::{tls_record_type as record_type, tls_version as version};

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
            signature: Signature::exact(vec![DataType::UInt16], Volatility::Immutable),
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
            .map(|opt| opt.map(tls_version_to_name))
            .collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

fn tls_version_to_name(ver: u16) -> String {
    match ver {
        version::SSL_2_0 => "SSL 2.0".to_string(),
        version::SSL_3_0 => "SSL 3.0".to_string(),
        version::TLS_1_0 => "TLS 1.0".to_string(),
        version::TLS_1_1 => "TLS 1.1".to_string(),
        version::TLS_1_2 => "TLS 1.2".to_string(),
        version::TLS_1_3 => "TLS 1.3".to_string(),
        // GREASE values (RFC 8701) - pattern 0x?a?a
        v if (v & 0x0f0f) == 0x0a0a => "GREASE".to_string(),
        _ => format!("Unknown (0x{ver:04x})"),
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
            signature: Signature::exact(vec![DataType::UInt8], Volatility::Immutable),
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
            .map(|opt| opt.map(tls_record_type_to_name))
            .collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

fn tls_record_type_to_name(rt: u8) -> String {
    match rt {
        record_type::CHANGE_CIPHER_SPEC => "ChangeCipherSpec".to_string(),
        record_type::ALERT => "Alert".to_string(),
        record_type::HANDSHAKE => "Handshake".to_string(),
        record_type::APPLICATION_DATA => "ApplicationData".to_string(),
        record_type::HEARTBEAT => "Heartbeat".to_string(),
        _ => format!("Unknown ({rt})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_version_name() {
        assert_eq!(tls_version_to_name(version::SSL_2_0), "SSL 2.0");
        assert_eq!(tls_version_to_name(version::SSL_3_0), "SSL 3.0");
        assert_eq!(tls_version_to_name(version::TLS_1_0), "TLS 1.0");
        assert_eq!(tls_version_to_name(version::TLS_1_1), "TLS 1.1");
        assert_eq!(tls_version_to_name(version::TLS_1_2), "TLS 1.2");
        assert_eq!(tls_version_to_name(version::TLS_1_3), "TLS 1.3");
        // GREASE values
        assert_eq!(tls_version_to_name(0x0a0a), "GREASE");
        assert_eq!(tls_version_to_name(0x1a1a), "GREASE");
        assert_eq!(tls_version_to_name(0xfafa), "GREASE");
        // Unknown
        assert_eq!(tls_version_to_name(0x0305), "Unknown (0x0305)");
    }

    #[test]
    fn test_tls_record_type_name() {
        assert_eq!(
            tls_record_type_to_name(record_type::CHANGE_CIPHER_SPEC),
            "ChangeCipherSpec"
        );
        assert_eq!(tls_record_type_to_name(record_type::ALERT), "Alert");
        assert_eq!(tls_record_type_to_name(record_type::HANDSHAKE), "Handshake");
        assert_eq!(
            tls_record_type_to_name(record_type::APPLICATION_DATA),
            "ApplicationData"
        );
        assert_eq!(tls_record_type_to_name(record_type::HEARTBEAT), "Heartbeat");
        assert_eq!(tls_record_type_to_name(99), "Unknown (99)");
    }
}
