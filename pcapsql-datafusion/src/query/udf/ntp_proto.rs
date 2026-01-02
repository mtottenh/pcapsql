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
use pcapsql_core::protocol::{ntp_mode as mode, ntp_stratum as stratum};

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
            signature: Signature::exact(vec![DataType::UInt8], Volatility::Immutable),
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

        let result: StringArray = values.iter().map(|opt| opt.map(ntp_mode_to_name)).collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

fn ntp_mode_to_name(m: u8) -> String {
    match m {
        mode::RESERVED => "Reserved".to_string(),
        mode::SYMMETRIC_ACTIVE => "Symmetric Active".to_string(),
        mode::SYMMETRIC_PASSIVE => "Symmetric Passive".to_string(),
        mode::CLIENT => "Client".to_string(),
        mode::SERVER => "Server".to_string(),
        mode::BROADCAST => "Broadcast".to_string(),
        mode::CONTROL => "NTP Control".to_string(),
        mode::PRIVATE => "Private".to_string(),
        _ => format!("Unknown ({m})"),
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
            signature: Signature::exact(vec![DataType::UInt8], Volatility::Immutable),
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
            .map(|opt| opt.map(ntp_stratum_to_name))
            .collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

fn ntp_stratum_to_name(s: u8) -> String {
    match s {
        stratum::UNSPECIFIED => "Unspecified".to_string(),
        stratum::PRIMARY => "Primary Reference".to_string(),
        2..=15 => format!("Secondary (stratum {s})"),
        stratum::UNSYNCHRONIZED => "Unsynchronized".to_string(),
        _ => format!("Reserved ({s})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntp_mode_name() {
        assert_eq!(ntp_mode_to_name(mode::RESERVED), "Reserved");
        assert_eq!(ntp_mode_to_name(mode::SYMMETRIC_ACTIVE), "Symmetric Active");
        assert_eq!(
            ntp_mode_to_name(mode::SYMMETRIC_PASSIVE),
            "Symmetric Passive"
        );
        assert_eq!(ntp_mode_to_name(mode::CLIENT), "Client");
        assert_eq!(ntp_mode_to_name(mode::SERVER), "Server");
        assert_eq!(ntp_mode_to_name(mode::BROADCAST), "Broadcast");
        assert_eq!(ntp_mode_to_name(mode::CONTROL), "NTP Control");
        assert_eq!(ntp_mode_to_name(mode::PRIVATE), "Private");
        assert_eq!(ntp_mode_to_name(8), "Unknown (8)");
    }

    #[test]
    fn test_ntp_stratum_name() {
        assert_eq!(ntp_stratum_to_name(stratum::UNSPECIFIED), "Unspecified");
        assert_eq!(ntp_stratum_to_name(stratum::PRIMARY), "Primary Reference");
        assert_eq!(ntp_stratum_to_name(2), "Secondary (stratum 2)");
        assert_eq!(ntp_stratum_to_name(15), "Secondary (stratum 15)");
        assert_eq!(
            ntp_stratum_to_name(stratum::UNSYNCHRONIZED),
            "Unsynchronized"
        );
        assert_eq!(ntp_stratum_to_name(17), "Reserved (17)");
    }
}
