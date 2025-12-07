//! Hex/Binary UDFs.
//!
//! Provides functions for converting between binary data and hexadecimal strings.

use std::sync::Arc;

use arrow::array::{Array, BinaryArray, StringArray};
use arrow::datatypes::DataType;
use datafusion::common::Result as DFResult;
use datafusion::logical_expr::{ColumnarValue, ScalarUDF, ScalarUDFImpl, Signature, Volatility};

/// Create the `hex()` UDF that converts binary data to hexadecimal string.
///
/// # Example
/// ```sql
/// SELECT hex(raw_data) FROM frames LIMIT 1;
/// -- Returns: "ffffffffffff001122334455..."
/// ```
pub fn create_hex_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(HexUdf::new())
}

/// Create the `unhex()` UDF that parses hexadecimal string to binary.
///
/// # Example
/// ```sql
/// SELECT * FROM frames WHERE raw_data LIKE unhex('ffffffffffff') || '%';
/// ```
pub fn create_unhex_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(UnhexUdf::new())
}

// ============================================================================
// hex() UDF Implementation
// ============================================================================

#[derive(Debug)]
struct HexUdf {
    signature: Signature,
}

impl HexUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::Binary], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for HexUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "hex"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Utf8)
    }

    fn invoke(&self, args: &[ColumnarValue]) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(args)?;
        let binary_values = args[0]
            .as_any()
            .downcast_ref::<BinaryArray>()
            .expect("hex: expected binary array");

        let result: StringArray = binary_values
            .iter()
            .map(|opt| opt.map(bytes_to_hex))
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

/// Convert bytes to lowercase hexadecimal string.
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ============================================================================
// unhex() UDF Implementation
// ============================================================================

#[derive(Debug)]
struct UnhexUdf {
    signature: Signature,
}

impl UnhexUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::Utf8], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for UnhexUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "unhex"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Binary)
    }

    fn invoke(&self, args: &[ColumnarValue]) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(args)?;
        let hex_values = args[0]
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("unhex: expected string array");

        let result: BinaryArray = hex_values
            .iter()
            .map(|opt| opt.and_then(hex_to_bytes))
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

/// Parse hexadecimal string to bytes (case-insensitive).
/// Returns None if the string is invalid.
fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim();

    // Handle optional "0x" prefix
    let hex = hex.strip_prefix("0x").or_else(|| hex.strip_prefix("0X")).unwrap_or(hex);

    // Must have even number of characters
    if !hex.len().is_multiple_of(2) {
        return None;
    }

    // Must only contain valid hex characters
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    let bytes: Option<Vec<u8>> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect();

    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_hex() {
        assert_eq!(bytes_to_hex(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), "ffffffffffff");
        assert_eq!(bytes_to_hex(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]), "001122334455");
        assert_eq!(bytes_to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(bytes_to_hex(&[]), "");
    }

    #[test]
    fn test_hex_to_bytes() {
        assert_eq!(
            hex_to_bytes("ffffffffffff"),
            Some(vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
        );
        assert_eq!(
            hex_to_bytes("001122334455"),
            Some(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
        assert_eq!(hex_to_bytes("deadbeef"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(hex_to_bytes("DEADBEEF"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(hex_to_bytes("DeAdBeEf"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(hex_to_bytes(""), Some(vec![]));
    }

    #[test]
    fn test_hex_to_bytes_with_prefix() {
        assert_eq!(hex_to_bytes("0xdeadbeef"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(hex_to_bytes("0XDEADBEEF"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
    }

    #[test]
    fn test_hex_to_bytes_invalid() {
        // Odd length
        assert_eq!(hex_to_bytes("deadbee"), None);
        // Invalid characters
        assert_eq!(hex_to_bytes("deadbeeg"), None);
        assert_eq!(hex_to_bytes("hello"), None);
    }

    #[test]
    fn test_hex_to_bytes_whitespace() {
        assert_eq!(hex_to_bytes("  deadbeef  "), Some(vec![0xde, 0xad, 0xbe, 0xef]));
    }

    #[test]
    fn test_roundtrip() {
        let original = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let hex = bytes_to_hex(&original);
        let result = hex_to_bytes(&hex).unwrap();
        assert_eq!(original, result);
    }
}
