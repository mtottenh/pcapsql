//! MAC address UDFs.
//!
//! Provides functions for converting MAC addresses stored as FixedSizeBinary(6).

use std::sync::Arc;

use arrow::array::{Array, FixedSizeBinaryArray, StringArray};
use arrow::datatypes::DataType;
use datafusion::common::Result as DFResult;
use datafusion::logical_expr::{ColumnarValue, ScalarUDF, ScalarUDFImpl, Signature, Volatility};

/// Create the `mac()` UDF that converts a MAC address string to FixedSizeBinary(6).
///
/// Supports formats:
/// - Colon-separated: `aa:bb:cc:dd:ee:ff`
/// - Hyphen-separated: `aa-bb-cc-dd-ee-ff`
/// - No separator: `aabbccddeeff`
///
/// # Example
/// ```sql
/// SELECT * FROM ethernet WHERE src_mac = mac('aa:bb:cc:dd:ee:ff');
/// ```
pub fn create_mac_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(MacUdf::new())
}

/// Create the `mac_to_string()` UDF that converts a FixedSizeBinary(6) to MAC string.
///
/// # Example
/// ```sql
/// SELECT mac_to_string(src_mac) AS src FROM ethernet;
/// ```
pub fn create_mac_to_string_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(MacToStringUdf::new())
}

// ============================================================================
// mac() UDF Implementation
// ============================================================================

#[derive(Debug)]
struct MacUdf {
    signature: Signature,
}

impl MacUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::Utf8], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for MacUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "mac"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::FixedSizeBinary(6))
    }

    fn invoke(&self, args: &[ColumnarValue]) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(args)?;
        let mac_strings = args[0]
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("mac: expected string array");

        let values: Vec<Option<[u8; 6]>> = mac_strings
            .iter()
            .map(|opt| opt.and_then(parse_mac_address))
            .collect();

        let result = FixedSizeBinaryArray::try_from_sparse_iter_with_size(
            values.iter().map(|v| v.as_ref().map(|arr| arr.as_slice())),
            6,
        )
        .expect("Failed to create FixedSizeBinaryArray");

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// mac_to_string() UDF Implementation
// ============================================================================

#[derive(Debug)]
struct MacToStringUdf {
    signature: Signature,
}

impl MacToStringUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::FixedSizeBinary(6)], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for MacToStringUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "mac_to_string"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Utf8)
    }

    fn invoke(&self, args: &[ColumnarValue]) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(args)?;
        let mac_values = args[0]
            .as_any()
            .downcast_ref::<FixedSizeBinaryArray>()
            .expect("mac_to_string: expected FixedSizeBinary(6) array");

        let result: StringArray = (0..mac_values.len())
            .map(|i| {
                if mac_values.is_null(i) {
                    None
                } else {
                    let bytes = mac_values.value(i);
                    Some(format_mac_address(bytes))
                }
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

/// Parse a MAC address string into 6 bytes.
///
/// Supports formats:
/// - Colon-separated: `aa:bb:cc:dd:ee:ff`
/// - Hyphen-separated: `aa-bb-cc-dd-ee-ff`
/// - No separator: `aabbccddeeff`
fn parse_mac_address(s: &str) -> Option<[u8; 6]> {
    let s = s.trim();

    // Try colon-separated
    if s.contains(':') {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() == 6 {
            let bytes: Option<Vec<u8>> = parts
                .iter()
                .map(|p| u8::from_str_radix(p, 16).ok())
                .collect();
            if let Some(b) = bytes {
                if b.len() == 6 {
                    return Some([b[0], b[1], b[2], b[3], b[4], b[5]]);
                }
            }
        }
        return None;
    }

    // Try hyphen-separated
    if s.contains('-') {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() == 6 {
            let bytes: Option<Vec<u8>> = parts
                .iter()
                .map(|p| u8::from_str_radix(p, 16).ok())
                .collect();
            if let Some(b) = bytes {
                if b.len() == 6 {
                    return Some([b[0], b[1], b[2], b[3], b[4], b[5]]);
                }
            }
        }
        return None;
    }

    // Try no separator (12 hex chars)
    if s.len() == 12 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes: Option<Vec<u8>> = (0..6)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
            .collect();
        if let Some(b) = bytes {
            if b.len() == 6 {
                return Some([b[0], b[1], b[2], b[3], b[4], b[5]]);
            }
        }
    }

    None
}

/// Format MAC address bytes as colon-separated string
fn format_mac_address(bytes: &[u8]) -> String {
    if bytes.len() != 6 {
        return String::new();
    }
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac_colon() {
        let result = parse_mac_address("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(result, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_mac_hyphen() {
        let result = parse_mac_address("aa-bb-cc-dd-ee-ff").unwrap();
        assert_eq!(result, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_mac_no_separator() {
        let result = parse_mac_address("aabbccddeeff").unwrap();
        assert_eq!(result, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_format_mac() {
        let bytes = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        assert_eq!(format_mac_address(&bytes), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_roundtrip() {
        let original = "12:34:56:78:9a:bc";
        let bytes = parse_mac_address(original).unwrap();
        let formatted = format_mac_address(&bytes);
        assert_eq!(original, formatted);
    }
}
