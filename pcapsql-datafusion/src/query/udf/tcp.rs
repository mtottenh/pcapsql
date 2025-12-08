//! TCP flag UDFs.
//!
//! Provides functions for working with TCP flags stored as UInt16 bitmaps.

use std::sync::Arc;

use arrow::array::{Array, BooleanArray, StringArray, UInt16Array};
use arrow::datatypes::DataType;
use datafusion::common::Result as DFResult;
use datafusion::logical_expr::{
    ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, Volatility,
};

/// TCP flag bit positions and names.
const TCP_FLAGS: &[(u16, &str)] = &[
    (0x001, "FIN"),
    (0x002, "SYN"),
    (0x004, "RST"),
    (0x008, "PSH"),
    (0x010, "ACK"),
    (0x020, "URG"),
    (0x040, "ECE"),
    (0x080, "CWR"),
    (0x100, "NS"),
];

/// Create the `tcp_flags_str()` UDF that converts TCP flags bitmap to human-readable string.
///
/// # Example
/// ```sql
/// SELECT tcp_flags_str(flags) FROM tcp;
/// -- Returns: "SYN", "SYN,ACK", "FIN,ACK", etc.
/// ```
pub fn create_tcp_flags_str_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(TcpFlagsStrUdf::new())
}

/// Create the `has_tcp_flag()` UDF that checks if a specific flag is set.
///
/// # Example
/// ```sql
/// SELECT * FROM tcp WHERE has_tcp_flag(flags, 'SYN');
/// SELECT * FROM tcp WHERE has_tcp_flag(flags, 'RST');
/// ```
pub fn create_has_tcp_flag_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(HasTcpFlagUdf::new())
}

// ============================================================================
// tcp_flags_str() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct TcpFlagsStrUdf {
    signature: Signature,
}

impl TcpFlagsStrUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::UInt16], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for TcpFlagsStrUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "tcp_flags_str"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Utf8)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let flags_values = args[0]
            .as_any()
            .downcast_ref::<UInt16Array>()
            .expect("tcp_flags_str: expected uint16 array");

        let result: StringArray = flags_values
            .iter()
            .map(|opt| opt.map(format_tcp_flags))
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

/// Convert TCP flags bitmap to comma-separated string.
fn format_tcp_flags(flags: u16) -> String {
    let mut names = Vec::new();
    for &(bit, name) in TCP_FLAGS {
        if flags & bit != 0 {
            names.push(name);
        }
    }
    if names.is_empty() {
        String::new()
    } else {
        names.join(",")
    }
}

// ============================================================================
// has_tcp_flag() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct HasTcpFlagUdf {
    signature: Signature,
}

impl HasTcpFlagUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(
                vec![DataType::UInt16, DataType::Utf8],
                Volatility::Immutable,
            ),
        }
    }
}

impl ScalarUDFImpl for HasTcpFlagUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "has_tcp_flag"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Boolean)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let flags_values = args[0]
            .as_any()
            .downcast_ref::<UInt16Array>()
            .expect("has_tcp_flag: expected uint16 array for flags");
        let name_values = args[1]
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("has_tcp_flag: expected string array for flag name");

        let result: BooleanArray = flags_values
            .iter()
            .zip(name_values.iter())
            .map(|(flags_opt, name_opt)| match (flags_opt, name_opt) {
                (Some(flags), Some(name)) => Some(check_tcp_flag(flags, name)),
                _ => None,
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

/// Check if a specific TCP flag is set (case-insensitive).
fn check_tcp_flag(flags: u16, name: &str) -> bool {
    let name_upper = name.to_uppercase();
    for &(bit, flag_name) in TCP_FLAGS {
        if flag_name == name_upper && flags & bit != 0 {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_flags_str() {
        // SYN only
        assert_eq!(format_tcp_flags(0x002), "SYN");
        // SYN+ACK
        assert_eq!(format_tcp_flags(0x012), "SYN,ACK");
        // FIN+ACK
        assert_eq!(format_tcp_flags(0x011), "FIN,ACK");
        // RST
        assert_eq!(format_tcp_flags(0x004), "RST");
        // All flags
        assert_eq!(
            format_tcp_flags(0x1FF),
            "FIN,SYN,RST,PSH,ACK,URG,ECE,CWR,NS"
        );
        // Empty
        assert_eq!(format_tcp_flags(0x000), "");
    }

    #[test]
    fn test_has_tcp_flag() {
        assert!(check_tcp_flag(0x002, "SYN"));
        assert!(check_tcp_flag(0x002, "syn")); // Case insensitive
        assert!(check_tcp_flag(0x002, "Syn")); // Mixed case
        assert!(!check_tcp_flag(0x002, "ACK"));
        assert!(check_tcp_flag(0x012, "SYN"));
        assert!(check_tcp_flag(0x012, "ACK"));
        assert!(!check_tcp_flag(0x012, "RST"));
    }

    #[test]
    fn test_common_flag_combinations() {
        // SYN (connection initiation)
        assert_eq!(format_tcp_flags(0x002), "SYN");

        // SYN-ACK (connection response)
        assert_eq!(format_tcp_flags(0x012), "SYN,ACK");

        // ACK (acknowledgment)
        assert_eq!(format_tcp_flags(0x010), "ACK");

        // FIN-ACK (graceful close)
        assert_eq!(format_tcp_flags(0x011), "FIN,ACK");

        // RST (reset)
        assert_eq!(format_tcp_flags(0x004), "RST");

        // RST-ACK
        assert_eq!(format_tcp_flags(0x014), "RST,ACK");

        // PSH-ACK (push data)
        assert_eq!(format_tcp_flags(0x018), "PSH,ACK");
    }
}
