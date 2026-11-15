//! TCP flag UDFs.
//!
//! Provides functions for working with TCP flags stored as UInt16 bitmaps.

use std::sync::Arc;

use arrow::array::{Array, BooleanArray, StringBuilder, UInt16Array};
use arrow::datatypes::DataType;
use datafusion::common::Result as DFResult;
use datafusion::logical_expr::{
    ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, Volatility,
};
use pcapsql_core::format::{has_tcp_flag, write_tcp_flags};

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
            signature: super::coercible_signature(&[DataType::UInt16], Volatility::Immutable),
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

        // "FIN,SYN,RST,PSH,ACK,URG,ECE,CWR,NS" is 34 bytes; most rows are
        // one or two flags.
        let mut result = StringBuilder::with_capacity(flags_values.len(), flags_values.len() * 8);
        for flags in flags_values.iter() {
            match flags {
                Some(flags) => {
                    // The kernel writes straight into the builder's value
                    // buffer; the empty append closes the row.
                    write_tcp_flags(flags, &mut result)
                        .expect("writing to a StringBuilder does not fail");
                    result.append_value("");
                }
                None => result.append_null(),
            }
        }

        Ok(ColumnarValue::Array(Arc::new(result.finish())))
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
            signature: super::coercible_signature(
                &[DataType::UInt16, DataType::Utf8],
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
        let name_values = super::string_arg(&args[1], "has_tcp_flag")?;

        let result: BooleanArray = flags_values
            .iter()
            .zip(name_values.iter())
            .map(|(flags_opt, name_opt)| match (flags_opt, name_opt) {
                (Some(flags), Some(name)) => Some(has_tcp_flag(flags, name)),
                _ => None,
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}
