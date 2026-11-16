//! Hex/Binary UDFs.
//!
//! Provides functions for converting between binary data and hexadecimal strings.

use std::sync::Arc;

use arrow::array::{Array, BinaryArray, StringBuilder};
use arrow::datatypes::DataType;
use datafusion::common::Result as DFResult;
use datafusion::logical_expr::{
    ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, Volatility,
};
use pcapsql_core::format::{parse_hex, write_hex};

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

#[derive(Debug, PartialEq, Eq, Hash)]
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

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let binary_values = args[0]
            .as_any()
            .downcast_ref::<BinaryArray>()
            .expect("hex: expected binary array");

        let mut result =
            StringBuilder::with_capacity(binary_values.len(), binary_values.value_data().len() * 2);
        for bytes in binary_values.iter() {
            match bytes {
                Some(bytes) => {
                    // The kernel writes straight into the builder's value
                    // buffer; the empty append closes the row.
                    write_hex(bytes, &mut result)
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
// unhex() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
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

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let hex_values = super::string_arg(&args[0], "unhex")?;

        let result: BinaryArray = hex_values
            .iter()
            .map(|opt| opt.and_then(parse_hex))
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}
