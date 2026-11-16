//! OSPF protocol UDFs.
//!
//! Provides functions for converting OSPF packet types and LSA types to human-readable names.
//! Uses protocol constants from pcapsql-core for consistency.

use std::sync::Arc;

use arrow::array::{Array, StringArray, UInt8Array};
use arrow::datatypes::DataType;
use datafusion::common::Result as DFResult;
use datafusion::logical_expr::{
    ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, Volatility,
};
use pcapsql_core::format::{ospf_lsa_type_name, ospf_packet_type_name};

/// Create the `ospf_packet_type_name()` UDF.
///
/// # Example
/// ```sql
/// SELECT ospf_packet_type_name(message_type) FROM ospf;
/// -- Returns: "Hello", "Database Description", "Link State Request", etc.
/// ```
pub fn create_ospf_packet_type_name_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(OspfPacketTypeNameUdf::new())
}

/// Create the `ospf_lsa_type_name()` UDF.
///
/// # Example
/// ```sql
/// SELECT ospf_lsa_type_name(lsa_type) FROM ospf WHERE lsa_type IS NOT NULL;
/// -- Returns: "Router-LSA", "Network-LSA", "Summary-LSA-Network", etc.
/// ```
pub fn create_ospf_lsa_type_name_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(OspfLsaTypeNameUdf::new())
}

// ============================================================================
// ospf_packet_type_name() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct OspfPacketTypeNameUdf {
    signature: Signature,
}

impl OspfPacketTypeNameUdf {
    fn new() -> Self {
        Self {
            signature: super::coercible_signature(&[DataType::UInt8], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for OspfPacketTypeNameUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "ospf_packet_type_name"
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
            .expect("ospf_packet_type_name: expected uint8 array");

        let result: StringArray = values
            .iter()
            .map(|opt| opt.map(ospf_packet_type_name))
            .collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// ospf_lsa_type_name() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct OspfLsaTypeNameUdf {
    signature: Signature,
}

impl OspfLsaTypeNameUdf {
    fn new() -> Self {
        Self {
            signature: super::coercible_signature(&[DataType::UInt8], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for OspfLsaTypeNameUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "ospf_lsa_type_name"
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
            .expect("ospf_lsa_type_name: expected uint8 array");

        let result: StringArray = values
            .iter()
            .map(|opt| opt.map(ospf_lsa_type_name))
            .collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}
