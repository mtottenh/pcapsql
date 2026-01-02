//! BGP protocol UDFs.
//!
//! Provides functions for converting BGP message types and path attributes to human-readable names.
//! Uses protocol constants from pcapsql-core for consistency.

use std::sync::Arc;

use arrow::array::{Array, StringArray, UInt8Array};
use arrow::datatypes::DataType;
use datafusion::common::Result as DFResult;
use datafusion::logical_expr::{
    ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, Volatility,
};
use pcapsql_core::protocol::{bgp_message_type as message_type, bgp_origin_type as origin_type};

/// Create the `bgp_message_type_name()` UDF.
///
/// # Example
/// ```sql
/// SELECT bgp_message_type_name(message_type) FROM bgp;
/// -- Returns: "OPEN", "UPDATE", "NOTIFICATION", "KEEPALIVE", "ROUTE-REFRESH"
/// ```
pub fn create_bgp_message_type_name_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(BgpMessageTypeNameUdf::new())
}

/// Create the `bgp_origin_name()` UDF.
///
/// # Example
/// ```sql
/// SELECT bgp_origin_name(origin) FROM bgp WHERE origin IS NOT NULL;
/// -- Returns: "IGP", "EGP", "INCOMPLETE"
/// ```
pub fn create_bgp_origin_name_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(BgpOriginNameUdf::new())
}

// ============================================================================
// bgp_message_type_name() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct BgpMessageTypeNameUdf {
    signature: Signature,
}

impl BgpMessageTypeNameUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::UInt8], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for BgpMessageTypeNameUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "bgp_message_type_name"
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
            .expect("bgp_message_type_name: expected uint8 array");

        let result: StringArray = values
            .iter()
            .map(|opt| opt.map(bgp_message_type_to_name))
            .collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

fn bgp_message_type_to_name(msg_type: u8) -> String {
    match msg_type {
        message_type::OPEN => "OPEN".to_string(),
        message_type::UPDATE => "UPDATE".to_string(),
        message_type::NOTIFICATION => "NOTIFICATION".to_string(),
        message_type::KEEPALIVE => "KEEPALIVE".to_string(),
        message_type::ROUTE_REFRESH => "ROUTE-REFRESH".to_string(),
        _ => format!("Unknown ({msg_type})"),
    }
}

// ============================================================================
// bgp_origin_name() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct BgpOriginNameUdf {
    signature: Signature,
}

impl BgpOriginNameUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::UInt8], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for BgpOriginNameUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "bgp_origin_name"
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
            .expect("bgp_origin_name: expected uint8 array");

        let result: StringArray = values
            .iter()
            .map(|opt| opt.map(bgp_origin_to_name))
            .collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

fn bgp_origin_to_name(origin: u8) -> String {
    match origin {
        origin_type::IGP => "IGP".to_string(),
        origin_type::EGP => "EGP".to_string(),
        origin_type::INCOMPLETE => "INCOMPLETE".to_string(),
        _ => format!("Unknown ({origin})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bgp_message_type_name() {
        assert_eq!(bgp_message_type_to_name(message_type::OPEN), "OPEN");
        assert_eq!(bgp_message_type_to_name(message_type::UPDATE), "UPDATE");
        assert_eq!(
            bgp_message_type_to_name(message_type::NOTIFICATION),
            "NOTIFICATION"
        );
        assert_eq!(
            bgp_message_type_to_name(message_type::KEEPALIVE),
            "KEEPALIVE"
        );
        assert_eq!(
            bgp_message_type_to_name(message_type::ROUTE_REFRESH),
            "ROUTE-REFRESH"
        );
        assert_eq!(bgp_message_type_to_name(99), "Unknown (99)");
    }

    #[test]
    fn test_bgp_origin_name() {
        assert_eq!(bgp_origin_to_name(origin_type::IGP), "IGP");
        assert_eq!(bgp_origin_to_name(origin_type::EGP), "EGP");
        assert_eq!(bgp_origin_to_name(origin_type::INCOMPLETE), "INCOMPLETE");
        assert_eq!(bgp_origin_to_name(3), "Unknown (3)");
    }
}
