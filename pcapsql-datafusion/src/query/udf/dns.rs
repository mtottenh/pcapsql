//! DNS UDFs.
//!
//! Provides functions for converting DNS type, rcode, and class values to human-readable names.

use std::sync::Arc;

use arrow::array::{Array, StringArray, UInt16Array, UInt8Array};
use arrow::datatypes::DataType;
use datafusion::common::Result as DFResult;
use datafusion::logical_expr::{
    ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, Volatility,
};
use pcapsql_core::format::{dns_class_name, dns_rcode_name, dns_type_name};

/// Create the `dns_type_name()` UDF that converts DNS query type number to name.
///
/// # Example
/// ```sql
/// SELECT dns_type_name(query_type) FROM dns;
/// -- Returns: "A", "AAAA", "CNAME", "MX", etc.
/// ```
pub fn create_dns_type_name_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(DnsTypeNameUdf::new())
}

/// Create the `dns_rcode_name()` UDF that converts DNS response code to name.
///
/// # Example
/// ```sql
/// SELECT dns_rcode_name(response_code) FROM dns WHERE NOT is_query;
/// -- Returns: "NOERROR", "NXDOMAIN", "SERVFAIL", etc.
/// ```
pub fn create_dns_rcode_name_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(DnsRcodeNameUdf::new())
}

/// Create the `dns_class_name()` UDF that converts DNS class to name.
///
/// # Example
/// ```sql
/// SELECT dns_class_name(query_class) FROM dns;
/// -- Returns: "IN", "CH", "HS", "ANY"
/// ```
pub fn create_dns_class_name_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(DnsClassNameUdf::new())
}

// ============================================================================
// dns_type_name() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct DnsTypeNameUdf {
    signature: Signature,
}

impl DnsTypeNameUdf {
    fn new() -> Self {
        Self {
            signature: super::coercible_signature(&[DataType::UInt16], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for DnsTypeNameUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "dns_type_name"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Utf8)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let type_values = args[0]
            .as_any()
            .downcast_ref::<UInt16Array>()
            .expect("dns_type_name: expected uint16 array");

        let result: StringArray = type_values
            .iter()
            .map(|opt| opt.map(|code| dns_type_name(code).into_cow()))
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// dns_rcode_name() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct DnsRcodeNameUdf {
    signature: Signature,
}

impl DnsRcodeNameUdf {
    fn new() -> Self {
        Self {
            signature: super::coercible_signature(&[DataType::UInt8], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for DnsRcodeNameUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "dns_rcode_name"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Utf8)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let rcode_values = args[0]
            .as_any()
            .downcast_ref::<UInt8Array>()
            .expect("dns_rcode_name: expected uint8 array");

        let result: StringArray = rcode_values
            .iter()
            .map(|opt| opt.map(|rcode| dns_rcode_name(u16::from(rcode)).into_cow()))
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// dns_class_name() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct DnsClassNameUdf {
    signature: Signature,
}

impl DnsClassNameUdf {
    fn new() -> Self {
        Self {
            signature: super::coercible_signature(&[DataType::UInt16], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for DnsClassNameUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "dns_class_name"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Utf8)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let class_values = args[0]
            .as_any()
            .downcast_ref::<UInt16Array>()
            .expect("dns_class_name: expected uint16 array");

        let result: StringArray = class_values
            .iter()
            .map(|opt| opt.map(|code| dns_class_name(code).into_cow()))
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}
