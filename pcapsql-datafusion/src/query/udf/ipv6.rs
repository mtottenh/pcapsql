//! IPv6 address UDFs.
//!
//! Provides functions for converting and querying IPv6 addresses stored as FixedSizeBinary(16).

use std::sync::Arc;

use arrow::array::{Array, BooleanArray, FixedSizeBinaryArray, StringArray};
use arrow::datatypes::DataType;
use datafusion::common::Result as DFResult;
use datafusion::logical_expr::{
    ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, Volatility,
};
use pcapsql_core::format::{
    format_ipv6, ipv6_in_prefix, is_link_local_ipv6, is_multicast_ipv6, parse_cidr_v6, parse_ipv6,
};

/// Create the `ip6()` UDF that converts an IPv6 string to FixedSizeBinary(16).
///
/// # Example
/// ```sql
/// SELECT * FROM ipv6 WHERE src_ip = ip6('fe80::1');
/// ```
pub fn create_ip6_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(Ip6Udf::new())
}

/// Create the `ip6_to_string()` UDF that converts a FixedSizeBinary(16) to IPv6 string.
///
/// # Example
/// ```sql
/// SELECT ip6_to_string(src_ip) AS src FROM ipv6;
/// ```
pub fn create_ip6_to_string_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(Ip6ToStringUdf::new())
}

/// Create the `ip6_in_cidr()` UDF that checks if an IPv6 is in a CIDR prefix.
///
/// # Example
/// ```sql
/// SELECT * FROM ipv6 WHERE ip6_in_cidr(src_ip, '2001:db8::/32');
/// ```
pub fn create_ip6_in_cidr_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(Ip6InCidrUdf::new())
}

/// Create the `is_link_local_ip6()` UDF that checks if an IPv6 is link-local.
///
/// # Example
/// ```sql
/// SELECT * FROM ipv6 WHERE is_link_local_ip6(src_ip);
/// -- Matches: fe80::/10
/// ```
pub fn create_is_link_local_ip6_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(IsLinkLocalIp6Udf::new())
}

/// Create the `is_multicast_ip6()` UDF that checks if an IPv6 is multicast.
///
/// # Example
/// ```sql
/// SELECT * FROM ipv6 WHERE is_multicast_ip6(dst_ip);
/// -- Matches: ff00::/8
/// ```
pub fn create_is_multicast_ip6_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(IsMulticastIp6Udf::new())
}

// ============================================================================
// ip6() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct Ip6Udf {
    signature: Signature,
}

impl Ip6Udf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::Utf8], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for Ip6Udf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "ip6"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::FixedSizeBinary(16))
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let ip_strings = super::string_arg(&args[0], "ip6")?;

        let values: Vec<Option<[u8; 16]>> = ip_strings
            .iter()
            .map(|opt| opt.and_then(parse_ipv6))
            .collect();

        let result = FixedSizeBinaryArray::try_from_sparse_iter_with_size(
            values.iter().map(|v| v.as_ref().map(|arr| arr.as_slice())),
            16,
        )
        .expect("Failed to create FixedSizeBinaryArray");

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// ip6_to_string() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct Ip6ToStringUdf {
    signature: Signature,
}

impl Ip6ToStringUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::FixedSizeBinary(16)], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for Ip6ToStringUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "ip6_to_string"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Utf8)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let ip_values = args[0]
            .as_any()
            .downcast_ref::<FixedSizeBinaryArray>()
            .expect("ip6_to_string: expected FixedSizeBinary(16) array");

        let result: StringArray = (0..ip_values.len())
            .map(|i| {
                if ip_values.is_null(i) {
                    None
                } else {
                    Some(format_ipv6(ip_values.value(i)).expect("Expected 16 bytes"))
                }
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// ip6_in_cidr() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct Ip6InCidrUdf {
    signature: Signature,
}

impl Ip6InCidrUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(
                vec![DataType::FixedSizeBinary(16), DataType::Utf8],
                Volatility::Immutable,
            ),
        }
    }
}

impl ScalarUDFImpl for Ip6InCidrUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "ip6_in_cidr"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Boolean)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let ip_values = args[0]
            .as_any()
            .downcast_ref::<FixedSizeBinaryArray>()
            .expect("ip6_in_cidr: expected FixedSizeBinary(16) array for IP");
        let cidr_values = super::string_arg(&args[1], "ip6_in_cidr")?;

        let result: BooleanArray = (0..ip_values.len())
            .zip(cidr_values.iter())
            .map(|(i, cidr_opt)| {
                if ip_values.is_null(i) {
                    return None;
                }
                let ip_bytes = ip_values.value(i);

                match cidr_opt {
                    Some(cidr) => parse_cidr_v6(cidr).map(|(network, prefix_len)| {
                        ipv6_in_prefix(ip_bytes, &network, prefix_len)
                    }),
                    None => None,
                }
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// is_link_local_ip6() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct IsLinkLocalIp6Udf {
    signature: Signature,
}

impl IsLinkLocalIp6Udf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::FixedSizeBinary(16)], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for IsLinkLocalIp6Udf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "is_link_local_ip6"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Boolean)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let ip_values = args[0]
            .as_any()
            .downcast_ref::<FixedSizeBinaryArray>()
            .expect("is_link_local_ip6: expected FixedSizeBinary(16) array");

        let result: BooleanArray = (0..ip_values.len())
            .map(|i| {
                if ip_values.is_null(i) {
                    None
                } else {
                    Some(is_link_local_ipv6(ip_values.value(i)))
                }
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// is_multicast_ip6() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct IsMulticastIp6Udf {
    signature: Signature,
}

impl IsMulticastIp6Udf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::FixedSizeBinary(16)], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for IsMulticastIp6Udf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "is_multicast_ip6"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Boolean)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let ip_values = args[0]
            .as_any()
            .downcast_ref::<FixedSizeBinaryArray>()
            .expect("is_multicast_ip6: expected FixedSizeBinary(16) array");

        let result: BooleanArray = (0..ip_values.len())
            .map(|i| {
                if ip_values.is_null(i) {
                    None
                } else {
                    Some(is_multicast_ipv6(ip_values.value(i)))
                }
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}
