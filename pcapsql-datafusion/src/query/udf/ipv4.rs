//! IPv4 address UDFs.
//!
//! Provides functions for converting and querying IPv4 addresses stored as UInt32.

use std::sync::Arc;

use arrow::array::{Array, BooleanArray, StringArray, UInt32Array};
use arrow::datatypes::DataType;
use datafusion::common::Result as DFResult;
use datafusion::logical_expr::{
    ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, Volatility,
};
use pcapsql_core::format::{
    format_ipv4, ipv4_in_cidr, is_loopback_ipv4, is_multicast_ipv4, is_private_ipv4, parse_cidr_v4,
    parse_ipv4,
};

/// Create the `ip4()` UDF that converts an IPv4 string to UInt32.
///
/// # Example
/// ```sql
/// SELECT * FROM ipv4 WHERE src_ip = ip4('192.168.1.1');
/// ```
pub fn create_ip4_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(Ip4Udf::new())
}

/// Create the `ip4_to_string()` UDF that converts a UInt32 to IPv4 string.
///
/// # Example
/// ```sql
/// SELECT ip4_to_string(src_ip) AS src FROM ipv4;
/// ```
pub fn create_ip4_to_string_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(Ip4ToStringUdf::new())
}

/// Create the `ip_in_cidr()` UDF that checks if an IPv4 is in a CIDR range.
///
/// # Example
/// ```sql
/// SELECT * FROM ipv4 WHERE ip_in_cidr(src_ip, '192.168.0.0/16');
/// ```
pub fn create_ip_in_cidr_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(IpInCidrUdf::new())
}

/// Create the `is_private_ip()` UDF that checks if an IPv4 is in RFC1918 private ranges.
///
/// # Example
/// ```sql
/// SELECT * FROM ipv4 WHERE is_private_ip(src_ip);
/// -- Matches: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
/// ```
pub fn create_is_private_ip_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(IsPrivateIpUdf::new())
}

/// Create the `is_multicast_ip()` UDF that checks if an IPv4 is a multicast address.
///
/// # Example
/// ```sql
/// SELECT * FROM ipv4 WHERE is_multicast_ip(dst_ip);
/// -- Matches: 224.0.0.0/4 (224.0.0.0 - 239.255.255.255)
/// ```
pub fn create_is_multicast_ip_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(IsMulticastIpUdf::new())
}

/// Create the `is_loopback_ip()` UDF that checks if an IPv4 is a loopback address.
///
/// # Example
/// ```sql
/// SELECT * FROM ipv4 WHERE is_loopback_ip(src_ip);
/// -- Matches: 127.0.0.0/8
/// ```
pub fn create_is_loopback_ip_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(IsLoopbackIpUdf::new())
}

// ============================================================================
// ip4() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct Ip4Udf {
    signature: Signature,
}

impl Ip4Udf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::Utf8], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for Ip4Udf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "ip4"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::UInt32)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let ip_strings = super::string_arg(&args[0], "ip4")?;

        let result: UInt32Array = ip_strings
            .iter()
            .map(|opt| opt.and_then(parse_ipv4))
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// ip4_to_string() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct Ip4ToStringUdf {
    signature: Signature,
}

impl Ip4ToStringUdf {
    fn new() -> Self {
        Self {
            signature: super::coercible_signature(&[DataType::UInt32], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for Ip4ToStringUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "ip4_to_string"
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
            .downcast_ref::<UInt32Array>()
            .expect("ip4_to_string: expected uint32 array");

        let result: StringArray = ip_values.iter().map(|opt| opt.map(format_ipv4)).collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// ip_in_cidr() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct IpInCidrUdf {
    signature: Signature,
}

impl IpInCidrUdf {
    fn new() -> Self {
        Self {
            signature: super::coercible_signature(
                &[DataType::UInt32, DataType::Utf8],
                Volatility::Immutable,
            ),
        }
    }
}

impl ScalarUDFImpl for IpInCidrUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "ip_in_cidr"
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
            .downcast_ref::<UInt32Array>()
            .expect("ip_in_cidr: expected uint32 array for IP");
        let cidr_values = super::string_arg(&args[1], "ip_in_cidr")?;

        let result: BooleanArray = ip_values
            .iter()
            .zip(cidr_values.iter())
            .map(|(ip_opt, cidr_opt)| {
                match (ip_opt, cidr_opt) {
                    // Parse CIDR notation: "192.168.0.0/16". Invalid
                    // notation gives NULL.
                    (Some(ip), Some(cidr)) => {
                        parse_cidr_v4(cidr).map(|(network, mask)| ipv4_in_cidr(ip, network, mask))
                    }
                    _ => None,
                }
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// is_private_ip() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct IsPrivateIpUdf {
    signature: Signature,
}

impl IsPrivateIpUdf {
    fn new() -> Self {
        Self {
            signature: super::coercible_signature(&[DataType::UInt32], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for IsPrivateIpUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "is_private_ip"
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
            .downcast_ref::<UInt32Array>()
            .expect("is_private_ip: expected uint32 array");

        let result: BooleanArray = ip_values
            .iter()
            .map(|opt| opt.map(is_private_ipv4))
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// is_multicast_ip() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct IsMulticastIpUdf {
    signature: Signature,
}

impl IsMulticastIpUdf {
    fn new() -> Self {
        Self {
            signature: super::coercible_signature(&[DataType::UInt32], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for IsMulticastIpUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "is_multicast_ip"
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
            .downcast_ref::<UInt32Array>()
            .expect("is_multicast_ip: expected uint32 array");

        let result: BooleanArray = ip_values
            .iter()
            .map(|opt| opt.map(is_multicast_ipv4))
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// is_loopback_ip() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct IsLoopbackIpUdf {
    signature: Signature,
}

impl IsLoopbackIpUdf {
    fn new() -> Self {
        Self {
            signature: super::coercible_signature(&[DataType::UInt32], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for IsLoopbackIpUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "is_loopback_ip"
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
            .downcast_ref::<UInt32Array>()
            .expect("is_loopback_ip: expected uint32 array");

        let result: BooleanArray = ip_values
            .iter()
            .map(|opt| opt.map(is_loopback_ipv4))
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}
