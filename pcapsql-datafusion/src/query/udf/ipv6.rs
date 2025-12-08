//! IPv6 address UDFs.
//!
//! Provides functions for converting and querying IPv6 addresses stored as FixedSizeBinary(16).

use std::net::Ipv6Addr;
use std::str::FromStr;
use std::sync::Arc;

use arrow::array::{Array, BooleanArray, FixedSizeBinaryArray, StringArray};
use arrow::datatypes::DataType;
use datafusion::common::Result as DFResult;
use datafusion::logical_expr::{
    ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, Volatility,
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
        let ip_strings = args[0]
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("ip6: expected string array");

        let values: Vec<Option<[u8; 16]>> = ip_strings
            .iter()
            .map(|opt| {
                opt.and_then(|s| Ipv6Addr::from_str(s).ok().map(|addr| addr.octets()))
            })
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
                    let bytes = ip_values.value(i);
                    let octets: [u8; 16] = bytes.try_into().expect("Expected 16 bytes");
                    Some(Ipv6Addr::from(octets).to_string())
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
        let cidr_values = args[1]
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("ip6_in_cidr: expected string array for CIDR");

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

/// Parse CIDR notation (e.g., "2001:db8::/32") into (network_address, prefix_length)
fn parse_cidr_v6(cidr: &str) -> Option<([u8; 16], u32)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let addr = Ipv6Addr::from_str(parts[0]).ok()?;
    let prefix_len: u32 = parts[1].parse().ok()?;

    if prefix_len > 128 {
        return None;
    }

    Some((addr.octets(), prefix_len))
}

/// Check if an IPv6 address is within a prefix
fn ipv6_in_prefix(ip: &[u8], network: &[u8; 16], prefix_len: u32) -> bool {
    if ip.len() != 16 {
        return false;
    }

    let full_bytes = (prefix_len / 8) as usize;
    let remaining_bits = (prefix_len % 8) as u8;

    // Check full bytes
    if ip[..full_bytes] != network[..full_bytes] {
        return false;
    }

    // Check remaining bits
    if remaining_bits > 0 && full_bytes < 16 {
        let mask = !0u8 << (8 - remaining_bits);
        if (ip[full_bytes] & mask) != (network[full_bytes] & mask) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv6() {
        let addr = Ipv6Addr::from_str("2001:db8::1").unwrap();
        let bytes = addr.octets();
        assert_eq!(bytes[0], 0x20);
        assert_eq!(bytes[1], 0x01);
        assert_eq!(bytes[15], 0x01);
    }

    #[test]
    fn test_parse_cidr_v6() {
        let (network, prefix) = parse_cidr_v6("2001:db8::/32").unwrap();
        assert_eq!(prefix, 32);
        assert_eq!(network[0], 0x20);
        assert_eq!(network[1], 0x01);
    }

    #[test]
    fn test_ipv6_in_prefix() {
        let (network, prefix_len) = parse_cidr_v6("2001:db8::/32").unwrap();

        // Should match
        let ip1 = Ipv6Addr::from_str("2001:db8::1").unwrap().octets();
        assert!(ipv6_in_prefix(&ip1, &network, prefix_len));

        // Should not match
        let ip2 = Ipv6Addr::from_str("fe80::1").unwrap().octets();
        assert!(!ipv6_in_prefix(&ip2, &network, prefix_len));
    }
}
