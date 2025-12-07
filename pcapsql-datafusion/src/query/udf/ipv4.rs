//! IPv4 address UDFs.
//!
//! Provides functions for converting and querying IPv4 addresses stored as UInt32.

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;

use arrow::array::{Array, BooleanArray, StringArray, UInt32Array};
use arrow::datatypes::DataType;
use datafusion::common::Result as DFResult;
use datafusion::logical_expr::{ColumnarValue, ScalarUDF, ScalarUDFImpl, Signature, Volatility};

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

// ============================================================================
// ip4() UDF Implementation
// ============================================================================

#[derive(Debug)]
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

    fn invoke(&self, args: &[ColumnarValue]) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(args)?;
        let ip_strings = args[0]
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("ip4: expected string array");

        let result: UInt32Array = ip_strings
            .iter()
            .map(|opt| {
                opt.and_then(|s| {
                    Ipv4Addr::from_str(s)
                        .ok()
                        .map(|addr| u32::from_be_bytes(addr.octets()))
                })
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// ip4_to_string() UDF Implementation
// ============================================================================

#[derive(Debug)]
struct Ip4ToStringUdf {
    signature: Signature,
}

impl Ip4ToStringUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::UInt32], Volatility::Immutable),
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

    fn invoke(&self, args: &[ColumnarValue]) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(args)?;
        let ip_values = args[0]
            .as_any()
            .downcast_ref::<UInt32Array>()
            .expect("ip4_to_string: expected uint32 array");

        let result: StringArray = ip_values
            .iter()
            .map(|opt| {
                opt.map(|v| {
                    let bytes = v.to_be_bytes();
                    Ipv4Addr::from(bytes).to_string()
                })
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// ip_in_cidr() UDF Implementation
// ============================================================================

#[derive(Debug)]
struct IpInCidrUdf {
    signature: Signature,
}

impl IpInCidrUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(
                vec![DataType::UInt32, DataType::Utf8],
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

    fn invoke(&self, args: &[ColumnarValue]) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(args)?;
        let ip_values = args[0]
            .as_any()
            .downcast_ref::<UInt32Array>()
            .expect("ip_in_cidr: expected uint32 array for IP");
        let cidr_values = args[1]
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("ip_in_cidr: expected string array for CIDR");

        let result: BooleanArray = ip_values
            .iter()
            .zip(cidr_values.iter())
            .map(|(ip_opt, cidr_opt)| {
                match (ip_opt, cidr_opt) {
                    (Some(ip), Some(cidr)) => {
                        // Parse CIDR notation: "192.168.0.0/16"
                        parse_cidr_v4(cidr).map(|(network, prefix_len)| {
                            let mask = if prefix_len == 0 {
                                0
                            } else {
                                !0u32 << (32 - prefix_len)
                            };
                            (ip & mask) == (network & mask)
                        })
                    }
                    _ => None,
                }
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

/// Parse CIDR notation (e.g., "192.168.0.0/16") into (network_address, prefix_length)
fn parse_cidr_v4(cidr: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let addr = Ipv4Addr::from_str(parts[0]).ok()?;
    let prefix_len: u32 = parts[1].parse().ok()?;

    if prefix_len > 32 {
        return None;
    }

    Some((u32::from_be_bytes(addr.octets()), prefix_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4() {
        let addr = Ipv4Addr::from_str("192.168.1.1").unwrap();
        let packed = u32::from_be_bytes(addr.octets());
        assert_eq!(packed, 0xC0A80101); // 192.168.1.1 in hex
    }

    #[test]
    fn test_unpack_ipv4() {
        let packed: u32 = 0xC0A80101;
        let addr = Ipv4Addr::from(packed.to_be_bytes());
        assert_eq!(addr.to_string(), "192.168.1.1");
    }

    #[test]
    fn test_parse_cidr_v4() {
        let (network, prefix) = parse_cidr_v4("192.168.0.0/16").unwrap();
        assert_eq!(prefix, 16);
        assert_eq!(network, 0xC0A80000);
    }

    #[test]
    fn test_cidr_matching() {
        let (network, prefix_len) = parse_cidr_v4("192.168.0.0/16").unwrap();
        let mask = !0u32 << (32 - prefix_len);

        // Should match
        let ip1 = u32::from_be_bytes(Ipv4Addr::from_str("192.168.1.1").unwrap().octets());
        assert_eq!((ip1 & mask), (network & mask));

        // Should not match
        let ip2 = u32::from_be_bytes(Ipv4Addr::from_str("10.0.0.1").unwrap().octets());
        assert_ne!((ip2 & mask), (network & mask));
    }
}
