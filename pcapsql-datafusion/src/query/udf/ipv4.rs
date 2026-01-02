//! IPv4 address UDFs.
//!
//! Provides functions for converting and querying IPv4 addresses stored as UInt32.

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;

use arrow::array::{Array, BooleanArray, StringArray, UInt32Array};
use arrow::datatypes::DataType;
use datafusion::common::Result as DFResult;
use datafusion::logical_expr::{
    ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, Volatility,
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

#[derive(Debug, PartialEq, Eq, Hash)]
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

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
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

#[derive(Debug, PartialEq, Eq, Hash)]
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

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
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

// ============================================================================
// Classification Helper Functions
// ============================================================================

/// Check if IPv4 address is in RFC1918 private ranges.
/// - 10.0.0.0/8
/// - 172.16.0.0/12
/// - 192.168.0.0/16
fn is_private_ipv4(ip: u32) -> bool {
    let first_octet = (ip >> 24) as u8;
    let second_octet = ((ip >> 16) & 0xFF) as u8;

    // 10.0.0.0/8
    first_octet == 10
        // 172.16.0.0/12 (172.16-31.x.x)
        || (first_octet == 172 && (16..=31).contains(&second_octet))
        // 192.168.0.0/16
        || (first_octet == 192 && second_octet == 168)
}

/// Check if IPv4 address is multicast (224.0.0.0/4).
fn is_multicast_ipv4(ip: u32) -> bool {
    (ip >> 28) == 0xE // First 4 bits = 1110
}

/// Check if IPv4 address is loopback (127.0.0.0/8).
fn is_loopback_ipv4(ip: u32) -> bool {
    (ip >> 24) == 127
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
            signature: Signature::exact(vec![DataType::UInt32], Volatility::Immutable),
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
            signature: Signature::exact(vec![DataType::UInt32], Volatility::Immutable),
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
            signature: Signature::exact(vec![DataType::UInt32], Volatility::Immutable),
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

    // Helper to convert IP string to u32
    fn ip4(s: &str) -> u32 {
        u32::from_be_bytes(Ipv4Addr::from_str(s).unwrap().octets())
    }

    #[test]
    fn test_is_private_ipv4() {
        // 10.0.0.0/8
        assert!(is_private_ipv4(ip4("10.0.0.1")));
        assert!(is_private_ipv4(ip4("10.255.255.255")));

        // 172.16.0.0/12 (172.16-31.x.x)
        assert!(is_private_ipv4(ip4("172.16.0.1")));
        assert!(is_private_ipv4(ip4("172.31.255.255")));
        assert!(!is_private_ipv4(ip4("172.15.255.255"))); // Below range
        assert!(!is_private_ipv4(ip4("172.32.0.1"))); // Above range

        // 192.168.0.0/16
        assert!(is_private_ipv4(ip4("192.168.0.1")));
        assert!(is_private_ipv4(ip4("192.168.255.255")));

        // Public IPs
        assert!(!is_private_ipv4(ip4("8.8.8.8")));
        assert!(!is_private_ipv4(ip4("1.1.1.1")));
        assert!(!is_private_ipv4(ip4("192.169.0.1")));
    }

    #[test]
    fn test_is_multicast_ipv4() {
        // Multicast range: 224.0.0.0 - 239.255.255.255
        assert!(is_multicast_ipv4(ip4("224.0.0.1")));
        assert!(is_multicast_ipv4(ip4("239.255.255.255")));
        assert!(is_multicast_ipv4(ip4("230.1.2.3")));

        // Not multicast
        assert!(!is_multicast_ipv4(ip4("223.255.255.255")));
        assert!(!is_multicast_ipv4(ip4("240.0.0.1"))); // Reserved
        assert!(!is_multicast_ipv4(ip4("192.168.1.1")));
    }

    #[test]
    fn test_is_loopback_ipv4() {
        // Loopback range: 127.0.0.0/8
        assert!(is_loopback_ipv4(ip4("127.0.0.1")));
        assert!(is_loopback_ipv4(ip4("127.255.255.255")));
        assert!(is_loopback_ipv4(ip4("127.0.0.0")));

        // Not loopback
        assert!(!is_loopback_ipv4(ip4("126.255.255.255")));
        assert!(!is_loopback_ipv4(ip4("128.0.0.1")));
        assert!(!is_loopback_ipv4(ip4("192.168.1.1")));
    }
}
