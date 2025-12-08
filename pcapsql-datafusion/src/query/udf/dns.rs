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
            signature: Signature::exact(vec![DataType::UInt16], Volatility::Immutable),
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
            .map(|opt| opt.map(dns_type_to_name))
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

/// Convert DNS type number to name.
fn dns_type_to_name(qtype: u16) -> String {
    match qtype {
        1 => "A".to_string(),
        2 => "NS".to_string(),
        5 => "CNAME".to_string(),
        6 => "SOA".to_string(),
        12 => "PTR".to_string(),
        15 => "MX".to_string(),
        16 => "TXT".to_string(),
        17 => "RP".to_string(),
        18 => "AFSDB".to_string(),
        24 => "SIG".to_string(),
        25 => "KEY".to_string(),
        28 => "AAAA".to_string(),
        29 => "LOC".to_string(),
        33 => "SRV".to_string(),
        35 => "NAPTR".to_string(),
        36 => "KX".to_string(),
        37 => "CERT".to_string(),
        39 => "DNAME".to_string(),
        41 => "OPT".to_string(),
        42 => "APL".to_string(),
        43 => "DS".to_string(),
        44 => "SSHFP".to_string(),
        45 => "IPSECKEY".to_string(),
        46 => "RRSIG".to_string(),
        47 => "NSEC".to_string(),
        48 => "DNSKEY".to_string(),
        49 => "DHCID".to_string(),
        50 => "NSEC3".to_string(),
        51 => "NSEC3PARAM".to_string(),
        52 => "TLSA".to_string(),
        53 => "SMIMEA".to_string(),
        55 => "HIP".to_string(),
        59 => "CDS".to_string(),
        60 => "CDNSKEY".to_string(),
        61 => "OPENPGPKEY".to_string(),
        62 => "CSYNC".to_string(),
        63 => "ZONEMD".to_string(),
        64 => "SVCB".to_string(),
        65 => "HTTPS".to_string(),
        99 => "SPF".to_string(),
        108 => "EUI48".to_string(),
        109 => "EUI64".to_string(),
        249 => "TKEY".to_string(),
        250 => "TSIG".to_string(),
        251 => "IXFR".to_string(),
        252 => "AXFR".to_string(),
        255 => "ANY".to_string(),
        256 => "URI".to_string(),
        257 => "CAA".to_string(),
        32768 => "TA".to_string(),
        32769 => "DLV".to_string(),
        _ => format!("TYPE{qtype}"),
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
            signature: Signature::exact(vec![DataType::UInt8], Volatility::Immutable),
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
            .map(|opt| opt.map(dns_rcode_to_name))
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

/// Convert DNS response code to name.
fn dns_rcode_to_name(rcode: u8) -> String {
    match rcode {
        0 => "NOERROR".to_string(),
        1 => "FORMERR".to_string(),
        2 => "SERVFAIL".to_string(),
        3 => "NXDOMAIN".to_string(),
        4 => "NOTIMP".to_string(),
        5 => "REFUSED".to_string(),
        6 => "YXDOMAIN".to_string(),
        7 => "YXRRSET".to_string(),
        8 => "NXRRSET".to_string(),
        9 => "NOTAUTH".to_string(),
        10 => "NOTZONE".to_string(),
        11 => "DSOTYPENI".to_string(),
        16 => "BADVERS".to_string(),
        17 => "BADKEY".to_string(),
        18 => "BADTIME".to_string(),
        19 => "BADMODE".to_string(),
        20 => "BADNAME".to_string(),
        21 => "BADALG".to_string(),
        22 => "BADTRUNC".to_string(),
        23 => "BADCOOKIE".to_string(),
        _ => format!("RCODE{rcode}"),
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
            signature: Signature::exact(vec![DataType::UInt16], Volatility::Immutable),
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
            .map(|opt| opt.map(dns_class_to_name))
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

/// Convert DNS class to name.
fn dns_class_to_name(class: u16) -> String {
    match class {
        1 => "IN".to_string(),
        3 => "CH".to_string(),
        4 => "HS".to_string(),
        254 => "NONE".to_string(),
        255 => "ANY".to_string(),
        _ => format!("CLASS{class}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_type_name() {
        assert_eq!(dns_type_to_name(1), "A");
        assert_eq!(dns_type_to_name(28), "AAAA");
        assert_eq!(dns_type_to_name(5), "CNAME");
        assert_eq!(dns_type_to_name(15), "MX");
        assert_eq!(dns_type_to_name(2), "NS");
        assert_eq!(dns_type_to_name(12), "PTR");
        assert_eq!(dns_type_to_name(6), "SOA");
        assert_eq!(dns_type_to_name(16), "TXT");
        assert_eq!(dns_type_to_name(33), "SRV");
        assert_eq!(dns_type_to_name(255), "ANY");
        assert_eq!(dns_type_to_name(257), "CAA");
        assert_eq!(dns_type_to_name(65), "HTTPS");
        // Unknown type
        assert_eq!(dns_type_to_name(999), "TYPE999");
    }

    #[test]
    fn test_dns_rcode_name() {
        assert_eq!(dns_rcode_to_name(0), "NOERROR");
        assert_eq!(dns_rcode_to_name(1), "FORMERR");
        assert_eq!(dns_rcode_to_name(2), "SERVFAIL");
        assert_eq!(dns_rcode_to_name(3), "NXDOMAIN");
        assert_eq!(dns_rcode_to_name(4), "NOTIMP");
        assert_eq!(dns_rcode_to_name(5), "REFUSED");
        assert_eq!(dns_rcode_to_name(9), "NOTAUTH");
        // Unknown rcode
        assert_eq!(dns_rcode_to_name(99), "RCODE99");
    }

    #[test]
    fn test_dns_class_name() {
        assert_eq!(dns_class_to_name(1), "IN");
        assert_eq!(dns_class_to_name(3), "CH");
        assert_eq!(dns_class_to_name(4), "HS");
        assert_eq!(dns_class_to_name(255), "ANY");
        // Unknown class
        assert_eq!(dns_class_to_name(99), "CLASS99");
    }
}
