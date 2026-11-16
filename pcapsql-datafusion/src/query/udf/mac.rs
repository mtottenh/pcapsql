//! MAC address UDFs.
//!
//! Provides functions for converting MAC addresses stored as FixedSizeBinary(6).

use std::sync::Arc;

use arrow::array::{Array, BooleanArray, FixedSizeBinaryArray, StringArray};
use arrow::datatypes::DataType;
use datafusion::common::Result as DFResult;
use datafusion::logical_expr::{
    ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, Volatility,
};
use pcapsql_core::format::{
    format_mac, is_broadcast_mac, is_local_mac, is_multicast_mac, parse_mac,
};

/// Create the `mac()` UDF that converts a MAC address string to FixedSizeBinary(6).
///
/// Supports formats:
/// - Colon-separated: `aa:bb:cc:dd:ee:ff`
/// - Hyphen-separated: `aa-bb-cc-dd-ee-ff`
/// - No separator: `aabbccddeeff`
///
/// # Example
/// ```sql
/// SELECT * FROM ethernet WHERE src_mac = mac('aa:bb:cc:dd:ee:ff');
/// ```
pub fn create_mac_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(MacUdf::new())
}

/// Create the `mac_to_string()` UDF that converts a FixedSizeBinary(6) to MAC string.
///
/// # Example
/// ```sql
/// SELECT mac_to_string(src_mac) AS src FROM ethernet;
/// ```
pub fn create_mac_to_string_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(MacToStringUdf::new())
}

/// Create the `mac_is_broadcast()` UDF that checks if a MAC is broadcast.
///
/// # Example
/// ```sql
/// SELECT * FROM ethernet WHERE mac_is_broadcast(dst_mac);
/// -- Matches: ff:ff:ff:ff:ff:ff
/// ```
pub fn create_mac_is_broadcast_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(MacIsBroadcastUdf::new())
}

/// Create the `mac_is_multicast()` UDF that checks if a MAC is multicast.
///
/// # Example
/// ```sql
/// SELECT * FROM ethernet WHERE mac_is_multicast(dst_mac);
/// -- Matches: bit 0 of first octet = 1 (e.g., 01:00:5e:xx:xx:xx for IPv4 multicast)
/// ```
pub fn create_mac_is_multicast_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(MacIsMulticastUdf::new())
}

/// Create the `mac_is_local()` UDF that checks if a MAC is locally administered.
///
/// # Example
/// ```sql
/// SELECT * FROM ethernet WHERE mac_is_local(src_mac);
/// -- Matches: bit 1 of first octet = 1 (locally administered address)
/// ```
pub fn create_mac_is_local_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(MacIsLocalUdf::new())
}

// ============================================================================
// mac() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct MacUdf {
    signature: Signature,
}

impl MacUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::Utf8], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for MacUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "mac"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::FixedSizeBinary(6))
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let mac_strings = super::string_arg(&args[0], "mac")?;

        let values: Vec<Option<[u8; 6]>> = mac_strings
            .iter()
            .map(|opt| opt.and_then(parse_mac))
            .collect();

        let result = FixedSizeBinaryArray::try_from_sparse_iter_with_size(
            values.iter().map(|v| v.as_ref().map(|arr| arr.as_slice())),
            6,
        )
        .expect("Failed to create FixedSizeBinaryArray");

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// mac_to_string() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct MacToStringUdf {
    signature: Signature,
}

impl MacToStringUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::FixedSizeBinary(6)], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for MacToStringUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "mac_to_string"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Utf8)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let mac_values = args[0]
            .as_any()
            .downcast_ref::<FixedSizeBinaryArray>()
            .expect("mac_to_string: expected FixedSizeBinary(6) array");

        let result: StringArray = (0..mac_values.len())
            .map(|i| {
                if mac_values.is_null(i) {
                    None
                } else {
                    // A value that is not 6 bytes (the argument type rules
                    // it out) formats as the empty string.
                    Some(format_mac(mac_values.value(i)).unwrap_or_default())
                }
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// mac_is_broadcast() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct MacIsBroadcastUdf {
    signature: Signature,
}

impl MacIsBroadcastUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::FixedSizeBinary(6)], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for MacIsBroadcastUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "mac_is_broadcast"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Boolean)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let mac_values = args[0]
            .as_any()
            .downcast_ref::<FixedSizeBinaryArray>()
            .expect("mac_is_broadcast: expected FixedSizeBinary(6) array");

        let result: BooleanArray = (0..mac_values.len())
            .map(|i| {
                if mac_values.is_null(i) {
                    None
                } else {
                    Some(is_broadcast_mac(mac_values.value(i)))
                }
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// mac_is_multicast() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct MacIsMulticastUdf {
    signature: Signature,
}

impl MacIsMulticastUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::FixedSizeBinary(6)], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for MacIsMulticastUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "mac_is_multicast"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Boolean)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let mac_values = args[0]
            .as_any()
            .downcast_ref::<FixedSizeBinaryArray>()
            .expect("mac_is_multicast: expected FixedSizeBinary(6) array");

        let result: BooleanArray = (0..mac_values.len())
            .map(|i| {
                if mac_values.is_null(i) {
                    None
                } else {
                    Some(is_multicast_mac(mac_values.value(i)))
                }
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// mac_is_local() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct MacIsLocalUdf {
    signature: Signature,
}

impl MacIsLocalUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::FixedSizeBinary(6)], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for MacIsLocalUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "mac_is_local"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Boolean)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let mac_values = args[0]
            .as_any()
            .downcast_ref::<FixedSizeBinaryArray>()
            .expect("mac_is_local: expected FixedSizeBinary(6) array");

        let result: BooleanArray = (0..mac_values.len())
            .map(|i| {
                if mac_values.is_null(i) {
                    None
                } else {
                    Some(is_local_mac(mac_values.value(i)))
                }
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}
