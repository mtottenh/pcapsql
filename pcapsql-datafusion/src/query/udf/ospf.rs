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
use pcapsql_core::protocol::{ospf_lsa_type as lsa_type, ospf_packet_type as packet_type};

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
            signature: Signature::exact(vec![DataType::UInt8], Volatility::Immutable),
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
            .map(|opt| opt.map(ospf_packet_type_to_name))
            .collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

fn ospf_packet_type_to_name(pkt_type: u8) -> String {
    match pkt_type {
        packet_type::HELLO => "Hello".to_string(),
        packet_type::DATABASE_DESCRIPTION => "Database Description".to_string(),
        packet_type::LINK_STATE_REQUEST => "Link State Request".to_string(),
        packet_type::LINK_STATE_UPDATE => "Link State Update".to_string(),
        packet_type::LINK_STATE_ACK => "Link State Acknowledgment".to_string(),
        _ => format!("Unknown ({pkt_type})"),
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
            signature: Signature::exact(vec![DataType::UInt8], Volatility::Immutable),
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
            .map(|opt| opt.map(ospf_lsa_type_to_name))
            .collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

fn ospf_lsa_type_to_name(ls_type: u8) -> String {
    match ls_type {
        lsa_type::ROUTER => "Router-LSA".to_string(),
        lsa_type::NETWORK => "Network-LSA".to_string(),
        lsa_type::SUMMARY_NETWORK => "Summary-LSA-Network".to_string(),
        lsa_type::SUMMARY_ASBR => "Summary-LSA-ASBR".to_string(),
        lsa_type::AS_EXTERNAL => "AS-External-LSA".to_string(),
        lsa_type::GROUP_MEMBERSHIP => "Group-Membership-LSA".to_string(),
        lsa_type::NSSA_EXTERNAL => "NSSA-External-LSA".to_string(),
        lsa_type::EXTERNAL_ATTRIBUTES => "External-Attributes-LSA".to_string(),
        lsa_type::OPAQUE_LINK => "Opaque-Link-LSA".to_string(),
        lsa_type::OPAQUE_AREA => "Opaque-Area-LSA".to_string(),
        lsa_type::OPAQUE_AS => "Opaque-AS-LSA".to_string(),
        _ => format!("Unknown ({ls_type})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ospf_packet_type_name() {
        assert_eq!(ospf_packet_type_to_name(packet_type::HELLO), "Hello");
        assert_eq!(
            ospf_packet_type_to_name(packet_type::DATABASE_DESCRIPTION),
            "Database Description"
        );
        assert_eq!(
            ospf_packet_type_to_name(packet_type::LINK_STATE_REQUEST),
            "Link State Request"
        );
        assert_eq!(
            ospf_packet_type_to_name(packet_type::LINK_STATE_UPDATE),
            "Link State Update"
        );
        assert_eq!(
            ospf_packet_type_to_name(packet_type::LINK_STATE_ACK),
            "Link State Acknowledgment"
        );
        assert_eq!(ospf_packet_type_to_name(99), "Unknown (99)");
    }

    #[test]
    fn test_ospf_lsa_type_name() {
        assert_eq!(ospf_lsa_type_to_name(lsa_type::ROUTER), "Router-LSA");
        assert_eq!(ospf_lsa_type_to_name(lsa_type::NETWORK), "Network-LSA");
        assert_eq!(
            ospf_lsa_type_to_name(lsa_type::AS_EXTERNAL),
            "AS-External-LSA"
        );
        assert_eq!(
            ospf_lsa_type_to_name(lsa_type::NSSA_EXTERNAL),
            "NSSA-External-LSA"
        );
        assert_eq!(ospf_lsa_type_to_name(99), "Unknown (99)");
    }
}
