//! GTP protocol UDFs.
//!
//! Provides functions for converting GTP message types to human-readable names.
//! Uses protocol constants from pcapsql-core for consistency.

use std::sync::Arc;

use arrow::array::{Array, StringArray, UInt8Array};
use arrow::datatypes::DataType;
use datafusion::common::Result as DFResult;
use datafusion::logical_expr::{
    ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, Volatility,
};
use pcapsql_core::protocol::gtp_message_type as message_type;

/// Create the `gtp_message_type_name()` UDF.
///
/// # Example
/// ```sql
/// SELECT gtp_message_type_name(message_type) FROM gtp;
/// -- Returns: "Echo Request", "Echo Response", "G-PDU", etc.
/// ```
pub fn create_gtp_message_type_name_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(GtpMessageTypeNameUdf::new())
}

// ============================================================================
// gtp_message_type_name() UDF Implementation
// ============================================================================

#[derive(Debug, PartialEq, Eq, Hash)]
struct GtpMessageTypeNameUdf {
    signature: Signature,
}

impl GtpMessageTypeNameUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::UInt8], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for GtpMessageTypeNameUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "gtp_message_type_name"
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
            .expect("gtp_message_type_name: expected uint8 array");

        let result: StringArray = values
            .iter()
            .map(|opt| opt.map(gtp_message_type_to_name))
            .collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

fn gtp_message_type_to_name(msg_type: u8) -> String {
    match msg_type {
        // Common messages
        message_type::ECHO_REQUEST => "Echo Request".to_string(),
        message_type::ECHO_RESPONSE => "Echo Response".to_string(),
        message_type::VERSION_NOT_SUPPORTED => "Version Not Supported".to_string(),
        // GTPv1-C messages
        message_type::CREATE_PDP_CONTEXT_REQUEST => "Create PDP Context Request".to_string(),
        message_type::CREATE_PDP_CONTEXT_RESPONSE => "Create PDP Context Response".to_string(),
        message_type::UPDATE_PDP_CONTEXT_REQUEST => "Update PDP Context Request".to_string(),
        message_type::UPDATE_PDP_CONTEXT_RESPONSE => "Update PDP Context Response".to_string(),
        message_type::DELETE_PDP_CONTEXT_REQUEST => "Delete PDP Context Request".to_string(),
        message_type::DELETE_PDP_CONTEXT_RESPONSE => "Delete PDP Context Response".to_string(),
        message_type::ERROR_INDICATION => "Error Indication".to_string(),
        message_type::PDU_NOTIFICATION_REQUEST => "PDU Notification Request".to_string(),
        message_type::PDU_NOTIFICATION_RESPONSE => "PDU Notification Response".to_string(),
        message_type::SUPPORTED_EXTENSION_HEADERS_NOTIFICATION => {
            "Supported Extension Headers Notification".to_string()
        }
        // GTPv2-C messages
        message_type::CREATE_SESSION_REQUEST => "Create Session Request".to_string(),
        message_type::CREATE_SESSION_RESPONSE => "Create Session Response".to_string(),
        message_type::MODIFY_BEARER_REQUEST => "Modify Bearer Request".to_string(),
        message_type::MODIFY_BEARER_RESPONSE => "Modify Bearer Response".to_string(),
        message_type::DELETE_SESSION_REQUEST => "Delete Session Request".to_string(),
        message_type::DELETE_SESSION_RESPONSE => "Delete Session Response".to_string(),
        message_type::CHANGE_NOTIFICATION_REQUEST => "Change Notification Request".to_string(),
        message_type::CHANGE_NOTIFICATION_RESPONSE => "Change Notification Response".to_string(),
        message_type::MODIFY_BEARER_COMMAND => "Modify Bearer Command".to_string(),
        message_type::MODIFY_BEARER_FAILURE_INDICATION => {
            "Modify Bearer Failure Indication".to_string()
        }
        message_type::DELETE_BEARER_COMMAND => "Delete Bearer Command".to_string(),
        message_type::DELETE_BEARER_FAILURE_INDICATION => {
            "Delete Bearer Failure Indication".to_string()
        }
        message_type::BEARER_RESOURCE_COMMAND => "Bearer Resource Command".to_string(),
        message_type::BEARER_RESOURCE_FAILURE_INDICATION => {
            "Bearer Resource Failure Indication".to_string()
        }
        message_type::DOWNLINK_DATA_NOTIFICATION_FAILURE_INDICATION => {
            "Downlink Data Notification Failure Indication".to_string()
        }
        message_type::CREATE_BEARER_REQUEST => "Create Bearer Request".to_string(),
        message_type::CREATE_BEARER_RESPONSE => "Create Bearer Response".to_string(),
        message_type::UPDATE_BEARER_REQUEST => "Update Bearer Request".to_string(),
        message_type::UPDATE_BEARER_RESPONSE => "Update Bearer Response".to_string(),
        message_type::DELETE_BEARER_REQUEST => "Delete Bearer Request".to_string(),
        message_type::DELETE_BEARER_RESPONSE => "Delete Bearer Response".to_string(),
        // GTPv1-U messages
        message_type::END_MARKER => "End Marker".to_string(),
        message_type::G_PDU => "G-PDU".to_string(),
        _ => format!("Unknown ({msg_type})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtp_message_type_name() {
        assert_eq!(
            gtp_message_type_to_name(message_type::ECHO_REQUEST),
            "Echo Request"
        );
        assert_eq!(
            gtp_message_type_to_name(message_type::ECHO_RESPONSE),
            "Echo Response"
        );
        assert_eq!(gtp_message_type_to_name(message_type::G_PDU), "G-PDU");
        assert_eq!(
            gtp_message_type_to_name(message_type::END_MARKER),
            "End Marker"
        );
        assert_eq!(
            gtp_message_type_to_name(message_type::CREATE_SESSION_REQUEST),
            "Create Session Request"
        );
        assert_eq!(
            gtp_message_type_to_name(message_type::CREATE_PDP_CONTEXT_REQUEST),
            "Create PDP Context Request"
        );
        assert_eq!(gtp_message_type_to_name(200), "Unknown (200)");
    }
}
