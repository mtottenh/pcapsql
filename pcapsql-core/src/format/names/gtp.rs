//! GTP message type names.

use std::borrow::Cow;

use crate::protocol::gtp_message_type as message_type;

/// Convert a GTP message type to its name; `Unknown (n)` otherwise.
pub fn gtp_message_type_name(msg_type: u8) -> Cow<'static, str> {
    match msg_type {
        // Common messages
        message_type::ECHO_REQUEST => Cow::Borrowed("Echo Request"),
        message_type::ECHO_RESPONSE => Cow::Borrowed("Echo Response"),
        message_type::VERSION_NOT_SUPPORTED => Cow::Borrowed("Version Not Supported"),
        // GTPv1-C messages
        message_type::CREATE_PDP_CONTEXT_REQUEST => Cow::Borrowed("Create PDP Context Request"),
        message_type::CREATE_PDP_CONTEXT_RESPONSE => Cow::Borrowed("Create PDP Context Response"),
        message_type::UPDATE_PDP_CONTEXT_REQUEST => Cow::Borrowed("Update PDP Context Request"),
        message_type::UPDATE_PDP_CONTEXT_RESPONSE => Cow::Borrowed("Update PDP Context Response"),
        message_type::DELETE_PDP_CONTEXT_REQUEST => Cow::Borrowed("Delete PDP Context Request"),
        message_type::DELETE_PDP_CONTEXT_RESPONSE => Cow::Borrowed("Delete PDP Context Response"),
        message_type::ERROR_INDICATION => Cow::Borrowed("Error Indication"),
        message_type::PDU_NOTIFICATION_REQUEST => Cow::Borrowed("PDU Notification Request"),
        message_type::PDU_NOTIFICATION_RESPONSE => Cow::Borrowed("PDU Notification Response"),
        message_type::SUPPORTED_EXTENSION_HEADERS_NOTIFICATION => {
            Cow::Borrowed("Supported Extension Headers Notification")
        }
        // GTPv2-C messages
        message_type::CREATE_SESSION_REQUEST => Cow::Borrowed("Create Session Request"),
        message_type::CREATE_SESSION_RESPONSE => Cow::Borrowed("Create Session Response"),
        message_type::MODIFY_BEARER_REQUEST => Cow::Borrowed("Modify Bearer Request"),
        message_type::MODIFY_BEARER_RESPONSE => Cow::Borrowed("Modify Bearer Response"),
        message_type::DELETE_SESSION_REQUEST => Cow::Borrowed("Delete Session Request"),
        message_type::DELETE_SESSION_RESPONSE => Cow::Borrowed("Delete Session Response"),
        message_type::CHANGE_NOTIFICATION_REQUEST => Cow::Borrowed("Change Notification Request"),
        message_type::CHANGE_NOTIFICATION_RESPONSE => Cow::Borrowed("Change Notification Response"),
        message_type::MODIFY_BEARER_COMMAND => Cow::Borrowed("Modify Bearer Command"),
        message_type::MODIFY_BEARER_FAILURE_INDICATION => {
            Cow::Borrowed("Modify Bearer Failure Indication")
        }
        message_type::DELETE_BEARER_COMMAND => Cow::Borrowed("Delete Bearer Command"),
        message_type::DELETE_BEARER_FAILURE_INDICATION => {
            Cow::Borrowed("Delete Bearer Failure Indication")
        }
        message_type::BEARER_RESOURCE_COMMAND => Cow::Borrowed("Bearer Resource Command"),
        message_type::BEARER_RESOURCE_FAILURE_INDICATION => {
            Cow::Borrowed("Bearer Resource Failure Indication")
        }
        message_type::DOWNLINK_DATA_NOTIFICATION_FAILURE_INDICATION => {
            Cow::Borrowed("Downlink Data Notification Failure Indication")
        }
        message_type::CREATE_BEARER_REQUEST => Cow::Borrowed("Create Bearer Request"),
        message_type::CREATE_BEARER_RESPONSE => Cow::Borrowed("Create Bearer Response"),
        message_type::UPDATE_BEARER_REQUEST => Cow::Borrowed("Update Bearer Request"),
        message_type::UPDATE_BEARER_RESPONSE => Cow::Borrowed("Update Bearer Response"),
        message_type::DELETE_BEARER_REQUEST => Cow::Borrowed("Delete Bearer Request"),
        message_type::DELETE_BEARER_RESPONSE => Cow::Borrowed("Delete Bearer Response"),
        // GTPv1-U messages
        message_type::END_MARKER => Cow::Borrowed("End Marker"),
        message_type::G_PDU => Cow::Borrowed("G-PDU"),
        _ => Cow::Owned(format!("Unknown ({msg_type})")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtp_message_type_name() {
        assert_eq!(
            gtp_message_type_name(message_type::ECHO_REQUEST),
            "Echo Request"
        );
        assert_eq!(
            gtp_message_type_name(message_type::ECHO_RESPONSE),
            "Echo Response"
        );
        assert_eq!(gtp_message_type_name(message_type::G_PDU), "G-PDU");
        assert_eq!(
            gtp_message_type_name(message_type::END_MARKER),
            "End Marker"
        );
        assert_eq!(
            gtp_message_type_name(message_type::CREATE_SESSION_REQUEST),
            "Create Session Request"
        );
        assert_eq!(
            gtp_message_type_name(message_type::CREATE_PDP_CONTEXT_REQUEST),
            "Create PDP Context Request"
        );
        assert_eq!(gtp_message_type_name(200), "Unknown (200)");
    }
}
