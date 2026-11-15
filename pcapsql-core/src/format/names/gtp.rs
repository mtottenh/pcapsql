//! GTP message type names.

use super::Name;

use crate::protocol::gtp_message_type as message_type;

/// Convert a GTP message type to its name; `Unknown (n)` otherwise.
pub fn gtp_message_type_name(msg_type: u8) -> Name {
    match msg_type {
        // Common messages
        message_type::ECHO_REQUEST => Name::fixed("Echo Request"),
        message_type::ECHO_RESPONSE => Name::fixed("Echo Response"),
        message_type::VERSION_NOT_SUPPORTED => Name::fixed("Version Not Supported"),
        // GTPv1-C messages
        message_type::CREATE_PDP_CONTEXT_REQUEST => Name::fixed("Create PDP Context Request"),
        message_type::CREATE_PDP_CONTEXT_RESPONSE => Name::fixed("Create PDP Context Response"),
        message_type::UPDATE_PDP_CONTEXT_REQUEST => Name::fixed("Update PDP Context Request"),
        message_type::UPDATE_PDP_CONTEXT_RESPONSE => Name::fixed("Update PDP Context Response"),
        message_type::DELETE_PDP_CONTEXT_REQUEST => Name::fixed("Delete PDP Context Request"),
        message_type::DELETE_PDP_CONTEXT_RESPONSE => Name::fixed("Delete PDP Context Response"),
        message_type::ERROR_INDICATION => Name::fixed("Error Indication"),
        message_type::PDU_NOTIFICATION_REQUEST => Name::fixed("PDU Notification Request"),
        message_type::PDU_NOTIFICATION_RESPONSE => Name::fixed("PDU Notification Response"),
        message_type::SUPPORTED_EXTENSION_HEADERS_NOTIFICATION => {
            Name::fixed("Supported Extension Headers Notification")
        }
        // GTPv2-C messages
        message_type::CREATE_SESSION_REQUEST => Name::fixed("Create Session Request"),
        message_type::CREATE_SESSION_RESPONSE => Name::fixed("Create Session Response"),
        message_type::MODIFY_BEARER_REQUEST => Name::fixed("Modify Bearer Request"),
        message_type::MODIFY_BEARER_RESPONSE => Name::fixed("Modify Bearer Response"),
        message_type::DELETE_SESSION_REQUEST => Name::fixed("Delete Session Request"),
        message_type::DELETE_SESSION_RESPONSE => Name::fixed("Delete Session Response"),
        message_type::CHANGE_NOTIFICATION_REQUEST => Name::fixed("Change Notification Request"),
        message_type::CHANGE_NOTIFICATION_RESPONSE => Name::fixed("Change Notification Response"),
        message_type::MODIFY_BEARER_COMMAND => Name::fixed("Modify Bearer Command"),
        message_type::MODIFY_BEARER_FAILURE_INDICATION => {
            Name::fixed("Modify Bearer Failure Indication")
        }
        message_type::DELETE_BEARER_COMMAND => Name::fixed("Delete Bearer Command"),
        message_type::DELETE_BEARER_FAILURE_INDICATION => {
            Name::fixed("Delete Bearer Failure Indication")
        }
        message_type::BEARER_RESOURCE_COMMAND => Name::fixed("Bearer Resource Command"),
        message_type::BEARER_RESOURCE_FAILURE_INDICATION => {
            Name::fixed("Bearer Resource Failure Indication")
        }
        message_type::DOWNLINK_DATA_NOTIFICATION_FAILURE_INDICATION => {
            Name::fixed("Downlink Data Notification Failure Indication")
        }
        message_type::CREATE_BEARER_REQUEST => Name::fixed("Create Bearer Request"),
        message_type::CREATE_BEARER_RESPONSE => Name::fixed("Create Bearer Response"),
        message_type::UPDATE_BEARER_REQUEST => Name::fixed("Update Bearer Request"),
        message_type::UPDATE_BEARER_RESPONSE => Name::fixed("Update Bearer Response"),
        message_type::DELETE_BEARER_REQUEST => Name::fixed("Delete Bearer Request"),
        message_type::DELETE_BEARER_RESPONSE => Name::fixed("Delete Bearer Response"),
        // GTPv1-U messages
        message_type::END_MARKER => Name::fixed("End Marker"),
        message_type::G_PDU => Name::fixed("G-PDU"),
        _ => Name::unknown(msg_type),
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
