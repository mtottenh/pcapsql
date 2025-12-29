//! Netlink table schema definition.
//!
//! The `netlink` table contains Linux Netlink message header fields.
//!
//! ## Usage
//!
//! ```sql
//! SELECT * FROM netlink WHERE is_request = true;
//! SELECT * FROM netlink WHERE family_name = 'ROUTE';
//! ```

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `netlink` table.
///
/// Fields match the Netlink protocol parser output (without prefix):
/// - `frame_number`: Reference to frames table
/// - `msg_len`: Netlink message length
/// - `msg_type`: Netlink message type
/// - `msg_flags`: Netlink message flags
/// - `msg_seq`: Sequence number
/// - `msg_pid`: Port ID (process ID)
/// - `msg_type_name`: Human-readable message type name
/// - `is_request`: True if NLM_F_REQUEST flag set
/// - `is_multipart`: True if NLM_F_MULTIPART flag set
/// - `is_ack`: True if NLM_F_ACK flag set
/// - `is_echo`: True if NLM_F_ECHO flag set
/// - `family`: Netlink family number
/// - `family_name`: Human-readable family name
pub fn netlink_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("msg_len", DataType::UInt32, true),
        Field::new("msg_type", DataType::UInt16, true),
        Field::new("msg_flags", DataType::UInt16, true),
        Field::new("msg_seq", DataType::UInt32, true),
        Field::new("msg_pid", DataType::UInt32, true),
        Field::new("msg_type_name", DataType::Utf8, true),
        Field::new("is_request", DataType::Boolean, true),
        Field::new("is_multipart", DataType::Boolean, true),
        Field::new("is_ack", DataType::Boolean, true),
        Field::new("is_echo", DataType::Boolean, true),
        Field::new("family", DataType::UInt8, true),
        Field::new("family_name", DataType::Utf8, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netlink_schema() {
        let schema = netlink_table_schema();

        assert_eq!(schema.fields().len(), 13);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("msg_len").is_ok());
        assert!(schema.field_with_name("msg_type").is_ok());
        assert!(schema.field_with_name("msg_flags").is_ok());
        assert!(schema.field_with_name("family").is_ok());
        assert!(schema.field_with_name("family_name").is_ok());
    }

    #[test]
    fn test_no_protocol_prefix() {
        let schema = netlink_table_schema();
        for field in schema.fields() {
            assert!(
                !field.name().starts_with("netlink."),
                "Field '{}' should not have protocol prefix",
                field.name()
            );
        }
    }
}
