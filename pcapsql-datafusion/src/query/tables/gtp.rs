//! GTP table schema definition.
//!
//! The `gtp` table contains GTP (GPRS Tunneling Protocol) fields.

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `gtp` table.
///
/// Fields:
/// - `frame_number`: Reference to frames table
/// - `version`: GTP version (1 for GTPv1)
/// - `protocol_type`: 1 = GTP, 0 = GTP'
/// - `message_type`: Message type code
/// - `length`: Payload length
/// - `teid`: Tunnel Endpoint Identifier
/// - `sequence`: Optional sequence number
pub fn gtp_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("version", DataType::UInt8, true),
        Field::new("protocol_type", DataType::UInt8, true),
        Field::new("message_type", DataType::UInt8, true),
        Field::new("length", DataType::UInt16, true),
        Field::new("teid", DataType::UInt32, true),
        Field::new("sequence", DataType::UInt16, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtp_schema() {
        let schema = gtp_table_schema();

        assert_eq!(schema.fields().len(), 7);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("version").is_ok());
        assert!(schema.field_with_name("protocol_type").is_ok());
        assert!(schema.field_with_name("message_type").is_ok());
        assert!(schema.field_with_name("length").is_ok());
        assert!(schema.field_with_name("teid").is_ok());
        assert!(schema.field_with_name("sequence").is_ok());
    }
}
