//! BGP table schema definition.
//!
//! The `bgp` table contains BGP (Border Gateway Protocol) fields.

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `bgp` table.
///
/// Fields:
/// - `frame_number`: Reference to frames table
/// - `message_type`: BGP message type code
/// - `message_type_name`: Human-readable message type name
/// - `length`: Total message length
/// - `version`: BGP version (OPEN message)
/// - `my_as`: My AS number (OPEN message)
/// - `hold_time`: Hold time in seconds (OPEN message)
/// - `bgp_id`: Router ID as IP string (OPEN message)
/// - `withdrawn_routes_len`: Withdrawn routes length (UPDATE message)
/// - `path_attr_len`: Path attributes length (UPDATE message)
pub fn bgp_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("message_type", DataType::UInt8, true),
        Field::new("message_type_name", DataType::Utf8, true),
        Field::new("length", DataType::UInt16, true),
        Field::new("version", DataType::UInt8, true),
        Field::new("my_as", DataType::UInt16, true),
        Field::new("hold_time", DataType::UInt16, true),
        Field::new("bgp_id", DataType::Utf8, true),
        Field::new("withdrawn_routes_len", DataType::UInt16, true),
        Field::new("path_attr_len", DataType::UInt16, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bgp_schema() {
        let schema = bgp_table_schema();

        assert_eq!(schema.fields().len(), 10);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("message_type").is_ok());
        assert!(schema.field_with_name("message_type_name").is_ok());
        assert!(schema.field_with_name("length").is_ok());
        assert!(schema.field_with_name("version").is_ok());
        assert!(schema.field_with_name("my_as").is_ok());
        assert!(schema.field_with_name("hold_time").is_ok());
        assert!(schema.field_with_name("bgp_id").is_ok());
        assert!(schema.field_with_name("withdrawn_routes_len").is_ok());
        assert!(schema.field_with_name("path_attr_len").is_ok());
    }
}
