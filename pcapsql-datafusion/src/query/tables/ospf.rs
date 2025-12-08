//! OSPF table schema definition.
//!
//! The `ospf` table contains OSPF (Open Shortest Path First) fields.

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `ospf` table.
///
/// Fields:
/// - `frame_number`: Reference to frames table
/// - `version`: OSPF version (2 or 3)
/// - `message_type`: OSPF packet type code
/// - `message_type_name`: Human-readable packet type name
/// - `length`: Packet length
/// - `router_id`: Router ID as IP string
/// - `area_id`: Area ID as IP string
/// - `auth_type`: Authentication type
/// - `hello_interval`: Hello interval in seconds (Hello packet)
/// - `dead_interval`: Dead interval in seconds (Hello packet)
/// - `designated_router`: DR IP address (Hello packet)
/// - `backup_dr`: BDR IP address (Hello packet)
pub fn ospf_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("version", DataType::UInt8, true),
        Field::new("message_type", DataType::UInt8, true),
        Field::new("message_type_name", DataType::Utf8, true),
        Field::new("length", DataType::UInt16, true),
        Field::new("router_id", DataType::Utf8, true),
        Field::new("area_id", DataType::Utf8, true),
        Field::new("auth_type", DataType::UInt16, true),
        Field::new("hello_interval", DataType::UInt16, true),
        Field::new("dead_interval", DataType::UInt32, true),
        Field::new("designated_router", DataType::Utf8, true),
        Field::new("backup_dr", DataType::Utf8, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ospf_schema() {
        let schema = ospf_table_schema();

        assert_eq!(schema.fields().len(), 12);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("version").is_ok());
        assert!(schema.field_with_name("message_type").is_ok());
        assert!(schema.field_with_name("message_type_name").is_ok());
        assert!(schema.field_with_name("length").is_ok());
        assert!(schema.field_with_name("router_id").is_ok());
        assert!(schema.field_with_name("area_id").is_ok());
        assert!(schema.field_with_name("auth_type").is_ok());
        assert!(schema.field_with_name("hello_interval").is_ok());
        assert!(schema.field_with_name("dead_interval").is_ok());
        assert!(schema.field_with_name("designated_router").is_ok());
        assert!(schema.field_with_name("backup_dr").is_ok());
    }
}
