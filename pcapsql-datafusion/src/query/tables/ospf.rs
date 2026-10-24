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
/// - `neighbor_count`: Neighbours listed (Hello packet)
/// - `dd_interface_mtu`, `dd_options`, `dd_flags`, `dd_sequence`: Database
///   Description packet header
/// - `dd_lsa_count`: LSA headers in a Database Description packet
/// - `lsu_lsa_count`: LSAs in a Link State Update packet
/// - `lsa_ack_count`: LSA headers in a Link State Acknowledgment packet
/// - `lsa_age`, `lsa_type`, `lsa_type_name`, `lsa_id`,
///   `lsa_advertising_router`, `lsa_sequence`: the first LSA header of a
///   Database Description, Link State Update or Link State Acknowledgment
///   packet
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
        // Hello
        Field::new("hello_interval", DataType::UInt16, true),
        Field::new("dead_interval", DataType::UInt32, true),
        Field::new("designated_router", DataType::Utf8, true),
        Field::new("backup_dr", DataType::Utf8, true),
        Field::new("neighbor_count", DataType::UInt16, true),
        // Database Description
        Field::new("dd_interface_mtu", DataType::UInt16, true),
        Field::new("dd_options", DataType::UInt8, true),
        Field::new("dd_flags", DataType::UInt8, true),
        Field::new("dd_sequence", DataType::UInt32, true),
        Field::new("dd_lsa_count", DataType::UInt16, true),
        // Link State Update / Acknowledgment
        Field::new("lsu_lsa_count", DataType::UInt32, true),
        Field::new("lsa_ack_count", DataType::UInt16, true),
        // First LSA header (DD, LSU, LSAck)
        Field::new("lsa_age", DataType::UInt16, true),
        Field::new("lsa_type", DataType::UInt8, true),
        Field::new("lsa_type_name", DataType::Utf8, true),
        Field::new("lsa_id", DataType::Utf8, true),
        Field::new("lsa_advertising_router", DataType::Utf8, true),
        Field::new("lsa_sequence", DataType::UInt32, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ospf_schema() {
        let schema = ospf_table_schema();

        assert_eq!(schema.fields().len(), 26);
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
        for (name, ty) in [
            ("neighbor_count", DataType::UInt16),
            ("dd_sequence", DataType::UInt32),
            ("lsu_lsa_count", DataType::UInt32),
            ("lsa_type_name", DataType::Utf8),
            ("lsa_advertising_router", DataType::Utf8),
            ("lsa_sequence", DataType::UInt32),
        ] {
            assert_eq!(
                schema.field_with_name(name).unwrap().data_type(),
                &ty,
                "{name}"
            );
        }
    }
}
