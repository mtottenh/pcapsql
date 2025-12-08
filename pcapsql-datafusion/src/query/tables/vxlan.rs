//! VXLAN table schema definition.
//!
//! The `vxlan` table contains VXLAN (Virtual Extensible LAN) fields.

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `vxlan` table.
///
/// Fields:
/// - `frame_number`: Reference to frames table
/// - `flags`: VXLAN flags byte (I flag in bit 3)
/// - `vni`: VXLAN Network Identifier (24-bit)
pub fn vxlan_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("flags", DataType::UInt8, true),
        Field::new("vni", DataType::UInt32, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vxlan_schema() {
        let schema = vxlan_table_schema();

        assert_eq!(schema.fields().len(), 3);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("flags").is_ok());
        assert!(schema.field_with_name("vni").is_ok());
    }
}
