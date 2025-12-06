//! VLAN table schema definition.
//!
//! The `vlan` table contains 802.1Q VLAN tag fields.

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `vlan` table.
///
/// Fields:
/// - `frame_number`: Reference to frames table
/// - `vlan_id`: VLAN identifier (12 bits)
/// - `priority`: Priority Code Point (3 bits)
/// - `dei`: Drop Eligible Indicator (1 bit)
/// - `inner_ethertype`: Encapsulated protocol type
pub fn vlan_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("vlan_id", DataType::UInt16, true),
        Field::new("priority", DataType::UInt8, true),
        Field::new("dei", DataType::Boolean, true),
        Field::new("inner_ethertype", DataType::UInt16, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vlan_schema() {
        let schema = vlan_table_schema();

        assert_eq!(schema.fields().len(), 5);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("vlan_id").is_ok());
        assert!(schema.field_with_name("priority").is_ok());
    }
}
