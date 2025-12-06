//! Ethernet table schema definition.
//!
//! The `ethernet` table contains Ethernet II frame headers.

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `ethernet` table.
///
/// Fields:
/// - `frame_number`: Reference to frames table
/// - `src_mac`: Source MAC address (6 bytes)
/// - `dst_mac`: Destination MAC address (6 bytes)
/// - `ethertype`: EtherType field (e.g., 0x0800 = IPv4)
pub fn ethernet_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("src_mac", DataType::FixedSizeBinary(6), true),
        Field::new("dst_mac", DataType::FixedSizeBinary(6), true),
        Field::new("ethertype", DataType::UInt16, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethernet_schema() {
        let schema = ethernet_table_schema();

        assert_eq!(schema.fields().len(), 4);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("src_mac").is_ok());
        assert!(schema.field_with_name("dst_mac").is_ok());
        assert!(schema.field_with_name("ethertype").is_ok());
    }

    #[test]
    fn test_mac_address_type() {
        let schema = ethernet_table_schema();
        let field = schema.field_with_name("src_mac").unwrap();
        assert_eq!(field.data_type(), &DataType::FixedSizeBinary(6));
    }
}
