//! UDP table schema definition.
//!
//! The `udp` table contains UDP datagram header fields.

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `udp` table.
///
/// Fields:
/// - `frame_number`: Reference to frames table
/// - `src_port`: Source port
/// - `dst_port`: Destination port
/// - `length`: Datagram length (header + data)
/// - `checksum`: Checksum
pub fn udp_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("src_port", DataType::UInt16, true),
        Field::new("dst_port", DataType::UInt16, true),
        Field::new("length", DataType::UInt16, true),
        Field::new("checksum", DataType::UInt16, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_schema() {
        let schema = udp_table_schema();

        assert_eq!(schema.fields().len(), 5);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("src_port").is_ok());
        assert!(schema.field_with_name("dst_port").is_ok());
        assert!(schema.field_with_name("length").is_ok());
        assert!(schema.field_with_name("checksum").is_ok());
    }
}
