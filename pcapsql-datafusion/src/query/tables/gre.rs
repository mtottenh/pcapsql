//! GRE table schema definition.
//!
//! The `gre` table contains GRE (Generic Routing Encapsulation) fields.

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `gre` table.
///
/// Fields:
/// - `frame_number`: Reference to frames table
/// - `checksum_present`: C flag - checksum present
/// - `key_present`: K flag - key present
/// - `sequence_present`: S flag - sequence number present
/// - `version`: GRE version (0 or 1)
/// - `protocol`: Encapsulated protocol (ethertype)
/// - `checksum`: Optional checksum value
/// - `key`: Optional key value
/// - `sequence`: Optional sequence number
pub fn gre_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("checksum_present", DataType::Boolean, true),
        Field::new("key_present", DataType::Boolean, true),
        Field::new("sequence_present", DataType::Boolean, true),
        Field::new("version", DataType::UInt8, true),
        Field::new("protocol", DataType::UInt16, true),
        Field::new("checksum", DataType::UInt16, true),
        Field::new("key", DataType::UInt32, true),
        Field::new("sequence", DataType::UInt32, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gre_schema() {
        let schema = gre_table_schema();

        assert_eq!(schema.fields().len(), 9);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("checksum_present").is_ok());
        assert!(schema.field_with_name("key_present").is_ok());
        assert!(schema.field_with_name("sequence_present").is_ok());
        assert!(schema.field_with_name("version").is_ok());
        assert!(schema.field_with_name("protocol").is_ok());
        assert!(schema.field_with_name("key").is_ok());
        assert!(schema.field_with_name("sequence").is_ok());
    }
}
