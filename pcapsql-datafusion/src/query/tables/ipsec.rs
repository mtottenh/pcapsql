//! IPsec table schema definition.
//!
//! The `ipsec` table contains IPsec (ESP and AH) fields.

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `ipsec` table.
///
/// Fields:
/// - `frame_number`: Reference to frames table
/// - `protocol`: "ESP" or "AH"
/// - `spi`: Security Parameters Index
/// - `sequence`: Sequence number
/// - `ah_next_header`: Next header (AH only)
/// - `ah_icv_length`: ICV length in bytes (AH only)
pub fn ipsec_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("protocol", DataType::Utf8, true),
        Field::new("spi", DataType::UInt32, true),
        Field::new("sequence", DataType::UInt32, true),
        Field::new("ah_next_header", DataType::UInt8, true),
        Field::new("ah_icv_length", DataType::UInt8, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipsec_schema() {
        let schema = ipsec_table_schema();

        assert_eq!(schema.fields().len(), 6);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("protocol").is_ok());
        assert!(schema.field_with_name("spi").is_ok());
        assert!(schema.field_with_name("sequence").is_ok());
        assert!(schema.field_with_name("ah_next_header").is_ok());
        assert!(schema.field_with_name("ah_icv_length").is_ok());
    }
}
