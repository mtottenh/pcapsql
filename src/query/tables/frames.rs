//! Frames table schema definition.
//!
//! The `frames` table contains raw packet metadata and data.
//! This is the base table that all other protocol tables reference.

use arrow::datatypes::{DataType, Field, Schema, TimeUnit};

/// Build the schema for the `frames` table.
///
/// The frames table contains:
/// - `frame_number`: Unique identifier (1-indexed)
/// - `timestamp`: Capture timestamp
/// - `length`: Captured length
/// - `original_length`: Original packet length on wire
/// - `link_type`: Link layer type (e.g., 1 = Ethernet)
/// - `raw_data`: Complete packet bytes
pub fn frames_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new(
            "timestamp",
            DataType::Timestamp(TimeUnit::Microsecond, None),
            false,
        ),
        Field::new("length", DataType::UInt32, false),
        Field::new("original_length", DataType::UInt32, false),
        Field::new("link_type", DataType::UInt16, false),
        Field::new("raw_data", DataType::Binary, false),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frames_schema() {
        let schema = frames_table_schema();

        assert_eq!(schema.fields().len(), 6);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("timestamp").is_ok());
        assert!(schema.field_with_name("length").is_ok());
        assert!(schema.field_with_name("original_length").is_ok());
        assert!(schema.field_with_name("link_type").is_ok());
        assert!(schema.field_with_name("raw_data").is_ok());
    }

    #[test]
    fn test_frame_number_not_nullable() {
        let schema = frames_table_schema();
        let field = schema.field_with_name("frame_number").unwrap();
        assert!(!field.is_nullable());
    }
}
