//! MPLS table schema definition.
//!
//! The `mpls` table contains MPLS (Multi-Protocol Label Switching) fields.

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `mpls` table.
///
/// Fields:
/// - `frame_number`: Reference to frames table
/// - `label`: Top label value (20-bit)
/// - `tc`: Traffic Class (3-bit)
/// - `bottom`: Bottom of stack flag
/// - `ttl`: Time to Live
/// - `stack_depth`: Number of labels in the stack
/// - `labels`: Comma-separated list of all labels
pub fn mpls_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("label", DataType::UInt32, true),
        Field::new("tc", DataType::UInt8, true),
        Field::new("bottom", DataType::Boolean, true),
        Field::new("ttl", DataType::UInt8, true),
        Field::new("stack_depth", DataType::UInt8, true),
        Field::new("labels", DataType::Utf8, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpls_schema() {
        let schema = mpls_table_schema();

        assert_eq!(schema.fields().len(), 7);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("label").is_ok());
        assert!(schema.field_with_name("tc").is_ok());
        assert!(schema.field_with_name("bottom").is_ok());
        assert!(schema.field_with_name("ttl").is_ok());
        assert!(schema.field_with_name("stack_depth").is_ok());
        assert!(schema.field_with_name("labels").is_ok());
    }
}
