//! BGP table schema definition.
//!
//! The `bgp` table contains BGP (Border Gateway Protocol) fields.

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `bgp` table.
///
/// Fields:
/// - `frame_number`: Reference to frames table
/// - `message_type`: BGP message type code
/// - `message_type_name`: Human-readable message type name
/// - `length`: Total message length
/// - `version`: BGP version (OPEN message)
/// - `my_as`: My AS number (OPEN message)
/// - `hold_time`: Hold time in seconds (OPEN message)
/// - `bgp_id`: Router ID as IP string (OPEN message)
/// - `my_as_4byte`: AS number from the 4-byte-AS capability, or `my_as`
///   when the OPEN carries none (OPEN message)
/// - `capabilities`: Capability names, comma-separated (OPEN message)
/// - `withdrawn_routes_len`: Withdrawn routes length (UPDATE message)
/// - `withdrawn_routes`: Withdrawn prefixes, comma-separated (UPDATE message)
/// - `withdrawn_count`: Number of withdrawn prefixes (UPDATE message)
/// - `path_attr_len`: Path attributes length (UPDATE message)
/// - `origin`, `origin_name`: ORIGIN attribute code and name (UPDATE message)
/// - `as_path`: AS_PATH, space-separated AS numbers; an AS_SET in braces
///   (UPDATE message)
/// - `as_path_length`: AS_PATH length (one per AS_SEQUENCE entry, one per
///   AS_SET) (UPDATE message)
/// - `next_hop`: NEXT_HOP IPv4 address as a string (UPDATE message)
/// - `med`: MULTI_EXIT_DISC (UPDATE message)
/// - `local_pref`: LOCAL_PREF (UPDATE message)
/// - `atomic_aggregate`: ATOMIC_AGGREGATE present (UPDATE message)
/// - `aggregator_as`, `aggregator_ip`: AGGREGATOR attribute (UPDATE message)
/// - `nlri`: Announced prefixes, comma-separated (UPDATE message)
/// - `nlri_count`: Number of announced prefixes (UPDATE message)
/// - `error_code`, `error_code_name`, `error_subcode`: NOTIFICATION message
/// - `afi`, `safi`: Address family (ROUTE-REFRESH message)
///
/// The list-valued attributes are strings because the parser formats them
/// (prefixes with their length, AS numbers with set braces); they match the
/// DuckDB table function's columns, which come from the same descriptors.
pub fn bgp_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("message_type", DataType::UInt8, true),
        Field::new("message_type_name", DataType::Utf8, true),
        Field::new("length", DataType::UInt16, true),
        // OPEN
        Field::new("version", DataType::UInt8, true),
        Field::new("my_as", DataType::UInt16, true),
        Field::new("my_as_4byte", DataType::UInt32, true),
        Field::new("hold_time", DataType::UInt16, true),
        Field::new("bgp_id", DataType::Utf8, true),
        Field::new("capabilities", DataType::Utf8, true),
        // UPDATE
        Field::new("withdrawn_routes_len", DataType::UInt16, true),
        Field::new("withdrawn_routes", DataType::Utf8, true),
        Field::new("withdrawn_count", DataType::UInt16, true),
        Field::new("path_attr_len", DataType::UInt16, true),
        Field::new("origin", DataType::UInt8, true),
        Field::new("origin_name", DataType::Utf8, true),
        Field::new("as_path", DataType::Utf8, true),
        Field::new("as_path_length", DataType::UInt16, true),
        Field::new("next_hop", DataType::Utf8, true),
        Field::new("med", DataType::UInt32, true),
        Field::new("local_pref", DataType::UInt32, true),
        Field::new("atomic_aggregate", DataType::Boolean, true),
        Field::new("aggregator_as", DataType::UInt32, true),
        Field::new("aggregator_ip", DataType::Utf8, true),
        Field::new("nlri", DataType::Utf8, true),
        Field::new("nlri_count", DataType::UInt16, true),
        // NOTIFICATION
        Field::new("error_code", DataType::UInt8, true),
        Field::new("error_code_name", DataType::Utf8, true),
        Field::new("error_subcode", DataType::UInt8, true),
        // ROUTE-REFRESH
        Field::new("afi", DataType::UInt16, true),
        Field::new("safi", DataType::UInt8, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bgp_schema() {
        let schema = bgp_table_schema();

        assert_eq!(schema.fields().len(), 31);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("message_type").is_ok());
        assert!(schema.field_with_name("message_type_name").is_ok());
        assert!(schema.field_with_name("length").is_ok());
        assert!(schema.field_with_name("version").is_ok());
        assert!(schema.field_with_name("my_as").is_ok());
        assert!(schema.field_with_name("hold_time").is_ok());
        assert!(schema.field_with_name("bgp_id").is_ok());
        assert!(schema.field_with_name("withdrawn_routes_len").is_ok());
        assert!(schema.field_with_name("path_attr_len").is_ok());
        for (name, ty) in [
            ("capabilities", DataType::Utf8),
            ("as_path", DataType::Utf8),
            ("nlri", DataType::Utf8),
            ("withdrawn_routes", DataType::Utf8),
            ("atomic_aggregate", DataType::Boolean),
            ("my_as_4byte", DataType::UInt32),
            ("error_code_name", DataType::Utf8),
            ("safi", DataType::UInt8),
        ] {
            assert_eq!(
                schema.field_with_name(name).unwrap().data_type(),
                &ty,
                "{name}"
            );
        }
    }
}
