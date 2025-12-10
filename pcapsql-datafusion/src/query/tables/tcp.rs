//! TCP table schema definition.
//!
//! The `tcp` table contains TCP segment header fields.

use std::sync::Arc;

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `tcp` table.
///
/// Fields match the TCP protocol parser output (without prefix):
/// - `frame_number`: Reference to frames table
/// - `src_port`: Source port
/// - `dst_port`: Destination port
/// - `seq`: Sequence number
/// - `ack`: Acknowledgment number
/// - `data_offset`: Data offset (header length in 32-bit words)
/// - `flags`: Combined flags value
/// - `flag_fin`, `flag_syn`, `flag_rst`, `flag_psh`, `flag_ack`, `flag_urg`: Individual flags
/// - `window`: Window size
/// - `checksum`: Checksum
/// - `urgent_ptr`: Urgent pointer
/// - `options_length`: Length of TCP options
/// - `options`: Comma-separated list of TCP options present
/// - `mss`: Maximum Segment Size (option 2)
/// - `window_scale`: Window scale factor (option 3)
/// - `sack_permitted`: SACK permitted (option 4)
/// - `sack_left_edges`: SACK block left edges (option 5)
/// - `sack_right_edges`: SACK block right edges (option 5)
/// - `ts_val`: TCP timestamp value (option 8)
/// - `ts_ecr`: TCP timestamp echo reply (option 8)
pub fn tcp_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("src_port", DataType::UInt16, true),
        Field::new("dst_port", DataType::UInt16, true),
        Field::new("seq", DataType::UInt32, true),
        Field::new("ack", DataType::UInt32, true),
        Field::new("data_offset", DataType::UInt8, true),
        Field::new("flags", DataType::UInt16, true),
        Field::new("flag_fin", DataType::Boolean, true),
        Field::new("flag_syn", DataType::Boolean, true),
        Field::new("flag_rst", DataType::Boolean, true),
        Field::new("flag_psh", DataType::Boolean, true),
        Field::new("flag_ack", DataType::Boolean, true),
        Field::new("flag_urg", DataType::Boolean, true),
        Field::new("window", DataType::UInt16, true),
        Field::new("checksum", DataType::UInt16, true),
        Field::new("urgent_ptr", DataType::UInt16, true),
        Field::new("options_length", DataType::UInt8, true),
        // TCP options fields
        Field::new("options", DataType::Utf8, true),
        Field::new("mss", DataType::UInt16, true),
        Field::new("window_scale", DataType::UInt8, true),
        Field::new("sack_permitted", DataType::Boolean, true),
        Field::new(
            "sack_left_edges",
            DataType::List(Arc::new(Field::new("item", DataType::UInt32, true))),
            true,
        ),
        Field::new(
            "sack_right_edges",
            DataType::List(Arc::new(Field::new("item", DataType::UInt32, true))),
            true,
        ),
        Field::new("ts_val", DataType::UInt32, true),
        Field::new("ts_ecr", DataType::UInt32, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_schema() {
        let schema = tcp_table_schema();

        // 17 original + 8 new option fields = 25
        assert_eq!(schema.fields().len(), 25);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("src_port").is_ok());
        assert!(schema.field_with_name("dst_port").is_ok());
        assert!(schema.field_with_name("seq").is_ok());
        assert!(schema.field_with_name("flags").is_ok());
        assert!(schema.field_with_name("flag_syn").is_ok());
        // New TCP options fields
        assert!(schema.field_with_name("options").is_ok());
        assert!(schema.field_with_name("mss").is_ok());
        assert!(schema.field_with_name("window_scale").is_ok());
        assert!(schema.field_with_name("sack_permitted").is_ok());
        assert!(schema.field_with_name("sack_left_edges").is_ok());
        assert!(schema.field_with_name("sack_right_edges").is_ok());
        assert!(schema.field_with_name("ts_val").is_ok());
        assert!(schema.field_with_name("ts_ecr").is_ok());
    }

    #[test]
    fn test_no_protocol_prefix() {
        let schema = tcp_table_schema();
        for field in schema.fields() {
            assert!(
                !field.name().starts_with("tcp."),
                "Field '{}' should not have protocol prefix",
                field.name()
            );
        }
    }
}
