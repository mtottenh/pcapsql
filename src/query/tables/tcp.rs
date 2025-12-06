//! TCP table schema definition.
//!
//! The `tcp` table contains TCP segment header fields.

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
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_schema() {
        let schema = tcp_table_schema();

        assert_eq!(schema.fields().len(), 17);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("src_port").is_ok());
        assert!(schema.field_with_name("dst_port").is_ok());
        assert!(schema.field_with_name("seq").is_ok());
        assert!(schema.field_with_name("flags").is_ok());
        assert!(schema.field_with_name("flag_syn").is_ok());
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
