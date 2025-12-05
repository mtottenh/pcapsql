//! Arrow schema generation for packet data.

use arrow::datatypes::{DataType, Field, Schema, TimeUnit};

use crate::protocol::{Protocol, ProtocolRegistry};

/// Build the schema for the `packets` unified table.
pub fn build_packets_schema(registry: &ProtocolRegistry) -> Schema {
    let mut fields = vec![
        // Frame metadata
        Field::new("frame_number", DataType::UInt64, false),
        Field::new(
            "timestamp",
            DataType::Timestamp(TimeUnit::Microsecond, None),
            false,
        ),
        Field::new("length", DataType::UInt32, false),
        Field::new("original_length", DataType::UInt32, false),
        // Common Layer 2 fields
        Field::new("eth_src", DataType::Utf8, true),
        Field::new("eth_dst", DataType::Utf8, true),
        Field::new("eth_type", DataType::UInt16, true),
        // Common Layer 3 fields
        Field::new("src_ip", DataType::Utf8, true),
        Field::new("dst_ip", DataType::Utf8, true),
        Field::new("ip_version", DataType::UInt8, true),
        Field::new("ip_ttl", DataType::UInt8, true),
        Field::new("ip_protocol", DataType::UInt8, true),
        // Common Layer 4 fields
        Field::new("src_port", DataType::UInt16, true),
        Field::new("dst_port", DataType::UInt16, true),
        Field::new("protocol", DataType::Utf8, true),
        // TCP-specific
        Field::new("tcp_flags", DataType::UInt16, true),
        Field::new("tcp_seq", DataType::UInt32, true),
        Field::new("tcp_ack", DataType::UInt32, true),
        // ICMP-specific
        Field::new("icmp_type", DataType::UInt8, true),
        Field::new("icmp_code", DataType::UInt8, true),
        // Payload
        Field::new("payload_length", DataType::UInt32, true),
        // Parse status
        Field::new("_parse_error", DataType::Utf8, true),
    ];

    // Add protocol-specific fields from registry
    for parser in registry.all_parsers() {
        for field in parser.schema_fields() {
            // Avoid duplicating fields already in the common schema
            if !fields.iter().any(|f| f.name() == field.name()) {
                fields.push(field);
            }
        }
    }

    Schema::new(fields)
}

/// Build a minimal schema for the `frames` table.
pub fn build_frames_schema() -> Schema {
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
