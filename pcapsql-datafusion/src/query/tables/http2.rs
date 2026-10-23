//! HTTP/2 table schema definition.
//!
//! The `http2` table contains HTTP/2 frame-level data parsed from decrypted
//! TLS streams. It includes frame metadata, headers (for HEADERS frames),
//! and stream state information.

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `http2` table.
///
/// The columns are exactly those the stream pass (`stream_tables`) produces,
/// plus the encapsulation columns every table carries; the two must agree or
/// `SELECT *` fails on a capture with decrypted HTTP/2 traffic.
///
/// ## Frame Information
/// - `frame_number`: Reference to frames table
/// - `connection_id`: Reassembled TCP connection the frame belongs to
/// - `frame_type`: HTTP/2 frame type (DATA, HEADERS, SETTINGS, etc.)
/// - `stream_id`: HTTP/2 stream identifier (0 for connection-level frames)
/// - `flags`: Raw frame flags byte
/// - `length`: Frame payload length
///
/// ## Request (from HEADERS frames)
/// - `method`: HTTP method (:method pseudo-header)
/// - `path`: Request path (:path pseudo-header)
/// - `authority`: Host/authority (:authority pseudo-header)
/// - `scheme`: URL scheme (:scheme pseudo-header)
///
/// ## Response (from HEADERS frames)
/// - `status`: HTTP status code (:status pseudo-header)
///
/// ## Headers
/// - `content_type`: Content-Type header value
/// - `content_length`: Content-Length header value
/// - `user_agent`: User-Agent header value
///
/// ## DATA Frames
/// - `data_length`: Length of data payload
/// - `end_stream`: Whether END_STREAM flag is set
/// - `end_headers`: Whether END_HEADERS flag is set
/// - `padding_length`: Length of padding (if PADDED flag set)
///
/// ## SETTINGS Frames
/// - `ack`: Whether ACK flag is set
/// - `header_table_size`: SETTINGS_HEADER_TABLE_SIZE value
/// - `max_concurrent_streams`: SETTINGS_MAX_CONCURRENT_STREAMS value
/// - `initial_window_size`: SETTINGS_INITIAL_WINDOW_SIZE value
/// - `max_frame_size`: SETTINGS_MAX_FRAME_SIZE value
///
/// ## Error Handling
/// - `error_code`: Error code from RST_STREAM or GOAWAY
/// - `error_name`: Human-readable error name
///
/// ## GOAWAY Frames
/// - `last_stream_id`: Last stream ID from GOAWAY
///
/// ## WINDOW_UPDATE Frames
/// - `window_increment`: Window size increment
///
/// ## Priority Information
/// - `priority_exclusive`: Exclusive dependency flag
/// - `priority_dependency`: Stream dependency
/// - `priority_weight`: Priority weight (1-256)
///
/// ## PUSH_PROMISE Frames
/// - `promised_stream_id`: Promised stream ID
pub fn http2_table_schema() -> Schema {
    Schema::new(vec![
        // Frame information
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("connection_id", DataType::UInt64, true),
        Field::new("frame_type", DataType::Utf8, true),
        Field::new("stream_id", DataType::UInt32, true),
        Field::new("flags", DataType::UInt8, true),
        Field::new("length", DataType::UInt32, true),
        // Request (pseudo-headers)
        Field::new("method", DataType::Utf8, true),
        Field::new("path", DataType::Utf8, true),
        Field::new("authority", DataType::Utf8, true),
        Field::new("scheme", DataType::Utf8, true),
        // Response
        Field::new("status", DataType::UInt16, true),
        // Headers
        Field::new("content_type", DataType::Utf8, true),
        Field::new("content_length", DataType::UInt64, true),
        Field::new("user_agent", DataType::Utf8, true),
        // DATA frames
        Field::new("data_length", DataType::UInt64, true),
        Field::new("end_stream", DataType::Boolean, true),
        Field::new("end_headers", DataType::Boolean, true),
        Field::new("padding_length", DataType::UInt8, true),
        // SETTINGS frames
        Field::new("ack", DataType::Boolean, true),
        Field::new("header_table_size", DataType::UInt32, true),
        Field::new("max_concurrent_streams", DataType::UInt32, true),
        Field::new("initial_window_size", DataType::UInt32, true),
        Field::new("max_frame_size", DataType::UInt32, true),
        // Error handling
        Field::new("error_code", DataType::UInt32, true),
        Field::new("error_name", DataType::Utf8, true),
        // GOAWAY frames
        Field::new("last_stream_id", DataType::UInt32, true),
        // WINDOW_UPDATE frames
        Field::new("window_increment", DataType::UInt32, true),
        // PRIORITY frames
        Field::new("priority_exclusive", DataType::Boolean, true),
        Field::new("priority_dependency", DataType::UInt32, true),
        Field::new("priority_weight", DataType::UInt8, true),
        // PUSH_PROMISE frames
        Field::new("promised_stream_id", DataType::UInt32, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http2_schema() {
        let schema = http2_table_schema();

        // Should have all expected fields
        assert_eq!(schema.fields().len(), 31);

        // Frame info
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("frame_type").is_ok());
        assert!(schema.field_with_name("stream_id").is_ok());
        assert!(schema.field_with_name("flags").is_ok());
        assert!(schema.field_with_name("length").is_ok());

        // Request pseudo-headers
        assert!(schema.field_with_name("method").is_ok());
        assert!(schema.field_with_name("path").is_ok());
        assert!(schema.field_with_name("authority").is_ok());
        assert!(schema.field_with_name("scheme").is_ok());

        // Response
        assert!(schema.field_with_name("status").is_ok());

        // Headers / connection
        assert!(schema.field_with_name("connection_id").is_ok());
        assert!(schema.field_with_name("content_type").is_ok());

        // Frame-specific fields
        assert!(schema.field_with_name("data_length").is_ok());
        assert!(schema.field_with_name("ack").is_ok());
        assert!(schema.field_with_name("error_code").is_ok());
        assert!(schema.field_with_name("window_increment").is_ok());
    }

    #[test]
    fn test_no_protocol_prefix() {
        let schema = http2_table_schema();
        for field in schema.fields() {
            assert!(
                !field.name().starts_with("http2."),
                "Field '{}' should not have protocol prefix",
                field.name()
            );
        }
    }

    #[test]
    fn test_required_fields_not_nullable() {
        let schema = http2_table_schema();

        // frame_number is the join key and is always present.
        let frame_number = schema.field_with_name("frame_number").unwrap();
        assert!(!frame_number.is_nullable());
    }

    #[test]
    fn test_optional_fields_nullable() {
        let schema = http2_table_schema();

        // method should be nullable (only present in HEADERS)
        let method = schema.field_with_name("method").unwrap();
        assert!(method.is_nullable());

        // status should be nullable (only present in response HEADERS)
        let status = schema.field_with_name("status").unwrap();
        assert!(status.is_nullable());

        // ack is only set on SETTINGS frames
        let ack = schema.field_with_name("ack").unwrap();
        assert!(ack.is_nullable());
    }
}
