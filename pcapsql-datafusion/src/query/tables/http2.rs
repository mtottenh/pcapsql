//! HTTP/2 table schema definition.
//!
//! The `http2` table contains HTTP/2 frame-level data parsed from decrypted
//! TLS streams. It includes frame metadata, headers (for HEADERS frames),
//! and stream state information.

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `http2` table.
///
/// ## Frame Information
/// - `frame_number`: Reference to frames table
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
/// - `request_headers`: All request headers as semicolon-separated string
/// - `response_headers`: All response headers as semicolon-separated string
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
/// - `settings`: Settings as comma-separated key=value pairs
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
/// - `debug_data`: Debug data from GOAWAY
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
///
/// ## Stream State
/// - `stream_state`: Current stream state (idle, open, half-closed, closed)
pub fn http2_table_schema() -> Schema {
    Schema::new(vec![
        // Frame information
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("frame_type", DataType::Utf8, false),
        Field::new("stream_id", DataType::UInt32, false),
        Field::new("flags", DataType::UInt8, false),
        Field::new("length", DataType::UInt32, false),
        // Request (pseudo-headers)
        Field::new("method", DataType::Utf8, true),
        Field::new("path", DataType::Utf8, true),
        Field::new("authority", DataType::Utf8, true),
        Field::new("scheme", DataType::Utf8, true),
        // Response
        Field::new("status", DataType::UInt16, true),
        // Headers
        Field::new("request_headers", DataType::Utf8, true),
        Field::new("response_headers", DataType::Utf8, true),
        Field::new("content_type", DataType::Utf8, true),
        Field::new("content_length", DataType::UInt64, true),
        Field::new("user_agent", DataType::Utf8, true),
        // DATA frame fields
        Field::new("data_length", DataType::UInt64, true),
        Field::new("end_stream", DataType::Boolean, true),
        Field::new("end_headers", DataType::Boolean, true),
        Field::new("padding_length", DataType::UInt8, true),
        // SETTINGS frame fields
        Field::new("settings", DataType::Utf8, true),
        Field::new("ack", DataType::Boolean, true),
        Field::new("header_table_size", DataType::UInt32, true),
        Field::new("max_concurrent_streams", DataType::UInt32, true),
        Field::new("initial_window_size", DataType::UInt32, true),
        Field::new("max_frame_size", DataType::UInt32, true),
        // Error handling
        Field::new("error_code", DataType::UInt32, true),
        Field::new("error_name", DataType::Utf8, true),
        // GOAWAY fields
        Field::new("last_stream_id", DataType::UInt32, true),
        Field::new("debug_data", DataType::Utf8, true),
        // WINDOW_UPDATE fields
        Field::new("window_increment", DataType::UInt32, true),
        // Priority fields
        Field::new("priority_exclusive", DataType::Boolean, true),
        Field::new("priority_dependency", DataType::UInt32, true),
        Field::new("priority_weight", DataType::UInt8, true),
        // PUSH_PROMISE fields
        Field::new("promised_stream_id", DataType::UInt32, true),
        // Stream state
        Field::new("stream_state", DataType::Utf8, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http2_schema() {
        let schema = http2_table_schema();

        // Should have all expected fields
        assert_eq!(schema.fields().len(), 35);

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

        // Headers
        assert!(schema.field_with_name("request_headers").is_ok());
        assert!(schema.field_with_name("response_headers").is_ok());
        assert!(schema.field_with_name("content_type").is_ok());

        // Frame-specific fields
        assert!(schema.field_with_name("data_length").is_ok());
        assert!(schema.field_with_name("settings").is_ok());
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

        // frame_number should not be nullable
        let frame_number = schema.field_with_name("frame_number").unwrap();
        assert!(!frame_number.is_nullable());

        // frame_type should not be nullable
        let frame_type = schema.field_with_name("frame_type").unwrap();
        assert!(!frame_type.is_nullable());

        // stream_id should not be nullable
        let stream_id = schema.field_with_name("stream_id").unwrap();
        assert!(!stream_id.is_nullable());
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

        // settings should be nullable (only in SETTINGS frames)
        let settings = schema.field_with_name("settings").unwrap();
        assert!(settings.is_nullable());
    }
}
