//! HTTP/1.x messages table schema definition.
//!
//! One row per HTTP/1.x request or response reassembled from a TCP stream
//! (a stream-analysis table, not per packet).
//!
//! ## Usage
//!
//! ```sql
//! SELECT method, uri, host, status_code FROM http_messages ORDER BY frame_number;
//! ```

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `http_messages` table.
///
/// - `frame_number`: frame that completed the message (join key / capture order)
/// - `connection_id`, `message_id`, `direction`: stream identity
/// - `is_request`, `method`, `uri`, `http_version`, `status_code`: start line
/// - `host`, `content_type`, `content_length`, `user_agent`, `server`: common headers
pub fn http_messages_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("connection_id", DataType::UInt64, false),
        Field::new("message_id", DataType::UInt32, false),
        Field::new("direction", DataType::Utf8, false),
        Field::new("is_request", DataType::Boolean, true),
        Field::new("method", DataType::Utf8, true),
        Field::new("uri", DataType::Utf8, true),
        Field::new("http_version", DataType::Utf8, true),
        Field::new("status_code", DataType::UInt16, true),
        Field::new("host", DataType::Utf8, true),
        Field::new("content_type", DataType::Utf8, true),
        Field::new("content_length", DataType::UInt64, true),
        Field::new("user_agent", DataType::Utf8, true),
        Field::new("server", DataType::Utf8, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_messages_schema() {
        let schema = http_messages_table_schema();
        assert_eq!(schema.fields().len(), 14);
        assert_eq!(schema.field(0).name(), "frame_number");
        assert!(schema.field_with_name("method").is_ok());
        assert!(schema.field_with_name("status_code").is_ok());
    }
}
