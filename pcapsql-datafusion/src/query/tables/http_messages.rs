//! Table provider for HTTP messages from stream parsing.

use std::collections::HashMap;
use std::sync::Arc;

use arrow::array::{
    ArrayRef, BooleanBuilder, Int16Builder, Int32Builder, Int64Builder, StringBuilder,
};
use arrow::datatypes::{DataType, Field, Schema, SchemaRef};
use arrow::record_batch::RecordBatch;
use datafusion::error::Result;

use pcapsql_core::stream::ParsedMessage;
use pcapsql_core::FieldValue;

/// Schema for http_messages table.
pub fn http_messages_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("connection_id", DataType::Int64, false),
        Field::new("message_id", DataType::Int32, false),
        Field::new("direction", DataType::Utf8, true),
        Field::new("is_request", DataType::Boolean, true),
        Field::new("first_frame", DataType::Int64, true),
        // Request fields
        Field::new("method", DataType::Utf8, true),
        Field::new("uri", DataType::Utf8, true),
        Field::new("http_version", DataType::Utf8, true),
        // Response fields
        Field::new("status_code", DataType::Int16, true),
        Field::new("status_text", DataType::Utf8, true),
        // Common headers
        Field::new("host", DataType::Utf8, true),
        Field::new("content_type", DataType::Utf8, true),
        Field::new("content_length", DataType::Int64, true),
        Field::new("user_agent", DataType::Utf8, true),
        Field::new("server", DataType::Utf8, true),
    ]))
}

/// Build a RecordBatch from HTTP messages.
pub fn build_http_messages_batch(messages: &[ParsedMessage]) -> Result<RecordBatch> {
    let http_messages: Vec<_> = messages.iter().filter(|m| m.protocol == "http").collect();

    let mut connection_id = Int64Builder::with_capacity(http_messages.len());
    let mut message_id = Int32Builder::with_capacity(http_messages.len());
    let mut direction = StringBuilder::new();
    let mut is_request = BooleanBuilder::with_capacity(http_messages.len());
    let mut first_frame = Int64Builder::with_capacity(http_messages.len());
    let mut method = StringBuilder::new();
    let mut uri = StringBuilder::new();
    let mut http_version = StringBuilder::new();
    let mut status_code = Int16Builder::with_capacity(http_messages.len());
    let mut status_text = StringBuilder::new();
    let mut host = StringBuilder::new();
    let mut content_type = StringBuilder::new();
    let mut content_length = Int64Builder::with_capacity(http_messages.len());
    let mut user_agent = StringBuilder::new();
    let mut server = StringBuilder::new();

    for msg in http_messages {
        connection_id.append_value(msg.connection_id as i64);
        message_id.append_value(msg.message_id as i32);
        direction.append_value(msg.direction.as_str());

        if let Some(FieldValue::Bool(req)) = msg.fields.get("is_request") {
            is_request.append_value(*req);
        } else {
            is_request.append_null();
        }

        first_frame.append_value(msg.frame_number as i64);

        append_string(&mut method, &msg.fields, "method");
        append_string(&mut uri, &msg.fields, "uri");
        append_string(&mut http_version, &msg.fields, "http_version");

        if let Some(FieldValue::UInt16(code)) = msg.fields.get("status_code") {
            status_code.append_value(*code as i16);
        } else {
            status_code.append_null();
        }

        append_string(&mut status_text, &msg.fields, "status_text");
        append_string(&mut host, &msg.fields, "host");
        append_string(&mut content_type, &msg.fields, "content_type");

        if let Some(FieldValue::UInt64(len)) = msg.fields.get("content_length") {
            content_length.append_value(*len as i64);
        } else {
            content_length.append_null();
        }

        append_string(&mut user_agent, &msg.fields, "user_agent");
        append_string(&mut server, &msg.fields, "server");
    }

    let columns: Vec<ArrayRef> = vec![
        Arc::new(connection_id.finish()),
        Arc::new(message_id.finish()),
        Arc::new(direction.finish()),
        Arc::new(is_request.finish()),
        Arc::new(first_frame.finish()),
        Arc::new(method.finish()),
        Arc::new(uri.finish()),
        Arc::new(http_version.finish()),
        Arc::new(status_code.finish()),
        Arc::new(status_text.finish()),
        Arc::new(host.finish()),
        Arc::new(content_type.finish()),
        Arc::new(content_length.finish()),
        Arc::new(user_agent.finish()),
        Arc::new(server.finish()),
    ];

    RecordBatch::try_new(http_messages_schema(), columns)
        .map_err(|e| datafusion::error::DataFusionError::ArrowError(e, None))
}

fn append_string(
    builder: &mut StringBuilder,
    fields: &HashMap<String, FieldValue>,
    key: &str,
) {
    if let Some(FieldValue::String(s)) = fields.get(key) {
        builder.append_value(s);
    } else {
        builder.append_null();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_messages_schema() {
        let schema = http_messages_schema();
        assert!(schema.field_with_name("method").is_ok());
        assert!(schema.field_with_name("uri").is_ok());
        assert!(schema.field_with_name("status_code").is_ok());
        assert!(schema.field_with_name("connection_id").is_ok());
    }

    #[test]
    fn test_empty_http_messages_batch() {
        let messages: Vec<ParsedMessage> = vec![];
        let batch = build_http_messages_batch(&messages);
        assert!(batch.is_ok());
        assert_eq!(batch.unwrap().num_rows(), 0);
    }
}
