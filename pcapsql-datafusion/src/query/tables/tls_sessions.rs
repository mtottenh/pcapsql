//! Table provider for TLS session metadata.

use std::collections::HashMap;
use std::sync::Arc;

use arrow::array::{ArrayRef, BooleanBuilder, Int16Builder, Int64Builder, StringBuilder};
use arrow::datatypes::{DataType, Field, Schema, SchemaRef};
use arrow::record_batch::RecordBatch;
use datafusion::error::Result;

use pcapsql_core::stream::ParsedMessage;
use pcapsql_core::FieldValue;

/// Schema for tls_sessions table.
pub fn tls_sessions_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("connection_id", DataType::Int64, false),
        Field::new("version", DataType::Utf8, true),
        Field::new("cipher_suite", DataType::Utf8, true),
        Field::new("cipher_suite_id", DataType::Int16, true),
        Field::new("sni", DataType::Utf8, true),
        Field::new("alpn", DataType::Utf8, true),
        Field::new("is_decrypted", DataType::Boolean, true),
        Field::new("first_frame", DataType::Int64, true),
    ]))
}

/// Build a RecordBatch from TLS session messages.
pub fn build_tls_sessions_batch(messages: &[ParsedMessage]) -> Result<RecordBatch> {
    // Filter to only TLS messages that represent sessions (have version field)
    let tls_sessions: Vec<_> = messages
        .iter()
        .filter(|m| m.protocol == "tls" && m.fields.contains_key("version"))
        .collect();

    let mut connection_id = Int64Builder::with_capacity(tls_sessions.len());
    let mut version = StringBuilder::new();
    let mut cipher_suite = StringBuilder::new();
    let mut cipher_suite_id = Int16Builder::with_capacity(tls_sessions.len());
    let mut sni = StringBuilder::new();
    let mut alpn = StringBuilder::new();
    let mut is_decrypted = BooleanBuilder::with_capacity(tls_sessions.len());
    let mut first_frame = Int64Builder::with_capacity(tls_sessions.len());

    for msg in tls_sessions {
        connection_id.append_value(msg.connection_id as i64);

        append_string_field(&mut version, &msg.fields, "version");
        append_string_field(&mut cipher_suite, &msg.fields, "cipher_suite");

        if let Some(FieldValue::UInt16(id)) = msg.fields.get("cipher_suite_id") {
            cipher_suite_id.append_value(*id as i16);
        } else {
            cipher_suite_id.append_null();
        }

        append_string_field(&mut sni, &msg.fields, "sni");
        append_string_field(&mut alpn, &msg.fields, "alpn");

        if let Some(FieldValue::Bool(dec)) = msg.fields.get("is_decrypted") {
            is_decrypted.append_value(*dec);
        } else {
            is_decrypted.append_value(false);
        }

        first_frame.append_value(msg.frame_number as i64);
    }

    let columns: Vec<ArrayRef> = vec![
        Arc::new(connection_id.finish()),
        Arc::new(version.finish()),
        Arc::new(cipher_suite.finish()),
        Arc::new(cipher_suite_id.finish()),
        Arc::new(sni.finish()),
        Arc::new(alpn.finish()),
        Arc::new(is_decrypted.finish()),
        Arc::new(first_frame.finish()),
    ];

    RecordBatch::try_new(tls_sessions_schema(), columns)
        .map_err(|e| datafusion::error::DataFusionError::ArrowError(Box::new(e), None))
}

fn append_string_field(
    builder: &mut StringBuilder,
    fields: &HashMap<&'static str, FieldValue>,
    key: &str,
) {
    match fields.get(key) {
        Some(FieldValue::Str(s)) => builder.append_value(s),
        Some(FieldValue::OwnedString(s)) => builder.append_value(s.as_str()),
        _ => builder.append_null(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_sessions_schema() {
        let schema = tls_sessions_schema();
        assert!(schema.field_with_name("sni").is_ok());
        assert!(schema.field_with_name("cipher_suite").is_ok());
        assert!(schema.field_with_name("alpn").is_ok());
        assert!(schema.field_with_name("connection_id").is_ok());
    }

    #[test]
    fn test_empty_tls_sessions_batch() {
        let messages: Vec<ParsedMessage> = vec![];
        let batch = build_tls_sessions_batch(&messages);
        assert!(batch.is_ok());
        assert_eq!(batch.unwrap().num_rows(), 0);
    }
}
