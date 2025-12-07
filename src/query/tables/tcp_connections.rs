//! Table provider for TCP connections from StreamManager.

use std::sync::Arc;

use arrow::array::{
    ArrayRef, BooleanBuilder, Int32Builder, Int64Builder, StringBuilder,
    TimestampMicrosecondBuilder,
};
use arrow::datatypes::{DataType, Field, Schema, SchemaRef, TimeUnit};
use arrow::record_batch::RecordBatch;
use datafusion::error::Result;

use crate::stream::{Connection, ConnectionState};

/// Schema for tcp_connections table.
pub fn tcp_connections_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("connection_id", DataType::Int64, false),
        Field::new("client_ip", DataType::Utf8, true),
        Field::new("server_ip", DataType::Utf8, true),
        Field::new("client_port", DataType::Int32, true),
        Field::new("server_port", DataType::Int32, true),
        Field::new("state", DataType::Utf8, true),
        Field::new(
            "start_time",
            DataType::Timestamp(TimeUnit::Microsecond, None),
            true,
        ),
        Field::new(
            "end_time",
            DataType::Timestamp(TimeUnit::Microsecond, None),
            true,
        ),
        Field::new("duration_us", DataType::Int64, true),
        Field::new("first_frame", DataType::Int64, true),
        Field::new("last_frame", DataType::Int64, true),
        Field::new("packets_to_server", DataType::Int32, true),
        Field::new("packets_to_client", DataType::Int32, true),
        Field::new("bytes_to_server", DataType::Int64, true),
        Field::new("bytes_to_client", DataType::Int64, true),
        Field::new("is_complete", DataType::Boolean, true),
    ]))
}

/// Build a RecordBatch from connections.
pub fn build_tcp_connections_batch(connections: &[Connection]) -> Result<RecordBatch> {
    let mut connection_id = Int64Builder::with_capacity(connections.len());
    let mut client_ip = StringBuilder::new();
    let mut server_ip = StringBuilder::new();
    let mut client_port = Int32Builder::with_capacity(connections.len());
    let mut server_port = Int32Builder::with_capacity(connections.len());
    let mut state = StringBuilder::new();
    let mut start_time = TimestampMicrosecondBuilder::with_capacity(connections.len());
    let mut end_time = TimestampMicrosecondBuilder::with_capacity(connections.len());
    let mut duration_us = Int64Builder::with_capacity(connections.len());
    let mut first_frame = Int64Builder::with_capacity(connections.len());
    let mut last_frame = Int64Builder::with_capacity(connections.len());
    let mut packets_to_server = Int32Builder::with_capacity(connections.len());
    let mut packets_to_client = Int32Builder::with_capacity(connections.len());
    let mut bytes_to_server = Int64Builder::with_capacity(connections.len());
    let mut bytes_to_client = Int64Builder::with_capacity(connections.len());
    let mut is_complete = BooleanBuilder::with_capacity(connections.len());

    for conn in connections {
        connection_id.append_value(conn.id as i64);
        client_ip.append_value(conn.client_ip().to_string());
        server_ip.append_value(conn.server_ip().to_string());
        client_port.append_value(conn.client_port() as i32);
        server_port.append_value(conn.server_port() as i32);
        state.append_value(conn.state.as_str());
        start_time.append_value(conn.start_time);

        if let Some(end) = conn.end_time {
            end_time.append_value(end);
            duration_us.append_value(end - conn.start_time);
        } else {
            end_time.append_null();
            duration_us.append_null();
        }

        first_frame.append_value(conn.first_frame as i64);
        last_frame.append_value(conn.last_frame as i64);
        packets_to_server.append_value(conn.packets_to_server as i32);
        packets_to_client.append_value(conn.packets_to_client as i32);
        bytes_to_server.append_value(conn.bytes_to_server as i64);
        bytes_to_client.append_value(conn.bytes_to_client as i64);

        // is_complete = true if connection reached a terminal state
        let complete = matches!(
            conn.state,
            ConnectionState::Closed | ConnectionState::TimeWait | ConnectionState::Reset
        );
        is_complete.append_value(complete);
    }

    let columns: Vec<ArrayRef> = vec![
        Arc::new(connection_id.finish()),
        Arc::new(client_ip.finish()),
        Arc::new(server_ip.finish()),
        Arc::new(client_port.finish()),
        Arc::new(server_port.finish()),
        Arc::new(state.finish()),
        Arc::new(start_time.finish()),
        Arc::new(end_time.finish()),
        Arc::new(duration_us.finish()),
        Arc::new(first_frame.finish()),
        Arc::new(last_frame.finish()),
        Arc::new(packets_to_server.finish()),
        Arc::new(packets_to_client.finish()),
        Arc::new(bytes_to_server.finish()),
        Arc::new(bytes_to_client.finish()),
        Arc::new(is_complete.finish()),
    ];

    RecordBatch::try_new(tcp_connections_schema(), columns)
        .map_err(|e| datafusion::error::DataFusionError::ArrowError(e, None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_connections_schema() {
        let schema = tcp_connections_schema();
        assert!(schema.field_with_name("connection_id").is_ok());
        assert!(schema.field_with_name("client_ip").is_ok());
        assert!(schema.field_with_name("server_ip").is_ok());
        assert!(schema.field_with_name("is_complete").is_ok());
    }

    #[test]
    fn test_empty_connections_batch() {
        let connections: Vec<Connection> = vec![];
        let batch = build_tcp_connections_batch(&connections);
        assert!(batch.is_ok());
        assert_eq!(batch.unwrap().num_rows(), 0);
    }
}
