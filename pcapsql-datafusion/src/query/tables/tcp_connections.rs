//! TCP connections table schema definition.
//!
//! One row per TCP connection tracked by stream reassembly (a stream-analysis
//! table: built from the whole capture in order, not per packet).
//!
//! ## Usage
//!
//! ```sql
//! SELECT client_ip, server_ip, server_port, state, bytes_to_server, bytes_to_client
//! FROM tcp_connections ORDER BY start_time;
//! ```

use arrow::datatypes::{DataType, Field, Schema, TimeUnit};

/// Build the schema for the `tcp_connections` table.
///
/// - `frame_number`: first frame of the connection (join key / capture order)
/// - `connection_id`: stream-manager connection id (shared with the other stream tables)
/// - `client_ip`, `server_ip`, `client_port`, `server_port`: endpoints (client = SYN sender)
/// - `state`: final TCP state seen (`established`, `closed`, `reset`, `mid_stream`, …)
/// - `start_time`: first segment; `end_time`, `duration_us`: last segment of a
///   connection that reached a terminal state (NULL while still open)
/// - `first_frame`, `last_frame`: frame range
/// - `packets_to_server`, `packets_to_client`: every segment in that direction
///   (handshake and pure ACKs included); `bytes_to_server`, `bytes_to_client`:
///   payload bytes
/// - `is_complete`: reached a terminal state (closed, time_wait or reset)
pub fn tcp_connections_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("connection_id", DataType::UInt64, false),
        Field::new("client_ip", DataType::Utf8, true),
        Field::new("server_ip", DataType::Utf8, true),
        Field::new("client_port", DataType::UInt16, true),
        Field::new("server_port", DataType::UInt16, true),
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
        Field::new("first_frame", DataType::UInt64, true),
        Field::new("last_frame", DataType::UInt64, true),
        Field::new("packets_to_server", DataType::UInt32, true),
        Field::new("packets_to_client", DataType::UInt32, true),
        Field::new("bytes_to_server", DataType::UInt64, true),
        Field::new("bytes_to_client", DataType::UInt64, true),
        Field::new("is_complete", DataType::Boolean, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_connections_schema() {
        let schema = tcp_connections_table_schema();
        assert_eq!(schema.fields().len(), 17);
        assert_eq!(schema.field(0).name(), "frame_number");
        assert!(schema.field_with_name("connection_id").is_ok());
        assert!(schema.field_with_name("is_complete").is_ok());
    }
}
