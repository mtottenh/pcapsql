//! Table provider for raw TCP stream data.

use std::sync::Arc;

use arrow::array::{
    ArrayRef, BinaryBuilder, BooleanBuilder, Int32Builder, Int64Builder, StringBuilder,
};
use arrow::datatypes::{DataType, Field, Schema, SchemaRef};
use arrow::record_batch::RecordBatch;
use datafusion::error::Result;

use pcapsql_core::stream::{Direction, StreamBuffer};

/// Schema for tcp_streams table.
pub fn tcp_streams_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("connection_id", DataType::Int64, false),
        Field::new("direction", DataType::Utf8, false),
        Field::new("payload", DataType::Binary, true),
        Field::new("payload_length", DataType::Int64, true),
        Field::new("is_complete", DataType::Boolean, true),
        Field::new("gap_count", DataType::Int32, true),
        Field::new("segment_count", DataType::Int32, true),
        Field::new("retransmit_count", DataType::Int32, true),
        Field::new("out_of_order_count", DataType::Int32, true),
    ]))
}

/// Stream data for building batch.
pub struct StreamData {
    pub connection_id: u64,
    pub direction: Direction,
    pub buffer: StreamBuffer,
}

/// Build a RecordBatch from stream data.
pub fn build_tcp_streams_batch(streams: &[StreamData]) -> Result<RecordBatch> {
    let mut connection_id = Int64Builder::with_capacity(streams.len());
    let mut direction = StringBuilder::new();
    let mut payload = BinaryBuilder::new();
    let mut payload_length = Int64Builder::with_capacity(streams.len());
    let mut is_complete = BooleanBuilder::with_capacity(streams.len());
    let mut gap_count = Int32Builder::with_capacity(streams.len());
    let mut segment_count = Int32Builder::with_capacity(streams.len());
    let mut retransmit_count = Int32Builder::with_capacity(streams.len());
    let mut out_of_order_count = Int32Builder::with_capacity(streams.len());

    for stream in streams {
        connection_id.append_value(stream.connection_id as i64);
        direction.append_value(stream.direction.as_str());

        let data = stream.buffer.get_contiguous();
        payload.append_value(data);
        payload_length.append_value(data.len() as i64);
        is_complete.append_value(stream.buffer.is_complete());
        gap_count.append_value(stream.buffer.gap_count() as i32);
        segment_count.append_value(stream.buffer.segment_count() as i32);
        retransmit_count.append_value(stream.buffer.retransmit_count() as i32);
        out_of_order_count.append_value(stream.buffer.out_of_order_count() as i32);
    }

    let columns: Vec<ArrayRef> = vec![
        Arc::new(connection_id.finish()),
        Arc::new(direction.finish()),
        Arc::new(payload.finish()),
        Arc::new(payload_length.finish()),
        Arc::new(is_complete.finish()),
        Arc::new(gap_count.finish()),
        Arc::new(segment_count.finish()),
        Arc::new(retransmit_count.finish()),
        Arc::new(out_of_order_count.finish()),
    ];

    RecordBatch::try_new(tcp_streams_schema(), columns)
        .map_err(|e| datafusion::error::DataFusionError::ArrowError(Box::new(e), None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_streams_schema() {
        let schema = tcp_streams_schema();
        assert!(schema.field_with_name("connection_id").is_ok());
        assert!(schema.field_with_name("direction").is_ok());
        assert!(schema.field_with_name("payload").is_ok());
        assert!(schema.field_with_name("is_complete").is_ok());
    }

    #[test]
    fn test_empty_streams_batch() {
        let streams: Vec<StreamData> = vec![];
        let batch = build_tcp_streams_batch(&streams);
        assert!(batch.is_ok());
        assert_eq!(batch.unwrap().num_rows(), 0);
    }
}
