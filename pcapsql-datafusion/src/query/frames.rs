//! Frames table builder for raw packet data.
//!
//! The frames table provides minimal parsing - just frame metadata and raw bytes.
//! This is useful for hex dumps and custom protocol research.

use std::sync::Arc;

use arrow::array::*;
use arrow::datatypes::{DataType, Schema, TimeUnit};
use arrow::error::ArrowError;
use arrow::record_batch::RecordBatch;

use crate::error::{Error, QueryError};
use pcapsql_core::RawPacket;

/// Builds Arrow RecordBatches for the frames table (raw packet data).
pub struct FramesBatchBuilder {
    batch_size: usize,
    rows: usize,

    // Column builders
    frame_numbers: UInt64Builder,
    timestamps: TimestampMicrosecondBuilder,
    lengths: UInt32Builder,
    original_lengths: UInt32Builder,
    link_types: UInt16Builder,
    raw_data: BinaryBuilder,
}

impl FramesBatchBuilder {
    /// Create a new frames batch builder with the given batch size.
    pub fn new(batch_size: usize) -> Self {
        Self {
            batch_size,
            rows: 0,
            frame_numbers: UInt64Builder::with_capacity(batch_size),
            timestamps: TimestampMicrosecondBuilder::with_capacity(batch_size),
            lengths: UInt32Builder::with_capacity(batch_size),
            original_lengths: UInt32Builder::with_capacity(batch_size),
            link_types: UInt16Builder::with_capacity(batch_size),
            // Estimate average packet size of 500 bytes
            raw_data: BinaryBuilder::with_capacity(batch_size, batch_size * 500),
        }
    }

    /// Add a raw packet to the batch.
    pub fn add_packet(&mut self, raw: &RawPacket) {
        self.rows += 1;

        self.frame_numbers.append_value(raw.frame_number);
        self.timestamps.append_value(raw.timestamp_us);
        self.lengths.append_value(raw.captured_length);
        self.original_lengths.append_value(raw.original_length);
        self.link_types.append_value(raw.link_type);
        self.raw_data.append_value(&raw.data);
    }

    /// Check if batch is full.
    pub fn is_full(&self) -> bool {
        self.rows >= self.batch_size
    }

    /// Try to build a batch if we've reached the batch size.
    pub fn try_build(&mut self) -> Result<Option<RecordBatch>, Error> {
        if self.rows >= self.batch_size {
            self.build_batch().map(Some)
        } else {
            Ok(None)
        }
    }

    /// Finish and return the final batch (even if not full).
    pub fn finish(mut self) -> Result<Option<RecordBatch>, Error> {
        if self.rows > 0 {
            self.build_batch().map(Some)
        } else {
            Ok(None)
        }
    }

    fn build_batch(&mut self) -> Result<RecordBatch, Error> {
        let schema = Arc::new(frames_schema());

        let arrays: Vec<Arc<dyn Array>> = vec![
            Arc::new(self.frame_numbers.finish()),
            Arc::new(self.timestamps.finish()),
            Arc::new(self.lengths.finish()),
            Arc::new(self.original_lengths.finish()),
            Arc::new(self.link_types.finish()),
            Arc::new(self.raw_data.finish()),
        ];

        let batch = RecordBatch::try_new(schema, arrays)
            .map_err(|e: ArrowError| Error::Query(QueryError::Arrow(e.to_string())))?;

        self.rows = 0;
        Ok(batch)
    }
}

/// Get the schema for the frames table.
pub fn frames_schema() -> Schema {
    Schema::new(vec![
        arrow::datatypes::Field::new("frame_number", DataType::UInt64, false),
        arrow::datatypes::Field::new(
            "timestamp",
            DataType::Timestamp(TimeUnit::Microsecond, None),
            false,
        ),
        arrow::datatypes::Field::new("length", DataType::UInt32, false),
        arrow::datatypes::Field::new("original_length", DataType::UInt32, false),
        arrow::datatypes::Field::new("link_type", DataType::UInt16, false),
        arrow::datatypes::Field::new("raw_data", DataType::Binary, false),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_raw_packet(frame_number: u64, data: Vec<u8>) -> RawPacket {
        RawPacket {
            frame_number,
            timestamp_us: 1000000 * frame_number as i64,
            captured_length: data.len() as u32,
            original_length: data.len() as u32,
            link_type: 1, // Ethernet
            data: data.into(),
        }
    }

    #[test]
    fn test_frames_table_schema() {
        let schema = frames_schema();

        assert_eq!(schema.fields().len(), 6);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("timestamp").is_ok());
        assert!(schema.field_with_name("length").is_ok());
        assert!(schema.field_with_name("original_length").is_ok());
        assert!(schema.field_with_name("link_type").is_ok());
        assert!(schema.field_with_name("raw_data").is_ok());
    }

    #[test]
    fn test_frames_builder_new() {
        let builder = FramesBatchBuilder::new(100);
        assert_eq!(builder.batch_size, 100);
        assert_eq!(builder.rows, 0);
    }

    #[test]
    fn test_frames_add_packet() {
        let mut builder = FramesBatchBuilder::new(100);

        let packet_data = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Dst MAC
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Src MAC
            0x08, 0x00, // EtherType
        ];
        let raw = create_test_raw_packet(1, packet_data);

        builder.add_packet(&raw);
        assert_eq!(builder.rows, 1);
    }

    #[test]
    fn test_frames_table_raw_data() {
        let mut builder = FramesBatchBuilder::new(100);

        let packet_data = vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe];
        let raw = create_test_raw_packet(1, packet_data.clone());

        builder.add_packet(&raw);

        let batch = builder.finish().unwrap().unwrap();

        // Verify raw_data column contains exact bytes
        let raw_data_col = batch.column_by_name("raw_data").unwrap();
        let raw_data_array = raw_data_col.as_any().downcast_ref::<BinaryArray>().unwrap();

        assert_eq!(raw_data_array.value(0), packet_data.as_slice());
    }

    #[test]
    fn test_frames_try_build_at_batch_size() {
        let mut builder = FramesBatchBuilder::new(5);

        for i in 1..=5 {
            let raw = create_test_raw_packet(i, vec![0x00; 14]);
            builder.add_packet(&raw);
        }

        let result = builder.try_build().unwrap();
        assert!(result.is_some());

        let batch = result.unwrap();
        assert_eq!(batch.num_rows(), 5);
    }

    #[test]
    fn test_frames_finish_partial_batch() {
        let mut builder = FramesBatchBuilder::new(100);

        for i in 1..=3 {
            let raw = create_test_raw_packet(i, vec![0x00; 14]);
            builder.add_packet(&raw);
        }

        let result = builder.finish().unwrap();
        assert!(result.is_some());

        let batch = result.unwrap();
        assert_eq!(batch.num_rows(), 3);
    }

    #[test]
    fn test_frames_finish_empty() {
        let builder = FramesBatchBuilder::new(100);

        let result = builder.finish().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_frames_multiple_packets() {
        let mut builder = FramesBatchBuilder::new(100);

        let packets: [&[u8]; 3] = [
            &[0x01, 0x02, 0x03],
            &[0x04, 0x05, 0x06, 0x07],
            &[0x08, 0x09],
        ];

        for (i, data) in packets.iter().enumerate() {
            let raw = create_test_raw_packet((i + 1) as u64, data.to_vec());
            builder.add_packet(&raw);
        }

        let batch = builder.finish().unwrap().unwrap();
        assert_eq!(batch.num_rows(), 3);

        // Verify frame numbers
        let frame_col = batch.column_by_name("frame_number").unwrap();
        let frame_array = frame_col.as_any().downcast_ref::<UInt64Array>().unwrap();
        assert_eq!(frame_array.value(0), 1);
        assert_eq!(frame_array.value(1), 2);
        assert_eq!(frame_array.value(2), 3);

        // Verify lengths
        let length_col = batch.column_by_name("length").unwrap();
        let length_array = length_col.as_any().downcast_ref::<UInt32Array>().unwrap();
        assert_eq!(length_array.value(0), 3);
        assert_eq!(length_array.value(1), 4);
        assert_eq!(length_array.value(2), 2);
    }
}
