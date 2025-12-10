//! Protocol-specific batch builder.
//!
//! Builds Arrow RecordBatches for a single protocol table from parsed packet data.

use std::collections::HashMap;
use std::sync::Arc;

use arrow::array::*;
use arrow::datatypes::{DataType, Schema, TimeUnit};
use arrow::error::ArrowError;
use arrow::record_batch::RecordBatch;

use crate::error::{Error, QueryError};
use crate::query::tables;
use pcapsql_core::{FieldValue, OwnedFieldValue, OwnedParseResult, ParseResult, RawPacket, TunnelType};

/// Dynamic array builder that can hold different builder types.
enum DynamicBuilder {
    UInt8(UInt8Builder),
    UInt16(UInt16Builder),
    UInt32(UInt32Builder),
    UInt64(UInt64Builder),
    Int64(Int64Builder),
    Boolean(BooleanBuilder),
    Utf8(StringBuilder),
    Binary(BinaryBuilder),
    FixedSizeBinary(FixedSizeBinaryBuilder),
    TimestampMicrosecond(TimestampMicrosecondBuilder),
    // List builders for multi-valued fields (e.g., DNS answers)
    ListOfUInt16(ListBuilder<UInt16Builder>),
    ListOfUInt32(ListBuilder<UInt32Builder>),
    ListOfUtf8(ListBuilder<StringBuilder>),
    ListOfBinary(ListBuilder<BinaryBuilder>),
    ListOfFixedSizeBinary(ListBuilder<FixedSizeBinaryBuilder>),
}

impl DynamicBuilder {
    /// Create a new builder for the given data type.
    fn new(data_type: &DataType, capacity: usize) -> Self {
        match data_type {
            DataType::UInt8 => DynamicBuilder::UInt8(UInt8Builder::with_capacity(capacity)),
            DataType::UInt16 => DynamicBuilder::UInt16(UInt16Builder::with_capacity(capacity)),
            DataType::UInt32 => DynamicBuilder::UInt32(UInt32Builder::with_capacity(capacity)),
            DataType::UInt64 => DynamicBuilder::UInt64(UInt64Builder::with_capacity(capacity)),
            DataType::Int64 => DynamicBuilder::Int64(Int64Builder::with_capacity(capacity)),
            DataType::Boolean => DynamicBuilder::Boolean(BooleanBuilder::with_capacity(capacity)),
            DataType::Utf8 => {
                DynamicBuilder::Utf8(StringBuilder::with_capacity(capacity, capacity * 32))
            }
            DataType::Binary => {
                DynamicBuilder::Binary(BinaryBuilder::with_capacity(capacity, capacity * 64))
            }
            DataType::FixedSizeBinary(size) => {
                DynamicBuilder::FixedSizeBinary(FixedSizeBinaryBuilder::with_capacity(
                    capacity, *size,
                ))
            }
            DataType::Timestamp(TimeUnit::Microsecond, _) => {
                DynamicBuilder::TimestampMicrosecond(TimestampMicrosecondBuilder::with_capacity(
                    capacity,
                ))
            }
            // List types - match on inner type
            DataType::List(field) => match field.data_type() {
                DataType::UInt16 => DynamicBuilder::ListOfUInt16(ListBuilder::new(
                    UInt16Builder::with_capacity(capacity),
                )),
                DataType::UInt32 => DynamicBuilder::ListOfUInt32(ListBuilder::new(
                    UInt32Builder::with_capacity(capacity),
                )),
                DataType::Utf8 => DynamicBuilder::ListOfUtf8(ListBuilder::new(
                    StringBuilder::with_capacity(capacity, capacity * 32),
                )),
                DataType::Binary => DynamicBuilder::ListOfBinary(ListBuilder::new(
                    BinaryBuilder::with_capacity(capacity, capacity * 64),
                )),
                DataType::FixedSizeBinary(size) => {
                    DynamicBuilder::ListOfFixedSizeBinary(ListBuilder::new(
                        FixedSizeBinaryBuilder::with_capacity(capacity, *size),
                    ))
                }
                // Default list to Utf8 for unsupported inner types
                _ => DynamicBuilder::ListOfUtf8(ListBuilder::new(
                    StringBuilder::with_capacity(capacity, capacity * 32),
                )),
            },
            // Default to Utf8 for unsupported types
            _ => DynamicBuilder::Utf8(StringBuilder::with_capacity(capacity, capacity * 32)),
        }
    }

    /// Append a null value.
    fn append_null(&mut self) {
        match self {
            DynamicBuilder::UInt8(b) => b.append_null(),
            DynamicBuilder::UInt16(b) => b.append_null(),
            DynamicBuilder::UInt32(b) => b.append_null(),
            DynamicBuilder::UInt64(b) => b.append_null(),
            DynamicBuilder::Int64(b) => b.append_null(),
            DynamicBuilder::Boolean(b) => b.append_null(),
            DynamicBuilder::ListOfUInt16(b) => b.append_null(),
            DynamicBuilder::ListOfUInt32(b) => b.append_null(),
            DynamicBuilder::ListOfUtf8(b) => b.append_null(),
            DynamicBuilder::ListOfBinary(b) => b.append_null(),
            DynamicBuilder::ListOfFixedSizeBinary(b) => b.append_null(),
            DynamicBuilder::Utf8(b) => b.append_null(),
            DynamicBuilder::Binary(b) => b.append_null(),
            DynamicBuilder::FixedSizeBinary(b) => b.append_null(),
            DynamicBuilder::TimestampMicrosecond(b) => b.append_null(),
        }
    }

    /// Append a FieldValue.
    fn append_field_value(&mut self, value: &FieldValue) {
        match self {
            DynamicBuilder::UInt8(b) => match value {
                FieldValue::UInt8(v) => b.append_value(*v),
                FieldValue::UInt16(v) => b.append_value(*v as u8),
                FieldValue::UInt32(v) => b.append_value(*v as u8),
                FieldValue::UInt64(v) => b.append_value(*v as u8),
                FieldValue::Null => b.append_null(),
                _ => b.append_null(),
            },
            DynamicBuilder::UInt16(b) => match value {
                FieldValue::UInt16(v) => b.append_value(*v),
                FieldValue::UInt8(v) => b.append_value(*v as u16),
                FieldValue::UInt32(v) => b.append_value(*v as u16),
                FieldValue::UInt64(v) => b.append_value(*v as u16),
                FieldValue::Null => b.append_null(),
                _ => b.append_null(),
            },
            DynamicBuilder::UInt32(b) => match value {
                FieldValue::UInt32(v) => b.append_value(*v),
                FieldValue::UInt8(v) => b.append_value(*v as u32),
                FieldValue::UInt16(v) => b.append_value(*v as u32),
                FieldValue::UInt64(v) => b.append_value(*v as u32),
                FieldValue::IpAddr(addr) => {
                    // Convert IPv4 to u32
                    if let std::net::IpAddr::V4(v4) = addr {
                        b.append_value(u32::from(*v4));
                    } else {
                        b.append_null();
                    }
                }
                FieldValue::Null => b.append_null(),
                _ => b.append_null(),
            },
            DynamicBuilder::UInt64(b) => match value {
                FieldValue::UInt64(v) => b.append_value(*v),
                FieldValue::UInt8(v) => b.append_value(*v as u64),
                FieldValue::UInt16(v) => b.append_value(*v as u64),
                FieldValue::UInt32(v) => b.append_value(*v as u64),
                FieldValue::Null => b.append_null(),
                _ => b.append_null(),
            },
            DynamicBuilder::Int64(b) => match value {
                FieldValue::Int64(v) => b.append_value(*v),
                FieldValue::UInt8(v) => b.append_value(*v as i64),
                FieldValue::UInt16(v) => b.append_value(*v as i64),
                FieldValue::UInt32(v) => b.append_value(*v as i64),
                FieldValue::UInt64(v) => b.append_value(*v as i64),
                FieldValue::Null => b.append_null(),
                _ => b.append_null(),
            },
            DynamicBuilder::Boolean(b) => match value {
                FieldValue::Bool(v) => b.append_value(*v),
                FieldValue::Null => b.append_null(),
                _ => b.append_null(),
            },
            DynamicBuilder::Utf8(b) => match value {
                FieldValue::Str(v) => b.append_value(v),
                FieldValue::OwnedString(v) => b.append_value(v.as_str()),
                FieldValue::IpAddr(v) => b.append_value(v.to_string()),
                FieldValue::MacAddr(mac) => b.append_value(FieldValue::format_mac(mac)),
                FieldValue::Null => b.append_null(),
                other => {
                    if let Some(s) = other.as_string() {
                        b.append_value(s);
                    } else {
                        b.append_null();
                    }
                }
            },
            DynamicBuilder::Binary(b) => match value {
                FieldValue::Bytes(v) => b.append_value(v),
                FieldValue::OwnedBytes(v) => b.append_value(v.as_slice()),
                FieldValue::Null => b.append_null(),
                _ => b.append_null(),
            },
            DynamicBuilder::FixedSizeBinary(b) => match value {
                FieldValue::MacAddr(mac) => {
                    let _ = b.append_value(mac.as_slice());
                }
                FieldValue::Bytes(v) => {
                    let _ = b.append_value(v);
                }
                FieldValue::OwnedBytes(v) => {
                    let _ = b.append_value(v.as_slice());
                }
                FieldValue::IpAddr(addr) => {
                    // For IPv6, store as 16 bytes
                    if let std::net::IpAddr::V6(v6) = addr {
                        let _ = b.append_value(&v6.octets());
                    } else {
                        b.append_null();
                    }
                }
                FieldValue::Null => b.append_null(),
                _ => b.append_null(),
            },
            DynamicBuilder::TimestampMicrosecond(b) => match value {
                FieldValue::Int64(v) => b.append_value(*v),
                FieldValue::UInt64(v) => b.append_value(*v as i64),
                FieldValue::Null => b.append_null(),
                _ => b.append_null(),
            },
            // List builders
            DynamicBuilder::ListOfUInt16(b) => match value {
                FieldValue::List(items) => {
                    let values: Vec<Option<u16>> = items
                        .iter()
                        .map(|v| match v {
                            FieldValue::UInt16(n) => Some(*n),
                            FieldValue::UInt8(n) => Some(*n as u16),
                            _ => None,
                        })
                        .collect();
                    b.append_value(values);
                }
                FieldValue::Null => b.append_null(),
                _ => b.append_null(),
            },
            DynamicBuilder::ListOfUInt32(b) => match value {
                FieldValue::List(items) => {
                    let values: Vec<Option<u32>> = items
                        .iter()
                        .map(|v| match v {
                            FieldValue::UInt32(n) => Some(*n),
                            FieldValue::UInt16(n) => Some(*n as u32),
                            FieldValue::UInt8(n) => Some(*n as u32),
                            FieldValue::IpAddr(std::net::IpAddr::V4(v4)) => Some(u32::from(*v4)),
                            _ => None,
                        })
                        .collect();
                    b.append_value(values);
                }
                FieldValue::Null => b.append_null(),
                _ => b.append_null(),
            },
            DynamicBuilder::ListOfUtf8(b) => match value {
                FieldValue::List(items) => {
                    let values: Vec<Option<String>> = items
                        .iter()
                        .map(|v| v.as_string())
                        .collect();
                    b.append_value(values);
                }
                FieldValue::Null => b.append_null(),
                _ => b.append_null(),
            },
            DynamicBuilder::ListOfBinary(b) => match value {
                FieldValue::List(items) => {
                    let values: Vec<Option<Vec<u8>>> = items
                        .iter()
                        .map(|v| match v {
                            FieldValue::Bytes(data) => Some(data.to_vec()),
                            FieldValue::OwnedBytes(data) => Some(data.clone()),
                            _ => None,
                        })
                        .collect();
                    b.append_value(values);
                }
                FieldValue::Null => b.append_null(),
                _ => b.append_null(),
            },
            DynamicBuilder::ListOfFixedSizeBinary(b) => match value {
                FieldValue::List(items) => {
                    for item in items {
                        match item {
                            FieldValue::Bytes(data) => {
                                let _ = b.values().append_value(data);
                            }
                            FieldValue::OwnedBytes(data) => {
                                let _ = b.values().append_value(data.as_slice());
                            }
                            FieldValue::IpAddr(std::net::IpAddr::V6(v6)) => {
                                let _ = b.values().append_value(&v6.octets());
                            }
                            FieldValue::MacAddr(mac) => {
                                let _ = b.values().append_value(mac.as_slice());
                            }
                            _ => b.values().append_null(),
                        }
                    }
                    b.append(true);
                }
                FieldValue::Null => b.append_null(),
                _ => b.append_null(),
            },
        }
    }

    /// Append a u64 value (for frame_number).
    fn append_u64(&mut self, value: u64) {
        if let DynamicBuilder::UInt64(b) = self {
            b.append_value(value);
        }
    }

    /// Append a timestamp value.
    fn append_timestamp(&mut self, value: i64) {
        if let DynamicBuilder::TimestampMicrosecond(b) = self {
            b.append_value(value);
        }
    }

    /// Append raw binary data.
    fn append_binary(&mut self, value: &[u8]) {
        if let DynamicBuilder::Binary(b) = self {
            b.append_value(value);
        }
    }

    /// Finish building and return the array.
    fn finish(&mut self) -> Arc<dyn Array> {
        match self {
            DynamicBuilder::UInt8(b) => Arc::new(b.finish()),
            DynamicBuilder::UInt16(b) => Arc::new(b.finish()),
            DynamicBuilder::UInt32(b) => Arc::new(b.finish()),
            DynamicBuilder::UInt64(b) => Arc::new(b.finish()),
            DynamicBuilder::Int64(b) => Arc::new(b.finish()),
            DynamicBuilder::Boolean(b) => Arc::new(b.finish()),
            DynamicBuilder::Utf8(b) => Arc::new(b.finish()),
            DynamicBuilder::Binary(b) => Arc::new(b.finish()),
            DynamicBuilder::FixedSizeBinary(b) => Arc::new(b.finish()),
            DynamicBuilder::TimestampMicrosecond(b) => Arc::new(b.finish()),
            DynamicBuilder::ListOfUInt16(b) => Arc::new(b.finish()),
            DynamicBuilder::ListOfUInt32(b) => Arc::new(b.finish()),
            DynamicBuilder::ListOfUtf8(b) => Arc::new(b.finish()),
            DynamicBuilder::ListOfBinary(b) => Arc::new(b.finish()),
            DynamicBuilder::ListOfFixedSizeBinary(b) => Arc::new(b.finish()),
        }
    }

    /// Get the current row count.
    fn len(&self) -> usize {
        match self {
            DynamicBuilder::UInt8(b) => b.len(),
            DynamicBuilder::UInt16(b) => b.len(),
            DynamicBuilder::UInt32(b) => b.len(),
            DynamicBuilder::UInt64(b) => b.len(),
            DynamicBuilder::Int64(b) => b.len(),
            DynamicBuilder::Boolean(b) => b.len(),
            DynamicBuilder::Utf8(b) => b.len(),
            DynamicBuilder::Binary(b) => b.len(),
            DynamicBuilder::FixedSizeBinary(b) => b.len(),
            DynamicBuilder::TimestampMicrosecond(b) => b.len(),
            DynamicBuilder::ListOfUInt16(b) => b.len(),
            DynamicBuilder::ListOfUInt32(b) => b.len(),
            DynamicBuilder::ListOfUtf8(b) => b.len(),
            DynamicBuilder::ListOfBinary(b) => b.len(),
            DynamicBuilder::ListOfFixedSizeBinary(b) => b.len(),
        }
    }
}

/// Builds Arrow RecordBatches for a single protocol table.
///
/// Unlike PacketBatchBuilder which creates a flat table with all protocols,
/// ProtocolBatchBuilder creates a table with only the fields relevant to
/// a specific protocol.
pub struct ProtocolBatchBuilder {
    /// Protocol name (e.g., "ethernet", "tcp", "dns")
    protocol_name: String,
    /// Schema for this protocol table
    schema: Arc<Schema>,
    /// Batch size limit
    batch_size: usize,
    /// Number of rows added
    rows: usize,
    /// Dynamic builders for each field in schema order
    builders: Vec<DynamicBuilder>,
    /// Map from field name to index in builders vec
    field_index: HashMap<String, usize>,
}

impl ProtocolBatchBuilder {
    /// Create a new builder for a specific protocol.
    pub fn new(protocol_name: &str, batch_size: usize) -> Option<Self> {
        let schema = tables::get_table_schema(protocol_name)?;
        Some(Self::with_schema(
            protocol_name.to_string(),
            Arc::new(schema),
            batch_size,
        ))
    }

    /// Create a new builder with a specific schema.
    pub fn with_schema(protocol_name: String, schema: Arc<Schema>, batch_size: usize) -> Self {
        let mut builders = Vec::with_capacity(schema.fields().len());
        let mut field_index = HashMap::with_capacity(schema.fields().len());

        for (idx, field) in schema.fields().iter().enumerate() {
            builders.push(DynamicBuilder::new(field.data_type(), batch_size));
            field_index.insert(field.name().to_string(), idx);
        }

        Self {
            protocol_name,
            schema,
            batch_size,
            rows: 0,
            builders,
            field_index,
        }
    }

    /// Get the protocol name.
    pub fn protocol_name(&self) -> &str {
        &self.protocol_name
    }

    /// Get the schema.
    pub fn schema(&self) -> &Arc<Schema> {
        &self.schema
    }

    /// Get the current row count.
    pub fn row_count(&self) -> usize {
        self.rows
    }

    /// Check if the batch is full.
    pub fn is_full(&self) -> bool {
        self.rows >= self.batch_size
    }

    /// Add a row for the frames table.
    pub fn add_frame(&mut self, raw: &RawPacket) {
        if self.protocol_name != "frames" {
            return;
        }

        self.rows += 1;

        for (field_name, idx) in &self.field_index {
            let builder = &mut self.builders[*idx];
            match field_name.as_str() {
                "frame_number" => builder.append_u64(raw.frame_number),
                "timestamp" => builder.append_timestamp(raw.timestamp_us),
                "length" => {
                    if let DynamicBuilder::UInt32(b) = builder {
                        b.append_value(raw.captured_length);
                    }
                }
                "original_length" => {
                    if let DynamicBuilder::UInt32(b) = builder {
                        b.append_value(raw.original_length);
                    }
                }
                "link_type" => {
                    if let DynamicBuilder::UInt16(b) = builder {
                        b.append_value(raw.link_type);
                    }
                }
                "raw_data" => builder.append_binary(&raw.data),
                _ => builder.append_null(),
            }
        }
    }

    /// Add a row for the frames table from raw components.
    ///
    /// This is used in streaming mode where we have the raw packet data
    /// but not a `RawPacket` struct.
    pub fn add_frame_from_raw(
        &mut self,
        frame_number: u64,
        timestamp_us: i64,
        captured_len: u32,
        original_len: u32,
        data: &[u8],
        link_type: u16,
    ) {
        if self.protocol_name != "frames" {
            return;
        }

        self.rows += 1;

        for (field_name, idx) in &self.field_index {
            let builder = &mut self.builders[*idx];
            match field_name.as_str() {
                "frame_number" => builder.append_u64(frame_number),
                "timestamp" => builder.append_timestamp(timestamp_us),
                "length" => {
                    if let DynamicBuilder::UInt32(b) = builder {
                        b.append_value(captured_len);
                    }
                }
                "original_length" => {
                    if let DynamicBuilder::UInt32(b) = builder {
                        b.append_value(original_len);
                    }
                }
                "link_type" => {
                    if let DynamicBuilder::UInt16(b) = builder {
                        b.append_value(link_type);
                    }
                }
                "raw_data" => builder.append_binary(data),
                _ => builder.append_null(),
            }
        }
    }

    /// Add a row for a protocol table from parsed data.
    ///
    /// `frame_number` is the frame that this parsed data came from.
    /// `parsed` is the ParseResult for this specific protocol (not the whole chain).
    ///
    /// This method also populates encapsulation context fields:
    /// - `encap_depth`: Encapsulation depth when this protocol was parsed
    /// - `tunnel_type`: Type of enclosing tunnel (if inside a tunnel)
    /// - `tunnel_id`: Tunnel identifier (VNI, GRE key, TEID, etc.)
    pub fn add_parsed_row(&mut self, frame_number: u64, parsed: &ParseResult<'_>) {
        self.rows += 1;

        for (field_name, idx) in &self.field_index {
            let builder = &mut self.builders[*idx];

            if field_name == "frame_number" {
                builder.append_u64(frame_number);
            } else if field_name == "encap_depth" {
                // Special handling for encap_depth from ParseResult
                if let DynamicBuilder::UInt8(b) = builder {
                    b.append_value(parsed.encap_depth);
                }
            } else if field_name == "tunnel_type" {
                // Special handling for tunnel_type from ParseResult
                if let DynamicBuilder::Utf8(b) = builder {
                    if let Some(type_str) = parsed.tunnel_type.as_str() {
                        b.append_value(type_str);
                    } else {
                        b.append_null();
                    }
                }
            } else if field_name == "tunnel_id" {
                // Special handling for tunnel_id from ParseResult
                if let DynamicBuilder::UInt64(b) = builder {
                    if let Some(id) = parsed.tunnel_id {
                        b.append_value(id);
                    } else {
                        b.append_null();
                    }
                }
            } else if let Some(value) = parsed.get(field_name) {
                builder.append_field_value(value);
            } else {
                builder.append_null();
            }
        }
    }

    /// Add a row for a protocol table from cached parsed data.
    ///
    /// Similar to `add_parsed_row` but takes an `OwnedParseResult` from the cache.
    /// Also populates encapsulation context fields from the cached result.
    pub fn add_cached_row(&mut self, frame_number: u64, parsed: &OwnedParseResult) {
        self.rows += 1;

        for (field_name, idx) in &self.field_index {
            let builder = &mut self.builders[*idx];

            if field_name == "frame_number" {
                builder.append_u64(frame_number);
            } else if field_name == "encap_depth" {
                // Special handling for encap_depth from OwnedParseResult
                if let DynamicBuilder::UInt8(b) = builder {
                    b.append_value(parsed.encap_depth);
                }
            } else if field_name == "tunnel_type" {
                // Special handling for tunnel_type from OwnedParseResult
                if let DynamicBuilder::Utf8(b) = builder {
                    if let Some(type_str) = parsed.tunnel_type.as_str() {
                        b.append_value(type_str);
                    } else {
                        b.append_null();
                    }
                }
            } else if field_name == "tunnel_id" {
                // Special handling for tunnel_id from OwnedParseResult
                if let DynamicBuilder::UInt64(b) = builder {
                    if let Some(id) = parsed.tunnel_id {
                        b.append_value(id);
                    } else {
                        b.append_null();
                    }
                }
            } else if let Some(value) = parsed.get(field_name) {
                builder.append_field_value(value);
            } else {
                builder.append_null();
            }
        }
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
    pub fn finish(&mut self) -> Result<Option<RecordBatch>, Error> {
        if self.rows > 0 {
            self.build_batch().map(Some)
        } else {
            Ok(None)
        }
    }

    fn build_batch(&mut self) -> Result<RecordBatch, Error> {
        let arrays: Vec<Arc<dyn Array>> =
            self.builders.iter_mut().map(|b| b.finish()).collect();

        let batch = RecordBatch::try_new(self.schema.clone(), arrays)
            .map_err(|e: ArrowError| Error::Query(QueryError::Arrow(e.to_string())))?;

        // Reset builders for next batch
        self.rows = 0;
        for (idx, field) in self.schema.fields().iter().enumerate() {
            self.builders[idx] = DynamicBuilder::new(field.data_type(), self.batch_size);
        }

        Ok(batch)
    }

    /// Reset the builder, discarding any accumulated rows.
    pub fn reset(&mut self) {
        self.rows = 0;
        for (idx, field) in self.schema.fields().iter().enumerate() {
            self.builders[idx] = DynamicBuilder::new(field.data_type(), self.batch_size);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smallvec::SmallVec;

    #[test]
    fn test_protocol_builder_new() {
        let builder = ProtocolBatchBuilder::new("tcp", 100);
        assert!(builder.is_some());

        let builder = builder.unwrap();
        assert_eq!(builder.protocol_name(), "tcp");
        assert_eq!(builder.row_count(), 0);
    }

    #[test]
    fn test_unknown_protocol() {
        let builder = ProtocolBatchBuilder::new("unknown", 100);
        assert!(builder.is_none());
    }

    #[test]
    fn test_frames_builder() {
        let mut builder = ProtocolBatchBuilder::new("frames", 10).unwrap();

        let raw = RawPacket {
            frame_number: 1,
            timestamp_us: 1000000,
            captured_length: 100,
            original_length: 100,
            link_type: 1,
            data: vec![0u8; 100].into(),
        };

        builder.add_frame(&raw);
        assert_eq!(builder.row_count(), 1);

        let batch = builder.finish().unwrap().unwrap();
        assert_eq!(batch.num_rows(), 1);
    }

    #[test]
    fn test_protocol_builder_add_parsed() {
        let mut builder = ProtocolBatchBuilder::new("tcp", 10).unwrap();

        let mut fields = SmallVec::new();
        fields.push(("src_port", FieldValue::UInt16(12345)));
        fields.push(("dst_port", FieldValue::UInt16(80)));
        fields.push(("seq", FieldValue::UInt32(100)));
        fields.push(("ack", FieldValue::UInt32(0)));
        fields.push(("flags", FieldValue::UInt16(0x02)));

        let parsed = ParseResult {
            fields,
            remaining: &[],
            child_hints: SmallVec::new(),
            error: None,
            encap_depth: 0,
            tunnel_type: TunnelType::None,
            tunnel_id: None,
        };

        builder.add_parsed_row(1, &parsed);
        assert_eq!(builder.row_count(), 1);

        let batch = builder.finish().unwrap().unwrap();
        assert_eq!(batch.num_rows(), 1);

        // Verify frame_number column
        let frame_col = batch.column_by_name("frame_number").unwrap();
        let frame_array = frame_col.as_any().downcast_ref::<UInt64Array>().unwrap();
        assert_eq!(frame_array.value(0), 1);

        // Verify src_port column
        let port_col = batch.column_by_name("src_port").unwrap();
        let port_array = port_col.as_any().downcast_ref::<UInt16Array>().unwrap();
        assert_eq!(port_array.value(0), 12345);
    }

    #[test]
    fn test_batch_size_trigger() {
        let mut builder = ProtocolBatchBuilder::new("tcp", 5).unwrap();

        for i in 1..=5 {
            let mut fields = SmallVec::new();
            fields.push(("src_port", FieldValue::UInt16(12345)));
            fields.push(("dst_port", FieldValue::UInt16(80)));

            let parsed = ParseResult {
                fields,
                remaining: &[],
                child_hints: SmallVec::new(),
                error: None,
                encap_depth: 0,
                tunnel_type: TunnelType::None,
                tunnel_id: None,
            };

            builder.add_parsed_row(i, &parsed);
        }

        assert!(builder.is_full());
        let batch = builder.try_build().unwrap();
        assert!(batch.is_some());
        assert_eq!(batch.unwrap().num_rows(), 5);
        assert_eq!(builder.row_count(), 0);
    }
}
