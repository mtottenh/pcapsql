//! Protocol-specific batch builder.
//!
//! Builds Arrow RecordBatches for a single protocol table from parsed packet data.

use std::sync::Arc;

use arrow::array::*;
use arrow::datatypes::{DataType, Schema, TimeUnit};
use arrow::error::ArrowError;
use arrow::record_batch::{RecordBatch, RecordBatchOptions};

use crate::error::{Error, QueryError};
use crate::query::tables;
use pcapsql_core::{FieldValue, ParseResult};

/// Dynamic array builder that can hold different builder types.
pub(crate) enum DynamicBuilder {
    UInt8(UInt8Builder),
    UInt16(UInt16Builder),
    UInt32(UInt32Builder),
    UInt64(UInt64Builder),
    Int8(Int8Builder),
    Int32(Int32Builder),
    Int64(Int64Builder),
    Float64(Float64Builder),
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
    pub(crate) fn new(data_type: &DataType, capacity: usize) -> Self {
        match data_type {
            DataType::UInt8 => DynamicBuilder::UInt8(UInt8Builder::with_capacity(capacity)),
            DataType::UInt16 => DynamicBuilder::UInt16(UInt16Builder::with_capacity(capacity)),
            DataType::UInt32 => DynamicBuilder::UInt32(UInt32Builder::with_capacity(capacity)),
            DataType::UInt64 => DynamicBuilder::UInt64(UInt64Builder::with_capacity(capacity)),
            DataType::Int8 => DynamicBuilder::Int8(Int8Builder::with_capacity(capacity)),
            DataType::Int32 => DynamicBuilder::Int32(Int32Builder::with_capacity(capacity)),
            DataType::Int64 => DynamicBuilder::Int64(Int64Builder::with_capacity(capacity)),
            DataType::Float64 => DynamicBuilder::Float64(Float64Builder::with_capacity(capacity)),
            DataType::Boolean => DynamicBuilder::Boolean(BooleanBuilder::with_capacity(capacity)),
            DataType::Utf8 => {
                DynamicBuilder::Utf8(StringBuilder::with_capacity(capacity, capacity * 32))
            }
            DataType::Binary => {
                DynamicBuilder::Binary(BinaryBuilder::with_capacity(capacity, capacity * 64))
            }
            DataType::FixedSizeBinary(size) => DynamicBuilder::FixedSizeBinary(
                FixedSizeBinaryBuilder::with_capacity(capacity, *size),
            ),
            DataType::Timestamp(TimeUnit::Microsecond, _) => DynamicBuilder::TimestampMicrosecond(
                TimestampMicrosecondBuilder::with_capacity(capacity),
            ),
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
                DataType::FixedSizeBinary(size) => DynamicBuilder::ListOfFixedSizeBinary(
                    ListBuilder::new(FixedSizeBinaryBuilder::with_capacity(capacity, *size)),
                ),
                // Default list to Utf8 for unsupported inner types
                _ => DynamicBuilder::ListOfUtf8(ListBuilder::new(StringBuilder::with_capacity(
                    capacity,
                    capacity * 32,
                ))),
            },
            // Default to Utf8 for unsupported types
            _ => DynamicBuilder::Utf8(StringBuilder::with_capacity(capacity, capacity * 32)),
        }
    }

    /// Whether `data_type` has a dedicated builder (the Utf8 fallback would
    /// make `RecordBatch::try_new` reject the column).
    #[cfg(test)]
    fn supports(data_type: &DataType) -> bool {
        match data_type {
            DataType::UInt8
            | DataType::UInt16
            | DataType::UInt32
            | DataType::UInt64
            | DataType::Int8
            | DataType::Int32
            | DataType::Int64
            | DataType::Float64
            | DataType::Boolean
            | DataType::Utf8
            | DataType::Binary
            | DataType::FixedSizeBinary(_)
            | DataType::Timestamp(TimeUnit::Microsecond, _) => true,
            DataType::List(field) => matches!(
                field.data_type(),
                DataType::UInt16
                    | DataType::UInt32
                    | DataType::Utf8
                    | DataType::Binary
                    | DataType::FixedSizeBinary(_)
            ),
            _ => false,
        }
    }

    /// Append a null value.
    pub(crate) fn append_null(&mut self) {
        match self {
            DynamicBuilder::UInt8(b) => b.append_null(),
            DynamicBuilder::UInt16(b) => b.append_null(),
            DynamicBuilder::UInt32(b) => b.append_null(),
            DynamicBuilder::UInt64(b) => b.append_null(),
            DynamicBuilder::Int32(b) => b.append_null(),
            DynamicBuilder::Int64(b) => b.append_null(),
            DynamicBuilder::Int8(b) => b.append_null(),
            DynamicBuilder::Float64(b) => b.append_null(),
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
    ///
    /// Integer values are converted to the column's width only when they fit:
    /// a value that does not fit the column becomes NULL, never a wrapped
    /// value. Parser field widths are pinned to the table schemas by a test,
    /// so in practice every value fits; the checks are the safety net for a
    /// parser emitting a wider variant than its descriptor declares.
    pub(crate) fn append_field_value(&mut self, value: &FieldValue) {
        match self {
            DynamicBuilder::UInt8(b) => match value {
                FieldValue::UInt8(v) => b.append_value(*v),
                FieldValue::UInt16(v) => b.append_option(u8::try_from(*v).ok()),
                FieldValue::UInt32(v) => b.append_option(u8::try_from(*v).ok()),
                FieldValue::UInt64(v) => b.append_option(u8::try_from(*v).ok()),
                FieldValue::Null => b.append_null(),
                _ => b.append_null(),
            },
            DynamicBuilder::UInt16(b) => match value {
                FieldValue::UInt16(v) => b.append_value(*v),
                FieldValue::UInt8(v) => b.append_value(u16::from(*v)),
                FieldValue::UInt32(v) => b.append_option(u16::try_from(*v).ok()),
                FieldValue::UInt64(v) => b.append_option(u16::try_from(*v).ok()),
                FieldValue::Null => b.append_null(),
                _ => b.append_null(),
            },
            DynamicBuilder::UInt32(b) => match value {
                FieldValue::UInt32(v) => b.append_value(*v),
                FieldValue::UInt8(v) => b.append_value(u32::from(*v)),
                FieldValue::UInt16(v) => b.append_value(u32::from(*v)),
                FieldValue::UInt64(v) => b.append_option(u32::try_from(*v).ok()),
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
                FieldValue::UInt8(v) => b.append_value(u64::from(*v)),
                FieldValue::UInt16(v) => b.append_value(u64::from(*v)),
                FieldValue::UInt32(v) => b.append_value(u64::from(*v)),
                FieldValue::Null => b.append_null(),
                _ => b.append_null(),
            },
            DynamicBuilder::Int32(b) => match value {
                FieldValue::UInt8(v) => b.append_value(i32::from(*v)),
                FieldValue::UInt16(v) => b.append_value(i32::from(*v)),
                FieldValue::UInt32(v) => b.append_option(i32::try_from(*v).ok()),
                FieldValue::Int64(v) => b.append_option(i32::try_from(*v).ok()),
                FieldValue::Null => b.append_null(),
                _ => b.append_null(),
            },
            DynamicBuilder::Int64(b) => match value {
                FieldValue::Int64(v) => b.append_value(*v),
                FieldValue::Int8(v) => b.append_value(i64::from(*v)),
                FieldValue::UInt8(v) => b.append_value(i64::from(*v)),
                FieldValue::UInt16(v) => b.append_value(i64::from(*v)),
                FieldValue::UInt32(v) => b.append_value(i64::from(*v)),
                FieldValue::UInt64(v) => b.append_option(i64::try_from(*v).ok()),
                FieldValue::Null => b.append_null(),
                _ => b.append_null(),
            },
            DynamicBuilder::Int8(b) => match value {
                FieldValue::Int8(v) => b.append_value(*v),
                FieldValue::Int64(v) => b.append_option(i8::try_from(*v).ok()),
                FieldValue::Null => b.append_null(),
                _ => b.append_null(),
            },
            DynamicBuilder::Float64(b) => match value {
                FieldValue::Float64(v) => b.append_value(*v),
                FieldValue::Int8(v) => b.append_value(*v as f64),
                FieldValue::Int64(v) => b.append_value(*v as f64),
                FieldValue::UInt8(v) => b.append_value(*v as f64),
                FieldValue::UInt16(v) => b.append_value(*v as f64),
                FieldValue::UInt32(v) => b.append_value(*v as f64),
                FieldValue::UInt64(v) => b.append_value(*v as f64),
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
                        let _ = b.append_value(v6.octets());
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
                    let values: Vec<Option<String>> = items.iter().map(|v| v.as_string()).collect();
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
                                let _ = b.values().append_value(v6.octets());
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
    pub(crate) fn append_u64(&mut self, value: u64) {
        if let DynamicBuilder::UInt64(b) = self {
            b.append_value(value);
        }
    }

    /// Append a u32 value (frame lengths).
    pub(crate) fn append_u32(&mut self, value: u32) {
        if let DynamicBuilder::UInt32(b) = self {
            b.append_value(value);
        }
    }

    /// Append a u16 value (link type).
    pub(crate) fn append_u16(&mut self, value: u16) {
        if let DynamicBuilder::UInt16(b) = self {
            b.append_value(value);
        }
    }

    /// Append a u8 value (encap_depth).
    pub(crate) fn append_u8(&mut self, value: u8) {
        if let DynamicBuilder::UInt8(b) = self {
            b.append_value(value);
        }
    }

    /// Append a string (tunnel_type).
    pub(crate) fn append_str(&mut self, value: &str) {
        if let DynamicBuilder::Utf8(b) = self {
            b.append_value(value);
        }
    }

    /// Append a timestamp value.
    pub(crate) fn append_timestamp(&mut self, value: i64) {
        if let DynamicBuilder::TimestampMicrosecond(b) = self {
            b.append_value(value);
        }
    }

    /// Append raw binary data.
    pub(crate) fn append_binary(&mut self, value: &[u8]) {
        if let DynamicBuilder::Binary(b) = self {
            b.append_value(value);
        }
    }

    /// Finish building and return the array.
    pub(crate) fn finish(&mut self) -> Arc<dyn Array> {
        match self {
            DynamicBuilder::UInt8(b) => Arc::new(b.finish()),
            DynamicBuilder::UInt16(b) => Arc::new(b.finish()),
            DynamicBuilder::UInt32(b) => Arc::new(b.finish()),
            DynamicBuilder::UInt64(b) => Arc::new(b.finish()),
            DynamicBuilder::Int32(b) => Arc::new(b.finish()),
            DynamicBuilder::Int64(b) => Arc::new(b.finish()),
            DynamicBuilder::Int8(b) => Arc::new(b.finish()),
            DynamicBuilder::Float64(b) => Arc::new(b.finish()),
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
    #[allow(dead_code)]
    fn len(&self) -> usize {
        match self {
            DynamicBuilder::UInt8(b) => b.len(),
            DynamicBuilder::UInt16(b) => b.len(),
            DynamicBuilder::UInt32(b) => b.len(),
            DynamicBuilder::UInt64(b) => b.len(),
            DynamicBuilder::Int32(b) => b.len(),
            DynamicBuilder::Int64(b) => b.len(),
            DynamicBuilder::Int8(b) => b.len(),
            DynamicBuilder::Float64(b) => b.len(),
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

/// Where a protocol table column's value comes from in
/// [`ProtocolBatchBuilder::add_parsed_row`], resolved once from the schema.
enum ParsedSource {
    FrameNumber,
    EncapDepth,
    TunnelType,
    TunnelId,
    /// A field the parser extracted, by name.
    Field(String),
}

/// Where a `frames` column's value comes from in
/// [`ProtocolBatchBuilder::add_frame_from_raw`].
enum FrameSource {
    FrameNumber,
    Timestamp,
    Length,
    OriginalLength,
    LinkType,
    RawData,
    Null,
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
    /// Per column, in schema order: its source for a parsed row and for a
    /// `frames` row. Resolved from the column names once, so that adding a
    /// row does no string work beyond the field lookup.
    parsed_sources: Vec<ParsedSource>,
    frame_sources: Vec<FrameSource>,
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
        let fields = schema.fields();
        let builders = fields
            .iter()
            .map(|f| DynamicBuilder::new(f.data_type(), batch_size))
            .collect();
        let parsed_sources = fields
            .iter()
            .map(|f| match f.name().as_str() {
                "frame_number" => ParsedSource::FrameNumber,
                "encap_depth" => ParsedSource::EncapDepth,
                "tunnel_type" => ParsedSource::TunnelType,
                "tunnel_id" => ParsedSource::TunnelId,
                name => ParsedSource::Field(name.to_string()),
            })
            .collect();
        let frame_sources = fields
            .iter()
            .map(|f| match f.name().as_str() {
                "frame_number" => FrameSource::FrameNumber,
                "timestamp" => FrameSource::Timestamp,
                "length" => FrameSource::Length,
                "original_length" => FrameSource::OriginalLength,
                "link_type" => FrameSource::LinkType,
                "raw_data" => FrameSource::RawData,
                _ => FrameSource::Null,
            })
            .collect();

        Self {
            protocol_name,
            schema,
            batch_size,
            rows: 0,
            builders,
            parsed_sources,
            frame_sources,
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

    /// Add a row for the frames table from raw components.
    pub fn add_frame_from_raw(
        &mut self,
        frame_number: u64,
        timestamp_ns: i64,
        captured_len: u32,
        original_len: u32,
        data: &[u8],
        link_type: u16,
    ) {
        if self.protocol_name != "frames" {
            return;
        }

        self.rows += 1;

        for (source, builder) in self.frame_sources.iter().zip(self.builders.iter_mut()) {
            match source {
                FrameSource::FrameNumber => builder.append_u64(frame_number),
                // Arrow timestamp column is microseconds; reader timestamps are ns.
                FrameSource::Timestamp => builder.append_timestamp(timestamp_ns / 1_000),
                FrameSource::Length => builder.append_u32(captured_len),
                FrameSource::OriginalLength => builder.append_u32(original_len),
                FrameSource::LinkType => builder.append_u16(link_type),
                FrameSource::RawData => builder.append_binary(data),
                FrameSource::Null => builder.append_null(),
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

        for (source, builder) in self.parsed_sources.iter().zip(self.builders.iter_mut()) {
            match source {
                ParsedSource::FrameNumber => builder.append_u64(frame_number),
                // The encapsulation columns come from the ParseResult's
                // context, not from its fields.
                ParsedSource::EncapDepth => builder.append_u8(parsed.encap_depth),
                ParsedSource::TunnelType => {
                    if let DynamicBuilder::Utf8(b) = builder {
                        b.append_option(parsed.tunnel_type.as_str());
                    }
                }
                ParsedSource::TunnelId => {
                    if let DynamicBuilder::UInt64(b) = builder {
                        b.append_option(parsed.tunnel_id);
                    }
                }
                ParsedSource::Field(name) => match parsed.get(name) {
                    Some(value) => builder.append_field_value(value),
                    None => builder.append_null(),
                },
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
        let arrays: Vec<Arc<dyn Array>> = self.builders.iter_mut().map(|b| b.finish()).collect();

        // A fully projected-away schema (e.g. `SELECT count(*)`) still needs
        // its row count carried.
        let batch = if arrays.is_empty() {
            let options = RecordBatchOptions::new().with_row_count(Some(self.rows));
            RecordBatch::try_new_with_options(self.schema.clone(), arrays, &options)
                .map_err(|e: ArrowError| Error::Query(QueryError::Arrow(e.to_string())))?
        } else {
            RecordBatch::try_new(self.schema.clone(), arrays)
                .map_err(|e: ArrowError| Error::Query(QueryError::Arrow(e.to_string())))?
        };

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

    /// Every registered table column type must have a dedicated builder;
    /// the Utf8 fallback makes `RecordBatch::try_new` reject the batch as
    /// soon as the table has rows (this is how `ntp` shipped broken).
    #[test]
    fn every_table_column_type_has_a_builder() {
        for name in crate::query::tables::all_table_names() {
            let schema = crate::query::tables::get_table_schema(name).expect("schema");
            for field in schema.fields() {
                assert!(
                    DynamicBuilder::supports(field.data_type()),
                    "{name}.{}: no builder for {:?}",
                    field.name(),
                    field.data_type()
                );
            }
        }
    }
    use pcapsql_core::TunnelType;
    use smallvec::SmallVec;

    /// An integer wider than its column is NULL, not a wrapped value.
    #[test]
    fn out_of_range_integers_become_null_not_wrapped() {
        use arrow::array::{Array, UInt16Array, UInt8Array};
        let mut b8 = DynamicBuilder::new(&DataType::UInt8, 4);
        b8.append_field_value(&FieldValue::UInt16(255));
        b8.append_field_value(&FieldValue::UInt16(256));
        b8.append_field_value(&FieldValue::UInt32(0x1_0005));
        let a = b8.finish();
        let a = a.as_any().downcast_ref::<UInt8Array>().unwrap();
        assert_eq!(a.value(0), 255);
        assert!(a.is_null(1), "256 does not fit u8");
        assert!(a.is_null(2), "0x10005 must not wrap to 5");

        let mut b16 = DynamicBuilder::new(&DataType::UInt16, 4);
        b16.append_field_value(&FieldValue::UInt32(65_535));
        b16.append_field_value(&FieldValue::UInt32(65_536));
        let a = b16.finish();
        let a = a.as_any().downcast_ref::<UInt16Array>().unwrap();
        assert_eq!(a.value(0), 65_535);
        assert!(a.is_null(1));
    }

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

        let data = vec![0u8; 100];
        builder.add_frame_from_raw(1, 1_000_000_000, 100, 100, &data, 1);
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
