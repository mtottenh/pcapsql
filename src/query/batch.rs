//! Arrow RecordBatch building from parsed packets.

use std::collections::HashMap;
use std::sync::Arc;

use arrow::array::*;
use arrow::datatypes::{DataType, Schema, TimeUnit};
use arrow::error::ArrowError;
use arrow::record_batch::RecordBatch;

use crate::error::{Error, QueryError};
use crate::pcap::RawPacket;
use crate::protocol::{FieldValue, ParseResult};

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
            DataType::Boolean => {
                DynamicBuilder::Boolean(BooleanBuilder::with_capacity(capacity))
            }
            DataType::Utf8 => {
                DynamicBuilder::Utf8(StringBuilder::with_capacity(capacity, capacity * 32))
            }
            DataType::Binary => {
                DynamicBuilder::Binary(BinaryBuilder::with_capacity(capacity, capacity * 64))
            }
            DataType::FixedSizeBinary(size) => {
                DynamicBuilder::FixedSizeBinary(FixedSizeBinaryBuilder::with_capacity(capacity, *size))
            }
            DataType::Timestamp(TimeUnit::Microsecond, _) => {
                DynamicBuilder::TimestampMicrosecond(TimestampMicrosecondBuilder::with_capacity(
                    capacity,
                ))
            }
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
                FieldValue::String(v) => b.append_value(v),
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
                FieldValue::Null => b.append_null(),
                _ => b.append_null(),
            },
            DynamicBuilder::FixedSizeBinary(b) => match value {
                FieldValue::MacAddr(mac) => {
                    let _ = b.append_value(mac.as_slice());
                }
                FieldValue::Bytes(v) => {
                    let _ = b.append_value(v.as_slice());
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
        }
    }
}

/// Builds Arrow RecordBatches from parsed packets.
///
/// This builder dynamically creates columns for all fields in the schema,
/// including protocol-specific fields from the registry.
pub struct PacketBatchBuilder {
    schema: Arc<Schema>,
    batch_size: usize,
    rows: usize,

    /// Dynamic builders for each field in schema order
    builders: Vec<DynamicBuilder>,

    /// Map from field name to index in builders vec
    field_index: HashMap<String, usize>,
}

impl PacketBatchBuilder {
    /// Create a new batch builder with the given schema and batch size.
    pub fn new(schema: Arc<Schema>, batch_size: usize) -> Self {
        let mut builders = Vec::with_capacity(schema.fields().len());
        let mut field_index = HashMap::with_capacity(schema.fields().len());

        for (idx, field) in schema.fields().iter().enumerate() {
            builders.push(DynamicBuilder::new(field.data_type(), batch_size));
            field_index.insert(field.name().to_string(), idx);
        }

        Self {
            schema,
            batch_size,
            rows: 0,
            builders,
            field_index,
        }
    }

    /// Add a parsed packet to the batch.
    pub fn add_packet(
        &mut self,
        raw: &RawPacket,
        parsed: &[(&'static str, ParseResult)],
    ) -> Result<(), Error> {
        self.rows += 1;

        // Extract values from parsed results
        let eth = parsed.iter().find(|(name, _)| *name == "ethernet");
        let ip = parsed
            .iter()
            .find(|(name, _)| *name == "ipv4" || *name == "ipv6");
        let tcp = parsed.iter().find(|(name, _)| *name == "tcp");
        let udp = parsed.iter().find(|(name, _)| *name == "udp");
        let icmp = parsed.iter().find(|(name, _)| *name == "icmp");

        // Collect any parse errors
        let errors: Vec<String> = parsed
            .iter()
            .filter_map(|(_, r)| r.error.clone())
            .collect();
        let parse_error = if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        };

        // Calculate payload length
        let payload_len = parsed
            .last()
            .map(|(_, r)| r.remaining.len() as u32)
            .unwrap_or(raw.data.len() as u32);

        // Determine protocol name
        let protocol_name = if tcp.is_some() {
            "TCP"
        } else if udp.is_some() {
            "UDP"
        } else if icmp.is_some() {
            "ICMP"
        } else if ip.is_some() {
            "IP"
        } else {
            ""
        };

        // Determine IP version
        let (is_ipv4, ip_result) = match ip {
            Some(("ipv4", r)) => (true, Some(r)),
            Some(("ipv6", r)) => (false, Some(r)),
            _ => (false, None),
        };

        // Transport layer (TCP or UDP)
        let transport = tcp.or(udp);

        // Get field names and indices first to avoid borrow conflict
        let field_info: Vec<(usize, String)> = self
            .schema
            .fields()
            .iter()
            .map(|f| (self.field_index[f.name()], f.name().to_string()))
            .collect();

        // Iterate through all schema fields and populate values
        for (idx, field_name) in field_info {
            match field_name.as_str() {
                // Frame metadata
                "frame_number" => {
                    if let DynamicBuilder::UInt64(b) = &mut self.builders[idx] {
                        b.append_value(raw.frame_number);
                    }
                }
                "timestamp" => {
                    if let DynamicBuilder::TimestampMicrosecond(b) = &mut self.builders[idx] {
                        b.append_value(raw.timestamp_us);
                    }
                }
                "length" => {
                    if let DynamicBuilder::UInt32(b) = &mut self.builders[idx] {
                        b.append_value(raw.captured_length);
                    }
                }
                "original_length" => {
                    if let DynamicBuilder::UInt32(b) = &mut self.builders[idx] {
                        b.append_value(raw.original_length);
                    }
                }

                // Layer 2 (Ethernet)
                "eth_src" => {
                    Self::append_protocol_field_static(&mut self.builders[idx], eth, "src_mac");
                }
                "eth_dst" => {
                    Self::append_protocol_field_static(&mut self.builders[idx], eth, "dst_mac");
                }
                "eth_type" => {
                    Self::append_protocol_field_static(&mut self.builders[idx], eth, "ethertype");
                }

                // Layer 3 (IP)
                "src_ip" => {
                    Self::append_protocol_field_static(&mut self.builders[idx], ip, "src_ip");
                }
                "dst_ip" => {
                    Self::append_protocol_field_static(&mut self.builders[idx], ip, "dst_ip");
                }
                "ip_version" => {
                    if ip_result.is_some() {
                        if let DynamicBuilder::UInt8(b) = &mut self.builders[idx] {
                            b.append_value(if is_ipv4 { 4 } else { 6 });
                        }
                    } else {
                        self.builders[idx].append_null();
                    }
                }
                "ip_ttl" => {
                    if let Some(result) = ip_result {
                        if let Some(v) = result.get("ttl").or_else(|| result.get("hop_limit")) {
                            self.builders[idx].append_field_value(v);
                        } else {
                            self.builders[idx].append_null();
                        }
                    } else {
                        self.builders[idx].append_null();
                    }
                }
                "ip_protocol" => {
                    if let Some(result) = ip_result {
                        if let Some(v) = result.get("protocol").or_else(|| result.get("next_header"))
                        {
                            self.builders[idx].append_field_value(v);
                        } else {
                            self.builders[idx].append_null();
                        }
                    } else {
                        self.builders[idx].append_null();
                    }
                }

                // Layer 4 (Transport)
                "src_port" => {
                    Self::append_protocol_field_static(&mut self.builders[idx], transport, "src_port");
                }
                "dst_port" => {
                    Self::append_protocol_field_static(&mut self.builders[idx], transport, "dst_port");
                }

                // Protocol name
                "protocol" => {
                    if let DynamicBuilder::Utf8(b) = &mut self.builders[idx] {
                        if protocol_name.is_empty() {
                            b.append_null();
                        } else {
                            b.append_value(protocol_name);
                        }
                    }
                }

                // TCP specific
                "tcp_flags" => {
                    Self::append_protocol_field_static(&mut self.builders[idx], tcp, "flags");
                }
                "tcp_seq" => {
                    Self::append_protocol_field_static(&mut self.builders[idx], tcp, "seq");
                }
                "tcp_ack" => {
                    Self::append_protocol_field_static(&mut self.builders[idx], tcp, "ack");
                }

                // ICMP specific
                "icmp_type" => {
                    Self::append_protocol_field_static(&mut self.builders[idx], icmp, "type");
                }
                "icmp_code" => {
                    Self::append_protocol_field_static(&mut self.builders[idx], icmp, "code");
                }

                // Payload
                "payload_length" => {
                    if let DynamicBuilder::UInt32(b) = &mut self.builders[idx] {
                        b.append_value(payload_len);
                    }
                }

                // Parse error
                "_parse_error" => {
                    if let DynamicBuilder::Utf8(b) = &mut self.builders[idx] {
                        match &parse_error {
                            Some(e) => b.append_value(e),
                            None => b.append_null(),
                        }
                    }
                }

                // Protocol-specific fields (e.g., "dns.query_name", "tls.sni")
                other => {
                    Self::append_protocol_specific_field_static(
                        &mut self.builders[idx],
                        other,
                        parsed,
                    );
                }
            }
        }

        Ok(())
    }

    /// Helper to append a field from a protocol result (static version).
    fn append_protocol_field_static(
        builder: &mut DynamicBuilder,
        protocol_result: Option<&(&'static str, ParseResult)>,
        field_name: &str,
    ) {
        if let Some((_, result)) = protocol_result {
            if let Some(value) = result.get(field_name) {
                builder.append_field_value(value);
                return;
            }
        }
        builder.append_null();
    }

    /// Append a protocol-specific field (static version).
    fn append_protocol_specific_field_static(
        builder: &mut DynamicBuilder,
        schema_field_name: &str,
        parsed: &[(&'static str, ParseResult)],
    ) {
        // Schema field names use dot notation: "dns.query_name", "tls.sni"
        // ParseResult field names use simple names: "query_name", "sni"
        if let Some(dot_pos) = schema_field_name.find('.') {
            let protocol_prefix = &schema_field_name[..dot_pos];
            let field_suffix = &schema_field_name[dot_pos + 1..];

            // Find the protocol result that matches this prefix
            for (proto_name, result) in parsed {
                if *proto_name == protocol_prefix {
                    if let Some(value) = result.get(field_suffix) {
                        builder.append_field_value(value);
                        return;
                    }
                    break;
                }
            }
        }

        // Field not found, append null
        builder.append_null();
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
        // Build arrays from all builders
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::datatypes::Field;
    use crate::protocol::FieldValue;

    fn create_test_schema() -> Arc<Schema> {
        Arc::new(Schema::new(vec![
            Field::new("frame_number", DataType::UInt64, false),
            Field::new(
                "timestamp",
                DataType::Timestamp(TimeUnit::Microsecond, None),
                false,
            ),
            Field::new("length", DataType::UInt32, false),
            Field::new("original_length", DataType::UInt32, false),
            Field::new("eth_src", DataType::Utf8, true),
            Field::new("eth_dst", DataType::Utf8, true),
            Field::new("eth_type", DataType::UInt16, true),
            Field::new("src_ip", DataType::Utf8, true),
            Field::new("dst_ip", DataType::Utf8, true),
            Field::new("ip_version", DataType::UInt8, true),
            Field::new("ip_ttl", DataType::UInt8, true),
            Field::new("ip_protocol", DataType::UInt8, true),
            Field::new("src_port", DataType::UInt16, true),
            Field::new("dst_port", DataType::UInt16, true),
            Field::new("protocol", DataType::Utf8, true),
            Field::new("tcp_flags", DataType::UInt16, true),
            Field::new("tcp_seq", DataType::UInt32, true),
            Field::new("tcp_ack", DataType::UInt32, true),
            Field::new("icmp_type", DataType::UInt8, true),
            Field::new("icmp_code", DataType::UInt8, true),
            Field::new("payload_length", DataType::UInt32, true),
            Field::new("_parse_error", DataType::Utf8, true),
        ]))
    }

    fn create_extended_schema() -> Arc<Schema> {
        Arc::new(Schema::new(vec![
            Field::new("frame_number", DataType::UInt64, false),
            Field::new(
                "timestamp",
                DataType::Timestamp(TimeUnit::Microsecond, None),
                false,
            ),
            Field::new("length", DataType::UInt32, false),
            Field::new("original_length", DataType::UInt32, false),
            Field::new("eth_src", DataType::Utf8, true),
            Field::new("eth_dst", DataType::Utf8, true),
            Field::new("eth_type", DataType::UInt16, true),
            Field::new("src_ip", DataType::Utf8, true),
            Field::new("dst_ip", DataType::Utf8, true),
            Field::new("ip_version", DataType::UInt8, true),
            Field::new("ip_ttl", DataType::UInt8, true),
            Field::new("ip_protocol", DataType::UInt8, true),
            Field::new("src_port", DataType::UInt16, true),
            Field::new("dst_port", DataType::UInt16, true),
            Field::new("protocol", DataType::Utf8, true),
            Field::new("tcp_flags", DataType::UInt16, true),
            Field::new("tcp_seq", DataType::UInt32, true),
            Field::new("tcp_ack", DataType::UInt32, true),
            Field::new("icmp_type", DataType::UInt8, true),
            Field::new("icmp_code", DataType::UInt8, true),
            Field::new("payload_length", DataType::UInt32, true),
            Field::new("_parse_error", DataType::Utf8, true),
            // Protocol-specific fields
            Field::new("dns.query_name", DataType::Utf8, true),
            Field::new("dns.query_type", DataType::UInt16, true),
            Field::new("dns.is_query", DataType::Boolean, true),
            Field::new("tls.sni", DataType::Utf8, true),
            Field::new("tls.version", DataType::Utf8, true),
            Field::new("http.method", DataType::Utf8, true),
            Field::new("http.uri", DataType::Utf8, true),
            Field::new("http.host", DataType::Utf8, true),
        ]))
    }

    fn create_test_raw_packet(frame_number: u64) -> RawPacket {
        RawPacket {
            frame_number,
            timestamp_us: 1000000 * frame_number as i64,
            captured_length: 100,
            original_length: 100,
            link_type: 1,
            data: vec![0u8; 100],
        }
    }

    fn create_parsed_ethernet() -> ParseResult<'static> {
        let mut fields = HashMap::new();
        fields.insert(
            "src_mac",
            FieldValue::String("00:11:22:33:44:55".to_string()),
        );
        fields.insert(
            "dst_mac",
            FieldValue::String("ff:ff:ff:ff:ff:ff".to_string()),
        );
        fields.insert("ethertype", FieldValue::UInt16(0x0800));

        let mut child_hints = HashMap::new();
        child_hints.insert("ethertype", 0x0800u64);

        ParseResult {
            fields,
            remaining: &[],
            child_hints,
            error: None,
        }
    }

    fn create_parsed_ipv4() -> ParseResult<'static> {
        let mut fields = HashMap::new();
        fields.insert("src_ip", FieldValue::String("192.168.1.1".to_string()));
        fields.insert("dst_ip", FieldValue::String("192.168.1.2".to_string()));
        fields.insert("ttl", FieldValue::UInt8(64));
        fields.insert("protocol", FieldValue::UInt8(6));

        let mut child_hints = HashMap::new();
        child_hints.insert("ip_protocol", 6u64);

        ParseResult {
            fields,
            remaining: &[],
            child_hints,
            error: None,
        }
    }

    fn create_parsed_tcp() -> ParseResult<'static> {
        let mut fields = HashMap::new();
        fields.insert("src_port", FieldValue::UInt16(12345));
        fields.insert("dst_port", FieldValue::UInt16(80));
        fields.insert("seq", FieldValue::UInt32(1));
        fields.insert("ack", FieldValue::UInt32(0));
        fields.insert("flags", FieldValue::UInt16(0x02)); // SYN

        let mut child_hints = HashMap::new();
        child_hints.insert("src_port", 12345u64);
        child_hints.insert("dst_port", 80u64);

        ParseResult {
            fields,
            remaining: &[],
            child_hints,
            error: None,
        }
    }

    fn create_parsed_dns() -> ParseResult<'static> {
        let mut fields = HashMap::new();
        fields.insert(
            "query_name",
            FieldValue::String("example.com".to_string()),
        );
        fields.insert("query_type", FieldValue::UInt16(1)); // A record
        fields.insert("is_query", FieldValue::Bool(true));
        fields.insert("transaction_id", FieldValue::UInt16(0x1234));

        ParseResult {
            fields,
            remaining: &[],
            child_hints: HashMap::new(),
            error: None,
        }
    }

    fn create_parsed_tls() -> ParseResult<'static> {
        let mut fields = HashMap::new();
        fields.insert("sni", FieldValue::String("www.example.com".to_string()));
        fields.insert("version", FieldValue::String("TLS 1.3".to_string()));
        fields.insert("record_type", FieldValue::UInt8(22)); // Handshake

        ParseResult {
            fields,
            remaining: &[],
            child_hints: HashMap::new(),
            error: None,
        }
    }

    fn create_parsed_http() -> ParseResult<'static> {
        let mut fields = HashMap::new();
        fields.insert("method", FieldValue::String("GET".to_string()));
        fields.insert("uri", FieldValue::String("/index.html".to_string()));
        fields.insert("host", FieldValue::String("www.example.com".to_string()));
        fields.insert("is_request", FieldValue::Bool(true));

        ParseResult {
            fields,
            remaining: &[],
            child_hints: HashMap::new(),
            error: None,
        }
    }

    #[test]
    fn test_builder_new() {
        let schema = create_test_schema();
        let builder = PacketBatchBuilder::new(schema.clone(), 100);

        assert_eq!(builder.batch_size, 100);
        assert_eq!(builder.rows, 0);
        assert_eq!(builder.builders.len(), schema.fields().len());
    }

    #[test]
    fn test_add_single_packet() {
        let schema = create_test_schema();
        let mut builder = PacketBatchBuilder::new(schema, 100);

        let raw = create_test_raw_packet(1);
        let eth = create_parsed_ethernet();
        let ipv4 = create_parsed_ipv4();
        let tcp = create_parsed_tcp();

        let parsed: Vec<(&'static str, ParseResult)> =
            vec![("ethernet", eth), ("ipv4", ipv4), ("tcp", tcp)];

        let result = builder.add_packet(&raw, &parsed);
        assert!(result.is_ok());
        assert_eq!(builder.rows, 1);
    }

    #[test]
    fn test_add_multiple_packets() {
        let schema = create_test_schema();
        let mut builder = PacketBatchBuilder::new(schema, 100);

        for i in 1..=10 {
            let raw = create_test_raw_packet(i);
            let eth = create_parsed_ethernet();
            let parsed: Vec<(&'static str, ParseResult)> = vec![("ethernet", eth)];

            builder.add_packet(&raw, &parsed).unwrap();
        }

        assert_eq!(builder.rows, 10);
    }

    #[test]
    fn test_try_build_under_batch_size() {
        let schema = create_test_schema();
        let mut builder = PacketBatchBuilder::new(schema, 100);

        let raw = create_test_raw_packet(1);
        let eth = create_parsed_ethernet();
        let parsed: Vec<(&'static str, ParseResult)> = vec![("ethernet", eth)];

        builder.add_packet(&raw, &parsed).unwrap();

        // Should not build yet (only 1 row, batch size is 100)
        let result = builder.try_build().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_try_build_at_batch_size() {
        let schema = create_test_schema();
        let mut builder = PacketBatchBuilder::new(schema, 5);

        for i in 1..=5 {
            let raw = create_test_raw_packet(i);
            let eth = create_parsed_ethernet();
            let parsed: Vec<(&'static str, ParseResult)> = vec![("ethernet", eth)];

            builder.add_packet(&raw, &parsed).unwrap();
        }

        // Should build now (5 rows, batch size is 5)
        let result = builder.try_build().unwrap();
        assert!(result.is_some());

        let batch = result.unwrap();
        assert_eq!(batch.num_rows(), 5);

        // Builder should be reset
        assert_eq!(builder.rows, 0);
    }

    #[test]
    fn test_finish_with_partial_batch() {
        let schema = create_test_schema();
        let mut builder = PacketBatchBuilder::new(schema, 100);

        for i in 1..=3 {
            let raw = create_test_raw_packet(i);
            let eth = create_parsed_ethernet();
            let parsed: Vec<(&'static str, ParseResult)> = vec![("ethernet", eth)];

            builder.add_packet(&raw, &parsed).unwrap();
        }

        // Finish should return remaining rows
        let result = builder.finish().unwrap();
        assert!(result.is_some());

        let batch = result.unwrap();
        assert_eq!(batch.num_rows(), 3);
    }

    #[test]
    fn test_finish_with_empty_builder() {
        let schema = create_test_schema();
        let builder = PacketBatchBuilder::new(schema, 100);

        // Finish with no rows should return None
        let result = builder.finish().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_batch_schema_columns() {
        let schema = create_test_schema();
        let mut builder = PacketBatchBuilder::new(schema, 100);

        let raw = create_test_raw_packet(1);
        let eth = create_parsed_ethernet();
        let ipv4 = create_parsed_ipv4();
        let tcp = create_parsed_tcp();

        let parsed: Vec<(&'static str, ParseResult)> =
            vec![("ethernet", eth), ("ipv4", ipv4), ("tcp", tcp)];

        builder.add_packet(&raw, &parsed).unwrap();

        let batch = builder.finish().unwrap().unwrap();
        let schema = batch.schema();

        // Check expected columns exist
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("timestamp").is_ok());
        assert!(schema.field_with_name("src_ip").is_ok());
        assert!(schema.field_with_name("dst_ip").is_ok());
        assert!(schema.field_with_name("src_port").is_ok());
        assert!(schema.field_with_name("dst_port").is_ok());
        assert!(schema.field_with_name("protocol").is_ok());
        assert!(schema.field_with_name("tcp_flags").is_ok());
    }

    #[test]
    fn test_packet_with_parse_error() {
        let schema = create_test_schema();
        let mut builder = PacketBatchBuilder::new(schema, 100);

        let raw = create_test_raw_packet(1);

        // Create a result with an error
        let error_result = ParseResult {
            fields: HashMap::new(),
            remaining: &[],
            child_hints: HashMap::new(),
            error: Some("Parse error: truncated packet".to_string()),
        };

        let parsed: Vec<(&'static str, ParseResult)> = vec![("ethernet", error_result)];

        builder.add_packet(&raw, &parsed).unwrap();

        let batch = builder.finish().unwrap().unwrap();

        // Check that the error was recorded
        let error_col = batch.column_by_name("_parse_error").unwrap();
        let error_array = error_col.as_any().downcast_ref::<StringArray>().unwrap();

        assert!(!error_array.is_null(0));
        assert!(error_array.value(0).contains("Parse error"));
    }

    #[test]
    fn test_dns_fields_populated() {
        let schema = create_extended_schema();
        let mut builder = PacketBatchBuilder::new(schema, 100);

        let raw = create_test_raw_packet(1);
        let eth = create_parsed_ethernet();
        let ipv4 = create_parsed_ipv4();
        let udp = {
            let mut fields = HashMap::new();
            fields.insert("src_port", FieldValue::UInt16(12345));
            fields.insert("dst_port", FieldValue::UInt16(53));
            let mut child_hints = HashMap::new();
            child_hints.insert("src_port", 12345u64);
            child_hints.insert("dst_port", 53u64);
            ParseResult {
                fields,
                remaining: &[],
                child_hints,
                error: None,
            }
        };
        let dns = create_parsed_dns();

        let parsed: Vec<(&'static str, ParseResult)> =
            vec![("ethernet", eth), ("ipv4", ipv4), ("udp", udp), ("dns", dns)];

        builder.add_packet(&raw, &parsed).unwrap();
        let batch = builder.finish().unwrap().unwrap();

        // Verify DNS fields are populated
        let query_name_col = batch.column_by_name("dns.query_name").unwrap();
        let query_name_array = query_name_col
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(query_name_array.value(0), "example.com");

        let query_type_col = batch.column_by_name("dns.query_type").unwrap();
        let query_type_array = query_type_col
            .as_any()
            .downcast_ref::<UInt16Array>()
            .unwrap();
        assert_eq!(query_type_array.value(0), 1); // A record

        let is_query_col = batch.column_by_name("dns.is_query").unwrap();
        let is_query_array = is_query_col
            .as_any()
            .downcast_ref::<BooleanArray>()
            .unwrap();
        assert!(is_query_array.value(0));
    }

    #[test]
    fn test_tls_fields_populated() {
        let schema = create_extended_schema();
        let mut builder = PacketBatchBuilder::new(schema, 100);

        let raw = create_test_raw_packet(1);
        let eth = create_parsed_ethernet();
        let ipv4 = create_parsed_ipv4();
        let tcp = {
            let mut fields = HashMap::new();
            fields.insert("src_port", FieldValue::UInt16(12345));
            fields.insert("dst_port", FieldValue::UInt16(443));
            fields.insert("seq", FieldValue::UInt32(1));
            fields.insert("ack", FieldValue::UInt32(0));
            fields.insert("flags", FieldValue::UInt16(0x02));
            let mut child_hints = HashMap::new();
            child_hints.insert("src_port", 12345u64);
            child_hints.insert("dst_port", 443u64);
            ParseResult {
                fields,
                remaining: &[],
                child_hints,
                error: None,
            }
        };
        let tls = create_parsed_tls();

        let parsed: Vec<(&'static str, ParseResult)> =
            vec![("ethernet", eth), ("ipv4", ipv4), ("tcp", tcp), ("tls", tls)];

        builder.add_packet(&raw, &parsed).unwrap();
        let batch = builder.finish().unwrap().unwrap();

        // Verify TLS fields are populated
        let sni_col = batch.column_by_name("tls.sni").unwrap();
        let sni_array = sni_col.as_any().downcast_ref::<StringArray>().unwrap();
        assert_eq!(sni_array.value(0), "www.example.com");

        let version_col = batch.column_by_name("tls.version").unwrap();
        let version_array = version_col.as_any().downcast_ref::<StringArray>().unwrap();
        assert_eq!(version_array.value(0), "TLS 1.3");
    }

    #[test]
    fn test_http_fields_populated() {
        let schema = create_extended_schema();
        let mut builder = PacketBatchBuilder::new(schema, 100);

        let raw = create_test_raw_packet(1);
        let eth = create_parsed_ethernet();
        let ipv4 = create_parsed_ipv4();
        let tcp = {
            let mut fields = HashMap::new();
            fields.insert("src_port", FieldValue::UInt16(12345));
            fields.insert("dst_port", FieldValue::UInt16(80));
            fields.insert("seq", FieldValue::UInt32(1));
            fields.insert("ack", FieldValue::UInt32(0));
            fields.insert("flags", FieldValue::UInt16(0x18)); // PSH+ACK
            let mut child_hints = HashMap::new();
            child_hints.insert("src_port", 12345u64);
            child_hints.insert("dst_port", 80u64);
            ParseResult {
                fields,
                remaining: &[],
                child_hints,
                error: None,
            }
        };
        let http = create_parsed_http();

        let parsed: Vec<(&'static str, ParseResult)> =
            vec![("ethernet", eth), ("ipv4", ipv4), ("tcp", tcp), ("http", http)];

        builder.add_packet(&raw, &parsed).unwrap();
        let batch = builder.finish().unwrap().unwrap();

        // Verify HTTP fields are populated
        let method_col = batch.column_by_name("http.method").unwrap();
        let method_array = method_col.as_any().downcast_ref::<StringArray>().unwrap();
        assert_eq!(method_array.value(0), "GET");

        let uri_col = batch.column_by_name("http.uri").unwrap();
        let uri_array = uri_col.as_any().downcast_ref::<StringArray>().unwrap();
        assert_eq!(uri_array.value(0), "/index.html");

        let host_col = batch.column_by_name("http.host").unwrap();
        let host_array = host_col.as_any().downcast_ref::<StringArray>().unwrap();
        assert_eq!(host_array.value(0), "www.example.com");
    }

    #[test]
    fn test_missing_protocol_fields_are_null() {
        let schema = create_extended_schema();
        let mut builder = PacketBatchBuilder::new(schema, 100);

        // UDP packet without DNS/TLS/HTTP
        let raw = create_test_raw_packet(1);
        let eth = create_parsed_ethernet();
        let ipv4 = create_parsed_ipv4();
        let udp = {
            let mut fields = HashMap::new();
            fields.insert("src_port", FieldValue::UInt16(12345));
            fields.insert("dst_port", FieldValue::UInt16(8888)); // Not a recognized protocol port
            let mut child_hints = HashMap::new();
            child_hints.insert("src_port", 12345u64);
            child_hints.insert("dst_port", 8888u64);
            ParseResult {
                fields,
                remaining: &[],
                child_hints,
                error: None,
            }
        };

        let parsed: Vec<(&'static str, ParseResult)> =
            vec![("ethernet", eth), ("ipv4", ipv4), ("udp", udp)];

        builder.add_packet(&raw, &parsed).unwrap();
        let batch = builder.finish().unwrap().unwrap();

        // DNS fields should be null
        let query_name_col = batch.column_by_name("dns.query_name").unwrap();
        let query_name_array = query_name_col
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert!(query_name_array.is_null(0));

        // TLS fields should be null
        let sni_col = batch.column_by_name("tls.sni").unwrap();
        let sni_array = sni_col.as_any().downcast_ref::<StringArray>().unwrap();
        assert!(sni_array.is_null(0));

        // HTTP fields should be null
        let method_col = batch.column_by_name("http.method").unwrap();
        let method_array = method_col.as_any().downcast_ref::<StringArray>().unwrap();
        assert!(method_array.is_null(0));
    }

    #[test]
    fn test_schema_field_count_matches_columns() {
        let schema = create_extended_schema();
        let mut builder = PacketBatchBuilder::new(schema.clone(), 100);

        let raw = create_test_raw_packet(1);
        let eth = create_parsed_ethernet();
        let parsed: Vec<(&'static str, ParseResult)> = vec![("ethernet", eth)];

        builder.add_packet(&raw, &parsed).unwrap();
        let batch = builder.finish().unwrap().unwrap();

        // Number of columns in batch should match schema
        assert_eq!(batch.num_columns(), schema.fields().len());
    }
}
