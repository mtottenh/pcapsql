//! Arrow RecordBatch building from parsed packets.

use std::sync::Arc;

use arrow::array::*;
use arrow::datatypes::{DataType, Schema, TimeUnit};
use arrow::error::ArrowError;
use arrow::record_batch::RecordBatch;

use crate::error::{Error, QueryError};
use crate::pcap::RawPacket;
use crate::protocol::ParseResult;

// Helper functions to append optional values to builders
fn append_opt_str(builder: &mut StringBuilder, value: Option<String>) {
    match value {
        Some(s) => builder.append_value(&s),
        None => builder.append_null(),
    }
}

fn append_opt_u8(builder: &mut UInt8Builder, value: Option<u8>) {
    match value {
        Some(v) => builder.append_value(v),
        None => builder.append_null(),
    }
}

fn append_opt_u16(builder: &mut UInt16Builder, value: Option<u16>) {
    match value {
        Some(v) => builder.append_value(v),
        None => builder.append_null(),
    }
}

fn append_opt_u32(builder: &mut UInt32Builder, value: Option<u32>) {
    match value {
        Some(v) => builder.append_value(v),
        None => builder.append_null(),
    }
}

/// Builds Arrow RecordBatches from parsed packets.
pub struct PacketBatchBuilder {
    schema: Arc<Schema>,
    batch_size: usize,
    rows: usize,

    // Column builders for common fields
    frame_numbers: UInt64Builder,
    timestamps: TimestampMicrosecondBuilder,
    lengths: UInt32Builder,
    original_lengths: UInt32Builder,

    // Layer 2
    eth_srcs: StringBuilder,
    eth_dsts: StringBuilder,
    eth_types: UInt16Builder,

    // Layer 3
    src_ips: StringBuilder,
    dst_ips: StringBuilder,
    ip_versions: UInt8Builder,
    ip_ttls: UInt8Builder,
    ip_protocols: UInt8Builder,

    // Layer 4
    src_ports: UInt16Builder,
    dst_ports: UInt16Builder,
    protocols: StringBuilder,

    // TCP
    tcp_flags: UInt16Builder,
    tcp_seqs: UInt32Builder,
    tcp_acks: UInt32Builder,

    // ICMP
    icmp_types: UInt8Builder,
    icmp_codes: UInt8Builder,

    // Payload
    payload_lengths: UInt32Builder,

    // Parse error
    parse_errors: StringBuilder,
}

impl PacketBatchBuilder {
    /// Create a new batch builder with the given schema and batch size.
    pub fn new(schema: Arc<Schema>, batch_size: usize) -> Self {
        Self {
            schema,
            batch_size,
            rows: 0,
            frame_numbers: UInt64Builder::with_capacity(batch_size),
            timestamps: TimestampMicrosecondBuilder::with_capacity(batch_size),
            lengths: UInt32Builder::with_capacity(batch_size),
            original_lengths: UInt32Builder::with_capacity(batch_size),
            eth_srcs: StringBuilder::with_capacity(batch_size, batch_size * 18),
            eth_dsts: StringBuilder::with_capacity(batch_size, batch_size * 18),
            eth_types: UInt16Builder::with_capacity(batch_size),
            src_ips: StringBuilder::with_capacity(batch_size, batch_size * 45),
            dst_ips: StringBuilder::with_capacity(batch_size, batch_size * 45),
            ip_versions: UInt8Builder::with_capacity(batch_size),
            ip_ttls: UInt8Builder::with_capacity(batch_size),
            ip_protocols: UInt8Builder::with_capacity(batch_size),
            src_ports: UInt16Builder::with_capacity(batch_size),
            dst_ports: UInt16Builder::with_capacity(batch_size),
            protocols: StringBuilder::with_capacity(batch_size, batch_size * 10),
            tcp_flags: UInt16Builder::with_capacity(batch_size),
            tcp_seqs: UInt32Builder::with_capacity(batch_size),
            tcp_acks: UInt32Builder::with_capacity(batch_size),
            icmp_types: UInt8Builder::with_capacity(batch_size),
            icmp_codes: UInt8Builder::with_capacity(batch_size),
            payload_lengths: UInt32Builder::with_capacity(batch_size),
            parse_errors: StringBuilder::with_capacity(batch_size, batch_size * 50),
        }
    }

    /// Add a parsed packet to the batch.
    pub fn add_packet(
        &mut self,
        raw: &RawPacket,
        parsed: &[(&'static str, ParseResult)],
    ) -> Result<(), Error> {
        self.rows += 1;

        // Frame metadata
        self.frame_numbers.append_value(raw.frame_number);
        self.timestamps.append_value(raw.timestamp_us);
        self.lengths.append_value(raw.captured_length);
        self.original_lengths.append_value(raw.original_length);

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

        // Layer 2 (Ethernet)
        append_opt_str(
            &mut self.eth_srcs,
            eth.and_then(|(_, r)| r.get("src_mac"))
                .and_then(|v| v.as_string()),
        );
        append_opt_str(
            &mut self.eth_dsts,
            eth.and_then(|(_, r)| r.get("dst_mac"))
                .and_then(|v| v.as_string()),
        );
        append_opt_u16(
            &mut self.eth_types,
            eth.and_then(|(_, r)| r.get("ethertype"))
                .and_then(|v| v.as_u64())
                .map(|v| v as u16),
        );

        // Layer 3 (IP)
        let (is_ipv4, ip_result) = match ip {
            Some(("ipv4", r)) => (true, Some(r)),
            Some(("ipv6", r)) => (false, Some(r)),
            _ => (false, None),
        };

        append_opt_str(
            &mut self.src_ips,
            ip_result
                .and_then(|r| r.get("src_ip"))
                .and_then(|v| v.as_string()),
        );
        append_opt_str(
            &mut self.dst_ips,
            ip_result
                .and_then(|r| r.get("dst_ip"))
                .and_then(|v| v.as_string()),
        );
        append_opt_u8(
            &mut self.ip_versions,
            ip_result.map(|_| if is_ipv4 { 4 } else { 6 }),
        );
        append_opt_u8(
            &mut self.ip_ttls,
            ip_result
                .and_then(|r| r.get("ttl").or_else(|| r.get("hop_limit")))
                .and_then(|v| v.as_u64())
                .map(|v| v as u8),
        );
        append_opt_u8(
            &mut self.ip_protocols,
            ip_result
                .and_then(|r| r.get("protocol").or_else(|| r.get("next_header")))
                .and_then(|v| v.as_u64())
                .map(|v| v as u8),
        );

        // Layer 4 (TCP/UDP)
        let transport = tcp.or(udp);
        append_opt_u16(
            &mut self.src_ports,
            transport
                .and_then(|(_, r)| r.get("src_port"))
                .and_then(|v| v.as_u64())
                .map(|v| v as u16),
        );
        append_opt_u16(
            &mut self.dst_ports,
            transport
                .and_then(|(_, r)| r.get("dst_port"))
                .and_then(|v| v.as_u64())
                .map(|v| v as u16),
        );

        // Protocol name
        let protocol_name = if tcp.is_some() {
            Some("TCP".to_string())
        } else if udp.is_some() {
            Some("UDP".to_string())
        } else if icmp.is_some() {
            Some("ICMP".to_string())
        } else if ip.is_some() {
            Some("IP".to_string())
        } else {
            None
        };
        append_opt_str(&mut self.protocols, protocol_name);

        // TCP specific
        append_opt_u16(
            &mut self.tcp_flags,
            tcp.and_then(|(_, r)| r.get("flags"))
                .and_then(|v| v.as_u64())
                .map(|v| v as u16),
        );
        append_opt_u32(
            &mut self.tcp_seqs,
            tcp.and_then(|(_, r)| r.get("seq"))
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
        );
        append_opt_u32(
            &mut self.tcp_acks,
            tcp.and_then(|(_, r)| r.get("ack"))
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
        );

        // ICMP specific
        append_opt_u8(
            &mut self.icmp_types,
            icmp.and_then(|(_, r)| r.get("type"))
                .and_then(|v| v.as_u64())
                .map(|v| v as u8),
        );
        append_opt_u8(
            &mut self.icmp_codes,
            icmp.and_then(|(_, r)| r.get("code"))
                .and_then(|v| v.as_u64())
                .map(|v| v as u8),
        );

        // Payload length (remaining bytes after all parsing)
        let payload_len = parsed
            .last()
            .map(|(_, r)| r.remaining.len() as u32)
            .unwrap_or(raw.data.len() as u32);
        self.payload_lengths.append_value(payload_len);

        // Parse error
        append_opt_str(&mut self.parse_errors, parse_error);

        Ok(())
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
        // Build arrays from builders
        let arrays: Vec<Arc<dyn Array>> = vec![
            Arc::new(self.frame_numbers.finish()),
            Arc::new(self.timestamps.finish()),
            Arc::new(self.lengths.finish()),
            Arc::new(self.original_lengths.finish()),
            Arc::new(self.eth_srcs.finish()),
            Arc::new(self.eth_dsts.finish()),
            Arc::new(self.eth_types.finish()),
            Arc::new(self.src_ips.finish()),
            Arc::new(self.dst_ips.finish()),
            Arc::new(self.ip_versions.finish()),
            Arc::new(self.ip_ttls.finish()),
            Arc::new(self.ip_protocols.finish()),
            Arc::new(self.src_ports.finish()),
            Arc::new(self.dst_ports.finish()),
            Arc::new(self.protocols.finish()),
            Arc::new(self.tcp_flags.finish()),
            Arc::new(self.tcp_seqs.finish()),
            Arc::new(self.tcp_acks.finish()),
            Arc::new(self.icmp_types.finish()),
            Arc::new(self.icmp_codes.finish()),
            Arc::new(self.payload_lengths.finish()),
            Arc::new(self.parse_errors.finish()),
        ];

        // Build a schema with just the common fields we're populating
        let common_schema = Arc::new(arrow::datatypes::Schema::new(vec![
            arrow::datatypes::Field::new("frame_number", DataType::UInt64, false),
            arrow::datatypes::Field::new(
                "timestamp",
                DataType::Timestamp(TimeUnit::Microsecond, None),
                false,
            ),
            arrow::datatypes::Field::new("length", DataType::UInt32, false),
            arrow::datatypes::Field::new("original_length", DataType::UInt32, false),
            arrow::datatypes::Field::new("eth_src", DataType::Utf8, true),
            arrow::datatypes::Field::new("eth_dst", DataType::Utf8, true),
            arrow::datatypes::Field::new("eth_type", DataType::UInt16, true),
            arrow::datatypes::Field::new("src_ip", DataType::Utf8, true),
            arrow::datatypes::Field::new("dst_ip", DataType::Utf8, true),
            arrow::datatypes::Field::new("ip_version", DataType::UInt8, true),
            arrow::datatypes::Field::new("ip_ttl", DataType::UInt8, true),
            arrow::datatypes::Field::new("ip_protocol", DataType::UInt8, true),
            arrow::datatypes::Field::new("src_port", DataType::UInt16, true),
            arrow::datatypes::Field::new("dst_port", DataType::UInt16, true),
            arrow::datatypes::Field::new("protocol", DataType::Utf8, true),
            arrow::datatypes::Field::new("tcp_flags", DataType::UInt16, true),
            arrow::datatypes::Field::new("tcp_seq", DataType::UInt32, true),
            arrow::datatypes::Field::new("tcp_ack", DataType::UInt32, true),
            arrow::datatypes::Field::new("icmp_type", DataType::UInt8, true),
            arrow::datatypes::Field::new("icmp_code", DataType::UInt8, true),
            arrow::datatypes::Field::new("payload_length", DataType::UInt32, true),
            arrow::datatypes::Field::new("_parse_error", DataType::Utf8, true),
        ]));

        let batch = RecordBatch::try_new(common_schema, arrays)
            .map_err(|e: ArrowError| Error::Query(QueryError::Arrow(e.to_string())))?;

        self.rows = 0;
        Ok(batch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::protocol::FieldValue;

    fn create_test_schema() -> Arc<Schema> {
        Arc::new(Schema::new(vec![
            arrow::datatypes::Field::new("frame_number", DataType::UInt64, false),
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
        fields.insert("src_mac", FieldValue::String("00:11:22:33:44:55".to_string()));
        fields.insert("dst_mac", FieldValue::String("ff:ff:ff:ff:ff:ff".to_string()));
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

    #[test]
    fn test_builder_new() {
        let schema = create_test_schema();
        let builder = PacketBatchBuilder::new(schema, 100);

        assert_eq!(builder.batch_size, 100);
        assert_eq!(builder.rows, 0);
    }

    #[test]
    fn test_add_single_packet() {
        let schema = create_test_schema();
        let mut builder = PacketBatchBuilder::new(schema, 100);

        let raw = create_test_raw_packet(1);
        let eth = create_parsed_ethernet();
        let ipv4 = create_parsed_ipv4();
        let tcp = create_parsed_tcp();

        let parsed: Vec<(&'static str, ParseResult)> = vec![
            ("ethernet", eth),
            ("ipv4", ipv4),
            ("tcp", tcp),
        ];

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

        let parsed: Vec<(&'static str, ParseResult)> = vec![
            ("ethernet", eth),
            ("ipv4", ipv4),
            ("tcp", tcp),
        ];

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
}
