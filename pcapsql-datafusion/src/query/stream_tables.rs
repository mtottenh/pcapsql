//! Stream parsing to DataFusion table integration.
//!
//! This module provides functionality to process TCP streams through the
//! stream parsing pipeline (including TLS decryption) and convert the
//! results to Arrow RecordBatches for querying.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use arrow::array::{
    ArrayRef, BooleanBuilder, StringBuilder, UInt16Builder, UInt32Builder, UInt64Builder,
    UInt8Builder,
};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;

use pcapsql_core::stream::{Http2StreamParser, ParsedMessage, StreamManager};
use pcapsql_core::{FieldValue, KeyLog, PcapReader};

use crate::error::{Error, QueryError};

/// Build Arrow RecordBatches from stream-parsed messages.
///
/// This processes a PCAP file through the stream parsing pipeline
/// (TCP reassembly → TLS decryption → HTTP/2 parsing) and converts
/// the resulting messages to Arrow format.
pub struct StreamTableBuilder {
    /// Stream manager for TCP reassembly and protocol parsing
    manager: StreamManager,
    /// Collected messages by protocol
    messages: HashMap<String, Vec<ParsedMessage>>,
}

impl StreamTableBuilder {
    /// Create a new builder with optional TLS keylog.
    pub fn new(keylog: Option<Arc<KeyLog>>) -> Self {
        // Create stream manager - with_defaults() sets up default config
        let mut manager = if let Some(kl) = keylog {
            // Enable TLS decryption with keylog
            // with_keylog() also registers the TLS decryption parser
            StreamManager::with_defaults().with_keylog((*kl).clone())
        } else {
            StreamManager::with_defaults()
        };

        // Register HTTP/2 parser so it can be found as child of TLS decryption
        manager.registry_mut().register(Http2StreamParser::new());

        Self {
            manager,
            messages: HashMap::new(),
        }
    }

    /// Process a PCAP file and collect stream-parsed messages.
    pub fn process_pcap(&mut self, path: &str) -> Result<(), Error> {
        let mut reader = PcapReader::open(path)?;

        // We need to extract TCP info from each packet
        // and feed it to the stream manager
        loop {
            let processed = reader.process_packets(1000, |packet| {
                self.process_packet(packet.data, packet.frame_number as u64, packet.timestamp_us)?;
                Ok(())
            })?;

            if processed == 0 {
                break;
            }
        }

        Ok(())
    }

    /// Process a single packet's data.
    fn process_packet(&mut self, data: &[u8], frame_number: u64, timestamp: i64) -> Result<(), Error> {
        // Parse Ethernet header
        if data.len() < 14 {
            return Ok(());
        }

        let ethertype = u16::from_be_bytes([data[12], data[13]]);

        // Only process IPv4 for now (ethertype 0x0800)
        if ethertype != 0x0800 {
            return Ok(());
        }

        let ip_data = &data[14..];
        if ip_data.len() < 20 {
            return Ok(());
        }

        // Parse IPv4 header
        let ihl = (ip_data[0] & 0x0f) as usize * 4;
        let protocol = ip_data[9];

        // Only process TCP (protocol 6)
        if protocol != 6 {
            return Ok(());
        }

        if ip_data.len() < ihl {
            return Ok(());
        }

        let src_ip = IpAddr::V4(std::net::Ipv4Addr::new(
            ip_data[12], ip_data[13], ip_data[14], ip_data[15],
        ));
        let dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(
            ip_data[16], ip_data[17], ip_data[18], ip_data[19],
        ));

        let tcp_data = &ip_data[ihl..];
        if tcp_data.len() < 20 {
            return Ok(());
        }

        // Parse TCP header
        let src_port = u16::from_be_bytes([tcp_data[0], tcp_data[1]]);
        let dst_port = u16::from_be_bytes([tcp_data[2], tcp_data[3]]);
        let seq = u32::from_be_bytes([tcp_data[4], tcp_data[5], tcp_data[6], tcp_data[7]]);
        let ack = u32::from_be_bytes([tcp_data[8], tcp_data[9], tcp_data[10], tcp_data[11]]);
        let data_offset = ((tcp_data[12] >> 4) as usize) * 4;
        let flags_byte = tcp_data[13];

        let flags = pcapsql_core::stream::TcpFlags {
            fin: flags_byte & 0x01 != 0,
            syn: flags_byte & 0x02 != 0,
            rst: flags_byte & 0x04 != 0,
            ack: flags_byte & 0x10 != 0,
        };

        let payload = if tcp_data.len() > data_offset {
            &tcp_data[data_offset..]
        } else {
            &[]
        };

        // Process through stream manager
        let messages = self.manager.process_segment(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            payload,
            frame_number,
            timestamp,
        ).map_err(|e| Error::Query(QueryError::Execution(format!("Stream processing error: {}", e))))?;

        // Collect messages by protocol
        for msg in messages {
            self.messages
                .entry(msg.protocol.to_string())
                .or_default()
                .push(msg);
        }

        Ok(())
    }

    /// Get HTTP/2 messages as Arrow RecordBatches.
    pub fn http2_batches(&self, batch_size: usize) -> Result<Vec<RecordBatch>, Error> {
        let messages = match self.messages.get("http2") {
            Some(msgs) if !msgs.is_empty() => msgs,
            _ => return Ok(vec![]),
        };

        let schema = http2_arrow_schema();
        let mut batches = Vec::new();

        for chunk in messages.chunks(batch_size) {
            let batch = build_http2_batch(&schema, chunk)?;
            batches.push(batch);
        }

        Ok(batches)
    }

    /// Get count of messages by protocol.
    pub fn message_counts(&self) -> HashMap<String, usize> {
        self.messages
            .iter()
            .map(|(k, v)| (k.clone(), v.len()))
            .collect()
    }

    /// Print debug info about collected messages
    pub fn debug_info(&self) {
        eprintln!("  Stream processing collected:");
        for (protocol, msgs) in &self.messages {
            eprintln!("    {}: {} messages", protocol, msgs.len());
            // Show first few message types for debug
            if protocol == "tls" && !msgs.is_empty() {
                for (i, msg) in msgs.iter().take(5).enumerate() {
                    if let Some(ht) = msg.fields.get("handshake_type") {
                        eprintln!("      [{i}] handshake_type: {:?}", ht);
                    }
                    if let Some(rt) = msg.fields.get("record_type") {
                        eprintln!("      [{i}] record_type: {:?}", rt);
                    }
                }
            }
        }
        if self.messages.is_empty() {
            eprintln!("    (no stream messages parsed)");
        }
    }
}

/// Arrow schema for HTTP/2 table.
fn http2_arrow_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("connection_id", DataType::UInt64, true),
        Field::new("frame_type", DataType::Utf8, true),
        Field::new("stream_id", DataType::UInt32, true),
        Field::new("flags", DataType::UInt8, true),
        Field::new("length", DataType::UInt32, true),
        // Request fields
        Field::new("method", DataType::Utf8, true),
        Field::new("path", DataType::Utf8, true),
        Field::new("authority", DataType::Utf8, true),
        Field::new("scheme", DataType::Utf8, true),
        // Response fields
        Field::new("status", DataType::UInt16, true),
        // Headers
        Field::new("content_type", DataType::Utf8, true),
        Field::new("content_length", DataType::UInt64, true),
        Field::new("user_agent", DataType::Utf8, true),
        // DATA frame
        Field::new("data_length", DataType::UInt64, true),
        Field::new("end_stream", DataType::Boolean, true),
        Field::new("end_headers", DataType::Boolean, true),
        Field::new("padding_length", DataType::UInt8, true),
        // SETTINGS
        Field::new("ack", DataType::Boolean, true),
        Field::new("header_table_size", DataType::UInt32, true),
        Field::new("max_concurrent_streams", DataType::UInt32, true),
        Field::new("initial_window_size", DataType::UInt32, true),
        Field::new("max_frame_size", DataType::UInt32, true),
        // Error
        Field::new("error_code", DataType::UInt32, true),
        Field::new("error_name", DataType::Utf8, true),
        // GOAWAY
        Field::new("last_stream_id", DataType::UInt32, true),
        // WINDOW_UPDATE
        Field::new("window_increment", DataType::UInt32, true),
        // PRIORITY
        Field::new("priority_exclusive", DataType::Boolean, true),
        Field::new("priority_dependency", DataType::UInt32, true),
        Field::new("priority_weight", DataType::UInt8, true),
        // PUSH_PROMISE
        Field::new("promised_stream_id", DataType::UInt32, true),
    ]))
}

/// Build an Arrow RecordBatch from HTTP/2 messages.
fn build_http2_batch(schema: &Arc<Schema>, messages: &[ParsedMessage]) -> Result<RecordBatch, Error> {
    let mut frame_number = UInt64Builder::new();
    let mut connection_id = UInt64Builder::new();
    let mut frame_type = StringBuilder::new();
    let mut stream_id = UInt32Builder::new();
    let mut flags = UInt8Builder::new();
    let mut length = UInt32Builder::new();
    let mut method = StringBuilder::new();
    let mut path = StringBuilder::new();
    let mut authority = StringBuilder::new();
    let mut scheme = StringBuilder::new();
    let mut status = UInt16Builder::new();
    let mut content_type = StringBuilder::new();
    let mut content_length = UInt64Builder::new();
    let mut user_agent = StringBuilder::new();
    let mut data_length = UInt64Builder::new();
    let mut end_stream = BooleanBuilder::new();
    let mut end_headers = BooleanBuilder::new();
    let mut padding_length = UInt8Builder::new();
    let mut ack = BooleanBuilder::new();
    let mut header_table_size = UInt32Builder::new();
    let mut max_concurrent_streams = UInt32Builder::new();
    let mut initial_window_size = UInt32Builder::new();
    let mut max_frame_size = UInt32Builder::new();
    let mut error_code = UInt32Builder::new();
    let mut error_name = StringBuilder::new();
    let mut last_stream_id = UInt32Builder::new();
    let mut window_increment = UInt32Builder::new();
    let mut priority_exclusive = BooleanBuilder::new();
    let mut priority_dependency = UInt32Builder::new();
    let mut priority_weight = UInt8Builder::new();
    let mut promised_stream_id = UInt32Builder::new();

    for msg in messages {
        frame_number.append_value(msg.frame_number);
        connection_id.append_option(get_u64(&msg.fields, "connection_id"));
        frame_type.append_option(get_str(&msg.fields, "frame_type"));
        stream_id.append_option(get_u32(&msg.fields, "stream_id"));
        flags.append_option(get_u8(&msg.fields, "flags"));
        length.append_option(get_u32(&msg.fields, "length"));
        method.append_option(get_str(&msg.fields, "method"));
        path.append_option(get_str(&msg.fields, "path"));
        authority.append_option(get_str(&msg.fields, "authority"));
        scheme.append_option(get_str(&msg.fields, "scheme"));
        status.append_option(get_u16(&msg.fields, "status"));
        content_type.append_option(get_str(&msg.fields, "content_type"));
        content_length.append_option(get_u64(&msg.fields, "content_length"));
        user_agent.append_option(get_str(&msg.fields, "user_agent"));
        data_length.append_option(get_u64(&msg.fields, "data_length"));
        end_stream.append_option(get_bool(&msg.fields, "end_stream"));
        end_headers.append_option(get_bool(&msg.fields, "end_headers"));
        padding_length.append_option(get_u8(&msg.fields, "padding_length"));
        ack.append_option(get_bool(&msg.fields, "ack"));
        header_table_size.append_option(get_u32(&msg.fields, "header_table_size"));
        max_concurrent_streams.append_option(get_u32(&msg.fields, "max_concurrent_streams"));
        initial_window_size.append_option(get_u32(&msg.fields, "initial_window_size"));
        max_frame_size.append_option(get_u32(&msg.fields, "max_frame_size"));
        error_code.append_option(get_u32(&msg.fields, "error_code"));
        error_name.append_option(get_str(&msg.fields, "error_name"));
        last_stream_id.append_option(get_u32(&msg.fields, "last_stream_id"));
        window_increment.append_option(get_u32(&msg.fields, "window_increment"));
        priority_exclusive.append_option(get_bool(&msg.fields, "priority_exclusive"));
        priority_dependency.append_option(get_u32(&msg.fields, "priority_dependency"));
        priority_weight.append_option(get_u8(&msg.fields, "priority_weight"));
        promised_stream_id.append_option(get_u32(&msg.fields, "promised_stream_id"));
    }

    let columns: Vec<ArrayRef> = vec![
        Arc::new(frame_number.finish()),
        Arc::new(connection_id.finish()),
        Arc::new(frame_type.finish()),
        Arc::new(stream_id.finish()),
        Arc::new(flags.finish()),
        Arc::new(length.finish()),
        Arc::new(method.finish()),
        Arc::new(path.finish()),
        Arc::new(authority.finish()),
        Arc::new(scheme.finish()),
        Arc::new(status.finish()),
        Arc::new(content_type.finish()),
        Arc::new(content_length.finish()),
        Arc::new(user_agent.finish()),
        Arc::new(data_length.finish()),
        Arc::new(end_stream.finish()),
        Arc::new(end_headers.finish()),
        Arc::new(padding_length.finish()),
        Arc::new(ack.finish()),
        Arc::new(header_table_size.finish()),
        Arc::new(max_concurrent_streams.finish()),
        Arc::new(initial_window_size.finish()),
        Arc::new(max_frame_size.finish()),
        Arc::new(error_code.finish()),
        Arc::new(error_name.finish()),
        Arc::new(last_stream_id.finish()),
        Arc::new(window_increment.finish()),
        Arc::new(priority_exclusive.finish()),
        Arc::new(priority_dependency.finish()),
        Arc::new(priority_weight.finish()),
        Arc::new(promised_stream_id.finish()),
    ];

    RecordBatch::try_new(schema.clone(), columns)
        .map_err(|e| Error::Query(QueryError::Execution(format!("Failed to build batch: {}", e))))
}

// Helper functions to extract values from FieldValue
fn get_str<'a>(fields: &'a HashMap<String, FieldValue>, key: &str) -> Option<&'a str> {
    match fields.get(key) {
        Some(FieldValue::Str(s)) => Some(s),
        Some(FieldValue::OwnedString(s)) => Some(s.as_str()),
        _ => None,
    }
}

fn get_u64(fields: &HashMap<String, FieldValue>, key: &str) -> Option<u64> {
    match fields.get(key) {
        Some(FieldValue::UInt64(v)) => Some(*v),
        _ => None,
    }
}

fn get_u32(fields: &HashMap<String, FieldValue>, key: &str) -> Option<u32> {
    match fields.get(key) {
        Some(FieldValue::UInt32(v)) => Some(*v),
        _ => None,
    }
}

fn get_u16(fields: &HashMap<String, FieldValue>, key: &str) -> Option<u16> {
    match fields.get(key) {
        Some(FieldValue::UInt16(v)) => Some(*v),
        _ => None,
    }
}

fn get_u8(fields: &HashMap<String, FieldValue>, key: &str) -> Option<u8> {
    match fields.get(key) {
        Some(FieldValue::UInt8(v)) => Some(*v),
        _ => None,
    }
}

fn get_bool(fields: &HashMap<String, FieldValue>, key: &str) -> Option<bool> {
    match fields.get(key) {
        Some(FieldValue::Bool(v)) => Some(*v),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_table_builder_creation() {
        let builder = StreamTableBuilder::new(None);
        assert!(builder.messages.is_empty());
    }

    #[test]
    fn test_http2_schema() {
        let schema = http2_arrow_schema();
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("frame_type").is_ok());
        assert!(schema.field_with_name("method").is_ok());
        assert!(schema.field_with_name("path").is_ok());
    }
}
