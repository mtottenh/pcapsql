//! Normalized batch set builder.
//!
//! Orchestrates multiple ProtocolBatchBuilders to create per-protocol tables
//! from parsed packet data.

use std::collections::HashMap;
use std::sync::Arc;

use arrow::datatypes::Schema;
use arrow::record_batch::RecordBatch;

use super::protocol::ProtocolBatchBuilder;
use crate::error::Error;
use crate::pcap::RawPacket;
use crate::protocol::ParseResult;
use crate::query::tables;

/// A set of batches for all protocol tables.
pub type ProtocolBatches = HashMap<String, Vec<RecordBatch>>;

/// Orchestrates multiple ProtocolBatchBuilders to create per-protocol tables.
///
/// Usage:
/// ```ignore
/// let mut batch_set = NormalizedBatchSet::new(1000);
///
/// // For each packet:
/// batch_set.add_packet(&raw_packet, &parsed_results)?;
///
/// // Get all batches when done:
/// let batches = batch_set.finish()?;
/// // batches: HashMap<"frames" -> Vec<RecordBatch>, "tcp" -> Vec<RecordBatch>, ...>
/// ```
pub struct NormalizedBatchSet {
    /// Frames table builder
    frames_builder: ProtocolBatchBuilder,
    /// Protocol builders (keyed by table name)
    protocol_builders: HashMap<String, ProtocolBatchBuilder>,
    /// Accumulated batches for each protocol
    batches: ProtocolBatches,
}

impl NormalizedBatchSet {
    /// Create a new normalized batch set with the given batch size.
    pub fn new(batch_size: usize) -> Self {
        let frames_builder = ProtocolBatchBuilder::new("frames", batch_size)
            .expect("frames schema should exist");

        let mut protocol_builders = HashMap::new();

        // Create builders for all protocol tables (except frames)
        for table_name in tables::all_table_names() {
            if table_name == "frames" {
                continue;
            }
            if let Some(builder) = ProtocolBatchBuilder::new(table_name, batch_size) {
                protocol_builders.insert(table_name.to_string(), builder);
            }
        }

        let mut batches = HashMap::new();
        batches.insert("frames".to_string(), Vec::new());
        for name in tables::all_table_names() {
            batches.insert(name.to_string(), Vec::new());
        }

        Self {
            frames_builder,
            protocol_builders,
            batches,
        }
    }

    /// Add a packet to all relevant protocol tables.
    ///
    /// `raw` is the raw packet data.
    /// `parsed` is the chain of parsed protocol layers from parse_packet().
    pub fn add_packet(
        &mut self,
        raw: &RawPacket,
        parsed: &[(&'static str, ParseResult<'_>)],
    ) -> Result<(), Error> {
        let frame_number = raw.frame_number;

        // Always add to frames table
        self.frames_builder.add_frame(raw);
        if let Some(batch) = self.frames_builder.try_build()? {
            self.batches
                .get_mut("frames")
                .expect("frames batches should exist")
                .push(batch);
        }

        // Route each parsed protocol to its table
        for (proto_name, result) in parsed {
            // Find the table name for this protocol
            if let Some(builder) = self.protocol_builders.get_mut(*proto_name) {
                builder.add_parsed_row(frame_number, result);

                if let Some(batch) = builder.try_build()? {
                    self.batches
                        .get_mut(*proto_name)
                        .expect("protocol batches should exist")
                        .push(batch);
                }
            }
        }

        Ok(())
    }

    /// Finish building and return all batches.
    ///
    /// Returns a HashMap mapping table names to vectors of RecordBatches.
    pub fn finish(mut self) -> Result<ProtocolBatches, Error> {
        // Finish frames table
        if let Some(batch) = self.frames_builder.finish()? {
            self.batches
                .get_mut("frames")
                .expect("frames batches should exist")
                .push(batch);
        }

        // Finish all protocol tables
        for (name, mut builder) in self.protocol_builders {
            if let Some(batch) = builder.finish()? {
                self.batches
                    .get_mut(&name)
                    .expect("protocol batches should exist")
                    .push(batch);
            }
        }

        Ok(self.batches)
    }

    /// Get the schema for a specific table.
    pub fn get_schema(table_name: &str) -> Option<Arc<Schema>> {
        tables::get_table_schema(table_name).map(Arc::new)
    }

    /// Get all table names.
    pub fn table_names() -> Vec<&'static str> {
        tables::all_table_names()
    }

    /// Get the accumulated batches so far (without finishing).
    ///
    /// Note: This clones the current batches, leaving partial batches in the builders.
    pub fn current_batches(&self) -> &ProtocolBatches {
        &self.batches
    }

    /// Get the number of rows added to a specific table.
    pub fn row_count(&self, table_name: &str) -> usize {
        if table_name == "frames" {
            self.frames_builder.row_count()
                + self
                    .batches
                    .get("frames")
                    .map(|b| b.iter().map(|rb| rb.num_rows()).sum())
                    .unwrap_or(0)
        } else if let Some(builder) = self.protocol_builders.get(table_name) {
            builder.row_count()
                + self
                    .batches
                    .get(table_name)
                    .map(|b| b.iter().map(|rb| rb.num_rows()).sum())
                    .unwrap_or(0)
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::FieldValue;

    fn create_test_packet(frame_number: u64) -> RawPacket {
        RawPacket {
            frame_number,
            timestamp_us: 1000000 * frame_number as i64,
            captured_length: 100,
            original_length: 100,
            link_type: 1,
            data: vec![0u8; 100],
        }
    }

    fn create_ethernet_result<'a>() -> ParseResult<'a> {
        let mut fields = HashMap::new();
        fields.insert(
            "src_mac",
            FieldValue::MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        );
        fields.insert(
            "dst_mac",
            FieldValue::MacAddr([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        );
        fields.insert("ethertype", FieldValue::UInt16(0x0800));

        ParseResult {
            fields,
            remaining: &[],
            child_hints: HashMap::new(),
            error: None,
        }
    }

    fn create_ipv4_result<'a>() -> ParseResult<'a> {
        let mut fields = HashMap::new();
        fields.insert("version", FieldValue::UInt8(4));
        fields.insert(
            "src_ip",
            FieldValue::IpAddr(std::net::IpAddr::V4("192.168.1.1".parse().unwrap())),
        );
        fields.insert(
            "dst_ip",
            FieldValue::IpAddr(std::net::IpAddr::V4("192.168.1.2".parse().unwrap())),
        );
        fields.insert("ttl", FieldValue::UInt8(64));
        fields.insert("protocol", FieldValue::UInt8(6));

        ParseResult {
            fields,
            remaining: &[],
            child_hints: HashMap::new(),
            error: None,
        }
    }

    fn create_tcp_result<'a>() -> ParseResult<'a> {
        let mut fields = HashMap::new();
        fields.insert("src_port", FieldValue::UInt16(12345));
        fields.insert("dst_port", FieldValue::UInt16(80));
        fields.insert("seq", FieldValue::UInt32(100));
        fields.insert("ack", FieldValue::UInt32(0));
        fields.insert("flags", FieldValue::UInt16(0x02));

        ParseResult {
            fields,
            remaining: &[],
            child_hints: HashMap::new(),
            error: None,
        }
    }

    #[test]
    fn test_normalized_batch_set_new() {
        let batch_set = NormalizedBatchSet::new(1000);

        // Check that all expected tables are present
        assert!(batch_set.batches.contains_key("frames"));
        assert!(batch_set.batches.contains_key("ethernet"));
        assert!(batch_set.batches.contains_key("tcp"));
        assert!(batch_set.batches.contains_key("dns"));
    }

    #[test]
    fn test_add_packet_frames_only() {
        let mut batch_set = NormalizedBatchSet::new(1000);

        let raw = create_test_packet(1);
        let parsed: Vec<(&'static str, ParseResult)> = vec![];

        batch_set.add_packet(&raw, &parsed).unwrap();

        // Frames should have 1 row (pending)
        assert_eq!(batch_set.frames_builder.row_count(), 1);
    }

    #[test]
    fn test_add_packet_with_protocols() {
        let mut batch_set = NormalizedBatchSet::new(1000);

        let raw = create_test_packet(1);
        let eth = create_ethernet_result();
        let ipv4 = create_ipv4_result();
        let tcp = create_tcp_result();

        let parsed: Vec<(&'static str, ParseResult)> =
            vec![("ethernet", eth), ("ipv4", ipv4), ("tcp", tcp)];

        batch_set.add_packet(&raw, &parsed).unwrap();

        // Check that rows were added
        assert_eq!(batch_set.frames_builder.row_count(), 1);
        assert_eq!(
            batch_set
                .protocol_builders
                .get("ethernet")
                .unwrap()
                .row_count(),
            1
        );
        assert_eq!(
            batch_set.protocol_builders.get("ipv4").unwrap().row_count(),
            1
        );
        assert_eq!(
            batch_set.protocol_builders.get("tcp").unwrap().row_count(),
            1
        );
    }

    #[test]
    fn test_finish_produces_batches() {
        let mut batch_set = NormalizedBatchSet::new(1000);

        for i in 1..=10 {
            let raw = create_test_packet(i);
            let eth = create_ethernet_result();
            let ipv4 = create_ipv4_result();
            let tcp = create_tcp_result();

            let parsed: Vec<(&'static str, ParseResult)> =
                vec![("ethernet", eth), ("ipv4", ipv4), ("tcp", tcp)];

            batch_set.add_packet(&raw, &parsed).unwrap();
        }

        let batches = batch_set.finish().unwrap();

        // Check that all tables have batches
        assert!(!batches.get("frames").unwrap().is_empty());
        assert!(!batches.get("ethernet").unwrap().is_empty());
        assert!(!batches.get("ipv4").unwrap().is_empty());
        assert!(!batches.get("tcp").unwrap().is_empty());

        // UDP should be empty (no UDP packets added)
        assert!(batches.get("udp").unwrap().is_empty());

        // Check row counts
        let frames_rows: usize = batches.get("frames").unwrap().iter().map(|b| b.num_rows()).sum();
        assert_eq!(frames_rows, 10);
    }

    #[test]
    fn test_batch_size_triggers_build() {
        let mut batch_set = NormalizedBatchSet::new(5);

        for i in 1..=7 {
            let raw = create_test_packet(i);
            let eth = create_ethernet_result();

            let parsed: Vec<(&'static str, ParseResult)> = vec![("ethernet", eth)];

            batch_set.add_packet(&raw, &parsed).unwrap();
        }

        // Should have built one batch of 5 for frames and ethernet
        assert_eq!(batch_set.batches.get("frames").unwrap().len(), 1);
        assert_eq!(batch_set.batches.get("ethernet").unwrap().len(), 1);

        // Pending rows should be 2
        assert_eq!(batch_set.frames_builder.row_count(), 2);
        assert_eq!(
            batch_set
                .protocol_builders
                .get("ethernet")
                .unwrap()
                .row_count(),
            2
        );
    }

    #[test]
    fn test_protocol_isolation() {
        let mut batch_set = NormalizedBatchSet::new(1000);

        // Add one TCP packet
        let raw1 = create_test_packet(1);
        let eth1 = create_ethernet_result();
        let ipv4_1 = create_ipv4_result();
        let tcp1 = create_tcp_result();
        let parsed1: Vec<(&'static str, ParseResult)> =
            vec![("ethernet", eth1), ("ipv4", ipv4_1), ("tcp", tcp1)];
        batch_set.add_packet(&raw1, &parsed1).unwrap();

        // Add one DNS packet (UDP)
        let raw2 = create_test_packet(2);
        let eth2 = create_ethernet_result();
        let ipv4_2 = create_ipv4_result();

        let mut udp_fields = HashMap::new();
        udp_fields.insert("src_port", FieldValue::UInt16(12345));
        udp_fields.insert("dst_port", FieldValue::UInt16(53));
        let udp = ParseResult {
            fields: udp_fields,
            remaining: &[],
            child_hints: HashMap::new(),
            error: None,
        };

        let mut dns_fields = HashMap::new();
        dns_fields.insert("query_name", FieldValue::String("example.com".to_string()));
        dns_fields.insert("query_type", FieldValue::UInt16(1));
        dns_fields.insert("is_query", FieldValue::Bool(true));
        let dns = ParseResult {
            fields: dns_fields,
            remaining: &[],
            child_hints: HashMap::new(),
            error: None,
        };

        let parsed2: Vec<(&'static str, ParseResult)> =
            vec![("ethernet", eth2), ("ipv4", ipv4_2), ("udp", udp), ("dns", dns)];
        batch_set.add_packet(&raw2, &parsed2).unwrap();

        let batches = batch_set.finish().unwrap();

        // TCP table should have 1 row
        let tcp_rows: usize = batches.get("tcp").unwrap().iter().map(|b| b.num_rows()).sum();
        assert_eq!(tcp_rows, 1);

        // UDP table should have 1 row
        let udp_rows: usize = batches.get("udp").unwrap().iter().map(|b| b.num_rows()).sum();
        assert_eq!(udp_rows, 1);

        // DNS table should have 1 row
        let dns_rows: usize = batches.get("dns").unwrap().iter().map(|b| b.num_rows()).sum();
        assert_eq!(dns_rows, 1);

        // Frames should have 2 rows
        let frames_rows: usize = batches.get("frames").unwrap().iter().map(|b| b.num_rows()).sum();
        assert_eq!(frames_rows, 2);
    }

    #[test]
    fn test_table_names() {
        let names = NormalizedBatchSet::table_names();
        assert!(names.contains(&"frames"));
        assert!(names.contains(&"ethernet"));
        assert!(names.contains(&"tcp"));
        assert!(names.contains(&"dns"));
        assert!(names.contains(&"tls"));
    }
}
