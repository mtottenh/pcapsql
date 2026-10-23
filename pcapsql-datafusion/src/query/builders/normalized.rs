//! Subscription-scoped batch set builder.
//!
//! Routes parsed packets into Arrow builders for exactly the tables (and
//! columns) a parse pass subscribes to, applying parse-time predicates and
//! row caps before any Arrow materialization happens.

use std::collections::HashMap;

use arrow::record_batch::RecordBatch;

use super::protocol::ProtocolBatchBuilder;
use crate::error::{Error, QueryError};
use crate::query::filter::FilterEvaluator;
use crate::query::providers::ParseSubscription;
use pcapsql_core::io::PacketRef;
use pcapsql_core::ParseResult;

/// Per-table build state within one parse pass.
struct TableSlot {
    builder: ProtocolBatchBuilder,
    batches: Vec<RecordBatch>,
    predicate: Option<FilterEvaluator>,
    fetch: Option<usize>,
    rows_added: usize,
}

impl TableSlot {
    fn capped(&self) -> bool {
        self.fetch.is_some_and(|f| self.rows_added >= f)
    }
}

/// Routes each packet's parsed layers into the subscribed tables' builders.
///
/// Usage:
/// ```ignore
/// let mut batch_set = NormalizedBatchSet::new(1000, &subscription)?;
///
/// // For each packet (borrowed, zero-copy):
/// batch_set.add_packet_from_ref(packet_ref, &parsed_results)?;
///
/// // Get the per-table batches when done:
/// let batches = batch_set.finish()?;
/// ```
pub struct NormalizedBatchSet {
    slots: HashMap<String, TableSlot>,
}

impl NormalizedBatchSet {
    /// Create builders for exactly the subscribed tables, each over its
    /// (possibly column-subset) schema.
    pub fn new(batch_size: usize, subscription: &ParseSubscription) -> Result<Self, Error> {
        let mut slots = HashMap::with_capacity(subscription.tables.len());
        for (name, sub) in &subscription.tables {
            let schema = subscription.table_schema(name).ok_or_else(|| {
                Error::Query(QueryError::Execution(format!("Unknown table: {name}")))
            })?;
            slots.insert(
                name.clone(),
                TableSlot {
                    builder: ProtocolBatchBuilder::with_schema(name.clone(), schema, batch_size),
                    batches: Vec::new(),
                    predicate: sub.predicate.clone(),
                    fetch: sub.fetch,
                    rows_added: 0,
                },
            );
        }
        Ok(Self { slots })
    }

    /// Add a packet to the subscribed tables.
    ///
    /// `packet` is a borrowed (zero-copy) reference to the packet data.
    /// `parsed` is the chain of parsed protocol layers from `parse_packet`.
    pub fn add_packet_from_ref(
        &mut self,
        packet: PacketRef<'_>,
        parsed: &[(&'static str, ParseResult<'_>)],
    ) -> Result<(), Error> {
        let frame_number = packet.frame_number;

        // The frames table is fed from packet metadata, not parse results.
        if let Some(slot) = self.slots.get_mut("frames") {
            // Predicates on frames are never pushed down (metadata fields are
            // not parse fields); only the row cap applies.
            if !slot.capped() {
                slot.builder.add_frame_from_raw(
                    packet.frame_number,
                    packet.timestamp_ns,
                    packet.captured_len,
                    packet.original_len,
                    packet.data,
                    packet.link_type,
                );
                slot.rows_added += 1;
                if let Some(batch) = slot.builder.try_build()? {
                    slot.batches.push(batch);
                }
            }
        }

        // Route each parsed protocol layer to its table, if subscribed.
        for (proto_name, result) in parsed {
            if let Some(slot) = self.slots.get_mut(*proto_name) {
                if slot.capped() {
                    continue;
                }
                if let Some(predicate) = &slot.predicate {
                    // Conservative: only a positively-false comparison drops
                    // the row; DataFusion re-checks everything kept.
                    if !predicate.matches_result(result) {
                        continue;
                    }
                }
                slot.builder.add_parsed_row(frame_number, result);
                slot.rows_added += 1;
                if let Some(batch) = slot.builder.try_build()? {
                    slot.batches.push(batch);
                }
            }
        }

        Ok(())
    }

    /// True when every subscribed table has reached its row cap — the parse
    /// loop can stop reading the source.
    pub fn all_capped(&self) -> bool {
        !self.slots.is_empty() && self.slots.values().all(TableSlot::capped)
    }

    /// Finish building and return the per-table batches.
    pub fn finish(self) -> Result<HashMap<String, Vec<RecordBatch>>, Error> {
        let mut out = HashMap::with_capacity(self.slots.len());
        for (name, mut slot) in self.slots {
            if let Some(batch) = slot.builder.finish()? {
                slot.batches.push(batch);
            }
            out.insert(name, slot.batches);
        }
        Ok(out)
    }

    /// Rows added to a table so far (pending and built).
    pub fn row_count(&self, table_name: &str) -> usize {
        self.slots
            .get(table_name)
            .map(|s| s.rows_added)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use compact_str::CompactString;
    use datafusion::logical_expr::col;
    use datafusion::prelude::lit;
    use pcapsql_core::{FieldValue, TunnelType};
    use smallvec::SmallVec;
    use std::collections::HashSet;

    const TEST_DATA: [u8; 100] = [0u8; 100];

    fn create_test_packet(frame_number: u64) -> PacketRef<'static> {
        PacketRef {
            frame_number,
            timestamp_ns: 1_000_000_000 * frame_number as i64,
            captured_len: 100,
            original_len: 100,
            link_type: 1,
            data: &TEST_DATA,
        }
    }

    fn create_ethernet_result<'a>() -> ParseResult<'a> {
        let mut fields = SmallVec::new();
        fields.push((
            "src_mac",
            FieldValue::MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        ));
        fields.push((
            "dst_mac",
            FieldValue::MacAddr([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        ));
        fields.push(("ethertype", FieldValue::UInt16(0x0800)));

        ParseResult {
            fields,
            remaining: &[],
            child_hints: SmallVec::new(),
            error: None,
            encap_depth: 0,
            tunnel_type: TunnelType::None,
            tunnel_id: None,
        }
    }

    fn create_tcp_result<'a>(dst_port: u16) -> ParseResult<'a> {
        let mut fields = SmallVec::new();
        fields.push(("src_port", FieldValue::UInt16(12345)));
        fields.push(("dst_port", FieldValue::UInt16(dst_port)));
        fields.push(("seq", FieldValue::UInt32(100)));

        ParseResult {
            fields,
            remaining: &[],
            child_hints: SmallVec::new(),
            error: None,
            encap_depth: 0,
            tunnel_type: TunnelType::None,
            tunnel_id: None,
        }
    }

    fn create_dns_result<'a>() -> ParseResult<'a> {
        let mut fields = SmallVec::new();
        fields.push((
            "query_name",
            FieldValue::OwnedString(CompactString::new("example.com")),
        ));
        fields.push(("is_query", FieldValue::Bool(true)));
        ParseResult {
            fields,
            remaining: &[],
            child_hints: SmallVec::new(),
            error: None,
            encap_depth: 0,
            tunnel_type: TunnelType::None,
            tunnel_id: None,
        }
    }

    fn sub_full(names: &[&str]) -> ParseSubscription {
        ParseSubscription::tables_full(names.iter().map(|s| s.to_string()))
    }

    #[test]
    fn builds_only_subscribed_tables() {
        let mut bs = NormalizedBatchSet::new(1000, &sub_full(&["frames", "tcp"])).unwrap();
        let parsed = vec![
            ("ethernet", create_ethernet_result()),
            ("tcp", create_tcp_result(80)),
            ("dns", create_dns_result()),
        ];
        bs.add_packet_from_ref(create_test_packet(1), &parsed)
            .unwrap();

        assert_eq!(bs.row_count("frames"), 1);
        assert_eq!(bs.row_count("tcp"), 1);
        // Unsubscribed layers are dropped, not built.
        assert_eq!(bs.row_count("ethernet"), 0);
        assert_eq!(bs.row_count("dns"), 0);

        let batches = bs.finish().unwrap();
        assert_eq!(batches.len(), 2);
        assert!(batches.contains_key("frames"));
        assert!(batches.contains_key("tcp"));
    }

    #[test]
    fn column_subset_schema_is_materialized() {
        let mut sub = sub_full(&["tcp"]);
        sub.tables.get_mut("tcp").unwrap().columns = Some(HashSet::from([
            "frame_number".to_string(),
            "dst_port".to_string(),
        ]));

        let mut bs = NormalizedBatchSet::new(1000, &sub).unwrap();
        let parsed = vec![("tcp", create_tcp_result(80))];
        bs.add_packet_from_ref(create_test_packet(1), &parsed)
            .unwrap();

        let batches = bs.finish().unwrap();
        let tcp = &batches["tcp"];
        assert_eq!(tcp.len(), 1);
        let schema = tcp[0].schema();
        assert_eq!(schema.fields().len(), 2);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("dst_port").is_ok());
        assert!(schema.field_with_name("src_port").is_err());
    }

    #[test]
    fn predicate_drops_only_positively_false_rows() {
        let mut sub = sub_full(&["tcp"]);
        sub.tables.get_mut("tcp").unwrap().predicate =
            FilterEvaluator::try_from_exprs(&[col("dst_port").eq(lit(443i32))]);

        let mut bs = NormalizedBatchSet::new(1000, &sub).unwrap();
        bs.add_packet_from_ref(create_test_packet(1), &[("tcp", create_tcp_result(80))])
            .unwrap();
        bs.add_packet_from_ref(create_test_packet(2), &[("tcp", create_tcp_result(443))])
            .unwrap();

        assert_eq!(bs.row_count("tcp"), 1);
    }

    #[test]
    fn fetch_caps_rows_and_reports_all_capped() {
        let mut sub = sub_full(&["frames"]);
        sub.tables.get_mut("frames").unwrap().fetch = Some(2);

        let mut bs = NormalizedBatchSet::new(1000, &sub).unwrap();
        for i in 1..=5 {
            bs.add_packet_from_ref(create_test_packet(i), &[]).unwrap();
        }
        assert_eq!(bs.row_count("frames"), 2);
        assert!(bs.all_capped());
    }

    #[test]
    fn batch_size_triggers_intermediate_batches() {
        let mut bs = NormalizedBatchSet::new(2, &sub_full(&["frames"])).unwrap();
        for i in 1..=5 {
            bs.add_packet_from_ref(create_test_packet(i), &[]).unwrap();
        }
        let batches = bs.finish().unwrap();
        let frames = &batches["frames"];
        // 5 rows at batch size 2 -> 2 full batches + 1 partial.
        assert_eq!(frames.len(), 3);
        let total: usize = frames.iter().map(|b| b.num_rows()).sum();
        assert_eq!(total, 5);
    }

    #[test]
    fn unknown_table_errors() {
        let result = NormalizedBatchSet::new(1000, &sub_full(&["nonexistent"]));
        assert!(result.is_err());
    }
}
