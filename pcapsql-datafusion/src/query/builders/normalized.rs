//! Subscription-scoped batch set builder.
//!
//! Routes parsed packets into Arrow builders for exactly the tables (and
//! columns) a parse pass subscribes to, applying parse-time predicates and
//! row caps before any Arrow materialization happens.

use std::collections::HashMap;

use super::fused::FusedBatchBuilder;
use super::protocol::ProtocolBatchBuilder;
use crate::error::{Error, QueryError};
use crate::query::filter::FilterEvaluator;
use arrow::record_batch::RecordBatch;
use std::sync::Arc;

use crate::query::providers::{BatchSender, OverflowStats, Pacer, ParseSubscription};
use pcapsql_core::io::PacketRef;
use pcapsql_core::ParseResult;

/// Where a table's completed batches go.
enum BatchSink {
    /// Accumulate in memory (materialize / cache-fill path).
    Accumulate(Vec<RecordBatch>),
    /// Stream to a consumer as batches complete (streaming path), through a
    /// bounded exchange that buffers (and accounts) when the consumer lags.
    Stream(BatchSender),
}

impl BatchSink {
    /// Deliver a batch. Returns `true` when the consumer is gone (the
    /// receiver was dropped: the query finished early or was cancelled).
    fn emit(&mut self, batch: RecordBatch) -> bool {
        match self {
            BatchSink::Accumulate(v) => {
                v.push(batch);
                false
            }
            BatchSink::Stream(tx) => tx.send(batch),
        }
    }
}

/// The rows of one output table: a protocol table's, or a fused join's.
enum RowBuilder {
    Protocol(ProtocolBatchBuilder),
    Fused(FusedBatchBuilder),
}

impl RowBuilder {
    fn try_build(&mut self) -> Result<Option<RecordBatch>, Error> {
        match self {
            RowBuilder::Protocol(b) => b.try_build(),
            RowBuilder::Fused(b) => b.try_build(),
        }
    }

    fn finish(&mut self) -> Result<Option<RecordBatch>, Error> {
        match self {
            RowBuilder::Protocol(b) => b.finish(),
            RowBuilder::Fused(b) => b.finish(),
        }
    }
}

/// Per-table build state within one parse pass.
struct TableSlot {
    builder: RowBuilder,
    sink: BatchSink,
    predicate: Option<FilterEvaluator>,
    fetch: Option<usize>,
    rows_added: usize,
    /// The streaming consumer dropped its receiver; nothing more is wanted.
    consumer_gone: bool,
}

impl TableSlot {
    fn capped(&self) -> bool {
        self.fetch.is_some_and(|f| self.rows_added >= f)
    }

    /// Nothing further this slot produces can be observed.
    fn done(&self) -> bool {
        self.capped() || self.consumer_gone
    }

    fn emit(&mut self, batch: RecordBatch) {
        if self.sink.emit(batch) {
            self.consumer_gone = true;
        }
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
    /// The slots that are fused joins, fed after the protocol tables.
    fused: Vec<String>,
    /// Streaming only: wakes the producer when a consumer takes a batch.
    pacer: Option<Arc<Pacer>>,
}

impl NormalizedBatchSet {
    /// Create builders for exactly the subscribed tables (materialize mode:
    /// completed batches accumulate in memory).
    pub fn new(batch_size: usize, subscription: &ParseSubscription) -> Result<Self, Error> {
        Self::build(batch_size, subscription, |_| {
            BatchSink::Accumulate(Vec::new())
        })
    }

    /// Create builders that stream each table's completed batches to the
    /// matching sender (streaming mode), taking ownership of the senders. A
    /// table without a sender accumulates (and is dropped on finish).
    pub fn new_streaming(
        batch_size: usize,
        subscription: &ParseSubscription,
        mut senders: HashMap<String, BatchSender>,
        pacer: Arc<Pacer>,
    ) -> Result<Self, Error> {
        let mut set = Self::build(batch_size, subscription, |name| {
            match senders.remove(name) {
                Some(tx) => BatchSink::Stream(tx),
                None => BatchSink::Accumulate(Vec::new()),
            }
        })?;
        set.pacer = Some(pacer);
        Ok(set)
    }

    fn build(
        batch_size: usize,
        subscription: &ParseSubscription,
        mut sink_for: impl FnMut(&str) -> BatchSink,
    ) -> Result<Self, Error> {
        let mut slots =
            HashMap::with_capacity(subscription.tables.len() + subscription.fused.len());
        for (name, sub) in &subscription.tables {
            let schema = subscription.table_schema(name).ok_or_else(|| {
                Error::Query(QueryError::Execution(format!("Unknown table: {name}")))
            })?;
            slots.insert(
                name.clone(),
                TableSlot {
                    builder: RowBuilder::Protocol(ProtocolBatchBuilder::with_schema(
                        name.clone(),
                        schema,
                        batch_size,
                    )),
                    sink: sink_for(name),
                    predicate: sub.predicate.clone(),
                    fetch: sub.fetch,
                    rows_added: 0,
                    consumer_gone: false,
                },
            );
        }
        let mut fused: Vec<String> = subscription.fused.keys().cloned().collect();
        fused.sort();
        for name in &fused {
            let sub = &subscription.fused[name];
            slots.insert(
                name.clone(),
                TableSlot {
                    builder: RowBuilder::Fused(FusedBatchBuilder::new(
                        Arc::clone(&sub.spec),
                        batch_size,
                    )),
                    sink: sink_for(name),
                    predicate: None,
                    fetch: sub.fetch,
                    rows_added: 0,
                    consumer_gone: false,
                },
            );
        }
        Ok(Self {
            slots,
            fused,
            pacer: None,
        })
    }

    /// Streaming: the producer may proceed with a batch for `name` when that
    /// table can take it normally, when its consumer is gone, or when the
    /// consumer is parked waiting on some *other* live streamed table — it
    /// will not poll this one until that table is complete (hash-join build
    /// side, sort input), so waiting here would deadlock.
    fn may_proceed(slots: &HashMap<String, TableSlot>, name: &str) -> bool {
        let this = match &slots[name].sink {
            BatchSink::Stream(tx) => tx,
            BatchSink::Accumulate(_) => return true,
        };
        if this.consumer_gone() || !this.is_backlogged() {
            return true;
        }
        slots.iter().any(|(other, slot)| {
            other != name
                && matches!(&slot.sink, BatchSink::Stream(tx) if !tx.consumer_gone() && tx.consumer_waiting())
        })
    }

    /// Deliver a completed batch for `name`, applying backpressure first:
    /// while this table is backlogged and the consumer is not parked on
    /// another table, the consumer is merely slower than the parse, so wait
    /// for it. Otherwise the batch is offered and, if the channel is still
    /// full, goes to the table's accounted overflow queue rather than
    /// stalling the pass.
    fn deliver(&mut self, name: &str, batch: RecordBatch) {
        if let Some(pacer) = &self.pacer {
            if !Self::may_proceed(&self.slots, name) {
                let slots = &self.slots;
                pacer.wait_until(|| Self::may_proceed(slots, name));
            }
        }
        self.slots.get_mut(name).expect("table slot").emit(batch);
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
            if !slot.done() {
                if let RowBuilder::Protocol(builder) = &mut slot.builder {
                    builder.add_frame_from_raw(
                        packet.frame_number,
                        packet.timestamp_ns,
                        packet.captured_len,
                        packet.original_len,
                        packet.data,
                        packet.link_type,
                    );
                }
                slot.rows_added += 1;
                // A full batch goes out; so does a partial one the moment the
                // row cap is reached, since nothing will be added to it (a
                // LIMIT on a live pipe would otherwise wait for input that
                // is not wanted).
                let batch = if slot.capped() {
                    slot.builder.finish()?
                } else {
                    slot.builder.try_build()?
                };
                if let Some(batch) = batch {
                    self.deliver("frames", batch);
                }
            }
        }

        // Route each parsed protocol layer to its table, if subscribed.
        for (proto_name, result) in parsed {
            if let Some(slot) = self.slots.get_mut(*proto_name) {
                if slot.done() {
                    continue;
                }
                if let Some(predicate) = &slot.predicate {
                    // Conservative: only a positively-false comparison drops
                    // the row; DataFusion re-checks everything kept.
                    if !predicate.matches_result(result) {
                        continue;
                    }
                }
                if let RowBuilder::Protocol(builder) = &mut slot.builder {
                    builder.add_parsed_row(frame_number, result);
                }
                slot.rows_added += 1;
                let batch = if slot.capped() {
                    slot.builder.finish()?
                } else {
                    slot.builder.try_build()?
                };
                if let Some(batch) = batch {
                    self.deliver(proto_name, batch);
                }
            }
        }

        // Fused joins: the frame's joined rows, from the same layers.
        for i in 0..self.fused.len() {
            let name = &self.fused[i];
            let slot = self.slots.get_mut(name).expect("fused slot");
            if slot.done() {
                continue;
            }
            let RowBuilder::Fused(builder) = &mut slot.builder else {
                continue;
            };
            let added = builder.add_packet(&packet, parsed);
            if added == 0 {
                continue;
            }
            slot.rows_added += added;
            let batch = if slot.capped() {
                slot.builder.finish()?
            } else {
                slot.builder.try_build()?
            };
            if let Some(batch) = batch {
                let name = self.fused[i].clone();
                self.deliver(&name, batch);
            }
        }

        Ok(())
    }

    /// Streaming: deliver every table's partially filled batch now (a
    /// continuous engine's time-based flush), leaving the builders empty.
    pub fn flush_partial(&mut self) -> Result<(), Error> {
        let mut pending = Vec::new();
        for (name, slot) in self.slots.iter_mut() {
            if slot.done() {
                continue;
            }
            if let Some(batch) = slot.builder.finish()? {
                pending.push((name.clone(), batch));
            }
        }
        for (name, batch) in pending {
            self.deliver(&name, batch);
        }
        Ok(())
    }

    /// True when nothing this pass produces can still be observed: every
    /// subscribed table has reached its row cap, or (streaming) every consumer
    /// has dropped its receiver because the query finished — e.g. a `LIMIT`
    /// above a filter that could not be pushed to the scan — or was cancelled.
    /// The parse loop can stop reading the source.
    pub fn all_capped(&self) -> bool {
        !self.slots.is_empty() && self.slots.values().all(TableSlot::done)
    }

    /// Finish building. Flushes each table's final partial batch into its
    /// sink and returns the accumulated batches per table (empty for tables
    /// in streaming mode — those went to their exchanges, which are closed
    /// here).
    pub fn finish(self) -> Result<HashMap<String, Vec<RecordBatch>>, Error> {
        let (batches, _) = self.finish_inner()?;
        Ok(batches)
    }

    /// Finish a streaming batch set: flush final batches, close every
    /// exchange and return, per streamed table, what went through its
    /// overflow buffer because the consumer was not draining it.
    pub fn finish_streaming(self) -> Result<HashMap<String, OverflowStats>, Error> {
        let (_, overflowed) = self.finish_inner()?;
        Ok(overflowed)
    }

    #[allow(clippy::type_complexity)]
    fn finish_inner(
        self,
    ) -> Result<
        (
            HashMap<String, Vec<RecordBatch>>,
            HashMap<String, OverflowStats>,
        ),
        Error,
    > {
        let mut out = HashMap::with_capacity(self.slots.len());
        let mut overflowed = HashMap::new();
        for (name, mut slot) in self.slots {
            if let Some(batch) = slot.builder.finish()? {
                slot.emit(batch);
            }
            let batches = match slot.sink {
                BatchSink::Accumulate(v) => v,
                BatchSink::Stream(tx) => {
                    overflowed.insert(name.clone(), tx.finish());
                    Vec::new()
                }
            };
            out.insert(name, batches);
        }
        Ok((out, overflowed))
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
