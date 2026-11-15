//! Subscription-scoped batch set builder.
//!
//! Delivers the rows of one parse pass, per subscribed table, as Arrow
//! batches. Which rows a packet adds to which table (with parse-time
//! predicates and row caps applied before any Arrow materialization) is
//! decided by the scan layer's `Router`, which writes them into one
//! [`ArrowSink`] per table; this type owns what is specific to DataFusion:
//! where a completed batch goes, backpressure, and the time-based flush of a
//! continuous engine.

use std::collections::HashMap;

use super::fused::FusedBatchBuilder;
use super::sink::ArrowSink;
use crate::error::Error;
use arrow::record_batch::RecordBatch;
use std::sync::Arc;

use crate::query::providers::{BatchSender, CompiledSubscription, OverflowStats, Pacer};
use pcapsql_core::io::PacketRef;
use pcapsql_core::scan::{OutputId, Routed, Router};
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

/// The rows of a fused join, which are not routed by the scan layer yet:
/// its builder, row cap and row count.
struct FusedRows {
    builder: FusedBatchBuilder,
    fetch: Option<usize>,
    rows_added: usize,
}

impl FusedRows {
    fn capped(&self) -> bool {
        self.fetch.is_some_and(|f| self.rows_added >= f)
    }
}

/// Per-table delivery state within one parse pass.
struct TableSlot {
    name: String,
    sink: BatchSink,
    /// The streaming consumer dropped its receiver; nothing more is wanted.
    consumer_gone: bool,
    /// `Some` for a fused join. A protocol table's rows are in the batch
    /// set's `sinks`, and its row cap and count with the router.
    fused: Option<FusedRows>,
}

/// Routes each packet's parsed layers into the subscribed tables' builders.
///
/// Usage:
/// ```ignore
/// let mut batch_set = NormalizedBatchSet::new(1000, &subscription.compile(&registry)?);
///
/// // For each packet (borrowed, zero-copy):
/// batch_set.add_packet_from_ref(packet_ref, &parsed_results)?;
///
/// // Get the per-table batches when done:
/// let batches = batch_set.finish()?;
/// ```
pub struct NormalizedBatchSet {
    /// Decides which rows a packet adds to which protocol table (and
    /// `frames`), and writes them to `sinks`.
    router: Router,
    /// The Arrow builders of the protocol tables: `sinks[i]` belongs to
    /// `slots[i]`. The compiled plan lists the protocol tables before the
    /// fused joins, so these are the first slots.
    sinks: Vec<ArrowSink>,
    /// Every subscribed table, in the order of the compiled plan's outputs.
    slots: Vec<TableSlot>,
    /// Indices of the slots that are fused joins (in name order), fed after
    /// the protocol tables.
    fused: Vec<usize>,
    /// Streaming only: wakes the producer when a consumer takes a batch.
    pacer: Option<Arc<Pacer>>,
}

impl NormalizedBatchSet {
    /// Create builders for exactly the subscribed tables (materialize mode:
    /// completed batches accumulate in memory).
    pub fn new(batch_size: usize, subscription: &CompiledSubscription) -> Self {
        Self::build(batch_size, subscription, |_| {
            BatchSink::Accumulate(Vec::new())
        })
    }

    /// Create builders that stream each table's completed batches to the
    /// matching sender (streaming mode), taking ownership of the senders. A
    /// table without a sender accumulates (and is dropped on finish).
    pub fn new_streaming(
        batch_size: usize,
        subscription: &CompiledSubscription,
        mut senders: HashMap<String, BatchSender>,
        pacer: Arc<Pacer>,
    ) -> Self {
        let mut set = Self::build(batch_size, subscription, |name| {
            match senders.remove(name) {
                Some(tx) => BatchSink::Stream(tx),
                None => BatchSink::Accumulate(Vec::new()),
            }
        });
        set.pacer = Some(pacer);
        set
    }

    fn build(
        batch_size: usize,
        subscription: &CompiledSubscription,
        mut sink_for: impl FnMut(&str) -> BatchSink,
    ) -> Self {
        let mut slots = Vec::new();
        let mut sinks = Vec::new();
        let mut fused = Vec::new();
        // The protocol tables, then the fused joins. A protocol table's
        // predicate and row cap are the router's, from the compiled plan.
        for (output, plan) in subscription.outputs() {
            let fused_rows = match &output.spec {
                Some(spec) => {
                    fused.push(slots.len());
                    Some(FusedRows {
                        builder: FusedBatchBuilder::new(Arc::clone(spec), batch_size),
                        fetch: plan
                            .fetch()
                            .map(|rows| usize::try_from(rows).unwrap_or(usize::MAX)),
                        rows_added: 0,
                    })
                }
                None => {
                    debug_assert_eq!(sinks.len(), slots.len(), "tables precede fused joins");
                    sinks.push(ArrowSink::with_schema(
                        Arc::clone(&output.schema),
                        &plan.columns,
                        batch_size,
                    ));
                    None
                }
            };
            slots.push(TableSlot {
                name: output.name.clone(),
                sink: sink_for(&output.name),
                consumer_gone: false,
                fused: fused_rows,
            });
        }
        Self {
            router: Router::new(subscription.scan()),
            sinks,
            slots,
            fused,
            pacer: None,
        }
    }

    /// Nothing further the table at `index` produces can be observed: it
    /// reached its row cap, or its consumer is gone.
    fn done(&self, index: usize) -> bool {
        let slot = &self.slots[index];
        match &slot.fused {
            Some(rows) => rows.capped() || slot.consumer_gone,
            // A table whose consumer is gone is closed in the router.
            None => self.router.is_done(OutputId(index as u16)),
        }
    }

    /// Streaming: the producer may proceed with a batch for `name` when that
    /// table can take it normally, when its consumer is gone, or when the
    /// consumer is parked waiting on some *other* live streamed table — it
    /// will not poll this one until that table is complete (hash-join build
    /// side, sort input), so waiting here would deadlock.
    fn may_proceed(slots: &[TableSlot], index: usize) -> bool {
        let this = match &slots[index].sink {
            BatchSink::Stream(tx) => tx,
            BatchSink::Accumulate(_) => return true,
        };
        if this.consumer_gone() || !this.is_backlogged() {
            return true;
        }
        slots.iter().enumerate().any(|(other, slot)| {
            other != index
                && matches!(&slot.sink, BatchSink::Stream(tx) if !tx.consumer_gone() && tx.consumer_waiting())
        })
    }

    /// Deliver a completed batch for `name`, applying backpressure first:
    /// while this table is backlogged and the consumer is not parked on
    /// another table, the consumer is merely slower than the parse, so wait
    /// for it. Otherwise the batch is offered and, if the channel is still
    /// full, goes to the table's accounted overflow queue rather than
    /// stalling the pass.
    fn deliver(&mut self, index: usize, batch: RecordBatch) {
        if let Some(pacer) = &self.pacer {
            if !Self::may_proceed(&self.slots, index) {
                let slots = &self.slots;
                pacer.wait_until(|| Self::may_proceed(slots, index));
            }
        }
        let slot = &mut self.slots[index];
        if slot.sink.emit(batch) {
            slot.consumer_gone = true;
            if slot.fused.is_none() {
                self.router.close_output(OutputId(index as u16));
            }
        }
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
        // The frame's row in `frames` and each layer's row in its table.
        // The router asks for a table's batch when its sink is full, and
        // also the moment its row cap is reached, since nothing will be
        // added to it (a LIMIT on a live pipe would otherwise wait for input
        // that is not wanted). A sink that fills in the middle of a frame
        // (a tunnelled packet has several rows in one table) leaves the
        // frame unfinished: it is routed again once the batch is out.
        loop {
            let routed = self.router.route_frame(&mut self.sinks, &packet, parsed);
            while let Some(OutputId(output)) = self.router.take_flush() {
                let index = usize::from(output);
                if let Some(batch) = self.sinks[index].take_batch()? {
                    self.deliver(index, batch);
                }
            }
            if routed == Routed::Consumed {
                break;
            }
        }

        // Fused joins: the frame's joined rows, from the same layers.
        for i in 0..self.fused.len() {
            let index = self.fused[i];
            if self.done(index) {
                continue;
            }
            let Some(rows) = &mut self.slots[index].fused else {
                continue;
            };
            let added = rows.builder.add_packet(&packet, parsed);
            if added == 0 {
                continue;
            }
            rows.rows_added += added;
            let batch = if rows.capped() {
                rows.builder.finish()?
            } else {
                rows.builder.try_build()?
            };
            if let Some(batch) = batch {
                self.deliver(index, batch);
            }
        }

        Ok(())
    }

    /// The rows the table at `index` holds that are not in a batch yet, as
    /// one.
    fn take_pending(&mut self, index: usize) -> Result<Option<RecordBatch>, Error> {
        match &mut self.slots[index].fused {
            Some(rows) => rows.builder.finish(),
            None => self.sinks[index].take_batch(),
        }
    }

    /// Streaming: deliver every table's partially filled batch now (a
    /// continuous engine's time-based flush), leaving the builders empty.
    pub fn flush_partial(&mut self) -> Result<(), Error> {
        let mut pending = Vec::new();
        for index in 0..self.slots.len() {
            if self.done(index) {
                continue;
            }
            if let Some(batch) = self.take_pending(index)? {
                pending.push((index, batch));
            }
        }
        for (index, batch) in pending {
            self.deliver(index, batch);
        }
        Ok(())
    }

    /// True when nothing this pass produces can still be observed: every
    /// subscribed table has reached its row cap, or (streaming) every consumer
    /// has dropped its receiver because the query finished — e.g. a `LIMIT`
    /// above a filter that could not be pushed to the scan — or was cancelled.
    /// The parse loop can stop reading the source.
    pub fn all_capped(&self) -> bool {
        !self.slots.is_empty() && (0..self.slots.len()).all(|index| self.done(index))
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
        let Self {
            mut sinks, slots, ..
        } = self;
        let mut out = HashMap::with_capacity(slots.len());
        let mut overflowed = HashMap::new();
        for (index, mut slot) in slots.into_iter().enumerate() {
            let last = match &mut slot.fused {
                Some(rows) => rows.builder.finish()?,
                None => sinks[index].take_batch()?,
            };
            if let Some(batch) = last {
                slot.sink.emit(batch);
            }
            let batches = match slot.sink {
                BatchSink::Accumulate(v) => v,
                BatchSink::Stream(tx) => {
                    overflowed.insert(slot.name.clone(), tx.finish());
                    Vec::new()
                }
            };
            out.insert(slot.name, batches);
        }
        Ok((out, overflowed))
    }

    /// Rows added to a table so far (pending and built).
    pub fn row_count(&self, table_name: &str) -> usize {
        let Some(index) = self.slots.iter().position(|s| s.name == table_name) else {
            return 0;
        };
        match &self.slots[index].fused {
            Some(rows) => rows.rows_added,
            None => usize::try_from(self.router.rows(OutputId(index as u16))).unwrap_or(usize::MAX),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::providers::{ParseSubscription, TableSubscription};
    use compact_str::CompactString;
    use datafusion::logical_expr::col;
    use datafusion::prelude::lit;
    use pcapsql_core::scan::Catalog;
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

    /// A batch set for `subscription`, compiled for the default registry.
    fn batch_set(batch_size: usize, subscription: &ParseSubscription) -> NormalizedBatchSet {
        let registry = pcapsql_core::default_registry();
        NormalizedBatchSet::new(batch_size, &subscription.compile(&registry).unwrap())
    }

    fn sub_full(names: &[&str]) -> ParseSubscription {
        ParseSubscription::tables_full(names).unwrap()
    }

    #[test]
    fn builds_only_subscribed_tables() {
        let mut bs = batch_set(1000, &sub_full(&["frames", "tcp"]));
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
        let mut sub = ParseSubscription::default();
        sub.subscribe_table(
            "tcp",
            TableSubscription {
                columns: Some(HashSet::from([
                    "frame_number".to_string(),
                    "dst_port".to_string(),
                ])),
                ..Default::default()
            },
        )
        .unwrap();

        let mut bs = batch_set(1000, &sub);
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
        let (_, tcp) = Catalog::builtin().table("tcp").unwrap();
        let predicate =
            crate::query::filter::row_predicate(&[col("dst_port").eq(lit(443i32))], tcp);
        assert!(predicate.is_some());
        let mut sub = ParseSubscription::default();
        sub.subscribe_table(
            "tcp",
            TableSubscription {
                predicate,
                ..Default::default()
            },
        )
        .unwrap();

        let mut bs = batch_set(1000, &sub);
        bs.add_packet_from_ref(create_test_packet(1), &[("tcp", create_tcp_result(80))])
            .unwrap();
        bs.add_packet_from_ref(create_test_packet(2), &[("tcp", create_tcp_result(443))])
            .unwrap();
        // The field is absent: undecided, so the row is kept.
        bs.add_packet_from_ref(create_test_packet(3), &[("tcp", create_dns_result())])
            .unwrap();

        assert_eq!(bs.row_count("tcp"), 2);
    }

    #[test]
    fn fetch_caps_rows_and_reports_all_capped() {
        let mut sub = ParseSubscription::default();
        sub.subscribe_table(
            "frames",
            TableSubscription {
                fetch: Some(2),
                ..Default::default()
            },
        )
        .unwrap();

        let mut bs = batch_set(1000, &sub);
        for i in 1..=5 {
            bs.add_packet_from_ref(create_test_packet(i), &[]).unwrap();
        }
        assert_eq!(bs.row_count("frames"), 2);
        assert!(bs.all_capped());
    }

    #[test]
    fn batch_size_triggers_intermediate_batches() {
        let mut bs = batch_set(2, &sub_full(&["frames"]));
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

    /// A frame with several rows in one table (a tunnel) may straddle a
    /// batch boundary: no batch exceeds the batch size, and every row is
    /// there once, in order.
    #[test]
    fn multi_row_frames_split_across_batches() {
        use arrow::array::{Array, UInt16Array, UInt64Array};
        for batch_size in [1, 2, 3, 4, 100] {
            let mut bs = batch_set(batch_size, &sub_full(&["frames", "tcp"]));
            let mut expected = Vec::new();
            for frame in 1..=7u64 {
                // 1, 2 or 3 tcp layers per frame.
                let layers: Vec<_> = (0..=(frame % 3) as u16)
                    .map(|depth| ("tcp", create_tcp_result(1000 * frame as u16 + depth)))
                    .collect();
                expected.extend(
                    layers
                        .iter()
                        .enumerate()
                        .map(|(depth, _)| (frame, 1000 * frame as u16 + depth as u16)),
                );
                bs.add_packet_from_ref(create_test_packet(frame), &layers)
                    .unwrap();
            }
            assert_eq!(bs.row_count("tcp"), expected.len());
            assert_eq!(bs.row_count("frames"), 7);
            let batches = bs.finish().unwrap();
            let mut rows = Vec::new();
            for batch in &batches["tcp"] {
                assert!(batch.num_rows() <= batch_size, "batch size {batch_size}");
                let frames = batch.column_by_name("frame_number").unwrap();
                let frames = frames.as_any().downcast_ref::<UInt64Array>().unwrap();
                let ports = batch.column_by_name("dst_port").unwrap();
                let ports = ports.as_any().downcast_ref::<UInt16Array>().unwrap();
                rows.extend((0..batch.num_rows()).map(|i| (frames.value(i), ports.value(i))));
            }
            assert_eq!(rows, expected, "batch size {batch_size}");
            let frames: usize = batches["frames"].iter().map(|b| b.num_rows()).sum();
            assert_eq!(frames, 7);
        }
    }

    #[test]
    fn unknown_table_errors() {
        assert!(ParseSubscription::tables_full(["nonexistent"]).is_err());
    }
}
