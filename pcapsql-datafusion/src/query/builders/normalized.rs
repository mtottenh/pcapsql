//! What one partition of a parse pass does with its rows, in DataFusion's
//! terms.
//!
//! Reading the capture, parsing each packet and deciding which rows it adds
//! to `frames` and the protocol tables is the scan layer's
//! (`pcapsql_core::scan::PartitionScan`), which writes those rows into one
//! [`ArrowSink`] per table. [`NormalizedBatchSet`] owns the rest:
//!
//! - where a table's completed batch goes (accumulated for the cache, or
//!   sent to the plan through a bounded exchange), with the backpressure
//!   rules that keep one producer feeding several tables from deadlocking;
//! - the fused joins, which the scan layer does not build yet: their rows
//!   come from [`FusedBatchBuilder`]s fed once per frame;
//! - the stream subscriber (TCP reassembly, TLS, HTTP), fed the same way.
//!
//! It is the scan's [`FrameObserver`]: the scan shows it every frame once,
//! and the push loop (`providers::shared`) reaches it between steps to
//! deliver the batches the scan asks to have taken.

use std::collections::HashMap;

use super::fused::FusedBatchBuilder;
use super::sink::ArrowSink;
use crate::error::Error;
use arrow::record_batch::RecordBatch;
use std::sync::Arc;

use crate::query::providers::{BatchSender, CompiledSubscription, OverflowStats, Pacer};
use crate::query::stream_tables::StreamSubscriber;
use pcapsql_core::io::PacketRef;
use pcapsql_core::scan::{FrameObserver, OutputId, ScanStats};
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
    /// `Some` for a fused join. A protocol table's rows are in its
    /// [`ArrowSink`], and its row cap and count with the scan.
    fused: Option<FusedRows>,
}

/// Delivers the batches of one partition of a parse pass, and builds what
/// the scan layer does not: fused joins and stream tables. See the
/// [module](self) documentation.
///
/// `slots[i]` is output `i` of the compiled plan ([`OutputId`]): the
/// protocol tables, then the fused joins.
pub struct NormalizedBatchSet {
    /// Every subscribed table, in the order of the compiled plan's outputs.
    slots: Vec<TableSlot>,
    /// Indices of the slots that are fused joins (in name order).
    fused: Vec<usize>,
    /// Streaming only: wakes the producer when a consumer takes a batch.
    pacer: Option<Arc<Pacer>>,
    /// Builds the stream tables of a pass that has any.
    subscriber: Option<StreamSubscriber>,
}

impl NormalizedBatchSet {
    /// Delivery for exactly the subscribed tables (materialize mode:
    /// completed batches accumulate in memory), and the [`ArrowSink`]s the
    /// scan writes the protocol tables' rows to: `sinks[i]` is output `i`.
    pub fn new(batch_size: usize, subscription: &CompiledSubscription) -> (Self, Vec<ArrowSink>) {
        Self::build(batch_size, subscription, |_| {
            BatchSink::Accumulate(Vec::new())
        })
    }

    /// [`new`](Self::new) for a pass that streams each table's completed
    /// batches to the matching sender (streaming mode), taking ownership of
    /// the senders. A table without a sender accumulates (and is dropped on
    /// finish).
    pub fn new_streaming(
        batch_size: usize,
        subscription: &CompiledSubscription,
        mut senders: HashMap<String, BatchSender>,
        pacer: Arc<Pacer>,
    ) -> (Self, Vec<ArrowSink>) {
        let (mut set, sinks) = Self::build(batch_size, subscription, |name| {
            match senders.remove(name) {
                Some(tx) => BatchSink::Stream(tx),
                None => BatchSink::Accumulate(Vec::new()),
            }
        });
        set.pacer = Some(pacer);
        (set, sinks)
    }

    /// Feed `subscriber` every frame of the pass. A set with a subscriber
    /// wants every frame: stream tables are complete only at end of capture.
    pub fn with_stream_subscriber(mut self, subscriber: Option<StreamSubscriber>) -> Self {
        self.subscriber = subscriber;
        self
    }

    fn build(
        batch_size: usize,
        subscription: &CompiledSubscription,
        mut sink_for: impl FnMut(&str) -> BatchSink,
    ) -> (Self, Vec<ArrowSink>) {
        let mut slots = Vec::new();
        let mut sinks = Vec::new();
        let mut fused = Vec::new();
        // The protocol tables, then the fused joins. A protocol table's
        // predicate and row cap are the scan's, from the compiled plan.
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
        let set = Self {
            slots,
            fused,
            pacer: None,
            subscriber: None,
        };
        (set, sinks)
    }

    /// Nothing further the fused join at `index` produces can be observed:
    /// it reached its row cap, or its consumer is gone.
    fn fused_done(&self, index: usize) -> bool {
        let slot = &self.slots[index];
        slot.consumer_gone || slot.fused.as_ref().is_some_and(FusedRows::capped)
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

    /// Deliver a completed batch of `output`, applying backpressure first:
    /// while this table is backlogged and the consumer is not parked on
    /// another table, the consumer is merely slower than the parse, so wait
    /// for it. Otherwise the batch is offered and, if the channel is still
    /// full, goes to the table's accounted overflow queue rather than
    /// stalling the pass.
    ///
    /// Returns `true` when the table's consumer is gone: nothing more is
    /// wanted for it (the caller closes a protocol table's output in the
    /// scan).
    pub fn deliver(&mut self, output: OutputId, batch: RecordBatch) -> bool {
        let index = usize::from(output.0);
        if let Some(pacer) = &self.pacer {
            if !Self::may_proceed(&self.slots, index) {
                let slots = &self.slots;
                pacer.wait_until(|| Self::may_proceed(slots, index));
            }
        }
        let slot = &mut self.slots[index];
        if slot.sink.emit(batch) {
            slot.consumer_gone = true;
        }
        slot.consumer_gone
    }

    /// The frame's rows in every fused join, from its parsed layers.
    fn feed_fused(
        &mut self,
        packet: &PacketRef<'_>,
        parsed: &[(&'static str, ParseResult<'_>)],
    ) -> Result<(), Error> {
        for i in 0..self.fused.len() {
            let index = self.fused[i];
            if self.fused_done(index) {
                continue;
            }
            let Some(rows) = &mut self.slots[index].fused else {
                continue;
            };
            let added = rows.builder.add_packet(packet, parsed);
            if added == 0 {
                continue;
            }
            rows.rows_added += added;
            // A full batch goes out; so does a partial one the moment the
            // row cap is reached, since nothing will be added to it (a
            // LIMIT on a live pipe would otherwise wait for input that is
            // not wanted).
            let batch = if rows.capped() {
                rows.builder.finish()?
            } else {
                rows.builder.try_build()?
            };
            if let Some(batch) = batch {
                self.deliver(OutputId(index as u16), batch);
            }
        }
        Ok(())
    }

    /// The partially filled batch of every fused join that is not done,
    /// appended to `pending` (a continuous engine's time-based flush),
    /// leaving the builders empty.
    pub fn take_fused_pending(
        &mut self,
        pending: &mut Vec<(OutputId, RecordBatch)>,
    ) -> Result<(), Error> {
        for i in 0..self.fused.len() {
            let index = self.fused[i];
            if self.fused_done(index) {
                continue;
            }
            let Some(rows) = &mut self.slots[index].fused else {
                continue;
            };
            if let Some(batch) = rows.builder.finish()? {
                pending.push((OutputId(index as u16), batch));
            }
        }
        Ok(())
    }

    /// Rows added to each table so far (pending and built): a protocol
    /// table's from the scan's statistics, a fused join's from its builder.
    pub fn rows_built(&self, stats: &ScanStats) -> HashMap<String, usize> {
        self.slots
            .iter()
            .enumerate()
            .map(|(index, slot)| {
                let rows = match &slot.fused {
                    Some(rows) => rows.rows_added,
                    None => usize::try_from(stats.rows[index]).unwrap_or(usize::MAX),
                };
                (slot.name.clone(), rows)
            })
            .collect()
    }

    /// The stream subscriber, to build its tables at the end of the pass.
    pub fn take_stream_subscriber(&mut self) -> Option<StreamSubscriber> {
        self.subscriber.take()
    }

    /// Finish the partition. Takes each table's final partial batch (a
    /// protocol table's out of `sinks`, the ones [`new`](Self::new)
    /// returned) and returns the accumulated batches per table (empty for
    /// tables in streaming mode — those went to their exchanges, which are
    /// closed here).
    pub fn finish(self, sinks: Vec<ArrowSink>) -> Result<HashMap<String, Vec<RecordBatch>>, Error> {
        let (batches, _) = self.finish_inner(sinks)?;
        Ok(batches)
    }

    /// Finish a streaming partition: flush final batches, close every
    /// exchange and return, per streamed table, what went through its
    /// overflow buffer because the consumer was not draining it.
    pub fn finish_streaming(
        self,
        sinks: Vec<ArrowSink>,
    ) -> Result<HashMap<String, OverflowStats>, Error> {
        let (_, overflowed) = self.finish_inner(sinks)?;
        Ok(overflowed)
    }

    #[allow(clippy::type_complexity)]
    fn finish_inner(
        self,
        mut sinks: Vec<ArrowSink>,
    ) -> Result<
        (
            HashMap<String, Vec<RecordBatch>>,
            HashMap<String, OverflowStats>,
        ),
        Error,
    > {
        let mut out = HashMap::with_capacity(self.slots.len());
        let mut overflowed = HashMap::new();
        for (index, mut slot) in self.slots.into_iter().enumerate() {
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
}

impl FrameObserver for NormalizedBatchSet {
    /// Feed the stream subscriber and the fused joins. Called by the scan
    /// once per frame, before the frame's rows are routed to the protocol
    /// tables. A fused join's completed batch is delivered from here, which
    /// may wait for its consumer.
    #[inline]
    fn observe(
        &mut self,
        packet: &PacketRef<'_>,
        layers: &[(&'static str, ParseResult<'_>)],
    ) -> Result<(), pcapsql_core::Error> {
        if let Some(subscriber) = self.subscriber.as_mut() {
            subscriber.observe(packet, layers)?;
        }
        if !self.fused.is_empty() {
            self.feed_fused(packet, layers)?;
        }
        Ok(())
    }

    /// The scan may stop once the protocol tables are done unless a fused
    /// join can still take rows or stream tables are being built (they are
    /// complete only at end of capture). A pass that delivers no table at
    /// all reads the whole capture.
    fn wants_frames(&self) -> bool {
        self.subscriber.is_some()
            || self.slots.is_empty()
            || self.fused.iter().any(|&index| !self.fused_done(index))
    }
}
