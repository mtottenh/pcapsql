//! What one partition of a parse pass does with its rows, in DataFusion's
//! terms.
//!
//! Reading the capture, parsing each packet and deciding which rows it adds
//! to `frames`, the protocol tables and the fused joins is the scan layer's
//! (`pcapsql_core::scan::PartitionScan`), which writes those rows into one
//! [`ArrowSink`] per table or join. [`NormalizedBatchSet`] owns the rest:
//!
//! - where a table's completed batch goes (accumulated for the cache, or
//!   sent to the plan through a bounded exchange), with the backpressure
//!   rules that keep one producer feeding several tables from deadlocking;
//! - the stream subscriber (TCP reassembly, TLS, HTTP), fed once per frame.
//!
//! It is the scan's [`FrameObserver`]: the scan shows it every frame once,
//! and the push loop (`providers::shared`) reaches it between steps to
//! deliver the batches the scan asks to have taken.

use std::collections::HashMap;

use super::sink::ArrowSink;
use crate::error::Error;
use arrow::record_batch::RecordBatch;
use std::sync::Arc;

use crate::query::providers::{BatchSender, CompiledSubscription, OverflowStats, Pacer};
use crate::query::stream_tables::StreamSubscriber;
use pcapsql_core::io::PacketRef;
use pcapsql_core::scan::{FrameObserver, OutputId, ScanStats};
use pcapsql_core::PacketLayers;

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

/// Per-table delivery state within one parse pass. A table's rows are in
/// its [`ArrowSink`], and its row cap and count with the scan.
struct TableSlot {
    name: String,
    sink: BatchSink,
    /// The streaming consumer dropped its receiver; nothing more is wanted.
    consumer_gone: bool,
}

/// Delivers the batches of one partition of a parse pass, and builds what
/// the scan layer does not: the stream tables. See the [module](self)
/// documentation.
///
/// `slots[i]` is output `i` of the compiled plan ([`OutputId`]): the
/// protocol tables, then the fused joins.
pub struct NormalizedBatchSet {
    /// Every subscribed table, in the order of the compiled plan's outputs.
    slots: Vec<TableSlot>,
    /// Streaming only: wakes the producer when a consumer takes a batch.
    pacer: Option<Arc<Pacer>>,
    /// Builds the stream tables of a pass that has any.
    subscriber: Option<StreamSubscriber>,
}

impl NormalizedBatchSet {
    /// Delivery for exactly the subscribed tables (materialize mode:
    /// completed batches accumulate in memory), and the [`ArrowSink`]s the
    /// scan writes the rows to: `sinks[i]` is output `i`.
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
        // The protocol tables, then the fused joins. Predicates and row
        // caps are the scan's, from the compiled plan. A fused join's
        // batches carry its spec's schema (the flattened column names);
        // the cells are the plan's columns either way.
        for (output, plan) in subscription.outputs() {
            sinks.push(ArrowSink::with_schema(
                Arc::clone(&output.schema),
                &plan.columns,
                batch_size,
            ));
            slots.push(TableSlot {
                name: output.name.clone(),
                sink: sink_for(&output.name),
                consumer_gone: false,
            });
        }
        let set = Self {
            slots,
            pacer: None,
            subscriber: None,
        };
        (set, sinks)
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
    /// wanted for it (the caller closes the output in the scan).
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

    /// Rows added to each table so far (pending and built), from the
    /// scan's statistics.
    pub fn rows_built(&self, stats: &ScanStats) -> HashMap<String, usize> {
        self.slots
            .iter()
            .enumerate()
            .map(|(index, slot)| {
                let rows = usize::try_from(stats.rows[index]).unwrap_or(usize::MAX);
                (slot.name.clone(), rows)
            })
            .collect()
    }

    /// The stream subscriber, to build its tables at the end of the pass.
    pub fn take_stream_subscriber(&mut self) -> Option<StreamSubscriber> {
        self.subscriber.take()
    }

    /// Finish the partition. Takes each table's final partial batch out of
    /// `sinks` (the ones [`new`](Self::new) returned) and returns the
    /// accumulated batches per table (empty for tables in streaming mode —
    /// those went to their exchanges, which are closed here).
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
            if let Some(batch) = sinks[index].take_batch()? {
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
    type Error = Error;

    /// Feed the stream subscriber. Called by the scan once per frame,
    /// before the frame's rows are routed.
    #[inline]
    fn observe(
        &mut self,
        packet: &PacketRef<'_>,
        layers: &PacketLayers<'_, '_>,
    ) -> Result<(), Error> {
        match self.subscriber.as_mut() {
            Some(subscriber) => subscriber.observe(packet, layers),
            None => Ok(()),
        }
    }

    /// The scan may stop once its outputs are done unless stream tables are
    /// being built (they are complete only at end of capture). A pass that
    /// delivers no table at all reads the whole capture.
    fn wants_frames(&self) -> bool {
        self.subscriber.is_some() || self.slots.is_empty()
    }
}
