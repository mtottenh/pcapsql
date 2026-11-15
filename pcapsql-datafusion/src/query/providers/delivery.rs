//! Where the batches of one partition of a parse pass go.
//!
//! Reading the capture, parsing each packet and deciding which rows it adds
//! to which table is the scan layer's (`pcapsql_core::scan::PartitionScan`),
//! which writes those rows into one [`ArrowSink`] per output of the pass.
//! [`BatchDelivery`] owns what DataFusion adds: where an output's completed
//! batch goes (accumulated for the cache, or sent to the plan through a
//! bounded exchange), with the backpressure rules that keep one producer
//! feeding several tables from deadlocking.
//!
//! Everything here is indexed by [`OutputId`]: slot `i`, sink `i` and sender
//! `i` belong to output `i` of the compiled plan.

use std::sync::Arc;

use arrow::record_batch::RecordBatch;

use super::exchange::{BatchSender, OverflowStats, Pacer};
use super::subscription::CompiledSubscription;
use crate::error::Error;
use crate::query::builders::ArrowSink;
use pcapsql_core::scan::OutputId;

/// Where an output's completed batches go.
enum Slot {
    /// Accumulate in memory (materialize / cache-fill path).
    Accumulate(Vec<RecordBatch>),
    /// Stream to a consumer as batches complete (streaming path), through a
    /// bounded exchange that buffers (and accounts) when the consumer lags.
    Stream(BatchSender),
}

impl Slot {
    /// Deliver a batch. Returns `true` when the consumer is gone (the
    /// receiver was dropped: the query finished early or was cancelled).
    fn emit(&mut self, batch: RecordBatch) -> bool {
        match self {
            Slot::Accumulate(batches) => {
                batches.push(batch);
                false
            }
            Slot::Stream(sender) => sender.send(batch),
        }
    }
}

/// What became of one output's batches when its partition finished.
pub enum Delivered {
    /// The batches a materializing pass accumulated, in row order.
    Batches(Vec<RecordBatch>),
    /// The batches went to the output's exchange, now closed: what went
    /// through its overflow buffer because the consumer was not draining
    /// it.
    Streamed(OverflowStats),
}

/// Delivers the batches of one partition of a parse pass. See the
/// [module](self) documentation.
pub struct BatchDelivery {
    /// One per output of the compiled plan, indexed by [`OutputId`].
    slots: Vec<Slot>,
    /// Streaming only: wakes the producer when a consumer takes a batch.
    pacer: Option<Arc<Pacer>>,
}

impl BatchDelivery {
    /// Delivery for a materializing pass (completed batches accumulate in
    /// memory), and the [`ArrowSink`]s the scan writes the rows to:
    /// `sinks[i]` is output `i`.
    pub fn accumulating(
        batch_size: usize,
        subscription: &CompiledSubscription,
    ) -> (Self, Vec<ArrowSink>) {
        let sinks = sinks(batch_size, subscription);
        let slots = sinks.iter().map(|_| Slot::Accumulate(Vec::new())).collect();
        (Self { slots, pacer: None }, sinks)
    }

    /// Delivery for a pass that streams each output's completed batches:
    /// `senders[i]` is the exchange of output `i`, all sharing `pacer`.
    ///
    /// # Panics
    ///
    /// If there is not exactly one sender per output.
    pub fn streaming(
        batch_size: usize,
        subscription: &CompiledSubscription,
        senders: Vec<BatchSender>,
        pacer: Arc<Pacer>,
    ) -> (Self, Vec<ArrowSink>) {
        let sinks = sinks(batch_size, subscription);
        assert_eq!(senders.len(), sinks.len(), "one sender per output");
        let slots = senders.into_iter().map(Slot::Stream).collect();
        let delivery = Self {
            slots,
            pacer: Some(pacer),
        };
        (delivery, sinks)
    }

    /// Streaming: the producer may proceed with a batch for output `index`
    /// when that output can take it normally, when its consumer is gone, or
    /// when the consumer is parked waiting on some *other* live streamed
    /// output — it will not poll this one until that one is complete
    /// (hash-join build side, sort input), so waiting here would deadlock.
    fn may_proceed(slots: &[Slot], index: usize) -> bool {
        let this = match &slots[index] {
            Slot::Stream(sender) => sender,
            Slot::Accumulate(_) => return true,
        };
        if this.consumer_gone() || !this.is_backlogged() {
            return true;
        }
        slots.iter().enumerate().any(|(other, slot)| {
            other != index
                && matches!(slot, Slot::Stream(tx) if !tx.consumer_gone() && tx.consumer_waiting())
        })
    }

    /// Deliver a completed batch of `output`, applying backpressure first:
    /// while this output is backlogged and the consumer is not parked on
    /// another one, the consumer is merely slower than the parse, so wait
    /// for it. Otherwise the batch is offered and, if the channel is still
    /// full, goes to the output's accounted overflow queue rather than
    /// stalling the pass.
    ///
    /// Returns `true` when the output's consumer is gone: nothing more is
    /// wanted for it (the caller closes the output in the scan).
    pub fn deliver(&mut self, output: OutputId, batch: RecordBatch) -> bool {
        let index = usize::from(output.0);
        if let Some(pacer) = &self.pacer {
            if !Self::may_proceed(&self.slots, index) {
                let slots = &self.slots;
                pacer.wait_until(|| Self::may_proceed(slots, index));
            }
        }
        self.slots[index].emit(batch)
    }

    /// Finish the partition: take each output's final partial batch out of
    /// `sinks` (the ones this delivery was made with), deliver it, and
    /// close every exchange (buffered batches become the receivers' tails).
    /// The result is indexed by [`OutputId`].
    pub fn finish(self, mut sinks: Vec<ArrowSink>) -> Result<Vec<Delivered>, Error> {
        let mut delivered = Vec::with_capacity(self.slots.len());
        for (mut slot, sink) in self.slots.into_iter().zip(&mut sinks) {
            if let Some(batch) = sink.take_batch()? {
                slot.emit(batch);
            }
            delivered.push(match slot {
                Slot::Accumulate(batches) => Delivered::Batches(batches),
                Slot::Stream(sender) => Delivered::Streamed(sender.finish()),
            });
        }
        Ok(delivered)
    }
}

/// One sink per output of the pass, in output order. An output's batches
/// carry its subscribed schema (for a fused join the spec's, with the
/// flattened column names); the cells are the plan's columns either way.
fn sinks(batch_size: usize, subscription: &CompiledSubscription) -> Vec<ArrowSink> {
    subscription
        .outputs()
        .map(|(output, plan)| {
            ArrowSink::with_schema(Arc::clone(&output.schema), &plan.columns, batch_size)
        })
        .collect()
}
