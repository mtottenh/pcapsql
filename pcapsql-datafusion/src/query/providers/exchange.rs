//! Bounded batch exchange between a parse producer and a DataFusion scan.
//!
//! One exchange per (table × partition) in the streaming (`RetentionPolicy::None`)
//! path. The fast path is a bounded `mpsc` channel of `STREAM_CHANNEL_CAPACITY`
//! batches, so while the consumer keeps pace (the frame-ordered sort-merge-join
//! case) the exchange holds at most that many batches.
//!
//! When a channel is full the producer must decide between two situations
//! that look the same from one table alone:
//!
//! - the consumer is simply **slower** than the parse: the producer waits —
//!   backpressure — until a consumer takes a batch from one of its channels
//!   ([`Pacer`]);
//! - the consumer is **parked waiting on another table** of the same pass
//!   (DataFusion drains a hash-join build side to completion before touching
//!   the probe side, a sort drains one input first) and that table is
//!   produced by the same producer, so waiting would deadlock. The batch is
//!   instead appended to the table's **overflow queue**, in order, and the
//!   pass continues. Every byte that goes through the overflow queue is
//!   accounted and reported per table in `ParseStats::overflowed_bytes` /
//!   `overflow_peak_bytes`, so divergent consumption degrades to
//!   *observable* buffering of that one table rather than to a stall.
//!
//! The overflow queue is shared with the receiver: the consumer reads the
//! channel first (its items are always older) and the queue once the channel
//! is empty, so an overflowed batch is never invisible to a consumer that
//! wants it. Once a table has overflowed, new batches keep going to the queue
//! until the consumer has drained it, which preserves order.
//!
//! The wait rule — wait while this table is backlogged *unless some other
//! live table's consumer is parked waiting on it* — is deadlock-free: a
//! waiting producer has data on this table, so a consumer that polls it makes
//! progress and frees a slot; a consumer that instead parks on another table
//! raises that table's waiting flag, which wakes the producer; a consumer
//! that has finished drops its receivers, which also wakes it. The decision
//! is taken by the batch set that owns all of a partition's senders
//! (`NormalizedBatchSet`), not by one sender.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use arrow::record_batch::RecordBatch;
use datafusion::error::Result as DFResult;
use tokio::sync::mpsc::{self, error::TryRecvError, error::TrySendError};
use tokio::sync::Notify;

/// Batches a bounded exchange holds before the producer starts buffering.
///
/// Per (table × partition); peak memory while consumers keep pace is
/// `tables × partitions × STREAM_CHANNEL_CAPACITY × batch bytes`.
pub const STREAM_CHANNEL_CAPACITY: usize = 4;

type Item = DFResult<RecordBatch>;

/// Wakes a blocked producer whenever one of its partition's consumers takes a
/// batch, starts waiting on a table, or goes away. Shared by every exchange
/// of one partition.
#[derive(Default)]
pub struct Pacer {
    progress: Mutex<u64>,
    cv: Condvar,
}

impl Pacer {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn bump(&self) {
        *self.progress.lock().expect("pacer lock poisoned") += 1;
        self.cv.notify_all();
    }

    /// Block the calling (non-async) thread until `ready()` holds. `ready` is
    /// evaluated under the pacer lock, so a consumer's progress between the
    /// check and the wait cannot be missed; the timeout is only a safety net.
    pub fn wait_until(&self, mut ready: impl FnMut() -> bool) {
        let mut guard = self.progress.lock().expect("pacer lock poisoned");
        while !ready() {
            guard = self
                .cv
                .wait_timeout(guard, Duration::from_millis(50))
                .expect("pacer lock poisoned")
                .0;
        }
    }
}

/// What a finished sender reports about its overflow queue.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OverflowStats {
    /// Total bytes that went through the overflow queue.
    pub total_bytes: usize,
    /// Most bytes held in the overflow queue at once: the memory the
    /// exchange used beyond its channel bound.
    pub peak_bytes: usize,
}

#[derive(Default)]
struct Overflow {
    items: VecDeque<RecordBatch>,
    bytes: usize,
    stats: OverflowStats,
}

impl Overflow {
    fn push(&mut self, batch: RecordBatch) {
        let bytes = batch.get_array_memory_size();
        self.bytes += bytes;
        self.stats.total_bytes += bytes;
        self.stats.peak_bytes = self.stats.peak_bytes.max(self.bytes);
        self.items.push_back(batch);
    }

    fn pop(&mut self) -> Option<RecordBatch> {
        let batch = self.items.pop_front()?;
        self.bytes -= batch.get_array_memory_size();
        Some(batch)
    }
}

/// State both ends share.
struct Shared {
    overflow: Mutex<Overflow>,
    /// Wakes a receiver parked on an empty channel when the queue grows.
    notify: Notify,
    /// The consumer is parked waiting for this table's next batch.
    waiting: AtomicBool,
}

/// Producer end of a bounded exchange. Not `Clone`: one per table.
pub struct BatchSender {
    tx: mpsc::Sender<Item>,
    shared: Arc<Shared>,
    consumer_gone: bool,
}

/// Consumer end of a bounded exchange: the channel, then the overflow queue.
pub struct BatchReceiver {
    rx: mpsc::Receiver<Item>,
    shared: Arc<Shared>,
    pacer: Arc<Pacer>,
}

/// Create a bounded exchange holding up to `capacity` batches in flight,
/// reporting consumer progress to `pacer`.
pub fn channel(capacity: usize, pacer: Arc<Pacer>) -> (BatchSender, BatchReceiver) {
    let (tx, rx) = mpsc::channel(capacity.max(1));
    let shared = Arc::new(Shared {
        overflow: Mutex::new(Overflow::default()),
        notify: Notify::new(),
        waiting: AtomicBool::new(false),
    });
    (
        BatchSender {
            tx,
            shared: shared.clone(),
            consumer_gone: false,
        },
        BatchReceiver { rx, shared, pacer },
    )
}

impl BatchSender {
    /// Offer a batch without blocking. Returns `true` once the consumer is
    /// gone (receiver dropped: the query finished early or was cancelled);
    /// the batch is then discarded.
    pub fn send(&mut self, batch: RecordBatch) -> bool {
        if self.consumer_gone() {
            self.consumer_gone = true;
            return true;
        }
        let mut overflow = self.shared.overflow.lock().expect("overflow lock poisoned");
        if overflow.items.is_empty() {
            // Normal path. The lock is held across try_send so the consumer
            // cannot observe "channel empty, queue empty" while a batch is
            // between the two.
            match self.tx.try_send(Ok(batch)) {
                Ok(()) => return false,
                Err(TrySendError::Closed(_)) => {
                    self.consumer_gone = true;
                    return true;
                }
                Err(TrySendError::Full(Ok(batch))) => overflow.push(batch),
                Err(TrySendError::Full(Err(_))) => unreachable!("only Ok items are sent"),
            }
        } else {
            overflow.push(batch);
        }
        drop(overflow);
        self.shared.notify.notify_one();
        false
    }

    /// True once the receiver has been dropped.
    pub fn consumer_gone(&self) -> bool {
        self.consumer_gone || self.tx.is_closed()
    }

    /// A normal send is not possible right now: the channel is full or the
    /// overflow queue is still draining, so the next batch would be queued.
    pub fn is_backlogged(&self) -> bool {
        self.tx.capacity() == 0
            || !self
                .shared
                .overflow
                .lock()
                .expect("overflow lock poisoned")
                .items
                .is_empty()
    }

    /// The consumer is parked waiting for this table's next batch.
    pub fn consumer_waiting(&self) -> bool {
        self.shared.waiting.load(Ordering::Acquire)
    }

    /// Bytes (Arrow array memory) of batches that went through the overflow
    /// queue so far.
    pub fn overflowed_bytes(&self) -> usize {
        self.shared
            .overflow
            .lock()
            .expect("overflow lock poisoned")
            .stats
            .total_bytes
    }

    /// Finish producing: closes the channel (the receiver then drains the
    /// overflow queue) and reports the queue's statistics. Never blocks.
    pub fn finish(self) -> OverflowStats {
        self.shared
            .overflow
            .lock()
            .expect("overflow lock poisoned")
            .stats
        // `tx` drops here, closing the channel.
    }
}

impl BatchReceiver {
    fn pop_overflow(&self) -> Option<RecordBatch> {
        self.shared
            .overflow
            .lock()
            .expect("overflow lock poisoned")
            .pop()
    }

    /// Next batch in production order: from the channel while it has items
    /// (always older than the queue), then from the overflow queue. `None`
    /// once the producer has finished and both are exhausted.
    pub async fn recv(&mut self) -> Option<Item> {
        loop {
            match self.rx.try_recv() {
                Ok(item) => {
                    self.pacer.bump();
                    return Some(item);
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    let next = self.pop_overflow().map(Ok);
                    if next.is_some() {
                        self.pacer.bump();
                    }
                    return next;
                }
            }
            if let Some(batch) = self.pop_overflow() {
                self.pacer.bump();
                return Some(Ok(batch));
            }
            // Nothing pending: park. The flag tells the producer this table
            // is wanted, so a backlogged sibling must not wait on us.
            // `notified()` is created before the flag is published, and a
            // `notify_one` with no waiter stores a permit, so a push between
            // the checks above and the await is not lost.
            let notified = self.shared.notify.notified();
            self.shared.waiting.store(true, Ordering::Release);
            self.pacer.bump();
            let got = tokio::select! {
                item = self.rx.recv() => Some(item),
                _ = notified => None,
            };
            self.shared.waiting.store(false, Ordering::Release);
            match got {
                Some(Some(item)) => {
                    self.pacer.bump();
                    return Some(item);
                }
                Some(None) => {
                    let next = self.pop_overflow().map(Ok);
                    if next.is_some() {
                        self.pacer.bump();
                    }
                    return next;
                }
                None => continue,
            }
        }
    }
}

impl Drop for BatchReceiver {
    fn drop(&mut self) {
        // Close first so a producer woken by the bump observes `is_closed()`.
        self.rx.close();
        self.shared.waiting.store(false, Ordering::Release);
        self.pacer.bump();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::{ArrayRef, UInt64Array};
    use arrow::datatypes::{DataType, Field, Schema};
    use std::sync::Arc;

    fn batch(v: u64) -> RecordBatch {
        let schema = Arc::new(Schema::new(vec![Field::new("v", DataType::UInt64, false)]));
        RecordBatch::try_new(
            schema,
            vec![Arc::new(UInt64Array::from(vec![v])) as ArrayRef],
        )
        .unwrap()
    }

    fn value(b: &RecordBatch) -> u64 {
        b.column(0)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .unwrap()
            .value(0)
    }

    #[tokio::test]
    async fn overflow_is_readable_before_the_producer_finishes() {
        let (mut tx, mut rx) = channel(2, Pacer::new());
        for i in 0..6 {
            assert!(!tx.send(batch(i)));
        }
        // 2 in the channel, 4 queued; all six must be readable now, in order.
        let mut got = Vec::new();
        for _ in 0..6 {
            got.push(value(&rx.recv().await.unwrap().unwrap()));
        }
        assert_eq!(got, vec![0, 1, 2, 3, 4, 5]);
        let stats = tx.finish();
        assert_eq!(stats.total_bytes, 4 * batch(0).get_array_memory_size());
        assert_eq!(
            stats.peak_bytes, stats.total_bytes,
            "all four queued at once"
        );
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn order_holds_while_the_queue_drains() {
        let (mut tx, mut rx) = channel(1, Pacer::new());
        tx.send(batch(0));
        tx.send(batch(1)); // queued
        assert!(tx.is_backlogged());
        assert_eq!(value(&rx.recv().await.unwrap().unwrap()), 0);
        // Channel has room but the queue is not empty: stays queued.
        tx.send(batch(2));
        assert_eq!(value(&rx.recv().await.unwrap().unwrap()), 1);
        assert_eq!(value(&rx.recv().await.unwrap().unwrap()), 2);
        assert!(!tx.is_backlogged());
        tx.send(batch(3)); // channel again
        let stats = tx.finish();
        assert_eq!(value(&rx.recv().await.unwrap().unwrap()), 3);
        assert!(rx.recv().await.is_none());
        assert_eq!(stats.total_bytes, 2 * batch(0).get_array_memory_size());
        assert_eq!(stats.peak_bytes, 2 * batch(0).get_array_memory_size());
    }

    #[tokio::test]
    async fn keeping_pace_never_overflows() {
        let (mut tx, mut rx) = channel(2, Pacer::new());
        for i in 0..10 {
            assert!(!tx.send(batch(i)));
            assert_eq!(value(&rx.recv().await.unwrap().unwrap()), i);
        }
        assert_eq!(tx.overflowed_bytes(), 0);
        assert_eq!(tx.finish(), OverflowStats::default());
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn parked_receiver_raises_waiting_flag_and_wakes_on_push() {
        let (mut tx, mut rx) = channel(1, Pacer::new());
        tx.send(batch(0)); // fills the channel
        let shared = tx.shared.clone();
        let reader = tokio::spawn(async move {
            let a = value(&rx.recv().await.unwrap().unwrap());
            let b = value(&rx.recv().await.unwrap().unwrap()); // parks until a push
            (a, b)
        });
        // Wait until the reader has parked.
        while !shared.waiting.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        assert!(tx.consumer_waiting());
        assert!(!tx.send(batch(1)));
        assert_eq!(reader.await.unwrap(), (0, 1));
        assert!(!tx.consumer_waiting());
    }

    #[test]
    fn pacer_wait_returns_once_consumer_makes_progress() {
        let pacer = Pacer::new();
        let (mut tx, mut rx) = channel(1, pacer.clone());
        assert!(!tx.send(batch(0)));
        assert!(tx.is_backlogged());
        let p = pacer.clone();
        let consumer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            rt.block_on(async { rx.recv().await.unwrap().unwrap() })
        });
        p.wait_until(|| !tx.is_backlogged());
        assert!(!tx.is_backlogged());
        consumer.join().unwrap();
    }

    #[tokio::test]
    async fn dropped_receiver_is_reported_as_consumer_gone() {
        let (mut tx, rx) = channel(1, Pacer::new());
        assert!(!tx.send(batch(0)));
        assert!(!tx.send(batch(1))); // queued
        drop(rx);
        assert!(tx.consumer_gone());
        assert!(tx.send(batch(2)));
    }
}
