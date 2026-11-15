//! What every parse pass has in common: its options, how a source is split
//! into partitions, and the push loop of one partition.
//!
//! A partition of a pass is the scan layer's resumable [`PartitionScan`],
//! which reads, parses and routes rows into one [`ArrowSink`] per output
//! (and, in a pass with stream tables, reassembles the TCP streams and
//! writes those tables' rows when the capture ends). [`push_partition`]
//! steps it and hands an output's batch to its consumer whenever the scan
//! asks for it to be taken. The materializing pass (`materialized.rs`) and
//! the streaming pass (`streamed.rs`) differ in where the batches go
//! ([`BatchDelivery`]) and in how the reader is treated ([`Feed`]).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arrow::record_batch::RecordBatch;

use pcapsql_core::io::PacketRange;
use pcapsql_core::scan::{
    partition_target, OutputId, PartitionPolicy, PartitionScan, ScanStats, Step,
};
use pcapsql_core::{KeyLog, PacketReader, ProtocolRegistry, SeekCost, SeekablePacketSource};

use super::delivery::BatchDelivery;
use super::subscription::CompiledSubscription;
use crate::error::Error;
use crate::query::builders::ArrowSink;

/// Progress callback: invoked with the cumulative packet count during parse.
pub type ProgressFn = Arc<dyn Fn(u64) + Send + Sync>;

/// How a parse pass is run: everything about it but the source and the
/// subscription.
#[derive(Clone)]
pub struct PassOptions {
    /// Rows per record batch.
    pub batch_size: usize,
    /// How many partitions to split a seekable source into, at most. A pass
    /// over a sequential reader, and one with stream tables, is one
    /// partition whatever this says.
    pub target_partitions: usize,
    /// Called with the pass's running packet count.
    pub progress: Option<ProgressFn>,
    /// TLS key log: with it the stream tables of a materializing pass see
    /// decrypted TLS (`tls_sessions.is_decrypted`, the `http2` table). A
    /// streaming pass builds no stream table and does not use it.
    pub keylog: Option<Arc<KeyLog>>,
    /// A streaming pass over a sequential reader (a continuous engine over
    /// a live feed) delivers partially filled batches on this cadence; see
    /// [`Feed::Stream`]. Not used by a materializing or partitioned pass.
    pub flush_interval: Option<Duration>,
}

impl PassOptions {
    /// One partition, batches of `batch_size` rows, and nothing else.
    pub fn new(batch_size: usize) -> Self {
        Self {
            batch_size,
            target_partitions: 1,
            progress: None,
            keylog: None,
            flush_interval: None,
        }
    }

    /// The pass's progress callback paired with the packet counter its
    /// partitions share.
    pub(super) fn progress<'a>(&'a self, counter: &'a AtomicU64) -> Option<Progress<'a>> {
        self.progress.as_ref().map(|callback| (counter, callback))
    }
}

/// A pass's shared packet counter and the callback it is reported to.
pub(super) type Progress<'a> = (&'a AtomicU64, &'a ProgressFn);

/// The partition count to use when the caller leaves it to the engine: the
/// available parallelism, except that small `Free`-seek (mmap) files are not
/// worth an index build, a sidecar and a thread per partition (under
/// [`PartitionPolicy::free_min_bytes`], 1 MiB).
///
/// This is the engine's parallelism, which DataFusion also plans with. For
/// a source that is not `Free` to seek it stays `default`: whether a pass
/// over such a source is partitioned at all is decided per pass, from its
/// size ([`partition_target`]).
pub fn auto_target_partitions<S: SeekablePacketSource>(source: &S, default: usize) -> usize {
    match source.seek_cost() {
        SeekCost::Free => partition_target(
            SeekCost::Free,
            source.metadata().size_bytes.unwrap_or(0),
            None,
            default,
            &PartitionPolicy::default(),
        ),
        SeekCost::Cheap | SeekCost::RangeRequest => default.max(1),
    }
}

/// Decide the partition ranges for a source, gating on seek cost and size
/// ([`partition_target`]): a `Cheap`-seek source is partitioned from 4 MiB
/// on, a `RangeRequest`-seek one from 16 MiB on (network round trips must be
/// amortized), a `Free`-seek one always.
pub(super) fn decide_ranges<S: SeekablePacketSource>(
    source: &S,
    target_partitions: usize,
) -> Result<Vec<PacketRange>, Error> {
    let want = partition_target(
        source.seek_cost(),
        source.metadata().size_bytes.unwrap_or(0),
        Some(target_partitions),
        target_partitions,
        &PartitionPolicy::default(),
    );
    if want <= 1 {
        return Ok(vec![PacketRange::whole()]);
    }
    // The boundary index is an optimization: if it cannot be built (a corrupt
    // record header, an unreadable sidecar) the capture is still readable
    // sequentially, with the reader's own truncation handling.
    match source.partitions(want) {
        Ok(ranges) => Ok(ranges),
        Err(e) => {
            tracing::warn!(error = %e, "boundary index unavailable; parsing in one partition");
            Ok(vec![PacketRange::whole()])
        }
    }
}

/// The scan of one partition of a pass over `reader`, decrypting TLS for
/// its stream tables with the pass's key log.
pub(super) fn partition_scan<R: PacketReader>(
    reader: R,
    registry: &Arc<ProtocolRegistry>,
    subscription: &CompiledSubscription,
    options: &PassOptions,
) -> PartitionScan<R> {
    let scan = PartitionScan::new(reader, subscription.shared_scan(), Arc::clone(registry));
    match &options.keylog {
        Some(keylog) => scan.with_keylog(keylog),
        None => scan,
    }
}

/// Packets per chunk of a partition's push loop: how often progress is
/// reported, and how often the loop looks whether anything it could still
/// produce is wanted.
const CHUNK: usize = 1024;

/// The scan's packet-timestamp range in microseconds, as the pass
/// statistics want it: `(i64::MAX, i64::MIN)` when it saw no packet.
pub(super) fn time_range_us(stats: &ScanStats) -> (i64, i64) {
    match stats.time_range_ns() {
        Some((min, max)) => (min / 1_000, max / 1_000),
        None => (i64::MAX, i64::MIN),
    }
}

/// Hand a completed batch of `output` to its consumer (which may wait for
/// the consumer, see [`BatchDelivery::deliver`]). A consumer that is gone
/// closes the output: the scan writes nothing more to it.
fn deliver<R: PacketReader>(
    scan: &mut PartitionScan<R>,
    delivery: &mut BatchDelivery,
    output: OutputId,
    batch: RecordBatch,
) {
    if delivery.deliver(output, batch) {
        scan.close_output(output);
    }
}

/// Deliver every output's partially filled batch now (a continuous engine's
/// time-based flush), leaving the builders empty. Outputs that are done
/// (capped, or without a consumer) are skipped.
fn flush_partial<R: PacketReader>(
    scan: &mut PartitionScan<R>,
    delivery: &mut BatchDelivery,
    sinks: &mut [ArrowSink],
) -> Result<(), Error> {
    for (index, sink) in sinks.iter_mut().enumerate() {
        let output = OutputId(index as u16);
        if scan.output_done(output) {
            continue;
        }
        if let Some(batch) = sink.take_batch()? {
            deliver(scan, delivery, output, batch);
        }
    }
    Ok(())
}

/// How a partition's push loop treats its reader.
#[derive(Clone, Copy)]
pub(super) enum Feed {
    /// A pass that materializes its tables: read to the end; any read error
    /// fails the pass.
    Materialize,
    /// A streaming producer: a cancelled reader ends the partition as if
    /// every table were capped. With a `flush_interval` (a continuous
    /// engine over a live feed) packets are read one at a time and a
    /// partially filled batch is delivered once the interval has passed
    /// since the last flush. On a reader that supports read timeouts
    /// (stdin, a pipe: `poll(2)` on the descriptor) the wait for input
    /// itself times out at the interval, so held packets are delivered on
    /// time even when nothing else arrives; on one that does not (an
    /// arbitrary `Read`, a compressed stream) the check runs when the next
    /// packet arrives, so held packets wait for it.
    Stream { flush_interval: Option<Duration> },
}

/// The push loop of one partition: step the scan until the partition ends
/// or nothing it could still produce is wanted, delivering each output's
/// batch when the scan asks for it to be taken (its sink is full, or the
/// output reached its row cap).
///
/// Progress is reported per chunk of [`CHUNK`] packets consumed (per packet
/// with a flush interval), with the pass's running total.
///
/// Returns whether the partition stopped before the end of its input.
pub(super) fn push_partition<R: PacketReader>(
    scan: &mut PartitionScan<R>,
    delivery: &mut BatchDelivery,
    sinks: &mut [ArrowSink],
    progress: Option<Progress<'_>>,
    feed: Feed,
) -> Result<bool, Error> {
    let (streaming, flush_interval) = match feed {
        Feed::Materialize => (false, None),
        Feed::Stream { flush_interval } => (true, flush_interval),
    };
    // With a flush interval packets are taken one at a time, so that the
    // interval is checked after each.
    let chunk = if flush_interval.is_some() { 1 } else { CHUNK };
    if let Some(interval) = flush_interval {
        // Best effort: a reader without timeouts keeps blocking in `read()`.
        scan.reader_mut().set_read_timeout(Some(interval));
    }
    let mut last_flush = Instant::now();
    // Packets of the current chunk still to consume, and the packets
    // already reported to the progress callback.
    let mut left = chunk;
    let mut reported: u64 = 0;
    // Report the packets consumed since the last report; `always` also
    // when there are none.
    let mut report = |scan: &PartitionScan<R>, always: bool| {
        let consumed = scan.stats().packets - reported;
        if let Some((counter, cb)) = progress {
            if always || consumed > 0 {
                cb(counter.fetch_add(consumed, Ordering::Relaxed) + consumed);
            }
        }
        reported += consumed;
    };

    loop {
        let before = scan.stats().packets;
        let step = match scan.step(sinks, left) {
            Ok(step) => step,
            Err(_) if streaming && scan.reader().cancelled() => {
                // The consumer is done and released the reader: stop with
                // what was parsed, as if every table had reached its cap.
                report(scan, false);
                return Ok(true);
            }
            Err(_) if streaming && scan.reader_mut().take_read_timeout() => {
                // Nothing arrived within the interval: hand on what is held
                // and keep waiting (the next step ends the partition if
                // that left no table with a consumer).
                report(scan, false);
                flush_partial(scan, delivery, sinks)?;
                last_flush = Instant::now();
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        left = left.saturating_sub((scan.stats().packets - before) as usize);
        match step {
            Step::Flush(output) => {
                if let Some(batch) = sinks[usize::from(output.0)].take_batch()? {
                    deliver(scan, delivery, output, batch);
                }
                if left > 0 {
                    continue;
                }
            }
            // The chunk is complete, or the reader had no more at hand.
            Step::More => {}
            Step::Done => {
                report(scan, false);
                return Ok(true);
            }
            Step::End => {
                report(scan, false);
                report(scan, true);
                return Ok(false);
            }
        }
        report(scan, true);
        left = chunk;
        if let Some(interval) = flush_interval {
            if last_flush.elapsed() >= interval {
                flush_partial(scan, delivery, sinks)?;
                last_flush = Instant::now();
            }
        }
    }
}
