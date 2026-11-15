//! The streaming pass (`RetentionPolicy::None`): batches flow to the plan
//! as they form.
//!
//! One producer per partition runs the push loop (`pass.rs`) on a blocking
//! thread and sends each table's batches through that table's exchange
//! (`exchange.rs`); the query's `ProtocolScanExec`s hold the receivers.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use arrow::datatypes::SchemaRef;
use tokio::task::JoinHandle;

use pcapsql_core::io::PacketRange;
use pcapsql_core::{PacketReader, PacketSource, ProtocolRegistry, SeekablePacketSource};

use super::delivery::{BatchDelivery, Delivered};
use super::exchange::{self, BatchReceiver, BatchSender, Pacer, STREAM_CHANNEL_CAPACITY};
use super::pass::{
    decide_ranges, partition_scan, push_partition, time_range_us, Feed, PassOptions, Progress,
};
use super::stats::{OutputStat, PartitionStat};
use super::subscription::{CompiledSubscription, ParseSubscription};
use crate::error::{Error, QueryError};

/// One table of an in-flight streaming parse.
pub struct StreamedTable {
    /// The table's name: a protocol table's, or a fused join's synthetic
    /// one.
    pub name: Arc<str>,
    /// The Arrow schema of its batches.
    pub schema: SchemaRef,
    /// One batch receiver per partition, in partition order.
    pub receivers: Vec<BatchReceiver>,
}

/// Handle to an in-flight streaming parse.
///
/// Per subscribed table it holds one batch receiver per partition;
/// `ProtocolScanExec` takes a receiver to serve `execute(partition)`. The
/// producer join handles are awaited by the engine after query execution to
/// fold statistics and surface parse errors.
pub struct StreamingHandle {
    /// The tables of the pass, indexed by
    /// [`OutputId`](pcapsql_core::scan::OutputId).
    pub tables: Vec<StreamedTable>,
    pub producers: Vec<JoinHandle<Result<PartitionStat, Error>>>,
    pub num_partitions: usize,
}

/// How a streaming producer opens the reader of its partition. Opened on the
/// producer's own blocking thread, so a slow open (a seek, a range request,
/// a pipe that has not produced its header) never stalls the caller.
trait OpenReader: Send + 'static {
    type Reader: PacketReader;
    fn open(self) -> Result<Self::Reader, Error>;
}

/// The one partition of a sequential pass.
struct SequentialOpener<S: PacketSource>(Arc<S>);

impl<S: PacketSource> OpenReader for SequentialOpener<S> {
    type Reader = S::Reader;
    fn open(self) -> Result<S::Reader, Error> {
        Ok(self.0.sequential_reader()?)
    }
}

/// One range of a partitioned pass over a seekable source.
struct RangeOpener<S: SeekablePacketSource> {
    source: Arc<S>,
    range: PacketRange,
}

impl<S: SeekablePacketSource> OpenReader for RangeOpener<S> {
    type Reader = S::Reader;
    fn open(self) -> Result<S::Reader, Error> {
        Ok(self.source.reader_at(&self.range)?)
    }
}

/// One streaming producer: parse `reader` to completion, sending each
/// output's batches to its exchange (`senders[i]` is output `i`'s) as they
/// form.
fn stream_partition<R: PacketReader>(
    reader: R,
    registry: &Arc<ProtocolRegistry>,
    subscription: &CompiledSubscription,
    options: &PassOptions,
    senders: Vec<BatchSender>,
    pacer: Arc<Pacer>,
    progress: Option<Progress<'_>>,
) -> Result<PartitionStat, Error> {
    let (mut delivery, mut sinks) =
        BatchDelivery::streaming(options.batch_size, subscription, senders, pacer);
    let mut scan = partition_scan(reader, registry, subscription, options);
    let feed = Feed::Stream {
        flush_interval: options.flush_interval,
    };
    let capped = push_partition(&mut scan, &mut delivery, &mut sinks, progress, feed)?;
    let (stats, _) = scan.finish();

    // Flushes final batches and closes every exchange (buffered batches
    // become the receivers' tails).
    let delivered = delivery.finish(sinks)?;
    let outputs = subscription
        .outputs()
        .zip(stats.rows.iter())
        .zip(delivered)
        .map(|(((output, _), rows), delivered)| OutputStat {
            table: Arc::clone(&output.name),
            rows: *rows,
            overflow: match delivered {
                Delivered::Streamed(overflow) => overflow,
                Delivered::Batches(_) => Default::default(),
            },
        })
        .collect();
    let (min_us, max_us) = time_range_us(&stats);

    Ok(PartitionStat {
        min_us,
        max_us,
        packets: stats.packets,
        capped,
        outputs,
    })
}

/// Stream tables are complete only at end of capture; the engine routes
/// queries that touch them through the materialize path.
fn refuse_stream_tables(subscription: &ParseSubscription) -> Result<(), Error> {
    if subscription.has_stream_tables() {
        return Err(Error::Query(QueryError::Execution(
            "stream tables cannot be streamed; use run_shared_parse".into(),
        )));
    }
    Ok(())
}

/// Start the producers of a streaming pass, one per opener (= per
/// partition), each on its own `spawn_blocking` thread with its own
/// per-table exchanges.
fn start_streaming_parse<O: OpenReader>(
    openers: Vec<O>,
    registry: &Arc<ProtocolRegistry>,
    subscription: &ParseSubscription,
    options: &PassOptions,
) -> Result<StreamingHandle, Error> {
    refuse_stream_tables(subscription)?;
    let subscription = Arc::new(subscription.compile(registry)?);
    let num_partitions = openers.len();
    let progress_count = Arc::new(AtomicU64::new(0));

    let mut tables: Vec<StreamedTable> = subscription
        .outputs()
        .map(|(output, _)| StreamedTable {
            name: Arc::clone(&output.name),
            schema: Arc::clone(&output.schema),
            receivers: Vec::with_capacity(num_partitions),
        })
        .collect();
    let mut producers = Vec::with_capacity(num_partitions);

    for opener in openers {
        // Per-table exchange for this partition, sharing one pacer so the
        // producer can wait for progress on any of them.
        let pacer = Pacer::new();
        let mut senders = Vec::with_capacity(tables.len());
        for table in &mut tables {
            let (tx, rx) = exchange::channel(STREAM_CHANNEL_CAPACITY, pacer.clone());
            senders.push(tx);
            table.receivers.push(rx);
        }

        let registry = registry.clone();
        let subscription = subscription.clone();
        let options = options.clone();
        let progress_count = progress_count.clone();

        producers.push(tokio::task::spawn_blocking(move || {
            let reader = opener.open()?;
            stream_partition(
                reader,
                &registry,
                &subscription,
                &options,
                senders,
                pacer,
                options.progress(&progress_count),
            )
        }));
    }

    Ok(StreamingHandle {
        tables,
        producers,
        num_partitions,
    })
}

/// Start one scoped parse pass that **streams** each subscribed table's
/// batches to per-(table, partition) bounded exchanges.
///
/// One `spawn_blocking` producer per partition owns its reader and builders
/// and runs the parse to completion, sending completed batches as they form.
/// Each exchange holds [`STREAM_CHANNEL_CAPACITY`] batches. A producer whose
/// every live channel is full waits for the consumer (backpressure), so a
/// consumer that is merely slower than the parse bounds memory at
/// `O(tables × partitions × capacity × batch)`. A producer never waits on a
/// channel while another of its tables is being drained — DataFusion drains a
/// hash-join build side (or a sort input) to completion before polling the
/// other table, and both come from this one pass, so waiting would deadlock;
/// batches of the un-polled table go to an accounted overflow buffer instead,
/// reported in [`ParseStats::overflowed_bytes`](super::ParseStats::overflowed_bytes).
/// A producer stops early once every subscribed table is capped or every
/// consumer has dropped its receiver (query finished or cancelled).
///
/// [`PassOptions::flush_interval`] is not used: a seekable source is not a
/// live feed (see [`run_streaming_parse_sequential`]).
pub fn run_streaming_parse<S: SeekablePacketSource>(
    source: &Arc<S>,
    registry: &Arc<ProtocolRegistry>,
    subscription: &ParseSubscription,
    options: &PassOptions,
) -> Result<StreamingHandle, Error> {
    refuse_stream_tables(subscription)?;
    let options = &PassOptions {
        flush_interval: None,
        ..options.clone()
    };
    let ranges = decide_ranges(source.as_ref(), options.target_partitions)?;
    if ranges.len() == 1 {
        return run_streaming_parse_sequential(source, registry, subscription, options);
    }
    let openers: Vec<RangeOpener<S>> = ranges
        .into_iter()
        .map(|range| RangeOpener {
            source: source.clone(),
            range,
        })
        .collect();
    start_streaming_parse(openers, registry, subscription, options)
}

/// [`run_streaming_parse`] for any source as a **single partition**: one
/// producer over the source's sequential reader. The whole of a streaming
/// pass over a non-seekable source (a pipe, stdin), and the one-partition
/// case of the seekable entry point.
///
/// [`PassOptions::flush_interval`] (a continuous engine) delivers partially
/// filled batches on a time basis.
pub fn run_streaming_parse_sequential<S: PacketSource>(
    source: &Arc<S>,
    registry: &Arc<ProtocolRegistry>,
    subscription: &ParseSubscription,
    options: &PassOptions,
) -> Result<StreamingHandle, Error> {
    start_streaming_parse(
        vec![SequentialOpener(source.clone())],
        registry,
        subscription,
        options,
    )
}
