//! The scoped, shared single-pass parse.
//!
//! A query touching N protocol tables parses the capture **once**, not once
//! per table — and only as much of it as the query needs. The engine
//! harvests each query's optimized plan into a [`ParseSubscription`]
//! (which tables, which columns, parse-time predicates, row caps), and
//! [`run_shared_parse`] performs one fan-out parse pass restricted to that
//! subscription, in parallel across partitions for seekable sources.
//!
//! Partitions are range-partitioned by frame number and reassembled in frame
//! order, so the result is identical to a single-partition parse — the
//! property the partition-equivalence tests assert.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arrow::datatypes::SchemaRef;
use arrow::record_batch::RecordBatch;
use tokio::task::JoinHandle;

use pcapsql_core::io::PacketRange;
use pcapsql_core::{
    parse_packet, PacketReader, PacketSource, ParseScope, ProtocolRegistry, SeekablePacketSource,
};

use super::exchange::{
    self, BatchReceiver, BatchSender, OverflowStats, Pacer, STREAM_CHANNEL_CAPACITY,
};
use crate::error::Error;
use crate::query::builders::NormalizedBatchSet;
use crate::query::filter::FilterEvaluator;
use crate::query::fusion::FrameJoinSpec;
use crate::query::stream_tables::StreamSubscriber;
use crate::query::tables;
use pcapsql_core::KeyLog;

/// Minimum object size before a `Cheap`-seek source is partitioned.
const CHEAP_MIN_BYTES: u64 = 4 * 1024 * 1024;
/// Minimum file size before a `Free`-seek (mmap) source is partitioned when
/// the caller did not ask for a specific partition count.
///
/// Partitioning costs a header-only index scan plus a sidecar write and one
/// thread per partition; below this size a single sequential parse is faster.
/// An explicit partition count (tests, benchmarks) is always honoured.
const FREE_MIN_BYTES: u64 = 1024 * 1024;

/// The partition count to use when the caller leaves it to the engine: the
/// available parallelism, except that small `Free`-seek (mmap) files are not
/// worth an index build, a sidecar and a thread per partition.
pub fn auto_target_partitions<S: SeekablePacketSource>(source: &S, default: usize) -> usize {
    use pcapsql_core::SeekCost;
    let size = source.metadata().size_bytes.unwrap_or(0);
    if source.seek_cost() == SeekCost::Free && size < FREE_MIN_BYTES {
        1
    } else {
        default.max(1)
    }
}
/// Minimum object size before a `RangeRequest`-seek source is partitioned
/// (network round trips must be amortized).
const RANGE_MIN_BYTES: u64 = 16 * 1024 * 1024;

/// Progress callback: invoked with the cumulative packet count during parse.
pub type ProgressFn = Arc<dyn Fn(u64) + Send + Sync>;

/// One table's subscription within a parse pass.
#[derive(Clone, Debug, Default)]
pub struct TableSubscription {
    /// Columns to materialize (schema order is preserved); `None` = all.
    pub columns: Option<HashSet<String>>,
    /// Parse-time predicate (conservative; DataFusion re-checks).
    pub predicate: Option<FilterEvaluator>,
    /// Per-partition row cap from a pushed-down `LIMIT`.
    pub fetch: Option<usize>,
}

/// One fused join's subscription within a parse pass.
#[derive(Clone, Debug)]
pub struct FusedSubscription {
    pub spec: Arc<FrameJoinSpec>,
    /// Per-partition row cap from a pushed-down `LIMIT`.
    pub fetch: Option<usize>,
}

/// What one parse pass materializes: the tables a query references, each
/// with optional column scoping, predicates and row caps.
#[derive(Clone, Debug, Default)]
pub struct ParseSubscription {
    /// Per-packet protocol tables.
    pub tables: HashMap<String, TableSubscription>,
    /// Fused joins (see [`crate::query::fusion`]), by synthetic table name:
    /// built per packet from the frame's layers, served like a table.
    pub fused: HashMap<String, FusedSubscription>,
    /// Stream-analysis tables (`tables::STREAM_TABLES`) built by the stream
    /// subscriber of the same pass. Non-empty pins the pass to one partition.
    pub stream_tables: HashSet<String>,
}

impl ParseSubscription {
    /// Subscribe to the given tables with full columns, no predicates, no
    /// caps (the cache-fill shape).
    pub fn tables_full<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            tables: names
                .into_iter()
                .map(|n| (n.into(), TableSubscription::default()))
                .collect(),
            fused: HashMap::new(),
            stream_tables: HashSet::new(),
        }
    }

    /// Nothing to parse: no packet table, no fused join and no stream table.
    pub fn is_empty(&self) -> bool {
        self.tables.is_empty() && self.fused.is_empty() && self.stream_tables.is_empty()
    }

    /// Every table the pass delivers: the protocol tables and the fused
    /// joins, by name.
    pub fn output_names(&self) -> Vec<String> {
        self.tables
            .keys()
            .chain(self.fused.keys())
            .cloned()
            .collect()
    }

    /// The protocol-level scope for this subscription: the subscribed
    /// tables' protocols (the fused joins' members included) plus dependency
    /// closure, with per-protocol field projections where columns are
    /// scoped.
    fn parse_scope(&self, registry: &ProtocolRegistry) -> ParseScope {
        // Per protocol table, the fields to extract: `None` = all. A table
        // asked for by several subscribers gets the union.
        fn want(
            fields: &mut HashMap<String, Option<HashSet<String>>>,
            table: &str,
            columns: Option<&HashSet<String>>,
        ) {
            let entry = fields
                .entry(table.to_string())
                .or_insert_with(|| Some(HashSet::new()));
            match columns {
                Some(cols) => {
                    if let Some(have) = entry.as_mut() {
                        have.extend(cols.iter().cloned());
                    }
                }
                None => *entry = None,
            }
        }
        let mut fields: HashMap<String, Option<HashSet<String>>> = HashMap::new();
        for (table, sub) in &self.tables {
            want(&mut fields, table, sub.columns.as_ref());
        }
        for fused in self.fused.values() {
            for (table, columns) in fused.spec.member_fields() {
                want(&mut fields, &table, Some(&columns));
            }
        }
        let mut names: Vec<&str> = fields.keys().map(String::as_str).collect();
        // Stream analysis reads the TCP layer (ports, seq, flags, payload) and
        // the IP addresses from every packet.
        let streams = !self.stream_tables.is_empty();
        if streams {
            names.push("tcp");
        }
        let mut scope = ParseScope::for_tables(&names, registry);

        for (table, columns) in &fields {
            if table == "frames" {
                continue; // frames come from packet metadata, not parsing
            }
            if streams && matches!(table.as_str(), "tcp" | "ipv4" | "ipv6") {
                continue; // the stream subscriber needs these layers' full fields
            }
            if let Some(columns) = columns {
                // Pseudo-columns are populated from ParseResult context, not
                // extracted fields; they don't belong in the field projection.
                let fields: HashSet<String> = columns
                    .iter()
                    .filter(|c| {
                        !matches!(
                            c.as_str(),
                            "frame_number" | "encap_depth" | "tunnel_type" | "tunnel_id"
                        )
                    })
                    .cloned()
                    .collect();
                scope = scope.with_projection(table.to_string(), fields);
            }
        }
        scope
    }

    /// The Arrow schema a subscribed table (or fused join) materializes: the
    /// column subset for a protocol table, the spec's schema for a fused
    /// join.
    pub fn table_schema(&self, table: &str) -> Option<SchemaRef> {
        if let Some(fused) = self.fused.get(table) {
            return Some(Arc::clone(&fused.spec.schema));
        }
        let full = tables::get_table_schema(table)?;
        let sub = self.tables.get(table)?;
        match &sub.columns {
            None => Some(Arc::new(full)),
            Some(cols) => {
                let fields: Vec<_> = full
                    .fields()
                    .iter()
                    .filter(|f| cols.contains(f.name().as_str()))
                    .cloned()
                    .collect();
                Some(Arc::new(arrow::datatypes::Schema::new(fields)))
            }
        }
    }
}

/// One table's materialized data: its (possibly column-subset) schema and
/// per-partition batches in frame order.
#[derive(Clone, Debug)]
pub struct TableData {
    pub schema: SchemaRef,
    pub partitions: Vec<Vec<RecordBatch>>,
}

impl TableData {
    /// Total rows across all partitions.
    pub fn total_rows(&self) -> usize {
        self.partitions
            .iter()
            .flat_map(|p| p.iter())
            .map(|b| b.num_rows())
            .sum()
    }
}

/// Where a query's rows came from — what `--stats` reports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ServedFrom {
    /// A scoped parse pass over the capture.
    #[default]
    Parse,
    /// Entirely from the `CacheOnTouch` cache: nothing parsed.
    Cache,
    /// The boundary index (`count(*) FROM frames` fast path): nothing parsed.
    Index,
    /// The statement never executed a scan (`EXPLAIN`, DDL, `DESCRIBE`,
    /// `SET`, …): nothing was prepared. The only parse it can report is the
    /// one-time header-only time-range bootstrap of a source without a
    /// boundary index.
    PlanOnly,
}

/// Instrumentation for the most recent parse pass.
#[derive(Clone, Debug, Default)]
pub struct ParseStats {
    /// Parse passes performed for the query (0 = served from cache or the
    /// index). Includes the one-time header-only time-range bootstrap that a
    /// time-UDF query pays on a source without a boundary index.
    pub parse_passes: usize,
    /// Packets read from the source during the pass.
    pub packets_scanned: u64,
    /// Partitions the pass was split into.
    pub partitions: usize,
    /// Rows materialized per table.
    pub rows_built: HashMap<String, usize>,
    /// Observed timestamp range (microseconds), valid when packets > 0.
    pub start_ts_us: i64,
    pub end_ts_us: i64,
    /// False when a row cap (LIMIT) stopped the pass before end of input.
    pub complete_scan: bool,
    /// Streaming only: per table, bytes of batches that went through a
    /// producer's overflow buffer because DataFusion was not draining that
    /// table while it drained another (e.g. a hash-join probe side waiting
    /// on the build side). Zero when consumers keep pace.
    pub overflowed_bytes: HashMap<String, usize>,
    /// Streaming only: per table, the most bytes the overflow buffers held
    /// at once (summed over partitions) — the memory the exchange used
    /// beyond its channel bound.
    pub overflow_peak_bytes: HashMap<String, usize>,
    /// Stream-analysis tables built by this pass's stream subscriber (sorted).
    /// Non-empty means the pass ran as one partition for reassembly order.
    pub stream_tables: Vec<String>,
    /// Where the rows came from; distinguishes a cache hit, the index fast
    /// path and a plan-only statement, which all report `parse_passes == 0`.
    pub served_from: ServedFrom,
    /// Continuous queries only: rows the streaming window aggregate dropped
    /// because their window had already been emitted when they arrived
    /// (later than `allowed_lateness` behind the stream, or after an idle
    /// timeout closed the window).
    pub late_rows: u64,
    /// Continuous queries only: windows the streaming window aggregate
    /// emitted before their time because the memory limit was reached
    /// (`--on-memory-limit close-oldest`).
    pub windows_forced: u64,
}

/// Result of one scoped parse pass.
pub struct SharedParseState {
    tables: HashMap<String, Arc<TableData>>,
    stats: ParseStats,
}

impl SharedParseState {
    /// Decompose into the materialized tables and the pass statistics.
    pub fn into_tables(self) -> (HashMap<String, Arc<TableData>>, ParseStats) {
        (self.tables, self.stats)
    }

    pub fn stats(&self) -> &ParseStats {
        &self.stats
    }
}

/// Decide the partition ranges for a source, gating on seek cost and size.
fn decide_ranges<S: SeekablePacketSource>(
    source: &S,
    target_partitions: usize,
) -> Result<Vec<PacketRange>, Error> {
    use pcapsql_core::SeekCost;
    let size = source.metadata().size_bytes.unwrap_or(0);
    let target = target_partitions.max(1);
    let want = match source.seek_cost() {
        SeekCost::Free => target,
        SeekCost::Cheap => {
            if size >= CHEAP_MIN_BYTES {
                target
            } else {
                1
            }
        }
        SeekCost::RangeRequest => {
            if size >= RANGE_MIN_BYTES {
                target
            } else {
                1
            }
        }
    };
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

/// Per-partition parse output.
struct PartitionOutput {
    batches: HashMap<String, Vec<RecordBatch>>,
    /// Stream tables (only from the single partition of a pass that has a
    /// stream subscriber).
    stream_tables: HashMap<String, TableData>,
    min_us: i64,
    max_us: i64,
    packets: u64,
    capped: bool,
}

/// Parse one partition through `reader` into per-table batches restricted to
/// the subscription. The reader is already positioned: a sequential reader
/// (the whole source) or a seekable source's reader at a range start.
fn parse_partition<R: PacketReader>(
    mut reader: R,
    registry: &ProtocolRegistry,
    scope: &ParseScope,
    subscription: &ParseSubscription,
    batch_size: usize,
    progress: Option<(&AtomicU64, &ProgressFn)>,
    mut subscriber: Option<StreamSubscriber>,
) -> Result<PartitionOutput, Error> {
    let mut batch_set = NormalizedBatchSet::new(batch_size, subscription)?;
    let mut min_us = i64::MAX;
    let mut max_us = i64::MIN;
    let mut packets: u64 = 0;
    let mut capped = false;

    loop {
        let processed = reader.process_packets(1024, |packet| {
            let us = packet.timestamp_ns / 1_000;
            if us < min_us {
                min_us = us;
            }
            if us > max_us {
                max_us = us;
            }
            // Per-packet link type is correct even for PCAPNG multi-interface.
            let parsed = parse_packet(registry, packet.link_type, packet.data, scope);
            if let Some(sub) = subscriber.as_mut() {
                sub.observe(&packet, &parsed)?;
            }
            batch_set.add_packet_from_ref(packet, &parsed)?;
            Ok(())
        })?;
        packets += processed as u64;
        if let Some((counter, cb)) = progress {
            let total = counter.fetch_add(processed as u64, Ordering::Relaxed) + processed as u64;
            cb(total);
        }
        if processed == 0 {
            break;
        }
        // Stream tables are complete only at end of capture: never stop early
        // while a subscriber is attached.
        if subscriber.is_none() && batch_set.all_capped() {
            capped = true;
            break;
        }
    }

    let stream_tables = match subscriber {
        Some(sub) => sub.finish(batch_size)?,
        None => HashMap::new(),
    };

    Ok(PartitionOutput {
        batches: batch_set.finish()?,
        stream_tables,
        min_us,
        max_us,
        packets,
        capped,
    })
}

/// Fold the partitions' outputs (in partition order) into the pass result:
/// per table, one `Vec<RecordBatch>` per partition in frame order, plus the
/// pass statistics. Surfaces the first partition error.
fn assemble_pass(
    results: Vec<Result<PartitionOutput, Error>>,
    subscription: &ParseSubscription,
) -> Result<SharedParseState, Error> {
    let mut outputs: Vec<HashMap<String, Vec<RecordBatch>>> = Vec::with_capacity(results.len());
    let mut start_ts_us = i64::MAX;
    let mut end_ts_us = i64::MIN;
    let mut packets_scanned: u64 = 0;
    let mut complete_scan = true;
    let mut stream_tables: HashMap<String, TableData> = HashMap::new();
    for r in results {
        let out = r?;
        if out.min_us != i64::MAX {
            start_ts_us = start_ts_us.min(out.min_us);
        }
        if out.max_us != i64::MIN {
            end_ts_us = end_ts_us.max(out.max_us);
        }
        packets_scanned += out.packets;
        complete_scan &= !out.capped;
        stream_tables.extend(out.stream_tables);
        outputs.push(out.batches);
    }
    if start_ts_us == i64::MAX {
        start_ts_us = 0;
        end_ts_us = 0;
    }

    // Reorganize: table -> per-partition Vec<RecordBatch> (frame order).
    let num_partitions = outputs.len();
    let mut tables_out: HashMap<String, Arc<TableData>> = HashMap::new();
    let mut rows_built: HashMap<String, usize> = HashMap::new();
    for table in &subscription.output_names() {
        let schema = subscription.table_schema(table).ok_or_else(|| {
            Error::Query(crate::error::QueryError::Execution(format!(
                "Unknown table: {table}"
            )))
        })?;
        let partitions: Vec<Vec<RecordBatch>> = outputs
            .iter_mut()
            .map(|pb| pb.remove(table).unwrap_or_default())
            .collect();
        let data = TableData { schema, partitions };
        rows_built.insert(table.clone(), data.total_rows());
        tables_out.insert(table.clone(), Arc::new(data));
    }

    let mut stream_names: Vec<String> = stream_tables.keys().cloned().collect();
    stream_names.sort();
    for (name, data) in stream_tables {
        rows_built.insert(name.clone(), data.total_rows());
        tables_out.insert(name, Arc::new(data));
    }

    Ok(SharedParseState {
        tables: tables_out,
        stats: ParseStats {
            late_rows: 0,
            windows_forced: 0,
            parse_passes: 1,
            packets_scanned,
            partitions: num_partitions,
            rows_built,
            start_ts_us,
            end_ts_us,
            complete_scan,
            overflowed_bytes: HashMap::new(),
            overflow_peak_bytes: HashMap::new(),
            stream_tables: stream_names,
            served_from: ServedFrom::Parse,
        },
    })
}

/// Run one scoped parse pass over a seekable source, fanning out to the
/// subscribed tables. Parses partitions in parallel when more than one;
/// each worker owns its reader and builders — no shared mutable state.
///
/// A subscription with stream tables attaches a [`StreamSubscriber`] (TCP
/// reassembly → TLS → HTTP) to the same pass; reassembly needs the capture
/// in order, so such a pass is pinned to a single partition. A pass that
/// ends up with one partition (stream tables, a compressed or small source,
/// an unavailable index) is exactly [`run_shared_parse_sequential`].
pub fn run_shared_parse<S: SeekablePacketSource>(
    source: &Arc<S>,
    registry: &Arc<ProtocolRegistry>,
    batch_size: usize,
    target_partitions: usize,
    progress: Option<ProgressFn>,
    subscription: &ParseSubscription,
    keylog: Option<Arc<KeyLog>>,
) -> Result<SharedParseState, Error> {
    let streams = !subscription.stream_tables.is_empty();
    let ranges = if streams {
        vec![PacketRange::whole()]
    } else {
        decide_ranges(source.as_ref(), target_partitions)?
    };
    if ranges.len() == 1 {
        return run_shared_parse_sequential(
            source.as_ref(),
            registry,
            batch_size,
            progress,
            subscription,
            keylog,
        );
    }

    let scope = subscription.parse_scope(registry);
    let progress_count = AtomicU64::new(0);
    let results: Vec<Result<PartitionOutput, Error>> = std::thread::scope(|thread_scope| {
        let handles: Vec<_> = ranges
            .iter()
            .map(|range| {
                let source = source.clone();
                let registry = registry.clone();
                let range = range.clone();
                let scope = &scope;
                let progress = progress.as_ref().map(|cb| (&progress_count, cb));
                thread_scope.spawn(move || {
                    let reader = source.reader_at(&range)?;
                    parse_partition(
                        reader,
                        &registry,
                        scope,
                        subscription,
                        batch_size,
                        progress,
                        None,
                    )
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join().unwrap_or_else(|_| {
                    Err(Error::Query(crate::error::QueryError::Execution(
                        "parse worker panicked".into(),
                    )))
                })
            })
            .collect()
    });
    assemble_pass(results, subscription)
}

/// Run one scoped parse pass over any source as a **single partition**,
/// through its sequential reader.
///
/// This is the whole of a pass over a non-seekable source (a pipe, stdin:
/// [`pcapsql_core::StdinPacketSource`]), and the one-partition case of
/// [`run_shared_parse`]. Stream tables, when subscribed, are built by a
/// subscriber of the same pass.
pub fn run_shared_parse_sequential<S: PacketSource>(
    source: &S,
    registry: &Arc<ProtocolRegistry>,
    batch_size: usize,
    progress: Option<ProgressFn>,
    subscription: &ParseSubscription,
    keylog: Option<Arc<KeyLog>>,
) -> Result<SharedParseState, Error> {
    let scope = subscription.parse_scope(registry);
    let subscriber = (!subscription.stream_tables.is_empty())
        .then(|| StreamSubscriber::new(subscription.stream_tables.clone(), keylog));
    let progress_count = AtomicU64::new(0);
    let reader = source.sequential_reader()?;
    let result = parse_partition(
        reader,
        registry,
        &scope,
        subscription,
        batch_size,
        progress.as_ref().map(|cb| (&progress_count, cb)),
        subscriber,
    );
    assemble_pass(vec![result], subscription)
}

// ============================================================================
// Streaming parse (RetentionPolicy::None) — batches flow to the plan as they form.
// ============================================================================

/// One partition producer's contribution to the pass statistics.
pub struct PartitionStat {
    pub min_us: i64,
    pub max_us: i64,
    pub packets: u64,
    pub capped: bool,
    pub rows_built: HashMap<String, usize>,
    /// Per table, what went through the exchange's overflow buffer (see
    /// [`ParseStats::overflowed_bytes`] / [`ParseStats::overflow_peak_bytes`]).
    pub overflow: HashMap<String, OverflowStats>,
}

/// Handle to an in-flight streaming parse.
///
/// Per subscribed table it holds one batch receiver per partition (in
/// partition order); `ProtocolScanExec` takes a receiver to serve
/// `execute(partition)`. The producer join handles are awaited by the engine
/// after query execution to fold statistics and surface parse errors.
pub struct StreamingHandle {
    pub receivers: HashMap<String, Vec<BatchReceiver>>,
    pub producers: Vec<JoinHandle<Result<PartitionStat, Error>>>,
    pub num_partitions: usize,
    pub schemas: HashMap<String, SchemaRef>,
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
/// table's batches to its exchange as they form.
///
/// With a `flush_interval` (a continuous engine over a live feed) packets
/// are read one at a time and a partially filled batch is delivered once the
/// interval has passed since the last flush. On a reader that supports read
/// timeouts (stdin, a pipe: `poll(2)` on the descriptor) the wait for input
/// itself times out at the interval, so held packets are delivered on time
/// even when nothing else arrives; on one that does not (an arbitrary
/// `Read`, a compressed stream) the check runs when the next packet arrives,
/// so held packets wait for it.
#[allow(clippy::too_many_arguments)]
fn stream_partition<R: PacketReader>(
    mut reader: R,
    registry: &ProtocolRegistry,
    scope: &ParseScope,
    subscription: &ParseSubscription,
    batch_size: usize,
    senders: HashMap<String, BatchSender>,
    pacer: Arc<Pacer>,
    progress: Option<(&AtomicU64, &ProgressFn)>,
    flush_interval: Option<Duration>,
) -> Result<PartitionStat, Error> {
    let mut batch_set =
        NormalizedBatchSet::new_streaming(batch_size, subscription, senders, pacer)?;
    let mut min_us = i64::MAX;
    let mut max_us = i64::MIN;
    let mut packets: u64 = 0;
    let mut capped = false;
    let chunk = if flush_interval.is_some() { 1 } else { 1024 };
    let mut last_flush = Instant::now();
    if let Some(interval) = flush_interval {
        // Best effort: a reader without timeouts keeps blocking in `read()`.
        reader.set_read_timeout(Some(interval));
    }

    loop {
        let result = reader.process_packets(chunk, |packet| {
            let us = packet.timestamp_ns / 1_000;
            min_us = min_us.min(us);
            max_us = max_us.max(us);
            let parsed = parse_packet(registry, packet.link_type, packet.data, scope);
            batch_set.add_packet_from_ref(packet, &parsed)?;
            Ok(())
        });
        let processed = match result {
            Ok(n) => n,
            Err(_) if reader.cancelled() => {
                // The consumer is done and released the reader: stop with
                // what was parsed, as if every table had reached its cap.
                capped = true;
                break;
            }
            Err(_) if reader.take_read_timeout() => {
                // Nothing arrived within the interval: hand on what is held
                // and keep waiting.
                batch_set.flush_partial()?;
                last_flush = Instant::now();
                if batch_set.all_capped() {
                    capped = true;
                    break;
                }
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        packets += processed as u64;
        if let Some((counter, cb)) = progress {
            let total = counter.fetch_add(processed as u64, Ordering::Relaxed) + processed as u64;
            cb(total);
        }
        if processed == 0 {
            break;
        }
        if batch_set.all_capped() {
            capped = true;
            break;
        }
        if let Some(interval) = flush_interval {
            if last_flush.elapsed() >= interval {
                batch_set.flush_partial()?;
                last_flush = Instant::now();
            }
        }
    }

    let rows_built: HashMap<String, usize> = subscription
        .output_names()
        .into_iter()
        .map(|t| {
            let rows = batch_set.row_count(&t);
            (t, rows)
        })
        .collect();
    // Flushes final batches and closes every exchange (buffered batches
    // become the receivers' tails).
    let overflow = batch_set.finish_streaming()?;

    Ok(PartitionStat {
        min_us,
        max_us,
        packets,
        capped,
        rows_built,
        overflow,
    })
}

/// Start the producers of a streaming pass, one per opener (= per
/// partition), each on its own `spawn_blocking` thread with its own
/// per-table exchanges.
fn start_streaming_parse<O: OpenReader>(
    openers: Vec<O>,
    registry: &Arc<ProtocolRegistry>,
    batch_size: usize,
    progress: Option<ProgressFn>,
    subscription: &ParseSubscription,
    flush_interval: Option<Duration>,
) -> Result<StreamingHandle, Error> {
    if !subscription.stream_tables.is_empty() {
        // Stream tables are complete only at end of capture; the engine
        // routes queries that touch them through the materialize path.
        return Err(Error::Query(crate::error::QueryError::Execution(
            "stream tables cannot be streamed; use run_shared_parse".into(),
        )));
    }
    let scope = Arc::new(subscription.parse_scope(registry));
    let num_partitions = openers.len();
    let progress_count = Arc::new(AtomicU64::new(0));

    let table_names: Vec<String> = subscription.output_names();
    let mut schemas = HashMap::with_capacity(table_names.len());
    for name in &table_names {
        let schema = subscription.table_schema(name).ok_or_else(|| {
            Error::Query(crate::error::QueryError::Execution(format!(
                "Unknown table: {name}"
            )))
        })?;
        schemas.insert(name.clone(), schema);
    }

    // receivers[table] = one receiver per partition, in partition order.
    let mut receivers: HashMap<String, Vec<BatchReceiver>> = table_names
        .iter()
        .map(|n| (n.clone(), Vec::with_capacity(num_partitions)))
        .collect();
    let mut producers = Vec::with_capacity(num_partitions);

    for opener in openers {
        // Per-table exchange for this partition, sharing one pacer so the
        // producer can wait for progress on any of them.
        let pacer = Pacer::new();
        let mut senders = HashMap::with_capacity(table_names.len());
        for name in &table_names {
            let (tx, rx) = exchange::channel(STREAM_CHANNEL_CAPACITY, pacer.clone());
            senders.insert(name.clone(), tx);
            receivers.get_mut(name).expect("receiver slot").push(rx);
        }

        let registry = registry.clone();
        let scope = scope.clone();
        let subscription = subscription.clone();
        let progress = progress.clone();
        let progress_count = progress_count.clone();

        producers.push(tokio::task::spawn_blocking(move || {
            let reader = opener.open()?;
            stream_partition(
                reader,
                &registry,
                &scope,
                &subscription,
                batch_size,
                senders,
                pacer,
                progress.as_ref().map(|cb| (progress_count.as_ref(), cb)),
                flush_interval,
            )
        }));
    }

    Ok(StreamingHandle {
        receivers,
        producers,
        num_partitions,
        schemas,
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
/// reported in [`ParseStats::overflowed_bytes`]. A producer stops early once
/// every subscribed table is capped or every consumer has dropped its
/// receiver (query finished or cancelled).
pub fn run_streaming_parse<S: SeekablePacketSource>(
    source: &Arc<S>,
    registry: &Arc<ProtocolRegistry>,
    batch_size: usize,
    target_partitions: usize,
    progress: Option<ProgressFn>,
    subscription: &ParseSubscription,
) -> Result<StreamingHandle, Error> {
    if !subscription.stream_tables.is_empty() {
        return Err(Error::Query(crate::error::QueryError::Execution(
            "stream tables cannot be streamed; use run_shared_parse".into(),
        )));
    }
    let ranges = decide_ranges(source.as_ref(), target_partitions)?;
    if ranges.len() == 1 {
        return run_streaming_parse_sequential(
            source,
            registry,
            batch_size,
            progress,
            subscription,
            None,
        );
    }
    let openers: Vec<RangeOpener<S>> = ranges
        .into_iter()
        .map(|range| RangeOpener {
            source: source.clone(),
            range,
        })
        .collect();
    start_streaming_parse(openers, registry, batch_size, progress, subscription, None)
}

/// [`run_streaming_parse`] for any source as a **single partition**: one
/// producer over the source's sequential reader. The whole of a streaming
/// pass over a non-seekable source (a pipe, stdin), and the one-partition
/// case of the seekable entry point.
///
/// `flush_interval` (a continuous engine) delivers partially filled batches
/// on a time basis; see `stream_partition`.
pub fn run_streaming_parse_sequential<S: PacketSource>(
    source: &Arc<S>,
    registry: &Arc<ProtocolRegistry>,
    batch_size: usize,
    progress: Option<ProgressFn>,
    subscription: &ParseSubscription,
    flush_interval: Option<Duration>,
) -> Result<StreamingHandle, Error> {
    start_streaming_parse(
        vec![SequentialOpener(source.clone())],
        registry,
        batch_size,
        progress,
        subscription,
        flush_interval,
    )
}
