//! The scoped, shared single-pass parse.
//!
//! A query touching N protocol tables parses the capture **once**, not once
//! per table — and only as much of it as the query needs. The engine
//! harvests each query's optimized plan into a [`ParseSubscription`]
//! (which tables, which columns, parse-time predicates, row caps), and
//! [`run_shared_parse`] performs one fan-out parse pass restricted to that
//! subscription, in parallel across partitions for seekable sources.
//!
//! A subscription is the scan layer's [`ScanPlan`] plus what only this
//! frontend has: the fused joins' specs (their Arrow schemas and synthetic
//! table names). A pass compiles it once ([`CompiledSubscription`]): the
//! plan's [`CompiledScan`] gives the parse scope, each table's columns,
//! predicate and row cap, and the Arrow schemas are derived from those
//! columns.
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
    parse_packet, PacketReader, PacketSource, ProtocolRegistry, SeekablePacketSource,
};

use super::exchange::{
    self, BatchReceiver, BatchSender, OverflowStats, Pacer, STREAM_CHANNEL_CAPACITY,
};
use crate::error::{Error, QueryError};
use crate::query::arrow_schema::out_columns_to_arrow_schema;
use crate::query::builders::NormalizedBatchSet;
use crate::query::fusion::FrameJoinSpec;
use crate::query::stream_tables::StreamSubscriber;
use pcapsql_core::scan::{
    Catalog, CompiledScan, OutputPlan, PlanError, RowPredicate, ScanPlan, TableScan,
};
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

/// One table's subscription within a parse pass, in DataFusion's terms.
#[derive(Clone, Debug, Default)]
pub struct TableSubscription {
    /// Columns to materialize (schema order is preserved); `None` = all.
    pub columns: Option<HashSet<String>>,
    /// Parse-time predicate (conservative; DataFusion re-checks). Built by
    /// [`row_predicate`](crate::query::row_predicate) for the same table.
    pub predicate: Option<RowPredicate>,
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
///
/// It wraps the scan layer's [`ScanPlan`], which holds all of that with
/// tables and columns resolved against the table catalogue, and adds the
/// fused joins' [`FrameJoinSpec`]s, which carry the Arrow schema and the
/// synthetic table name a fused join is served under.
#[derive(Clone, Debug, Default)]
pub struct ParseSubscription {
    /// Per-packet protocol tables (`tables`), fused joins (`fused`, in name
    /// order) and stream-analysis tables (`streams`); timestamps in
    /// microseconds, every frame.
    plan: ScanPlan,
    /// The spec of each of `plan.fused`, in the same order.
    fused: Vec<Arc<FrameJoinSpec>>,
}

fn execution_error(message: impl Into<String>) -> Error {
    Error::Query(QueryError::Execution(message.into()))
}

fn plan_error(error: PlanError) -> Error {
    execution_error(error.to_string())
}

impl ParseSubscription {
    /// Subscribe to the given tables with full columns, no predicates, no
    /// caps (the cache-fill shape). Fails on a name that is not a per-packet
    /// table, or that is given twice.
    pub fn tables_full<I, S>(names: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut subscription = Self::default();
        for name in names {
            subscription.subscribe_table(name.as_ref(), TableSubscription::default())?;
        }
        Ok(subscription)
    }

    /// Subscribe to a per-packet table (`frames` or a protocol table): the
    /// columns DataFusion sees of it, in schema order, restricted to
    /// `sub.columns`. Fails on an unknown table or column, a stream table
    /// (see [`Self::subscribe_stream_table`]) and a table already
    /// subscribed.
    pub fn subscribe_table(&mut self, name: &str, sub: TableSubscription) -> Result<(), Error> {
        let (id, table) = Catalog::builtin()
            .table(name)
            .ok_or_else(|| execution_error(format!("Unknown table: {name}")))?;
        if table.is_stream() {
            return Err(plan_error(PlanError::NotAPacketTable(table.name)));
        }
        if self.plan.tables.iter().any(|scan| scan.table == id) {
            return Err(plan_error(PlanError::DuplicateTable(table.name)));
        }
        if let Some(wanted) = &sub.columns {
            let unknown = wanted
                .iter()
                .find(|column| !table.default_columns().any(|(_, c)| c.name == *column));
            if let Some(column) = unknown {
                return Err(Error::Query(QueryError::UnknownColumn {
                    table: name.to_string(),
                    column: column.clone(),
                }));
            }
        }
        let columns = table
            .default_columns()
            .filter(|(_, c)| sub.columns.as_ref().is_none_or(|set| set.contains(c.name)))
            .map(|(id, _)| id)
            .collect();
        self.plan.tables.push(TableScan {
            table: id,
            columns,
            predicate: sub.predicate,
            fetch: sub.fetch.map(|rows| rows as u64),
        });
        Ok(())
    }

    /// Subscribe to a fused join (see [`crate::query::fusion`]): built per
    /// packet from the frame's layers and served like a table, under the
    /// spec's synthetic name.
    pub fn subscribe_fused(&mut self, sub: FusedSubscription) -> Result<(), Error> {
        if self.fused.iter().any(|spec| spec.name == sub.spec.name) {
            return Err(execution_error(format!(
                "fused join {} is subscribed twice",
                sub.spec.name
            )));
        }
        let scan = sub.spec.to_fused_scan(sub.fetch)?;
        // Kept in name order, so that the order the joins are fed in does
        // not depend on the order they were subscribed in.
        let at = self.fused.partition_point(|spec| spec.name < sub.spec.name);
        self.plan.fused.insert(at, scan);
        self.fused.insert(at, sub.spec);
        Ok(())
    }

    /// Subscribe to a stream-analysis table (`tables::stream_table_names`),
    /// built in full by the stream subscriber of the same pass. Any such
    /// table pins the pass to one partition. Subscribing one twice is a
    /// no-op.
    pub fn subscribe_stream_table(&mut self, name: &str) -> Result<(), Error> {
        let (id, table) = Catalog::builtin()
            .table(name)
            .ok_or_else(|| execution_error(format!("Unknown table: {name}")))?;
        if !table.is_stream() {
            return Err(plan_error(PlanError::NotAStreamTable(table.name)));
        }
        if !self.plan.streams.iter().any(|scan| scan.table == id) {
            let columns = table.default_columns().map(|(id, _)| id).collect();
            self.plan.streams.push(TableScan::new(id, columns));
        }
        Ok(())
    }

    /// The subscription as the scan layer's plan.
    pub fn plan(&self) -> &ScanPlan {
        &self.plan
    }

    /// Nothing to parse: no packet table, no fused join and no stream table.
    pub fn is_empty(&self) -> bool {
        !self.has_packet_tables() && !self.has_stream_tables()
    }

    /// Whether the pass builds anything per packet: a protocol table or a
    /// fused join.
    pub fn has_packet_tables(&self) -> bool {
        !self.plan.tables.is_empty() || !self.plan.fused.is_empty()
    }

    /// Whether the pass builds a stream-analysis table (and therefore runs
    /// as one partition).
    pub fn has_stream_tables(&self) -> bool {
        !self.plan.streams.is_empty()
    }

    /// Every table the pass delivers per packet: the protocol tables and
    /// the fused joins, by name.
    pub fn output_names(&self) -> Vec<String> {
        let catalog = Catalog::builtin();
        self.plan
            .tables
            .iter()
            .map(|scan| catalog.get(scan.table).name.to_string())
            .chain(self.fused.iter().map(|spec| spec.name.clone()))
            .collect()
    }

    /// The stream-analysis tables the pass builds, by name.
    pub fn stream_table_names(&self) -> Vec<&'static str> {
        let catalog = Catalog::builtin();
        self.plan
            .streams
            .iter()
            .map(|scan| catalog.get(scan.table).name)
            .collect()
    }

    /// Resolve the subscription for one pass against `registry`: the parse
    /// scope (the subscribed tables' protocols, the fused joins' members
    /// included, plus dependency closure, with per-protocol field
    /// projections where columns are scoped), and per delivered table its
    /// Arrow schema, predicate and row cap.
    pub fn compile(&self, registry: &ProtocolRegistry) -> Result<CompiledSubscription, Error> {
        let catalog = Catalog::builtin();
        let scan = self.plan.compile(catalog, registry).map_err(plan_error)?;
        // `scan.outputs()` is the plan's tables, then its fused joins.
        let tables = self
            .plan
            .tables
            .iter()
            .zip(scan.outputs())
            .map(|(t, out)| SubscribedOutput {
                name: catalog.get(t.table).name.to_string(),
                schema: Arc::new(out_columns_to_arrow_schema(&out.columns)),
                spec: None,
            });
        let fused = self.fused.iter().map(|spec| SubscribedOutput {
            name: spec.name.clone(),
            schema: Arc::clone(&spec.schema),
            spec: Some(Arc::clone(spec)),
        });
        let outputs: Vec<SubscribedOutput> = tables.chain(fused).collect();
        debug_assert_eq!(outputs.len(), scan.outputs().len());
        let stream_tables = self
            .stream_table_names()
            .into_iter()
            .map(String::from)
            .collect();
        Ok(CompiledSubscription {
            scan,
            outputs,
            stream_tables,
        })
    }
}

/// One table a pass delivers per packet, as DataFusion sees it.
#[derive(Clone, Debug)]
pub struct SubscribedOutput {
    /// The table's name: a protocol table's, or a fused join's synthetic
    /// one.
    pub name: String,
    /// The Arrow schema it materializes: the subscribed columns of a
    /// protocol table (derived from the compiled plan's columns), the
    /// spec's schema for a fused join.
    pub schema: SchemaRef,
    /// The spec, for a fused join.
    pub spec: Option<Arc<FrameJoinSpec>>,
}

/// A [`ParseSubscription`] resolved for one pass (see
/// [`ParseSubscription::compile`]).
#[derive(Clone, Debug)]
pub struct CompiledSubscription {
    scan: CompiledScan,
    /// One per output of `scan.outputs()`, in the same order.
    outputs: Vec<SubscribedOutput>,
    stream_tables: HashSet<String>,
}

impl CompiledSubscription {
    /// The compiled scan plan: the parse scope and, per output, its
    /// columns, predicate and row cap.
    pub fn scan(&self) -> &CompiledScan {
        &self.scan
    }

    /// The tables the pass delivers per packet (protocol tables, then fused
    /// joins), each with its part of the compiled plan.
    pub fn outputs(&self) -> impl Iterator<Item = (&SubscribedOutput, &OutputPlan)> {
        self.outputs.iter().zip(self.scan.outputs())
    }

    /// The names of [`Self::outputs`].
    pub fn output_names(&self) -> impl Iterator<Item = &str> {
        self.outputs.iter().map(|output| output.name.as_str())
    }

    /// The Arrow schema a subscribed table (or fused join) materializes.
    pub fn table_schema(&self, table: &str) -> Option<SchemaRef> {
        self.outputs
            .iter()
            .find(|output| output.name == table)
            .map(|output| Arc::clone(&output.schema))
    }

    /// The stream-analysis tables the pass builds. Non-empty pins the pass
    /// to one partition.
    pub fn stream_tables(&self) -> &HashSet<String> {
        &self.stream_tables
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
    subscription: &CompiledSubscription,
    batch_size: usize,
    progress: Option<(&AtomicU64, &ProgressFn)>,
    mut subscriber: Option<StreamSubscriber>,
) -> Result<PartitionOutput, Error> {
    let scope = subscription.scan().scope();
    let mut batch_set = NormalizedBatchSet::new(batch_size, subscription);
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
    subscription: &CompiledSubscription,
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
    for (output, _) in subscription.outputs() {
        let partitions: Vec<Vec<RecordBatch>> = outputs
            .iter_mut()
            .map(|pb| pb.remove(&output.name).unwrap_or_default())
            .collect();
        let data = TableData {
            schema: Arc::clone(&output.schema),
            partitions,
        };
        rows_built.insert(output.name.clone(), data.total_rows());
        tables_out.insert(output.name.clone(), Arc::new(data));
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
    let subscription = &subscription.compile(registry)?;
    let ranges = if subscription.scan().requires_single_partition() {
        vec![PacketRange::whole()]
    } else {
        decide_ranges(source.as_ref(), target_partitions)?
    };
    if ranges.len() == 1 {
        return sequential_pass(
            source.as_ref(),
            registry,
            batch_size,
            progress,
            subscription,
            keylog,
        );
    }

    let progress_count = AtomicU64::new(0);
    let results: Vec<Result<PartitionOutput, Error>> = std::thread::scope(|thread_scope| {
        let handles: Vec<_> = ranges
            .iter()
            .map(|range| {
                let source = source.clone();
                let registry = registry.clone();
                let range = range.clone();
                let progress = progress.as_ref().map(|cb| (&progress_count, cb));
                thread_scope.spawn(move || {
                    let reader = source.reader_at(&range)?;
                    parse_partition(reader, &registry, subscription, batch_size, progress, None)
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
    let subscription = subscription.compile(registry)?;
    sequential_pass(
        source,
        registry,
        batch_size,
        progress,
        &subscription,
        keylog,
    )
}

/// [`run_shared_parse_sequential`] for a compiled subscription.
fn sequential_pass<S: PacketSource>(
    source: &S,
    registry: &Arc<ProtocolRegistry>,
    batch_size: usize,
    progress: Option<ProgressFn>,
    subscription: &CompiledSubscription,
    keylog: Option<Arc<KeyLog>>,
) -> Result<SharedParseState, Error> {
    let subscriber = (!subscription.stream_tables().is_empty())
        .then(|| StreamSubscriber::new(subscription.stream_tables().clone(), keylog));
    let progress_count = AtomicU64::new(0);
    let reader = source.sequential_reader()?;
    let result = parse_partition(
        reader,
        registry,
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
    subscription: &CompiledSubscription,
    batch_size: usize,
    senders: HashMap<String, BatchSender>,
    pacer: Arc<Pacer>,
    progress: Option<(&AtomicU64, &ProgressFn)>,
    flush_interval: Option<Duration>,
) -> Result<PartitionStat, Error> {
    let scope = subscription.scan().scope();
    let mut batch_set = NormalizedBatchSet::new_streaming(batch_size, subscription, senders, pacer);
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
        .map(|t| (t.to_string(), batch_set.row_count(t)))
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
    if subscription.has_stream_tables() {
        // Stream tables are complete only at end of capture; the engine
        // routes queries that touch them through the materialize path.
        return Err(Error::Query(crate::error::QueryError::Execution(
            "stream tables cannot be streamed; use run_shared_parse".into(),
        )));
    }
    let subscription = Arc::new(subscription.compile(registry)?);
    let num_partitions = openers.len();
    let progress_count = Arc::new(AtomicU64::new(0));

    let table_names: Vec<String> = subscription.output_names().map(String::from).collect();
    let schemas: HashMap<String, SchemaRef> = subscription
        .outputs()
        .map(|(output, _)| (output.name.clone(), Arc::clone(&output.schema)))
        .collect();

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
        let subscription = subscription.clone();
        let progress = progress.clone();
        let progress_count = progress_count.clone();

        producers.push(tokio::task::spawn_blocking(move || {
            let reader = opener.open()?;
            stream_partition(
                reader,
                &registry,
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
    if subscription.has_stream_tables() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::fusion::{FusedColumn, JoinKind, Member, MemberJoin};
    use crate::query::tables;
    use arrow::datatypes::{DataType, Field, Schema};
    use pcapsql_core::scan::{CmpOp, TimestampUnit};

    fn names(columns: &[&str]) -> Option<HashSet<String>> {
        Some(columns.iter().map(|c| c.to_string()).collect())
    }

    fn fused(name: &str) -> FusedSubscription {
        let schema = Schema::new(vec![
            Field::new("f__frame_number", DataType::UInt64, false),
            Field::new("tcp__dst_port", DataType::UInt16, true),
        ]);
        FusedSubscription {
            spec: Arc::new(FrameJoinSpec {
                name: name.to_string(),
                members: vec![
                    Member {
                        table: "frames".to_string(),
                        alias: "f".to_string(),
                        join: None,
                    },
                    Member {
                        table: "tcp".to_string(),
                        alias: "tcp".to_string(),
                        join: Some(MemberJoin {
                            kind: JoinKind::Left,
                            with: 0,
                            depth: false,
                        }),
                    },
                ],
                schema: Arc::new(schema),
                columns: vec![
                    FusedColumn {
                        member: 0,
                        column: "frame_number".to_string(),
                    },
                    FusedColumn {
                        member: 1,
                        column: "dst_port".to_string(),
                    },
                ],
            }),
            fetch: Some(4),
        }
    }

    /// A subscribed table's schema is derived from the compiled plan and is
    /// the table's Arrow schema restricted to the subscribed columns, in
    /// schema order, whatever order (a set) they were named in.
    #[test]
    fn schemas_derive_from_the_plan() {
        let registry = pcapsql_core::default_registry();
        for name in tables::all_table_names() {
            if tables::is_stream_table(name) {
                continue;
            }
            let full = tables::get_table_schema(name).unwrap();
            let all = ParseSubscription::tables_full([name]).unwrap();
            let compiled = all.compile(&registry).unwrap();
            assert_eq!(*compiled.table_schema(name).unwrap(), full, "{name}");

            let every_other: Vec<&str> = full
                .fields()
                .iter()
                .step_by(2)
                .map(|f| f.name().as_str())
                .collect();
            let mut some = ParseSubscription::default();
            some.subscribe_table(
                name,
                TableSubscription {
                    columns: names(&every_other),
                    ..Default::default()
                },
            )
            .unwrap();
            let schema = some.compile(&registry).unwrap().table_schema(name).unwrap();
            let expected: Vec<_> = full.fields().iter().step_by(2).cloned().collect();
            assert_eq!(*schema, Schema::new(expected), "{name}");
        }
    }

    #[test]
    fn plan_holds_tables_fused_joins_and_stream_tables() {
        let (tcp_id, tcp) = Catalog::builtin().table("tcp").unwrap();
        let (dst_port, _) = tcp.column("dst_port").unwrap();
        let predicate = RowPredicate::cmp(dst_port, CmpOp::Eq, 443);

        let mut sub = ParseSubscription::default();
        assert!(sub.is_empty());
        sub.subscribe_table(
            "tcp",
            TableSubscription {
                columns: names(&["dst_port", "frame_number"]),
                predicate: Some(predicate.clone()),
                fetch: Some(9),
            },
        )
        .unwrap();
        sub.subscribe_fused(fused("fused_b")).unwrap();
        sub.subscribe_fused(fused("fused_a")).unwrap();
        assert!(sub.has_packet_tables());
        assert!(!sub.has_stream_tables());
        sub.subscribe_stream_table("tls_sessions").unwrap();
        sub.subscribe_stream_table("tls_sessions").unwrap();
        assert!(sub.has_stream_tables());
        assert!(!sub.is_empty());

        let plan = sub.plan();
        assert_eq!(plan.timestamps, TimestampUnit::Micros);
        assert!(plan.frames.is_all());
        let [scan] = plan.tables.as_slice() else {
            panic!("one table scan");
        };
        assert_eq!(scan.table, tcp_id);
        // Schema order, not the order the columns were named in.
        let (frame_number, _) = tcp.column("frame_number").unwrap();
        assert_eq!(scan.columns, vec![frame_number, dst_port]);
        assert_eq!(scan.predicate, Some(predicate));
        assert_eq!(scan.fetch, Some(9));
        assert_eq!(plan.fused.len(), 2);
        assert_eq!(plan.fused[0].fetch, Some(4));
        assert_eq!(plan.streams.len(), 1);

        // Fused joins are kept in name order.
        assert_eq!(sub.output_names(), ["tcp", "fused_a", "fused_b"]);
        assert_eq!(sub.stream_table_names(), ["tls_sessions"]);

        let registry = pcapsql_core::default_registry();
        let compiled = sub.compile(&registry).unwrap();
        assert!(compiled.scan().requires_single_partition());
        assert_eq!(
            compiled.stream_tables(),
            &HashSet::from(["tls_sessions".to_string()])
        );
        let outputs: Vec<_> = compiled.outputs().collect();
        assert_eq!(
            compiled.output_names().collect::<Vec<_>>(),
            ["tcp", "fused_a", "fused_b"]
        );
        assert!(outputs[0].0.spec.is_none());
        assert!(outputs[0].1.predicate().is_some());
        assert_eq!(outputs[0].1.fetch(), Some(9));
        // A fused join keeps its spec's schema.
        let spec = outputs[1].0.spec.as_ref().unwrap();
        assert_eq!(spec.name, "fused_a");
        assert!(Arc::ptr_eq(&outputs[1].0.schema, &spec.schema));
        assert_eq!(outputs[1].1.columns.len(), spec.schema.fields().len());
        assert_eq!(outputs[1].1.fetch(), Some(4));
        assert!(compiled.table_schema("udp").is_none());
    }

    /// The scope is what the plan compiles to: the subscribed protocols with
    /// their dependencies, projected to the fields the columns read.
    #[test]
    fn compiled_scope_follows_the_subscribed_columns() {
        let registry = pcapsql_core::default_registry();
        let mut sub = ParseSubscription::tables_full(["dns", "frames"]).unwrap();
        sub.subscribe_table(
            "udp",
            TableSubscription {
                columns: names(&["frame_number", "dst_port", "encap_depth"]),
                ..Default::default()
            },
        )
        .unwrap();
        let compiled = sub.compile(&registry).unwrap();
        let scope = compiled.scan().scope();
        assert_eq!(
            scope.required(),
            pcapsql_core::ParseScope::for_tables(&["dns", "udp"], &registry).required()
        );
        assert_eq!(
            scope.projections(),
            &HashMap::from([("udp".to_string(), HashSet::from(["dst_port".to_string()]))])
        );
        assert!(!compiled.scan().requires_single_partition());
    }

    #[test]
    fn invalid_subscriptions_are_errors() {
        let mut sub = ParseSubscription::default();
        assert!(sub
            .subscribe_table("nonexistent", TableSubscription::default())
            .is_err());
        // A stream table is not built per packet, and the reverse.
        assert!(sub
            .subscribe_table("tcp_connections", TableSubscription::default())
            .is_err());
        assert!(sub.subscribe_stream_table("tcp").is_err());
        assert!(sub.subscribe_stream_table("nonexistent").is_err());
        // A column the table does not have, or one DataFusion does not see.
        for column in ["query_name", "timestamp"] {
            let error = sub
                .subscribe_table(
                    "tcp",
                    TableSubscription {
                        columns: names(&["dst_port", column]),
                        ..Default::default()
                    },
                )
                .unwrap_err();
            assert!(
                matches!(&error, Error::Query(QueryError::UnknownColumn { table, column: c })
                    if table == "tcp" && c == column),
                "{error}"
            );
        }
        assert!(sub.is_empty());
        // One subscription per table and per fused join.
        sub.subscribe_table("tcp", TableSubscription::default())
            .unwrap();
        assert!(sub
            .subscribe_table("tcp", TableSubscription::default())
            .is_err());
        sub.subscribe_fused(fused("fused_a")).unwrap();
        assert!(sub.subscribe_fused(fused("fused_a")).is_err());
        assert!(ParseSubscription::tables_full(["udp", "udp"]).is_err());
        assert_eq!(sub.output_names(), ["tcp", "fused_a"]);
    }
}
