//! SQL query engine module.
//!
//! This module provides DataFusion integration for querying packet data.
//!
//! ## Architecture
//!
//! Normalized multi-table schema: per-protocol tables (`frames`, `ethernet`,
//! `ipv4`, `tcp`, `dns`, …) with `frame_number` as the linking key, plus
//! cross-layer views (e.g. `tcp_packets`) and the backward-compatible
//! `packets` view.
//!
//! [`QueryEngine::open`] is the single entry point: local files (mmap by
//! default), cloud URLs and standard input funnel into one shared parse pass,
//! parallel across partitions for seekable sources and sequential for a
//! stream, fanned out to every protocol table. JOINs use sort-merge since all
//! tables emit rows sorted by `frame_number`.
//! The `tumble` / `hop` / `session` table functions (`windowing`) add time
//! windows over `frames` and the `*_packets` views.
//!
//! The migration plan in `docs/query-scoped-parse-migration.md` moves this
//! parse from engine construction to query time, scoped to each query.
//!
//! See the `tables`, `views`, and `providers` submodules for details.

pub mod arrow_schema;
pub mod bpf;
pub mod builders;
mod filter;
pub mod fusion;
pub mod providers;
pub mod stream_tables;
pub mod streaming;
pub mod tables;
pub mod udf;
pub mod views;
pub mod windowing;

pub use arrow_schema::{descriptors_to_arrow_schema, protocol_to_arrow_schema, to_arrow_field};
pub use builders::NormalizedBatchSet;
pub use filter::FilterEvaluator;
pub use providers::{
    auto_target_partitions, merge_ordered_partitions, ParseStats, ParseSubscription, ProgressFn,
    ProtocolScanExec, ProtocolTableProvider, ServedFrom, TableSubscription,
};
pub use streaming::MemoryLimitPolicy;
pub use udf::CaptureTimeRange;

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use arrow::array::RecordBatch;
use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
use datafusion::config::ConfigOptions;
use datafusion::execution::runtime_env::RuntimeEnvBuilder;
use datafusion::execution::session_state::{SessionState, SessionStateBuilder};
use datafusion::logical_expr::{DdlStatement, Expr, LogicalPlan, Statement};
use datafusion::physical_optimizer::optimizer::PhysicalOptimizer;
use datafusion::physical_plan::{ExecutionPlan, SendableRecordBatchStream};
use datafusion::prelude::*;
use futures::{Stream, StreamExt};
use tokio::task::JoinHandle;

use crate::error::{Error, QueryError};
use crate::query::providers::{
    run_shared_parse, run_shared_parse_sequential, run_streaming_parse_sequential, CachedTable,
    PartitionStat, QueryTables, SharedParseState, StreamingHandle, TableCache, TableData,
};
use pcapsql_core::{
    default_registry, FilePacketSource, KeyLog, MmapPacketSource, PacketSource, ProtocolRegistry,
    SeekablePacketSource, StdinPacketSource,
};

#[cfg(feature = "cloud")]
use pcapsql_core::io::{CloudLocation, CloudPacketSource};

/// Default number of partitions to split a seekable source into for the shared
/// parallel parse pass.
fn default_target_partitions() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(1, 16)
}

/// DataFusion's `target_partitions` for a plan whose scans have `partitions`
/// partitions, on an engine with parse parallelism `parallelism`.
///
/// A partitioned scan is planned for exactly its own partition count, so no
/// scan with more than one partition is repartitioned: DataFusion round-robin
/// repartitions a scan with fewer partitions than the target up to it and,
/// when the query has no `ORDER BY`, strips the order-preserving variant of
/// that repartition, which loses the `frame_number` ordering
/// [`merge_ordered_partitions`] merges on and leaves the output in arrival
/// order (#122). A one-partition scan (compressed, unindexed or small cloud
/// source; a pass pinned by a stream table; a table cached from such a pass)
/// keeps the engine's parallelism instead, so filters and projections above
/// it are not throttled: a repartition from one ordered partition keeps the
/// order by construction, each output being a subsequence of one sorted
/// stream. At least 2 either way, since the physical planner plans joins as
/// SortMergeJoin only when `target_partitions > 1` (otherwise a collect-left
/// hash join that buffers one side).
fn session_target_partitions(partitions: usize, parallelism: usize) -> usize {
    if partitions <= 1 {
        parallelism.max(2)
    } else {
        partitions
    }
}

/// Configure DataFusion for SortMergeJoin on frame_number-sorted streams,
/// with the planner for the window table functions' extension nodes.
///
/// `parallelism` is the engine's parse parallelism; each query re-targets its
/// own session state to the partition count it actually has (see
/// [`session_target_partitions`]).
fn create_session_context(
    parallelism: usize,
    continuous: Option<&streaming::ContinuousConfig>,
    fuse_frame_joins: bool,
    memory_limit: Option<usize>,
) -> Result<SessionContext, Error> {
    let mut config = ConfigOptions::default();

    config.execution.target_partitions = session_target_partitions(1, parallelism);
    // Use our declared sort order (by frame_number)
    config.optimizer.prefer_existing_sort = true;
    // Prefer SortMergeJoin - works better with our sorted streams
    config.optimizer.prefer_hash_join = false;
    config.optimizer.repartition_joins = true;
    if continuous.is_some() {
        // One partition end to end: the stream is one partition, and a
        // repartition between the partial and final aggregate would be a
        // pipeline-breaking exchange above it. No batch coalescing either: it
        // would hold the stream's small batches back until 8192 rows had
        // accumulated above every filter.
        config.execution.target_partitions = 1;
        config.execution.coalesce_batches = false;
    }

    let mut builder = SessionStateBuilder::new()
        .with_config(config.into())
        .with_default_features()
        .with_query_planner(Arc::new(windowing::WindowQueryPlanner));
    if let Some(limit) = memory_limit {
        // A greedy pool: every consumer takes what it asks for until the
        // limit, then the request fails (DataFusion's operators spill or
        // error; the streaming aggregate applies its policy).
        let runtime = RuntimeEnvBuilder::new()
            .with_memory_limit(limit, 1.0)
            .build_arc()
            .map_err(|e| Error::Query(QueryError::from(e)))?;
        builder = builder.with_runtime_env(runtime);
    }
    if fuse_frame_joins {
        // Last, over the optimized plan: the view joins it replaces must
        // already have had their projections and filters pushed down.
        let mut rules = datafusion::optimizer::Optimizer::new().rules;
        // The fused scan's nominal partition count is the parse parallelism,
        // as for every protocol table (a plan-only scan must report what
        // will run: a continuous plan is checked on it).
        rules.push(Arc::new(fusion::FuseFrameJoins::new(
            parallelism,
            continuous.is_some(),
        )));
        builder = builder.with_optimizer_rules(rules);
    }
    if let Some(continuous) = continuous {
        // The fused streaming aggregate must replace `AggregateExec` over a
        // window before `SanityCheckPlan` rejects the plan as pipeline
        // breaking, so it goes right in front of that rule.
        let mut rules = PhysicalOptimizer::new().rules;
        let at = rules
            .iter()
            .position(|r| r.name() == streaming::SANITY_CHECK_RULE)
            .unwrap_or(rules.len());
        rules.insert(
            at,
            Arc::new(streaming::FuseWindowAggregate::new(continuous.clone())),
        );
        builder = builder.with_physical_optimizer_rules(rules);
    }
    Ok(SessionContext::new_with_state(builder.build()))
}

/// Where to read a capture from.
///
/// A file or cloud object is seekable and can be read any number of times;
/// the engine partitions it for parallel parsing and, under
/// [`RetentionPolicy::CacheOnTouch`], re-reads it as queries need. Standard
/// input (or any other stream) can be read **once**, sequentially: such an
/// engine runs exactly one parse pass, with the restrictions documented on
/// [`QueryEngine::open`].
#[derive(Clone, Debug)]
pub enum SourceSpec {
    /// Local file path (pcap/pcapng, optionally compressed).
    Path(PathBuf),
    /// Cloud object URL (`s3://…`, `gs://…`, `az://…`); needs the `cloud` feature.
    Url(String),
    /// The process's standard input (pcap/pcapng, optionally compressed),
    /// read sequentially to end of input. The capture header is read when
    /// the engine is opened.
    Stdin,
    /// An already-opened non-seekable stream (a pipe, a socket, an in-memory
    /// buffer): the library form of [`SourceSpec::Stdin`], built with
    /// [`StdinPacketSource::from_reader`].
    Sequential(StdinPacketSource),
}

/// Options for cloud sources (ignored for local paths).
#[derive(Clone, Debug, Default)]
pub struct CloudSourceOptions {
    /// Custom endpoint (S3-compatible stores such as MinIO/SeaweedFS/R2).
    pub endpoint: Option<String>,
    /// Use anonymous (unsigned) requests for public buckets.
    pub anonymous: bool,
    /// Byte-range request chunk size in bytes (`None` = backend default).
    pub chunk_size: Option<usize>,
}

/// What the engine retains between queries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionPolicy {
    /// Retain nothing: each query parses exactly what it needs (columns,
    /// parse-time predicates, row caps) and the result is dropped after
    /// execution. The right policy for one-shot queries.
    None,
    /// Cache each touched table on first use, so later queries over the same
    /// tables parse nothing. The right policy for the REPL. The cache is
    /// column-aware: a table is cached with the columns the first query
    /// needed (unfiltered, uncapped), a later query needing more columns
    /// re-parses the union and widens the entry, and the entry never
    /// narrows, so reuse stays sound for any later query shape.
    CacheOnTouch,
}

/// Construction options for [`QueryEngine::open`].
#[derive(Clone)]
pub struct EngineOptions {
    /// Packets per RecordBatch.
    pub batch_size: usize,
    /// What to retain between queries (see [`RetentionPolicy`]).
    pub retention: RetentionPolicy,
    /// Partition count for the parallel parse pass. `None` = available
    /// parallelism clamped to 1..=16, except that a memory-mapped file under
    /// 1 MiB is parsed in a single partition (see
    /// [`auto_target_partitions`]); an explicit count is always honoured.
    pub target_partitions: Option<usize>,
    /// TLS keylog enabling the decrypted `http2` table.
    pub keylog: Option<Arc<KeyLog>>,
    /// Memory-map local files. Compressed captures are mapped too: they are
    /// decompressed from the map and parsed as a single partition. Falls
    /// back to buffered file I/O only when mapping the file itself fails.
    pub mmap: bool,
    /// Boundary-index checkpoint stride override (mainly tests/benchmarks).
    pub index_stride: Option<u64>,
    /// Invoked with the cumulative packet count as the parse progresses.
    pub progress: Option<ProgressFn>,
    /// Cloud-source options (ignored for local paths).
    pub cloud: CloudSourceOptions,
    /// Treat the source as an unbounded stream (a live capture piped in):
    /// scans are unbounded, `GROUP BY window_start` over `tumble()` / `hop()`
    /// runs as a streaming aggregate that emits each window as it closes
    /// (see [`crate::query::streaming`]), and results are consumed with
    /// [`QueryEngine::execute_stream`]. Needs a stream source
    /// ([`SourceSpec::Stdin`] / [`SourceSpec::Sequential`]) and
    /// [`RetentionPolicy::None`]; the single-use restrictions of a stream
    /// apply, and queries that need the whole input (stream tables, several
    /// scans of one table, sorts, joins, aggregates without a window) are
    /// rejected at planning.
    pub continuous: bool,
    /// Continuous only: how far behind the largest timestamp seen a row may
    /// be and still count — the watermark trails the stream by this much.
    pub allowed_lateness: Duration,
    /// Continuous only: a partially filled batch is handed to the query once
    /// this long has passed since the last one (checked as packets arrive).
    pub flush_interval: Duration,
    /// Continuous only: close and emit every open window after this long
    /// without any input (`None`: windows close on event time only).
    pub idle_timeout: Option<Duration>,
    /// Fuse frame joins into the parse (see [`fusion`]): the `*_packets`
    /// views and hand-written joins of protocol tables on `frame_number` are
    /// built by the parser instead of DataFusion's join operators. Applies
    /// under [`RetentionPolicy::None`] only; on by default. Off is for
    /// comparing plans and results against the join path.
    pub fuse_frame_joins: bool,
    /// Bytes DataFusion's memory pool may hand out to this engine's queries
    /// (sorts, joins, aggregates, and a continuous query's window state).
    /// `None`: unbounded, DataFusion's default.
    pub memory_limit: Option<usize>,
    /// Continuous only: what the streaming window aggregate does when its
    /// state does not fit the memory limit (see [`MemoryLimitPolicy`]).
    pub on_memory_limit: MemoryLimitPolicy,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            batch_size: 10_000,
            retention: RetentionPolicy::CacheOnTouch,
            target_partitions: None,
            keylog: None,
            mmap: true,
            index_stride: None,
            progress: None,
            cloud: CloudSourceOptions::default(),
            continuous: false,
            allowed_lateness: Duration::from_secs(1),
            flush_interval: Duration::from_secs(1),
            idle_timeout: None,
            fuse_frame_joins: true,
            memory_limit: None,
            on_memory_limit: MemoryLimitPolicy::Error,
        }
    }
}

/// A query's results together with the statistics of the parse that
/// produced them (see [`QueryEngine::execute`]).
#[derive(Clone, Debug)]
pub struct QueryOutput {
    /// The result batches.
    pub batches: Vec<RecordBatch>,
    /// What this query parsed; [`ServedFrom::PlanOnly`] for a statement that never
    /// executed a scan.
    pub stats: ParseStats,
}

/// Query engine for PCAP files.
///
/// # Concurrency
///
/// The engine is `Send + Sync` and may be shared between tasks;
/// [`QueryEngine::query`] / [`QueryEngine::execute`] may be called
/// concurrently from any number of tasks. Each query prepares the tables it
/// needs on its own context (one scoped parse pass, or the retention
/// policy's cache), so independent queries do not interfere. Under
/// [`RetentionPolicy::CacheOnTouch`] concurrent first-touch queries of one
/// table may each parse it; the cache only ever widens and converges to the
/// widest column set. [`QueryEngine::context`] is shared: DDL through it is
/// visible to every query, while a data query issued through it builds a
/// plan (`EXPLAIN` works) but fails at execution, since only `query` /
/// `execute` prepare tables. Statistics belong to the query that produced
/// them: use [`QueryEngine::execute`] under concurrency;
/// [`QueryEngine::last_parse_stats`] reports the most recently completed
/// query. Design: `docs/query-context-design.md`.
pub struct QueryEngine {
    ctx: SessionContext,
    registry: Arc<ProtocolRegistry>,
    /// `CacheOnTouch`'s column-aware table cache (empty under
    /// `RetentionPolicy::None`). Each query snapshots the entries it hits
    /// into its own [`QueryTables`].
    cache: Arc<TableCache>,
    /// Capture time range, widened by every parse pass (drives time UDFs).
    time_range: Arc<CaptureTimeRange>,
    retention: RetentionPolicy,
    /// Runs one scoped parse pass over the engine's source (materialize or
    /// stream).
    parse_source: Arc<dyn ParseSource>,
    /// Instrumentation for the most recent query (shared with in-flight
    /// [`QueryStream`]s, which write it when they finish).
    last_stats: Arc<RwLock<ParseStats>>,
    /// Table names this engine registered (the harvest universe).
    known_tables: HashSet<String>,
    /// Parse parallelism (the partition count asked of a seekable source);
    /// also the execution width of a query over one-partition tables.
    parallelism: usize,
    /// Serializes the one-time capture time-range bootstrap
    /// ([`Self::ensure_time_range`]) between concurrent first queries.
    time_range_lock: tokio::sync::Mutex<()>,
    /// The source can be read exactly once (stdin, a pipe): the engine runs
    /// one parse pass, and anything that would need a second one is refused
    /// up front (see [`Self::open`]).
    single_use: bool,
    /// Set when a single-use source's one parse pass has been started.
    consumed: AtomicBool,
    /// Continuous mode (see [`EngineOptions::continuous`]).
    continuous: Option<streaming::ContinuousConfig>,
}

/// Type-erased scoped parse over the engine's source: either materialize the
/// subscribed tables (cache-fill) or stream them to the executing plan.
trait ParseSource: Send + Sync {
    fn materialize(&self, sub: &ParseSubscription) -> Result<SharedParseState, Error>;
    fn stream(&self, sub: &ParseSubscription) -> Result<StreamingHandle, Error>;
    /// The source's own answer for the capture time range (microseconds, from
    /// its boundary index); `None` when it has to be scanned for.
    fn time_range_us(&self) -> Option<(i64, i64)>;
    /// Total frame count from the boundary index, if cheaply available
    /// (header-only scan; `None` for compressed/non-seekable sources).
    fn frame_count(&self) -> Option<u64>;
    /// Release a producer waiting for input on the source (a stream whose
    /// pipe has gone quiet), for good: called once a query is done with its
    /// tables. A file source has nothing to release.
    fn cancel(&self) {}
}

/// Binds a concrete seekable source to the parse parameters.
struct SourceParser<S: SeekablePacketSource> {
    source: Arc<S>,
    registry: Arc<ProtocolRegistry>,
    batch_size: usize,
    partitions: usize,
    progress: Option<providers::ProgressFn>,
    /// TLS keylog enabling decrypted HTTP/2 in the stream subscriber.
    keylog: Option<Arc<KeyLog>>,
}

impl<S: SeekablePacketSource> ParseSource for SourceParser<S> {
    fn materialize(&self, sub: &ParseSubscription) -> Result<SharedParseState, Error> {
        run_shared_parse(
            &self.source,
            &self.registry,
            self.batch_size,
            self.partitions,
            self.progress.clone(),
            sub,
            self.keylog.clone(),
        )
    }

    fn time_range_us(&self) -> Option<(i64, i64)> {
        self.source
            .time_range_ns()
            .map(|(start, end)| (start / 1_000, end / 1_000))
    }

    fn stream(&self, sub: &ParseSubscription) -> Result<StreamingHandle, Error> {
        providers::run_streaming_parse(
            &self.source,
            &self.registry,
            self.batch_size,
            self.partitions,
            self.progress.clone(),
            sub,
        )
    }

    fn frame_count(&self) -> Option<u64> {
        self.source.frame_count()
    }
}

/// Binds a non-seekable source (stdin, a pipe) to the parse parameters: one
/// partition through the source's sequential reader; no boundary index, so
/// the time range and the frame count are never known up front (the
/// `count(*)` fast path is off and a time-range UDF cannot be bootstrapped).
struct SequentialParser<S: PacketSource> {
    source: Arc<S>,
    registry: Arc<ProtocolRegistry>,
    batch_size: usize,
    progress: Option<providers::ProgressFn>,
    keylog: Option<Arc<KeyLog>>,
    /// Continuous engines deliver partial batches on this cadence.
    flush_interval: Option<Duration>,
}

impl<S: PacketSource> ParseSource for SequentialParser<S> {
    fn materialize(&self, sub: &ParseSubscription) -> Result<SharedParseState, Error> {
        run_shared_parse_sequential(
            self.source.as_ref(),
            &self.registry,
            self.batch_size,
            self.progress.clone(),
            sub,
            self.keylog.clone(),
        )
    }

    fn stream(&self, sub: &ParseSubscription) -> Result<StreamingHandle, Error> {
        run_streaming_parse_sequential(
            &self.source,
            &self.registry,
            self.batch_size,
            self.progress.clone(),
            sub,
            self.flush_interval,
        )
    }

    fn time_range_us(&self) -> Option<(i64, i64)> {
        None
    }

    fn frame_count(&self) -> Option<u64> {
        None
    }

    fn cancel(&self) {
        self.source.cancel_reads();
    }
}

/// The error for anything that would need a second read of a single-use
/// source.
fn single_use_error(what: &str) -> Error {
    Error::Query(QueryError::Execution(format!(
        "{what}: stdin can be read once, so an engine over it runs exactly one parse pass"
    )))
}

/// Names of the UDFs whose result depends on the capture's full time range.
const TIME_RANGE_UDFS: &[&str] = &["start_time", "end_time", "relative_time"];

/// Does any expression in the plan call a time-range UDF?
///
/// Runs on the *unoptimized* plan (see [`QueryEngine::execute`]). A user view
/// is normally already inlined there: DataFusion's `LogicalPlanBuilder::scan`
/// expands a view's plan at SQL planning, so `CREATE VIEW v AS SELECT
/// relative_time(…) …` followed by `SELECT * FROM v` is detected like a
/// direct call. A `TableScan` that still carries a view plan
/// (`TableSource::get_logical_plan`) is searched too, so the detection does
/// not depend on that planner detail.
fn uses_time_range_udfs(plan: &LogicalPlan) -> bool {
    let mut found = false;
    let _ = plan.apply_with_subqueries(|node| {
        if let LogicalPlan::TableScan(scan) = node {
            if let Some(view_plan) = scan.source.get_logical_plan() {
                if uses_time_range_udfs(&view_plan) {
                    found = true;
                    return Ok(TreeNodeRecursion::Stop);
                }
            }
        }
        let _ = node.apply_expressions(|expr| {
            let _ = expr.apply(|e| {
                if let Expr::ScalarFunction(f) = e {
                    if TIME_RANGE_UDFS.contains(&f.name()) {
                        found = true;
                        return Ok(TreeNodeRecursion::Stop);
                    }
                }
                Ok(TreeNodeRecursion::Continue)
            });
            Ok(if found {
                TreeNodeRecursion::Stop
            } else {
                TreeNodeRecursion::Continue
            })
        });
        Ok(if found {
            TreeNodeRecursion::Stop
        } else {
            TreeNodeRecursion::Continue
        })
    });
    found
}

/// What one query needs from one table, harvested from its optimized plan.
#[derive(Debug, Default)]
struct TableNeeds {
    /// Referenced columns (`None` = all, e.g. `SELECT *`).
    columns: Option<HashSet<String>>,
    /// Filters pushed into the scan (`Inexact`; DataFusion re-checks).
    filters: Vec<Expr>,
    /// Pushed-down LIMIT.
    fetch: Option<usize>,
    /// Number of scans of this table in the plan (self-joins disable
    /// per-scan scoping so one materialization can serve every scan).
    scan_count: usize,
    /// A fused join (see [`fusion`]) rather than a protocol table: the parse
    /// builds it from the spec.
    fused: Option<Arc<fusion::FrameJoinSpec>>,
}

/// A query's prepared tables plus what is still in flight.
struct PreparedQuery {
    /// What the query's providers serve; handed to DataFusion on the query's
    /// session state and dropped with the query.
    tables: Arc<QueryTables>,
    /// Streaming producers to await after execution (fold stats, surface
    /// parse errors).
    producers: Vec<JoinHandle<Result<PartitionStat, Error>>>,
    /// Statistics known before execution (materialize path, cache hit, fast
    /// path); streaming folds the producers' numbers in afterwards.
    stats: ParseStats,
}

/// Walk an optimized plan and collect per-table needs for our tables.
fn harvest_table_needs(
    plan: &LogicalPlan,
    known_tables: &HashSet<String>,
) -> Result<HashMap<String, TableNeeds>, Error> {
    let mut needs: HashMap<String, TableNeeds> = HashMap::new();
    plan.apply_with_subqueries(|node| {
        if let Some(spec) = fusion::fused_spec_of(node) {
            // The parse builds the whole fused table (its projection is
            // applied by the scan); a LIMIT pushed into the scan caps it.
            let fetch = match node {
                LogicalPlan::TableScan(scan) => scan.fetch,
                _ => None,
            };
            let entry = needs.entry(spec.name.clone()).or_default();
            entry.scan_count += 1;
            entry.fetch = if entry.scan_count == 1 { fetch } else { None };
            entry.fused = Some(spec);
            return Ok(TreeNodeRecursion::Continue);
        }
        if let LogicalPlan::TableScan(scan) = node {
            let name = scan.table_name.table();
            if known_tables.contains(name) {
                let columns: Option<HashSet<String>> = scan.projection.as_ref().map(|indices| {
                    let schema = scan.source.schema();
                    indices
                        .iter()
                        .map(|&i| schema.field(i).name().clone())
                        .collect()
                });
                let entry = needs.entry(name.to_string()).or_default();
                entry.scan_count += 1;
                if entry.scan_count == 1 {
                    entry.columns = columns;
                    entry.filters = scan.filters.clone();
                    entry.fetch = scan.fetch;
                } else {
                    // Multiple scans of one table: one materialization must
                    // serve them all — union columns, drop predicates/caps.
                    entry.columns = match (entry.columns.take(), columns) {
                        (Some(mut a), Some(b)) => {
                            a.extend(b);
                            Some(a)
                        }
                        _ => None,
                    };
                    entry.filters.clear();
                    entry.fetch = None;
                }
            }
        }
        Ok(TreeNodeRecursion::Continue)
    })
    .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;
    Ok(needs)
}

/// A statement after logical planning: finished (it parsed nothing), or a
/// query to prepare and execute.
enum Planned {
    Done(Box<QueryOutput>),
    Query(Box<PlannedQuery>),
}

/// A query ready to prepare and execute.
struct PlannedQuery {
    state: SessionState,
    optimized: LogicalPlan,
    bootstrap: ParseStats,
}

/// Join a streaming pass's producers and fold their statistics (and any
/// parse error, which fails the query closed) into the query's.
///
/// `stats` is what was known before execution (the materialize path, a cache
/// hit, the fast path); a streaming pass replaces it with the producers'
/// numbers. `bootstrap` is a time-range bootstrap pass this query paid for.
async fn fold_producers(
    producers: Vec<JoinHandle<Result<PartitionStat, Error>>>,
    mut stats: ParseStats,
    bootstrap: &ParseStats,
    time_range: &CaptureTimeRange,
) -> (ParseStats, Option<Error>) {
    let mut producer_error = None;
    if !producers.is_empty() {
        let outcomes = futures::future::join_all(producers).await;
        stats = ParseStats {
            parse_passes: 1,
            partitions: outcomes.len(),
            complete_scan: true,
            ..Default::default()
        };
        let mut start = i64::MAX;
        let mut end = i64::MIN;
        for outcome in outcomes {
            match outcome {
                Ok(Ok(p)) => {
                    stats.packets_scanned += p.packets;
                    stats.complete_scan &= !p.capped;
                    if p.min_us != i64::MAX {
                        start = start.min(p.min_us);
                    }
                    if p.max_us != i64::MIN {
                        end = end.max(p.max_us);
                    }
                    for (t, n) in p.rows_built {
                        *stats.rows_built.entry(t).or_insert(0) += n;
                    }
                    for (t, o) in p.overflow {
                        if o.total_bytes > 0 {
                            *stats.overflowed_bytes.entry(t.clone()).or_insert(0) += o.total_bytes;
                            *stats.overflow_peak_bytes.entry(t).or_insert(0) += o.peak_bytes;
                        }
                    }
                }
                Ok(Err(e)) => producer_error = producer_error.or(Some(e)),
                Err(join_err) => {
                    producer_error = producer_error.or(Some(Error::Query(QueryError::Execution(
                        format!("parse producer panicked: {join_err}"),
                    ))))
                }
            }
        }
        if start != i64::MAX {
            stats.start_ts_us = start;
            stats.end_ts_us = end;
            time_range.record(start, end);
            if stats.complete_scan {
                time_range.mark_complete();
            }
        }
    }
    // A time-range bootstrap pass (source without a boundary index) is part
    // of what this query cost; fold it in rather than hide it.
    stats.parse_passes += bootstrap.parse_passes;
    stats.packets_scanned += bootstrap.packets_scanned;
    (stats, producer_error)
}

/// A query's result as a stream of batches (see
/// [`QueryEngine::execute_stream`]).
///
/// Owns the query's session state, prepared tables and parse producers.
/// Yields `Err` once and ends on an execution error. Dropping the stream
/// cancels the query: its receivers go away, the source is told to stop
/// waiting for input, and the producers stop. [`QueryStream::finish`] drops
/// the same holders *before* joining the producers, in that order, so a
/// producer waiting on a receiver the plan never drained is released rather
/// than waited for.
pub struct QueryStream {
    inner: Option<SendableRecordBatchStream>,
    plan: Option<Arc<dyn ExecutionPlan>>,
    state: Option<SessionState>,
    prepared: Option<Arc<QueryTables>>,
    producers: Vec<JoinHandle<Result<PartitionStat, Error>>>,
    /// The engine's source, told to release a waiting producer when the
    /// stream is finished or dropped.
    parse_source: Option<Arc<dyn ParseSource>>,
    /// Statistics known before execution (see [`fold_producers`]).
    stats: ParseStats,
    bootstrap: ParseStats,
    time_range: Arc<CaptureTimeRange>,
    last_stats: Arc<RwLock<ParseStats>>,
    /// Batches of a statement that already ran (DDL, EXPLAIN).
    ready: VecDeque<RecordBatch>,
}

impl QueryStream {
    fn ready(output: QueryOutput) -> Self {
        Self {
            inner: None,
            plan: None,
            state: None,
            prepared: None,
            producers: Vec::new(),
            parse_source: None,
            stats: output.stats,
            bootstrap: ParseStats::default(),
            time_range: Arc::new(CaptureTimeRange::new()),
            last_stats: Arc::new(RwLock::new(ParseStats::default())),
            ready: output.batches.into(),
        }
    }

    /// The physical plan being executed (`None` for a statement that parsed
    /// nothing), e.g. to inspect a continuous query's fused aggregate.
    pub fn plan(&self) -> Option<&Arc<dyn ExecutionPlan>> {
        self.plan.as_ref()
    }

    /// Continuous queries: the streaming aggregate's current watermark in
    /// microseconds since the epoch, once it has one.
    pub fn watermark_us(&self) -> Option<i64> {
        self.plan.as_ref().and_then(streaming::watermark_us)
    }

    /// Continuous queries: rows dropped as late so far.
    pub fn late_rows(&self) -> u64 {
        self.plan.as_ref().map(streaming::late_rows).unwrap_or(0)
    }

    /// Continuous queries: windows emitted so far.
    pub fn windows_emitted(&self) -> u64 {
        self.plan
            .as_ref()
            .map(streaming::windows_emitted)
            .unwrap_or(0)
    }

    /// Continuous queries: windows emitted early because the memory limit
    /// was reached (`on_memory_limit: CloseOldest`).
    pub fn windows_forced(&self) -> u64 {
        self.plan
            .as_ref()
            .map(streaming::windows_forced)
            .unwrap_or(0)
    }

    /// Continuous queries: bytes of window state the streaming aggregate
    /// holds right now (what it accounts to the memory pool).
    pub fn state_bytes(&self) -> u64 {
        self.plan.as_ref().map(streaming::state_bytes).unwrap_or(0)
    }

    /// Release the query's context and join its parse producers, returning
    /// the query's statistics (what `--stats` prints) or the parse error that
    /// ended it. Call it after the stream has ended, or earlier to cancel.
    ///
    /// A producer waiting for input on a quiet pipe is released
    /// ([`pcapsql_core::PacketSource::cancel_reads`]) before it is joined, so
    /// this returns promptly on a source opened from a descriptor (stdin, a
    /// pipe). A source opened from an arbitrary `Read` cannot be released:
    /// its producer returns at the next byte or when the writer closes, so
    /// bound the call with a timeout if that matters.
    pub async fn finish(mut self) -> Result<ParseStats, Error> {
        let late_rows = self.late_rows();
        let windows_forced = self.windows_forced();
        // Order matters: the stream and the plan hold the receivers and the
        // TaskContext, the state and the tables hold the rest.
        self.inner = None;
        self.plan = None;
        self.state = None;
        self.prepared = None;
        let producers = std::mem::take(&mut self.producers);
        // Only a query that started the parse has a producer to release;
        // cancelling is permanent on a single-use source, so a statement
        // that parsed nothing must leave the stream for the next one.
        if let Some(source) = self.parse_source.take() {
            if !producers.is_empty() {
                source.cancel();
            }
        }
        let stats = std::mem::take(&mut self.stats);
        let (mut stats, error) =
            fold_producers(producers, stats, &self.bootstrap, &self.time_range).await;
        stats.late_rows = late_rows;
        stats.windows_forced = windows_forced;
        *self.last_stats.write().expect("stats lock poisoned") = stats.clone();
        match error {
            Some(e) => Err(e),
            None => Ok(stats),
        }
    }
}

impl Drop for QueryStream {
    /// A stream dropped before `finish()` cancels its query: the receivers
    /// go with the fields, and the source releases a producer still waiting
    /// for input. The producers are detached, not joined.
    fn drop(&mut self) {
        if !self.producers.is_empty() {
            if let Some(source) = self.parse_source.take() {
                source.cancel();
            }
        }
    }
}

impl Stream for QueryStream {
    type Item = Result<RecordBatch, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(batch) = self.ready.pop_front() {
            return Poll::Ready(Some(Ok(batch)));
        }
        let Some(inner) = self.inner.as_mut() else {
            return Poll::Ready(None);
        };
        match inner.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(batch))) => Poll::Ready(Some(Ok(batch))),
            Poll::Ready(Some(Err(e))) => {
                self.inner = None;
                Poll::Ready(Some(Err(Error::Query(QueryError::from(e)))))
            }
            Poll::Ready(None) => {
                self.inner = None;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// What a statement does with the capture, decided from the top node of the
/// unoptimized plan **before** anything is prepared.
#[derive(Debug, PartialEq, Eq)]
enum StatementKind {
    /// Reads capture tables: harvest, prepare, execute.
    Query,
    /// Builds and displays a plan but never polls a scan (`EXPLAIN`):
    /// planned without prepared tables, nothing parsed.
    PlanOnly,
    /// DDL / session statement (`CREATE VIEW`, `DESCRIBE`, `SET`, …):
    /// executed on the shared context, nothing parsed.
    Statement,
}

/// Classify a statement. `CREATE TABLE … AS SELECT` over a capture table and
/// `EXECUTE` are rejected: DataFusion runs their input on the plain session
/// state, where no table is prepared.
fn classify_statement(
    plan: &LogicalPlan,
    known_tables: &HashSet<String>,
) -> Result<StatementKind, Error> {
    Ok(match plan {
        LogicalPlan::Explain(_) => StatementKind::PlanOnly,
        LogicalPlan::Ddl(DdlStatement::CreateMemoryTable(cmd)) => {
            if harvest_table_needs(&cmd.input, known_tables)?.is_empty() {
                StatementKind::Statement
            } else {
                return Err(Error::Query(QueryError::Execution(
                    "CREATE TABLE … AS SELECT over a capture table is not supported; \
                     CREATE VIEW over it, or run the SELECT and keep its batches"
                        .into(),
                )));
            }
        }
        LogicalPlan::Statement(Statement::Execute(_)) => {
            return Err(Error::Query(QueryError::Execution(
                "EXECUTE of a prepared statement is not supported through \
                 QueryEngine::query; run the statement's SQL directly"
                    .into(),
            )));
        }
        LogicalPlan::Ddl(_) | LogicalPlan::Statement(_) | LogicalPlan::DescribeTable(_) => {
            StatementKind::Statement
        }
        _ => StatementKind::Query,
    })
}

/// Does a cached column set cover what a query needs?
///
/// `cached` is the cached entry's column names (`None` = not cached).
/// `needed` is the query's projected columns (`None` = all columns).
fn cache_covers(
    cached: Option<&std::collections::HashSet<String>>,
    needed: &Option<HashSet<String>>,
    table: &str,
) -> bool {
    let Some(cached) = cached else {
        return false; // not cached
    };
    match needed {
        // Needs every column: covered only if the cache is the full table.
        None => tables::get_table_schema(table)
            .map(|schema| cached.len() == schema.fields().len())
            .unwrap_or(false),
        Some(cols) => cols.iter().all(|c| cached.contains(c)),
    }
}

/// Union of a cached column set and a query's needed columns; `None`
/// (all columns) on either side widens to all.
fn column_union(
    cached: Option<std::collections::HashSet<String>>,
    needed: &Option<HashSet<String>>,
) -> Option<HashSet<String>> {
    match (cached, needed) {
        (_, None) => None,
        (None, Some(n)) => Some(n.clone()),
        (Some(mut c), Some(n)) => {
            c.extend(n.iter().cloned());
            Some(c)
        }
    }
}

impl QueryEngine {
    /// Open a capture and build the engine.
    ///
    /// The single constructor: local files (memory-mapped by default, with a
    /// buffered-file fallback), cloud URLs and standard input are served by
    /// the same scoped parse machinery. **No parsing happens here** — each
    /// query parses exactly the tables (and columns/predicates/limits) it
    /// references, per the engine's [`RetentionPolicy`]. (Opening stdin does
    /// read the capture *header*, to learn the format and link type.)
    ///
    /// # Standard input and other single-use sources
    ///
    /// A stream ([`SourceSpec::Stdin`], [`SourceSpec::Sequential`]) can be
    /// read once, so the engine runs **one** parse pass, as a single
    /// partition, and refuses what would need another:
    ///
    /// - `opts.retention` must be [`RetentionPolicy::None`]; `CacheOnTouch`
    ///   is rejected here, since a cache that is filled per query would need
    ///   a pass per first-touched table set.
    /// - `opts.target_partitions` is ignored: the pass is one partition.
    /// - One query may parse. A query over capture tables after that pass
    ///   fails with "stdin was already consumed". Statements that parse
    ///   nothing (`EXPLAIN`, DDL, `SELECT 1`) are fine before and after.
    /// - Any one query may touch any number of tables, including stream
    ///   tables (`tcp_connections`, …): they share the one pass.
    /// - The time-range functions `start_time()`, `end_time()` and
    ///   `relative_time()` are not available before the pass: they need the
    ///   whole capture read first. Such a query is rejected without
    ///   consuming the stream. After a complete pass the range is known, so
    ///   a later scan-free query (`SELECT start_time()`) is answered from it.
    /// - The `count(*)` index fast path is off (no boundary index): a count
    ///   parses, like any other query.
    ///
    /// The stream is read to end of input, like a file.
    pub async fn open(spec: SourceSpec, opts: EngineOptions) -> Result<Self, Error> {
        match spec {
            SourceSpec::Stdin => {
                let source = StdinPacketSource::stdin()?;
                Self::build_sequential(Arc::new(source), opts).await
            }
            SourceSpec::Sequential(source) => Self::build_sequential(Arc::new(source), opts).await,
            SourceSpec::Path(path) => {
                if opts.mmap {
                    if let Ok(source) = MmapPacketSource::open(&path) {
                        let source = match opts.index_stride {
                            Some(stride) => source.with_index_stride(stride),
                            None => source,
                        };
                        return Self::build(Arc::new(source), opts).await;
                    }
                    // mmap rejected the file (e.g. compressed): fall back to
                    // buffered file I/O below.
                }
                let source = FilePacketSource::open(&path)?;
                let source = match opts.index_stride {
                    Some(stride) => source.with_index_stride(stride),
                    None => source,
                };
                Self::build(Arc::new(source), opts).await
            }
            #[cfg(feature = "cloud")]
            SourceSpec::Url(url) => {
                let mut location = CloudLocation::parse(&url).map_err(|e| {
                    Error::Query(QueryError::Execution(format!("Invalid cloud URL: {e}")))
                })?;
                if let Some(endpoint) = &opts.cloud.endpoint {
                    location = location.with_endpoint(endpoint);
                }
                if opts.cloud.anonymous {
                    location = location.with_anonymous(true);
                }
                if let Some(chunk_size) = opts.cloud.chunk_size {
                    location = location.with_chunk_size(chunk_size);
                }
                let source = CloudPacketSource::open(location).map_err(|e| {
                    Error::Query(QueryError::Execution(format!("Cloud source error: {e}")))
                })?;
                let source = match opts.index_stride {
                    Some(stride) => source.with_index_stride(stride),
                    None => source,
                };
                Self::build(Arc::new(source), opts).await
            }
            #[cfg(not(feature = "cloud"))]
            SourceSpec::Url(url) => Err(Error::Query(QueryError::Execution(format!(
                "Cannot open '{url}': built without cloud support (enable the `cloud` feature)"
            )))),
        }
    }

    /// Build the engine over an opened seekable source: the scoped parse is
    /// partitioned across the engine's parallelism.
    async fn build<S: SeekablePacketSource>(
        source: Arc<S>,
        opts: EngineOptions,
    ) -> Result<Self, Error> {
        if opts.continuous {
            return Err(Error::Query(QueryError::Execution(
                "continuous mode reads a live stream: open standard input or a pipe \
                 (SourceSpec::Stdin / SourceSpec::Sequential, `--stdin`), not a file"
                    .into(),
            )));
        }
        let registry = Arc::new(default_registry());
        // An explicit count is honoured; otherwise small mmap files stay in
        // one partition (see `auto_target_partitions`).
        let parallelism = opts.target_partitions.unwrap_or_else(|| {
            auto_target_partitions(source.as_ref(), default_target_partitions())
        });
        let parse_source: Arc<dyn ParseSource> = Arc::new(SourceParser {
            source,
            registry: registry.clone(),
            batch_size: opts.batch_size,
            partitions: parallelism,
            progress: opts.progress.clone(),
            keylog: opts.keylog.clone(),
        });
        Self::finish_build(parse_source, registry, parallelism, opts, false).await
    }

    /// Build the engine over a single-use sequential source (stdin, a pipe):
    /// one partition, no partition auto-tuning, `RetentionPolicy::None`
    /// required (see [`Self::open`]).
    async fn build_sequential<S: PacketSource>(
        source: Arc<S>,
        opts: EngineOptions,
    ) -> Result<Self, Error> {
        if opts.retention != RetentionPolicy::None {
            return Err(single_use_error(
                "RetentionPolicy::CacheOnTouch is not available on stdin (use RetentionPolicy::None)",
            ));
        }
        let registry = Arc::new(default_registry());
        let parse_source: Arc<dyn ParseSource> = Arc::new(SequentialParser {
            source,
            registry: registry.clone(),
            batch_size: opts.batch_size,
            progress: opts.progress.clone(),
            keylog: opts.keylog.clone(),
            flush_interval: opts.continuous.then_some(opts.flush_interval),
        });
        Self::finish_build(parse_source, registry, 1, opts, true).await
    }

    /// Register providers, UDFs and views on a session context sized for
    /// `parallelism` parse partitions, and bind the scoped-parse source
    /// queries will drive.
    async fn finish_build(
        parse_source: Arc<dyn ParseSource>,
        registry: Arc<ProtocolRegistry>,
        parallelism: usize,
        opts: EngineOptions,
        single_use: bool,
    ) -> Result<Self, Error> {
        let continuous = opts.continuous.then_some(streaming::ContinuousConfig {
            allowed_lateness: opts.allowed_lateness,
            idle_timeout: opts.idle_timeout,
            on_memory_limit: opts.on_memory_limit,
        });
        // Fusion needs the parse to serve the joined table directly; under
        // CacheOnTouch the per-table cache and DataFusion's joins stay.
        let ctx = create_session_context(
            parallelism,
            continuous.as_ref(),
            opts.retention == RetentionPolicy::None && opts.fuse_frame_joins,
            opts.memory_limit,
        )?;
        udf::register_all_udfs(&ctx)?;

        // Time UDFs read a shared range that parse passes widen.
        let time_range = Arc::new(CaptureTimeRange::new());
        udf::register_time_udfs(&ctx, time_range.clone())?;

        // One provider per table; each query hands them its own prepared
        // tables through the session state it is planned with.
        let cache = Arc::new(TableCache::new());
        let mut known_tables = HashSet::new();
        for table_name in tables::all_table_names() {
            let schema = Arc::new(tables::get_table_schema(table_name).ok_or_else(|| {
                Error::Query(QueryError::Execution(format!(
                    "Unknown table: {table_name}"
                )))
            })?);
            let provider =
                providers::ProtocolTableProvider::new(table_name.to_string(), schema, parallelism)
                    .with_unbounded(continuous.is_some());
            ctx.register_table(table_name, Arc::new(provider))
                .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;
            known_tables.insert(table_name.to_string());
        }

        Self::register_cross_layer_views(&ctx).await?;
        // tumble / hop / session resolve their source in this context's
        // catalog (tables and views alike) and expand into its scan.
        windowing::register_window_functions(&ctx);

        Ok(Self {
            ctx,
            registry,
            cache,
            time_range,
            retention: opts.retention,
            parse_source,
            last_stats: Arc::new(RwLock::new(ParseStats::default())),
            known_tables,
            parallelism,
            time_range_lock: tokio::sync::Mutex::new(()),
            single_use,
            consumed: AtomicBool::new(false),
            continuous,
        })
    }

    /// Make sure the capture time range behind `start_time()` / `end_time()` /
    /// `relative_time()` covers the whole capture before a query that calls
    /// them runs.
    ///
    /// Parsing is scoped per query, so a query's own parse may see only some
    /// packets (a pushed-down LIMIT), or none at all (`SELECT start_time()`).
    /// The range therefore comes from the boundary index when the source has
    /// one (no packet parsing), else from one header-only pass over the
    /// capture (a `frames`-only scope runs no protocol parser). Either way it
    /// is established once per engine, also when concurrent first queries
    /// need it at the same time.
    ///
    /// Returns the statistics of the header-only pass when one ran (so the
    /// query can report it), or an empty `ParseStats` otherwise.
    async fn ensure_time_range(&self) -> Result<ParseStats, Error> {
        if self.time_range.is_complete() {
            return Ok(ParseStats::default());
        }
        let _once = self.time_range_lock.lock().await;
        if self.time_range.is_complete() {
            return Ok(ParseStats::default()); // bootstrapped while we waited
        }
        if let Some((start_us, end_us)) = self.parse_source.time_range_us() {
            self.time_range.record(start_us, end_us);
            self.time_range.mark_complete();
            return Ok(ParseStats::default());
        }
        let mut subscription = ParseSubscription::default();
        subscription.tables.insert(
            "frames".to_string(),
            TableSubscription {
                columns: Some(["timestamp".to_string()].into_iter().collect()),
                predicate: None,
                fetch: None,
            },
        );
        let (_, stats) = self.parse_source.materialize(&subscription)?.into_tables();
        if stats.packets_scanned > 0 {
            self.time_range.record(stats.start_ts_us, stats.end_ts_us);
        }
        self.time_range.mark_complete();
        // The pass built no table the query asked for; report the scan only.
        Ok(ParseStats {
            rows_built: HashMap::new(),
            ..stats
        })
    }

    /// Execute a SQL query and return results.
    ///
    /// Plans first, harvests the optimized plan's table needs, prepares them
    /// for this query (one scoped parse pass, or the retention policy's
    /// cache) into a [`QueryTables`] carried on the query's own session
    /// state, then executes exactly the plan that was harvested. This is THE
    /// query path: queries issued directly against [`Self::context`] bypass
    /// the parse and fail at execution with "table was not prepared for this
    /// query".
    ///
    /// Statements that never poll a scan parse nothing: `EXPLAIN` is planned
    /// over unprepared (plan-only) tables and displayed; DDL and session
    /// statements run on the shared context. [`Self::last_parse_stats`] then
    /// reports [`ServedFrom::PlanOnly`]. `EXPLAIN ANALYZE` executes and parses like a
    /// query. `CREATE TABLE … AS SELECT` over a capture table and `EXECUTE`
    /// are rejected with a clear error.
    ///
    /// Queries on one engine may run concurrently (see the type-level
    /// documentation). Only the batches are returned; [`Self::execute`] also
    /// returns the query's [`ParseStats`].
    pub async fn query(&self, sql: &str) -> Result<Vec<RecordBatch>, Error> {
        Ok(self.execute(sql).await?.batches)
    }

    /// Execute a SQL query and return its results together with the
    /// statistics of the parse it performed (the query path is described on
    /// [`Self::query`]). The statistics are this query's own, whatever else
    /// runs on the engine; they are also what [`Self::last_parse_stats`]
    /// reports until another query completes.
    pub async fn execute(&self, sql: &str) -> Result<QueryOutput, Error> {
        let PlannedQuery {
            mut state,
            optimized,
            bootstrap,
        } = match self.plan_statement(sql).await? {
            Planned::Done(output) => return Ok(*output),
            Planned::Query(query) => *query,
        };

        let needs = harvest_table_needs(&optimized, &self.known_tables)?;
        self.check_continuous_needs(&needs)?;
        self.check_plannable(&state, &optimized).await?;
        let PreparedQuery {
            tables: prepared,
            producers,
            stats,
        } = self.prepare(needs)?;

        // Hand this query's tables to its providers and execute. The result
        // is captured, not returned early: the producers below must always be
        // joined (fail closed on a parse error).
        self.configure_query_state(&mut state, &prepared);
        let result = async {
            let plan = self.physical_plan(&state, &optimized).await?;
            Self::collect_plan(&state, plan).await
        }
        .await;

        // Every holder of the query's tables goes away before the producers
        // are joined: the physical plan and the TaskContext were owned by
        // `collect_plan`; `state` carries the extension on its config;
        // `prepared` is ours. Receivers of partitions the plan never executed
        // (a LIMIT satisfied early) drop here, so a producer waiting on them
        // sees its consumers gone rather than waiting forever. Dropping this
        // future anywhere above has the same effect. A producer of a
        // single-use stream may instead be waiting for input on a quiet
        // pipe: the source releases it (only when this query started one;
        // cancelling is permanent, and a statement that parsed nothing must
        // leave the stream for the next).
        drop(state);
        drop(prepared);
        if !producers.is_empty() {
            self.parse_source.cancel();
        }

        let (stats, producer_error) =
            fold_producers(producers, stats, &bootstrap, &self.time_range).await;
        // Written once, after the producers are folded, so what
        // `last_parse_stats` reports is always a completed query's.
        *self.last_stats.write().expect("stats lock poisoned") = stats.clone();

        match producer_error {
            Some(e) => Err(e),
            None => Ok(QueryOutput {
                batches: result?,
                stats,
            }),
        }
    }

    /// Execute a query and consume its result as a stream of batches.
    ///
    /// This is the query path of a continuous engine
    /// ([`EngineOptions::continuous`]): a windowed aggregate over a live
    /// capture emits each window as it closes, and the stream runs until the
    /// input ends (or the stream is dropped). It works on any engine — a file
    /// query simply streams its batches as they are produced. Statements that
    /// parse nothing (`EXPLAIN`, DDL) yield their result batches and end.
    ///
    /// A continuous query with an idle timeout arms a `tokio::time` timer, so
    /// such a stream must be polled inside a tokio runtime with time enabled.
    ///
    /// The returned [`QueryStream`] owns everything the query holds (its
    /// session state, prepared tables, parse producers); call
    /// [`QueryStream::finish`] after the last batch for the query's
    /// [`ParseStats`] and any parse error, or just drop it to cancel: the
    /// producers see their consumers gone and stop, and one waiting for
    /// input on a quiet pipe is released by the source (a source opened
    /// from an arbitrary `Read` cannot be: its producer stops at the next
    /// byte, or when the process exits).
    pub async fn execute_stream(&self, sql: &str) -> Result<QueryStream, Error> {
        let PlannedQuery {
            mut state,
            optimized,
            bootstrap,
        } = match self.plan_statement(sql).await? {
            Planned::Done(output) => return Ok(QueryStream::ready(*output)),
            Planned::Query(query) => *query,
        };
        let needs = harvest_table_needs(&optimized, &self.known_tables)?;
        self.check_continuous_needs(&needs)?;
        self.check_plannable(&state, &optimized).await?;
        let PreparedQuery {
            tables: prepared,
            producers,
            stats,
        } = self.prepare(needs)?;
        self.configure_query_state(&mut state, &prepared);
        let planned = async {
            let plan = self.physical_plan(&state, &optimized).await?;
            let stream =
                datafusion::physical_plan::execute_stream(Arc::clone(&plan), state.task_ctx())
                    .map_err(|e| Error::Query(QueryError::from(e)))?;
            Ok::<_, Error>((plan, stream))
        }
        .await;
        match planned {
            Ok((plan, stream)) => Ok(QueryStream {
                inner: Some(stream),
                plan: Some(plan),
                state: Some(state),
                prepared: Some(prepared),
                producers,
                parse_source: Some(Arc::clone(&self.parse_source)),
                stats,
                bootstrap,
                time_range: Arc::clone(&self.time_range),
                last_stats: Arc::clone(&self.last_stats),
                ready: VecDeque::new(),
            }),
            Err(e) => {
                // Planning failed: release the tables and the source, then
                // join the producers so a parse error is not lost and
                // nothing leaks.
                drop(state);
                drop(prepared);
                if !producers.is_empty() {
                    self.parse_source.cancel();
                }
                let (_, producer_error) =
                    fold_producers(producers, stats, &bootstrap, &self.time_range).await;
                Err(producer_error.unwrap_or(e))
            }
        }
    }

    /// Plan a statement up to the optimized logical plan, running statements
    /// that parse nothing (DDL, EXPLAIN) to completion on the way.
    async fn plan_statement(&self, sql: &str) -> Result<Planned, Error> {
        // A per-query copy of the shared session state: the query's prepared
        // tables ride on its config as an extension.
        let state = self.ctx.state();
        let plan = state
            .create_logical_plan(sql)
            .await
            .map_err(|e| Error::Query(QueryError::from(e)))?;
        let kind = classify_statement(&plan, &self.known_tables)?;
        if kind == StatementKind::Statement {
            // DDL / session statements: nothing to prepare. Run on the shared
            // context so e.g. CREATE VIEW lands in the shared catalog.
            let batches = self.collect_on_context(plan).await?;
            let stats = ParseStats {
                served_from: ServedFrom::PlanOnly,
                ..Default::default()
            };
            *self.last_stats.write().expect("stats lock poisoned") = stats.clone();
            return Ok(Planned::Done(Box::new(QueryOutput { batches, stats })));
        }
        // The time UDFs are `Stable`, so the optimizer constant-folds
        // `start_time()` / `end_time()` *during* `optimize`: the range must be
        // complete before that, hence the check on the unoptimized plan.
        // (Also for EXPLAIN, so the displayed constant is the real one; the
        // range comes from the boundary index without a packet parse.)
        let bootstrap = if uses_time_range_udfs(&plan) {
            if self.single_use && !self.time_range.is_complete() {
                // The bootstrap is a header-only pass over the whole capture,
                // which would consume the stream before the query runs. Once
                // the one pass has read the whole stream the range is known
                // and `ensure_time_range` answers from it without reading.
                return Err(single_use_error(
                    "time-range functions (start_time, end_time, relative_time) are not \
                     available on stdin",
                ));
            }
            self.ensure_time_range().await?
        } else {
            ParseStats::default()
        };
        let optimized = state
            .optimize(&plan)
            .map_err(|e| Error::Query(QueryError::from(e)))?;
        if kind == StatementKind::PlanOnly {
            // EXPLAIN: build and display the plan on a state without prepared
            // tables (the providers return plan-only scans); no parse, no
            // execution. DataFusion's EXPLAIN keeps a physical optimizer
            // error for EXPLAIN VERBOSE only, so in continuous mode plan the
            // explained query itself first and report what the query would.
            if self.continuous.is_some() {
                if let LogicalPlan::Explain(explain) = &optimized {
                    self.physical_plan(&state, explain.plan.as_ref()).await?;
                }
            }
            let plan = self.physical_plan(&state, &optimized).await?;
            let batches = Self::collect_plan(&state, plan).await?;
            // The only parse a plan-only statement can trigger is the
            // time-range bootstrap; report it rather than claim zero.
            let stats = ParseStats {
                served_from: ServedFrom::PlanOnly,
                ..bootstrap
            };
            *self.last_stats.write().expect("stats lock poisoned") = stats.clone();
            return Ok(Planned::Done(Box::new(QueryOutput { batches, stats })));
        }
        Ok(Planned::Query(Box::new(PlannedQuery {
            state,
            optimized,
            bootstrap,
        })))
    }

    /// A continuous query runs on what has arrived so far; refuse what needs
    /// the whole input first, before anything is prepared.
    fn check_continuous_needs(&self, needs: &HashMap<String, TableNeeds>) -> Result<(), Error> {
        if self.continuous.is_none() {
            return Ok(());
        }
        let mut stream_tables: Vec<&str> = needs
            .keys()
            .filter(|t| tables::is_stream_table(t))
            .map(String::as_str)
            .collect();
        stream_tables.sort_unstable();
        if !stream_tables.is_empty() {
            return Err(Error::Query(QueryError::Execution(format!(
                "continuous queries cannot read stream tables ({}): they are complete only at \
                 end of input",
                stream_tables.join(", ")
            ))));
        }
        if needs.values().any(|n| n.scan_count > 1) {
            return Err(Error::Query(QueryError::Execution(
                "continuous queries cannot scan one table twice (a self-join the parser cannot \
                 fuse, an IN subquery on the same table): the stream is read once"
                    .into(),
            )));
        }
        Ok(())
    }

    /// On a single-use source, build the physical plan once *before* the
    /// stream is touched, over plan-only scans (same shape and properties,
    /// unboundedness included), so that a plan DataFusion rejects — a
    /// continuous query that needs the whole stream — fails without starting
    /// the one parse pass, whose producer could otherwise only be joined once
    /// the pipe delivers its next byte.
    async fn check_plannable(
        &self,
        state: &SessionState,
        optimized: &LogicalPlan,
    ) -> Result<(), Error> {
        if self.single_use {
            let mut dry_run = state.clone();
            if self.continuous.is_some() {
                dry_run
                    .config_mut()
                    .options_mut()
                    .execution
                    .target_partitions = 1;
            }
            self.physical_plan(&dry_run, optimized).await?;
        }
        Ok(())
    }

    /// Give a query's session state its prepared tables and its partition
    /// count.
    fn configure_query_state(&self, state: &mut SessionState, prepared: &Arc<QueryTables>) {
        // Plan for the partition count this query actually has: the boundary
        // index may yield fewer partitions than the engine's parallelism, and a
        // scan with fewer partitions than `target_partitions` would be
        // round-robin repartitioned in a way that loses capture order (#122;
        // see `session_target_partitions`). A continuous query stays on one
        // partition throughout: a repartition between the partial and final
        // aggregate would put a pipeline-breaking exchange above the stream.
        state.config_mut().options_mut().execution.target_partitions = if self.continuous.is_some()
        {
            1
        } else {
            session_target_partitions(prepared.partitions(), self.parallelism)
        };
        state.config_mut().set_extension(Arc::clone(prepared));
    }

    /// Plan an already optimized logical plan on `state`, whose config
    /// carries the query's [`QueryTables`] (or none, for a plan-only
    /// statement).
    ///
    /// The physical planner is called directly: `SessionState::create_physical_plan`
    /// would optimize again, and the plan executed must be exactly the one the
    /// table needs were harvested from. Capture order is kept across
    /// partitions by [`merge_ordered_partitions`].
    async fn physical_plan(
        &self,
        state: &SessionState,
        optimized: &LogicalPlan,
    ) -> Result<Arc<dyn ExecutionPlan>, Error> {
        let plan = state
            .query_planner()
            .create_physical_plan(optimized, state)
            .await
            .map_err(|e| self.map_planning_error(e))?;
        if self.continuous.is_some() {
            // A join buffers one side of an unbounded stream for ever and
            // DataFusion does not refuse it. The joins a continuous query can
            // use are the ones the parser fuses (see `fusion`): the
            // `*_packets` views, and any tree of inner/left joins on
            // frame_number (and encap_depth) between protocol tables, below
            // the window.
            let mut join = None;
            let _ = plan.apply(|node| {
                if node.name().contains("Join") {
                    join = Some(node.name().to_string());
                    return Ok(TreeNodeRecursion::Stop);
                }
                Ok(TreeNodeRecursion::Continue)
            });
            if let Some(join) = join {
                return Err(Error::Query(QueryError::Execution(format!(
                    "continuous queries cannot run this join ({join}): it would buffer one \
                     side of the stream for ever. Joins the parser can fuse run: the \
                     `*_packets` views, and inner or left joins of protocol tables on \
                     frame_number (and encap_depth) placed below the window, as in \
                     tumble(tcp_packets, …). Not fusible: FULL joins (the `packets` view), \
                     other join conditions, and a join above the window"
                ))));
            }
        }
        Ok(merge_ordered_partitions(plan))
    }

    /// Run a physical plan to completion; the plan and the `TaskContext` are
    /// owned here, so nothing of the query's context outlives the call.
    async fn collect_plan(
        state: &SessionState,
        plan: Arc<dyn ExecutionPlan>,
    ) -> Result<Vec<RecordBatch>, Error> {
        datafusion::physical_plan::collect(plan, state.task_ctx())
            .await
            .map_err(|e| Error::Query(QueryError::from(e)))
    }

    /// DataFusion's sanity check rejects an operator that needs the whole of
    /// an unbounded input; in continuous mode say what is supported instead.
    fn map_planning_error(&self, e: datafusion::error::DataFusionError) -> Error {
        if self.continuous.is_some() {
            let text = e.to_string();
            if text.contains("pipeline breaking") {
                let what = if text.contains("SessionAssignExec") {
                    "session() windows need every packet of a key before any session is known, \
                     so they cannot run continuously; window with tumble() or hop()"
                } else if text.contains("JoinExec") {
                    "continuous queries cannot run this join: it would buffer one side of the \
                     stream for ever. Joins the parser can fuse run (the `*_packets` views, \
                     inner or left joins of protocol tables on frame_number below the window); \
                     FULL joins, other join conditions and a join above the window do not"
                } else {
                    "a continuous query aggregates over tumble() or hop() windows and nothing \
                     else: SELECT window_start, …, <aggregates> FROM tumble(frames, INTERVAL …) \
                     [WHERE <source columns>] GROUP BY window_start [, window_end, <columns>]. \
                     Sorts, limits, joins, DISTINCT, window functions and aggregates without \
                     GROUP BY window_start need the whole stream first"
                };
                // Name the operator DataFusion refused, not its Debug dump.
                let operator = text
                    .split("operator: ")
                    .nth(1)
                    .and_then(|rest| rest.split([' ', '{', '\n']).next())
                    .unwrap_or("the plan");
                return Error::Query(QueryError::Execution(format!(
                    "{what} (DataFusion refused {operator})"
                )));
            }
        }
        Error::Query(QueryError::from(e))
    }

    /// Prepare the tables a query needs into its own [`QueryTables`]: cache
    /// hits are snapshotted, the `count(*) FROM frames` fast path is answered
    /// from the boundary index, and whatever remains is parsed in one scoped
    /// pass — materialized (`CacheOnTouch`, which also fills the cache; or a
    /// query that needs two consumers of one table / a stream table) or
    /// streamed to the plan (`RetentionPolicy::None`).
    fn prepare(&self, mut needs: HashMap<String, TableNeeds>) -> Result<PreparedQuery, Error> {
        let mut tables = QueryTables::new();
        // Until something is parsed, whatever the query gets comes from the
        // cache (or the index, below).
        let mut stats = ParseStats {
            served_from: ServedFrom::Cache,
            ..Default::default()
        };

        // Stream-analysis tables (TCP reassembly → TLS → HTTP) are built by a
        // subscriber of the same packet pass, not by per-packet builders.
        // They are complete only at end of capture and need the whole capture
        // in order, so a query touching one takes the single-partition
        // materialize path. Cached ones are hits like any table.
        let mut stream_needed: HashSet<String> = HashSet::new();
        for name in needs.keys().filter(|t| tables::is_stream_table(t)) {
            match self.cache.get(name) {
                Some(data) => tables.insert_batches(name.clone(), data),
                None => {
                    stream_needed.insert(name.clone());
                }
            }
        }
        needs.retain(|t, _| !tables::is_stream_table(t));

        // Fast path: a pure `count(*) FROM frames` (frames only, no columns,
        // no filter, no limit, single scan) is answered from the boundary
        // index's frame count — a header-only scan (persisted in a sidecar),
        // no packet parse. Falls through to a normal parse when the count
        // isn't cheaply available (compressed/non-seekable) or frames is
        // cached (the cache serves it).
        let is_count_only_frames = needs.len() == 1
            && needs.get("frames").is_some_and(|n| {
                n.scan_count == 1
                    && n.filters.is_empty()
                    && n.fetch.is_none()
                    && matches!(&n.columns, Some(c) if c.is_empty())
            });
        if is_count_only_frames && !self.cache.contains("frames") {
            if let Some(n) = self.parse_source.frame_count() {
                let schema = Arc::new(arrow::datatypes::Schema::empty());
                let options =
                    arrow::array::RecordBatchOptions::new().with_row_count(Some(n as usize));
                let batch = RecordBatch::try_new_with_options(schema.clone(), vec![], &options)
                    .map_err(|e| Error::Query(QueryError::Arrow(e.to_string())))?;
                tables.insert_batches(
                    "frames".to_string(),
                    Arc::new(TableData {
                        schema,
                        partitions: vec![vec![batch]],
                    }),
                );
                needs.clear();
                stats.served_from = ServedFrom::Index;
                stats.partitions = 1;
                stats.complete_scan = true;
                stats.rows_built.insert("frames".to_string(), n as usize);
            }
        }

        // A table scanned twice in one plan (a self-join the parser did not
        // fuse, an IN-subquery on the same table) needs two consumers, but a
        // stream can be consumed once. Such queries take the materialize path
        // for this one query — still a single parse pass.
        let any_multi_scan = needs.values().any(|n| n.scan_count > 1);
        let (mut subscription, hits) = self.build_subscription(needs);
        for (name, data) in hits {
            tables.insert_batches(name, data);
        }
        subscription.stream_tables = stream_needed;

        // CacheOnTouch materializes (so the cache can serve any later query);
        // RetentionPolicy::None streams — producers hand batches to DataFusion
        // as they form, so memory stays flat while consumers keep pace — and
        // the producer stats are folded after execution. An empty
        // subscription means every referenced table is served from the cache
        // or the fast path — nothing to parse.
        let streaming = self.retention == RetentionPolicy::None
            && (!subscription.tables.is_empty() || !subscription.fused.is_empty())
            && subscription.stream_tables.is_empty()
            && !any_multi_scan;

        let mut producers: Vec<JoinHandle<Result<PartitionStat, Error>>> = Vec::new();
        if subscription.is_empty() {
            // Nothing to parse.
        } else if self.single_use && self.consumed.swap(true, Ordering::AcqRel) {
            // The one pass a stream affords has been started by an earlier
            // query (the source itself would refuse a second reader; this
            // says why before any producer is spawned).
            return Err(single_use_error("stdin was already consumed"));
        } else if streaming {
            let mut handle = self.parse_source.stream(&subscription)?;
            tables.insert_streams(&mut handle);
            producers = std::mem::take(&mut handle.producers);
            stats.served_from = ServedFrom::Parse;
            stats.parse_passes = 1;
            stats.partitions = handle.num_partitions;
        } else {
            let (parsed, pass) = self.parse_source.materialize(&subscription)?.into_tables();
            if pass.packets_scanned > 0 {
                self.time_range.record(pass.start_ts_us, pass.end_ts_us);
                // Timestamps are observed for every scanned packet, before
                // any predicate, so a complete scan fixes the whole range.
                if pass.complete_scan {
                    self.time_range.mark_complete();
                }
            }
            if self.retention == RetentionPolicy::CacheOnTouch {
                self.cache.install(parsed.clone());
            }
            for (name, data) in parsed {
                tables.insert_batches(name, data);
            }
            stats = pass;
        }

        Ok(PreparedQuery {
            tables: Arc::new(tables),
            producers,
            stats,
        })
    }

    /// Execute a plan on the shared context without preparing any table
    /// (DDL, session statements, EXPLAIN).
    async fn collect_on_context(&self, plan: LogicalPlan) -> Result<Vec<RecordBatch>, Error> {
        self.ctx
            .execute_logical_plan(plan)
            .await
            .map_err(|e| Error::Query(QueryError::from(e)))?
            .collect()
            .await
            .map_err(|e| Error::Query(QueryError::from(e)))
    }

    /// Build the parse subscription for a query, honoring the retention policy
    /// and the pushdown/retention matrix (`docs/query-scoped-parse-migration.md`).
    ///
    /// Also returns the cache entries that serve the query as they are (the
    /// hits), read once here so that a concurrent re-install cannot change
    /// what this query planned against.
    fn build_subscription(
        &self,
        needs: HashMap<String, TableNeeds>,
    ) -> (ParseSubscription, HashMap<String, Arc<TableData>>) {
        let mut subscription = ParseSubscription::default();
        let mut hits = HashMap::new();
        match self.retention {
            RetentionPolicy::CacheOnTouch => {
                // Column-aware cache: cache exactly the columns a query touches
                // (unfiltered, so reuse stays sound). A later query whose
                // columns are a subset is a cache hit; one needing more
                // columns re-parses the UNION and widens the entry. This keeps
                // heavy/rarely-queried columns (notably frames.raw_data) and
                // unused wide-table columns out of the cache until selected.
                for (name, table_needs) in needs {
                    let cached = self.cache.get(&name);
                    let cached_columns = cached.as_deref().map(providers::column_names);
                    let needed = &table_needs.columns;
                    if cache_covers(cached_columns.as_ref(), needed, &name) {
                        if let Some(data) = cached {
                            hits.insert(name, data); // subset already cached
                        }
                        continue;
                    }
                    // Subscribe the union of cached and needed columns so the
                    // rebuilt entry is a superset (no churn / loss).
                    let columns = column_union(cached_columns, needed);
                    subscription.tables.insert(
                        name,
                        TableSubscription {
                            columns,
                            predicate: None,
                            fetch: None,
                        },
                    );
                }
            }
            RetentionPolicy::None => {
                for (name, table_needs) in needs {
                    if let Some(spec) = table_needs.fused {
                        subscription.fused.insert(
                            name,
                            providers::FusedSubscription {
                                spec,
                                fetch: table_needs.fetch,
                            },
                        );
                        continue;
                    }
                    let multi_scan = table_needs.scan_count > 1;
                    let predicate = if multi_scan || name == "frames" {
                        None
                    } else {
                        FilterEvaluator::try_from_exprs(&table_needs.filters)
                    };
                    subscription.tables.insert(
                        name,
                        TableSubscription {
                            columns: if multi_scan {
                                None
                            } else {
                                table_needs.columns
                            },
                            predicate,
                            fetch: if multi_scan { None } else { table_needs.fetch },
                        },
                    );
                }
            }
        }
        (subscription, hits)
    }

    /// Instrumentation of the most recently *completed* query on this engine:
    /// parse passes (0 when fully served from cache, 1 otherwise — the
    /// shared-parse invariant), packets scanned, partitions, and rows built
    /// per table. A statement that never executed a scan (EXPLAIN, DDL)
    /// reports [`ServedFrom::PlanOnly`]. Exact for sequential use (the CLI, the REPL);
    /// with concurrent queries, use [`Self::execute`], which returns each
    /// query's own statistics.
    pub fn last_parse_stats(&self) -> ParseStats {
        self.last_stats.read().expect("stats lock poisoned").clone()
    }

    /// The retention policy this engine was opened with.
    pub fn retention(&self) -> RetentionPolicy {
        self.retention
    }

    /// The tables currently held by the [`RetentionPolicy::CacheOnTouch`]
    /// cache (name, columns, rows), sorted by name. Always empty under
    /// [`RetentionPolicy::None`].
    pub fn cached_tables(&self) -> Vec<CachedTable> {
        self.cache.summary()
    }

    /// Drop every cached table, so the next query over each table parses it
    /// again. Queries already running keep the data they were prepared with.
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Get the protocol registry.
    pub fn registry(&self) -> &ProtocolRegistry {
        self.registry.as_ref()
    }

    /// Get the session context for advanced usage.
    pub fn context(&self) -> &SessionContext {
        &self.ctx
    }

    /// Register cross-layer views that JOIN normalized protocol tables.
    ///
    /// This creates views like `tcp_packets`, `dns_packets`, and the backward-compatible
    /// `packets` view that JOINs all protocol tables together.
    async fn register_cross_layer_views(ctx: &SessionContext) -> Result<(), Error> {
        // Register all cross-layer views from the views module
        for view_def in views::all_views() {
            let sql = format!("CREATE VIEW {} AS {}", view_def.name, view_def.sql);
            ctx.sql(&sql).await.map_err(|e| {
                Error::Query(QueryError::Execution(format!(
                    "Failed to create view '{}': {}",
                    view_def.name, e
                )))
            })?;
        }

        Ok(())
    }
}
