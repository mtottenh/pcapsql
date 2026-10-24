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
//! default) and cloud URLs funnel into one shared parse pass, parallel across
//! partitions for seekable sources, fanned out to every protocol table. JOINs
//! use sort-merge since all tables emit rows sorted by `frame_number`.
//!
//! The migration plan in `docs/query-scoped-parse-migration.md` moves this
//! parse from engine construction to query time, scoped to each query.
//!
//! See the `tables`, `views`, and `providers` submodules for details.

pub mod arrow_schema;
pub mod bpf;
pub mod builders;
mod filter;
pub mod providers;
pub mod stream_tables;
pub mod tables;
pub mod udf;
pub mod views;

pub use arrow_schema::{descriptors_to_arrow_schema, protocol_to_arrow_schema, to_arrow_field};
pub use builders::NormalizedBatchSet;
pub use filter::FilterEvaluator;
pub use providers::{
    auto_target_partitions, merge_ordered_partitions, ParseStats, ParseSubscription, ProgressFn,
    ProtocolScanExec, ProtocolTableProvider, ServedFrom, TableSubscription,
};
pub use udf::CaptureTimeRange;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use arrow::array::RecordBatch;
use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
use datafusion::config::ConfigOptions;
use datafusion::execution::session_state::SessionState;
use datafusion::logical_expr::{DdlStatement, Expr, LogicalPlan, Statement};
use datafusion::prelude::*;
use tokio::task::JoinHandle;

use crate::error::{Error, QueryError};
use crate::query::providers::{
    run_shared_parse, CachedTable, PartitionStat, QueryTables, SharedParseState, StreamingHandle,
    TableCache, TableData,
};
use pcapsql_core::{
    default_registry, FilePacketSource, KeyLog, MmapPacketSource, ProtocolRegistry,
    SeekablePacketSource,
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

/// Configure DataFusion for SortMergeJoin on frame_number-sorted streams.
///
/// `parallelism` is the engine's parse parallelism; each query re-targets its
/// own session state to the partition count it actually has (see
/// [`session_target_partitions`]).
fn create_session_context(parallelism: usize) -> SessionContext {
    let mut config = ConfigOptions::default();

    config.execution.target_partitions = session_target_partitions(1, parallelism);
    // Use our declared sort order (by frame_number)
    config.optimizer.prefer_existing_sort = true;
    // Prefer SortMergeJoin - works better with our sorted streams
    config.optimizer.prefer_hash_join = false;
    config.optimizer.repartition_joins = true;

    SessionContext::new_with_config(config.into())
}

/// Where to read a capture from.
#[derive(Clone, Debug)]
pub enum SourceSpec {
    /// Local file path (pcap/pcapng, optionally compressed).
    Path(PathBuf),
    /// Cloud object URL (`s3://…`, `gs://…`, `az://…`); needs the `cloud` feature.
    Url(String),
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
    /// Instrumentation for the most recent query.
    last_stats: RwLock<ParseStats>,
    /// Table names this engine registered (the harvest universe).
    known_tables: HashSet<String>,
    /// Parse parallelism (the partition count asked of a seekable source);
    /// also the execution width of a query over one-partition tables.
    parallelism: usize,
    /// Serializes the one-time capture time-range bootstrap
    /// ([`Self::ensure_time_range`]) between concurrent first queries.
    time_range_lock: tokio::sync::Mutex<()>,
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
    /// buffered-file fallback) and cloud URLs are served by the same scoped
    /// parse machinery. **No parsing happens here** — each query parses
    /// exactly the tables (and columns/predicates/limits) it references, per
    /// the engine's [`RetentionPolicy`].
    pub async fn open(spec: SourceSpec, opts: EngineOptions) -> Result<Self, Error> {
        match spec {
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

    /// Build the engine over an opened source: register providers, UDFs and
    /// views, and capture the scoped-parse closure queries will drive.
    async fn build<S: SeekablePacketSource>(
        source: Arc<S>,
        opts: EngineOptions,
    ) -> Result<Self, Error> {
        let registry = Arc::new(default_registry());
        // An explicit count is honoured; otherwise small mmap files stay in
        // one partition (see `auto_target_partitions`).
        let parallelism = opts.target_partitions.unwrap_or_else(|| {
            auto_target_partitions(source.as_ref(), default_target_partitions())
        });
        let ctx = create_session_context(parallelism);
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
                providers::ProtocolTableProvider::new(table_name.to_string(), schema, parallelism);
            ctx.register_table(table_name, Arc::new(provider))
                .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;
            known_tables.insert(table_name.to_string());
        }

        Self::register_cross_layer_views(&ctx).await?;

        let parse_source: Arc<dyn ParseSource> = Arc::new(SourceParser {
            source,
            registry: registry.clone(),
            batch_size: opts.batch_size,
            partitions: parallelism,
            progress: opts.progress.clone(),
            keylog: opts.keylog.clone(),
        });

        Ok(Self {
            ctx,
            registry,
            cache,
            time_range,
            retention: opts.retention,
            parse_source,
            last_stats: RwLock::new(ParseStats::default()),
            known_tables,
            parallelism,
            time_range_lock: tokio::sync::Mutex::new(()),
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
        // A per-query copy of the shared session state: the query's prepared
        // tables ride on its config as an extension.
        let mut state = self.ctx.state();
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
            return Ok(QueryOutput { batches, stats });
        }
        // The time UDFs are `Stable`, so the optimizer constant-folds
        // `start_time()` / `end_time()` *during* `optimize`: the range must be
        // complete before that, hence the check on the unoptimized plan.
        // (Also for EXPLAIN, so the displayed constant is the real one; the
        // range comes from the boundary index without a packet parse.)
        let bootstrap = if uses_time_range_udfs(&plan) {
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
            // execution.
            let batches = Self::execute_plan(&state, &optimized).await?;
            // The only parse a plan-only statement can trigger is the
            // time-range bootstrap; report it rather than claim zero.
            let stats = ParseStats {
                served_from: ServedFrom::PlanOnly,
                ..bootstrap
            };
            *self.last_stats.write().expect("stats lock poisoned") = stats.clone();
            return Ok(QueryOutput { batches, stats });
        }

        let needs = harvest_table_needs(&optimized, &self.known_tables)?;
        let PreparedQuery {
            tables: prepared,
            producers,
            mut stats,
        } = self.prepare(needs)?;

        // Plan for the partition count this query actually has: the boundary
        // index may yield fewer partitions than the engine's parallelism, and a
        // scan with fewer partitions than `target_partitions` would be
        // round-robin repartitioned in a way that loses capture order (#122;
        // see `session_target_partitions`).
        state.config_mut().options_mut().execution.target_partitions =
            session_target_partitions(prepared.partitions(), self.parallelism);
        // Hand this query's tables to its providers and execute. The result
        // is captured, not returned early: the producers below must always be
        // joined (fail closed on a parse error).
        state.config_mut().set_extension(prepared.clone());
        let result = Self::execute_plan(&state, &optimized).await;

        // Every holder of the query's tables goes away before the producers
        // are joined: the physical plan and the TaskContext were owned by
        // `execute_plan`; `state` carries the extension on its config;
        // `prepared` is ours. Receivers of partitions the plan never executed
        // (a LIMIT satisfied early) drop here, so a producer waiting on them
        // sees its consumers gone rather than waiting forever. Dropping this
        // future anywhere above has the same effect.
        drop(state);
        drop(prepared);

        // Streaming: collect() drove the producers to completion. Await them
        // to fold statistics and surface any parse error (fail closed).
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
                                *stats.overflowed_bytes.entry(t.clone()).or_insert(0) +=
                                    o.total_bytes;
                                *stats.overflow_peak_bytes.entry(t).or_insert(0) += o.peak_bytes;
                            }
                        }
                    }
                    Ok(Err(e)) => producer_error = producer_error.or(Some(e)),
                    Err(join_err) => {
                        producer_error = producer_error.or(Some(Error::Query(
                            QueryError::Execution(format!("parse producer panicked: {join_err}")),
                        )))
                    }
                }
            }
            if start != i64::MAX {
                stats.start_ts_us = start;
                stats.end_ts_us = end;
                self.time_range.record(start, end);
                if stats.complete_scan {
                    self.time_range.mark_complete();
                }
            }
        }

        // A time-range bootstrap pass (source without a boundary index) is
        // part of what this query cost; fold it in rather than hide it.
        stats.parse_passes += bootstrap.parse_passes;
        stats.packets_scanned += bootstrap.packets_scanned;

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

    /// Plan an already optimized logical plan and run it to completion on
    /// `state`, whose config carries the query's [`QueryTables`] (or none,
    /// for a plan-only statement).
    ///
    /// The physical planner is called directly: `SessionState::create_physical_plan`
    /// would optimize again, and the plan executed must be exactly the one the
    /// table needs were harvested from. The physical plan and the
    /// `TaskContext` are owned here, so nothing of the query's context
    /// outlives the call.
    async fn execute_plan(
        state: &SessionState,
        optimized: &LogicalPlan,
    ) -> Result<Vec<RecordBatch>, Error> {
        let plan = state
            .query_planner()
            .create_physical_plan(optimized, state)
            .await
            .map_err(|e| Error::Query(QueryError::from(e)))?;
        // Keep capture order for un-ORDERed queries over a partitioned parse.
        let plan = merge_ordered_partitions(plan);
        datafusion::physical_plan::collect(plan, state.task_ctx())
            .await
            .map_err(|e| Error::Query(QueryError::from(e)))
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

        // A table scanned twice in one plan (self-join, IN-subquery on the same
        // table, a view joined with one of its members) needs two consumers,
        // but a stream can be consumed once. Such queries take the materialize
        // path for this one query — still a single parse pass.
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
            && !subscription.tables.is_empty()
            && subscription.stream_tables.is_empty()
            && !any_multi_scan;

        let mut producers: Vec<JoinHandle<Result<PartitionStat, Error>>> = Vec::new();
        if subscription.is_empty() {
            // Nothing to parse.
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
