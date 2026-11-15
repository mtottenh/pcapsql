//! The query engine.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use arrow::array::RecordBatch;
use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
use datafusion::execution::session_state::SessionState;
use datafusion::logical_expr::LogicalPlan;
use datafusion::physical_plan::ExecutionPlan;
use datafusion::prelude::*;
use tokio::task::JoinHandle;

use super::options::{EngineOptions, RetentionPolicy, SourceSpec};
use super::planning::{
    cache_covers, classify_statement, column_union, fold_producers, harvest_table_needs,
    uses_time_range_udfs, Planned, PlannedQuery, PreparedQuery, StatementKind, TableNeeds,
};
use super::query_stream::QueryStream;
use super::session::{
    create_session_context, default_target_partitions, session_target_partitions,
};
use super::source::{single_use_error, ParseSource, SequentialParser, SourceParser};
use super::{providers, streaming, tables, udf, views, windowing};
use crate::error::{Error, QueryError};
use crate::query::filter::row_predicate;
use crate::query::providers::{
    auto_target_partitions, merge_ordered_partitions, CachedTable, ParseStats, ParseSubscription,
    PartitionStat, PassOptions, QueryTables, ServedFrom, TableCache, TableData, TableSubscription,
};
use crate::query::udf::CaptureTimeRange;
#[cfg(feature = "cloud")]
use pcapsql_core::io::{CloudLocation, CloudPacketSource};
use pcapsql_core::{
    default_registry, FilePacketSource, MmapPacketSource, PacketSource, ProtocolRegistry,
    SeekablePacketSource, StdinPacketSource,
};

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
            options: PassOptions {
                batch_size: opts.batch_size,
                target_partitions: parallelism,
                progress: opts.progress.clone(),
                keylog: opts.keylog.clone(),
                flush_interval: None,
            },
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
            options: PassOptions {
                batch_size: opts.batch_size,
                target_partitions: 1,
                progress: opts.progress.clone(),
                keylog: opts.keylog.clone(),
                flush_interval: opts.continuous.then_some(opts.flush_interval),
            },
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
        subscription.subscribe_table(
            "frames",
            TableSubscription {
                columns: Some(["timestamp".to_string()].into_iter().collect()),
                predicate: None,
                fetch: None,
            },
        )?;
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

        // Stream-analysis tables (TCP reassembly → TLS → HTTP) are built by
        // the scan of the same packet pass when the capture ends, not packet
        // by packet.
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
        let (mut subscription, hits) = self.build_subscription(needs)?;
        for (name, data) in hits {
            tables.insert_batches(name, data);
        }
        for name in &stream_needed {
            subscription.subscribe_stream_table(name)?;
        }

        // CacheOnTouch materializes (so the cache can serve any later query);
        // RetentionPolicy::None streams — producers hand batches to DataFusion
        // as they form, so memory stays flat while consumers keep pace — and
        // the producer stats are folded after execution. An empty
        // subscription means every referenced table is served from the cache
        // or the fast path — nothing to parse.
        let streaming = self.retention == RetentionPolicy::None
            && subscription.has_packet_tables()
            && !subscription.has_stream_tables()
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
    ) -> Result<(ParseSubscription, HashMap<String, Arc<TableData>>), Error> {
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
                    subscription.subscribe_table(
                        &name,
                        TableSubscription {
                            columns,
                            predicate: None,
                            fetch: None,
                        },
                    )?;
                }
            }
            RetentionPolicy::None => {
                for (name, table_needs) in needs {
                    if let Some(spec) = table_needs.fused {
                        subscription.subscribe_fused(providers::FusedSubscription {
                            spec,
                            fetch: table_needs.fetch,
                        })?;
                        continue;
                    }
                    let multi_scan = table_needs.scan_count > 1;
                    let predicate = if multi_scan || name == "frames" {
                        None
                    } else {
                        pcapsql_core::scan::Catalog::builtin()
                            .table(&name)
                            .and_then(|(_, table)| row_predicate(&table_needs.filters, table))
                    };
                    subscription.subscribe_table(
                        &name,
                        TableSubscription {
                            columns: if multi_scan {
                                None
                            } else {
                                table_needs.columns
                            },
                            predicate,
                            fetch: if multi_scan { None } else { table_needs.fetch },
                        },
                    )?;
                }
            }
        }
        Ok((subscription, hits))
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
