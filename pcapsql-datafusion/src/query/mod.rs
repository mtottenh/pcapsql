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
    ParseStats, ParseSubscription, ProgressFn, ProtocolScanExec, ProtocolTableProvider,
    TableSubscription,
};
pub use udf::CaptureTimeRange;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use arrow::array::RecordBatch;
use datafusion::common::tree_node::TreeNodeRecursion;
use datafusion::config::ConfigOptions;
use datafusion::logical_expr::{Expr, LogicalPlan};
use datafusion::prelude::*;
use tokio::task::JoinHandle;

use crate::error::{Error, QueryError};
use crate::query::providers::{
    run_shared_parse, EngineTables, PartitionStat, SharedParseState, StreamingHandle, TableData,
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

/// Tables produced by the stream-analysis pass (TCP reassembly / TLS
/// decryption / HTTP-2) rather than the per-packet parse. They are built
/// on demand by a single sequential read when a query references them.
const STREAM_TABLES: &[&str] = &["http2"];

/// Configure DataFusion for SortMergeJoin on frame_number-sorted streams.
fn create_session_context(target_partitions: usize) -> SessionContext {
    let mut config = ConfigOptions::default();

    // SortMergeJoin requires target_partitions > 1; otherwise scale with the
    // parse parallelism so execution is not throttled below it.
    config.execution.target_partitions = target_partitions.max(2);
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
    /// Cache each touched table (full columns, unfiltered) on first use, so
    /// later queries over the same tables parse nothing. The right policy
    /// for the REPL. Caching full columns keeps reuse sound for any later
    /// query shape.
    CacheOnTouch,
}

/// Construction options for [`QueryEngine::open`].
#[derive(Clone)]
pub struct EngineOptions {
    /// Packets per RecordBatch.
    pub batch_size: usize,
    /// What to retain between queries (see [`RetentionPolicy`]).
    pub retention: RetentionPolicy,
    /// Partition count for the parallel parse pass
    /// (`None` = available parallelism, clamped to 1..=16).
    pub target_partitions: Option<usize>,
    /// TLS keylog enabling the decrypted `http2` table.
    pub keylog: Option<Arc<KeyLog>>,
    /// Memory-map local files; falls back to buffered file I/O when mmap
    /// fails (e.g. compressed captures).
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

/// Query engine for PCAP files.
pub struct QueryEngine {
    ctx: SessionContext,
    registry: Arc<ProtocolRegistry>,
    /// Tables materialized for the current query (or cached, per retention).
    tables: Arc<EngineTables>,
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
}

/// Type-erased scoped parse over the engine's source: either materialize the
/// subscribed tables (cache-fill) or stream them (bounded memory).
trait ParseSource: Send + Sync {
    fn materialize(&self, sub: &ParseSubscription) -> Result<SharedParseState, Error>;
    fn stream(&self, sub: &ParseSubscription) -> Result<StreamingHandle, Error>;
    /// Run the stream-analysis pass (one sequential read, single partition):
    /// TCP reassembly + TLS decryption + HTTP/2, producing the [`STREAM_TABLES`].
    fn stream_pass(&self) -> Result<HashMap<String, TableData>, Error>;
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
    /// TLS keylog enabling decrypted HTTP/2 in the stream pass.
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
        )
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

    fn stream_pass(&self) -> Result<HashMap<String, TableData>, Error> {
        // Stream reassembly needs whole-capture sequential order, so this is
        // always a single sequential read (single partition).
        let mut builder = stream_tables::StreamTableBuilder::new(self.keylog.clone());
        let mut reader = self.source.sequential_reader()?;
        builder.process_reader(&mut reader)?;

        let mut out = HashMap::new();
        let http2 = builder.http2_batches(self.batch_size)?;
        let schema = http2
            .first()
            .map(|b| b.schema())
            .unwrap_or_else(|| Arc::new(tables::get_table_schema("http2").expect("http2 schema")));
        out.insert(
            "http2".to_string(),
            TableData {
                schema,
                partitions: vec![http2],
            },
        );
        Ok(out)
    }
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
        let parallelism = opts
            .target_partitions
            .unwrap_or_else(default_target_partitions);
        let ctx = create_session_context(parallelism);
        udf::register_all_udfs(&ctx)?;

        // Time UDFs read a shared range that parse passes widen.
        let time_range = Arc::new(CaptureTimeRange::new());
        udf::register_time_udfs(&ctx, time_range.clone())?;

        // One provider per table, all serving from the same engine state.
        let engine_tables = Arc::new(EngineTables::new());
        let mut known_tables = HashSet::new();
        for table_name in tables::all_table_names() {
            let schema = Arc::new(tables::get_table_schema(table_name).ok_or_else(|| {
                Error::Query(QueryError::Execution(format!(
                    "Unknown table: {table_name}"
                )))
            })?);
            let provider = providers::ProtocolTableProvider::new(
                table_name.to_string(),
                schema,
                engine_tables.clone(),
            );
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
            tables: engine_tables,
            time_range,
            retention: opts.retention,
            parse_source,
            last_stats: RwLock::new(ParseStats::default()),
            known_tables,
        })
    }

    /// Execute a SQL query and return results.
    ///
    /// Plans first, harvests the optimized plan's table needs, runs one
    /// scoped parse pass covering them (subject to the retention policy's
    /// cache), then executes. This is THE query path: queries issued
    /// directly against [`Self::context`] bypass the parse and will fail
    /// with "table was not prepared".
    pub async fn query(&self, sql: &str) -> Result<Vec<RecordBatch>, Error> {
        let state = self.ctx.state();
        let plan = state
            .create_logical_plan(sql)
            .await
            .map_err(|e| Error::Query(QueryError::from(e)))?;
        let optimized = state
            .optimize(&plan)
            .map_err(|e| Error::Query(QueryError::from(e)))?;

        let mut needs = harvest_table_needs(&optimized, &self.known_tables)?;

        // Stream-analysis tables are produced by the on-demand stream pass,
        // not the per-packet parse. Split them out and run the pass once if a
        // referenced stream table isn't already prepared (cached). A query
        // mixing stream and packet tables runs both passes.
        let stream_needed: Vec<String> = needs
            .keys()
            .filter(|t| STREAM_TABLES.contains(&t.as_str()))
            .cloned()
            .collect();
        for t in &stream_needed {
            needs.remove(t);
        }
        let mut stream_rows: HashMap<String, usize> = HashMap::new();
        let mut stream_passes = 0usize;
        if stream_needed.iter().any(|t| !self.tables.contains(t)) {
            let produced = self.parse_source.stream_pass()?;
            let installed: HashMap<String, Arc<TableData>> = produced
                .into_iter()
                .map(|(name, data)| {
                    stream_rows.insert(name.clone(), data.total_rows());
                    (name, Arc::new(data))
                })
                .collect();
            self.tables.install(installed);
            stream_passes = 1;
        }

        // Fast path: a pure `count(*) FROM frames` (frames only, no columns,
        // no filter, no limit, single scan) is answered from the boundary
        // index's frame count — a header-only scan (persisted in a sidecar),
        // no packet parse. Falls through to a normal parse when the count
        // isn't cheaply available (compressed/non-seekable) or frames is
        // already prepared.
        let mut fast_frame_count: Option<u64> = None;
        let is_count_only_frames = needs.len() == 1
            && needs.get("frames").is_some_and(|n| {
                n.scan_count == 1
                    && n.filters.is_empty()
                    && n.fetch.is_none()
                    && matches!(&n.columns, Some(c) if c.is_empty())
            });
        if is_count_only_frames && !self.tables.contains("frames") {
            if let Some(n) = self.parse_source.frame_count() {
                let schema = std::sync::Arc::new(arrow::datatypes::Schema::empty());
                let options =
                    arrow::array::RecordBatchOptions::new().with_row_count(Some(n as usize));
                let batch = RecordBatch::try_new_with_options(schema.clone(), vec![], &options)
                    .map_err(|e| Error::Query(QueryError::Arrow(e.to_string())))?;
                let mut tables = HashMap::new();
                tables.insert(
                    "frames".to_string(),
                    std::sync::Arc::new(TableData {
                        schema,
                        partitions: vec![vec![batch]],
                    }),
                );
                self.tables.install(tables);
                needs.clear();
                fast_frame_count = Some(n);
            }
        }

        let subscription = self.build_subscription(needs);

        // CacheOnTouch materializes (so the cache can serve any later query);
        // RetentionPolicy::None streams (bounded memory) and we fold the
        // producer stats after execution. An empty subscription means every
        // referenced table is already cached/pinned — nothing to parse.
        let streaming = self.retention == RetentionPolicy::None && !subscription.tables.is_empty();

        let mut producers: Vec<JoinHandle<Result<PartitionStat, Error>>> = Vec::new();
        if subscription.tables.is_empty() {
            let mut stats = ParseStats::default();
            if let Some(n) = fast_frame_count {
                stats.partitions = 1;
                stats.complete_scan = true;
                stats.rows_built.insert("frames".to_string(), n as usize);
            }
            *self.last_stats.write().expect("stats lock poisoned") = stats;
        } else if streaming {
            let mut handle = self.parse_source.stream(&subscription)?;
            self.tables.install_streams(&mut handle);
            producers = std::mem::take(&mut handle.producers);
            *self.last_stats.write().expect("stats lock poisoned") = ParseStats {
                parse_passes: 1,
                partitions: handle.num_partitions,
                ..Default::default()
            };
        } else {
            let (tables, stats) = self.parse_source.materialize(&subscription)?.into_tables();
            if stats.packets_scanned > 0 {
                self.time_range.record(stats.start_ts_us, stats.end_ts_us);
            }
            self.tables.install(tables);
            *self.last_stats.write().expect("stats lock poisoned") = stats;
        }

        let result = async {
            let df = self
                .ctx
                .execute_logical_plan(optimized)
                .await
                .map_err(|e| Error::Query(QueryError::from(e)))?;
            df.collect()
                .await
                .map_err(|e| Error::Query(QueryError::from(e)))
        }
        .await;

        // Streaming: collect() drove the producers to completion. Await them
        // to fold statistics and surface any parse error (fail closed).
        let mut producer_error = None;
        if !producers.is_empty() {
            let outcomes = futures::future::join_all(producers).await;
            let mut stats = ParseStats {
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
            }
            *self.last_stats.write().expect("stats lock poisoned") = stats;
        }

        // Fold the stream pass into the reported statistics.
        if stream_passes > 0 {
            let mut stats = self.last_stats.write().expect("stats lock poisoned");
            stats.parse_passes += stream_passes;
            for (t, n) in stream_rows {
                stats.rows_built.insert(t, n);
            }
        }

        if self.retention == RetentionPolicy::None {
            self.tables.clear();
        }

        match producer_error {
            Some(e) => Err(e),
            None => result,
        }
    }

    /// Build the parse subscription for a query, honoring the retention policy
    /// and the pushdown/retention matrix (`docs/query-scoped-parse-migration.md`).
    fn build_subscription(&self, needs: HashMap<String, TableNeeds>) -> ParseSubscription {
        let mut subscription = ParseSubscription::default();
        match self.retention {
            RetentionPolicy::CacheOnTouch => {
                // Column-aware cache: cache exactly the columns a query touches
                // (unfiltered, so reuse stays sound). A later query whose
                // columns are a subset is a cache hit; one needing more
                // columns re-parses the UNION and widens the entry. This keeps
                // heavy/rarely-queried columns (notably frames.raw_data) and
                // unused wide-table columns out of the cache until selected.
                for (name, table_needs) in needs {
                    let cached = self.tables.cached_columns(&name);
                    let needed = &table_needs.columns;
                    if cache_covers(cached.as_ref(), needed, &name) {
                        continue; // subset already cached
                    }
                    // Subscribe the union of cached and needed columns so the
                    // rebuilt entry is a superset (no churn / loss).
                    let columns = column_union(cached, needed);
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
                    if self.tables.contains(&name) {
                        continue; // pinned (e.g. keylog http2)
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
        subscription
    }

    /// Instrumentation for the most recent query: parse passes (0 when fully
    /// served from cache, 1 otherwise — the shared-parse invariant), packets
    /// scanned, partitions, and rows built per table.
    pub fn last_parse_stats(&self) -> ParseStats {
        self.last_stats.read().expect("stats lock poisoned").clone()
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
