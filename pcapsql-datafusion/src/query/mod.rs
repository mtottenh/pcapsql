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
pub use providers::{ProgressFn, ProtocolScanExec, ProtocolTableProvider, SharedParseState};

use std::path::PathBuf;
use std::sync::Arc;

use arrow::array::RecordBatch;
use datafusion::config::ConfigOptions;
use datafusion::prelude::*;

use crate::error::{Error, QueryError};
use crate::query::providers::run_shared_parse;
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

/// Configure DataFusion for SortMergeJoin on frame_number-sorted streams.
fn create_session_context() -> SessionContext {
    let mut config = ConfigOptions::default();

    // SortMergeJoin requires target_partitions > 1
    config.execution.target_partitions = 2;
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

/// Construction options for [`QueryEngine::open`].
#[derive(Clone)]
pub struct EngineOptions {
    /// Packets per RecordBatch.
    pub batch_size: usize,
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
    registry: ProtocolRegistry,
    /// Result of the single shared parse pass every table serves from.
    shared: Arc<SharedParseState>,
}

impl QueryEngine {
    /// Open a capture and build the engine.
    ///
    /// The single constructor: local files (memory-mapped by default, with a
    /// buffered-file fallback) and cloud URLs funnel into the same shared
    /// parse pass, parallel across partitions for seekable sources. With a
    /// [`EngineOptions::keylog`], an additional sequential stream pass
    /// populates the decrypted `http2` table (folded into the main pass by
    /// migration phase P4).
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

    /// Build the engine over an opened source: ONE parse pass, fanned out to
    /// all protocol tables, parallel across partitions.
    async fn build<S: SeekablePacketSource>(
        source: Arc<S>,
        opts: EngineOptions,
    ) -> Result<Self, Error> {
        let registry = Arc::new(default_registry());
        let ctx = create_session_context();
        udf::register_all_udfs(&ctx)?;

        let target_partitions = opts
            .target_partitions
            .unwrap_or_else(default_target_partitions);

        let shared = Arc::new(run_shared_parse(
            &source,
            &registry,
            opts.batch_size,
            target_partitions,
            opts.progress.clone(),
        )?);

        if shared.total_frames() == 0 {
            return Err(Error::Query(QueryError::Execution(
                "No packets found in PCAP source".to_string(),
            )));
        }

        // Timestamp range comes from the shared pass (no extra scan).
        let (start_us, end_us) = shared.timestamp_range_us();
        udf::register_time_udfs_eager(&ctx, start_us, end_us)?;

        // One provider per table, all sharing the single parse result.
        for table_name in tables::all_table_names() {
            let schema = Arc::new(tables::get_table_schema(table_name).ok_or_else(|| {
                Error::Query(QueryError::Execution(format!(
                    "Unknown table: {table_name}"
                )))
            })?);
            let provider = providers::ProtocolTableProvider::shared(
                table_name.to_string(),
                schema,
                shared.clone(),
            );
            ctx.register_table(table_name, Arc::new(provider))
                .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;
        }

        // With a keylog, a sequential stream pass (TCP reassembly + TLS
        // decryption + HTTP/2) replaces the empty http2 table. Migration
        // phase P4 folds this second pass into the shared one.
        if let Some(keylog) = opts.keylog.clone() {
            let mut stream_builder = stream_tables::StreamTableBuilder::new(Some(keylog));
            let mut reader = source.sequential_reader()?;
            stream_builder.process_reader(&mut reader)?;
            let http2_batches = stream_builder.http2_batches(opts.batch_size)?;
            if !http2_batches.is_empty() {
                let schema = http2_batches[0].schema();
                let provider = providers::ProtocolTableProvider::in_memory(
                    "http2".to_string(),
                    schema,
                    vec![http2_batches],
                );
                ctx.deregister_table("http2")
                    .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;
                ctx.register_table("http2", Arc::new(provider))
                    .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;
            }
        }

        Self::register_cross_layer_views(&ctx).await?;

        Ok(Self {
            ctx,
            registry: (*registry).clone(),
            shared,
        })
    }

    /// Execute a SQL query and return results.
    pub async fn query(&self, sql: &str) -> Result<Vec<RecordBatch>, Error> {
        let df = self
            .ctx
            .sql(sql)
            .await
            .map_err(|e| Error::Query(QueryError::from(e)))?;

        let batches = df
            .collect()
            .await
            .map_err(|e| Error::Query(QueryError::from(e)))?;

        Ok(batches)
    }

    /// Get the protocol registry.
    pub fn registry(&self) -> &ProtocolRegistry {
        &self.registry
    }

    /// Get the session context for advanced usage.
    pub fn context(&self) -> &SessionContext {
        &self.ctx
    }

    /// Number of parse passes performed over the source.
    ///
    /// Always `1` regardless of how many protocol tables a query touches —
    /// the instrumentation behind the shared-parse invariant.
    pub fn parse_pass_count(&self) -> usize {
        self.shared.parse_passes()
    }

    /// Number of partitions the shared parse pass used (1 if non-partitioned or
    /// in-memory mode).
    pub fn partition_count(&self) -> usize {
        self.shared.num_partitions()
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
