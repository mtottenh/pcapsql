//! SQL query engine module.
//!
//! This module provides DataFusion integration for querying packet data.
//!
//! ## Architecture
//!
//! The query module uses a normalized multi-table architecture:
//!
//! ### Normalized Schema (Phase 1)
//! Per-protocol tables (`frames`, `ethernet`, `ipv4`, `tcp`, `dns`, etc.)
//! with `frame_number` as the linking key. Cross-layer views provide
//! convenient access patterns (e.g., `tcp_packets` joins frames + ipv4 + tcp).
//!
//! The `packets` view provides backward compatibility with the old flat schema.
//!
//! ### Streaming Mode (Phase 2)
//! Streaming mode now uses the same normalized tables. Each protocol table
//! has its own streaming provider that reads the PCAP file independently.
//! JOINs work via sort-merge since all tables emit rows sorted by `frame_number`.
//!
//! See the `tables`, `views`, and `providers` submodules for details.

pub mod arrow_schema;
pub mod builders;
mod filter;
mod frames;
mod provider;
pub mod providers;
pub mod tables;
pub mod udf;
pub mod udtf;
pub mod views;

pub use arrow_schema::{descriptors_to_arrow_schema, protocol_to_arrow_schema, to_arrow_field};
pub use builders::NormalizedBatchSet;
pub use filter::FilterEvaluator;
pub use frames::{frames_schema, FramesBatchBuilder};
pub use provider::PcapTableProvider;
pub use providers::{ProtocolBatchStream, ProtocolStreamExec, ProtocolTableProvider};

use std::path::Path;
use std::sync::Arc;

use arrow::array::RecordBatch;
use datafusion::config::ConfigOptions;
use datafusion::prelude::*;
use indicatif::{ProgressBar, ProgressStyle};

use crate::error::{Error, QueryError};
use pcapsql_core::{
    default_registry, parse_packet, CacheStats, FilePacketSource, LruParseCache, MmapPacketSource,
    NoCache, PacketSource, ParseCache, PcapReader, ProtocolRegistry,
};

/// File size threshold for automatic streaming mode selection.
/// Files >= 100MB use streaming mode.
const STREAMING_THRESHOLD_BYTES: u64 = 100 * 1024 * 1024;

/// Default cache size for streaming mode (number of parsed packets to cache).
pub const DEFAULT_CACHE_SIZE: usize = 10_000;

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

/// Query engine for PCAP files.
pub struct QueryEngine {
    ctx: SessionContext,
    registry: ProtocolRegistry,
    /// Parse cache for streaming mode (if enabled)
    cache: Option<Arc<dyn ParseCache>>,
}

impl QueryEngine {
    /// Create a new query engine for a PCAP file.
    pub async fn new<P: AsRef<Path>>(path: P, batch_size: usize) -> Result<Self, Error> {
        Self::with_progress(path, batch_size, false).await
    }

    /// Create a new query engine for a PCAP file with optional progress bar.
    ///
    /// Uses the normalized schema with per-protocol tables.
    pub async fn with_progress<P: AsRef<Path>>(
        path: P,
        batch_size: usize,
        show_progress: bool,
    ) -> Result<Self, Error> {
        let registry = default_registry();
        let ctx = create_session_context();

        // Register all UDFs (network addresses, protocol names, utilities)
        udf::register_all_udfs(&ctx)?;

        // Load all packets into normalized per-protocol tables
        let protocol_batches =
            Self::load_normalized_packets(&path, &registry, batch_size, show_progress)?;

        // Check if we got any frames
        let frames_batches = protocol_batches
            .get("frames")
            .ok_or_else(|| Error::Query(QueryError::Execution("No frames table".to_string())))?;

        if frames_batches.is_empty() {
            return Err(Error::Query(QueryError::Execution(
                "No packets found in PCAP file".to_string(),
            )));
        }

        // Register all protocol tables
        for (table_name, batches) in &protocol_batches {
            if batches.is_empty() {
                // Register an empty table with the correct schema
                if let Some(schema) = tables::get_table_schema(table_name) {
                    let empty_provider =
                        provider::PcapTableProvider::new(Arc::new(schema), vec![]);
                    ctx.register_table(table_name.as_str(), Arc::new(empty_provider))
                        .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;
                }
            } else {
                let schema = batches[0].schema();
                let table_provider =
                    provider::PcapTableProvider::new(schema, batches.clone());
                ctx.register_table(table_name.as_str(), Arc::new(table_provider))
                    .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;
            }
        }

        // Register cross-layer views (including backward-compatible packets view)
        Self::register_cross_layer_views(&ctx).await?;

        // Register cache_stats() table function (returns default stats in in-memory mode)
        let stats_fn = udtf::CacheStatsFunction::new(|| None);
        ctx.register_udtf("cache_stats", Arc::new(stats_fn));

        Ok(Self {
            ctx,
            registry,
            cache: None,
        })
    }

    /// Create a QueryEngine in streaming mode for large files.
    ///
    /// In streaming mode, packets are read on-demand as DataFusion pulls batches,
    /// rather than loading the entire file into memory upfront. This allows
    /// querying very large PCAP files (10GB+) with bounded memory usage.
    ///
    /// Each protocol table gets its own streaming provider that reads
    /// the PCAP file independently. JOINs work via sort-merge since
    /// all tables emit rows sorted by frame_number.
    ///
    /// # Type Parameters
    ///
    /// This method is generic over the packet source, but defaults to
    /// `FilePacketSource`. Future backends (mmap, S3) can use
    /// `with_streaming_source()` directly.
    pub async fn with_streaming<P: AsRef<Path>>(
        path: P,
        batch_size: usize,
    ) -> Result<Self, Error> {
        let source = FilePacketSource::open(path)?;
        Self::with_streaming_source(Arc::new(source), batch_size).await
    }

    /// Create a QueryEngine with a custom packet source.
    ///
    /// This is the generic entry point that works with any `PacketSource`
    /// implementation (File, Mmap, S3, etc.).
    pub async fn with_streaming_source<S: PacketSource + 'static>(
        source: Arc<S>,
        batch_size: usize,
    ) -> Result<Self, Error> {
        Self::with_streaming_source_and_cache::<S, NoCache>(source, batch_size, None).await
    }

    /// Create a QueryEngine with streaming and parse cache.
    ///
    /// The cache reduces redundant parsing when multiple protocol readers
    /// traverse the same PCAP file (e.g., during JOIN queries).
    ///
    /// # Arguments
    ///
    /// * `source` - The packet source to read from
    /// * `batch_size` - Number of packets per RecordBatch
    /// * `cache_size` - Maximum number of parsed packets to cache (0 to disable)
    pub async fn with_streaming_source_cached<S: PacketSource + 'static>(
        source: Arc<S>,
        batch_size: usize,
        cache_size: usize,
    ) -> Result<Self, Error> {
        Self::with_streaming_source_cached_opts(source, batch_size, cache_size, true).await
    }

    /// Create a streaming QueryEngine with cache options.
    pub async fn with_streaming_source_cached_opts<S: PacketSource + 'static>(
        source: Arc<S>,
        batch_size: usize,
        cache_size: usize,
        reader_eviction: bool,
    ) -> Result<Self, Error> {
        if cache_size > 0 {
            let cache = Arc::new(LruParseCache::with_options(cache_size, reader_eviction));
            Self::with_streaming_source_and_cache(source, batch_size, Some(cache)).await
        } else {
            Self::with_streaming_source_and_cache::<S, NoCache>(source, batch_size, None).await
        }
    }

    /// Internal method: Create a streaming QueryEngine with optional cache.
    async fn with_streaming_source_and_cache<S: PacketSource + 'static, C: ParseCache + 'static>(
        source: Arc<S>,
        batch_size: usize,
        cache: Option<Arc<C>>,
    ) -> Result<Self, Error> {
        let registry = Arc::new(default_registry());
        let ctx = create_session_context();

        // Register all UDFs (network addresses, protocol names, utilities)
        udf::register_all_udfs(&ctx)?;

        // Convert cache to trait object if present
        let cache_dyn: Option<Arc<dyn ParseCache>> = cache.map(|c| c as Arc<dyn ParseCache>);

        // Register streaming provider for each protocol table
        for table_name in tables::all_table_names() {
            let schema = Arc::new(
                tables::get_table_schema(table_name).ok_or_else(|| {
                    Error::Query(QueryError::Execution(format!(
                        "Unknown table: {}",
                        table_name
                    )))
                })?,
            );

            let provider = if let Some(ref cache) = cache_dyn {
                providers::ProtocolTableProvider::<S>::streaming_cached(
                    table_name.to_string(),
                    schema,
                    source.clone(),
                    registry.clone(),
                    batch_size,
                    cache.clone(),
                )
            } else {
                providers::ProtocolTableProvider::<S>::streaming(
                    table_name.to_string(),
                    schema,
                    source.clone(),
                    registry.clone(),
                    batch_size,
                )
            };

            ctx.register_table(table_name, Arc::new(provider))
                .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;
        }

        // Register cross-layer views (including backward-compatible packets view)
        Self::register_cross_layer_views(&ctx).await?;

        // Register cache_stats() table function
        let cache_for_udtf = cache_dyn.clone();
        let stats_fn = udtf::CacheStatsFunction::new(move || {
            cache_for_udtf.as_ref().and_then(|c| c.stats())
        });
        ctx.register_udtf("cache_stats", Arc::new(stats_fn));

        Ok(Self {
            ctx,
            registry: (*registry).clone(),
            cache: cache_dyn,
        })
    }

    /// Create a QueryEngine with automatic mode selection.
    ///
    /// Mode is selected based on file size:
    /// - Files < 100MB: In-memory mode (fastest for small files)
    /// - Files >= 100MB: Streaming mode with cache (bounded memory)
    ///
    /// Use `new()` or `with_streaming()` to force a specific mode.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the PCAP file
    /// * `batch_size` - Number of packets per RecordBatch
    /// * `cache_size` - Cache size for streaming mode (0 to disable)
    /// * `use_mmap` - Use memory-mapped I/O for large files
    pub async fn auto<P: AsRef<Path>>(
        path: P,
        batch_size: usize,
        cache_size: usize,
        use_mmap: bool,
    ) -> Result<Self, Error> {
        let file_size = std::fs::metadata(path.as_ref())
            .map(|m| m.len())
            .unwrap_or(0);

        if file_size >= STREAMING_THRESHOLD_BYTES {
            // Large file: use streaming mode
            if use_mmap {
                match MmapPacketSource::open(&path) {
                    Ok(source) => {
                        return Self::with_streaming_source_cached(
                            Arc::new(source),
                            batch_size,
                            cache_size,
                        )
                        .await;
                    }
                    Err(_) => {
                        // Fall back to file source if mmap fails (e.g., PCAPNG)
                    }
                }
            }

            let source = Arc::new(FilePacketSource::open(&path)?);
            Self::with_streaming_source_cached(source, batch_size, cache_size).await
        } else {
            // Small file: use in-memory mode
            Self::with_progress(path, batch_size, false).await
        }
    }

    /// Load packets from a PCAP file into normalized per-protocol Arrow batches.
    ///
    /// Returns a HashMap mapping table names to vectors of RecordBatches.
    /// Uses zero-copy processing via `process_packets()` callback API.
    fn load_normalized_packets<P: AsRef<Path>>(
        path: P,
        registry: &ProtocolRegistry,
        batch_size: usize,
        show_progress: bool,
    ) -> Result<builders::ProtocolBatches, Error> {
        let mut reader = PcapReader::open(path)?;
        let link_type = reader.link_type();

        let mut batch_set = builders::NormalizedBatchSet::new(batch_size);

        // Create progress bar if requested
        let progress = if show_progress {
            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::with_template(
                    "{spinner:.green} [{elapsed_precise}] {msg} ({per_sec})",
                )
                .unwrap()
                .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ "),
            );
            pb.set_message("Loading packets...");
            Some(pb)
        } else {
            None
        };

        let mut packet_count = 0u64;

        // Process packets in batches using zero-copy callback API
        loop {
            let processed = reader.process_packets(1000, |packet| {
                // Parse the packet through all protocol layers
                let parsed = parse_packet(registry, link_type, packet.data);

                // Add to normalized batch set (routes to appropriate protocol tables)
                batch_set.add_packet_from_ref(packet, &parsed)?;

                packet_count += 1;
                Ok(())
            })?;

            // Update progress bar
            if let Some(ref pb) = progress {
                pb.set_message(format!("{} packets loaded", packet_count));
                pb.tick();
            }

            // Check for EOF
            if processed == 0 {
                break;
            }
        }

        // Finish progress bar
        if let Some(pb) = progress {
            pb.finish_with_message(format!("{} packets loaded", packet_count));
        }

        // Finish and return all batches
        batch_set.finish()
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

    /// Get current cache statistics, if caching is enabled.
    ///
    /// Returns `None` if cache is disabled or in non-streaming mode.
    pub fn cache_stats(&self) -> Option<CacheStats> {
        self.cache.as_ref().and_then(|c| c.stats())
    }

    /// Get a reference to the parse cache, if enabled.
    ///
    /// This can be used to reset statistics or access advanced cache features.
    pub fn cache(&self) -> Option<&Arc<dyn ParseCache>> {
        self.cache.as_ref()
    }

    /// Register cross-layer views that JOIN normalized protocol tables.
    ///
    /// This creates views like `tcp_packets`, `dns_packets`, and the backward-compatible
    /// `packets` view that JOINs all protocol tables together.
    async fn register_cross_layer_views(ctx: &SessionContext) -> Result<(), Error> {
        // Register all cross-layer views from the views module
        for view_def in views::all_views() {
            let sql = format!("CREATE VIEW {} AS {}", view_def.name, view_def.sql);
            ctx.sql(&sql)
                .await
                .map_err(|e| {
                    Error::Query(QueryError::Execution(format!(
                        "Failed to create view '{}': {}",
                        view_def.name, e
                    )))
                })?;
        }

        Ok(())
    }
}
