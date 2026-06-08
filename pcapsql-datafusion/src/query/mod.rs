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
pub mod bpf;
pub mod builders;
mod filter;
mod frames;
mod provider;
pub mod providers;
pub mod stream_tables;
pub mod tables;
pub mod udf;
pub mod views;

pub use arrow_schema::{descriptors_to_arrow_schema, protocol_to_arrow_schema, to_arrow_field};
pub use builders::NormalizedBatchSet;
pub use filter::FilterEvaluator;
pub use frames::{frames_schema, FramesBatchBuilder};
pub use provider::PcapTableProvider;
pub use providers::{ProtocolScanExec, ProtocolTableProvider, SharedParseState};

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use arrow::array::{Array, RecordBatch, TimestampMicrosecondArray};
use datafusion::config::ConfigOptions;
use datafusion::prelude::*;
use indicatif::{ProgressBar, ProgressStyle};

use crate::error::{Error, QueryError};
use crate::query::providers::run_shared_parse;
use pcapsql_core::{
    default_registry, parse_packet, FilePacketSource, KeyLog, MmapPacketSource, PcapReader,
    ProtocolRegistry, SeekablePacketSource,
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
    /// Shared parse state for the streaming/parallel path (None for in-memory).
    shared: Option<Arc<SharedParseState>>,
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

        // Extract timestamp range and register time UDFs
        let (start_us, end_us) = Self::extract_timestamp_range(&protocol_batches)?;
        udf::register_time_udfs_eager(&ctx, start_us, end_us)?;

        // Register all protocol tables
        for (table_name, batches) in &protocol_batches {
            if batches.is_empty() {
                // Register an empty table with the correct schema
                if let Some(schema) = tables::get_table_schema(table_name) {
                    let empty_provider = provider::PcapTableProvider::new(Arc::new(schema), vec![]);
                    ctx.register_table(table_name.as_str(), Arc::new(empty_provider))
                        .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;
                }
            } else {
                let schema = batches[0].schema();
                let table_provider = provider::PcapTableProvider::new(schema, batches.clone());
                ctx.register_table(table_name.as_str(), Arc::new(table_provider))
                    .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;
            }
        }

        // Register cross-layer views (including backward-compatible packets view)
        Self::register_cross_layer_views(&ctx).await?;

        Ok(Self {
            ctx,
            registry,
            shared: None,
        })
    }

    /// Create a query engine with TLS decryption support.
    ///
    /// This enables decryption of TLS traffic using the provided SSLKEYLOGFILE,
    /// allowing queries on decrypted protocols like HTTP/2.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the PCAP file
    /// * `keylog` - TLS keylog for decryption (from SSLKEYLOGFILE)
    /// * `batch_size` - Number of packets per RecordBatch
    pub async fn with_keylog<P: AsRef<Path>>(
        path: P,
        keylog: Arc<KeyLog>,
        batch_size: usize,
    ) -> Result<Self, Error> {
        let registry = default_registry();
        let ctx = create_session_context();

        // Register all UDFs
        udf::register_all_udfs(&ctx)?;

        // Load all packets into normalized per-protocol tables
        let protocol_batches = Self::load_normalized_packets(&path, &registry, batch_size, false)?;

        // Check if we got any frames
        let frames_batches = protocol_batches
            .get("frames")
            .ok_or_else(|| Error::Query(QueryError::Execution("No frames table".to_string())))?;

        if frames_batches.is_empty() {
            return Err(Error::Query(QueryError::Execution(
                "No packets found in PCAP file".to_string(),
            )));
        }

        // Extract timestamp range and register time UDFs
        let (start_us, end_us) = Self::extract_timestamp_range(&protocol_batches)?;
        udf::register_time_udfs_eager(&ctx, start_us, end_us)?;

        // Register all protocol tables
        for (table_name, batches) in &protocol_batches {
            if batches.is_empty() {
                if let Some(schema) = tables::get_table_schema(table_name) {
                    let empty_provider = provider::PcapTableProvider::new(Arc::new(schema), vec![]);
                    ctx.register_table(table_name.as_str(), Arc::new(empty_provider))
                        .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;
                }
            } else {
                let schema = batches[0].schema();
                let table_provider = provider::PcapTableProvider::new(schema, batches.clone());
                ctx.register_table(table_name.as_str(), Arc::new(table_provider))
                    .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;
            }
        }

        // Process streams with TLS decryption to populate HTTP/2 table
        let path_str = path.as_ref().to_string_lossy().to_string();
        let mut stream_builder = stream_tables::StreamTableBuilder::new(Some(keylog));
        stream_builder.process_pcap(&path_str)?;

        // Get HTTP/2 batches from stream processing
        let http2_batches = stream_builder.http2_batches(batch_size)?;

        // Replace the http2 table with stream-parsed data
        if !http2_batches.is_empty() {
            let schema = http2_batches[0].schema();
            let http2_provider = provider::PcapTableProvider::new(schema, http2_batches);
            // Deregister the empty http2 table and register with data
            ctx.deregister_table("http2")
                .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;
            ctx.register_table("http2", Arc::new(http2_provider))
                .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;
        }

        // Register cross-layer views
        Self::register_cross_layer_views(&ctx).await?;

        Ok(Self {
            ctx,
            registry,
            shared: None,
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
    pub async fn with_streaming<P: AsRef<Path>>(path: P, batch_size: usize) -> Result<Self, Error> {
        let source = FilePacketSource::open(path)?;
        Self::with_streaming_source(Arc::new(source), batch_size).await
    }

    /// Create a QueryEngine with a custom seekable packet source.
    ///
    /// Performs a single shared parse pass over the source (fanning out to all
    /// protocol tables), parallelized across partitions for seekable sources,
    /// then serves every table from the shared result — so a query joining N
    /// tables parses the capture once, not N times.
    pub async fn with_streaming_source<S: SeekablePacketSource>(
        source: Arc<S>,
        batch_size: usize,
    ) -> Result<Self, Error> {
        Self::with_streaming_source_partitions(source, batch_size, default_target_partitions()).await
    }

    /// Like [`with_streaming_source`](Self::with_streaming_source) but with an
    /// explicit target partition count for the shared parse pass (mainly for
    /// tests and benchmarks).
    pub async fn with_streaming_source_partitions<S: SeekablePacketSource>(
        source: Arc<S>,
        batch_size: usize,
        target_partitions: usize,
    ) -> Result<Self, Error> {
        let registry = Arc::new(default_registry());
        let ctx = create_session_context();
        udf::register_all_udfs(&ctx)?;

        // ONE parse pass, fanned out to all tables, parallel across partitions.
        let shared = Arc::new(run_shared_parse(
            &source,
            &registry,
            batch_size,
            target_partitions,
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
                Error::Query(QueryError::Execution(format!("Unknown table: {table_name}")))
            })?);
            let provider = providers::ProtocolTableProvider::shared(
                table_name.to_string(),
                schema,
                shared.clone(),
            );
            ctx.register_table(table_name, Arc::new(provider))
                .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;
        }

        Self::register_cross_layer_views(&ctx).await?;

        Ok(Self {
            ctx,
            registry: (*registry).clone(),
            shared: Some(shared),
        })
    }

    /// Create a QueryEngine for a cloud storage URL.
    ///
    /// Supports S3, GCS, and Azure Blob Storage URLs:
    /// - `s3://bucket/path/to/file.pcap`
    /// - `gs://bucket/path/to/file.pcap`
    /// - `az://container/path/to/blob.pcap`
    ///
    /// Cloud sources always use streaming mode since the data must be fetched
    /// over the network.
    ///
    /// # Arguments
    ///
    /// * `url` - Cloud storage URL
    /// * `batch_size` - Number of packets per RecordBatch
    /// * `endpoint` - Custom endpoint URL (for S3-compatible services like MinIO)
    /// * `anonymous` - Use anonymous (unsigned) requests for public buckets
    /// * `chunk_size` - Buffer size for byte-range requests (default 8MB)
    #[cfg(feature = "cloud")]
    pub async fn with_cloud_source(
        url: &str,
        batch_size: usize,
        endpoint: Option<&str>,
        anonymous: bool,
        chunk_size: usize,
    ) -> Result<Self, Error> {
        // Parse cloud URL
        let location = CloudLocation::parse(url)
            .map_err(|e| Error::Query(QueryError::Execution(format!("Invalid cloud URL: {e}"))))?;

        // Apply options
        let location = if let Some(ep) = endpoint {
            location.with_endpoint(ep)
        } else {
            location
        };

        let location = if anonymous {
            location.with_anonymous(true)
        } else {
            location
        };

        let location = location.with_chunk_size(chunk_size);

        // Create cloud packet source
        // CloudPacketSource::open handles runtime nesting via run_async
        let source = CloudPacketSource::open(location)
            .map_err(|e| Error::Query(QueryError::Execution(format!("Cloud source error: {e}"))))?;

        // Cloud sources use the shared (parallel) parse path.
        Self::with_streaming_source(Arc::new(source), batch_size).await
    }

    /// Create a QueryEngine with automatic mode selection.
    ///
    /// Mode is selected based on file size:
    /// - Files < 100MB: In-memory mode (fastest for small files)
    /// - Files >= 100MB: Shared parallel parse over a seekable source
    ///
    /// Use `new()` or `with_streaming()` to force a specific mode.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the PCAP file
    /// * `batch_size` - Number of packets per RecordBatch
    /// * `use_mmap` - Use memory-mapped I/O for large files
    pub async fn auto<P: AsRef<Path>>(
        path: P,
        batch_size: usize,
        use_mmap: bool,
    ) -> Result<Self, Error> {
        let file_size = std::fs::metadata(path.as_ref())
            .map(|m| m.len())
            .unwrap_or(0);

        if file_size >= STREAMING_THRESHOLD_BYTES {
            // Large file: shared parallel parse.
            if use_mmap {
                if let Ok(source) = MmapPacketSource::open(&path) {
                    return Self::with_streaming_source(Arc::new(source), batch_size).await;
                }
                // Fall back to file source if mmap fails.
            }
            let source = Arc::new(FilePacketSource::open(&path)?);
            Self::with_streaming_source(source, batch_size).await
        } else {
            // Small file: use in-memory mode.
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
                pb.set_message(format!("{packet_count} packets loaded"));
                pb.tick();
            }

            // Check for EOF
            if processed == 0 {
                break;
            }
        }

        // Finish progress bar
        if let Some(pb) = progress {
            pb.finish_with_message(format!("{packet_count} packets loaded"));
        }

        // Finish and return all batches
        batch_set.finish()
    }

    /// Extract the timestamp range (min, max) from loaded frame batches.
    ///
    /// Returns (start_timestamp_us, end_timestamp_us) for the capture.
    fn extract_timestamp_range(
        batches: &HashMap<String, Vec<RecordBatch>>,
    ) -> Result<(i64, i64), Error> {
        let frames = batches.get("frames").ok_or_else(|| {
            Error::Query(QueryError::Execution(
                "No frames table for timestamp extraction".to_string(),
            ))
        })?;

        let mut min_ts = i64::MAX;
        let mut max_ts = i64::MIN;

        for batch in frames {
            if let Some(ts_col) = batch.column_by_name("timestamp") {
                let ts_array = ts_col
                    .as_any()
                    .downcast_ref::<TimestampMicrosecondArray>()
                    .expect("timestamp column should be TimestampMicrosecondArray");

                for i in 0..ts_array.len() {
                    if !ts_array.is_null(i) {
                        let ts = ts_array.value(i);
                        min_ts = min_ts.min(ts);
                        max_ts = max_ts.max(ts);
                    }
                }
            }
        }

        // Handle empty capture
        if min_ts == i64::MAX {
            Ok((0, 0))
        } else {
            Ok((min_ts, max_ts))
        }
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
    /// For the shared (streaming/parallel) path this is `1` regardless of how
    /// many protocol tables a query touches — the instrumentation behind #6.
    /// Returns `0` for the in-memory path (which also parses once, via a
    /// separate code path).
    pub fn parse_pass_count(&self) -> usize {
        self.shared.as_ref().map(|s| s.parse_passes()).unwrap_or(0)
    }

    /// Number of partitions the shared parse pass used (1 if non-partitioned or
    /// in-memory mode).
    pub fn partition_count(&self) -> usize {
        self.shared.as_ref().map(|s| s.num_partitions()).unwrap_or(1)
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
