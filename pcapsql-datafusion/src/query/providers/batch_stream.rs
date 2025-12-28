//! Async stream that produces RecordBatches for a protocol table.

use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tracing::debug;

use arrow::datatypes::SchemaRef;
use arrow::record_batch::RecordBatch;

use datafusion::error::DataFusionError;
use datafusion::physical_plan::RecordBatchStream;
use futures::Stream;

/// Global sequence counter for tracking batch scheduling order across all streams.
static BATCH_SEQUENCE: AtomicU64 = AtomicU64::new(0);

use crate::error::{Error, Result};
use crate::query::builders::ProtocolBatchBuilder;
use pcapsql_core::io::PacketRef;
use pcapsql_core::{
    parse_packet, parse_packet_projected, parse_packet_pruned, parse_packet_pruned_projected,
    CachedParse, PacketReader, ParseCache, ProtocolRegistry,
};

/// Async stream that produces RecordBatches for a protocol table.
///
/// Generic over the reader type for zero-vtable hot path.
///
/// # How It Works
///
/// 1. Reads packets from the source using `reader.process_packets()` (zero-copy)
/// 2. Parses each packet using the protocol registry (or cache lookup)
/// 3. Filters to only packets matching this table's protocol
/// 4. Builds Arrow RecordBatches in chunks of `batch_size`
///
/// # Zero-Copy Processing
///
/// Uses the callback-based `process_packets()` API to avoid copying packet
/// data. The callback receives borrowed packet data that is parsed and
/// added to Arrow builders before the borrow ends.
///
/// # Caching
///
/// When a cache is provided, parsed results are stored and shared between
/// multiple readers. This significantly reduces CPU usage when multiple
/// protocol tables read the same PCAP file (e.g., during JOINs).
///
/// # Limit Pushdown
///
/// When a limit is provided, the stream stops reading packets once the
/// limit is satisfied, avoiding unnecessary parsing work.
pub struct ProtocolBatchStream<R: PacketReader> {
    table_name: String,
    schema: SchemaRef,
    reader: R,
    registry: Arc<ProtocolRegistry>,
    link_type: u32,
    batch_size: usize,
    projection: Option<Vec<usize>>,
    finished: bool,
    /// Optional parse cache for reducing redundant parsing
    cache: Option<Arc<dyn ParseCache>>,
    /// Reader ID for cache eviction tracking
    cache_reader_id: Option<usize>,
    /// Optional row limit for limit pushdown optimization
    limit: Option<usize>,
    /// Number of rows already emitted (for limit tracking)
    rows_emitted: usize,
    /// Optional set of required protocols for pruning optimization.
    /// When set, uses parse_packet_pruned instead of parse_packet.
    required_protocols: Option<Arc<HashSet<String>>>,
    /// Optional per-protocol field projections for field extraction optimization.
    /// Key is protocol name, value is set of field names to extract.
    /// When set, only requested fields are extracted during parsing.
    field_projections: Option<Arc<HashMap<String, HashSet<String>>>>,
}

impl<R: PacketReader> ProtocolBatchStream<R> {
    pub fn new(
        table_name: String,
        schema: SchemaRef,
        reader: R,
        registry: Arc<ProtocolRegistry>,
        link_type: u32,
        batch_size: usize,
        projection: Option<Vec<usize>>,
        cache: Option<Arc<dyn ParseCache>>,
        limit: Option<usize>,
        required_protocols: Option<Arc<HashSet<String>>>,
    ) -> Result<Self> {
        Self::new_with_field_projections(
            table_name,
            schema,
            reader,
            registry,
            link_type,
            batch_size,
            projection,
            cache,
            limit,
            required_protocols,
            None, // No field projections
        )
    }

    /// Create a new stream with field projection support.
    ///
    /// Field projections specify which fields to extract for each protocol.
    /// This can significantly reduce CPU usage when queries only need a
    /// subset of fields.
    ///
    /// # Arguments
    ///
    /// * `field_projections` - Per-protocol field sets. Key is protocol name,
    ///   value is set of field names to extract.
    pub fn new_with_field_projections(
        table_name: String,
        schema: SchemaRef,
        reader: R,
        registry: Arc<ProtocolRegistry>,
        link_type: u32,
        batch_size: usize,
        projection: Option<Vec<usize>>,
        cache: Option<Arc<dyn ParseCache>>,
        limit: Option<usize>,
        required_protocols: Option<Arc<HashSet<String>>>,
        field_projections: Option<Arc<HashMap<String, HashSet<String>>>>,
    ) -> Result<Self> {
        // Register with cache if provided
        let cache_reader_id = cache.as_ref().map(|c| c.register_reader());

        Ok(Self {
            table_name,
            schema,
            reader,
            registry,
            link_type,
            batch_size,
            projection,
            finished: false,
            cache,
            cache_reader_id,
            limit,
            rows_emitted: 0,
            required_protocols,
            field_projections,
        })
    }

    /// Read and process the next batch of packets.
    ///
    /// Uses the zero-copy `process_packets()` API to avoid copying packet data.
    /// The callback receives borrowed packet data that is parsed and added to
    /// Arrow builders before the borrow ends.
    ///
    /// # Limit Pushdown
    ///
    /// When a limit is set, this method tracks rows emitted and stops reading
    /// once the limit is satisfied. The final batch may be sliced to not exceed
    /// the limit.
    fn read_next_batch(&mut self) -> Result<Option<RecordBatch>> {
        if self.finished {
            return Ok(None);
        }

        // Check if we've already satisfied the limit
        if let Some(limit) = self.limit {
            if self.rows_emitted >= limit {
                self.finished = true;
                return Ok(None);
            }
        }

        let mut builder = match ProtocolBatchBuilder::new(&self.table_name, self.batch_size) {
            Some(b) => b,
            None => {
                // Unknown table name
                self.finished = true;
                return Ok(None);
            }
        };

        let mut rows_added = 0usize;
        let mut first_frame = 0u64;
        let mut last_frame = 0u64;
        let mut batch_hits = 0usize;
        let mut batch_misses = 0usize;

        // Capture references for the closure
        let table_name = &self.table_name;
        let cache = &self.cache;
        let registry = &self.registry;
        let link_type = self.link_type;
        let required_protocols = &self.required_protocols;
        let field_projections = &self.field_projections;

        // Process packets using zero-copy callback API
        let packets_processed =
            self.reader
                .process_packets(self.batch_size, |packet: PacketRef<'_>| {
                    // Track first frame of this batch
                    if first_frame == 0 {
                        first_frame = packet.frame_number;
                    }
                    last_frame = packet.frame_number;

                    // For frames table, add all packets without parsing
                    if table_name == "frames" {
                        builder.add_frame_from_raw(
                            packet.frame_number,
                            packet.timestamp_us,
                            packet.captured_len,
                            packet.original_len,
                            packet.data, // Borrowed slice - copied into Arrow buffer
                            packet.link_type,
                        );
                        rows_added += 1;
                        return Ok(());
                    }

                    if let Some(ref cache) = cache {
                        let (cached, was_hit) = cache.get_or_insert_with(
                            packet.frame_number,
                            Box::new(|| {
                                // Parse using borrowed data
                                let parsed = match (required_protocols, field_projections) {
                                    // Both pruning and projection
                                    (Some(ref required), Some(ref projections)) => {
                                        parse_packet_pruned_projected(
                                            registry,
                                            link_type as u16,
                                            packet.data,
                                            required,
                                            projections,
                                        )
                                    }
                                    // Only pruning
                                    (Some(ref required), None) => parse_packet_pruned(
                                        registry,
                                        link_type as u16,
                                        packet.data,
                                        required,
                                    ),
                                    // Only projection
                                    (None, Some(ref projections)) => parse_packet_projected(
                                        registry,
                                        link_type as u16,
                                        packet.data,
                                        projections,
                                    ),
                                    // Neither - full parsing
                                    (None, None) => {
                                        parse_packet(registry, link_type as u16, packet.data)
                                    }
                                };
                                Arc::new(CachedParse::from_parse_results(
                                    packet.frame_number,
                                    &parsed,
                                ))
                            }),
                        );

                        // Track batch-level hit/miss
                        if was_hit {
                            batch_hits += 1;
                        } else {
                            batch_misses += 1;
                        }

                        // Use cached result to add rows
                        // get_all_protocols handles tunneled packets with multiple
                        // occurrences of the same protocol at different encap depths
                        for result in cached.get_all_protocols(table_name) {
                            builder.add_cached_row(packet.frame_number, result);
                            rows_added += 1;
                        }
                    } else {
                        // No cache - parse directly using borrowed data (no Arc allocation)
                        let parsed = match (required_protocols, field_projections) {
                            // Both pruning and projection
                            (Some(ref required), Some(ref projections)) => {
                                parse_packet_pruned_projected(
                                    registry,
                                    link_type as u16,
                                    packet.data,
                                    required,
                                    projections,
                                )
                            }
                            // Only pruning
                            (Some(ref required), None) => parse_packet_pruned(
                                registry,
                                link_type as u16,
                                packet.data,
                                required,
                            ),
                            // Only projection
                            (None, Some(ref projections)) => parse_packet_projected(
                                registry,
                                link_type as u16,
                                packet.data,
                                projections,
                            ),
                            // Neither - full parsing
                            (None, None) => parse_packet(registry, link_type as u16, packet.data),
                        };

                        // For protocol-specific tables, add ALL occurrences (supports tunneled traffic)
                        // For example, a VXLAN packet may have two Ethernet/IPv4 layers at different depths
                        for (proto_name, result) in &parsed {
                            if *proto_name == *table_name {
                                builder.add_parsed_row(packet.frame_number, result);
                                rows_added += 1;
                                // NO break - include all occurrences for tunnel support
                            }
                        }
                    }

                    Ok(())
                })?;

        // Log batch scheduling information for debugging cache behavior
        if packets_processed > 0 {
            let seq = BATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            debug!(
                seq = seq,
                table = %self.table_name,
                first_frame = first_frame,
                last_frame = last_frame,
                packets = packets_processed,
                rows = rows_added,
                hits = batch_hits,
                misses = batch_misses,
                "batch_read"
            );
        }

        // Check if we've reached EOF
        if packets_processed == 0 {
            self.finished = true;
        }

        // Notify cache of progress for eviction
        if let (Some(cache), Some(reader_id)) = (&self.cache, self.cache_reader_id) {
            if last_frame > 0 {
                cache.reader_passed(reader_id, last_frame);
            }
        }

        if rows_added == 0 {
            return Ok(None);
        }

        let batch = builder.finish()?.unwrap_or_else(|| {
            // Empty batch - shouldn't happen if rows_added > 0
            RecordBatch::new_empty(self.schema.clone())
        });

        // Apply projection if specified
        let batch = if let Some(ref indices) = self.projection {
            batch
                .project(indices)
                .map_err(|e| Error::Query(crate::error::QueryError::Arrow(e.to_string())))?
        } else {
            batch
        };

        // Apply limit: slice batch if it would exceed the remaining limit
        let batch = if let Some(limit) = self.limit {
            let remaining = limit.saturating_sub(self.rows_emitted);
            if batch.num_rows() > remaining {
                // Slice to only return remaining rows
                self.finished = true;
                batch.slice(0, remaining)
            } else {
                batch
            }
        } else {
            batch
        };

        // Track rows emitted for limit pushdown
        self.rows_emitted += batch.num_rows();

        // Mark finished if we've now hit the limit
        if let Some(limit) = self.limit {
            if self.rows_emitted >= limit {
                self.finished = true;
            }
        }

        Ok(Some(batch))
    }

    /// Get the output schema (after projection)
    fn output_schema(&self) -> SchemaRef {
        if let Some(ref indices) = self.projection {
            Arc::new(self.schema.project(indices).unwrap())
        } else {
            self.schema.clone()
        }
    }
}

impl<R: PacketReader + Unpin> Stream for ProtocolBatchStream<R> {
    type Item = std::result::Result<RecordBatch, DataFusionError>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Note: This is synchronous I/O wrapped in async.
        // For true async I/O, we'd use tokio::fs in Phase 3.
        let this = self.get_mut();
        match this.read_next_batch() {
            Ok(Some(batch)) => Poll::Ready(Some(Ok(batch))),
            Ok(None) => Poll::Ready(None),
            Err(e) => Poll::Ready(Some(Err(DataFusionError::External(Box::new(e))))),
        }
    }
}

impl<R: PacketReader + Unpin> RecordBatchStream for ProtocolBatchStream<R> {
    fn schema(&self) -> SchemaRef {
        self.output_schema()
    }
}

impl<R: PacketReader> Drop for ProtocolBatchStream<R> {
    fn drop(&mut self) {
        // Unregister from cache when stream is dropped
        if let (Some(cache), Some(reader_id)) = (&self.cache, self.cache_reader_id) {
            cache.unregister_reader(reader_id);
        }
    }
}
