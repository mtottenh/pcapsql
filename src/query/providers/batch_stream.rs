//! Async stream that produces RecordBatches for a protocol table.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use arrow::datatypes::SchemaRef;
use arrow::record_batch::RecordBatch;
use datafusion::error::DataFusionError;
use datafusion::physical_plan::RecordBatchStream;
use futures::Stream;

use crate::cache::{CachedParse, ParseCache};
use crate::error::{Error, Result};
use crate::io::{PacketReader, RawPacket};
use crate::protocol::{parse_packet, ProtocolRegistry};
use crate::query::builders::ProtocolBatchBuilder;

/// Async stream that produces RecordBatches for a protocol table.
///
/// Generic over the reader type for zero-vtable hot path.
///
/// # How It Works
///
/// 1. Reads packets from the source using `reader.next_packet()`
/// 2. Parses each packet using the protocol registry (or cache lookup)
/// 3. Filters to only packets matching this table's protocol
/// 4. Builds Arrow RecordBatches in chunks of `batch_size`
///
/// # Caching
///
/// When a cache is provided, parsed results are stored and shared between
/// multiple readers. This significantly reduces CPU usage when multiple
/// protocol tables read the same PCAP file (e.g., during JOINs).
pub struct ProtocolBatchStream<R: PacketReader> {
    table_name: String,
    schema: SchemaRef,
    reader: R,
    registry: Arc<ProtocolRegistry>,
    link_type: u32,
    batch_size: usize,
    projection: Option<Vec<usize>>,
    finished: bool,
    /// Reusable buffer for batch reads
    packet_buffer: Vec<RawPacket>,
    /// Optional parse cache for reducing redundant parsing
    cache: Option<Arc<dyn ParseCache>>,
    /// Reader ID for cache eviction tracking
    cache_reader_id: Option<usize>,
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
            packet_buffer: Vec::with_capacity(batch_size),
            cache,
            cache_reader_id,
        })
    }

    /// Read and process the next batch of packets.
    fn read_next_batch(&mut self) -> Result<Option<RecordBatch>> {
        if self.finished {
            return Ok(None);
        }

        let mut builder = match ProtocolBatchBuilder::new(&self.table_name, self.batch_size) {
            Some(b) => b,
            None => {
                // Unknown table name
                self.finished = true;
                return Ok(None);
            }
        };

        let mut rows_added = 0;
        let mut last_frame = 0u64;

        // Read packets until we have a full batch or reach EOF
        while rows_added < self.batch_size {
            // Use batch reading for efficiency
            let count = self.reader.read_batch(
                &mut self.packet_buffer,
                (self.batch_size - rows_added).min(256), // Read in reasonable chunks
            )?;

            if count == 0 {
                self.finished = true;
                break;
            }

            for packet in &self.packet_buffer[..count] {
                last_frame = packet.frame_number;

                // For frames table, add all packets without parsing
                if self.table_name == "frames" {
                    builder.add_frame_from_raw(
                        packet.frame_number,
                        packet.timestamp_us,
                        packet.captured_len,
                        packet.original_len,
                        &packet.data,
                        self.link_type as u16,
                    );
                    rows_added += 1;
                    continue;
                }

                // Check cache first
                if let Some(ref cache) = self.cache {
                    if let Some(cached) = cache.get(packet.frame_number) {
                        // Cache hit - use cached parse result
                        if let Some(result) = cached.get_protocol(&self.table_name) {
                            builder.add_cached_row(packet.frame_number, result);
                            rows_added += 1;
                        }
                        continue;
                    }
                }

                // Cache miss (or no cache) - parse packet
                let parsed = parse_packet(
                    &self.registry,
                    self.link_type as u16,
                    &packet.data,
                );

                // Store in cache if available
                if let Some(ref cache) = self.cache {
                    let cached = Arc::new(CachedParse::from_parse_results(
                        packet.frame_number,
                        &parsed,
                    ));
                    cache.put(packet.frame_number, cached);
                }

                // For protocol-specific tables, only add if the protocol is present
                for (proto_name, result) in &parsed {
                    if *proto_name == self.table_name {
                        builder.add_parsed_row(packet.frame_number, result);
                        rows_added += 1;
                        break;
                    }
                }
            }
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
        if let Some(ref indices) = self.projection {
            Ok(Some(batch.project(indices).map_err(|e| {
                Error::Query(crate::error::QueryError::Arrow(e.to_string()))
            })?))
        } else {
            Ok(Some(batch))
        }
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
