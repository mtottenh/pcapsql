//! SQL query engine module.
//!
//! This module provides DataFusion integration for querying packet data.

mod batch;
mod filter;
mod frames;
mod provider;
mod schema;
mod stream_provider;
mod streaming;

pub use batch::PacketBatchBuilder;
pub use filter::FilterEvaluator;
pub use frames::{frames_schema, FramesBatchBuilder};
pub use provider::PcapTableProvider;
pub use schema::{build_common_schema, build_packets_schema};
pub use stream_provider::StreamingPcapProvider;
pub use streaming::PcapStreamingExec;

use std::path::Path;
use std::sync::Arc;

use arrow::array::RecordBatch;
use datafusion::prelude::*;
use indicatif::{ProgressBar, ProgressStyle};

use crate::error::{Error, QueryError};
use crate::pcap::PcapReader;
use crate::protocol::{default_registry, parse_packet, ProtocolRegistry};

/// Query engine for PCAP files.
pub struct QueryEngine {
    ctx: SessionContext,
    registry: ProtocolRegistry,
}

impl QueryEngine {
    /// Create a new query engine for a PCAP file.
    pub async fn new<P: AsRef<Path>>(path: P, batch_size: usize) -> Result<Self, Error> {
        Self::with_progress(path, batch_size, false).await
    }

    /// Create a new query engine for a PCAP file with optional progress bar.
    pub async fn with_progress<P: AsRef<Path>>(
        path: P,
        batch_size: usize,
        show_progress: bool,
    ) -> Result<Self, Error> {
        let registry = default_registry();
        let ctx = SessionContext::new();

        // Load all packets into memory as Arrow batches
        let (packet_batches, frames_batches) =
            Self::load_packets(&path, &registry, batch_size, show_progress)?;

        if packet_batches.is_empty() {
            return Err(Error::Query(QueryError::Execution(
                "No packets found in PCAP file".to_string(),
            )));
        }

        // Register the packets table
        let packets_schema = packet_batches[0].schema();
        let packets_provider = provider::PcapTableProvider::new(packets_schema, packet_batches);
        ctx.register_table("packets", Arc::new(packets_provider))
            .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;

        // Register the frames table
        let frames_schema = frames_batches[0].schema();
        let frames_provider = provider::PcapTableProvider::new(frames_schema, frames_batches);
        ctx.register_table("frames", Arc::new(frames_provider))
            .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;

        // Register per-protocol views
        Self::register_protocol_views(&ctx).await?;

        Ok(Self { ctx, registry })
    }

    /// Create a new query engine with streaming mode (for large files).
    ///
    /// In streaming mode, packets are read on-demand as DataFusion pulls batches,
    /// rather than loading the entire file into memory upfront. This allows
    /// querying very large PCAP files (10GB+) with bounded memory usage.
    ///
    /// Filter and limit pushdown are supported to minimize the amount of data read.
    ///
    /// Streaming mode now supports all protocol-specific fields from the registry,
    /// including DNS, TLS, HTTP, and other application-layer protocol fields.
    pub async fn with_streaming<P: AsRef<Path>>(
        path: P,
        batch_size: usize,
    ) -> Result<Self, Error> {
        let registry = default_registry();
        // Use full schema with protocol-specific fields
        let schema = Arc::new(build_packets_schema(&registry));
        let ctx = SessionContext::new();

        // Register streaming provider for packets table
        let packets_provider = StreamingPcapProvider::new(
            path.as_ref().to_path_buf(),
            schema,
            Arc::new(registry.clone()),
            batch_size,
        );
        ctx.register_table("packets", Arc::new(packets_provider))
            .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;

        // Note: frames table is not available in streaming mode since it requires
        // raw packet data which we don't want to duplicate

        // Register per-protocol views
        Self::register_protocol_views(&ctx).await?;

        Ok(Self { ctx, registry })
    }

    /// Load packets from a PCAP file into Arrow batches.
    /// Returns (packet_batches, frames_batches).
    fn load_packets<P: AsRef<Path>>(
        path: P,
        registry: &ProtocolRegistry,
        batch_size: usize,
        show_progress: bool,
    ) -> Result<(Vec<RecordBatch>, Vec<RecordBatch>), Error> {
        let mut reader = PcapReader::open(path)?;
        let link_type = reader.link_type();

        let schema = Arc::new(build_packets_schema(registry));
        let mut packets_builder = PacketBatchBuilder::new(schema.clone(), batch_size);
        let mut frames_builder = FramesBatchBuilder::new(batch_size);
        let mut packet_batches = Vec::new();
        let mut frames_batches = Vec::new();

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

        while let Some(raw_packet) = reader.next_packet()? {
            // Parse the packet through all protocol layers
            let parsed = parse_packet(registry, link_type, &raw_packet.data);

            // Add to packets batch builder
            packets_builder.add_packet(&raw_packet, &parsed)?;

            // Add to frames batch builder
            frames_builder.add_packet(&raw_packet);

            packet_count += 1;

            // Update progress bar
            if let Some(ref pb) = progress {
                if packet_count % 1000 == 0 {
                    pb.set_message(format!("{} packets loaded", packet_count));
                    pb.tick();
                }
            }

            // Check if packets batch is full
            if let Some(batch) = packets_builder.try_build()? {
                packet_batches.push(batch);
            }

            // Check if frames batch is full
            if let Some(batch) = frames_builder.try_build()? {
                frames_batches.push(batch);
            }
        }

        // Build final partial batches
        if let Some(batch) = packets_builder.finish()? {
            packet_batches.push(batch);
        }
        if let Some(batch) = frames_builder.finish()? {
            frames_batches.push(batch);
        }

        // Finish progress bar
        if let Some(pb) = progress {
            pb.finish_with_message(format!("{} packets loaded", packet_count));
        }

        Ok((packet_batches, frames_batches))
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

    /// Register per-protocol views on top of the packets table.
    async fn register_protocol_views(ctx: &SessionContext) -> Result<(), Error> {
        // TCP view - packets where protocol is TCP
        ctx.sql("CREATE VIEW tcp AS SELECT * FROM packets WHERE protocol = 'TCP'")
            .await
            .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;

        // UDP view - packets where protocol is UDP
        ctx.sql("CREATE VIEW udp AS SELECT * FROM packets WHERE protocol = 'UDP'")
            .await
            .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;

        // ICMP view - packets where protocol is ICMP
        ctx.sql("CREATE VIEW icmp AS SELECT * FROM packets WHERE protocol = 'ICMP'")
            .await
            .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;

        // ARP view - packets where eth_type is 0x0806 (ARP ethertype)
        ctx.sql("CREATE VIEW arp AS SELECT * FROM packets WHERE eth_type = 2054")
            .await
            .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;

        // DNS view - packets where src_port or dst_port is 53
        ctx.sql("CREATE VIEW dns AS SELECT * FROM packets WHERE src_port = 53 OR dst_port = 53")
            .await
            .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;

        // DHCP view - packets where src_port or dst_port is 67 or 68
        ctx.sql("CREATE VIEW dhcp AS SELECT * FROM packets WHERE src_port = 67 OR dst_port = 67 OR src_port = 68 OR dst_port = 68")
            .await
            .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;

        // NTP view - packets where src_port or dst_port is 123
        ctx.sql("CREATE VIEW ntp AS SELECT * FROM packets WHERE src_port = 123 OR dst_port = 123")
            .await
            .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;

        // HTTP view - packets where src_port or dst_port is 80 or 8080
        ctx.sql("CREATE VIEW http AS SELECT * FROM packets WHERE src_port = 80 OR dst_port = 80 OR src_port = 8080 OR dst_port = 8080")
            .await
            .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;

        // TLS view - packets where src_port or dst_port is 443
        ctx.sql("CREATE VIEW tls AS SELECT * FROM packets WHERE src_port = 443 OR dst_port = 443")
            .await
            .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;

        Ok(())
    }
}
