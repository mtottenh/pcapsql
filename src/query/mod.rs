//! SQL query engine module.
//!
//! This module provides DataFusion integration for querying packet data.

mod batch;
mod provider;
mod schema;

pub use batch::PacketBatchBuilder;
pub use provider::PcapTableProvider;
pub use schema::build_packets_schema;

use std::path::Path;
use std::sync::Arc;

use arrow::array::RecordBatch;
use datafusion::prelude::*;

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
        let registry = default_registry();
        let ctx = SessionContext::new();

        // Load all packets into memory as Arrow batches
        let batches = Self::load_packets(&path, &registry, batch_size)?;

        if batches.is_empty() {
            return Err(Error::Query(QueryError::Execution(
                "No packets found in PCAP file".to_string(),
            )));
        }

        // Register the packets table
        let schema = batches[0].schema();
        let provider = provider::PcapTableProvider::new(schema, batches);
        ctx.register_table("packets", Arc::new(provider))
            .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;

        // Register per-protocol views
        Self::register_protocol_views(&ctx).await?;

        Ok(Self { ctx, registry })
    }

    /// Load packets from a PCAP file into Arrow batches.
    fn load_packets<P: AsRef<Path>>(
        path: P,
        registry: &ProtocolRegistry,
        batch_size: usize,
    ) -> Result<Vec<RecordBatch>, Error> {
        let mut reader = PcapReader::open(path)?;
        let link_type = reader.link_type();

        let schema = Arc::new(build_packets_schema(registry));
        let mut builder = PacketBatchBuilder::new(schema.clone(), batch_size);
        let mut batches = Vec::new();

        while let Some(raw_packet) = reader.next_packet()? {
            // Parse the packet through all protocol layers
            let parsed = parse_packet(registry, link_type, &raw_packet.data);

            // Add to batch builder
            builder.add_packet(&raw_packet, &parsed)?;

            // Check if batch is full
            if let Some(batch) = builder.try_build()? {
                batches.push(batch);
            }
        }

        // Build final partial batch
        if let Some(batch) = builder.finish()? {
            batches.push(batch);
        }

        Ok(batches)
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

        Ok(())
    }
}
