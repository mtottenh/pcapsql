//! Protocol table provider for DataFusion.

use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use arrow::datatypes::SchemaRef;
use arrow::record_batch::RecordBatch;
use async_trait::async_trait;
use datafusion::catalog::Session;
use datafusion::datasource::{TableProvider, TableType};
use datafusion::error::Result as DFResult;
use datafusion::logical_expr::Expr;
use datafusion_datasource::memory::MemorySourceConfig;
use datafusion::physical_plan::ExecutionPlan;

use pcapsql_core::{compute_required_protocols, PacketSource, ParseCache, ProtocolRegistry};

use super::ProtocolStreamExec;

/// Table provider for a protocol table.
///
/// Generic over the packet source type to enable static dispatch
/// in the streaming hot path.
pub struct ProtocolTableProvider<S: PacketSource> {
    table_name: String,
    schema: SchemaRef,
    mode: TableMode<S>,
}

enum TableMode<S: PacketSource> {
    /// Pre-loaded batches in memory
    InMemory { batches: Vec<RecordBatch> },
    /// Streaming from packet source
    Streaming {
        source: Arc<S>,
        registry: Arc<ProtocolRegistry>,
        batch_size: usize,
        /// Optional parse cache for reducing redundant parsing
        cache: Option<Arc<dyn ParseCache>>,
    },
}

impl<S: PacketSource + 'static> ProtocolTableProvider<S> {
    /// Create an in-memory provider with pre-loaded batches.
    pub fn in_memory(table_name: String, schema: SchemaRef, batches: Vec<RecordBatch>) -> Self {
        Self {
            table_name,
            schema,
            mode: TableMode::InMemory { batches },
        }
    }

    /// Create a streaming provider.
    pub fn streaming(
        table_name: String,
        schema: SchemaRef,
        source: Arc<S>,
        registry: Arc<ProtocolRegistry>,
        batch_size: usize,
    ) -> Self {
        Self {
            table_name,
            schema,
            mode: TableMode::Streaming {
                source,
                registry,
                batch_size,
                cache: None,
            },
        }
    }

    /// Create a streaming provider with parse cache.
    pub fn streaming_cached(
        table_name: String,
        schema: SchemaRef,
        source: Arc<S>,
        registry: Arc<ProtocolRegistry>,
        batch_size: usize,
        cache: Arc<dyn ParseCache>,
    ) -> Self {
        Self {
            table_name,
            schema,
            mode: TableMode::Streaming {
                source,
                registry,
                batch_size,
                cache: Some(cache),
            },
        }
    }
}

#[async_trait]
impl<S: PacketSource + 'static> TableProvider for ProtocolTableProvider<S> {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> SchemaRef {
        self.schema.clone()
    }

    fn table_type(&self) -> TableType {
        TableType::Base
    }

    async fn scan(
        &self,
        _state: &dyn Session,
        projection: Option<&Vec<usize>>,
        _filters: &[Expr],
        limit: Option<usize>,
    ) -> DFResult<Arc<dyn ExecutionPlan>> {
        match &self.mode {
            TableMode::InMemory { batches } => Ok(MemorySourceConfig::try_new_exec(
                &[batches.clone()],
                self.schema.clone(),
                projection.cloned(),
            )? as Arc<dyn ExecutionPlan>),
            TableMode::Streaming {
                source,
                registry,
                batch_size,
                cache,
            } => {
                // Get partitions from source (single partition in Phase 2)
                let partitions = source
                    .partitions(1)
                    .map_err(|e| datafusion::error::DataFusionError::External(Box::new(e)))?;

                // Protocol Pruning Optimization:
                // Compute required protocols for this table scan.
                // This includes the table itself and all its dependencies (e.g., tcp requires ipv4/ipv6, ethernet).
                // Parsing will stop once all required protocols have been parsed.
                let required_protocols = Arc::new(compute_required_protocols(
                    &[self.table_name.as_str()],
                    registry,
                ));

                // Field Projection Optimization:
                // Convert DataFusion projection indices to field names.
                // This tells the parser to only extract needed fields, reducing CPU usage.
                let field_projections = projection.map(|indices| {
                    let field_names: HashSet<String> = indices
                        .iter()
                        .filter_map(|&idx| self.schema.field(idx).name().to_string().into())
                        .collect();

                    let mut projections = HashMap::new();
                    projections.insert(self.table_name.clone(), field_names);
                    Arc::new(projections)
                });

                Ok(Arc::new(ProtocolStreamExec::new_with_optimizations(
                    self.table_name.clone(),
                    self.schema.clone(),
                    source.clone(),
                    registry.clone(),
                    partitions,
                    *batch_size,
                    projection.cloned(),
                    cache.clone(),
                    limit,
                    Some(required_protocols),
                    field_projections,
                )))
            }
        }
    }
}

impl<S: PacketSource> std::fmt::Debug for ProtocolTableProvider<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolTableProvider")
            .field("table_name", &self.table_name)
            .field(
                "mode",
                &match &self.mode {
                    TableMode::InMemory { .. } => "InMemory",
                    TableMode::Streaming { .. } => "Streaming",
                },
            )
            .finish()
    }
}
