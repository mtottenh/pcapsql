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
use datafusion::logical_expr::{Expr, TableProviderFilterPushDown};
use datafusion::physical_plan::ExecutionPlan;
use datafusion_datasource::memory::MemorySourceConfig;

use pcapsql_core::{compute_required_protocols, PacketSource, ParseCache, ProtocolRegistry};

use super::ProtocolStreamExec;
use crate::query::filter::PushdownPredicate;

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

    fn supports_filters_pushdown(
        &self,
        filters: &[&Expr],
    ) -> DFResult<Vec<TableProviderFilterPushDown>> {
        match &self.mode {
            // In-memory batches are already materialized; filtering them in
            // the scan would duplicate the FilterExec above it for no gain.
            TableMode::InMemory { .. } => Ok(vec![
                TableProviderFilterPushDown::Unsupported;
                filters.len()
            ]),
            // Streaming scans evaluate supported predicates against parsed
            // fields before Arrow materialization. Inexact: DataFusion still
            // re-applies the filter above the scan.
            TableMode::Streaming { .. } => Ok(filters
                .iter()
                .map(|f| {
                    if PushdownPredicate::try_compile(f, &self.schema).is_some() {
                        TableProviderFilterPushDown::Inexact
                    } else {
                        TableProviderFilterPushDown::Unsupported
                    }
                })
                .collect()),
        }
    }

    async fn scan(
        &self,
        _state: &dyn Session,
        projection: Option<&Vec<usize>>,
        filters: &[Expr],
        limit: Option<usize>,
    ) -> DFResult<Arc<dyn ExecutionPlan>> {
        match &self.mode {
            TableMode::InMemory { batches } => Ok(MemorySourceConfig::try_new_exec(
                std::slice::from_ref(batches),
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

                // Protocol pruning: only parse protocols needed for this table.
                // Disabled when caching since cache entries need all protocols.
                let required_protocols = if cache.is_none() {
                    Some(Arc::new(compute_required_protocols(
                        &[self.table_name.as_str()],
                        registry,
                    )))
                } else {
                    None
                };

                // Field projection: only extract fields in the SELECT list.
                let field_projections = projection.map(|indices| {
                    let field_names: HashSet<String> = indices
                        .iter()
                        .filter_map(|&idx| self.schema.field(idx).name().to_string().into())
                        .collect();

                    let mut projections = HashMap::new();
                    projections.insert(self.table_name.clone(), field_names);
                    Arc::new(projections)
                });

                // Compile pushed-down filters into a predicate evaluated
                // before rows are materialized into Arrow.
                let predicate = PushdownPredicate::compile_all(filters, &self.schema).map(Arc::new);

                Ok(Arc::new(
                    ProtocolStreamExec::new_with_optimizations(
                        self.table_name.clone(),
                        self.schema.clone(),
                        source.clone(),
                        registry.clone(),
                        partitions,
                        *batch_size,
                        projection.cloned(),
                        cache.clone(),
                        limit,
                        required_protocols,
                        field_projections,
                    )
                    .with_predicate(predicate),
                ))
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
