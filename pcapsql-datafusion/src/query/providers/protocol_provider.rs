//! Protocol table provider backed by the shared parse pass.

use std::any::Any;
use std::sync::Arc;

use arrow::datatypes::SchemaRef;
use arrow::record_batch::RecordBatch;
use async_trait::async_trait;
use datafusion::catalog::Session;
use datafusion::datasource::{TableProvider, TableType};
use datafusion::error::Result as DFResult;
use datafusion::logical_expr::Expr;
use datafusion::physical_plan::ExecutionPlan;

use super::shared::SharedParseState;
use super::ProtocolScanExec;

/// Table provider for a single protocol table.
///
/// All providers for a query share one [`SharedParseState`] (the result of the
/// single parse pass), so a query touching N tables parses the capture once.
pub struct ProtocolTableProvider {
    table_name: String,
    schema: SchemaRef,
    /// Shared parse result, or pre-loaded batches for the in-memory path.
    source: TableSource,
}

enum TableSource {
    /// Slice of the shared parse pass.
    Shared(Arc<SharedParseState>),
    /// Pre-loaded batches (used for empty tables / direct registration).
    InMemory(Vec<Vec<RecordBatch>>),
}

impl ProtocolTableProvider {
    /// Create a provider that draws this table's batches from the shared parse.
    pub fn shared(table_name: String, schema: SchemaRef, state: Arc<SharedParseState>) -> Self {
        Self {
            table_name,
            schema,
            source: TableSource::Shared(state),
        }
    }

    /// Create a provider over pre-loaded per-partition batches.
    pub fn in_memory(
        table_name: String,
        schema: SchemaRef,
        partitions: Vec<Vec<RecordBatch>>,
    ) -> Self {
        Self {
            table_name,
            schema,
            source: TableSource::InMemory(partitions),
        }
    }

    fn partitions(&self) -> Vec<Vec<RecordBatch>> {
        match &self.source {
            TableSource::Shared(state) => state.table_partitions(&self.table_name),
            TableSource::InMemory(parts) => parts.clone(),
        }
    }
}

#[async_trait]
impl TableProvider for ProtocolTableProvider {
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
        _limit: Option<usize>,
    ) -> DFResult<Arc<dyn ExecutionPlan>> {
        let partitions = Arc::new(self.partitions());
        Ok(Arc::new(ProtocolScanExec::new(
            self.table_name.clone(),
            self.schema.clone(),
            partitions,
            projection.cloned(),
        )))
    }
}

impl std::fmt::Debug for ProtocolTableProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolTableProvider")
            .field("table_name", &self.table_name)
            .field(
                "mode",
                &match &self.source {
                    TableSource::Shared(_) => "Shared",
                    TableSource::InMemory(_) => "InMemory",
                },
            )
            .finish()
    }
}
