//! DataFusion TableProvider implementation for PCAP data.

use std::any::Any;
use std::sync::Arc;

use arrow::datatypes::SchemaRef;
use arrow::record_batch::RecordBatch;
use async_trait::async_trait;
use datafusion::catalog::Session;
use datafusion::datasource::{TableProvider, TableType};
use datafusion::error::Result as DFResult;
use datafusion_datasource::memory::MemorySourceConfig;
use datafusion::physical_plan::ExecutionPlan;
use datafusion::prelude::*;

/// A TableProvider backed by in-memory Arrow RecordBatches.
#[derive(Debug)]
pub struct PcapTableProvider {
    schema: SchemaRef,
    batches: Vec<RecordBatch>,
}

impl PcapTableProvider {
    /// Create a new provider with the given schema and batches.
    pub fn new(schema: SchemaRef, batches: Vec<RecordBatch>) -> Self {
        Self { schema, batches }
    }
}

#[async_trait]
impl TableProvider for PcapTableProvider {
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
        let partitions = vec![self.batches.clone()];
        Ok(MemorySourceConfig::try_new_exec(
            &partitions,
            self.schema.clone(),
            projection.cloned(),
        )? as Arc<dyn ExecutionPlan>)
    }
}
