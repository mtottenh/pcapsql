//! Partition-aware scan execution plan for a protocol table.
//!
//! Non-generic: it streams pre-parsed per-partition batches produced by the
//! shared parse pass. It reports the real partition count in [`PlanProperties`]
//! and declares output ordering by `frame_number` so cross-partition sort-merge
//! joins reassemble global order without extra sorting.

use std::any::Any;
use std::fmt;
use std::sync::Arc;

use arrow::compute::SortOptions;
use arrow::datatypes::SchemaRef;
use arrow::record_batch::RecordBatch;
use datafusion::error::{DataFusionError, Result as DFResult};
use datafusion::execution::context::TaskContext;
use datafusion::physical_expr::{EquivalenceProperties, PhysicalSortExpr};
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, Partitioning, PlanProperties,
    SendableRecordBatchStream,
};
use futures::stream;

/// Execution plan that emits a protocol table's batches, one DataFusion
/// partition per parse partition.
pub struct ProtocolScanExec {
    table_name: String,
    /// One `Vec<RecordBatch>` per partition (frame order).
    partitions: Arc<Vec<Vec<RecordBatch>>>,
    projected_schema: SchemaRef,
    projection: Option<Vec<usize>>,
    properties: PlanProperties,
}

impl ProtocolScanExec {
    /// Create a scan over `partitions` (this table's per-partition batches).
    pub fn new(
        table_name: String,
        schema: SchemaRef,
        partitions: Arc<Vec<Vec<RecordBatch>>>,
        projection: Option<Vec<usize>>,
    ) -> Self {
        let projected_schema = match &projection {
            Some(idx) => Arc::new(schema.project(idx).expect("valid projection")),
            None => schema.clone(),
        };
        let num_partitions = partitions.len().max(1);
        let eq_props = Self::compute_equivalence_properties(&projected_schema);
        let properties = PlanProperties::new(
            eq_props,
            Partitioning::UnknownPartitioning(num_partitions),
            EmissionType::Incremental,
            Boundedness::Bounded,
        );
        Self {
            table_name,
            partitions,
            projected_schema,
            projection,
            properties,
        }
    }

    fn compute_equivalence_properties(schema: &SchemaRef) -> EquivalenceProperties {
        use datafusion::physical_expr::expressions::col;
        let mut eq_props = EquivalenceProperties::new(schema.clone());
        if schema.index_of("frame_number").is_ok() {
            if let Ok(col_expr) = col("frame_number", schema) {
                let sort_expr = PhysicalSortExpr {
                    expr: col_expr,
                    options: SortOptions {
                        descending: false,
                        nulls_first: false,
                    },
                };
                eq_props.add_orderings(vec![vec![sort_expr]]);
            }
        }
        eq_props
    }
}

impl ExecutionPlan for ProtocolScanExec {
    fn name(&self) -> &str {
        "ProtocolScanExec"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> SchemaRef {
        self.projected_schema.clone()
    }

    fn properties(&self) -> &PlanProperties {
        &self.properties
    }

    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        vec![]
    }

    fn with_new_children(
        self: Arc<Self>,
        _children: Vec<Arc<dyn ExecutionPlan>>,
    ) -> DFResult<Arc<dyn ExecutionPlan>> {
        Ok(self)
    }

    fn execute(
        &self,
        partition: usize,
        _context: Arc<TaskContext>,
    ) -> DFResult<SendableRecordBatchStream> {
        let batches = self.partitions.get(partition).cloned().unwrap_or_default();
        let projection = self.projection.clone();
        let iter = batches.into_iter().map(move |batch| match &projection {
            Some(indices) => batch
                .project(indices)
                .map_err(|e| DataFusionError::ArrowError(Box::new(e), None)),
            None => Ok(batch),
        });
        Ok(Box::pin(RecordBatchStreamAdapter::new(
            self.projected_schema.clone(),
            stream::iter(iter),
        )))
    }
}

impl DisplayAs for ProtocolScanExec {
    fn fmt_as(&self, t: DisplayFormatType, f: &mut fmt::Formatter) -> fmt::Result {
        match t {
            DisplayFormatType::Default
            | DisplayFormatType::Verbose
            | DisplayFormatType::TreeRender => {
                write!(
                    f,
                    "ProtocolScanExec: table={}, partitions={}",
                    self.table_name,
                    self.partitions.len()
                )
            }
        }
    }
}

impl fmt::Debug for ProtocolScanExec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtocolScanExec")
            .field("table_name", &self.table_name)
            .field("partitions", &self.partitions.len())
            .finish()
    }
}
