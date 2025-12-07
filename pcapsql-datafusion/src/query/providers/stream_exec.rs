//! Streaming execution plan for protocol tables.

use std::any::Any;
use std::fmt;
use std::sync::Arc;

use arrow::compute::SortOptions;
use arrow::datatypes::SchemaRef;
use datafusion::error::Result as DFResult;
use datafusion::execution::context::TaskContext;
use datafusion::physical_expr::{EquivalenceProperties, PhysicalSortExpr};
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionMode, ExecutionPlan, Partitioning, PlanProperties,
    SendableRecordBatchStream,
};

use pcapsql_core::io::PacketRange;
use pcapsql_core::{PacketSource, ParseCache, ProtocolRegistry};

use super::ProtocolBatchStream;

/// Streaming execution plan for a protocol table.
///
/// Generic over the packet source to enable zero-vtable hot path.
///
/// # Output Ordering
///
/// This plan declares that output is sorted by `frame_number`.
/// This is critical for enabling sort-merge joins between protocol
/// tables without additional sorting.
pub struct ProtocolStreamExec<S: PacketSource> {
    table_name: String,
    schema: SchemaRef,
    source: Arc<S>,
    registry: Arc<ProtocolRegistry>,
    partitions: Vec<PacketRange>,
    batch_size: usize,
    projection: Option<Vec<usize>>,
    /// Projected schema (after projection applied)
    projected_schema: SchemaRef,
    /// Plan properties (includes output ordering)
    properties: PlanProperties,
    /// Optional parse cache for reducing redundant parsing
    cache: Option<Arc<dyn ParseCache>>,
}

impl<S: PacketSource + 'static> ProtocolStreamExec<S> {
    pub fn new(
        table_name: String,
        schema: SchemaRef,
        source: Arc<S>,
        registry: Arc<ProtocolRegistry>,
        partitions: Vec<PacketRange>,
        batch_size: usize,
        projection: Option<Vec<usize>>,
        cache: Option<Arc<dyn ParseCache>>,
    ) -> Self {
        // Compute projected schema
        let projected_schema = if let Some(ref indices) = projection {
            Arc::new(schema.project(indices).unwrap())
        } else {
            schema.clone()
        };

        // Create equivalence properties with output ordering
        let eq_props = Self::compute_equivalence_properties(&projected_schema);

        let properties = PlanProperties::new(
            eq_props,
            Partitioning::UnknownPartitioning(partitions.len()),
            ExecutionMode::Bounded,
        );

        Self {
            table_name,
            schema,
            source,
            registry,
            partitions,
            batch_size,
            projection,
            projected_schema,
            properties,
            cache,
        }
    }

    fn compute_equivalence_properties(schema: &SchemaRef) -> EquivalenceProperties {
        let mut eq_props = EquivalenceProperties::new(schema.clone());

        // Declare that output is sorted by frame_number (if present in schema)
        if schema.index_of("frame_number").is_ok() {
            use datafusion::physical_expr::expressions::col;
            use datafusion::physical_expr::LexOrdering;

            if let Ok(col_expr) = col("frame_number", schema) {
                let sort_expr = PhysicalSortExpr {
                    expr: col_expr,
                    options: SortOptions {
                        descending: false,
                        nulls_first: false,
                    },
                };
                let ordering = LexOrdering::new(vec![sort_expr]);
                eq_props = eq_props.with_reorder(ordering);
            }
        }

        eq_props
    }
}

impl<S: PacketSource + 'static> ExecutionPlan for ProtocolStreamExec<S> {
    fn name(&self) -> &str {
        "ProtocolStreamExec"
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
        vec![] // Leaf node
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
        let range = self.partitions.get(partition).ok_or_else(|| {
            datafusion::error::DataFusionError::Internal(format!(
                "Partition {} out of range (max {})",
                partition,
                self.partitions.len()
            ))
        })?;

        // Create reader for this partition's range
        let reader = self
            .source
            .reader(Some(range))
            .map_err(|e| datafusion::error::DataFusionError::External(Box::new(e)))?;

        let stream = ProtocolBatchStream::new(
            self.table_name.clone(),
            self.schema.clone(),
            reader,
            self.registry.clone(),
            self.source.metadata().link_type,
            self.batch_size,
            self.projection.clone(),
            self.cache.clone(),
        )
        .map_err(|e| datafusion::error::DataFusionError::External(Box::new(e)))?;

        Ok(Box::pin(stream))
    }
}

impl<S: PacketSource> DisplayAs for ProtocolStreamExec<S> {
    fn fmt_as(&self, t: DisplayFormatType, f: &mut fmt::Formatter) -> fmt::Result {
        match t {
            DisplayFormatType::Default | DisplayFormatType::Verbose => {
                write!(
                    f,
                    "ProtocolStreamExec: table={}, partitions={}, batch_size={}",
                    self.table_name,
                    self.partitions.len(),
                    self.batch_size
                )
            }
        }
    }
}

impl<S: PacketSource> fmt::Debug for ProtocolStreamExec<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtocolStreamExec")
            .field("table_name", &self.table_name)
            .field("partitions", &self.partitions.len())
            .field("batch_size", &self.batch_size)
            .finish()
    }
}
