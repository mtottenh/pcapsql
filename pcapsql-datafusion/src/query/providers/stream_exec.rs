//! Streaming execution plan for protocol tables.

use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use arrow::compute::SortOptions;
use arrow::datatypes::SchemaRef;
use datafusion::error::Result as DFResult;
use datafusion::execution::context::TaskContext;
use datafusion::physical_expr::{EquivalenceProperties, PhysicalSortExpr};
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, Partitioning, PlanProperties,
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
///
/// # Limit Pushdown
///
/// When a limit is provided, the stream will stop reading packets
/// once the limit is satisfied, avoiding unnecessary parsing work.
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
    /// Optional row limit for limit pushdown optimization
    limit: Option<usize>,
    /// Optional set of required protocols for pruning optimization.
    /// When set, only protocols in this set (and their dependencies) will be parsed.
    required_protocols: Option<Arc<HashSet<String>>>,
    /// Optional per-protocol field projections.
    /// When set, only specified fields are extracted for each protocol.
    field_projections: Option<Arc<HashMap<String, HashSet<String>>>>,
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
        limit: Option<usize>,
    ) -> Self {
        Self::new_with_pruning(
            table_name,
            schema,
            source,
            registry,
            partitions,
            batch_size,
            projection,
            cache,
            limit,
            None,
        )
    }

    /// Create a new streaming execution plan with protocol pruning.
    ///
    /// When `required_protocols` is provided, only protocols in that set
    /// (and their dependencies) will be parsed, reducing CPU usage for
    /// selective queries.
    pub fn new_with_pruning(
        table_name: String,
        schema: SchemaRef,
        source: Arc<S>,
        registry: Arc<ProtocolRegistry>,
        partitions: Vec<PacketRange>,
        batch_size: usize,
        projection: Option<Vec<usize>>,
        cache: Option<Arc<dyn ParseCache>>,
        limit: Option<usize>,
        required_protocols: Option<Arc<HashSet<String>>>,
    ) -> Self {
        Self::new_with_optimizations(
            table_name,
            schema,
            source,
            registry,
            partitions,
            batch_size,
            projection,
            cache,
            limit,
            required_protocols,
            None,
        )
    }

    /// Create a new streaming execution plan with all optimizations.
    ///
    /// This constructor supports both protocol pruning and field projection:
    /// - Protocol pruning: Only parse protocols in the required set
    /// - Field projection: Only extract needed fields within each protocol
    pub fn new_with_optimizations(
        table_name: String,
        schema: SchemaRef,
        source: Arc<S>,
        registry: Arc<ProtocolRegistry>,
        partitions: Vec<PacketRange>,
        batch_size: usize,
        projection: Option<Vec<usize>>,
        cache: Option<Arc<dyn ParseCache>>,
        limit: Option<usize>,
        required_protocols: Option<Arc<HashSet<String>>>,
        field_projections: Option<Arc<HashMap<String, HashSet<String>>>>,
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
            EmissionType::Incremental,
            Boundedness::Bounded,
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
            limit,
            required_protocols,
            field_projections,
        }
    }

    fn compute_equivalence_properties(schema: &SchemaRef) -> EquivalenceProperties {
        let mut eq_props = EquivalenceProperties::new(schema.clone());

        // Declare that output is sorted by frame_number (if present in schema)
        if schema.index_of("frame_number").is_ok() {
            use datafusion::physical_expr::expressions::col;

            if let Ok(col_expr) = col("frame_number", schema) {
                let sort_expr = PhysicalSortExpr {
                    expr: col_expr,
                    options: SortOptions {
                        descending: false,
                        nulls_first: false,
                    },
                };
                // reorder() mutates in place and returns Result<bool>
                let _ = eq_props.reorder(vec![sort_expr]);
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

        let stream = ProtocolBatchStream::new_with_field_projections(
            self.table_name.clone(),
            self.schema.clone(),
            reader,
            self.registry.clone(),
            self.source.metadata().link_type,
            self.batch_size,
            self.projection.clone(),
            self.cache.clone(),
            self.limit,
            self.required_protocols.clone(),
            self.field_projections.clone(),
        )
        .map_err(|e| datafusion::error::DataFusionError::External(Box::new(e)))?;

        Ok(Box::pin(stream))
    }
}

impl<S: PacketSource> ProtocolStreamExec<S> {
    /// Get the required protocols set for this execution plan.
    pub fn required_protocols(&self) -> Option<&HashSet<String>> {
        self.required_protocols.as_ref().map(|arc| arc.as_ref())
    }

    /// Get the field projections for this execution plan.
    pub fn field_projections(&self) -> Option<&HashMap<String, HashSet<String>>> {
        self.field_projections.as_ref().map(|arc| arc.as_ref())
    }
}

impl<S: PacketSource> DisplayAs for ProtocolStreamExec<S> {
    fn fmt_as(&self, t: DisplayFormatType, f: &mut fmt::Formatter) -> fmt::Result {
        match t {
            DisplayFormatType::Default | DisplayFormatType::Verbose | DisplayFormatType::TreeRender => {
                write!(
                    f,
                    "ProtocolStreamExec: table={}, partitions={}, batch_size={}",
                    self.table_name,
                    self.partitions.len(),
                    self.batch_size
                )?;
                if let Some(limit) = self.limit {
                    write!(f, ", limit={}", limit)?;
                }
                if self.field_projections.is_some() {
                    write!(f, ", field_projection=true")?;
                }
                Ok(())
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
            .field("limit", &self.limit)
            .finish()
    }
}
