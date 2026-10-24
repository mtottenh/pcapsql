//! Partition-aware scan execution plan for a protocol table.
//!
//! Serves a table either from pre-materialized per-partition batches
//! (`CacheOnTouch` cache, stream-pass tables) or from per-partition streaming
//! receivers fed by a concurrent parse (`RetentionPolicy::None`). Either way
//! it reports the real partition count and declares `frame_number` (and,
//! for protocol tables, `encap_depth`) output ordering so cross-partition
//! sort-merge joins reassemble global order without extra sorting.
//!
//! A table that was not prepared for the query being planned (EXPLAIN, a
//! query issued directly on the session context) gets a *plan-only* scan: it
//! has the table's schema and a nominal partition count so the plan can be
//! built and displayed, and fails if executed.

use std::any::Any;
use std::fmt;
use std::sync::{Arc, Mutex};

use arrow::compute::SortOptions;
use arrow::datatypes::SchemaRef;
use arrow::record_batch::RecordBatch;
use datafusion::common::stats::Precision;
use datafusion::error::{DataFusionError, Result as DFResult};
use datafusion::execution::context::TaskContext;
use datafusion::physical_expr::{EquivalenceProperties, PhysicalSortExpr};
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, Partitioning, PlanProperties,
    SendableRecordBatchStream, Statistics,
};
use futures::stream;
use futures::StreamExt;

use super::exchange::BatchReceiver;

/// Per-partition batch receiver, taken once at `execute`.
type ReceiverSlot = Mutex<Option<BatchReceiver>>;

/// Where a scan's rows come from.
enum ScanSource {
    /// Pre-materialized: one `Vec<RecordBatch>` per partition (frame order).
    Batches(Arc<Vec<Vec<RecordBatch>>>),
    /// Streamed: one batch receiver per partition, taken once each.
    Streams(Arc<Vec<ReceiverSlot>>),
    /// Not prepared for this query: plannable, not executable.
    Unprepared { partitions: usize },
}

impl ScanSource {
    fn num_partitions(&self) -> usize {
        match self {
            ScanSource::Batches(p) => p.len(),
            ScanSource::Streams(r) => r.len(),
            ScanSource::Unprepared { partitions } => *partitions,
        }
    }
}

/// Execution plan that emits a protocol table's batches, one DataFusion
/// partition per parse partition.
pub struct ProtocolScanExec {
    table_name: String,
    source: ScanSource,
    /// The materialized data's schema (what the batches/streams carry).
    data_schema: SchemaRef,
    /// Output schema after `projection` (a subset of `data_schema`).
    projected_schema: SchemaRef,
    projection: Option<Vec<usize>>,
    properties: PlanProperties,
}

impl ProtocolScanExec {
    /// Scan over pre-materialized per-partition batches.
    pub fn batches(
        table_name: String,
        data_schema: SchemaRef,
        partitions: Arc<Vec<Vec<RecordBatch>>>,
        projection: Option<Vec<usize>>,
    ) -> Self {
        Self::new(
            table_name,
            data_schema,
            ScanSource::Batches(partitions),
            projection,
        )
    }

    /// Scan over per-partition streaming receivers.
    pub fn streaming(
        table_name: String,
        data_schema: SchemaRef,
        receivers: Arc<Vec<ReceiverSlot>>,
        projection: Option<Vec<usize>>,
    ) -> Self {
        Self::new(
            table_name,
            data_schema,
            ScanSource::Streams(receivers),
            projection,
        )
    }

    /// Mark the scan as reading an unbounded stream (a continuous engine):
    /// DataFusion then refuses operators that need the whole input, and the
    /// fused streaming window aggregate takes over `GROUP BY window_start`.
    pub fn unbounded(mut self) -> Self {
        self.properties = self.properties.with_boundedness(Boundedness::Unbounded {
            requires_infinite_memory: false,
        });
        self
    }

    /// Whether the scan reads an unbounded stream.
    pub fn is_unbounded(&self) -> bool {
        self.properties.boundedness.is_unbounded()
    }

    /// Plan-only scan over the table's full schema for a table that was not
    /// prepared for the query being planned. `partitions` is the nominal
    /// partition count to display; `execute` fails.
    pub fn plan_only(
        table_name: String,
        schema: SchemaRef,
        projection: Option<Vec<usize>>,
        partitions: usize,
    ) -> Self {
        Self::new(
            table_name,
            schema,
            ScanSource::Unprepared { partitions },
            projection,
        )
    }

    fn new(
        table_name: String,
        data_schema: SchemaRef,
        source: ScanSource,
        projection: Option<Vec<usize>>,
    ) -> Self {
        let projected_schema = match &projection {
            Some(idx) => Arc::new(data_schema.project(idx).expect("valid projection")),
            None => data_schema.clone(),
        };
        let num_partitions = source.num_partitions().max(1);
        let eq_props = Self::compute_equivalence_properties(&projected_schema);
        let properties = PlanProperties::new(
            eq_props,
            Partitioning::UnknownPartitioning(num_partitions),
            EmissionType::Incremental,
            Boundedness::Bounded,
        );
        Self {
            table_name,
            source,
            data_schema,
            projected_schema,
            projection,
            properties,
        }
    }

    /// The parser appends a frame's rows in layer order, outer first, so a
    /// protocol table is ordered by `(frame_number, encap_depth)`; `frames`
    /// has no depth and is ordered by `frame_number`. The views join on both
    /// columns, and declaring the pair keeps a sort from being planned under
    /// their sort-merge joins.
    fn compute_equivalence_properties(schema: &SchemaRef) -> EquivalenceProperties {
        use datafusion::physical_expr::expressions::col;
        let mut eq_props = EquivalenceProperties::new(schema.clone());
        let ordering: Vec<PhysicalSortExpr> = ["frame_number", "encap_depth"]
            .iter()
            .map_while(|name| col(name, schema).ok())
            .map(|expr| PhysicalSortExpr {
                expr,
                options: SortOptions {
                    descending: false,
                    nulls_first: false,
                },
            })
            .collect();
        if !ordering.is_empty() {
            eq_props.add_orderings(vec![ordering]);
        }
        eq_props
    }

    /// Project a batch to the output schema (no-op when unprojected).
    fn project(projection: &Option<Vec<usize>>, batch: RecordBatch) -> DFResult<RecordBatch> {
        match projection {
            Some(indices) => batch
                .project(indices)
                .map_err(|e| DataFusionError::ArrowError(Box::new(e), None)),
            None => Ok(batch),
        }
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
        let projection = self.projection.clone();
        match &self.source {
            ScanSource::Batches(partitions) => {
                let batches = partitions.get(partition).cloned().unwrap_or_default();
                let iter = batches
                    .into_iter()
                    .map(move |batch| Self::project(&projection, batch));
                Ok(Box::pin(RecordBatchStreamAdapter::new(
                    self.projected_schema.clone(),
                    stream::iter(iter),
                )))
            }
            ScanSource::Streams(receivers) => {
                let rx = receivers
                    .get(partition)
                    .and_then(|slot| slot.lock().expect("receiver lock").take())
                    .ok_or_else(|| {
                        DataFusionError::Execution(format!(
                            "ProtocolScanExec: stream for table '{}' partition {} \
                             already consumed (a streamed table must be scanned once)",
                            self.table_name, partition
                        ))
                    })?;
                let s = stream::unfold(rx, |mut rx| async move {
                    rx.recv().await.map(|item| (item, rx))
                })
                .map(move |item| item.and_then(|b| Self::project(&projection, b)));
                Ok(Box::pin(RecordBatchStreamAdapter::new(
                    self.projected_schema.clone(),
                    s,
                )))
            }
            ScanSource::Unprepared { .. } => Err(DataFusionError::Execution(format!(
                "table '{}' was not prepared for this query; \
                 run queries through QueryEngine::query",
                self.table_name
            ))),
        }
    }

    fn partition_statistics(&self, partition: Option<usize>) -> DFResult<Statistics> {
        // Exact only for materialized batches; streamed row counts are not
        // known until the parse completes.
        let num_rows = match &self.source {
            ScanSource::Batches(partitions) => {
                let rows: usize = match partition {
                    Some(i) => partitions
                        .get(i)
                        .map(|p| p.iter().map(|b| b.num_rows()).sum())
                        .unwrap_or(0),
                    None => partitions
                        .iter()
                        .flat_map(|p| p.iter())
                        .map(|b| b.num_rows())
                        .sum(),
                };
                Precision::Exact(rows)
            }
            ScanSource::Streams(_) | ScanSource::Unprepared { .. } => Precision::Absent,
        };
        Ok(Statistics {
            num_rows,
            total_byte_size: Precision::Absent,
            column_statistics: Statistics::unknown_column(&self.projected_schema),
        })
    }
}

impl DisplayAs for ProtocolScanExec {
    fn fmt_as(&self, t: DisplayFormatType, f: &mut fmt::Formatter) -> fmt::Result {
        match t {
            DisplayFormatType::Default
            | DisplayFormatType::Verbose
            | DisplayFormatType::TreeRender => {
                let mode = match self.source {
                    ScanSource::Batches(_) => "batches",
                    ScanSource::Streams(_) => "stream",
                    ScanSource::Unprepared { .. } => "plan-only",
                };
                write!(
                    f,
                    "ProtocolScanExec: table={}, mode={mode}, partitions={}{}",
                    self.table_name,
                    self.source.num_partitions(),
                    if self.is_unbounded() {
                        ", unbounded"
                    } else {
                        ""
                    }
                )
            }
        }
    }
}

impl fmt::Debug for ProtocolScanExec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtocolScanExec")
            .field("table_name", &self.table_name)
            .field("partitions", &self.source.num_partitions())
            .field("data_schema", &self.data_schema)
            .finish()
    }
}
