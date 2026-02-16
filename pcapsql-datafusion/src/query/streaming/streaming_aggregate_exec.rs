//! Streaming window aggregate execution plan.
//!
//! `StreamingWindowAggregateExec` fuses window assignment and aggregation for
//! unbounded sources. It reads batches from the child (protocol stream), assigns
//! each row to window(s), accumulates aggregate values per (window, group), and
//! emits result batches when windows close based on watermark advancement.

use std::any::Any;
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use arrow::array::{ArrayRef, RecordBatch, TimestampMicrosecondArray};
use arrow::datatypes::SchemaRef;
use datafusion::error::{DataFusionError, Result as DFResult};
use datafusion::execution::context::TaskContext;
use datafusion::physical_expr::aggregate::AggregateFunctionExpr;
use datafusion::physical_expr::EquivalenceProperties;
use datafusion::physical_expr_common::physical_expr::PhysicalExpr;
use datafusion::physical_plan::aggregates::PhysicalGroupBy;
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, Partitioning, PlanProperties,
    SendableRecordBatchStream,
};
use futures::{Stream, StreamExt};

use pcapsql_core::windowing::{
    HoppingWindowAssigner, TumblingWindowAssigner, WatermarkConfig, WatermarkGenerator, WindowType,
};

use super::window_state::{GroupKey, WindowStateManager};

/// Streaming window aggregate execution plan.
///
/// Replaces the `AggregateExec → WindowAssignExec` pattern for unbounded sources.
/// Uses watermark-driven window management to emit results incrementally.
#[derive(Debug)]
pub struct StreamingWindowAggregateExec {
    /// Child execution plan (the original data source, before window assignment).
    child: Arc<dyn ExecutionPlan>,
    /// Window specification (tumble or hop).
    window_type: WindowType,
    /// Timestamp column name.
    timestamp_col: String,
    /// Group-by expressions from the original AggregateExec.
    group_by: PhysicalGroupBy,
    /// Aggregate expressions from the original AggregateExec.
    aggr_exprs: Vec<Arc<AggregateFunctionExpr>>,
    /// Output schema (matching what AggregateExec would have produced).
    output_schema: SchemaRef,
    /// Plan properties.
    properties: PlanProperties,
}

impl StreamingWindowAggregateExec {
    pub fn new(
        child: Arc<dyn ExecutionPlan>,
        window_type: WindowType,
        timestamp_col: String,
        group_by: PhysicalGroupBy,
        aggr_exprs: Vec<Arc<AggregateFunctionExpr>>,
        output_schema: SchemaRef,
    ) -> Self {
        let eq_props = EquivalenceProperties::new(output_schema.clone());
        // This operator can process unbounded streams with bounded memory
        // (windows are closed and evicted as watermark advances).
        let properties = PlanProperties::new(
            eq_props,
            Partitioning::UnknownPartitioning(child.properties().partitioning.partition_count()),
            EmissionType::Incremental,
            Boundedness::Unbounded {
                requires_infinite_memory: false,
            },
        );

        Self {
            child,
            window_type,
            timestamp_col,
            group_by,
            aggr_exprs,
            output_schema,
            properties,
        }
    }
}

impl ExecutionPlan for StreamingWindowAggregateExec {
    fn name(&self) -> &str {
        "StreamingWindowAggregateExec"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> SchemaRef {
        self.output_schema.clone()
    }

    fn properties(&self) -> &PlanProperties {
        &self.properties
    }

    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        vec![&self.child]
    }

    fn with_new_children(
        self: Arc<Self>,
        children: Vec<Arc<dyn ExecutionPlan>>,
    ) -> DFResult<Arc<dyn ExecutionPlan>> {
        if children.len() != 1 {
            return Err(DataFusionError::Internal(
                "StreamingWindowAggregateExec expects exactly 1 child".to_string(),
            ));
        }
        Ok(Arc::new(Self::new(
            children[0].clone(),
            self.window_type.clone(),
            self.timestamp_col.clone(),
            self.group_by.clone(),
            self.aggr_exprs.clone(),
            self.output_schema.clone(),
        )))
    }

    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> DFResult<SendableRecordBatchStream> {
        let child_stream = self.child.execute(partition, context)?;

        let stream = StreamingWindowAggregateStream::new(
            child_stream,
            self.window_type.clone(),
            self.timestamp_col.clone(),
            self.group_by.clone(),
            self.aggr_exprs.clone(),
            self.output_schema.clone(),
        )?;

        Ok(Box::pin(stream))
    }
}

impl DisplayAs for StreamingWindowAggregateExec {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut fmt::Formatter) -> fmt::Result {
        let group_exprs: Vec<String> = self
            .group_by
            .expr()
            .iter()
            .map(|(_, alias)| alias.clone())
            .collect();
        let agg_names: Vec<String> = self
            .aggr_exprs
            .iter()
            .map(|e| e.name().to_string())
            .collect();
        write!(
            f,
            "StreamingWindowAggregateExec: window={}, groups=[{}], aggrs=[{}]",
            self.window_type,
            group_exprs.join(", "),
            agg_names.join(", "),
        )
    }
}

/// The streaming aggregate stream that processes batches and emits results.
struct StreamingWindowAggregateStream {
    /// Child data stream.
    child_stream: SendableRecordBatchStream,
    /// Window type for assignment.
    window_type: WindowType,
    /// Timestamp column name in child schema.
    timestamp_col: String,
    /// Group-by expressions.
    group_by_exprs: Vec<(Arc<dyn PhysicalExpr>, String)>,
    /// Aggregate expressions (for evaluating input values).
    aggr_exprs: Vec<Arc<AggregateFunctionExpr>>,
    /// Window state manager.
    state_manager: WindowStateManager,
    /// Watermark generator.
    watermark: WatermarkGenerator,
    /// Output schema.
    output_schema: SchemaRef,
    /// Pending result batches to emit.
    pending_results: Vec<RecordBatch>,
    /// Whether the child stream has ended.
    child_exhausted: bool,
    /// Whether we've flushed remaining windows after child exhaustion.
    flushed: bool,
}

impl StreamingWindowAggregateStream {
    fn new(
        child_stream: SendableRecordBatchStream,
        window_type: WindowType,
        timestamp_col: String,
        group_by: PhysicalGroupBy,
        aggr_exprs: Vec<Arc<AggregateFunctionExpr>>,
        output_schema: SchemaRef,
    ) -> DFResult<Self> {
        let state_manager =
            WindowStateManager::new(aggr_exprs.clone(), &group_by, output_schema.clone());
        let watermark = WatermarkGenerator::new(WatermarkConfig::for_file());

        Ok(Self {
            child_stream,
            window_type,
            timestamp_col,
            group_by_exprs: group_by.expr().to_vec(),
            aggr_exprs,
            state_manager,
            watermark,
            output_schema,
            pending_results: Vec::new(),
            child_exhausted: false,
            flushed: false,
        })
    }

    /// Process a batch from the child stream.
    fn process_batch(&mut self, batch: &RecordBatch) -> DFResult<()> {
        if batch.num_rows() == 0 {
            return Ok(());
        }

        // Find timestamp column
        let ts_idx = batch.schema().index_of(&self.timestamp_col).map_err(|_| {
            DataFusionError::Execution(format!(
                "Timestamp column '{}' not found in child schema",
                self.timestamp_col,
            ))
        })?;

        let ts_array = batch
            .column(ts_idx)
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .ok_or_else(|| {
                DataFusionError::Execution(format!(
                    "Timestamp column '{}' is not TimestampMicrosecond type",
                    self.timestamp_col,
                ))
            })?;

        // Evaluate aggregate input expressions once for the whole batch
        let agg_input_arrays: Vec<ArrayRef> = self
            .aggr_exprs
            .iter()
            .map(|expr| {
                // Get the input expressions for this aggregate
                let input_exprs = expr.expressions();
                if input_exprs.is_empty() {
                    // COUNT(*) has no input expressions — use a dummy array
                    Ok(
                        Arc::new(arrow::array::UInt8Array::from(vec![1u8; batch.num_rows()]))
                            as ArrayRef,
                    )
                } else {
                    // Evaluate the first input expression
                    let result = input_exprs[0].evaluate(batch)?;
                    Ok(result.into_array(batch.num_rows())?)
                }
            })
            .collect::<DFResult<_>>()?;

        // Process each row
        let prev_watermark = self.watermark.current();

        for row_idx in 0..batch.num_rows() {
            let ts = ts_array.value(row_idx);

            // Skip late events
            if self.watermark.is_late(ts) {
                continue;
            }

            // Assign to window(s)
            let windows = match &self.window_type {
                WindowType::Tumble { size } => {
                    let assigner = TumblingWindowAssigner::new(*size);
                    vec![assigner.assign(ts)]
                }
                WindowType::Hop { slide, size } => {
                    let assigner = HoppingWindowAssigner::new(*slide, *size);
                    assigner.assign(ts)
                }
                WindowType::Session { .. } => {
                    return Err(DataFusionError::NotImplemented(
                        "Session windows in streaming mode are not yet supported. \
                         Use session() with bounded (file) sources."
                            .to_string(),
                    ));
                }
            };

            // Extract group key (excluding window_start/window_end which aren't in child schema)
            // Filter out group expressions that reference window columns
            let group_key = self.extract_group_key_from_child(batch, row_idx)?;

            // Accumulate into each window
            for window in windows {
                self.state_manager.accumulate(
                    window,
                    group_key.clone(),
                    &agg_input_arrays,
                    row_idx,
                )?;
            }

            // Update watermark
            self.watermark.observe(ts);
        }

        // Check if watermark advanced enough to close windows
        let current_wm = self.watermark.current();
        if current_wm > prev_watermark {
            if let Some(batch) = self.state_manager.close_windows(current_wm.as_micros())? {
                self.pending_results.push(batch);
            }
        }

        Ok(())
    }

    /// Extract a group key from child batch columns, excluding window columns.
    ///
    /// The group-by expressions from AggregateExec may include references to
    /// window_start and window_end. Since we're processing the child batch
    /// (before window assignment), we need to handle these specially.
    fn extract_group_key_from_child(
        &self,
        batch: &RecordBatch,
        row_idx: usize,
    ) -> DFResult<GroupKey> {
        let mut key_values = Vec::with_capacity(self.group_by_exprs.len());
        for (expr, alias) in &self.group_by_exprs {
            // Skip window_start and window_end — they're handled separately
            // in the state manager
            if alias == "window_start" || alias == "window_end" {
                continue;
            }
            let array = expr.evaluate(batch)?.into_array(batch.num_rows())?;
            let scalar = datafusion::common::ScalarValue::try_from_array(&array, row_idx)?;
            key_values.push(scalar);
        }
        Ok(GroupKey::new(key_values))
    }
}

impl Stream for StreamingWindowAggregateStream {
    type Item = DFResult<RecordBatch>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // First, drain any pending results
        if !self.pending_results.is_empty() {
            return Poll::Ready(Some(Ok(self.pending_results.remove(0))));
        }

        // If we've already flushed, we're done
        if self.flushed {
            return Poll::Ready(None);
        }

        // If child is exhausted, flush remaining windows
        if self.child_exhausted {
            self.flushed = true;
            match self.state_manager.flush_all() {
                Ok(Some(batch)) => return Poll::Ready(Some(Ok(batch))),
                Ok(None) => return Poll::Ready(None),
                Err(e) => return Poll::Ready(Some(Err(e))),
            }
        }

        // Poll for next batch from child
        match self.child_stream.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(batch))) => {
                if let Err(e) = self.process_batch(&batch) {
                    return Poll::Ready(Some(Err(e)));
                }
                // Check for pending results after processing
                if !self.pending_results.is_empty() {
                    Poll::Ready(Some(Ok(self.pending_results.remove(0))))
                } else {
                    // No windows closed yet, keep polling
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => {
                // Child exhausted — flush remaining windows
                self.child_exhausted = true;
                self.flushed = true;
                match self.state_manager.flush_all() {
                    Ok(Some(batch)) => Poll::Ready(Some(Ok(batch))),
                    Ok(None) => Poll::Ready(None),
                    Err(e) => Poll::Ready(Some(Err(e))),
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl datafusion::physical_plan::RecordBatchStream for StreamingWindowAggregateStream {
    fn schema(&self) -> SchemaRef {
        self.output_schema.clone()
    }
}
