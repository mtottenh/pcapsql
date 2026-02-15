//! Window assignment execution plan.
//!
//! `WindowAssignExec` wraps a child execution plan and adds `window_start`
//! and `window_end` columns to each output batch based on the timestamp
//! column and window specification.

use std::any::Any;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use arrow::array::{RecordBatch, TimestampMicrosecondArray};
use arrow::datatypes::{DataType, Field, SchemaRef, TimeUnit};
use datafusion::error::Result as DFResult;
use datafusion::execution::context::TaskContext;
use datafusion::physical_expr::EquivalenceProperties;
use datafusion::physical_plan::execution_plan::EmissionType;
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, Partitioning, PlanProperties,
    SendableRecordBatchStream,
};
use futures::stream::StreamExt;

use pcapsql_core::windowing::{HoppingWindowAssigner, TumblingWindowAssigner, WindowType};

/// Execution plan that assigns window bounds to each row.
///
/// Adds `window_start` and `window_end` columns (Timestamp(Microsecond)) to
/// the output. For tumbling windows each row maps to exactly one window.
/// For hopping windows rows may be duplicated into multiple windows.
#[derive(Debug)]
pub struct WindowAssignExec {
    /// Child execution plan providing the input data.
    child: Arc<dyn ExecutionPlan>,
    /// Window specification.
    window_type: WindowType,
    /// Name of the timestamp column in the child schema.
    timestamp_col: String,
    /// Output schema (child schema + window_start + window_end).
    output_schema: SchemaRef,
    /// Plan properties.
    properties: PlanProperties,
}

impl WindowAssignExec {
    pub fn new(
        child: Arc<dyn ExecutionPlan>,
        window_type: WindowType,
        timestamp_col: String,
    ) -> Self {
        let child_schema = child.schema();
        let output_schema = build_window_schema(&child_schema);

        let eq_props = EquivalenceProperties::new(output_schema.clone());
        let properties = PlanProperties::new(
            eq_props,
            Partitioning::UnknownPartitioning(child.properties().partitioning.partition_count()),
            EmissionType::Incremental,
            child.properties().boundedness,
        );

        Self {
            child,
            window_type,
            timestamp_col,
            output_schema,
            properties,
        }
    }

    /// Get the window specification.
    /// Used by the streaming optimizer rule to extract window params.
    pub fn window_type(&self) -> &WindowType {
        &self.window_type
    }

    /// Get the timestamp column name.
    /// Used by the streaming optimizer rule to extract window params.
    pub fn timestamp_col(&self) -> &str {
        &self.timestamp_col
    }
}

impl ExecutionPlan for WindowAssignExec {
    fn name(&self) -> &str {
        "WindowAssignExec"
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
            return Err(datafusion::error::DataFusionError::Internal(
                "WindowAssignExec expects exactly 1 child".to_string(),
            ));
        }
        Ok(Arc::new(WindowAssignExec::new(
            children[0].clone(),
            self.window_type.clone(),
            self.timestamp_col.clone(),
        )))
    }

    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> DFResult<SendableRecordBatchStream> {
        let child_stream = self.child.execute(partition, context)?;
        let output_schema = self.output_schema.clone();
        let timestamp_col = self.timestamp_col.clone();
        let window_type = self.window_type.clone();

        let stream = futures::stream::unfold(
            (
                child_stream,
                output_schema.clone(),
                timestamp_col,
                window_type,
            ),
            |(mut child_stream, schema, ts_col, wt)| async move {
                match child_stream.next().await {
                    Some(Ok(batch)) => {
                        let result = assign_windows(&batch, &ts_col, &wt, &schema);
                        Some((result, (child_stream, schema, ts_col, wt)))
                    }
                    Some(Err(e)) => Some((Err(e), (child_stream, schema, ts_col, wt))),
                    None => None,
                }
            },
        );

        Ok(Box::pin(RecordBatchStreamAdapter::new(
            output_schema,
            stream,
        )))
    }
}

impl DisplayAs for WindowAssignExec {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "WindowAssignExec: window={}, timestamp_col={}",
            self.window_type, self.timestamp_col
        )
    }
}

/// Build output schema: window_start, window_end prepended to child columns.
pub fn build_window_schema(child_schema: &SchemaRef) -> SchemaRef {
    let mut fields = vec![
        Arc::new(Field::new(
            "window_start",
            DataType::Timestamp(TimeUnit::Microsecond, None),
            false,
        )),
        Arc::new(Field::new(
            "window_end",
            DataType::Timestamp(TimeUnit::Microsecond, None),
            false,
        )),
    ];
    fields.extend(child_schema.fields().iter().cloned());
    Arc::new(arrow::datatypes::Schema::new(fields))
}

/// Assign windows to a batch and produce an output batch with window columns.
fn assign_windows(
    batch: &RecordBatch,
    timestamp_col: &str,
    window_type: &WindowType,
    output_schema: &SchemaRef,
) -> DFResult<RecordBatch> {
    if batch.num_rows() == 0 {
        return Ok(RecordBatch::new_empty(output_schema.clone()));
    }

    // Find and extract timestamp column
    let ts_idx = batch.schema().index_of(timestamp_col).map_err(|_| {
        datafusion::error::DataFusionError::Execution(format!(
            "Timestamp column '{}' not found in input schema. Available columns: {:?}",
            timestamp_col,
            batch
                .schema()
                .fields()
                .iter()
                .map(|f| f.name().as_str())
                .collect::<Vec<_>>()
        ))
    })?;

    let ts_array = batch
        .column(ts_idx)
        .as_any()
        .downcast_ref::<TimestampMicrosecondArray>()
        .ok_or_else(|| {
            datafusion::error::DataFusionError::Execution(format!(
                "Timestamp column '{timestamp_col}' is not TimestampMicrosecond type"
            ))
        })?;

    match window_type {
        WindowType::Tumble { size } => assign_tumble_windows(batch, ts_array, *size, output_schema),
        WindowType::Hop { slide, size } => {
            assign_hop_windows(batch, ts_array, *slide, *size, output_schema)
        }
    }
}

/// Assign tumbling windows. Each row maps to exactly one window.
fn assign_tumble_windows(
    batch: &RecordBatch,
    ts_array: &TimestampMicrosecondArray,
    window_size: Duration,
    output_schema: &SchemaRef,
) -> DFResult<RecordBatch> {
    let assigner = TumblingWindowAssigner::new(window_size);
    let num_rows = batch.num_rows();

    let mut starts = Vec::with_capacity(num_rows);
    let mut ends = Vec::with_capacity(num_rows);

    for i in 0..num_rows {
        let ts = ts_array.value(i);
        let bounds = assigner.assign(ts);
        starts.push(bounds.start);
        ends.push(bounds.end);
    }

    let start_array = TimestampMicrosecondArray::from(starts);
    let end_array = TimestampMicrosecondArray::from(ends);

    // Build output: window_start, window_end, then all child columns
    let mut columns: Vec<Arc<dyn arrow::array::Array>> =
        Vec::with_capacity(2 + batch.num_columns());
    columns.push(Arc::new(start_array));
    columns.push(Arc::new(end_array));
    columns.extend(batch.columns().iter().cloned());

    RecordBatch::try_new(output_schema.clone(), columns)
        .map_err(|e| datafusion::error::DataFusionError::ArrowError(Box::new(e), None))
}

/// Assign hopping windows. Rows may be duplicated into multiple windows.
fn assign_hop_windows(
    batch: &RecordBatch,
    ts_array: &TimestampMicrosecondArray,
    slide: Duration,
    size: Duration,
    output_schema: &SchemaRef,
) -> DFResult<RecordBatch> {
    let assigner = HoppingWindowAssigner::new(slide, size);
    let num_rows = batch.num_rows();

    // For hop windows, each row can map to multiple windows.
    // We need to collect all (row_index, window_bounds) pairs.
    let mut row_indices: Vec<usize> = Vec::new();
    let mut starts: Vec<i64> = Vec::new();
    let mut ends: Vec<i64> = Vec::new();

    for i in 0..num_rows {
        let ts = ts_array.value(i);
        let windows = assigner.assign(ts);
        for w in windows {
            row_indices.push(i);
            starts.push(w.start);
            ends.push(w.end);
        }
    }

    let start_array = TimestampMicrosecondArray::from(starts);
    let end_array = TimestampMicrosecondArray::from(ends);

    // Use take() to duplicate rows according to row_indices
    let indices =
        arrow::array::UInt32Array::from(row_indices.iter().map(|&i| i as u32).collect::<Vec<_>>());

    let mut columns: Vec<Arc<dyn arrow::array::Array>> =
        Vec::with_capacity(2 + batch.num_columns());
    columns.push(Arc::new(start_array));
    columns.push(Arc::new(end_array));

    for col in batch.columns() {
        let taken = arrow::compute::take(col, &indices, None)
            .map_err(|e| datafusion::error::DataFusionError::ArrowError(Box::new(e), None))?;
        columns.push(taken);
    }

    RecordBatch::try_new(output_schema.clone(), columns)
        .map_err(|e| datafusion::error::DataFusionError::ArrowError(Box::new(e), None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::{Int64Array, UInt32Array};
    use arrow::datatypes::{Field, Schema};

    fn test_batch() -> RecordBatch {
        let schema = Arc::new(Schema::new(vec![
            Field::new(
                "timestamp",
                DataType::Timestamp(TimeUnit::Microsecond, None),
                false,
            ),
            Field::new("frame_number", DataType::UInt32, false),
            Field::new("value", DataType::Int64, false),
        ]));

        let ts = TimestampMicrosecondArray::from(vec![
            0,           // t=0s → window [0, 60s)
            30_000_000,  // t=30s → window [0, 60s)
            60_000_000,  // t=60s → window [60s, 120s)
            90_000_000,  // t=90s → window [60s, 120s)
            120_000_000, // t=120s → window [120s, 180s)
        ]);
        let frame = UInt32Array::from(vec![1, 2, 3, 4, 5]);
        let value = Int64Array::from(vec![10, 20, 30, 40, 50]);

        RecordBatch::try_new(schema, vec![Arc::new(ts), Arc::new(frame), Arc::new(value)]).unwrap()
    }

    #[test]
    fn test_tumble_window_assignment() {
        let batch = test_batch();
        let child_schema = batch.schema();
        let output_schema = build_window_schema(&child_schema);

        let result = assign_windows(
            &batch,
            "timestamp",
            &WindowType::tumble(Duration::from_secs(60)),
            &output_schema,
        )
        .unwrap();

        assert_eq!(result.num_rows(), 5);
        assert_eq!(result.num_columns(), 5); // window_start, window_end, ts, frame, value

        let starts = result
            .column(0)
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        let ends = result
            .column(1)
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();

        // First two rows: window [0, 60s)
        assert_eq!(starts.value(0), 0);
        assert_eq!(ends.value(0), 60_000_000);
        assert_eq!(starts.value(1), 0);
        assert_eq!(ends.value(1), 60_000_000);

        // Next two rows: window [60s, 120s)
        assert_eq!(starts.value(2), 60_000_000);
        assert_eq!(ends.value(2), 120_000_000);
        assert_eq!(starts.value(3), 60_000_000);
        assert_eq!(ends.value(3), 120_000_000);

        // Last row: window [120s, 180s)
        assert_eq!(starts.value(4), 120_000_000);
        assert_eq!(ends.value(4), 180_000_000);
    }

    #[test]
    fn test_hop_window_assignment() {
        let batch = test_batch();
        let child_schema = batch.schema();
        let output_schema = build_window_schema(&child_schema);

        // 60s window, 30s slide → each row in 2 windows
        let result = assign_windows(
            &batch,
            "timestamp",
            &WindowType::hop(Duration::from_secs(30), Duration::from_secs(60)),
            &output_schema,
        )
        .unwrap();

        // Each of the 5 rows should be in 2 windows → 10 output rows
        assert_eq!(result.num_rows(), 10);

        // Verify the value column was properly duplicated
        let values = result
            .column(4) // value is the 5th column (after window_start, window_end, timestamp, frame_number)
            .as_any()
            .downcast_ref::<Int64Array>()
            .unwrap();

        // First row (value=10) should appear twice
        assert_eq!(values.value(0), 10);
        assert_eq!(values.value(1), 10);
    }

    #[test]
    fn test_empty_batch() {
        let schema = Arc::new(Schema::new(vec![Field::new(
            "timestamp",
            DataType::Timestamp(TimeUnit::Microsecond, None),
            false,
        )]));
        let batch = RecordBatch::new_empty(schema.clone());
        let output_schema = build_window_schema(&schema);

        let result = assign_windows(
            &batch,
            "timestamp",
            &WindowType::tumble(Duration::from_secs(60)),
            &output_schema,
        )
        .unwrap();

        assert_eq!(result.num_rows(), 0);
    }

    #[test]
    fn test_build_window_schema() {
        let child_schema = Arc::new(Schema::new(vec![
            Field::new("frame_number", DataType::UInt32, false),
            Field::new("value", DataType::Int64, false),
        ]));

        let output = build_window_schema(&child_schema);
        assert_eq!(output.fields().len(), 4);
        assert_eq!(output.field(0).name(), "window_start");
        assert_eq!(output.field(1).name(), "window_end");
        assert_eq!(output.field(2).name(), "frame_number");
        assert_eq!(output.field(3).name(), "value");

        // Window columns should be Timestamp(Microsecond)
        assert_eq!(
            *output.field(0).data_type(),
            DataType::Timestamp(TimeUnit::Microsecond, None)
        );
    }
}
