//! Session window assignment execution plan.
//!
//! `SessionAssignExec` buffers all input data, detects sessions per key,
//! and emits output with `window_start` and `window_end` columns.
//!
//! Unlike `WindowAssignExec` (which processes per-batch), session windows
//! require seeing all events for a key to determine final session boundaries.
//! This exec collects all input, runs session detection, and emits the result.

use std::any::Any;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use arrow::array::{Array, RecordBatch, StringArray, TimestampMicrosecondArray};
use arrow::compute::concat_batches;
use arrow::datatypes::SchemaRef;
use datafusion::common::ScalarValue;
use datafusion::error::Result as DFResult;
use datafusion::execution::context::TaskContext;
use datafusion::physical_expr::EquivalenceProperties;
use datafusion::physical_plan::coalesce_partitions::CoalescePartitionsExec;
use datafusion::physical_plan::execution_plan::EmissionType;
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, Partitioning, PlanProperties,
    SendableRecordBatchStream,
};
use futures::StreamExt;

use pcapsql_core::windowing::session::detect_sessions;

use super::window_exec::build_window_schema;

/// Execution plan that assigns session windows to each row.
///
/// Buffers all input data, detects sessions per key based on timestamp
/// gaps, and emits output with `window_start` and `window_end` columns.
#[derive(Debug)]
pub struct SessionAssignExec {
    /// Child execution plan providing the input data.
    child: Arc<dyn ExecutionPlan>,
    /// Name of the key column for session partitioning.
    key_col: String,
    /// Name of the timestamp column.
    timestamp_col: String,
    /// Session gap duration.
    gap: Duration,
    /// Output schema (window_start, window_end, + child columns).
    output_schema: SchemaRef,
    /// Plan properties.
    properties: PlanProperties,
}

impl SessionAssignExec {
    pub fn new(
        child: Arc<dyn ExecutionPlan>,
        key_col: String,
        timestamp_col: String,
        gap: Duration,
    ) -> Self {
        // Session windows require seeing ALL events for a key to determine
        // session boundaries. If the child has multiple partitions (e.g., from
        // a JOIN), we must coalesce them into a single partition first.
        let coalesced: Arc<dyn ExecutionPlan> =
            if child.properties().partitioning.partition_count() > 1 {
                Arc::new(CoalescePartitionsExec::new(child))
            } else {
                child
            };

        let child_schema = coalesced.schema();
        let output_schema = build_window_schema(&child_schema);

        let eq_props = EquivalenceProperties::new(output_schema.clone());
        let properties = PlanProperties::new(
            eq_props,
            // Session detection always produces a single partition
            Partitioning::UnknownPartitioning(1),
            EmissionType::Final,
            coalesced.properties().boundedness,
        );

        Self {
            child: coalesced,
            key_col,
            timestamp_col,
            gap,
            output_schema,
            properties,
        }
    }
}

impl ExecutionPlan for SessionAssignExec {
    fn name(&self) -> &str {
        "SessionAssignExec"
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
                "SessionAssignExec expects exactly 1 child".to_string(),
            ));
        }
        Ok(Arc::new(SessionAssignExec::new(
            children[0].clone(),
            self.key_col.clone(),
            self.timestamp_col.clone(),
            self.gap,
        )))
    }

    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> DFResult<SendableRecordBatchStream> {
        let child_stream = self.child.execute(partition, context)?;
        let output_schema = self.output_schema.clone();
        let child_schema = self.child.schema();
        let key_col = self.key_col.clone();
        let timestamp_col = self.timestamp_col.clone();
        let gap_us = self.gap.as_micros() as i64;

        let stream = futures::stream::once(async move {
            // Collect all batches from child
            let batches: Vec<RecordBatch> = child_stream
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .collect::<DFResult<Vec<_>>>()?;

            if batches.is_empty() {
                return Ok(RecordBatch::new_empty(output_schema));
            }

            // Concatenate all batches
            let combined = concat_batches(&child_schema, &batches)
                .map_err(|e| datafusion::error::DataFusionError::ArrowError(Box::new(e), None))?;

            if combined.num_rows() == 0 {
                return Ok(RecordBatch::new_empty(output_schema));
            }

            // Extract key and timestamp columns
            let key_idx = combined.schema().index_of(&key_col).map_err(|_| {
                datafusion::error::DataFusionError::Execution(format!(
                    "Session key column '{key_col}' not found in input schema"
                ))
            })?;

            let ts_idx = combined.schema().index_of(&timestamp_col).map_err(|_| {
                datafusion::error::DataFusionError::Execution(format!(
                    "Timestamp column '{timestamp_col}' not found in input schema"
                ))
            })?;

            let ts_array = combined
                .column(ts_idx)
                .as_any()
                .downcast_ref::<TimestampMicrosecondArray>()
                .ok_or_else(|| {
                    datafusion::error::DataFusionError::Execution(format!(
                        "Timestamp column '{timestamp_col}' is not TimestampMicrosecond type"
                    ))
                })?;

            // Extract key values as strings for session detection.
            // We use ScalarValue for generic key support.
            let key_array = combined.column(key_idx);
            let keys = extract_key_values(key_array, &key_col)?;
            let timestamps: Vec<i64> = (0..combined.num_rows())
                .map(|i| ts_array.value(i))
                .collect();

            // Detect sessions
            let bounds = detect_sessions(&keys, &timestamps, gap_us);

            // Build output batch with window columns
            let mut starts = Vec::with_capacity(bounds.len());
            let mut ends = Vec::with_capacity(bounds.len());
            for b in &bounds {
                starts.push(b.start);
                ends.push(b.end);
            }

            let start_array = TimestampMicrosecondArray::from(starts);
            let end_array = TimestampMicrosecondArray::from(ends);

            let mut columns: Vec<Arc<dyn Array>> = Vec::with_capacity(2 + combined.num_columns());
            columns.push(Arc::new(start_array));
            columns.push(Arc::new(end_array));
            columns.extend(combined.columns().iter().cloned());

            RecordBatch::try_new(output_schema, columns)
                .map_err(|e| datafusion::error::DataFusionError::ArrowError(Box::new(e), None))
        });

        Ok(Box::pin(RecordBatchStreamAdapter::new(
            self.output_schema.clone(),
            stream,
        )))
    }
}

impl DisplayAs for SessionAssignExec {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "SessionAssignExec: key={}, timestamp={}, gap={}s",
            self.key_col,
            self.timestamp_col,
            self.gap.as_secs()
        )
    }
}

/// Extract key values from an array as ScalarValue strings for hashing.
///
/// Converts various arrow data types to string representations that can
/// be used as HashMap keys for session detection.
fn extract_key_values(array: &dyn Array, col_name: &str) -> DFResult<Vec<ScalarValue>> {
    let len = array.len();
    let mut keys = Vec::with_capacity(len);

    // Try to extract as StringArray first (most common for IP addresses, etc.)
    if let Some(str_array) = array.as_any().downcast_ref::<StringArray>() {
        for i in 0..len {
            if str_array.is_null(i) {
                keys.push(ScalarValue::Utf8(None));
            } else {
                keys.push(ScalarValue::Utf8(Some(str_array.value(i).to_string())));
            }
        }
        return Ok(keys);
    }

    // Generic fallback: use ScalarValue::try_from_array
    for i in 0..len {
        let scalar = ScalarValue::try_from_array(array, i).map_err(|e| {
            datafusion::error::DataFusionError::Execution(format!(
                "Failed to extract key value from column '{col_name}' at row {i}: {e}"
            ))
        })?;
        keys.push(scalar);
    }

    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::{Int64Array, UInt32Array};
    use arrow::datatypes::{DataType, Field, Schema, TimeUnit};

    #[test]
    fn test_build_session_output_schema() {
        let child_schema = Arc::new(Schema::new(vec![
            Field::new(
                "timestamp",
                DataType::Timestamp(TimeUnit::Microsecond, None),
                false,
            ),
            Field::new("src_ip", DataType::Utf8, true),
            Field::new("value", DataType::Int64, false),
        ]));

        let output = build_window_schema(&child_schema);
        assert_eq!(output.fields().len(), 5);
        assert_eq!(output.field(0).name(), "window_start");
        assert_eq!(output.field(1).name(), "window_end");
        assert_eq!(output.field(2).name(), "timestamp");
        assert_eq!(output.field(3).name(), "src_ip");
        assert_eq!(output.field(4).name(), "value");
    }

    #[test]
    fn test_extract_key_values_string() {
        let array = StringArray::from(vec![Some("A"), Some("B"), None, Some("A")]);
        let keys = extract_key_values(&array, "test").unwrap();
        assert_eq!(keys.len(), 4);
        assert_eq!(keys[0], ScalarValue::Utf8(Some("A".to_string())));
        assert_eq!(keys[1], ScalarValue::Utf8(Some("B".to_string())));
        assert_eq!(keys[2], ScalarValue::Utf8(None));
        assert_eq!(keys[3], ScalarValue::Utf8(Some("A".to_string())));
    }

    #[test]
    fn test_extract_key_values_uint32() {
        let array = UInt32Array::from(vec![1, 2, 3, 1]);
        let keys = extract_key_values(&array, "test").unwrap();
        assert_eq!(keys.len(), 4);
        assert_eq!(keys[0], ScalarValue::UInt32(Some(1)));
        assert_eq!(keys[3], ScalarValue::UInt32(Some(1)));
    }
}
