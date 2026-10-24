//! Hopping windows: the `HopAssign` logical node and `HopAssignExec`.
//!
//! An event belongs to every window that covers it, so a row is emitted once
//! per window (`ceil(size / slide)` times when the size is a multiple of the
//! slide). The copies of one row are adjacent, oldest window first, which
//! keeps the input's row order — and therefore the `frame_number` ordering —
//! through the operator.

use std::any::Any;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::fmt;
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;

use arrow::array::{Array, ArrayRef, RecordBatch, UInt32Array};
use arrow::compute::take;
use arrow::datatypes::SchemaRef;
use datafusion::common::{internal_err, plan_err, Column, DFSchemaRef, Result};
use datafusion::execution::TaskContext;
use datafusion::logical_expr::{Expr, LogicalPlan, UserDefinedLogicalNodeCore};
use datafusion::physical_plan::execution_plan::EmissionType;
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, ExecutionPlanProperties, Partitioning,
    PlanProperties, SendableRecordBatchStream,
};
use futures::StreamExt;
use pcapsql_core::windowing::HoppingWindowAssigner;

use super::{
    exec_properties, timestamp_array, timestamp_index, window_arrays, window_schema, WINDOW_END,
    WINDOW_START,
};

/// The most windows one row may belong to (`ceil(size / slide)`); larger
/// ratios are rejected at planning, since every row is emitted once per
/// window.
pub const MAX_WINDOWS_PER_EVENT: i64 = 10_000;

/// Logical node: assign hopping windows over `input` by `timestamp`.
///
/// Output: `window_start`, `window_end`, then every input column.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct HopAssign {
    input: LogicalPlan,
    timestamp: Column,
    slide_us: i64,
    size_us: i64,
    schema: DFSchemaRef,
}

impl HopAssign {
    pub(super) fn try_new(
        input: LogicalPlan,
        timestamp: Column,
        slide_us: i64,
        size_us: i64,
    ) -> Result<Self> {
        if slide_us <= 0 || size_us <= 0 || slide_us > size_us {
            return plan_err!(
                "hop(): slide ({slide_us} us) and size ({size_us} us) must be positive \
                 with slide <= size"
            );
        }
        if (size_us + slide_us - 1) / slide_us > MAX_WINDOWS_PER_EVENT {
            return plan_err!(
                "hop(): at most {MAX_WINDOWS_PER_EVENT} windows per row are supported"
            );
        }
        let schema = window_schema(input.schema(), &timestamp)?;
        Ok(Self {
            input,
            timestamp,
            slide_us,
            size_us,
            schema,
        })
    }

    /// The timestamp column of the input.
    pub fn timestamp(&self) -> &Column {
        &self.timestamp
    }

    /// Slide in microseconds.
    pub fn slide_us(&self) -> i64 {
        self.slide_us
    }

    /// Window size in microseconds.
    pub fn size_us(&self) -> i64 {
        self.size_us
    }
}

impl PartialOrd for HopAssign {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        (&self.input, &self.timestamp, self.slide_us, self.size_us).partial_cmp(&(
            &other.input,
            &other.timestamp,
            other.slide_us,
            other.size_us,
        ))
    }
}

impl UserDefinedLogicalNodeCore for HopAssign {
    fn name(&self) -> &str {
        "HopAssign"
    }

    fn inputs(&self) -> Vec<&LogicalPlan> {
        vec![&self.input]
    }

    fn schema(&self) -> &DFSchemaRef {
        &self.schema
    }

    fn expressions(&self) -> Vec<Expr> {
        vec![Expr::Column(self.timestamp.clone())]
    }

    /// Predicates on the window columns stay above the node; everything else
    /// is pushed to the source (and from there into the parse).
    fn prevent_predicate_push_down_columns(&self) -> HashSet<String> {
        [WINDOW_START, WINDOW_END]
            .into_iter()
            .map(str::to_string)
            .collect()
    }

    fn fmt_for_explain(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "HopAssign: timestamp={}, slide={:?}, size={:?}",
            self.timestamp,
            Duration::from_micros(self.slide_us as u64),
            Duration::from_micros(self.size_us as u64)
        )
    }

    fn with_exprs_and_inputs(&self, exprs: Vec<Expr>, inputs: Vec<LogicalPlan>) -> Result<Self> {
        if exprs.len() != 1 || inputs.len() != 1 {
            return internal_err!("HopAssign expects one timestamp column and one input");
        }
        let Expr::Column(timestamp) = &exprs[0] else {
            return internal_err!("HopAssign expects a column expression");
        };
        let input = inputs.into_iter().next().expect("one input");
        Self::try_new(input, timestamp.clone(), self.slide_us, self.size_us)
    }

    /// Projection pushdown: an output column past the two window columns is
    /// the input column two positions earlier; the timestamp is always needed.
    fn necessary_children_exprs(&self, output_columns: &[usize]) -> Option<Vec<Vec<usize>>> {
        let ts = timestamp_index(self.input.schema(), &self.timestamp).ok()?;
        let mut needed: Vec<usize> = output_columns
            .iter()
            .filter_map(|&i| i.checked_sub(2))
            .collect();
        needed.push(ts);
        needed.sort_unstable();
        needed.dedup();
        Some(vec![needed])
    }
}

/// Physical operator for [`HopAssign`]: one output row per (input row,
/// covering window), in input order.
#[derive(Debug)]
pub struct HopAssignExec {
    input: Arc<dyn ExecutionPlan>,
    timestamp_index: usize,
    assigner: HoppingWindowAssigner,
    schema: SchemaRef,
    properties: PlanProperties,
}

impl HopAssignExec {
    pub(super) fn try_new(
        input: Arc<dyn ExecutionPlan>,
        timestamp_index: usize,
        slide_us: i64,
        size_us: i64,
    ) -> Result<Self> {
        let schema = super::exec_schema(&input, timestamp_index)?;
        let properties = exec_properties(
            &input,
            Arc::clone(&schema),
            Partitioning::UnknownPartitioning(input.output_partitioning().partition_count()),
            EmissionType::Incremental,
        )?;
        Ok(Self {
            input,
            timestamp_index,
            assigner: HoppingWindowAssigner::from_micros(slide_us, size_us),
            schema,
            properties,
        })
    }

    /// The hop assigner (slide and size).
    pub fn assigner(&self) -> &HoppingWindowAssigner {
        &self.assigner
    }

    /// Index of the timestamp column in the input.
    pub fn timestamp_index(&self) -> usize {
        self.timestamp_index
    }
}

impl DisplayAs for HopAssignExec {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "HopAssignExec: timestamp={}, slide={:?}, size={:?}",
            self.input.schema().field(self.timestamp_index).name(),
            self.assigner.slide(),
            self.assigner.window_size()
        )
    }
}

impl ExecutionPlan for HopAssignExec {
    fn name(&self) -> &str {
        "HopAssignExec"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn properties(&self) -> &PlanProperties {
        &self.properties
    }

    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        vec![&self.input]
    }

    fn maintains_input_order(&self) -> Vec<bool> {
        vec![true]
    }

    fn benefits_from_input_partitioning(&self) -> Vec<bool> {
        vec![false]
    }

    fn with_new_children(
        self: Arc<Self>,
        children: Vec<Arc<dyn ExecutionPlan>>,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        let Some(input) = children.into_iter().next() else {
            return internal_err!("HopAssignExec expects one child");
        };
        Ok(Arc::new(Self::try_new(
            input,
            self.timestamp_index,
            self.assigner.slide_us(),
            self.assigner.size_us(),
        )?))
    }

    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> Result<SendableRecordBatchStream> {
        let max_rows = context.session_config().batch_size().max(1);
        let input = self.input.execute(partition, context)?;
        let schema = Arc::clone(&self.schema);
        let assigner = self.assigner.clone();
        let ts_index = self.timestamp_index;
        let out_schema = Arc::clone(&schema);
        let stream = input.flat_map(move |batch| {
            let out = match batch {
                Ok(batch) => match assign_hop(&batch, ts_index, &assigner, &schema, max_rows) {
                    Ok(batches) => batches.into_iter().map(Ok).collect(),
                    Err(e) => vec![Err(e)],
                },
                Err(e) => vec![Err(e)],
            };
            futures::stream::iter(out)
        });
        Ok(Box::pin(RecordBatchStreamAdapter::new(out_schema, stream)))
    }
}

/// Expand a batch: every row once per covering window, a row with a null
/// timestamp once with null window bounds. The expansion is `rows × k`, so
/// it is emitted in slices of about `max_rows` rows (a row's windows stay
/// together) rather than as one batch.
fn assign_hop(
    batch: &RecordBatch,
    ts_index: usize,
    assigner: &HoppingWindowAssigner,
    schema: &SchemaRef,
    max_rows: usize,
) -> Result<Vec<RecordBatch>> {
    let ts = timestamp_array(batch.column(ts_index))?;
    let mut out = Vec::new();
    let mut indices: Vec<u32> = Vec::with_capacity(max_rows);
    let mut bounds: Vec<Option<(i64, i64)>> = Vec::with_capacity(max_rows);
    let flush =
        |indices: &mut Vec<u32>, bounds: &mut Vec<Option<(i64, i64)>>| -> Result<RecordBatch> {
            let (starts, ends) = window_arrays(std::mem::take(bounds), ts.timezone());
            let indices = UInt32Array::from(std::mem::take(indices));
            let mut columns: Vec<ArrayRef> = Vec::with_capacity(batch.num_columns() + 2);
            columns.push(starts);
            columns.push(ends);
            for column in batch.columns() {
                columns.push(take(column.as_ref(), &indices, None)?);
            }
            Ok(RecordBatch::try_new(Arc::clone(schema), columns)?)
        };
    for row in 0..batch.num_rows() {
        let row_index = u32::try_from(row).map_err(|_| {
            datafusion::common::DataFusionError::Execution(
                "hop(): input batch exceeds u32::MAX rows".to_string(),
            )
        })?;
        if ts.is_null(row) {
            indices.push(row_index);
            bounds.push(None);
        } else {
            for window in assigner.assign(ts.value(row)) {
                indices.push(row_index);
                bounds.push(Some((window.start, window.end)));
            }
        }
        if indices.len() >= max_rows {
            out.push(flush(&mut indices, &mut bounds)?);
        }
    }
    if !indices.is_empty() || out.is_empty() {
        out.push(flush(&mut indices, &mut bounds)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::{Int64Array, TimestampMicrosecondArray};
    use arrow::datatypes::{DataType, Field, Schema, TimeUnit};

    #[test]
    fn assign_hop_slices_by_max_rows_keeping_a_row_together() {
        let ts_type = DataType::Timestamp(TimeUnit::Microsecond, None);
        let schema = Arc::new(Schema::new(vec![
            Field::new("ts", ts_type.clone(), true),
            Field::new("v", DataType::Int64, false),
        ]));
        let ts = TimestampMicrosecondArray::from(vec![
            Some(0),
            Some(1_000_000),
            None,
            Some(2_500_000),
            Some(9_000_000),
        ]);
        let v = Int64Array::from(vec![10, 20, 30, 40, 50]);
        let batch = RecordBatch::try_new(schema, vec![Arc::new(ts), Arc::new(v)]).unwrap();
        // Slide 1 s, size 3 s: three windows per timestamped row, one row
        // for the null; 13 rows in all.
        let assigner = HoppingWindowAssigner::from_micros(1_000_000, 3_000_000);
        let out_schema = Arc::new(Schema::new(vec![
            Field::new(WINDOW_START, ts_type.clone(), true),
            Field::new(WINDOW_END, ts_type.clone(), true),
            Field::new("ts", ts_type, true),
            Field::new("v", DataType::Int64, false),
        ]));
        let slices = assign_hop(&batch, 0, &assigner, &out_schema, 4).unwrap();
        let rows: Vec<usize> = slices.iter().map(|b| b.num_rows()).collect();
        // A row's windows are never split: 3 + 3 (= 6 >= 4), then 1 + 3, then 3.
        assert_eq!(rows, vec![6, 4, 3]);
        let values: Vec<i64> = slices
            .iter()
            .flat_map(|b| {
                b.column(3)
                    .as_any()
                    .downcast_ref::<Int64Array>()
                    .unwrap()
                    .values()
                    .to_vec()
            })
            .collect();
        assert_eq!(
            values,
            vec![10, 10, 10, 20, 20, 20, 30, 40, 40, 40, 50, 50, 50]
        );
        let starts = slices[0]
            .column(0)
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(starts.value(0), -2_000_000);
        assert_eq!(starts.value(2), 0);
        assert!(
            slices[1].column(0).is_null(0),
            "null timestamp gives a null window"
        );
        // One slice when everything fits; one empty slice for an empty input.
        assert_eq!(
            assign_hop(&batch, 0, &assigner, &out_schema, 100)
                .unwrap()
                .len(),
            1
        );
        let empty = RecordBatch::new_empty(batch.schema());
        let out = assign_hop(&empty, 0, &assigner, &out_schema, 4).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].num_rows(), 0);
    }
}
