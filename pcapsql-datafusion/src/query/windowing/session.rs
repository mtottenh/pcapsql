//! Session windows: the `SessionAssign` logical node and `SessionAssignExec`.
//!
//! A session's bounds depend on every event of its key, so the operator
//! buffers its whole (single-partition) input, runs
//! [`detect_sessions`](pcapsql_core::windowing::detect_sessions) — which
//! sorts by `(key, timestamp)` itself, so the input may arrive in any order —
//! and re-emits the input batches with the bounds prepended, in input order.

use std::any::Any;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::fmt;
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;

use arrow::array::{Array, ArrayRef, RecordBatch};
use arrow::datatypes::SchemaRef;
use arrow::row::{RowConverter, SortField};
use datafusion::common::{internal_err, plan_err, Column, DFSchemaRef, Result};
use datafusion::execution::memory_pool::{MemoryConsumer, MemoryReservation};
use datafusion::execution::TaskContext;
use datafusion::logical_expr::{Expr, LogicalPlan, UserDefinedLogicalNodeCore};
use datafusion::physical_plan::execution_plan::EmissionType;
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, Distribution, ExecutionPlan, Partitioning, PlanProperties,
    SendableRecordBatchStream,
};
use futures::{StreamExt, TryStreamExt};
use pcapsql_core::windowing::detect_sessions;

use super::{
    exec_properties, timestamp_array, timestamp_index, window_arrays, window_schema, WINDOW_END,
    WINDOW_START,
};

/// Logical node: assign per-`key` session windows over `input` by
/// `timestamp`, closing a session after `gap_us` without an event.
///
/// Output: `window_start`, `window_end`, then every input column.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct SessionAssign {
    input: LogicalPlan,
    timestamp: Column,
    key: Column,
    gap_us: i64,
    schema: DFSchemaRef,
}

impl SessionAssign {
    pub(super) fn try_new(
        input: LogicalPlan,
        timestamp: Column,
        key: Column,
        gap_us: i64,
    ) -> Result<Self> {
        if gap_us <= 0 {
            return plan_err!("session(): the gap must be positive");
        }
        input.schema().index_of_column(&key)?;
        let schema = window_schema(input.schema(), &timestamp)?;
        Ok(Self {
            input,
            timestamp,
            key,
            gap_us,
            schema,
        })
    }

    /// The timestamp column of the input.
    pub fn timestamp(&self) -> &Column {
        &self.timestamp
    }

    /// The session key column of the input.
    pub fn key(&self) -> &Column {
        &self.key
    }

    /// Inactivity gap in microseconds.
    pub fn gap_us(&self) -> i64 {
        self.gap_us
    }
}

impl PartialOrd for SessionAssign {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        (&self.input, &self.timestamp, &self.key, self.gap_us).partial_cmp(&(
            &other.input,
            &other.timestamp,
            &other.key,
            other.gap_us,
        ))
    }
}

impl UserDefinedLogicalNodeCore for SessionAssign {
    fn name(&self) -> &str {
        "SessionAssign"
    }

    fn inputs(&self) -> Vec<&LogicalPlan> {
        vec![&self.input]
    }

    fn schema(&self) -> &DFSchemaRef {
        &self.schema
    }

    fn expressions(&self) -> Vec<Expr> {
        vec![
            Expr::Column(self.timestamp.clone()),
            Expr::Column(self.key.clone()),
        ]
    }

    fn prevent_predicate_push_down_columns(&self) -> HashSet<String> {
        [WINDOW_START, WINDOW_END]
            .into_iter()
            .map(str::to_string)
            .collect()
    }

    fn fmt_for_explain(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "SessionAssign: timestamp={}, key={}, gap={:?}",
            self.timestamp,
            self.key,
            Duration::from_micros(self.gap_us as u64)
        )
    }

    fn with_exprs_and_inputs(&self, exprs: Vec<Expr>, inputs: Vec<LogicalPlan>) -> Result<Self> {
        if exprs.len() != 2 || inputs.len() != 1 {
            return internal_err!("SessionAssign expects two columns and one input");
        }
        let (Expr::Column(timestamp), Expr::Column(key)) = (&exprs[0], &exprs[1]) else {
            return internal_err!("SessionAssign expects column expressions");
        };
        let input = inputs.into_iter().next().expect("one input");
        Self::try_new(input, timestamp.clone(), key.clone(), self.gap_us)
    }

    fn necessary_children_exprs(&self, output_columns: &[usize]) -> Option<Vec<Vec<usize>>> {
        let input = self.input.schema();
        let ts = timestamp_index(input, &self.timestamp).ok()?;
        let key = input.index_of_column(&self.key).ok()?;
        let mut needed: Vec<usize> = output_columns
            .iter()
            .filter_map(|&i| i.checked_sub(2))
            .collect();
        needed.extend([ts, key]);
        needed.sort_unstable();
        needed.dedup();
        Some(vec![needed])
    }
}

/// Physical operator for [`SessionAssign`].
///
/// Requires a single input partition (every event of a key must be seen
/// together); DataFusion inserts the coalesce, which the engine turns into
/// an order-preserving merge. The whole (projected) input is buffered, and
/// accounted to the task's memory pool, before anything is emitted. Rows
/// come out in input order with the session bounds prepended; a row whose
/// timestamp is null belongs to no session and gets null bounds; null keys
/// form a session of their own.
#[derive(Debug)]
pub struct SessionAssignExec {
    input: Arc<dyn ExecutionPlan>,
    timestamp_index: usize,
    key_index: usize,
    gap_us: i64,
    schema: SchemaRef,
    properties: PlanProperties,
}

impl SessionAssignExec {
    pub(super) fn try_new(
        input: Arc<dyn ExecutionPlan>,
        timestamp_index: usize,
        key_index: usize,
        gap_us: i64,
    ) -> Result<Self> {
        let schema = super::exec_schema(&input, timestamp_index)?;
        let properties = exec_properties(
            &input,
            Arc::clone(&schema),
            Partitioning::UnknownPartitioning(1),
            EmissionType::Final,
        )?;
        Ok(Self {
            input,
            timestamp_index,
            key_index,
            gap_us,
            schema,
            properties,
        })
    }

    /// Inactivity gap in microseconds.
    pub fn gap_us(&self) -> i64 {
        self.gap_us
    }
}

impl DisplayAs for SessionAssignExec {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut fmt::Formatter) -> fmt::Result {
        let schema = self.input.schema();
        write!(
            f,
            "SessionAssignExec: timestamp={}, key={}, gap={:?}",
            schema.field(self.timestamp_index).name(),
            schema.field(self.key_index).name(),
            Duration::from_micros(self.gap_us as u64)
        )
    }
}

impl ExecutionPlan for SessionAssignExec {
    fn name(&self) -> &str {
        "SessionAssignExec"
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

    fn required_input_distribution(&self) -> Vec<Distribution> {
        vec![Distribution::SinglePartition]
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
            return internal_err!("SessionAssignExec expects one child");
        };
        Ok(Arc::new(Self::try_new(
            input,
            self.timestamp_index,
            self.key_index,
            self.gap_us,
        )?))
    }

    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> Result<SendableRecordBatchStream> {
        if partition != 0 {
            return internal_err!("SessionAssignExec has a single partition, got {partition}");
        }
        let mut reservation =
            MemoryConsumer::new("SessionAssignExec").register(context.memory_pool());
        let mut input = self.input.execute(0, context)?;
        let schema = Arc::clone(&self.schema);
        let (ts_index, key_index, gap_us) = (self.timestamp_index, self.key_index, self.gap_us);
        let out_schema = Arc::clone(&schema);
        let stream = futures::stream::once(async move {
            let mut batches: Vec<RecordBatch> = Vec::new();
            while let Some(batch) = input.try_next().await? {
                reservation.try_grow(batch.get_array_memory_size())?;
                batches.push(batch);
            }
            let out = assign_sessions(&batches, ts_index, key_index, gap_us, &schema)?;
            // The output shares the input's buffers: keep the reservation
            // until the consumer has taken the last batch.
            Ok::<_, datafusion::common::DataFusionError>(
                futures::stream::iter(out.into_iter().map(Ok))
                    .inspect(move |_| keep_alive(&reservation)),
            )
        })
        .try_flatten();
        Ok(Box::pin(RecordBatchStreamAdapter::new(out_schema, stream)))
    }
}

/// Ties a memory reservation to the output stream's lifetime.
fn keep_alive(_reservation: &MemoryReservation) {}

/// Detect the sessions over all input rows and prepend the bounds to each
/// input batch.
fn assign_sessions(
    batches: &[RecordBatch],
    ts_index: usize,
    key_index: usize,
    gap_us: i64,
    schema: &SchemaRef,
) -> Result<Vec<RecordBatch>> {
    let batches: Vec<&RecordBatch> = batches.iter().filter(|b| b.num_rows() > 0).collect();
    let total: usize = batches.iter().map(|b| b.num_rows()).sum();
    if total == 0 {
        return Ok(vec![RecordBatch::new_empty(Arc::clone(schema))]);
    }

    // Keys as comparable rows (any type, nulls included); timestamps of the
    // rows that have one.
    let key_type = batches[0].column(key_index).data_type().clone();
    let converter = RowConverter::new(vec![SortField::new(key_type)])?;
    let encoded: Vec<_> = batches
        .iter()
        .map(|b| converter.convert_columns(&[Arc::clone(b.column(key_index))]))
        .collect::<std::result::Result<_, _>>()?;
    let mut keys = Vec::with_capacity(total);
    let mut timestamps = Vec::with_capacity(total);
    let mut has_timestamp = Vec::with_capacity(total);
    let mut timezone = None;
    for (batch, rows) in batches.iter().zip(&encoded) {
        let ts = timestamp_array(batch.column(ts_index))?;
        timezone = ts.timezone();
        for (row, key) in rows.iter().enumerate() {
            if ts.is_null(row) {
                has_timestamp.push(false);
            } else {
                has_timestamp.push(true);
                keys.push(key);
                timestamps.push(ts.value(row));
            }
        }
    }
    let bounds = detect_sessions(&keys, &timestamps, gap_us);

    // Re-emit batch by batch, in input order.
    let mut next_bound = bounds.into_iter();
    let mut out = Vec::with_capacity(batches.len());
    let mut offset = 0;
    for batch in batches {
        let rows = batch.num_rows();
        let row_bounds = has_timestamp[offset..offset + rows].iter().map(|&has| {
            has.then(|| {
                let b = next_bound.next().expect("one bound per timestamped row");
                (b.start, b.end)
            })
        });
        let (starts, ends) = window_arrays(row_bounds, timezone);
        let mut columns: Vec<ArrayRef> = Vec::with_capacity(batch.num_columns() + 2);
        columns.push(starts);
        columns.push(ends);
        columns.extend(batch.columns().iter().cloned());
        out.push(RecordBatch::try_new(Arc::clone(schema), columns)?);
        offset += rows;
    }
    Ok(out)
}
