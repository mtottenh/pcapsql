//! Window state management for streaming aggregation.
//!
//! Manages per-window, per-group accumulator state. Each active window
//! maintains a `HashMap<GroupKey, Vec<Box<dyn Accumulator>>>` for O(1)
//! group lookup. Windows are stored in a `BTreeMap` ordered by start time
//! for efficient watermark-based cleanup.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use arrow::array::{ArrayRef, RecordBatch};
use arrow::datatypes::SchemaRef;
use datafusion::common::ScalarValue;
use datafusion::error::Result as DFResult;
use datafusion::logical_expr::Accumulator;
use datafusion::physical_expr::aggregate::AggregateFunctionExpr;
use datafusion::physical_expr_common::physical_expr::PhysicalExpr;
use datafusion::physical_plan::aggregates::PhysicalGroupBy;

use pcapsql_core::windowing::WindowBounds;

/// Key for grouping within a window.
///
/// Uses a `Vec<ScalarValue>` to represent the group-by values for a row.
/// This is hashable via the `ScalarValue` implementation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupKey(Vec<ScalarValue>);

impl GroupKey {
    /// Create a group key from scalar values.
    pub fn new(values: Vec<ScalarValue>) -> Self {
        Self(values)
    }

    /// Get the underlying scalar values.
    pub fn values(&self) -> &[ScalarValue] {
        &self.0
    }
}

/// State for a single window, containing per-group accumulators.
pub struct WindowState {
    /// Per-group accumulator state.
    groups: HashMap<GroupKey, Vec<Box<dyn Accumulator>>>,
}

impl WindowState {
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
        }
    }

    /// Get or create accumulators for a group key.
    pub fn get_or_create_accumulators(
        &mut self,
        key: &GroupKey,
        aggr_exprs: &[Arc<AggregateFunctionExpr>],
    ) -> DFResult<&mut Vec<Box<dyn Accumulator>>> {
        if !self.groups.contains_key(key) {
            let accumulators: Vec<Box<dyn Accumulator>> = aggr_exprs
                .iter()
                .map(|expr| expr.create_accumulator())
                .collect::<DFResult<_>>()?;
            self.groups.insert(key.clone(), accumulators);
        }
        Ok(self.groups.get_mut(key).unwrap())
    }

    /// Drain all groups for emission.
    pub fn drain(self) -> HashMap<GroupKey, Vec<Box<dyn Accumulator>>> {
        self.groups
    }
}

/// Manages all active windows and their state.
///
/// Windows are stored in a `BTreeMap<WindowBounds, WindowState>` ordered
/// by window start time. This allows efficient iteration over windows
/// that should be closed based on watermark advancement.
pub struct WindowStateManager {
    /// Active windows ordered by start time.
    windows: BTreeMap<WindowBounds, WindowState>,
    /// Aggregate expressions for creating new accumulators.
    aggr_exprs: Vec<Arc<AggregateFunctionExpr>>,
    /// Group-by expressions for extracting group keys.
    group_by_exprs: Vec<(Arc<dyn PhysicalExpr>, String)>,
    /// Output schema for result batches.
    output_schema: SchemaRef,
}

impl WindowStateManager {
    pub fn new(
        aggr_exprs: Vec<Arc<AggregateFunctionExpr>>,
        group_by: &PhysicalGroupBy,
        output_schema: SchemaRef,
    ) -> Self {
        Self {
            windows: BTreeMap::new(),
            aggr_exprs,
            group_by_exprs: group_by.expr().to_vec(),
            output_schema,
        }
    }

    /// Accumulate values from a batch into the appropriate window and group.
    pub fn accumulate(
        &mut self,
        window: WindowBounds,
        group_key: GroupKey,
        aggr_values: &[ArrayRef],
        row_idx: usize,
    ) -> DFResult<()> {
        let state = self.windows.entry(window).or_insert_with(WindowState::new);
        let accumulators = state.get_or_create_accumulators(&group_key, &self.aggr_exprs)?;

        // Update each accumulator with the single row's values
        for (acc, val) in accumulators.iter_mut().zip(aggr_values.iter()) {
            let single_row = val.slice(row_idx, 1);
            acc.update_batch(&[single_row])?;
        }

        Ok(())
    }

    /// Close all windows whose end time is <= the watermark and emit results.
    pub fn close_windows(&mut self, watermark_us: i64) -> DFResult<Option<RecordBatch>> {
        // Collect windows to close
        let to_close: Vec<WindowBounds> = self
            .windows
            .keys()
            .take_while(|w| w.end <= watermark_us)
            .copied()
            .collect();

        if to_close.is_empty() {
            return Ok(None);
        }

        // Collect all results from closed windows
        let mut all_window_starts: Vec<i64> = Vec::new();
        let mut all_window_ends: Vec<i64> = Vec::new();
        let mut all_group_values: Vec<Vec<ScalarValue>> = Vec::new();
        let mut all_agg_values: Vec<Vec<ScalarValue>> = Vec::new();

        for window_bounds in to_close {
            if let Some(state) = self.windows.remove(&window_bounds) {
                for (group_key, mut accumulators) in state.drain() {
                    all_window_starts.push(window_bounds.start);
                    all_window_ends.push(window_bounds.end);
                    all_group_values.push(group_key.values().to_vec());

                    let mut agg_vals = Vec::with_capacity(accumulators.len());
                    for acc in accumulators.iter_mut() {
                        agg_vals.push(acc.evaluate()?);
                    }
                    all_agg_values.push(agg_vals);
                }
            }
        }

        if all_window_starts.is_empty() {
            return Ok(None);
        }

        // Build the output RecordBatch
        self.build_result_batch(
            &all_window_starts,
            &all_window_ends,
            &all_group_values,
            &all_agg_values,
        )
    }

    /// Flush all remaining windows (called at end of stream).
    pub fn flush_all(&mut self) -> DFResult<Option<RecordBatch>> {
        let all_windows: Vec<WindowBounds> = self.windows.keys().copied().collect();

        if all_windows.is_empty() {
            return Ok(None);
        }

        let mut all_window_starts: Vec<i64> = Vec::new();
        let mut all_window_ends: Vec<i64> = Vec::new();
        let mut all_group_values: Vec<Vec<ScalarValue>> = Vec::new();
        let mut all_agg_values: Vec<Vec<ScalarValue>> = Vec::new();

        for window_bounds in all_windows {
            if let Some(state) = self.windows.remove(&window_bounds) {
                for (group_key, mut accumulators) in state.drain() {
                    all_window_starts.push(window_bounds.start);
                    all_window_ends.push(window_bounds.end);
                    all_group_values.push(group_key.values().to_vec());

                    let mut agg_vals = Vec::with_capacity(accumulators.len());
                    for acc in accumulators.iter_mut() {
                        agg_vals.push(acc.evaluate()?);
                    }
                    all_agg_values.push(agg_vals);
                }
            }
        }

        if all_window_starts.is_empty() {
            return Ok(None);
        }

        self.build_result_batch(
            &all_window_starts,
            &all_window_ends,
            &all_group_values,
            &all_agg_values,
        )
    }

    /// Build a RecordBatch from accumulated results.
    ///
    /// Output schema matches AggregateExec: group-by columns first, then
    /// aggregate columns. We include window_start and window_end as part
    /// of the group-by columns.
    fn build_result_batch(
        &self,
        window_starts: &[i64],
        window_ends: &[i64],
        group_values: &[Vec<ScalarValue>],
        agg_values: &[Vec<ScalarValue>],
    ) -> DFResult<Option<RecordBatch>> {
        let num_rows = window_starts.len();
        if num_rows == 0 {
            return Ok(None);
        }

        let mut columns: Vec<ArrayRef> = Vec::new();

        // Build columns based on output schema order
        for (col_idx, field) in self.output_schema.fields().iter().enumerate() {
            let name = field.name();
            let data_type = field.data_type();

            if name == "window_start" {
                let array = arrow::array::TimestampMicrosecondArray::from(window_starts.to_vec());
                columns.push(Arc::new(array));
            } else if name == "window_end" {
                let array = arrow::array::TimestampMicrosecondArray::from(window_ends.to_vec());
                columns.push(Arc::new(array));
            } else if let Some(group_idx) = self.find_group_expr_index(name) {
                // This is a group-by column
                let scalars: Vec<ScalarValue> = group_values
                    .iter()
                    .map(|gv| gv[group_idx].clone())
                    .collect();
                let array = ScalarValue::iter_to_array(scalars)?;
                columns.push(array);
            } else {
                // This is an aggregate column — find it by position
                // Aggregate columns come after group-by columns in the output schema
                let agg_idx = self.find_agg_index(col_idx);
                let scalars: Vec<ScalarValue> =
                    agg_values.iter().map(|av| av[agg_idx].clone()).collect();
                let array = ScalarValue::iter_to_array(scalars)?;
                // Cast if needed to match output schema type
                let array = if array.data_type() != data_type {
                    arrow::compute::cast(&array, data_type).map_err(|e| {
                        datafusion::error::DataFusionError::ArrowError(Box::new(e), None)
                    })?
                } else {
                    array
                };
                columns.push(array);
            }
        }

        let batch = RecordBatch::try_new(self.output_schema.clone(), columns)
            .map_err(|e| datafusion::error::DataFusionError::ArrowError(Box::new(e), None))?;
        Ok(Some(batch))
    }

    /// Find the index of a group-by expression by column name.
    fn find_group_expr_index(&self, name: &str) -> Option<usize> {
        self.group_by_exprs
            .iter()
            .position(|(_, alias)| alias == name)
    }

    /// Map an output schema column index to an aggregate expression index.
    ///
    /// The output schema has group-by columns first (including window_start/window_end),
    /// then aggregate columns. We need to determine which aggregate expression
    /// corresponds to a given output column.
    fn find_agg_index(&self, col_idx: usize) -> usize {
        // Count how many group-by + window columns precede this column
        let num_group_cols = self.group_by_exprs.len();
        let num_window_cols = 2; // window_start, window_end
        let group_and_window = num_group_cols + num_window_cols;

        col_idx.saturating_sub(group_and_window)
    }
}
