//! Time-window table functions: `tumble`, `hop` and `session`.
//!
//! ```sql
//! SELECT window_start, count(*) FROM tumble(frames, INTERVAL '10' SECOND) GROUP BY 1;
//! SELECT window_start, sum(length) FROM hop(frames, INTERVAL '10' SECOND, INTERVAL '30' SECOND) GROUP BY 1;
//! SELECT window_start, window_end, src_ip_v4, count(*)
//! FROM session(tcp_packets, src_ip_v4, INTERVAL '30' SECOND) GROUP BY 1, 2, 3;
//! ```
//!
//! Each function takes a *source* — `frames`, a `*_packets` view, or any
//! table or view with a `Timestamp(Microsecond)` column named as the second
//! argument — and yields the source's columns preceded by `window_start` and
//! `window_end` (`Timestamp(Microsecond)`, half-open `[start, end)`).
//!
//! # Attachment: a logical rewrite
//!
//! A table function is called while the SQL is planned and returns a
//! [`TableProvider`](datafusion::catalog::TableProvider). Ours
//! ([`WindowTableProvider`]) carries a *logical plan* — the window assignment
//! over the source's own scan — and DataFusion inlines it where the function
//! is referenced, exactly as it inlines a view. The query therefore contains
//! the real `TableScan`s before the engine harvests what to parse: projection
//! pushdown prunes the source to the columns the query uses, predicates on
//! source columns reach the parse, and `EXPLAIN` shows ordinary operators.
//!
//! The shapes the rewrite produces, which later work (a fused streaming
//! aggregate) can match:
//!
//! - **tumble** is a `Projection` with
//!   `date_bin(IntervalMonthDayNano(size), <timestamp>) AS window_start` and
//!   `date_bin(…) + IntervalMonthDayNano(size) AS window_end` followed by the
//!   source columns. `date_bin` floors to a multiple of the size from the
//!   epoch, so timestamps before the epoch are placed correctly. Physically
//!   this is a `ProjectionExec` whose first expression is the `date_bin`
//!   scalar function of an interval literal and the timestamp column.
//! - **hop** is the [`HopAssign`] extension node, planned as
//!   [`HopAssignExec`] (slide and size via `assigner()`), which emits one row
//!   per covering window, adjacent and oldest first.
//! - **session** is the [`SessionAssign`] extension node, planned as
//!   [`SessionAssignExec`] on a single partition; it buffers its input and
//!   detects sessions with `pcapsql_core::windowing::detect_sessions`, which
//!   sorts by `(key, timestamp)` itself, so unordered input (a join, several
//!   parse partitions) is handled.
//!
//! Both extension nodes report the source columns they need for projection
//! pushdown and let predicates that do not mention the window columns pass
//! to the source. All three keep the input's row order, so the engine's
//! order-preserving merge still returns un-`ORDER BY`ed results in capture
//! order.
//!
//! The window columns are null for a row whose timestamp is null (one row
//! for `hop`; no session for `session`). Type checks happen at planning: the
//! timestamp column must be `Timestamp(Microsecond)`, sizes are positive
//! intervals without month/year parts, and a hop's slide must not exceed its
//! size.

mod args;
mod functions;
mod hop;
mod planner;
mod provider;
mod session;

pub use functions::{HopFunction, SessionFunction, TumbleFunction};
pub use hop::{HopAssign, HopAssignExec};
pub use planner::WindowQueryPlanner;
pub use provider::WindowTableProvider;
pub use session::{SessionAssign, SessionAssignExec};

use std::sync::Arc;

use arrow::array::{ArrayRef, TimestampMicrosecondArray};
use arrow::datatypes::{DataType, Field, Schema, SchemaRef, TimeUnit};
use datafusion::common::tree_node::{Transformed, TreeNode};
use datafusion::common::{
    internal_err, plan_err, Column, DFSchema, DFSchemaRef, Result, TableReference,
};
use datafusion::physical_expr::expressions::Column as PhysicalColumn;
use datafusion::physical_expr::{EquivalenceProperties, PhysicalExpr, PhysicalSortExpr};
use datafusion::physical_plan::execution_plan::EmissionType;
use datafusion::physical_plan::{
    ExecutionPlan, ExecutionPlanProperties, Partitioning, PlanProperties,
};
use datafusion::prelude::SessionContext;

/// Name of the window start column every window function adds.
pub const WINDOW_START: &str = "window_start";
/// Name of the window end column every window function adds.
pub const WINDOW_END: &str = "window_end";

/// Register `tumble`, `hop` and `session` on a session context.
///
/// The functions resolve their source in this context's catalog, so views
/// created later (`CREATE VIEW`) can be windowed too. They hold only a weak
/// reference to the context's state.
pub fn register_window_functions(ctx: &SessionContext) {
    let state = ctx.state_weak_ref();
    ctx.register_udtf("tumble", Arc::new(TumbleFunction::new(state.clone())));
    ctx.register_udtf("hop", Arc::new(HopFunction::new(state.clone())));
    ctx.register_udtf("session", Arc::new(SessionFunction::new(state)));
}

/// Position of the timestamp column in a window node's input.
pub(crate) fn timestamp_index(input: &DFSchema, timestamp: &Column) -> Result<usize> {
    input.index_of_column(timestamp)
}

/// The window columns' type (the timestamp's `Timestamp(Microsecond)` with
/// its time zone) and nullability (the timestamp's).
fn window_column_type(timestamp: &Field) -> Result<(DataType, bool)> {
    match timestamp.data_type() {
        DataType::Timestamp(TimeUnit::Microsecond, tz) => Ok((
            DataType::Timestamp(TimeUnit::Microsecond, tz.clone()),
            timestamp.is_nullable(),
        )),
        other => plan_err!(
            "window timestamp column '{}' has type {other}; Timestamp(Microsecond) is required",
            timestamp.name()
        ),
    }
}

/// Logical output schema of a window node: unqualified `window_start` and
/// `window_end`, then the input's (qualified) fields.
pub(crate) fn window_schema(input: &DFSchema, timestamp: &Column) -> Result<DFSchemaRef> {
    let ts_index = timestamp_index(input, timestamp)?;
    let (window_type, nullable) = window_column_type(input.field(ts_index))?;
    let mut fields: Vec<(Option<TableReference>, Arc<Field>)> = vec![
        (
            None,
            Arc::new(Field::new(WINDOW_START, window_type.clone(), nullable)),
        ),
        (
            None,
            Arc::new(Field::new(WINDOW_END, window_type, nullable)),
        ),
    ];
    fields.extend(input.iter().map(|(q, f)| (q.cloned(), Arc::clone(f))));
    Ok(Arc::new(DFSchema::new_with_metadata(
        fields,
        input.metadata().clone(),
    )?))
}

/// Physical output schema of a window operator over `input`.
pub(crate) fn exec_schema(input: &Arc<dyn ExecutionPlan>, ts_index: usize) -> Result<SchemaRef> {
    let input_schema = input.schema();
    let Some(ts_field) = input_schema.fields().get(ts_index) else {
        return internal_err!("window timestamp column {ts_index} is out of range");
    };
    let (window_type, nullable) = window_column_type(ts_field)?;
    let mut fields = vec![
        Field::new(WINDOW_START, window_type.clone(), nullable),
        Field::new(WINDOW_END, window_type, nullable),
    ];
    fields.extend(input_schema.fields().iter().map(|f| f.as_ref().clone()));
    Ok(Arc::new(Schema::new_with_metadata(
        fields,
        input_schema.metadata().clone(),
    )))
}

/// Plan properties of a window operator: the input's ordering, shifted past
/// the two window columns (the operators keep row order), with the given
/// partitioning and emission type; bounded iff the input is.
pub(crate) fn exec_properties(
    input: &Arc<dyn ExecutionPlan>,
    schema: SchemaRef,
    partitioning: Partitioning,
    emission: EmissionType,
) -> Result<PlanProperties> {
    let mut eq = EquivalenceProperties::new(schema);
    if let Some(ordering) = input.properties().output_ordering() {
        let shifted = ordering
            .into_iter()
            .map(|sort| {
                let expr = Arc::clone(&sort.expr)
                    .transform_down(|e| {
                        Ok(match e.as_any().downcast_ref::<PhysicalColumn>() {
                            Some(c) => Transformed::yes(Arc::new(PhysicalColumn::new(
                                c.name(),
                                c.index() + 2,
                            ))
                                as Arc<dyn PhysicalExpr>),
                            None => Transformed::no(e),
                        })
                    })?
                    .data;
                Ok(PhysicalSortExpr {
                    expr,
                    options: sort.options,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        eq.add_ordering(shifted);
    }
    Ok(PlanProperties::new(
        eq,
        partitioning,
        emission,
        input.boundedness(),
    ))
}

/// The timestamp column of a batch as microseconds.
pub(crate) fn timestamp_array(array: &ArrayRef) -> Result<&TimestampMicrosecondArray> {
    match array.as_any().downcast_ref::<TimestampMicrosecondArray>() {
        Some(ts) => Ok(ts),
        None => internal_err!(
            "window timestamp column is {} at execution, not Timestamp(Microsecond)",
            array.data_type()
        ),
    }
}

/// `window_start` / `window_end` arrays from per-row bounds (`None` → null).
pub(crate) fn window_arrays(
    bounds: impl IntoIterator<Item = Option<(i64, i64)>>,
    timezone: Option<&str>,
) -> (ArrayRef, ArrayRef) {
    let (starts, ends): (Vec<Option<i64>>, Vec<Option<i64>>) = bounds
        .into_iter()
        .map(|b| match b {
            Some((start, end)) => (Some(start), Some(end)),
            None => (None, None),
        })
        .unzip();
    let tz: Option<Arc<str>> = timezone.map(Arc::from);
    (
        Arc::new(TimestampMicrosecondArray::from(starts).with_timezone_opt(tz.clone())),
        Arc::new(TimestampMicrosecondArray::from(ends).with_timezone_opt(tz)),
    )
}
