//! The `tumble`, `hop` and `session` table functions.
//!
//! Each function parses its arguments, resolves the source relation in the
//! session's catalog and returns a [`WindowTableProvider`] whose logical plan
//! is the window assignment over the source. DataFusion inlines that plan
//! where the function is referenced (see the module documentation).

use std::sync::{Arc, Weak};

use arrow::datatypes::{DataType, TimeUnit};
use arrow::row::{RowConverter, SortField};
use datafusion::catalog::{TableFunctionImpl, TableProvider};
use datafusion::common::{plan_datafusion_err, plan_err, Column, Result, TableReference};
use datafusion::datasource::provider_as_source;
use datafusion::execution::session_state::SessionState;
use datafusion::functions::datetime::date_bin;
use datafusion::logical_expr::{Cast, Expr, Extension, LogicalPlan, LogicalPlanBuilder};
use futures::FutureExt;
use parking_lot::RwLock;
use pcapsql_core::windowing::WindowType;

use super::args::{column_name, interval_literal, interval_micros, split_args};
use super::hop::{HopAssign, MAX_WINDOWS_PER_EVENT};
use super::provider::WindowTableProvider;
use super::session::SessionAssign;
use super::{WINDOW_END, WINDOW_START};
use crate::query::{tables, views};

/// The default timestamp column: the `frames` column every `*_packets` view
/// carries through.
const DEFAULT_TIMESTAMP_COLUMN: &str = "timestamp";

/// Shared handle on the session whose catalog resolves source names.
///
/// A `Weak` reference: the session's function registry owns the function,
/// so a strong reference would be a cycle that kept the state alive forever.
type SessionRef = Weak<RwLock<SessionState>>;

/// `tumble(source, [timestamp_column,] size)`.
#[derive(Debug)]
pub struct TumbleFunction {
    state: SessionRef,
}

/// `hop(source, [timestamp_column,] slide, size)`.
#[derive(Debug)]
pub struct HopFunction {
    state: SessionRef,
}

/// `session(source, [timestamp_column,] key_column, gap)`.
#[derive(Debug)]
pub struct SessionFunction {
    state: SessionRef,
}

impl TumbleFunction {
    pub(super) fn new(state: SessionRef) -> Self {
        Self { state }
    }
}

impl HopFunction {
    pub(super) fn new(state: SessionRef) -> Self {
        Self { state }
    }
}

impl SessionFunction {
    pub(super) fn new(state: SessionRef) -> Self {
        Self { state }
    }
}

impl TableFunctionImpl for TumbleFunction {
    fn call(&self, args: &[Expr]) -> Result<Arc<dyn TableProvider>> {
        const FUNC: &str = "tumble";
        let (source, timestamp, rest) = split_args(
            args,
            FUNC,
            1,
            "tumble(source, size) or tumble(source, timestamp_column, size), \
             e.g. tumble(frames, INTERVAL '10' SECOND)",
        )?;
        let size_us = interval_micros(&rest[0], FUNC, "window size")?;
        let input = resolve_source(&self.state, &source, FUNC)?;
        let timestamp = timestamp_column(&input, timestamp.as_deref(), &source, FUNC)?;
        let plan = tumble_plan(input, timestamp, size_us)?;
        Ok(Arc::new(WindowTableProvider::new(
            plan,
            WindowType::Tumble {
                size: micros(size_us),
            },
        )))
    }
}

impl TableFunctionImpl for HopFunction {
    fn call(&self, args: &[Expr]) -> Result<Arc<dyn TableProvider>> {
        const FUNC: &str = "hop";
        let (source, timestamp, rest) = split_args(
            args,
            FUNC,
            2,
            "hop(source, slide, size) or hop(source, timestamp_column, slide, size), \
             e.g. hop(frames, INTERVAL '10' SECOND, INTERVAL '30' SECOND)",
        )?;
        let slide_us = interval_micros(&rest[0], FUNC, "slide")?;
        let size_us = interval_micros(&rest[1], FUNC, "window size")?;
        if slide_us > size_us {
            return plan_err!(
                "{FUNC}(): the slide ({}) must not exceed the window size ({}); \
                 windows would leave gaps",
                format_micros(slide_us),
                format_micros(size_us)
            );
        }
        let windows_per_event = (size_us + slide_us - 1) / slide_us;
        if windows_per_event > MAX_WINDOWS_PER_EVENT {
            return plan_err!(
                "{FUNC}(): a window size of {} with a slide of {} puts every row in \
                 {windows_per_event} windows; at most {MAX_WINDOWS_PER_EVENT} are supported \
                 (each row is emitted once per window)",
                format_micros(size_us),
                format_micros(slide_us)
            );
        }
        let input = resolve_source(&self.state, &source, FUNC)?;
        let timestamp = timestamp_column(&input, timestamp.as_deref(), &source, FUNC)?;
        let node = HopAssign::try_new(input, timestamp, slide_us, size_us)?;
        let plan = LogicalPlan::Extension(Extension {
            node: Arc::new(node),
        });
        Ok(Arc::new(WindowTableProvider::new(
            plan,
            WindowType::Hop {
                slide: micros(slide_us),
                size: micros(size_us),
            },
        )))
    }
}

impl TableFunctionImpl for SessionFunction {
    fn call(&self, args: &[Expr]) -> Result<Arc<dyn TableProvider>> {
        const FUNC: &str = "session";
        let (source, timestamp, rest) = split_args(
            args,
            FUNC,
            2,
            "session(source, key_column, gap) or \
             session(source, timestamp_column, key_column, gap), \
             e.g. session(tcp_packets, src_ip_v4, INTERVAL '30' SECOND)",
        )?;
        let key = column_name(&rest[0], FUNC, "key column", &source)?;
        let gap_us = interval_micros(&rest[1], FUNC, "gap")?;
        let input = resolve_source(&self.state, &source, FUNC)?;
        let timestamp = timestamp_column(&input, timestamp.as_deref(), &source, FUNC)?;
        let key = key_column(&input, &key, &source, FUNC)?;
        let node = SessionAssign::try_new(input, timestamp, key, gap_us)?;
        let plan = LogicalPlan::Extension(Extension {
            node: Arc::new(node),
        });
        Ok(Arc::new(WindowTableProvider::new(
            plan,
            WindowType::Session {
                gap: micros(gap_us),
            },
        )))
    }
}

fn micros(us: i64) -> std::time::Duration {
    std::time::Duration::from_micros(us as u64)
}

fn format_micros(us: i64) -> String {
    format!("{:?}", micros(us))
}

/// Resolve the source relation to its scan: a `TableScan` of a protocol
/// table, or a view's plan (`LogicalPlanBuilder::scan` inlines views).
///
/// Table functions are called while the SQL is planned, with no session
/// parameter; the lookup goes through the session this function was
/// registered on. The catalog is in memory, so the asynchronous
/// `SchemaProvider::table` resolves on its first poll — the planner is never
/// blocked on it.
fn resolve_source(state: &SessionRef, source: &TableReference, func: &str) -> Result<LogicalPlan> {
    let provider = {
        let state = state.upgrade().ok_or_else(|| {
            plan_datafusion_err!("{func}(): the session that registered the function is gone")
        })?;
        let state = state.read();
        let schema = state.schema_for_ref(source.clone())?;
        schema
            .table(source.table())
            .now_or_never()
            .ok_or_else(|| {
                plan_datafusion_err!(
                    "{func}(): the catalog did not resolve '{source}' synchronously; \
                     only in-memory catalogs can be windowed"
                )
            })??
            .ok_or_else(|| {
                plan_datafusion_err!(
                    "{func}(): table or view '{source}' not found; the windowable sources \
                     are `frames` and the `*_packets` views"
                )
            })?
    };
    LogicalPlanBuilder::scan(source.clone(), provider_as_source(provider), None)?.build()
}

/// The timestamp column of the source, by unqualified name on the source's
/// schema (so a view's qualifier is kept and an ambiguous name is an error),
/// checked to be `Timestamp(Microsecond)`.
fn timestamp_column(
    input: &LogicalPlan,
    explicit: Option<&str>,
    source: &TableReference,
    func: &str,
) -> Result<Column> {
    let name = explicit.unwrap_or(DEFAULT_TIMESTAMP_COLUMN);
    let schema = input.schema();
    let matches = schema.qualified_fields_with_unqualified_name(name);
    let (qualifier, field) = match matches.as_slice() {
        [one] => *one,
        [] if explicit.is_some() => {
            return plan_err!(
                "{func}(): '{source}' has no column '{name}'; available columns: {}",
                column_list(input)
            )
        }
        [] => {
            let hint = match packets_view_for(source.table()) {
                Some(view) => format!("use `{view}` instead of `{}`", source.table()),
                None => "window `frames` or a `*_packets` view, or name a \
                         Timestamp(Microsecond) column as the second argument"
                    .to_string(),
            };
            return plan_err!("{func}(): '{source}' has no `timestamp` column; {hint}");
        }
        _ => {
            return plan_err!(
                "{func}(): column '{name}' is ambiguous in '{source}'; \
                 window a view that exposes it once"
            )
        }
    };
    match field.data_type() {
        DataType::Timestamp(TimeUnit::Microsecond, _) => Ok(Column::from((qualifier, field))),
        other => plan_err!(
            "{func}(): column '{name}' of '{source}' has type {other}; \
             the timestamp column must be Timestamp(Microsecond) like `frames.timestamp`"
        ),
    }
}

/// The session key column, by unqualified name, with a type the row encoder
/// can compare.
fn key_column(
    input: &LogicalPlan,
    name: &str,
    source: &TableReference,
    func: &str,
) -> Result<Column> {
    let schema = input.schema();
    let matches = schema.qualified_fields_with_unqualified_name(name);
    let (qualifier, field) = match matches.as_slice() {
        [one] => *one,
        [] => {
            return plan_err!(
                "{func}(): '{source}' has no column '{name}' to key sessions by; \
                 available columns: {}",
                column_list(input)
            )
        }
        _ => return plan_err!("{func}(): key column '{name}' is ambiguous in '{source}'"),
    };
    if !RowConverter::supports_fields(&[SortField::new(field.data_type().clone())]) {
        return plan_err!(
            "{func}(): column '{name}' of type {} cannot be a session key",
            field.data_type()
        );
    }
    Ok(Column::from((qualifier, field)))
}

fn column_list(input: &LogicalPlan) -> String {
    input
        .schema()
        .fields()
        .iter()
        .map(|f| f.name().as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The `<table>_packets` view that adds `frames.timestamp` to a protocol
/// table, if the table has one.
fn packets_view_for(table: &str) -> Option<String> {
    if !tables::all_table_names().contains(&table) {
        return None;
    }
    let view = format!("{table}_packets");
    views::all_views()
        .iter()
        .any(|v| v.name == view)
        .then_some(view)
}

/// Tumbling windows as a projection: `window_start` is the timestamp binned
/// to the window size from the epoch (`date_bin`, which floors, so
/// timestamps before the epoch are placed correctly), `window_end` is one
/// size later, then every source column.
fn tumble_plan(input: LogicalPlan, timestamp: Column, size_us: i64) -> Result<LogicalPlan> {
    let ts_index = input.schema().index_of_column(&timestamp)?;
    let ts_type = input.schema().field(ts_index).data_type().clone();
    let size = interval_literal(size_us);
    let mut start = date_bin().call(vec![size.clone(), Expr::Column(timestamp)]);
    if matches!(&ts_type, DataType::Timestamp(_, Some(_))) {
        // `date_bin`'s signature matches a time-zoned Timestamp(Microsecond)
        // only through coercion, which picks the nanosecond variant; keep the
        // source's unit (and zone) so every window function agrees.
        start = Expr::Cast(Cast::new(Box::new(start), ts_type));
    }
    let end = start.clone() + size;
    let mut exprs = vec![start.alias(WINDOW_START), end.alias(WINDOW_END)];
    exprs.extend(input.schema().columns().into_iter().map(Expr::Column));
    LogicalPlanBuilder::from(input).project(exprs)?.build()
}
