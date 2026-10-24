//! Continuous queries: the fused streaming window aggregate.
//!
//! A continuous engine (`EngineOptions::continuous`) reads an unbounded
//! stream, so its scans report `Boundedness::Unbounded`. DataFusion refuses
//! to execute a plan that must see the whole input before emitting anything
//! (its `SanityCheckPlan` rule: an unbounded operator with
//! `EmissionType::Final`), which is every ordinary `AggregateExec`. This
//! module adds the one operator that can aggregate such a stream: a window
//! aggregate that keeps state per `(window, group)`, closes a window once
//! the event-time watermark passes its end, and emits that window's rows.
//!
//! # Fusion
//!
//! [`FuseWindowAggregate`] is a physical optimizer rule that runs just before
//! `SanityCheckPlan`. It matches **only** this shape:
//!
//! ```text
//! AggregateExec (Single)            or     AggregateExec (Final)
//!   <chain>                                  AggregateExec (Partial)
//!                                              <chain>
//! ```
//!
//! where `<chain>` is any number of `ProjectionExec`, `FilterExec`,
//! `CoalesceBatchesExec` and `CooperativeExec` nodes ending in a window node:
//! the tumble projection (`window_start = date_bin(size, ts)`, see
//! `crate::query::windowing`; found by following the `window_start` /
//! `window_end` column through intermediate projections, since the logical
//! optimizer may split it) or a `HopAssignExec`, over an unbounded,
//! single-partition input. The aggregate's `GROUP BY` must contain the
//! `window_start` column. Anything else between the aggregate and the window
//! node (a sort, a limit, a repartition, a join, another aggregate) leaves
//! the plan alone, and DataFusion's sanity check then reports it; the engine
//! maps that error to a message naming the supported shape. What this
//! accepts, besides aggregates and `GROUP BY` columns: `WHERE` on source
//! columns (a filter below the window node) and on the window columns (a
//! filter in the chain), `FILTER (WHERE …)` per aggregate, `HAVING`
//! (a filter above the fused aggregate), `SELECT DISTINCT` (a group-by
//! without aggregates) and `LIMIT` above the aggregate (the first N windows,
//! then the query ends). What it rejects: `ORDER BY`, `count(DISTINCT …)`
//! (two aggregates), `GROUPING SETS`, `ORDER BY` inside an aggregate, joins,
//! `session()`, and an aggregate without `GROUP BY window_start`.
//!
//! The fused operator evaluates the aggregate's own group and argument
//! expressions against the aggregate's own input (the top of the chain), so
//! nothing is re-indexed; the chain is only rebuilt to carry the timestamp
//! column through to the operator, which needs it for the watermark.
//!
//! # Semantics
//!
//! - Watermark: `max(timestamp seen) - allowed_lateness`, re-evaluated after
//!   every row. A window `[start, end)` closes and is emitted once the
//!   watermark reaches `end`; its state is dropped.
//! - Late rows: a row whose window has already closed (`end <= watermark`
//!   when its batch arrived) is dropped and counted (`late_rows` in
//!   `ParseStats` and `--stats`). A row that is merely behind the maximum
//!   timestamp but whose window is still open is aggregated normally.
//! - Idle timeout (opt-in): if no batch arrives for `idle_timeout`, every
//!   open window is closed and emitted on wall-clock time; a row for one of
//!   them arriving afterwards is late. Without it, windows close on event
//!   time only, so a quiet feed holds its last window open until the next
//!   packet (or end of input, which closes everything).
//! - End of input closes and emits every open window.
//!
//! Each emitted batch holds one window's groups, sorted by group key.

use std::any::Any;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use arrow::array::{
    Array, ArrayRef, BooleanArray, RecordBatch, TimestampMicrosecondArray, UInt32Array,
};
use arrow::compute::{cast, filter, take};
use arrow::datatypes::{DataType, SchemaRef};
use arrow::row::{OwnedRow, RowConverter, SortField};
use datafusion::common::tree_node::{Transformed, TreeNode};
use datafusion::common::{plan_err, DataFusionError, Result, ScalarValue};
use datafusion::config::ConfigOptions;
use datafusion::execution::memory_pool::{MemoryConsumer, MemoryReservation};
use datafusion::execution::TaskContext;
use datafusion::logical_expr::Accumulator;
use datafusion::logical_expr::Operator;
use datafusion::physical_expr::aggregate::AggregateFunctionExpr;
use datafusion::physical_expr::expressions::{BinaryExpr, CastExpr, Column, Literal};
use datafusion::physical_expr::utils::collect_columns;
use datafusion::physical_expr::{EquivalenceProperties, PhysicalExpr, ScalarFunctionExpr};
use datafusion::physical_optimizer::PhysicalOptimizerRule;
use datafusion::physical_plan::aggregates::{AggregateExec, AggregateMode, PhysicalGroupBy};
use datafusion::physical_plan::coalesce_batches::CoalesceBatchesExec;
use datafusion::physical_plan::coop::CooperativeExec;
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
use datafusion::physical_plan::filter::FilterExec;
use datafusion::physical_plan::metrics::{
    Count, ExecutionPlanMetricsSet, Gauge, MetricBuilder, MetricsSet,
};
use datafusion::physical_plan::projection::{ProjectionExec, ProjectionExpr};
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, Distribution, ExecutionPlan, ExecutionPlanProperties,
    Partitioning, PlanProperties, RecordBatchStream, SendableRecordBatchStream,
};
use futures::Stream;
use pcapsql_core::windowing::{
    WatermarkConfig, WatermarkEmitStrategy, WatermarkGenerator, WindowType,
};

use crate::query::windowing::{HopAssignExec, WINDOW_END, WINDOW_START};

/// What a continuous engine tells the fused aggregate.
#[derive(Clone, Debug)]
pub struct ContinuousConfig {
    /// How far the watermark trails the largest timestamp seen: how late a
    /// row may be and still be aggregated.
    pub allowed_lateness: Duration,
    /// Close every open window after this long without input (`None`:
    /// windows close on event time only).
    pub idle_timeout: Option<Duration>,
    /// What to do when the window state does not fit the memory pool.
    pub on_memory_limit: MemoryLimitPolicy,
}

/// What the streaming window aggregate does when its state (open windows ×
/// groups × accumulators, accounted to DataFusion's memory pool) exceeds
/// the engine's memory limit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MemoryLimitPolicy {
    /// Fail the query, naming the open windows and groups (the default:
    /// nothing is silently approximated).
    #[default]
    Error,
    /// Emit the oldest open windows before their time until the state fits
    /// again. Each is counted in `windows_forced`; a row arriving for one of
    /// them later is late. If the newest window alone does not fit, fail.
    CloseOldest,
}

impl std::str::FromStr for MemoryLimitPolicy {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "error" => Ok(Self::Error),
            "close-oldest" => Ok(Self::CloseOldest),
            other => Err(format!(
                "unknown memory-limit policy '{other}': use 'error' or 'close-oldest'"
            )),
        }
    }
}

/// The window a fused aggregate groups by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WindowSpec {
    Tumble {
        size_us: i64,
    },
    Hop {
        slide_us: i64,
        size_us: i64,
        /// Aggregated per slice (see [`WindowSpec::sliced`]); decided by the
        /// rule, which knows what else reads the window columns.
        sliced: bool,
    },
}

impl WindowSpec {
    fn size_us(&self) -> i64 {
        match self {
            WindowSpec::Tumble { size_us } | WindowSpec::Hop { size_us, .. } => *size_us,
        }
    }

    /// Whether the window may be sliced: a hop whose size is a multiple of
    /// its slide.
    fn slice_candidate(&self) -> bool {
        matches!(self, WindowSpec::Hop { slide_us, size_us, .. } if size_us % slide_us == 0 && size_us > slide_us)
    }

    fn with_slicing(self, sliced: bool) -> Self {
        match self {
            WindowSpec::Hop {
                slide_us, size_us, ..
            } => WindowSpec::Hop {
                slide_us,
                size_us,
                sliced,
            },
            tumble => tumble,
        }
    }

    /// A sliced hop is aggregated per **slice** (one slide's worth of rows)
    /// and the slices merged into each window when it closes: every row
    /// updates one accumulator instead of `size / slide`. The rows carry the
    /// slice's bounds in the window columns, so slicing is only used when
    /// nothing but the aggregate's `GROUP BY window_start` / `window_end`
    /// reads them. Any other window is aggregated per window.
    fn sliced(&self) -> bool {
        matches!(self, WindowSpec::Hop { sliced: true, .. })
    }

    /// The width of one state entry: the slide for a sliced hop, else the
    /// window size.
    fn slice_us(&self) -> i64 {
        match self {
            WindowSpec::Hop { slide_us, .. } if self.sliced() => *slide_us,
            other => other.size_us(),
        }
    }

    fn window_type(&self) -> WindowType {
        let micros = |us: i64| Duration::from_micros(us as u64);
        match self {
            WindowSpec::Tumble { size_us } => WindowType::Tumble {
                size: micros(*size_us),
            },
            WindowSpec::Hop {
                slide_us, size_us, ..
            } => WindowType::Hop {
                slide: micros(*slide_us),
                size: micros(*size_us),
            },
        }
    }
}

/// Name of the physical optimizer rule the fused aggregate must precede.
pub const SANITY_CHECK_RULE: &str = "SanityCheckPlan";

/// Physical optimizer rule replacing an aggregate over a window node of an
/// unbounded input with [`StreamingWindowAggregateExec`] (see the module
/// documentation for the exact shape).
#[derive(Debug)]
pub struct FuseWindowAggregate {
    config: ContinuousConfig,
}

impl FuseWindowAggregate {
    pub fn new(config: ContinuousConfig) -> Self {
        Self { config }
    }

    fn try_fuse(
        &self,
        node: Arc<dyn ExecutionPlan>,
    ) -> Result<Transformed<Arc<dyn ExecutionPlan>>> {
        let Some(top) = node.as_any().downcast_ref::<AggregateExec>() else {
            return Ok(Transformed::no(node));
        };
        let source: &AggregateExec = match top.mode() {
            AggregateMode::Single | AggregateMode::SinglePartitioned => top,
            AggregateMode::Final | AggregateMode::FinalPartitioned => {
                match top.input().as_any().downcast_ref::<AggregateExec>() {
                    Some(partial) if *partial.mode() == AggregateMode::Partial => partial,
                    _ => return Ok(Transformed::no(node)),
                }
            }
            AggregateMode::Partial => return Ok(Transformed::no(node)),
        };
        let input = source.input();
        if !input.boundedness().is_unbounded() || input.output_partitioning().partition_count() != 1
        {
            return Ok(Transformed::no(node));
        }
        let Some(mut chain) = match_window_chain(input) else {
            return Ok(Transformed::no(node));
        };
        if chain.spec.slice_candidate() {
            // Sliced rows carry slice bounds in the window columns: slice
            // only when nothing but the window group columns reads them.
            let sliced = match chain.window_bound_columns() {
                Some(bounds) => {
                    let reads_bounds = |e: &Arc<dyn PhysicalExpr>| {
                        collect_columns(e)
                            .iter()
                            .any(|c| bounds.contains(&c.index()))
                    };
                    // The group columns the aggregate treats as the window
                    // (as `StreamingWindowAggregateExec::try_new` finds them);
                    // any other group expression is a key.
                    let is_bare_window_col = |(e, alias): &(Arc<dyn PhysicalExpr>, String)| {
                        (alias == WINDOW_START || alias == WINDOW_END)
                            && e.as_any()
                                .downcast_ref::<Column>()
                                .is_some_and(|c| c.name() == alias)
                    };
                    !source
                        .group_expr()
                        .expr()
                        .iter()
                        .filter(|g| !is_bare_window_col(g))
                        .any(|(e, _)| reads_bounds(e))
                        && !source
                            .aggr_expr()
                            .iter()
                            .flat_map(|a| a.expressions())
                            .any(|e| reads_bounds(&e))
                        && !source.filter_expr().iter().flatten().any(reads_bounds)
                }
                None => false,
            };
            chain.spec = chain.spec.with_slicing(sliced);
        }
        let (input, ts_index) = chain.with_timestamp()?;
        let exec = StreamingWindowAggregateExec::try_new(
            input,
            chain.spec,
            ts_index,
            chain.ts_name,
            source.group_expr().clone(),
            source.aggr_expr().to_vec(),
            source.filter_expr().to_vec(),
            top.schema(),
            self.config.clone(),
        )?;
        Ok(Transformed::yes(Arc::new(exec)))
    }
}

impl PhysicalOptimizerRule for FuseWindowAggregate {
    fn optimize(
        &self,
        plan: Arc<dyn ExecutionPlan>,
        _config: &ConfigOptions,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        plan.transform_down(|node| self.try_fuse(node))
            .map(|t| t.data)
    }

    fn name(&self) -> &str {
        "FuseWindowAggregate"
    }

    fn schema_check(&self) -> bool {
        true
    }
}

/// Alias of the timestamp column the rule appends to the aggregate's input,
/// so the operator finds it by position, never by a user-visible name.
const RESERVED_TS: &str = "__pcapsql_ts";

/// A node between the aggregate and the window node, top first.
enum ChainNode {
    Projection(Vec<ProjectionExpr>),
    Filter(Arc<dyn PhysicalExpr>),
    Coalesce {
        target_batch_size: usize,
        fetch: Option<usize>,
    },
    Cooperative,
}

/// The window node and the chain above it.
struct WindowChain {
    spec: WindowSpec,
    /// Name of the timestamp column at the window node (for display).
    ts_name: String,
    /// Nodes above the window node, top first.
    chain: Vec<ChainNode>,
    /// The window node itself: the tumble projection or `HopAssignExec`.
    window: Arc<dyn ExecutionPlan>,
    /// For a tumble projection: the position of the timestamp column in its
    /// input (the `date_bin` argument).
    tumble_ts_input_index: Option<usize>,
}

impl WindowChain {
    /// Where a hop's window columns surface at the top of the chain: the
    /// positions that forward them unchanged. `None` when a node computes
    /// something from them (a filter on `window_start`, an expression over
    /// `window_end`), which a sliced hop would feed slice bounds.
    fn window_bound_columns(&self) -> Option<HashSet<usize>> {
        let mut bounds: HashSet<usize> = [0, 1].into_iter().collect();
        for node in self.chain.iter().rev() {
            match node {
                ChainNode::Projection(exprs) => {
                    let mut next = HashSet::new();
                    for (i, e) in exprs.iter().enumerate() {
                        match e.expr.as_any().downcast_ref::<Column>() {
                            Some(c) if bounds.contains(&c.index()) => {
                                next.insert(i);
                            }
                            Some(_) => {}
                            None => {
                                if collect_columns(&e.expr)
                                    .iter()
                                    .any(|c| bounds.contains(&c.index()))
                                {
                                    return None;
                                }
                            }
                        }
                    }
                    bounds = next;
                }
                ChainNode::Filter(predicate) => {
                    if collect_columns(predicate)
                        .iter()
                        .any(|c| bounds.contains(&c.index()))
                    {
                        return None;
                    }
                }
                ChainNode::Coalesce { .. } | ChainNode::Cooperative => {}
            }
        }
        Some(bounds)
    }

    /// Rebuild the chain so that the timestamp column reaches the
    /// aggregate's input under [`RESERVED_TS`] (appended at the end of every
    /// projection, so no existing column index moves) and return the new
    /// input with the column's position.
    fn with_timestamp(&self) -> Result<(Arc<dyn ExecutionPlan>, usize)> {
        let (mut current, mut ts_index): (Arc<dyn ExecutionPlan>, usize) =
            match self.tumble_ts_input_index {
                Some(ts_in) => {
                    let proj = self
                        .window
                        .as_any()
                        .downcast_ref::<ProjectionExec>()
                        .expect("tumble window node is a projection");
                    let mut exprs = proj.expr().to_vec();
                    exprs.push(ProjectionExpr {
                        expr: Arc::new(Column::new(
                            proj.input().schema().field(ts_in).name(),
                            ts_in,
                        )),
                        alias: RESERVED_TS.to_string(),
                    });
                    let n = exprs.len() - 1;
                    (
                        Arc::new(ProjectionExec::try_new(exprs, Arc::clone(proj.input()))?),
                        n,
                    )
                }
                None => {
                    let hop = self
                        .window
                        .as_any()
                        .downcast_ref::<HopAssignExec>()
                        .expect("hop window node");
                    // HopAssignExec prepends the two window columns. A sliced
                    // hop (see `WindowSpec::sliced`) is fed one row per
                    // input row with the *slice* bounds in those columns: a
                    // hop whose size is its slide, same schema. The aggregate
                    // knows the real window from the spec.
                    let window: Arc<dyn ExecutionPlan> = if self.spec.sliced() {
                        let slide = hop.assigner().slide_us();
                        Arc::new(HopAssignExec::try_new(
                            Arc::clone(hop.input()),
                            hop.timestamp_index(),
                            slide,
                            slide,
                        )?)
                    } else {
                        Arc::clone(&self.window)
                    };
                    (window, hop.timestamp_index() + 2)
                }
            };
        for node in self.chain.iter().rev() {
            current = match node {
                ChainNode::Projection(exprs) => {
                    let mut exprs = exprs.clone();
                    exprs.push(ProjectionExpr {
                        expr: Arc::new(Column::new(
                            current.schema().field(ts_index).name(),
                            ts_index,
                        )),
                        alias: RESERVED_TS.to_string(),
                    });
                    ts_index = exprs.len() - 1;
                    Arc::new(ProjectionExec::try_new(exprs, current)?)
                }
                ChainNode::Filter(predicate) => {
                    Arc::new(FilterExec::try_new(Arc::clone(predicate), current)?)
                }
                ChainNode::Coalesce {
                    target_batch_size,
                    fetch,
                } => Arc::new(
                    CoalesceBatchesExec::new(current, *target_batch_size).with_fetch(*fetch),
                ),
                ChainNode::Cooperative => Arc::new(CooperativeExec::new(current)),
            };
        }
        Ok((current, ts_index))
    }
}

/// Walk down from an aggregate's input through projections, filters,
/// coalesces and cooperative yields to a window node.
///
/// The tumble projection is found by following the aggregate's
/// `window_start` (or, failing that, `window_end`) column down through the
/// chain: a projection may merely forward it as a column (the logical
/// optimizer's common-subexpression pass splits the tumble projection into
/// `window_start = __common_expr` over `__common_expr = date_bin(...)`), so
/// the column's *position* is followed until the projection whose expression
/// at that position is the `date_bin` call (cast-wrapped or not).
fn match_window_chain(input: &Arc<dyn ExecutionPlan>) -> Option<WindowChain> {
    let mut chain = Vec::new();
    let mut current = Arc::clone(input);
    // Position of the window column being followed in `current`'s output
    // (`None` until a projection names it).
    let mut followed: Option<usize> = None;
    loop {
        let any = current.as_any();
        if let Some(c) = any.downcast_ref::<CoalesceBatchesExec>() {
            chain.push(ChainNode::Coalesce {
                target_batch_size: c.target_batch_size(),
                fetch: c.fetch(),
            });
            current = Arc::clone(c.input());
            continue;
        }
        if let Some(c) = any.downcast_ref::<CooperativeExec>() {
            chain.push(ChainNode::Cooperative);
            current = Arc::clone(c.input());
            continue;
        }
        if let Some(f) = any.downcast_ref::<FilterExec>() {
            if f.projection().is_some() {
                return None;
            }
            chain.push(ChainNode::Filter(Arc::clone(f.predicate())));
            current = Arc::clone(f.input());
            continue;
        }
        if let Some(hop) = any.downcast_ref::<HopAssignExec>() {
            // The window columns are the first two of the hop output.
            if followed.is_some_and(|i| i > 1) {
                return None;
            }
            let ts_name = hop
                .input()
                .schema()
                .field(hop.timestamp_index())
                .name()
                .clone();
            return Some(WindowChain {
                spec: WindowSpec::Hop {
                    slide_us: hop.assigner().slide_us(),
                    size_us: hop.assigner().size_us(),
                    sliced: false,
                },
                ts_name,
                chain,
                window: current,
                tumble_ts_input_index: None,
            });
        }
        if let Some(proj) = any.downcast_ref::<ProjectionExec>() {
            let candidate = match followed {
                Some(i) => proj.expr().get(i),
                None => proj
                    .expr()
                    .iter()
                    .find(|e| e.alias == WINDOW_START)
                    .or_else(|| proj.expr().iter().find(|e| e.alias == WINDOW_END)),
            }?;
            if let Some((size_us, ts_in)) = tumble_expr(&candidate.expr) {
                let ts_name = proj.input().schema().field(ts_in).name().clone();
                return Some(WindowChain {
                    spec: WindowSpec::Tumble { size_us },
                    ts_name,
                    chain,
                    window: current,
                    tumble_ts_input_index: Some(ts_in),
                });
            }
            let column = candidate.expr.as_any().downcast_ref::<Column>()?;
            followed = Some(column.index());
            chain.push(ChainNode::Projection(proj.expr().to_vec()));
            current = Arc::clone(proj.input());
            continue;
        }
        return None;
    }
}

/// Recognize a tumble window expression: `date_bin(IntervalMonthDayNano,
/// Column)` (the window start), possibly cast (time-zoned sources) and
/// possibly plus the size interval (the window end). Returns the size in
/// microseconds and the timestamp column's index in the expression's input.
fn tumble_expr(expr: &Arc<dyn PhysicalExpr>) -> Option<(i64, usize)> {
    let mut expr = expr;
    if let Some(c) = expr.as_any().downcast_ref::<CastExpr>() {
        expr = c.expr();
    }
    if let Some(b) = expr.as_any().downcast_ref::<BinaryExpr>() {
        if *b.op() == Operator::Plus && b.right().as_any().is::<Literal>() {
            expr = b.left();
            if let Some(c) = expr.as_any().downcast_ref::<CastExpr>() {
                expr = c.expr();
            }
        }
    }
    let func = expr.as_any().downcast_ref::<ScalarFunctionExpr>()?;
    if func.name() != "date_bin" || func.args().len() < 2 {
        return None;
    }
    let interval = func.args()[0].as_any().downcast_ref::<Literal>()?;
    let size_us = match interval.value() {
        ScalarValue::IntervalMonthDayNano(Some(v)) if v.months == 0 => {
            i64::from(v.days) * 86_400_000_000 + v.nanoseconds / 1_000
        }
        _ => return None,
    };
    let ts = func.args()[1].as_any().downcast_ref::<Column>()?;
    (size_us > 0).then_some((size_us, ts.index()))
}

/// Streaming window aggregate over an unbounded, single-partition input.
///
/// Built only by [`FuseWindowAggregate`]; see the module documentation.
pub struct StreamingWindowAggregateExec {
    input: Arc<dyn ExecutionPlan>,
    spec: WindowSpec,
    /// Timestamp column in `input` (appended by the rule under a reserved
    /// alias), and the source column's name for display.
    ts_index: usize,
    ts_name: String,
    group_by: PhysicalGroupBy,
    aggr_expr: Vec<Arc<AggregateFunctionExpr>>,
    filter_expr: Vec<Option<Arc<dyn PhysicalExpr>>>,
    /// Position of `window_start` / `window_end` among the group expressions.
    window_start_pos: usize,
    window_end_pos: Option<usize>,
    schema: SchemaRef,
    config: ContinuousConfig,
    properties: PlanProperties,
    metrics: ExecutionPlanMetricsSet,
}

impl fmt::Debug for StreamingWindowAggregateExec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamingWindowAggregateExec")
            .field("spec", &self.spec)
            .field("ts_index", &self.ts_index)
            .finish()
    }
}

impl StreamingWindowAggregateExec {
    #[allow(clippy::too_many_arguments)]
    fn try_new(
        input: Arc<dyn ExecutionPlan>,
        spec: WindowSpec,
        ts_index: usize,
        ts_name: String,
        group_by: PhysicalGroupBy,
        aggr_expr: Vec<Arc<AggregateFunctionExpr>>,
        filter_expr: Vec<Option<Arc<dyn PhysicalExpr>>>,
        schema: SchemaRef,
        config: ContinuousConfig,
    ) -> Result<Self> {
        if !group_by.is_single() {
            return plan_err!(
                "continuous queries do not support GROUPING SETS, ROLLUP or CUBE; \
                 GROUP BY window_start and plain columns"
            );
        }
        let is_window_col = |name: &str, (expr, alias): &(Arc<dyn PhysicalExpr>, String)| {
            alias == name
                && expr
                    .as_any()
                    .downcast_ref::<Column>()
                    .is_some_and(|c| c.name() == name)
        };
        let Some(window_start_pos) = group_by
            .expr()
            .iter()
            .position(|g| is_window_col(WINDOW_START, g))
        else {
            return plan_err!(
                "a continuous query must GROUP BY window_start (the column tumble() / hop() \
                 adds), so that each window can be emitted when it closes"
            );
        };
        let window_end_pos = group_by
            .expr()
            .iter()
            .position(|g| is_window_col(WINDOW_END, g));
        for agg in &aggr_expr {
            if !agg.order_bys().is_empty() {
                return plan_err!(
                    "continuous queries do not support ORDER BY inside an aggregate ({})",
                    agg.name()
                );
            }
        }
        if schema.fields().len() != group_by.expr().len() + aggr_expr.len() {
            return plan_err!(
                "streaming aggregate: output schema does not match {} group and {} aggregate \
                 expressions",
                group_by.expr().len(),
                aggr_expr.len()
            );
        }
        match input.schema().field(ts_index).data_type() {
            DataType::Timestamp(arrow::datatypes::TimeUnit::Microsecond, _) => {}
            other => {
                return plan_err!(
                    "streaming aggregate: timestamp column has type {other}, expected \
                     Timestamp(Microsecond)"
                )
            }
        }
        let properties = PlanProperties::new(
            EquivalenceProperties::new(Arc::clone(&schema)),
            Partitioning::UnknownPartitioning(1),
            EmissionType::Incremental,
            Boundedness::Unbounded {
                requires_infinite_memory: false,
            },
        );
        Ok(Self {
            input,
            spec,
            ts_index,
            ts_name,
            group_by,
            aggr_expr,
            filter_expr,
            window_start_pos,
            window_end_pos,
            schema,
            config,
            properties,
            metrics: ExecutionPlanMetricsSet::new(),
        })
    }

    /// The window the aggregate groups by.
    pub fn spec(&self) -> &WindowSpec {
        &self.spec
    }
}

impl DisplayAs for StreamingWindowAggregateExec {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut fmt::Formatter) -> fmt::Result {
        let groups: Vec<&str> = self
            .group_by
            .expr()
            .iter()
            .map(|(_, name)| name.as_str())
            .collect();
        let aggs: Vec<&str> = self.aggr_expr.iter().map(|a| a.name()).collect();
        write!(
            f,
            "StreamingWindowAggregateExec: window={}, timestamp={}, gby=[{}], aggr=[{}], \
             allowed_lateness={:?}",
            self.spec.window_type(),
            self.ts_name,
            groups.join(", "),
            aggs.join(", "),
            self.config.allowed_lateness
        )?;
        if let Some(idle) = self.config.idle_timeout {
            write!(f, ", idle_timeout={idle:?}")?;
        }
        if self.spec.sliced() {
            write!(f, ", sliced")?;
        }
        if self.config.on_memory_limit == MemoryLimitPolicy::CloseOldest {
            write!(f, ", on_memory_limit=close-oldest")?;
        }
        Ok(())
    }
}

impl ExecutionPlan for StreamingWindowAggregateExec {
    fn name(&self) -> &str {
        "StreamingWindowAggregateExec"
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

    fn with_new_children(
        self: Arc<Self>,
        children: Vec<Arc<dyn ExecutionPlan>>,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        let Some(input) = children.into_iter().next() else {
            return plan_err!("StreamingWindowAggregateExec expects one child");
        };
        Ok(Arc::new(Self::try_new(
            input,
            self.spec.clone(),
            self.ts_index,
            self.ts_name.clone(),
            self.group_by.clone(),
            self.aggr_expr.clone(),
            self.filter_expr.clone(),
            Arc::clone(&self.schema),
            self.config.clone(),
        )?))
    }

    fn metrics(&self) -> Option<MetricsSet> {
        Some(self.metrics.clone_inner())
    }

    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> Result<SendableRecordBatchStream> {
        if partition != 0 {
            return plan_err!("StreamingWindowAggregateExec has one partition, got {partition}");
        }
        let reservation = MemoryConsumer::new(format!("StreamingWindowAggregateExec[{partition}]"))
            .register(context.memory_pool());
        let input = self.input.execute(0, context)?;
        let state = AggregateState::try_new(self, partition, reservation)?;
        Ok(Box::pin(StreamingAggregateStream {
            input,
            state,
            queue: VecDeque::new(),
            schema: Arc::clone(&self.schema),
            idle_timeout: self.config.idle_timeout,
            idle: None,
            done: false,
        }))
    }
}

/// The accumulators of one `(slice, group)`.
type Accumulators = Vec<Box<dyn Accumulator>>;

/// One group's state within one slice.
struct GroupState {
    /// Accumulators still taking rows.
    live: Accumulators,
    /// For a sliced hop: the states frozen out of `live` each time a window
    /// containing this slice was emitted (`frozen[piece][aggregate]`), to be
    /// merged into the later windows that contain the slice too. A frozen
    /// accumulator cannot take rows again (`state()` consumes it), so `live`
    /// is replaced by a fresh one; rows arriving after a freeze land there.
    frozen: Vec<Vec<Vec<ScalarValue>>>,
    /// Rows have reached `live` since it was created or last frozen; an
    /// untouched `live` is not worth a piece.
    dirty: bool,
}

/// The groups of one slice, keyed by the encoded non-window group values
/// (`None` when the query groups by the window alone).
type SliceGroups = BTreeMap<Option<OwnedRow>, GroupState>;

/// Per-partition aggregate state.
struct AggregateState {
    spec: WindowSpec,
    ts_index: usize,
    group_exprs: Vec<Arc<dyn PhysicalExpr>>,
    window_start_pos: usize,
    window_end_pos: Option<usize>,
    /// Group expressions other than the window columns, with their output
    /// positions.
    key_positions: Vec<usize>,
    key_converter: Option<RowConverter>,
    aggr_expr: Vec<Arc<AggregateFunctionExpr>>,
    filter_expr: Vec<Option<Arc<dyn PhysicalExpr>>>,
    schema: SchemaRef,
    /// Open state by slice start: one slice per window (tumble, a hop whose
    /// size is not a multiple of its slide) or per slide (a sliced hop).
    slices: BTreeMap<i64, SliceGroups>,
    watermark: WatermarkGenerator,
    /// Every window ending at or before this has been emitted (by the
    /// watermark, the idle timeout, end of input or the memory limit). For a
    /// sliced hop this is also where the pending window is derived from:
    /// the next one starts `size - slide` before it, and a slice is only
    /// ever inserted if some window containing it is still open.
    closed_through: i64,
    /// What the state above weighs, as last accounted to the pool.
    reservation: MemoryReservation,
    on_memory_limit: MemoryLimitPolicy,
    late_rows: Count,
    windows_emitted: Count,
    windows_forced: Count,
    watermark_metric: Gauge,
    state_bytes_metric: Gauge,
}

impl AggregateState {
    fn try_new(
        exec: &StreamingWindowAggregateExec,
        partition: usize,
        reservation: MemoryReservation,
    ) -> Result<Self> {
        let group_exprs: Vec<Arc<dyn PhysicalExpr>> = exec
            .group_by
            .expr()
            .iter()
            .map(|(e, _)| Arc::clone(e))
            .collect();
        let key_positions: Vec<usize> = (0..group_exprs.len())
            .filter(|&i| i != exec.window_start_pos && Some(i) != exec.window_end_pos)
            .collect();
        let key_converter = if key_positions.is_empty() {
            None
        } else {
            let fields = key_positions
                .iter()
                .map(|&i| Ok(SortField::new(exec.schema.field(i).data_type().clone())))
                .collect::<Result<Vec<_>>>()?;
            Some(RowConverter::new(fields)?)
        };
        Ok(Self {
            spec: exec.spec.clone(),
            ts_index: exec.ts_index,
            group_exprs,
            window_start_pos: exec.window_start_pos,
            window_end_pos: exec.window_end_pos,
            key_positions,
            key_converter,
            aggr_expr: exec.aggr_expr.clone(),
            filter_expr: exec.filter_expr.clone(),
            schema: Arc::clone(&exec.schema),
            slices: BTreeMap::new(),
            watermark: WatermarkGenerator::new(WatermarkConfig {
                allowed_lateness: exec.config.allowed_lateness,
                emit_strategy: WatermarkEmitStrategy::EveryEvent,
                track_late_events: false,
            }),
            closed_through: i64::MIN,
            reservation,
            on_memory_limit: exec.config.on_memory_limit,
            late_rows: MetricBuilder::new(&exec.metrics).counter("late_rows", partition),
            windows_emitted: MetricBuilder::new(&exec.metrics)
                .counter("windows_emitted", partition),
            windows_forced: MetricBuilder::new(&exec.metrics).counter("windows_forced", partition),
            watermark_metric: MetricBuilder::new(&exec.metrics).gauge("watermark_us", partition),
            state_bytes_metric: MetricBuilder::new(&exec.metrics).gauge("state_bytes", partition),
        })
    }

    /// The point before which a window counts as closed.
    fn horizon(&self) -> i64 {
        self.watermark
            .current()
            .as_micros()
            .max(self.closed_through)
    }

    /// Whether any state is open.
    fn is_empty(&self) -> bool {
        self.slices.is_empty()
    }

    /// Windows containing the slice at `slice` that are closed at `horizon`:
    /// a sliced hop's windows are `slice - j * slide` for `j` in
    /// `0..size/slide`, and window `w` is closed once `w + size <= horizon`.
    /// For an unsliced window the slice is the window: 0 or 1.
    fn closed_windows_of(&self, slice: i64, horizon: i64) -> i64 {
        let size = self.spec.size_us();
        let slide = self.spec.slice_us();
        let k = size / slide;
        // Closed: slice - j*slide + size <= horizon, i.e. j >= (slice + size - horizon) / slide.
        // The horizon starts at i64::MIN (no watermark yet): saturate.
        let still_open = slice.saturating_add(size).saturating_sub(horizon);
        let first_closed = if still_open <= 0 {
            0
        } else {
            still_open.saturating_add(slide - 1) / slide
        };
        (k - first_closed).clamp(0, k)
    }

    /// The bytes the open state holds: accumulators, frozen states and keys.
    fn state_bytes(&self) -> usize {
        // Per entry: the map node, the key, the vectors.
        const OVERHEAD: usize = 96;
        self.slices
            .values()
            .flat_map(|groups| groups.iter())
            .map(|(key, group)| {
                OVERHEAD
                    + key.as_ref().map(|k| k.as_ref().len()).unwrap_or(0)
                    + group.live.iter().map(|a| a.size()).sum::<usize>()
                    + group
                        .frozen
                        .iter()
                        .flat_map(|piece| piece.iter())
                        .flat_map(|states| states.iter())
                        .map(ScalarValue::size)
                        .sum::<usize>()
            })
            .sum()
    }

    /// Account the state to the memory pool; when it does not fit, apply the
    /// policy: fail, or emit the oldest windows (appended to `out`) until it
    /// does.
    fn account(&mut self, out: &mut Vec<RecordBatch>) -> Result<()> {
        loop {
            let bytes = self.state_bytes();
            self.state_bytes_metric.set(bytes);
            match self.reservation.try_resize(bytes) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    let windows = self.open_windows();
                    let groups: usize = self.slices.values().map(BTreeMap::len).sum();
                    if self.on_memory_limit == MemoryLimitPolicy::Error || windows <= 1 {
                        let hint = if self.on_memory_limit == MemoryLimitPolicy::Error {
                            "lower --allowed-lateness, use a larger window or fewer group \
                             columns, raise --memory-limit, or --on-memory-limit close-oldest"
                        } else {
                            "the newest window alone does not fit: use a larger window or \
                             fewer group columns, or raise --memory-limit"
                        };
                        return Err(DataFusionError::ResourcesExhausted(format!(
                            "the streaming aggregate holds {bytes} bytes of state for {windows} \
                             open windows ({groups} group entries), more than the memory limit \
                             allows; {hint} ({e})"
                        )));
                    }
                    let forced = self.emit_oldest()?;
                    self.windows_forced.add(forced.len());
                    out.extend(forced);
                }
            }
        }
    }

    /// Open windows: for a sliced hop, those from the oldest pending window
    /// to the one starting at the newest slice; otherwise one per slice.
    fn open_windows(&self) -> usize {
        if !self.spec.sliced() {
            return self.slices.len();
        }
        match (self.pending_window(), self.slices.keys().next_back()) {
            (Some(next), Some(&last)) => ((last - next) / self.spec.slice_us() + 1) as usize,
            _ => 0,
        }
    }

    /// Emit the oldest open window before its time (memory limit).
    fn emit_oldest(&mut self) -> Result<Vec<RecordBatch>> {
        let size = self.spec.size_us();
        if self.spec.sliced() {
            let Some(w) = self.pending_window() else {
                return Ok(Vec::new());
            };
            self.emit_hop_windows_through(w.saturating_add(size))
        } else {
            let Some(&start) = self.slices.keys().next() else {
                return Ok(Vec::new());
            };
            let groups = self.slices.remove(&start).expect("window present");
            self.closed_through = self.closed_through.max(start + size);
            Ok(vec![self.emit_window(start, size, groups)?])
        }
    }

    /// Fold one input batch into the open windows; returns the windows the
    /// watermark closed, in start order.
    fn process(&mut self, batch: &RecordBatch) -> Result<Vec<RecordBatch>> {
        let n = batch.num_rows();
        if n == 0 {
            return Ok(Vec::new());
        }
        let horizon_before = self.horizon();
        let ts = batch
            .column(self.ts_index)
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .ok_or_else(|| {
                DataFusionError::Internal(
                    "streaming aggregate: timestamp column is not Timestamp(Microsecond)".into(),
                )
            })?;
        let starts = self.group_exprs[self.window_start_pos]
            .evaluate(batch)?
            .into_array(n)?;
        let starts = starts
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .ok_or_else(|| {
                DataFusionError::Internal(
                    "streaming aggregate: window_start is not Timestamp(Microsecond)".into(),
                )
            })?;
        let key_rows = match &self.key_converter {
            Some(converter) => {
                let columns = self
                    .key_positions
                    .iter()
                    .map(|&i| self.group_exprs[i].evaluate(batch)?.into_array(n))
                    .collect::<Result<Vec<_>>>()?;
                Some(converter.convert_columns(&columns)?)
            }
            None => None,
        };
        let args: Vec<Vec<ArrayRef>> = self
            .aggr_expr
            .iter()
            .map(|agg| {
                agg.expressions()
                    .iter()
                    .map(|e| e.evaluate(batch)?.into_array(n))
                    .collect::<Result<Vec<_>>>()
            })
            .collect::<Result<Vec<_>>>()?;
        let masks: Vec<Option<BooleanArray>> = self
            .filter_expr
            .iter()
            .map(|f| match f {
                Some(f) => {
                    let array = f.evaluate(batch)?.into_array(n)?;
                    let mask = array
                        .as_any()
                        .downcast_ref::<BooleanArray>()
                        .ok_or_else(|| {
                            DataFusionError::Internal(
                                "aggregate FILTER did not evaluate to a boolean".into(),
                            )
                        })?
                        .clone();
                    Ok(Some(mask))
                }
                None => Ok(None),
            })
            .collect::<Result<Vec<_>>>()?;

        // Bucket rows by (slice, group). A row whose windows have all been
        // emitted is late; for a sliced hop a row may be late for some of
        // its windows and counted for the rest, and the late ones are
        // counted (as the per-window expansion would have).
        let size = self.spec.size_us();
        let mut buckets: HashMap<(i64, Option<OwnedRow>), Vec<u32>> = HashMap::new();
        let mut late = 0usize;
        for i in 0..n {
            if ts.is_null(i) || starts.is_null(i) {
                // No event time: the row belongs to no window (unreachable
                // from `frames.timestamp`, which is not nullable; a view with
                // a nullable timestamp drops such rows here, uncounted).
                continue;
            }
            self.watermark.observe(ts.value(i));
            let start = starts.value(i);
            late += self.closed_windows_of(start, horizon_before) as usize;
            if start + size <= horizon_before {
                continue;
            }
            let key = key_rows.as_ref().map(|rows| rows.row(i).owned());
            buckets.entry((start, key)).or_default().push(i as u32);
        }
        if late > 0 {
            self.late_rows.add(late);
        }
        for ((start, key), indices) in buckets {
            let indices = UInt32Array::from(indices);
            let groups = self.slices.entry(start).or_default();
            let group = match groups.get_mut(&key) {
                Some(g) => g,
                None => {
                    let fresh = self
                        .aggr_expr
                        .iter()
                        .map(|a| a.create_accumulator())
                        .collect::<Result<Vec<_>>>()?;
                    groups.entry(key).or_insert(GroupState {
                        live: fresh,
                        frozen: Vec::new(),
                        dirty: false,
                    })
                }
            };
            group.dirty = true;
            let accumulators = &mut group.live;
            for (k, acc) in accumulators.iter_mut().enumerate() {
                let mut values = args[k]
                    .iter()
                    .map(|a| Ok(take(a.as_ref(), &indices, None)?))
                    .collect::<Result<Vec<ArrayRef>>>()?;
                if let Some(mask) = &masks[k] {
                    let mask = take(mask, &indices, None)?;
                    let mask = mask
                        .as_any()
                        .downcast_ref::<BooleanArray>()
                        .expect("boolean mask");
                    values = values
                        .iter()
                        .map(|a| Ok(filter(a.as_ref(), mask)?))
                        .collect::<Result<Vec<_>>>()?;
                }
                acc.update_batch(&values)?;
            }
        }

        let wm = self.watermark.current().as_micros();
        if wm > 0 {
            self.watermark_metric.set(wm as usize);
        }
        let mut out = self.emit_closed(wm)?;
        // Every window ending at or before the watermark is closed now,
        // emitted or (empty) not: a later row for one is late, and a sliced
        // hop must not emit it after the fact.
        self.closed_through = self.closed_through.max(wm);
        self.account(&mut out)?;
        Ok(out)
    }

    /// Emit every window whose end is at or before `horizon`.
    fn emit_closed(&mut self, horizon: i64) -> Result<Vec<RecordBatch>> {
        if self.spec.sliced() {
            return self.emit_hop_windows_through(horizon);
        }
        let size = self.spec.size_us();
        let closed: Vec<i64> = self
            .slices
            .keys()
            .copied()
            .take_while(|start| start + size <= horizon)
            .collect();
        let mut out = Vec::with_capacity(closed.len());
        for start in closed {
            let groups = self.slices.remove(&start).expect("window present");
            self.closed_through = self.closed_through.max(start + size);
            out.push(self.emit_window(start, size, groups)?);
        }
        Ok(out)
    }

    /// Emit every open window (idle timeout, end of input).
    fn emit_all(&mut self) -> Result<Vec<RecordBatch>> {
        self.emit_closed(i64::MAX)
    }

    /// Sliced hop: the oldest window not yet emitted, while any slice is
    /// open. It is the later of the first window containing the oldest slice
    /// and the window after the last one emitted (`closed_through - size`):
    /// a slice older than the latter is never inserted (all its windows are
    /// closed), so it always covers the oldest slice, and a long gap in the
    /// stream is jumped rather than walked window by window.
    fn pending_window(&self) -> Option<i64> {
        let size = self.spec.size_us();
        let slide = self.spec.slice_us();
        let &first = self.slices.keys().next()?;
        let earliest = first - size + slide;
        // Windows starting at or before `closed_through - size` are closed;
        // the first slide-aligned start after that is the next candidate.
        let last_closed = self.closed_through.saturating_sub(size);
        let after_closed = last_closed
            .div_euclid(slide)
            .saturating_mul(slide)
            .saturating_add(slide);
        Some(earliest.max(after_closed))
    }

    /// Sliced hop: emit, in start order, every window ending at or before
    /// `horizon`, merging the slices it covers; drop a slice once the last
    /// window containing it (the one starting at it) has been emitted.
    fn emit_hop_windows_through(&mut self, horizon: i64) -> Result<Vec<RecordBatch>> {
        let size = self.spec.size_us();
        let mut out = Vec::new();
        while let Some(w) = self.pending_window() {
            if w.saturating_add(size) > horizon {
                break;
            }
            let covered: Vec<i64> = self.slices.range(w..w + size).map(|(s, _)| *s).collect();
            debug_assert!(
                !covered.is_empty(),
                "the pending window covers the oldest slice"
            );
            out.push(self.emit_hop_window(w, &covered)?);
            // Slice `w` was in its last window.
            self.slices.remove(&w);
            self.closed_through = self.closed_through.max(w + size);
        }
        Ok(out)
    }

    /// Sliced hop: one window from the slices it covers. Each slice's live
    /// accumulators are frozen into states (and replaced, since freezing
    /// consumes them) so later windows covering the slice merge the same
    /// states again; the window's own accumulators are fresh ones that merge
    /// every piece of every covered slice. A live set that took no rows
    /// since the last freeze is left alone, so a slice that received its
    /// rows in order holds one piece however many windows it is in.
    fn emit_hop_window(&mut self, start: i64, covered: &[i64]) -> Result<RecordBatch> {
        let size = self.spec.size_us();
        // pieces[group][aggregate] = the state rows to merge.
        let mut pieces: BTreeMap<Option<OwnedRow>, Vec<Vec<Vec<ScalarValue>>>> = BTreeMap::new();
        for s in covered {
            let groups = self.slices.get_mut(s).expect("covered slice");
            for (key, group) in groups.iter_mut() {
                if group.dirty {
                    let states = group
                        .live
                        .iter_mut()
                        .map(|a| a.state())
                        .collect::<Result<Vec<_>>>()?;
                    group.live = self
                        .aggr_expr
                        .iter()
                        .map(|a| a.create_accumulator())
                        .collect::<Result<Vec<_>>>()?;
                    group.frozen.push(states);
                    group.dirty = false;
                }
                let into = pieces
                    .entry(key.clone())
                    .or_insert_with(|| vec![Vec::new(); self.aggr_expr.len()]);
                for piece in &group.frozen {
                    for (k, states) in piece.iter().enumerate() {
                        into[k].push(states.clone());
                    }
                }
            }
        }
        let mut merged: SliceGroups = BTreeMap::new();
        for (key, per_agg) in pieces {
            let mut live = Vec::with_capacity(self.aggr_expr.len());
            for (k, agg) in self.aggr_expr.iter().enumerate() {
                let mut acc = agg.create_accumulator()?;
                let rows = &per_agg[k];
                if let Some(first) = rows.first() {
                    let columns = (0..first.len())
                        .map(|j| ScalarValue::iter_to_array(rows.iter().map(|r| r[j].clone())))
                        .collect::<Result<Vec<ArrayRef>>>()?;
                    acc.merge_batch(&columns)?;
                }
                live.push(acc);
            }
            merged.insert(
                key,
                GroupState {
                    live,
                    frozen: Vec::new(),
                    dirty: true,
                },
            );
        }
        self.emit_window(start, size, merged)
    }

    fn emit_window(&mut self, start: i64, size: i64, groups: SliceGroups) -> Result<RecordBatch> {
        let n = groups.len();
        let mut columns: Vec<ArrayRef> = Vec::with_capacity(self.schema.fields().len());
        let keys: Vec<ArrayRef> = match &self.key_converter {
            Some(converter) => {
                let rows: Vec<_> = groups
                    .keys()
                    .map(|k| k.as_ref().expect("keyed group").row())
                    .collect();
                converter.convert_rows(rows)?
            }
            None => Vec::new(),
        };
        let mut key_iter = keys.into_iter();
        for (pos, field) in self
            .schema
            .fields()
            .iter()
            .enumerate()
            .take(self.group_exprs.len())
        {
            let tz = match field.data_type() {
                DataType::Timestamp(_, tz) => tz.clone(),
                _ => None,
            };
            let column: ArrayRef = if pos == self.window_start_pos {
                Arc::new(TimestampMicrosecondArray::from(vec![start; n]).with_timezone_opt(tz))
            } else if Some(pos) == self.window_end_pos {
                Arc::new(
                    TimestampMicrosecondArray::from(vec![start + size; n]).with_timezone_opt(tz),
                )
            } else {
                key_iter.next().expect("one array per key expression")
            };
            columns.push(cast_to(column, field.data_type())?);
        }
        let mut results: Vec<Vec<ScalarValue>> = vec![Vec::with_capacity(n); self.aggr_expr.len()];
        for mut group in groups.into_values() {
            for (k, acc) in group.live.iter_mut().enumerate() {
                results[k].push(acc.evaluate()?);
            }
        }
        for (k, values) in results.into_iter().enumerate() {
            let field = self.schema.field(self.group_exprs.len() + k);
            let array = if values.is_empty() {
                arrow::array::new_empty_array(field.data_type())
            } else {
                ScalarValue::iter_to_array(values)?
            };
            columns.push(cast_to(array, field.data_type())?);
        }
        self.windows_emitted.add(1);
        Ok(RecordBatch::try_new(Arc::clone(&self.schema), columns)?)
    }
}

fn cast_to(array: ArrayRef, data_type: &DataType) -> Result<ArrayRef> {
    if array.data_type() == data_type {
        Ok(array)
    } else {
        Ok(cast(array.as_ref(), data_type)?)
    }
}

/// The output stream: folds input batches, yields closed windows.
struct StreamingAggregateStream {
    input: SendableRecordBatchStream,
    state: AggregateState,
    queue: VecDeque<RecordBatch>,
    schema: SchemaRef,
    idle_timeout: Option<Duration>,
    idle: Option<Pin<Box<tokio::time::Sleep>>>,
    done: bool,
}

impl Stream for StreamingAggregateStream {
    type Item = Result<RecordBatch>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if let Some(batch) = self.queue.pop_front() {
                return Poll::Ready(Some(Ok(batch)));
            }
            if self.done {
                return Poll::Ready(None);
            }
            match Pin::new(&mut self.input).poll_next(cx) {
                Poll::Ready(Some(Ok(batch))) => {
                    self.idle = None;
                    match self.state.process(&batch) {
                        Ok(closed) => self.queue.extend(closed),
                        Err(e) => return Poll::Ready(Some(Err(e))),
                    }
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => {
                    self.done = true;
                    match self.state.emit_all() {
                        Ok(closed) => self.queue.extend(closed),
                        Err(e) => return Poll::Ready(Some(Err(e))),
                    }
                }
                Poll::Pending => {
                    let Some(idle_timeout) = self.idle_timeout else {
                        return Poll::Pending;
                    };
                    if self.state.is_empty() {
                        // Nothing to close: no timer until a window opens.
                        self.idle = None;
                        return Poll::Pending;
                    }
                    let sleep = self
                        .idle
                        .get_or_insert_with(|| Box::pin(tokio::time::sleep(idle_timeout)));
                    match sleep.as_mut().poll(cx) {
                        Poll::Ready(()) => {
                            self.idle = None;
                            match self.state.emit_all() {
                                Ok(closed) => self.queue.extend(closed),
                                Err(e) => return Poll::Ready(Some(Err(e))),
                            }
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

impl RecordBatchStream for StreamingAggregateStream {
    fn schema(&self) -> SchemaRef {
        Arc::clone(&self.schema)
    }
}

/// Sum of a named counter metric over every fused aggregate in `plan`.
fn sum_metric(plan: &Arc<dyn ExecutionPlan>, name: &str) -> usize {
    let mut total = 0;
    let _ = plan.apply(|node| {
        if node.as_any().is::<StreamingWindowAggregateExec>() {
            if let Some(v) = node.metrics().and_then(|m| m.sum_by_name(name)) {
                total += v.as_usize();
            }
        }
        Ok(datafusion::common::tree_node::TreeNodeRecursion::Continue)
    });
    total
}

/// Rows the fused aggregates of `plan` dropped as late so far.
pub fn late_rows(plan: &Arc<dyn ExecutionPlan>) -> u64 {
    sum_metric(plan, "late_rows") as u64
}

/// Windows the fused aggregates of `plan` emitted so far.
pub fn windows_emitted(plan: &Arc<dyn ExecutionPlan>) -> u64 {
    sum_metric(plan, "windows_emitted") as u64
}

/// Windows the fused aggregates of `plan` emitted before their time because
/// the memory limit was reached.
pub fn windows_forced(plan: &Arc<dyn ExecutionPlan>) -> u64 {
    sum_metric(plan, "windows_forced") as u64
}

/// Bytes of window state the fused aggregates of `plan` hold now.
pub fn state_bytes(plan: &Arc<dyn ExecutionPlan>) -> u64 {
    sum_metric(plan, "state_bytes") as u64
}

/// The fused aggregate's current watermark (microseconds since the epoch),
/// once it has advanced past the epoch.
pub fn watermark_us(plan: &Arc<dyn ExecutionPlan>) -> Option<i64> {
    let mut found = None;
    let _ = plan.apply(|node| {
        if node.as_any().is::<StreamingWindowAggregateExec>() {
            if let Some(v) = node.metrics().and_then(|m| m.sum_by_name("watermark_us")) {
                let us = v.as_usize();
                if us > 0 {
                    found = Some(found.unwrap_or(0).max(us as i64));
                }
            }
        }
        Ok(datafusion::common::tree_node::TreeNodeRecursion::Continue)
    });
    found
}

/// Whether `plan` contains a fused streaming aggregate.
pub fn has_streaming_aggregate(plan: &Arc<dyn ExecutionPlan>) -> bool {
    let mut found = false;
    let _ = plan.apply(|node| {
        if node.as_any().is::<StreamingWindowAggregateExec>() {
            found = true;
            return Ok(datafusion::common::tree_node::TreeNodeRecursion::Stop);
        }
        Ok(datafusion::common::tree_node::TreeNodeRecursion::Continue)
    });
    found
}
