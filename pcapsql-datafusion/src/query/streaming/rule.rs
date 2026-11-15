//! The physical optimizer rule that fuses a window aggregate.

use std::collections::HashSet;
use std::sync::Arc;

use datafusion::common::tree_node::{Transformed, TreeNode};
use datafusion::common::{Result, ScalarValue};
use datafusion::config::ConfigOptions;
use datafusion::logical_expr::Operator;
use datafusion::physical_expr::expressions::{BinaryExpr, CastExpr, Column, Literal};
use datafusion::physical_expr::utils::collect_columns;
use datafusion::physical_expr::{PhysicalExpr, ScalarFunctionExpr};
use datafusion::physical_optimizer::PhysicalOptimizerRule;
use datafusion::physical_plan::aggregates::{AggregateExec, AggregateMode};
use datafusion::physical_plan::coalesce_batches::CoalesceBatchesExec;
use datafusion::physical_plan::coop::CooperativeExec;
use datafusion::physical_plan::filter::FilterExec;
use datafusion::physical_plan::projection::{ProjectionExec, ProjectionExpr};
use datafusion::physical_plan::{ExecutionPlan, ExecutionPlanProperties};

use super::config::{ContinuousConfig, WindowSpec};
use super::exec::StreamingWindowAggregateExec;
use crate::query::windowing::{HopAssignExec, WINDOW_END, WINDOW_START};

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
