//! Physical optimizer rule for streaming window aggregation.
//!
//! Detects the pattern:
//! ```text
//! AggregateExec
//!   └── WindowAssignExec
//!         └── child with Boundedness::Unbounded
//! ```
//! and replaces it with `StreamingWindowAggregateExec` that fuses window
//! assignment and aggregation for incremental result emission.

use std::sync::Arc;

use datafusion::common::config::ConfigOptions;
use datafusion::error::Result as DFResult;
use datafusion::physical_optimizer::PhysicalOptimizerRule;
use datafusion::physical_plan::aggregates::AggregateExec;
use datafusion::physical_plan::ExecutionPlan;

use super::StreamingWindowAggregateExec;
use crate::query::udtf::window_exec::WindowAssignExec;

/// Physical optimizer rule that fuses `AggregateExec → WindowAssignExec` for
/// unbounded sources into a single `StreamingWindowAggregateExec`.
///
/// This rule only fires when:
/// 1. The plan contains `AggregateExec` with a `WindowAssignExec` child
/// 2. The `WindowAssignExec`'s child is unbounded (stdin, live capture, etc.)
///
/// For bounded sources, the rule does nothing and DataFusion's standard
/// `AggregateExec` handles aggregation normally.
#[derive(Debug)]
pub struct StreamingWindowAggregateRule;

impl PhysicalOptimizerRule for StreamingWindowAggregateRule {
    fn optimize(
        &self,
        plan: Arc<dyn ExecutionPlan>,
        _config: &ConfigOptions,
    ) -> DFResult<Arc<dyn ExecutionPlan>> {
        optimize_plan(plan)
    }

    fn name(&self) -> &str {
        "StreamingWindowAggregateRule"
    }

    fn schema_check(&self) -> bool {
        true
    }
}

/// Recursively walk the plan tree and apply the optimization.
fn optimize_plan(plan: Arc<dyn ExecutionPlan>) -> DFResult<Arc<dyn ExecutionPlan>> {
    // Try to match at this node
    if let Some(optimized) = try_fuse_aggregate_window(&plan) {
        return Ok(optimized);
    }

    // Recurse into children
    let children = plan.children();
    if children.is_empty() {
        return Ok(plan);
    }

    let new_children: Vec<Arc<dyn ExecutionPlan>> = children
        .iter()
        .map(|child| optimize_plan(Arc::clone(child)))
        .collect::<DFResult<_>>()?;

    // Check if any children changed
    let children_changed = new_children
        .iter()
        .zip(children.iter())
        .any(|(new, old)| !Arc::ptr_eq(new, old));

    if children_changed {
        plan.with_new_children(new_children)
    } else {
        Ok(plan)
    }
}

/// Try to match and fuse `AggregateExec → WindowAssignExec → Unbounded child`.
fn try_fuse_aggregate_window(plan: &Arc<dyn ExecutionPlan>) -> Option<Arc<dyn ExecutionPlan>> {
    // Step 1: Is this an AggregateExec?
    let aggregate = plan.as_any().downcast_ref::<AggregateExec>()?;

    // Step 2: Is its child a WindowAssignExec?
    let child = aggregate.input();
    let window_assign = child.as_any().downcast_ref::<WindowAssignExec>()?;

    // Step 3: Is the WindowAssignExec's child unbounded?
    let window_child = &window_assign.children()[0];
    if !window_child.properties().boundedness.is_unbounded() {
        return None;
    }

    // Match found! Extract parameters and create fused operator.
    let window_type = window_assign.window_type().clone();
    let timestamp_col = window_assign.timestamp_col().to_string();
    let group_by = aggregate.group_expr().clone();
    let aggr_exprs = aggregate.aggr_expr().to_vec();
    let output_schema = aggregate.schema();

    // The child of the streaming aggregate is the WindowAssignExec's child
    // (the original protocol stream exec), NOT the WindowAssignExec itself.
    let source_child = Arc::clone(window_child);

    Some(Arc::new(StreamingWindowAggregateExec::new(
        source_child,
        window_type,
        timestamp_col,
        group_by,
        aggr_exprs,
        output_schema,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_name() {
        let rule = StreamingWindowAggregateRule;
        assert_eq!(rule.name(), "StreamingWindowAggregateRule");
    }

    #[test]
    fn test_schema_check_enabled() {
        let rule = StreamingWindowAggregateRule;
        assert!(rule.schema_check());
    }
}
