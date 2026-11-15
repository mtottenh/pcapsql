//! The metrics the fused aggregates of a plan report.

use std::sync::Arc;

use datafusion::common::tree_node::TreeNode;
use datafusion::physical_plan::ExecutionPlan;

use super::exec::StreamingWindowAggregateExec;

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
