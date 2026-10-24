//! Table providers for protocol tables, backed by a single shared parse pass.
//!
//! ```text
//!                         capture (one source)
//!                               │
//!                    SharedParseState (ONE parse pass)
//!              ┌──────────────┬───┴───┬──────────────┐   parallel partitions
//!              ▼              ▼        ▼              ▼   (seekable sources)
//!         per-protocol Arrow builders (NormalizedBatchSet fan-out)
//!              │              │        │              │
//!              ▼              ▼        ▼              ▼
//!        frames table    ipv4 table  tcp table   dns table   ...
//!              └──────────────┴───────┴──────────────┘
//!          one QueryTables per query, read by its ProtocolTableProviders
//! ```
//!
//! A query joining N protocol tables therefore parses the capture once, not N
//! times (#6), and that single pass is parallelized across partitions for
//! seekable sources (#9).

mod exchange;
mod protocol_provider;
mod scan_exec;
mod shared;

pub use exchange::{BatchReceiver, BatchSender, OverflowStats, Pacer, STREAM_CHANNEL_CAPACITY};
pub use protocol_provider::{
    column_names, CachedTable, PreparedTable, ProtocolTableProvider, QueryTables, TableCache,
};
pub use scan_exec::ProtocolScanExec;
pub use shared::{
    auto_target_partitions, run_shared_parse, run_shared_parse_sequential, run_streaming_parse,
    run_streaming_parse_sequential, ParseStats, ParseSubscription, PartitionStat, ProgressFn,
    ServedFrom, SharedParseState, StreamingHandle, TableData, TableSubscription,
};

use std::sync::Arc;

use datafusion::common::tree_node::{Transformed, TreeNode};
use datafusion::physical_plan::coalesce_partitions::CoalescePartitionsExec;
use datafusion::physical_plan::sorts::sort_preserving_merge::SortPreservingMergeExec;
use datafusion::physical_plan::ExecutionPlan;

/// Keep capture order when a partitioned plan is merged back into one stream.
///
/// The scan declares `frame_number` ordering per partition, and projections and
/// filters preserve it. DataFusion merges partitions with
/// `CoalescePartitionsExec`, which emits batches in *arrival* order, so once
/// the parse is partitioned an un-`ORDER BY`ed query such as
/// `SELECT frame_number FROM frames LIMIT 5` would return whichever
/// partition finished first (`LIMIT` plans a coalesce *inside* the plan, under
/// the global limit). Every coalesce whose input is still frame-ordered is
/// replaced by a `SortPreservingMergeExec` on that ordering (keeping its
/// fetch), and a plan that ends with several ordered partitions is merged the
/// same way, so results come back in capture order exactly as they did with a
/// single partition. Inputs without an ordering (aggregates, hash joins) are
/// left alone — their row order is unspecified anyway.
///
/// This relies on the scan's ordering surviving to the coalesce: a scan with
/// several partitions must be planned with `target_partitions` equal to its
/// partition count, or DataFusion repartitions it round-robin and, absent an
/// `ORDER BY`, drops the ordering with it (#122; the engine re-targets each
/// query's session state in `QueryEngine::execute`). A round-robin
/// repartition from a single ordered partition keeps the order.
pub fn merge_ordered_partitions(plan: Arc<dyn ExecutionPlan>) -> Arc<dyn ExecutionPlan> {
    let original = Arc::clone(&plan);
    let plan = plan
        .transform_down(|node| {
            if let Some(coalesce) = node.as_any().downcast_ref::<CoalescePartitionsExec>() {
                if let Some(merged) = ordered_merge(coalesce.input(), coalesce.fetch()) {
                    return Ok(Transformed::yes(merged));
                }
            }
            Ok(Transformed::no(node))
        })
        .map(|t| t.data)
        .unwrap_or(original);
    match ordered_merge(&plan, None) {
        Some(merged) => merged,
        None => plan,
    }
}

/// A sort-preserving merge over `input` when it has several partitions and a
/// declared output ordering; `None` when a plain coalesce is all that is
/// possible.
fn ordered_merge(
    input: &Arc<dyn ExecutionPlan>,
    fetch: Option<usize>,
) -> Option<Arc<dyn ExecutionPlan>> {
    let props = input.properties();
    if props.output_partitioning().partition_count() <= 1 {
        return None;
    }
    let ordering = props.output_ordering()?.clone();
    Some(Arc::new(
        SortPreservingMergeExec::new(ordering, Arc::clone(input)).with_fetch(fetch),
    ))
}
