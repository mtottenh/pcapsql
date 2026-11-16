//! DataFusion session setup for the query engine.

use std::sync::Arc;

use datafusion::config::ConfigOptions;
use datafusion::execution::runtime_env::RuntimeEnvBuilder;
use datafusion::execution::session_state::SessionStateBuilder;
use datafusion::physical_optimizer::optimizer::PhysicalOptimizer;
use datafusion::prelude::*;

use super::{fusion, streaming, windowing};
use crate::error::{Error, QueryError};

/// Default number of partitions to split a seekable source into for the shared
/// parallel parse pass.
pub(super) fn default_target_partitions() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(1, 16)
}

/// DataFusion's `target_partitions` for a plan whose scans have `partitions`
/// partitions, on an engine with parse parallelism `parallelism`.
///
/// A partitioned scan is planned for exactly its own partition count, so no
/// scan with more than one partition is repartitioned: DataFusion round-robin
/// repartitions a scan with fewer partitions than the target up to it and,
/// when the query has no `ORDER BY`, strips the order-preserving variant of
/// that repartition, which loses the `frame_number` ordering
/// [`merge_ordered_partitions`] merges on and leaves the output in arrival
/// order (#122). A one-partition scan (compressed, unindexed or small cloud
/// source; a pass pinned by a stream table; a table cached from such a pass)
/// keeps the engine's parallelism instead, so filters and projections above
/// it are not throttled: a repartition from one ordered partition keeps the
/// order by construction, each output being a subsequence of one sorted
/// stream. At least 2 either way, since the physical planner plans joins as
/// SortMergeJoin only when `target_partitions > 1` (otherwise a collect-left
/// hash join that buffers one side).
pub(super) fn session_target_partitions(partitions: usize, parallelism: usize) -> usize {
    if partitions <= 1 {
        parallelism.max(2)
    } else {
        partitions
    }
}

/// Configure DataFusion for SortMergeJoin on frame_number-sorted streams,
/// with the planner for the window table functions' extension nodes.
///
/// `parallelism` is the engine's parse parallelism; each query re-targets its
/// own session state to the partition count it actually has (see
/// [`session_target_partitions`]).
pub(super) fn create_session_context(
    parallelism: usize,
    continuous: Option<&streaming::ContinuousConfig>,
    fuse_frame_joins: bool,
    memory_limit: Option<usize>,
) -> Result<SessionContext, Error> {
    let mut config = ConfigOptions::default();

    config.execution.target_partitions = session_target_partitions(1, parallelism);
    // Use our declared sort order (by frame_number)
    config.optimizer.prefer_existing_sort = true;
    // Prefer SortMergeJoin - works better with our sorted streams
    config.optimizer.prefer_hash_join = false;
    config.optimizer.repartition_joins = true;
    if continuous.is_some() {
        // One partition end to end: the stream is one partition, and a
        // repartition between the partial and final aggregate would be a
        // pipeline-breaking exchange above it. No batch coalescing either: it
        // would hold the stream's small batches back until 8192 rows had
        // accumulated above every filter.
        config.execution.target_partitions = 1;
        config.execution.coalesce_batches = false;
    }

    let mut builder = SessionStateBuilder::new()
        .with_config(config.into())
        .with_default_features()
        .with_query_planner(Arc::new(windowing::WindowQueryPlanner));
    if let Some(limit) = memory_limit {
        // A greedy pool: every consumer takes what it asks for until the
        // limit, then the request fails (DataFusion's operators spill or
        // error; the streaming aggregate applies its policy).
        let runtime = RuntimeEnvBuilder::new()
            .with_memory_limit(limit, 1.0)
            .build_arc()
            .map_err(|e| Error::Query(QueryError::from(e)))?;
        builder = builder.with_runtime_env(runtime);
    }
    if fuse_frame_joins {
        // Last, over the optimized plan: the view joins it replaces must
        // already have had their projections and filters pushed down.
        let mut rules = datafusion::optimizer::Optimizer::new().rules;
        // The fused scan's nominal partition count is the parse parallelism,
        // as for every protocol table (a plan-only scan must report what
        // will run: a continuous plan is checked on it).
        rules.push(Arc::new(fusion::FuseFrameJoins::new(
            parallelism,
            continuous.is_some(),
        )));
        builder = builder.with_optimizer_rules(rules);
    }
    if let Some(continuous) = continuous {
        // The fused streaming aggregate must replace `AggregateExec` over a
        // window before `SanityCheckPlan` rejects the plan as pipeline
        // breaking, so it goes right in front of that rule.
        let mut rules = PhysicalOptimizer::new().rules;
        let at = rules
            .iter()
            .position(|r| r.name() == streaming::SANITY_CHECK_RULE)
            .unwrap_or(rules.len());
        rules.insert(
            at,
            Arc::new(streaming::FuseWindowAggregate::new(continuous.clone())),
        );
        builder = builder.with_physical_optimizer_rules(rules);
    }
    Ok(SessionContext::new_with_state(builder.build()))
}
