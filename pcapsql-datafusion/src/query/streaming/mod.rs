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

mod config;
mod exec;
mod metrics;
mod rule;
mod state;
mod stream;

pub use config::{ContinuousConfig, MemoryLimitPolicy, WindowSpec};
pub use exec::StreamingWindowAggregateExec;
pub use metrics::{
    has_streaming_aggregate, late_rows, state_bytes, watermark_us, windows_emitted, windows_forced,
};
pub use rule::{FuseWindowAggregate, SANITY_CHECK_RULE};
