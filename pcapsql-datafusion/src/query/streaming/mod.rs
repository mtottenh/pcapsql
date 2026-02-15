//! Streaming window aggregation.
//!
//! This module implements watermark-driven window aggregation for unbounded
//! sources (e.g., stdin piped from tcpdump). A `PhysicalOptimizerRule` detects
//! the pattern `AggregateExec → WindowAssignExec → Unbounded child` and fuses
//! them into a `StreamingWindowAggregateExec` that emits results incrementally
//! as windows close.
//!
//! For bounded sources (pcap files), the rule does not fire and DataFusion's
//! standard `AggregateExec` handles everything normally.

mod optimizer_rule;
mod streaming_aggregate_exec;
mod window_state;

pub use optimizer_rule::StreamingWindowAggregateRule;
pub use streaming_aggregate_exec::StreamingWindowAggregateExec;
