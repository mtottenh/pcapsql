//! SQL query engine module.
//!
//! This module provides DataFusion integration for querying packet data.
//!
//! ## Architecture
//!
//! Normalized multi-table schema: per-protocol tables (`frames`, `ethernet`,
//! `ipv4`, `tcp`, `dns`, …) with `frame_number` as the linking key, plus
//! cross-layer views (e.g. `tcp_packets`) and the backward-compatible
//! `packets` view.
//!
//! [`QueryEngine::open`] is the single entry point: local files (mmap by
//! default), cloud URLs and standard input funnel into one shared parse pass,
//! parallel across partitions for seekable sources and sequential for a
//! stream, fanned out to every protocol table. JOINs use sort-merge since all
//! tables emit rows sorted by `frame_number`.
//! The `tumble` / `hop` / `session` table functions (`windowing`) add time
//! windows over `frames` and the `*_packets` views.
//!
//! The migration plan in `docs/query-scoped-parse-migration.md` moves this
//! parse from engine construction to query time, scoped to each query.
//!
//! See the `tables`, `views`, and `providers` submodules for details.

pub mod arrow_schema;
pub mod bpf;
pub mod builders;
mod engine;
mod filter;
pub mod fusion;
mod options;
mod planning;
pub mod providers;
mod query_stream;
mod session;
mod source;
pub mod streaming;
pub mod tables;
pub mod udf;
pub mod views;
pub mod windowing;

pub use engine::{QueryEngine, QueryOutput};
pub use filter::{is_pushable, row_predicate};
pub use options::{CloudSourceOptions, EngineOptions, RetentionPolicy, SourceSpec};
pub use providers::{
    auto_target_partitions, merge_ordered_partitions, CompiledSubscription, ParseStats,
    ParseSubscription, ProgressFn, ProtocolScanExec, ProtocolTableProvider, ServedFrom,
    TableSubscription,
};
pub use query_stream::QueryStream;
pub use streaming::MemoryLimitPolicy;
pub use udf::CaptureTimeRange;
