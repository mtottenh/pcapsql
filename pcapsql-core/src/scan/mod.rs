//! The engine-neutral scan layer.
//!
//! **Unstable API.** This module is the part of the scan path that the SQL
//! frontends (`pcapsql-datafusion`, the DuckDB extension) share. It is being
//! built up step by step and its types may change in any release, without a
//! deprecation period. Nothing here depends on Arrow or on a SQL engine.
//!
//! So far it holds:
//!
//! - the [`catalog`]: which tables exist and which columns they have;
//! - the [`plan`]: what one pass over a capture must produce
//!   ([`ScanPlan`]), and that description resolved for the packet loop
//!   ([`CompiledScan`]);
//! - the [`predicate`]s a scan applies itself: the conservative
//!   [`RowPredicate`] and the exact [`FramePredicate`].
//!
//! - the [`sink`] a frontend implements to store rows in its own format
//!   ([`RowSink`]);
//! - the [`row`]s: what every cell holds. [`write_value`] is the one place
//!   a parsed value is turned into a column's kind, so every frontend
//!   stores the same cells;
//! - the [`route`]: which rows a frame adds to which output, with row
//!   predicates, row caps and sinks of bounded size ([`Router`]);
//! - [`testing`]: a recording sink and the conformance suite a sink
//!   implementation runs in its tests.
//!
//! Nothing in core reads a capture for a [`CompiledScan`] yet: the
//! frontends run their own packet loops and call the [`Router`] per frame.

pub mod catalog;
pub mod plan;
pub mod predicate;
pub mod route;
pub mod row;
pub mod sink;
mod tables;
pub mod testing;

pub use catalog::{
    Catalog, ColId, ColKind, ColumnDef, ColumnSource, StreamTable, TableDef, TableId, TableKind,
    TimestampUnit, UnsupportedKind,
};
pub use plan::{
    CompiledScan, FusedMember, FusedScan, JoinKind, MemberJoin, OutCol, OutColumn, OutputId,
    OutputPlan, PlanError, ScanPlan, TableScan,
};
pub use predicate::{CmpOp, CompiledPredicate, FramePredicate, Literal, RowPredicate};
pub use route::{Routed, Router};
pub use row::{write_frame_row, write_layer_row, write_value, FieldResolver};
pub use sink::{Full, ListSink, RowSink};
