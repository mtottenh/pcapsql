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
//! Nothing in core runs a [`CompiledScan`] yet: the frontends drive their
//! own packet loops from it.

pub mod catalog;
pub mod plan;
pub mod predicate;
mod tables;

pub use catalog::{
    Catalog, ColId, ColKind, ColumnDef, ColumnSource, StreamTable, TableDef, TableId, TableKind,
    TimestampUnit, UnsupportedKind,
};
pub use plan::{
    CompiledScan, FusedMember, FusedScan, JoinKind, MemberJoin, OutCol, OutColumn, OutputId,
    OutputPlan, PlanError, ScanPlan, TableScan,
};
pub use predicate::{CmpOp, CompiledPredicate, FramePredicate, Literal, RowPredicate};
