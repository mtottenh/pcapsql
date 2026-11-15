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
//!   predicates, row caps and sinks of bounded size ([`Router`]). The
//!   outputs are `frames`, the protocol tables, and fused joins
//!   ([`FusedScan`]): joins of those tables on `frame_number`, evaluated per
//!   frame over the frame's own layers, so that a table of joined rows
//!   costs one pass and no join operator;
//! - the [`views`]: the `*_packets` tables, each a fixed fused join with
//!   named columns ([`PacketsView`]), defined once for every frontend;
//! - the [`driver`]: one partition of a scan, read step by step
//!   ([`PartitionScan`]). It reads the packets, parses them and routes
//!   their rows (of the frames the plan's [`FramePredicate`] accepts, and
//!   no further than it can accept any), and returns whenever the frontend
//!   has something to do, so
//!   that an engine that pushes rows to its consumer and one whose consumer
//!   pulls a chunk at a time run the same loop;
//! - [`partition`]: how many partitions a capture is worth
//!   ([`partition_target`]), which ranges of it a plan's frame predicate
//!   leaves to scan ([`plan_ranges`]) and a queue workers claim them from
//!   ([`PartitionQueue`]);
//! - `testing`, behind the cargo feature of that name: a recording sink
//!   and the conformance suite a sink implementation runs in its tests.
//!
//! Stream tables are not built here yet: a frontend that has them feeds
//! its own builders from a [`FrameObserver`].

pub mod catalog;
pub mod driver;
mod fused;
pub mod partition;
pub mod plan;
pub mod predicate;
pub mod route;
pub mod row;
pub mod sink;
mod tables;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod views;

pub use catalog::{
    Catalog, ColId, ColKind, ColumnDef, ColumnSource, TableDef, TableId, TableKind, TimestampUnit,
};
pub use driver::{FrameObserver, NoObserver, PartitionScan, ScanStats, Step};
pub use partition::{partition_target, plan_ranges, PartitionPolicy, PartitionQueue};
pub use plan::{
    CompiledScan, FusedColumn, FusedFilter, FusedMember, FusedScan, FusedValue, JoinKind,
    MemberJoin, OutCol, OutColumn, OutputId, OutputPlan, PlanError, ScanPlan, TableScan,
};
pub use predicate::{CmpOp, CompiledPredicate, FramePredicate, Literal, RowPredicate};
pub use route::{Routed, Router};
pub use row::{write_frame_row, write_layer_row, write_value, FieldResolver};
pub use sink::{Full, ListSink, RowSink};
pub use views::{PacketsView, ViewColumn};
