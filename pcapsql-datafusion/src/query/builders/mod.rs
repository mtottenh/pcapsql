//! Batch builders for normalized protocol tables.
//!
//! This module provides builders for creating Arrow RecordBatches from parsed
//! packet data. Instead of a single flat table, we build separate tables for
//! each protocol layer.
//!
//! ## Architecture
//!
//! ```text
//! PartitionScan (pcapsql-core) ──► ArrowSink per SUBSCRIBED protocol table
//!   reads, parses, routes rows        (per-query column subsets, parse-time
//!        │                             predicates and row caps applied
//!        │ every frame, once           before any Arrow materialization)
//!        ▼
//! NormalizedBatchSet ──► fused joins    (a view's joined row, built from
//!   (the scan's observer)                the frame's own layers; see
//!        │                               `crate::query::fusion`)
//!        └─► delivery of every table's batches: accumulated, or sent to
//!            the plan through its exchange
//! ```
//!
//! Each protocol table contains only the fields relevant to that protocol,
//! with `frame_number` as the linking key for JOINs.
//!
//! Reading a partition, which rows a packet adds to `frames` and the
//! protocol tables, and what each cell holds, is decided in
//! `pcapsql_core::scan` (`PartitionScan`, `Router`, `write_value`), which
//! the frontends share. Here the rows land in an [`ArrowSink`] per table,
//! and [`NormalizedBatchSet`] delivers the batches. Fused joins still have
//! their own builder ([`FusedBatchBuilder`]), fed by the batch set.

mod dynamic;
mod fused;
mod normalized;
mod sink;

pub use fused::FusedBatchBuilder;
pub use normalized::NormalizedBatchSet;
pub use sink::{ArrowList, ArrowSink};
