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
//!        │                             before any Arrow materialization)
//!        │                         ──► ArrowSink per fused join (a view's
//!        │                             joined row, from the frame's own
//!        │ every frame, once           layers; see `crate::query::fusion`)
//!        ▼
//! NormalizedBatchSet ──► the stream subscriber
//!   (the scan's observer)
//!        └─► delivery of every table's batches: accumulated, or sent to
//!            the plan through its exchange
//! ```
//!
//! Each protocol table contains only the fields relevant to that protocol,
//! with `frame_number` as the linking key for JOINs.
//!
//! Reading a partition, which rows a packet adds to `frames`, the protocol
//! tables and the fused joins, and what each cell holds, is decided in
//! `pcapsql_core::scan` (`PartitionScan`, `Router`, `write_value`), which
//! the frontends share. Here the rows land in an [`ArrowSink`] per table
//! or fused join, and [`NormalizedBatchSet`] delivers the batches.

mod normalized;
mod sink;

pub use normalized::NormalizedBatchSet;
pub use sink::{ArrowList, ArrowSink};
