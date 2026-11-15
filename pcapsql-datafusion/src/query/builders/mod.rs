//! Batch builders for normalized protocol tables.
//!
//! This module provides builders for creating Arrow RecordBatches from parsed
//! packet data. Instead of a single flat table, we build separate tables for
//! each protocol layer.
//!
//! ## Architecture
//!
//! ```text
//! Parsed Packets → NormalizedBatchSet → the SUBSCRIBED protocol tables
//!                        │                  (per-query column subsets,
//!                        ├─► frames          parse-time predicates and
//!                        ├─► tcp             row caps applied before any
//!                        ├─► …               Arrow materialization)
//!                        └─► fused joins    (a view's joined row, built from
//!                                            the frame's own layers; see
//!                                            `crate::query::fusion`)
//! ```
//!
//! Each protocol table contains only the fields relevant to that protocol,
//! with `frame_number` as the linking key for JOINs.
//!
//! Which rows a packet adds to `frames` and the protocol tables, and what
//! each cell holds, is decided in `pcapsql_core::scan` (`Router`,
//! `write_value`), which the frontends share. Here the rows land in an
//! [`ArrowSink`] per table, and [`NormalizedBatchSet`] delivers the batches.
//! Fused joins still have their own builder ([`FusedBatchBuilder`]).

mod dynamic;
mod fused;
mod normalized;
mod sink;

pub use fused::FusedBatchBuilder;
pub use normalized::NormalizedBatchSet;
pub use sink::{ArrowList, ArrowSink};
