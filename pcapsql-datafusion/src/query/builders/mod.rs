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
//!                        └─► …               Arrow materialization)
//! ```
//!
//! Each protocol table contains only the fields relevant to that protocol,
//! with `frame_number` as the linking key for JOINs.

mod normalized;
mod protocol;

pub use normalized::NormalizedBatchSet;
pub use protocol::ProtocolBatchBuilder;
