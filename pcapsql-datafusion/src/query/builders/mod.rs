//! Batch builders for normalized protocol tables.
//!
//! This module provides builders for creating Arrow RecordBatches from parsed
//! packet data. Instead of a single flat table, we build separate tables for
//! each protocol layer.
//!
//! ## Architecture
//!
//! ```text
//! Parsed Packets → NormalizedBatchSet → Multiple Protocol Tables
//!                        │
//!                        ├─► frames table
//!                        ├─► ethernet table
//!                        ├─► ipv4 table
//!                        ├─► ipv6 table
//!                        ├─► tcp table
//!                        ├─► udp table
//!                        ├─► dns table
//!                        └─► ... other protocol tables
//! ```
//!
//! Each protocol table contains only the fields relevant to that protocol,
//! with `frame_number` as the linking key for JOINs.

mod normalized;
mod protocol;

pub use normalized::NormalizedBatchSet;
pub use protocol::ProtocolBatchBuilder;

use std::collections::HashMap;

use arrow::record_batch::RecordBatch;

/// A collection of RecordBatches for all protocol tables.
pub type ProtocolBatches = HashMap<String, Vec<RecordBatch>>;

/// A single set of RecordBatches, one per protocol table.
pub type ProtocolBatchMap = HashMap<String, RecordBatch>;
