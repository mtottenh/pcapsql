//! pcapsql-datafusion: SQL interface for PCAP analysis.
//!
//! This crate provides DataFusion integration for pcapsql:
//! - Table providers for all protocol tables
//! - Cross-layer SQL views
//! - Network-focused UDFs
//! - Query engine: each query runs one scoped parse pass (parallel across
//!   partitions for seekable sources), materialized or streamed into the plan
//!   according to its [`query::RetentionPolicy`]
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use pcapsql_datafusion::query::{EngineOptions, QueryEngine, SourceSpec};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Open a capture (local path or cloud URL) and build the engine
//!     let engine = QueryEngine::open(
//!         SourceSpec::Path("capture.pcap".into()),
//!         EngineOptions::default(),
//!     )
//!     .await?;
//!
//!     // Execute SQL queries
//!     let results = engine.query("SELECT COUNT(*) FROM frames").await?;
//!     Ok(())
//! }
//! ```
//!
//! A [`QueryEngine`] can be shared between tasks and queried concurrently
//! (see [`query::QueryEngine`] for the concurrency contract).
//!
//! ## Architecture
//!
//! ```text
//! +---------------------------------------------------------------------+
//! |                      pcapsql-datafusion                             |
//! +---------------------------------------------------------------------+
//! |  query/        - QueryEngine, table providers, UDFs                 |
//! |  cli/          - Command-line interface and REPL                    |
//! |  error         - DataFusion-specific error types                    |
//! +---------------------------------------------------------------------+
//!                              |
//!                              v
//! +---------------------------------------------------------------------+
//! |                        pcapsql-core                                 |
//! +---------------------------------------------------------------------+
//! |  Protocol parsing, PCAP reading, boundary index, TCP reassembly     |
//! +---------------------------------------------------------------------+
//! ```

pub mod cli;
pub mod error;
pub mod query;

// Re-export core for convenience
pub use pcapsql_core;

// Re-export commonly used types
pub use error::{Error, QueryError, Result};
pub use query::{ParseStats, QueryEngine, QueryOutput, ServedFrom};
