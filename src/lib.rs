//! pcapsql - Query PCAP files using SQL syntax.
//!
//! This library provides tools for parsing PCAP/PCAPNG files and
//! querying packet data using SQL via Apache DataFusion.
//!
//! # Example
//!
//! ```no_run
//! use pcapsql::query::QueryEngine;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let engine = QueryEngine::new("capture.pcap", 10000).await?;
//!     let results = engine.query("SELECT COUNT(*) FROM packets").await?;
//!     // Process results...
//!     Ok(())
//! }
//! ```

pub mod cache;
pub mod cli;
pub mod error;
pub mod format;
pub mod io;
pub mod pcap;
pub mod protocol;
pub mod query;
pub mod stream;

pub use error::{Error, Result};
