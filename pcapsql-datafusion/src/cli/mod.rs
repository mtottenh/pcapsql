//! Command-line interface module.
//!
//! This module handles:
//! - Argument parsing via clap
//! - Interactive REPL via rustyline
//! - Output formatting (table, CSV, JSON)
//! - Export functionality (Parquet, JSON, CSV, SQLite files)
//! - URI handling and cloud storage detection

mod args;
mod export;
mod output;
mod repl;
mod sqlite;
mod uri;

pub use args::{parse_size, Args, ExportFormat};
pub use export::Exporter;
pub use output::{OutputFormat, OutputFormatter};
pub use repl::{Repl, ReplCommand, ReplInput};
pub use sqlite::SqliteExporter;
pub use uri::InputSource;

#[cfg(feature = "cloud")]
pub use uri::CloudOptions;
