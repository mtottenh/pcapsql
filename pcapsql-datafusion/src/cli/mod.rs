//! Command-line interface module.
//!
//! This module handles:
//! - Argument parsing via clap
//! - Interactive REPL via rustyline
//! - Output formatting (table, CSV, JSON, raw)
//! - Export functionality (Parquet, JSON, CSV, SQLite files)
//! - URI handling and cloud storage detection

mod args;
mod continuous;
mod export;
mod format;
mod listing;
mod output;
mod repl;
mod repl_loop;
mod sqlite;
mod stats;
mod uri;

#[cfg(feature = "cloud")]
pub use args::parse_size;
pub use args::{Args, ExportFormat};
pub use continuous::run_continuous;
pub use export::Exporter;
pub use listing::{list_protocols, list_udfs, show_schema};
pub use output::{OutputFormat, OutputFormatter};
pub use repl::{Repl, ReplCommand, ReplInput};
pub use repl_loop::{run_repl, ReplOptions};
pub use sqlite::SqliteExporter;
pub use stats::print_parse_stats;
pub use uri::InputSource;

#[cfg(feature = "cloud")]
pub use uri::CloudOptions;
