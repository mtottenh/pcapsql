//! Command-line interface module.
//!
//! This module handles:
//! - Argument parsing via clap
//! - Interactive REPL via rustyline
//! - Output formatting (table, CSV, JSON)
//! - Export functionality (Parquet, JSON, CSV files)

mod args;
mod export;
mod output;
mod repl;

pub use args::{Args, ExportFormat};
pub use export::Exporter;
pub use output::{OutputFormat, OutputFormatter};
pub use repl::{Repl, ReplCommand, ReplInput};
