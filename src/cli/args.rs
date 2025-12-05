//! Command-line argument definitions.

use clap::{Parser, ValueEnum};
use std::path::PathBuf;

use super::OutputFormat;

/// Export file formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ExportFormat {
    /// Apache Parquet columnar format
    Parquet,
    /// JSON Lines (one JSON object per row)
    Json,
    /// Comma-separated values
    Csv,
}

impl ExportFormat {
    /// Infer export format from file extension.
    pub fn from_extension(path: &PathBuf) -> Option<Self> {
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_lowercase())
            .and_then(|ext| match ext.as_str() {
                "parquet" | "pq" => Some(ExportFormat::Parquet),
                "json" | "jsonl" | "ndjson" => Some(ExportFormat::Json),
                "csv" => Some(ExportFormat::Csv),
                _ => None,
            })
    }
}

/// Query PCAP files using SQL syntax.
#[derive(Parser, Debug)]
#[command(name = "pcapsql")]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// PCAP file to query
    #[arg(value_name = "FILE")]
    pub file: Option<PathBuf>,

    /// Execute a single SQL query and exit
    #[arg(short = 'e', long = "execute", value_name = "SQL")]
    pub query: Option<String>,

    /// Read SQL query from file
    #[arg(short = 'f', long = "file", value_name = "QUERY_FILE")]
    pub query_file: Option<PathBuf>,

    /// Output format for stdout
    #[arg(long = "format", value_enum, default_value = "table")]
    pub format: OutputFormat,

    /// Export query results to file
    #[arg(short = 'o', long = "output", value_name = "OUTPUT_FILE")]
    pub output: Option<PathBuf>,

    /// Export format (inferred from extension if not specified)
    #[arg(long = "export-format", value_enum, value_name = "FORMAT")]
    pub export_format: Option<ExportFormat>,

    /// List registered protocol parsers
    #[arg(long = "list-protocols")]
    pub list_protocols: bool,

    /// Show table schemas
    #[arg(long = "schema")]
    pub show_schema: bool,

    /// Batch size for processing (packets per batch)
    #[arg(long = "batch-size", default_value = "10000")]
    pub batch_size: usize,

    /// Enable verbose output
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,
}

impl Args {
    /// Check if we should enter interactive REPL mode.
    pub fn is_interactive(&self) -> bool {
        self.file.is_some() && self.query.is_none() && self.query_file.is_none()
    }

    /// Check if this is an info-only command (no PCAP file needed).
    pub fn is_info_only(&self) -> bool {
        self.list_protocols || self.show_schema
    }
}
