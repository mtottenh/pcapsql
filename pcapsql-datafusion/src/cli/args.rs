//! Command-line argument definitions.

use clap::{Parser, ValueEnum};
use std::path::PathBuf;

use super::OutputFormat;

/// Parse size string like "512M" or "1G" into bytes.
pub fn parse_size(s: &str) -> Result<usize, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("Empty size string".to_string());
    }

    let (num_str, multiplier) = if let Some(n) = s.strip_suffix('G') {
        (n, 1024 * 1024 * 1024)
    } else if let Some(n) = s.strip_suffix('M') {
        (n, 1024 * 1024)
    } else if let Some(n) = s.strip_suffix('K') {
        (n, 1024)
    } else {
        (s, 1)
    };

    num_str
        .trim()
        .parse::<usize>()
        .map(|n| n * multiplier)
        .map_err(|e| format!("Invalid size '{s}': {e}"))
}

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

    /// Show progress bar when loading packets
    #[arg(long = "progress")]
    pub progress: bool,

    /// Use streaming mode for large files (lower memory, supports filter/limit pushdown)
    ///
    /// In streaming mode, packets are read on-demand during query execution
    /// rather than loading the entire file into memory. This allows querying
    /// very large PCAP files (10GB+) with bounded memory usage.
    #[arg(long = "streaming")]
    pub streaming: bool,

    /// Cache size for streaming mode (number of parsed packets to cache).
    ///
    /// The parse cache reduces redundant parsing when multiple protocol
    /// tables read the same PCAP file (e.g., during JOIN queries).
    /// Set to 0 to disable caching.
    #[arg(long = "cache-size", default_value = "10000")]
    pub cache_size: usize,

    /// Use memory-mapped I/O for reading PCAP files.
    ///
    /// Can improve performance for large files by letting the OS handle
    /// caching and paging. Not supported for PCAPNG or compressed files.
    #[arg(long = "mmap")]
    pub mmap: bool,

    // --- Stream Tracking Options ---
    /// Enable TCP stream tracking and reassembly.
    ///
    /// When enabled, provides additional tables:
    /// - tcp_connections: Connection metadata and statistics
    /// - tcp_streams: Raw reassembled stream data
    /// - http_messages: Parsed HTTP request/response messages
    /// - tls_sessions: TLS handshake metadata (SNI, cipher suites)
    #[arg(long = "track-streams")]
    pub track_streams: bool,

    /// Path to SSLKEYLOGFILE for TLS decryption.
    ///
    /// Format: One key per line, e.g.:
    ///   CLIENT_RANDOM <hex> <hex_master_secret>
    ///   CLIENT_TRAFFIC_SECRET_0 <hex> <hex_secret>
    #[arg(long = "keylog", value_name = "FILE")]
    pub keylog: Option<PathBuf>,

    /// Maximum memory for stream reassembly buffers.
    ///
    /// Accepts suffixes: K, M, G (e.g., "512M", "1G").
    /// When this limit is reached, oldest connections are evicted.
    #[arg(long = "max-stream-memory", default_value = "1G", value_name = "SIZE", value_parser = parse_size_arg)]
    pub max_stream_memory: usize,

    /// Connection timeout in seconds.
    ///
    /// Connections with no activity for this duration are cleaned up.
    #[arg(long = "stream-timeout", default_value = "300", value_name = "SECONDS")]
    pub stream_timeout_secs: u64,

    /// Show cache statistics after query execution.
    ///
    /// Displays hit rate, eviction counts, memory usage, and other
    /// cache performance metrics. Useful for tuning --cache-size.
    #[arg(long = "stats")]
    pub show_stats: bool,
}

/// Value parser for size arguments (e.g., "512M", "1G").
fn parse_size_arg(s: &str) -> Result<usize, String> {
    parse_size(s)
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

#[cfg(test)]
mod tests {
    use super::*;

    // Test 1: Parse size strings
    #[test]
    fn test_parse_size() {
        assert_eq!(parse_size("1G").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("512M").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_size("64K").unwrap(), 64 * 1024);
        assert_eq!(parse_size("1024").unwrap(), 1024);
    }

    // Test 2: Invalid size strings
    #[test]
    fn test_parse_size_invalid() {
        assert!(parse_size("").is_err());
        assert!(parse_size("abc").is_err());
        assert!(parse_size("-1G").is_err());
    }

    // Test 3: CLI argument parsing with stream options
    #[test]
    fn test_cli_stream_args() {
        let args = Args::try_parse_from([
            "pcapsql",
            "test.pcap",
            "--track-streams",
            "--max-stream-memory",
            "256M",
            "--stream-timeout",
            "60",
        ])
        .unwrap();

        assert!(args.track_streams);
        assert_eq!(args.max_stream_memory, 256 * 1024 * 1024);
        assert_eq!(args.stream_timeout_secs, 60);
    }

    // Test 4: Default stream args
    #[test]
    fn test_default_stream_args() {
        let args = Args::try_parse_from(["pcapsql", "test.pcap"]).unwrap();

        assert!(!args.track_streams);
        assert!(args.keylog.is_none());
        assert_eq!(args.max_stream_memory, 1024 * 1024 * 1024); // 1G default
        assert_eq!(args.stream_timeout_secs, 300); // 5 min default
    }
}
