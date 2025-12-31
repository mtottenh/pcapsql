// Command-line argument definitions.

use clap::{Parser, ValueEnum};
use std::path::{Path, PathBuf};

/// Supported output formats for query results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Pretty-printed table (default)
    Table,
    /// Comma-separated values
    Csv,
    /// JSON Lines (one JSON object per row)
    Json,
}

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
    /// SQLite database
    Sqlite,
}

impl ExportFormat {
    /// Infer export format from file extension.
    // Allow dead_code: This function is used in main.rs but the build script
    // includes this file via include!(), causing a false positive warning.
    #[allow(dead_code)]
    pub fn from_extension(path: &Path) -> Option<Self> {
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_lowercase())
            .and_then(|ext| match ext.as_str() {
                "parquet" | "pq" => Some(ExportFormat::Parquet),
                "json" | "jsonl" | "ndjson" => Some(ExportFormat::Json),
                "csv" => Some(ExportFormat::Csv),
                "sqlite" | "db" | "sqlite3" => Some(ExportFormat::Sqlite),
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

    /// BPF filter expression (tcpdump-style syntax).
    ///
    /// The filter is translated to SQL and added to the query's WHERE clause.
    /// Supports: tcp, udp, icmp, host, port, net, and boolean operators.
    ///
    /// Examples:
    ///   --filter "tcp port 80"
    ///   --filter "host 192.168.1.1 and not port 22"
    ///   --filter "net 10.0.0.0/8 or net 172.16.0.0/12"
    #[arg(long = "filter", value_name = "FILTER")]
    pub filter: Option<String>,

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
    /// Disabled by default (0) since cache overhead typically exceeds parsing cost.
    #[arg(long = "cache-size", default_value = "0")]
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
    /// Enables decryption of TLS 1.2 and TLS 1.3 traffic when the corresponding
    /// session keys are available. The http2 table becomes queryable for decrypted
    /// HTTP/2 frames.
    ///
    /// Format: NSS Key Log format (one key per line):
    ///   CLIENT_RANDOM <hex> <hex_master_secret>       (TLS 1.2)
    ///   CLIENT_TRAFFIC_SECRET_0 <hex> <hex_secret>    (TLS 1.3)
    ///
    /// Generate with: SSLKEYLOGFILE=/tmp/keys.log curl https://example.com
    ///
    /// Falls back to PCAPSQL_KEYLOG or SSLKEYLOGFILE environment variables.
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

    /// Use LRU-only cache eviction (disable reader-position-based eviction).
    #[arg(long = "no-reader-eviction")]
    pub no_reader_eviction: bool,
}

/// Value parser for size arguments (e.g., "512M", "1G").
fn parse_size_arg(s: &str) -> Result<usize, String> {
    parse_size(s)
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

    // Test 5: Keylog argument parsing
    #[test]
    fn test_keylog_argument() {
        let args = Args::try_parse_from([
            "pcapsql",
            "test.pcap",
            "--keylog",
            "/tmp/sslkeylog.txt",
            "-e",
            "SELECT 1",
        ])
        .unwrap();

        assert_eq!(args.keylog, Some(PathBuf::from("/tmp/sslkeylog.txt")));
    }

    // Test 6: Keylog with verbose
    #[test]
    fn test_keylog_with_verbose() {
        let args = Args::try_parse_from([
            "pcapsql",
            "test.pcap",
            "--keylog",
            "/path/to/keys.log",
            "-v",
            "-e",
            "SELECT * FROM http2",
        ])
        .unwrap();

        assert_eq!(args.keylog, Some(PathBuf::from("/path/to/keys.log")));
        assert_eq!(args.verbose, 1);
    }

    // Test 7: BPF filter argument
    #[test]
    fn test_bpf_filter_argument() {
        let args = Args::try_parse_from([
            "pcapsql",
            "test.pcap",
            "--filter",
            "tcp port 80",
            "-e",
            "SELECT * FROM tcp",
        ])
        .unwrap();

        assert_eq!(args.filter, Some("tcp port 80".to_string()));
    }

    // Test 8: BPF filter with complex expression
    #[test]
    fn test_bpf_filter_complex() {
        let args = Args::try_parse_from([
            "pcapsql",
            "test.pcap",
            "--filter",
            "host 192.168.1.1 and not port 22",
            "-e",
            "SELECT * FROM packets",
        ])
        .unwrap();

        assert_eq!(
            args.filter,
            Some("host 192.168.1.1 and not port 22".to_string())
        );
    }
}
