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
///
/// Only consumed by the `--cloud-chunk-size` value parser; gated with it so
/// the build-script `include!` of this file (which sees no crate features)
/// doesn't carry dead code.
#[cfg(any(feature = "cloud", test))]
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

    /// List available SQL functions (UDFs)
    #[arg(long = "list-udfs")]
    pub list_udfs: bool,

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

    /// Disable memory-mapped I/O and use buffered file reads instead.
    ///
    /// Local files are memory-mapped by default (with automatic fallback to
    /// buffered reads when mmap is unavailable, e.g. compressed captures).
    #[arg(long = "no-mmap")]
    pub no_mmap: bool,

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

    /// Show parse statistics after query execution.
    ///
    /// Displays the number of parse passes performed over the capture and
    /// the partition count used by the parallel parse.
    #[arg(long = "stats")]
    pub show_stats: bool,

    // --- Cloud Storage Options ---
    /// Custom cloud storage endpoint (for S3-compatible services like MinIO, R2).
    ///
    /// Used when reading from cloud URLs (s3://, gs://, az://).
    /// For AWS S3, this is usually not needed (auto-detected from region).
    ///
    /// Examples:
    ///   --cloud-endpoint http://localhost:9000  (MinIO)
    ///   --cloud-endpoint https://s3.us-west-2.amazonaws.com
    #[cfg_attr(feature = "cloud", arg(long = "cloud-endpoint", value_name = "URL"))]
    #[cfg(feature = "cloud")]
    pub cloud_endpoint: Option<String>,

    /// Use anonymous (unsigned) requests for public cloud buckets.
    ///
    /// Skips credential lookup for read-only access to public data.
    #[cfg_attr(feature = "cloud", arg(long = "cloud-anonymous"))]
    #[cfg(feature = "cloud")]
    pub cloud_anonymous: bool,

    /// Buffer size for cloud storage reads (default 8MB).
    ///
    /// Larger values reduce the number of HTTP requests but increase memory usage.
    /// Accepts suffixes: K, M, G (e.g., "16M", "32M").
    #[cfg_attr(feature = "cloud", arg(long = "cloud-chunk-size", default_value = "8M", value_name = "SIZE", value_parser = parse_size_arg))]
    #[cfg(feature = "cloud")]
    pub cloud_chunk_size: usize,
}

/// Value parser for size arguments (e.g., "512M", "1G").
#[cfg(feature = "cloud")]
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

    // Test 3: CLI argument parsing with the keylog option
    #[test]
    fn test_cli_keylog_arg() {
        let args =
            Args::try_parse_from(["pcapsql", "test.pcap", "--keylog", "/tmp/keys.log"]).unwrap();

        assert_eq!(
            args.keylog.as_deref(),
            Some(std::path::Path::new("/tmp/keys.log"))
        );
    }

    // Test 4: Defaults
    #[test]
    fn test_default_args() {
        let args = Args::try_parse_from(["pcapsql", "test.pcap"]).unwrap();

        assert!(args.keylog.is_none());
        assert!(!args.no_mmap);
        assert!(!args.show_stats);
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

    // Test 9: Cloud storage arguments (only when cloud feature enabled)
    #[cfg(feature = "cloud")]
    #[test]
    fn test_cloud_arguments() {
        let args = Args::try_parse_from([
            "pcapsql",
            "s3://bucket/capture.pcap",
            "--cloud-endpoint",
            "http://localhost:9000",
            "--cloud-anonymous",
            "--cloud-chunk-size",
            "16M",
            "-e",
            "SELECT COUNT(*) FROM frames",
        ])
        .unwrap();

        assert_eq!(
            args.cloud_endpoint,
            Some("http://localhost:9000".to_string())
        );
        assert!(args.cloud_anonymous);
        assert_eq!(args.cloud_chunk_size, 16 * 1024 * 1024);
    }

    // Test 10: Cloud storage default values
    #[cfg(feature = "cloud")]
    #[test]
    fn test_cloud_defaults() {
        let args = Args::try_parse_from(["pcapsql", "s3://bucket/test.pcap"]).unwrap();

        assert!(args.cloud_endpoint.is_none());
        assert!(!args.cloud_anonymous);
        assert_eq!(args.cloud_chunk_size, 8 * 1024 * 1024); // 8MB default
    }
}
