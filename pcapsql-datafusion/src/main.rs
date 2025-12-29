//! pcapsql CLI entry point.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;

use pcapsql_core::{default_registry, KeyLog, Protocol};
use pcapsql_datafusion::cli::{
    Args, ExportFormat, Exporter, OutputFormatter, Repl, ReplCommand, ReplInput,
};
use pcapsql_datafusion::query::{tables, views, QueryEngine};

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Set up logging
    let filter = match args.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()))
        .init();

    // Handle info-only commands
    if args.list_protocols {
        list_protocols();
        return Ok(());
    }

    if args.show_schema {
        show_schema();
        return Ok(());
    }

    // Load keylog for TLS decryption (if provided)
    let keylog = load_keylog(&args);
    if args.verbose > 0 {
        print_tls_status(&keylog);
    }

    // Require a PCAP file for query operations
    let pcap_file = args
        .file
        .context("PCAP file required. Use --help for usage.")?;

    // Create query engine - choose mode based on flags and keylog
    let engine = if let Some(kl) = keylog {
        // TLS decryption enabled - use with_keylog for stream processing
        if args.verbose > 0 {
            eprintln!("Processing TCP streams for TLS decryption...");
        }
        QueryEngine::with_keylog(&pcap_file, kl, args.batch_size)
            .await
            .with_context(|| format!("Failed to open PCAP file: {}", pcap_file.display()))?
    } else if args.streaming {
        // Explicit streaming mode with cache
        if args.mmap {
            // Try mmap first
            use pcapsql_core::MmapPacketSource;
            match MmapPacketSource::open(&pcap_file) {
                Ok(source) => QueryEngine::with_streaming_source_cached_opts(
                    Arc::new(source),
                    args.batch_size,
                    args.cache_size,
                    !args.no_reader_eviction,
                )
                .await
                .with_context(|| format!("Failed to open PCAP file: {}", pcap_file.display()))?,
                Err(e) => {
                    eprintln!(
                        "Warning: mmap not supported for this file ({e}), falling back to file source"
                    );
                    use pcapsql_core::FilePacketSource;
                    let source =
                        Arc::new(FilePacketSource::open(&pcap_file).with_context(|| {
                            format!("Failed to open PCAP file: {}", pcap_file.display())
                        })?);
                    QueryEngine::with_streaming_source_cached_opts(
                        source,
                        args.batch_size,
                        args.cache_size,
                        !args.no_reader_eviction,
                    )
                    .await
                    .with_context(|| "Failed to create engine".to_string())?
                }
            }
        } else {
            use pcapsql_core::FilePacketSource;
            let source =
                Arc::new(FilePacketSource::open(&pcap_file).with_context(|| {
                    format!("Failed to open PCAP file: {}", pcap_file.display())
                })?);
            QueryEngine::with_streaming_source_cached_opts(
                source,
                args.batch_size,
                args.cache_size,
                !args.no_reader_eviction,
            )
            .await
            .with_context(|| "Failed to create engine".to_string())?
        }
    } else {
        // In-memory mode (default for small files)
        QueryEngine::with_progress(&pcap_file, args.batch_size, args.progress)
            .await
            .with_context(|| format!("Failed to open PCAP file: {}", pcap_file.display()))?
    };

    let formatter = OutputFormatter::new(args.format);

    // Execute query from -e flag
    if let Some(query) = args.query {
        let batches = engine.query(&query).await?;

        // Export if output file specified
        if let Some(output_path) = &args.output {
            let export_format = args
                .export_format
                .or_else(|| ExportFormat::from_extension(output_path))
                .unwrap_or(ExportFormat::Parquet);

            let rows = Exporter::export(output_path, export_format, &batches)?;
            eprintln!("Exported {} rows to {}", rows, output_path.display());
        } else {
            // Print to stdout
            let mut stdout = io::stdout();
            formatter.write_batches(&batches, &mut stdout)?;
        }

        // Show cache stats if requested
        if args.show_stats {
            print_cache_stats(&engine);
        }

        return Ok(());
    }

    // Execute query from -f file
    if let Some(query_file) = args.query_file {
        let query = std::fs::read_to_string(&query_file)
            .with_context(|| format!("Failed to read query file: {}", query_file.display()))?;

        let batches = engine.query(&query).await?;

        // Export if output file specified
        if let Some(output_path) = &args.output {
            let export_format = args
                .export_format
                .or_else(|| ExportFormat::from_extension(output_path))
                .unwrap_or(ExportFormat::Parquet);

            let rows = Exporter::export(output_path, export_format, &batches)?;
            eprintln!("Exported {} rows to {}", rows, output_path.display());
        } else {
            // Print to stdout
            let mut stdout = io::stdout();
            formatter.write_batches(&batches, &mut stdout)?;
        }

        // Show cache stats if requested
        if args.show_stats {
            print_cache_stats(&engine);
        }

        return Ok(());
    }

    // Interactive REPL
    run_repl(&engine, &formatter, &pcap_file).await
}

fn print_cache_stats(engine: &QueryEngine) {
    if let Some(stats) = engine.cache_stats() {
        eprintln!();
        eprintln!("{}", stats.format_summary());
    } else {
        eprintln!();
        eprintln!("Cache statistics not available (cache disabled or in-memory mode)");
    }
}

fn list_protocols() {
    let registry = default_registry();

    println!("Registered Protocol Parsers:");
    println!("{:-<50}", "");

    for parser in registry.all_parsers() {
        println!("  {} ({})", parser.display_name(), parser.name());

        let children = parser.child_protocols();
        if !children.is_empty() {
            println!("    -> Can identify: {}", children.join(", "));
        }

        let fields = parser.schema_fields();
        if !fields.is_empty() {
            println!("    Fields: {}", fields.len());
        }
    }
}

fn show_schema() {
    println!("=== Protocol Tables ===");
    println!();
    println!("Each protocol has its own table with 'frame_number' as the linking key.");
    println!("Use JOINs on frame_number to combine data across protocol layers.");
    println!();

    // Show each protocol table
    for (table_name, schema) in tables::all_table_schemas() {
        println!("Table: {table_name}");
        println!("{:-<70}", "");
        println!("{:<30} {:<30} Nullable", "Column", "Type");
        println!("{:-<70}", "");

        for field in schema.fields() {
            let arrow_type = format!("{:?}", field.data_type());
            let nullable = if field.is_nullable() { "YES" } else { "NO" };
            println!("{:<30} {:<30} {}", field.name(), arrow_type, nullable);
        }
        println!();
    }

    println!();
    println!("=== Cross-Layer Views ===");
    println!();
    println!("Views provide convenient JOINed access to related protocol data.");
    println!("The 'packets' view provides backward compatibility with the flat schema.");
    println!();

    for view in views::all_views() {
        println!("View: {}", view.name);
        println!("  {}", view.description);
        println!();
    }
}

async fn run_repl(
    engine: &QueryEngine,
    formatter: &OutputFormatter,
    pcap_file: &Path,
) -> Result<()> {
    use arrow::array::RecordBatch;

    let history_path = dirs::data_local_dir()
        .map(|d| d.join("pcapsql").join("history.txt"))
        .unwrap_or_else(|| PathBuf::from(".pcapsql_history"));

    // Create parent directory if needed
    if let Some(parent) = history_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let mut repl = Repl::new()?.with_history(history_path.to_str().unwrap_or(".pcapsql_history"));

    // Store last query result for export
    let mut last_result: Option<Vec<RecordBatch>> = None;

    println!("pcapsql - Query PCAP files with SQL");
    println!("Loaded: {}", pcap_file.display());
    println!("Type .help for help, .quit to exit");
    println!();

    loop {
        match repl.read_input()? {
            ReplInput::Exit => {
                println!("Goodbye!");
                break;
            }
            ReplInput::Command(cmd) => {
                match cmd {
                    ReplCommand::Empty => continue,
                    ReplCommand::Quit => {
                        println!("Goodbye!");
                        break;
                    }
                    ReplCommand::Help => print_help(),
                    ReplCommand::Tables => print_tables(),
                    ReplCommand::Schema => show_schema(),
                    ReplCommand::Protocols => list_protocols(),
                    ReplCommand::Stats => {
                        if let Some(stats) = engine.cache_stats() {
                            println!("{}", stats.format_summary());
                        } else {
                            println!("Cache statistics not available.");
                            println!("Cache is only used in streaming mode with --cache-size > 0");
                        }
                    }
                    ReplCommand::StatsReset => {
                        if let Some(cache) = engine.cache() {
                            cache.reset_stats();
                            println!("Cache statistics reset.");
                        } else {
                            println!("No cache to reset.");
                        }
                    }
                    ReplCommand::TimeInfo => {
                        use arrow::array::{Array, Int64Array, TimestampMicrosecondArray};

                        let query = "SELECT MIN(timestamp) as start_ts, MAX(timestamp) as end_ts, COUNT(*) as packet_count FROM frames";
                        match engine.query(query).await {
                            Ok(batches) => {
                                if let Some(batch) = batches.first() {
                                    // Extract start timestamp
                                    let start_ts = batch
                                        .column(0)
                                        .as_any()
                                        .downcast_ref::<TimestampMicrosecondArray>()
                                        .and_then(|a| {
                                            if a.is_null(0) {
                                                None
                                            } else {
                                                Some(a.value(0))
                                            }
                                        });

                                    // Extract end timestamp
                                    let end_ts = batch
                                        .column(1)
                                        .as_any()
                                        .downcast_ref::<TimestampMicrosecondArray>()
                                        .and_then(|a| {
                                            if a.is_null(0) {
                                                None
                                            } else {
                                                Some(a.value(0))
                                            }
                                        });

                                    // Extract packet count
                                    let packet_count = batch
                                        .column(2)
                                        .as_any()
                                        .downcast_ref::<Int64Array>()
                                        .map(|a| a.value(0))
                                        .unwrap_or(0);

                                    match (start_ts, end_ts) {
                                        (Some(start), Some(end)) => {
                                            let duration = end - start;
                                            println!("Capture Time Information:");
                                            println!("  Start:     {}", format_timestamp_us(start));
                                            println!("  End:       {}", format_timestamp_us(end));
                                            println!(
                                                "  Duration:  {}",
                                                format_duration_us(duration)
                                            );
                                            println!("  Packets:   {packet_count}");
                                        }
                                        _ => {
                                            println!("No packets in capture.");
                                        }
                                    }
                                } else {
                                    println!("No data available.");
                                }
                            }
                            Err(e) => eprintln!("Error: {e}"),
                        }
                    }
                    ReplCommand::Unknown(s) => {
                        eprintln!("Unknown command: {s}");
                        eprintln!("Type .help for available commands");
                    }
                    ReplCommand::Sql(query) => match engine.query(&query).await {
                        Ok(batches) => {
                            let mut stdout = io::stdout();
                            if let Err(e) = formatter.write_batches(&batches, &mut stdout) {
                                eprintln!("Error writing output: {e}");
                            }
                            last_result = Some(batches);
                        }
                        Err(e) => {
                            eprintln!("Error: {e}");
                        }
                    },
                    ReplCommand::Export(filename, query_opt) => {
                        // Determine export format from filename
                        let path = PathBuf::from(&filename);
                        let format =
                            ExportFormat::from_extension(&path).unwrap_or(ExportFormat::Parquet);

                        // Get batches to export
                        let batches_result = if let Some(query) = query_opt {
                            // Run the provided query
                            engine.query(&query).await
                        } else if let Some(ref batches) = last_result {
                            // Use last result
                            Ok(batches.clone())
                        } else {
                            eprintln!("No previous query result to export. Run a query first or provide one.");
                            continue;
                        };

                        match batches_result {
                            Ok(batches) => match Exporter::export(&path, format, &batches) {
                                Ok(rows) => {
                                    println!("Exported {rows} rows to {filename}");
                                }
                                Err(e) => {
                                    eprintln!("Export error: {e}");
                                }
                            },
                            Err(e) => {
                                eprintln!("Query error: {e}");
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

fn print_help() {
    println!("Commands:");
    println!("  .help            Show this help");
    println!("  .tables          List available tables");
    println!("  .schema          Show table schemas");
    println!("  .protocols       List registered protocols");
    println!("  .export <file> [query]  Export to file (format inferred from extension)");
    println!("  .timeinfo        Show capture time information");
    println!("  .stats           Show cache statistics");
    println!("  .stats reset     Reset cache statistics counters");
    println!("  .quit            Exit");
    println!();
    println!("Export formats: .parquet, .json/.jsonl, .csv");
    println!("SQL queries end with a semicolon (;)");
}

fn print_tables() {
    println!("Protocol Tables (use frame_number for JOINs):");
    for table_name in tables::all_table_names() {
        println!("  {table_name}");
    }

    println!();
    println!("Cross-Layer Views (JOINed protocol data):");
    for view in views::all_views() {
        println!("  {:20} - {}", view.name, view.description);
    }
}

/// Get the keylog path from CLI argument or environment variable.
///
/// Priority:
/// 1. --keylog CLI argument
/// 2. PCAPSQL_KEYLOG environment variable
/// 3. SSLKEYLOGFILE environment variable (standard)
fn get_keylog_path(args: &Args) -> Option<PathBuf> {
    // CLI argument takes precedence
    if let Some(path) = &args.keylog {
        return Some(path.clone());
    }

    // Fall back to environment variables
    std::env::var("PCAPSQL_KEYLOG")
        .ok()
        .or_else(|| std::env::var("SSLKEYLOGFILE").ok())
        .map(PathBuf::from)
}

/// Load SSLKEYLOGFILE for TLS decryption.
///
/// Returns None if no keylog is provided or if loading fails.
/// Errors are logged as warnings but don't cause failure.
fn load_keylog(args: &Args) -> Option<Arc<KeyLog>> {
    let path = get_keylog_path(args)?;

    match KeyLog::from_file(&path) {
        Ok(keylog) => {
            if keylog.is_empty() {
                eprintln!("Warning: SSLKEYLOGFILE is empty: {}", path.display());
                return None;
            }
            Some(Arc::new(keylog))
        }
        Err(e) => {
            eprintln!("Warning: Failed to load SSLKEYLOGFILE: {e}");
            eprintln!("         Path: {}", path.display());
            eprintln!("         TLS decryption will be disabled.");
            None
        }
    }
}

/// Format a microsecond Unix timestamp as ISO 8601 UTC.
fn format_timestamp_us(us: i64) -> String {
    // Convert to broken-down time components
    let secs_since_epoch = us / 1_000_000;
    let subsec_us = us % 1_000_000;

    // Calculate date/time components (simplified UTC calculation)
    let days_since_epoch = secs_since_epoch / 86400;
    let time_of_day = secs_since_epoch % 86400;

    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Calculate year, month, day from days since epoch (1970-01-01)
    let (year, month, day) = days_to_ymd(days_since_epoch);

    format!(
        "{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}.{subsec_us:06}Z"
    )
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: i64) -> (i64, u32, u32) {
    // Algorithm from Howard Hinnant's date algorithms
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Format a duration in microseconds as human-readable string.
fn format_duration_us(us: i64) -> String {
    let total_secs = us / 1_000_000;
    let subsec_ms = (us % 1_000_000) / 1000;

    let hours = total_secs / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;

    if hours > 0 {
        format!("{hours}h {mins}m {secs}.{subsec_ms:03}s")
    } else if mins > 0 {
        format!("{mins}m {secs}.{subsec_ms:03}s")
    } else {
        format!("{secs}.{subsec_ms:03}s")
    }
}

/// Print TLS decryption status.
fn print_tls_status(keylog: &Option<Arc<KeyLog>>) {
    match keylog {
        Some(kl) => {
            eprintln!("TLS decryption: enabled");
            eprintln!("  Keylog sessions: {}", kl.session_count());
            eprintln!("  Keylog entries:  {}", kl.entry_count());
            eprintln!();
            eprintln!("  Note: SSLKEYLOGFILE contains sensitive key material.");
            eprintln!("        Do not share or commit these files.");
        }
        None => {
            eprintln!("TLS decryption: disabled");
            eprintln!("  Hint: Use --keylog /path/to/sslkeylog.txt to decrypt TLS traffic");
            eprintln!("        Or set SSLKEYLOGFILE environment variable");
        }
    }
    eprintln!();
}
