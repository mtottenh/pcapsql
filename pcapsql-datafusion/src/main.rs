//! pcapsql CLI entry point.

use std::io;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;

use pcapsql_datafusion::cli::{
    Args, ExportFormat, Exporter, OutputFormatter, Repl, ReplCommand, ReplInput,
};
use pcapsql_datafusion::query::{tables, views, QueryEngine};
use pcapsql_core::{default_registry, Protocol};

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

    // Require a PCAP file for query operations
    let pcap_file = args
        .file
        .context("PCAP file required. Use --help for usage.")?;

    // Create query engine - choose mode based on flags
    let engine = if args.streaming {
        // Explicit streaming mode with cache
        if args.mmap {
            // Try mmap first
            use pcapsql_core::MmapPacketSource;
            use std::sync::Arc;
            match MmapPacketSource::open(&pcap_file) {
                Ok(source) => {
                    QueryEngine::with_streaming_source_cached_opts(
                        Arc::new(source),
                        args.batch_size,
                        args.cache_size,
                        !args.no_reader_eviction,
                    )
                    .await
                    .with_context(|| format!("Failed to open PCAP file: {}", pcap_file.display()))?
                }
                Err(e) => {
                    eprintln!(
                        "Warning: mmap not supported for this file ({}), falling back to file source",
                        e
                    );
                    use pcapsql_core::FilePacketSource;
                    let source = Arc::new(FilePacketSource::open(&pcap_file)
                        .with_context(|| format!("Failed to open PCAP file: {}", pcap_file.display()))?);
                    QueryEngine::with_streaming_source_cached_opts(source, args.batch_size, args.cache_size, !args.no_reader_eviction)
                        .await
                        .with_context(|| format!("Failed to create engine"))?
                }
            }
        } else {
            use pcapsql_core::FilePacketSource;
            use std::sync::Arc;
            let source = Arc::new(FilePacketSource::open(&pcap_file)
                .with_context(|| format!("Failed to open PCAP file: {}", pcap_file.display()))?);
            QueryEngine::with_streaming_source_cached_opts(source, args.batch_size, args.cache_size, !args.no_reader_eviction)
                .await
                .with_context(|| format!("Failed to create engine"))?
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
            let export_format = args.export_format
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
            let export_format = args.export_format
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
        println!("Table: {}", table_name);
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
    pcap_file: &PathBuf,
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
                    ReplCommand::Unknown(s) => {
                        eprintln!("Unknown command: {s}");
                        eprintln!("Type .help for available commands");
                    }
                    ReplCommand::Sql(query) => {
                        match engine.query(&query).await {
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
                        }
                    }
                    ReplCommand::Export(filename, query_opt) => {
                        // Determine export format from filename
                        let path = PathBuf::from(&filename);
                        let format = ExportFormat::from_extension(&path)
                            .unwrap_or(ExportFormat::Parquet);

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
                            Ok(batches) => {
                                match Exporter::export(&path, format, &batches) {
                                    Ok(rows) => {
                                        println!("Exported {rows} rows to {filename}");
                                    }
                                    Err(e) => {
                                        eprintln!("Export error: {e}");
                                    }
                                }
                            }
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
        println!("  {}", table_name);
    }

    println!();
    println!("Cross-Layer Views (JOINed protocol data):");
    for view in views::all_views() {
        println!("  {:20} - {}", view.name, view.description);
    }
}
