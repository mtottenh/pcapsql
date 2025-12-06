//! pcapsql CLI entry point.

use std::io;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;

use pcapsql::cli::{Args, ExportFormat, Exporter, OutputFormatter, Repl, ReplCommand, ReplInput};
use pcapsql::protocol::{default_registry, Protocol};
use pcapsql::query::QueryEngine;

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

    // Create query engine - streaming mode or eager loading
    let engine = if args.streaming {
        QueryEngine::with_streaming(&pcap_file, args.batch_size)
            .await
            .with_context(|| format!("Failed to open PCAP file: {}", pcap_file.display()))?
    } else {
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
            for batch in batches {
                formatter.write(&batch, &mut stdout)?;
            }
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
            for batch in batches {
                formatter.write(&batch, &mut stdout)?;
            }
        }
        return Ok(());
    }

    // Interactive REPL
    run_repl(&engine, &formatter, &pcap_file).await
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
    let registry = default_registry();

    println!("Table: packets");
    println!("{:-<60}", "");
    println!("{:<30} {:<20} Nullable", "Column", "Type");
    println!("{:-<60}", "");

    // Common fields
    let common_fields = [
        ("frame_number", "BIGINT", "NO"),
        ("timestamp", "TIMESTAMP", "NO"),
        ("length", "INT", "NO"),
        ("original_length", "INT", "NO"),
        ("eth_src", "VARCHAR", "YES"),
        ("eth_dst", "VARCHAR", "YES"),
        ("eth_type", "SMALLINT", "YES"),
        ("src_ip", "VARCHAR", "YES"),
        ("dst_ip", "VARCHAR", "YES"),
        ("ip_version", "TINYINT", "YES"),
        ("ip_ttl", "TINYINT", "YES"),
        ("ip_protocol", "TINYINT", "YES"),
        ("src_port", "SMALLINT", "YES"),
        ("dst_port", "SMALLINT", "YES"),
        ("protocol", "VARCHAR", "YES"),
        ("tcp_flags", "SMALLINT", "YES"),
        ("tcp_seq", "INT", "YES"),
        ("tcp_ack", "INT", "YES"),
        ("icmp_type", "TINYINT", "YES"),
        ("icmp_code", "TINYINT", "YES"),
        ("payload_length", "INT", "YES"),
        ("_parse_error", "VARCHAR", "YES"),
    ];

    for (name, dtype, nullable) in &common_fields {
        println!("{name:<30} {dtype:<20} {nullable}");
    }

    println!();
    println!("Protocol-specific fields available via registry:");

    for parser in registry.all_parsers() {
        let fields = parser.schema_fields();
        if !fields.is_empty() {
            println!("\n  {} fields:", parser.display_name());
            for field in fields {
                let arrow_type = format!("{:?}", field.data_type());
                let nullable = if field.is_nullable() { "YES" } else { "NO" };
                println!("    {:<26} {:<20} {}", field.name(), arrow_type, nullable);
            }
        }
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
                    ReplCommand::Unknown(s) => {
                        eprintln!("Unknown command: {s}");
                        eprintln!("Type .help for available commands");
                    }
                    ReplCommand::Sql(query) => {
                        match engine.query(&query).await {
                            Ok(batches) => {
                                let mut stdout = io::stdout();
                                for batch in &batches {
                                    if let Err(e) = formatter.write(batch, &mut stdout) {
                                        eprintln!("Error writing output: {e}");
                                    }
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
    println!("  .help      Show this help");
    println!("  .tables    List available tables");
    println!("  .schema    Show table schemas");
    println!("  .protocols List registered protocols");
    println!("  .export <file> [query]  Export to file (format inferred from extension)");
    println!("  .quit      Exit");
    println!();
    println!("Export formats: .parquet, .json/.jsonl, .csv");
    println!("SQL queries end with a semicolon (;)");
}

fn print_tables() {
    println!("Tables:");
    println!("  packets - Unified packet view with common fields");
    println!("  frames  - Raw frame data (frame_number, timestamp, length, original_length, link_type, raw_data)");
    println!();
    println!("Views (filtered subsets of packets):");
    println!("  tcp     - TCP packets only");
    println!("  udp     - UDP packets only");
    println!("  icmp    - ICMP packets only");
    println!("  arp     - ARP packets only");
    println!("  dns     - DNS packets (port 53)");
    println!("  dhcp    - DHCP packets (ports 67, 68)");
    println!("  ntp     - NTP packets (port 123)");
    println!("  http    - HTTP packets (ports 80, 8080)");
    println!("  tls     - TLS/HTTPS packets (port 443)");
}
