//! The interactive REPL: the read loop and one function per command.

use std::io;
use std::path::PathBuf;

use anyhow::Result;
use arrow::array::RecordBatch;

use super::format::{
    format_arrow_value, format_bytes_decimal, format_count, format_duration_us, format_hexdump,
    format_timestamp_us, render_bar,
};
use super::listing::{list_protocols, list_udfs, print_help, print_tables, show_schema};
use super::stats::{print_cache_stats, print_parse_stats};
use super::{ExportFormat, Exporter, OutputFormatter, Repl, ReplCommand, ReplInput};
use crate::query::QueryEngine;
use crate::QueryOutput;

/// Run one REPL statement with the spinner live (when `--progress`), cleared
/// before anything is printed.
async fn run_statement(
    engine: &QueryEngine,
    progress_bar: Option<&indicatif::ProgressBar>,
    sql: &str,
) -> crate::Result<QueryOutput> {
    if let Some(pb) = progress_bar {
        pb.reset();
    }
    let output = engine.execute(sql).await;
    if let Some(pb) = progress_bar {
        pb.finish_and_clear();
    }
    output
}

/// CLI flags that apply to every statement the REPL runs.
pub struct ReplOptions {
    /// `--stats`: print the parse statistics after each query.
    pub show_stats: bool,
    /// `--progress`: the spinner, ticked by the engine's parse callback.
    pub progress_bar: Option<indicatif::ProgressBar>,
}

/// Run the interactive REPL until `.quit` or end of input.
pub async fn run_repl(
    engine: &QueryEngine,
    formatter: &OutputFormatter,
    source_name: &str,
    options: ReplOptions,
) -> Result<()> {
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
    println!("Loaded: {source_name}");
    println!("Type .help for help, .quit to exit");
    println!();

    loop {
        match repl.read_input()? {
            ReplInput::Exit => {
                println!("Goodbye!");
                break;
            }
            ReplInput::Command(cmd) => match cmd {
                ReplCommand::Empty => continue,
                ReplCommand::Quit => {
                    println!("Goodbye!");
                    break;
                }
                ReplCommand::Help => print_help(),
                ReplCommand::Tables => print_tables(),
                ReplCommand::Schema => show_schema(),
                ReplCommand::Protocols => list_protocols(),
                ReplCommand::Udfs => list_udfs(),
                ReplCommand::CacheStats => print_cache_stats(engine),
                ReplCommand::CacheStatsReset => cache_stats_reset(engine),
                ReplCommand::TimeInfo => time_info(engine).await,
                ReplCommand::Hexdump(frame_num) => hexdump(engine, frame_num).await,
                ReplCommand::Stats => stats(engine).await,
                ReplCommand::Top(column, limit) => top(engine, column, limit).await,
                ReplCommand::Histogram(column) => histogram(engine, column).await,
                ReplCommand::Unknown(s) => unknown(s),
                ReplCommand::Sql(query) => {
                    sql(engine, formatter, &options, query, &mut last_result).await
                }
                ReplCommand::Export(filename, query_opt) => {
                    export(engine, &options, filename, query_opt, &last_result).await
                }
            },
        }
    }

    Ok(())
}

/// `.cachestats reset`: clear the table cache.
fn cache_stats_reset(engine: &QueryEngine) {
    let n = engine.cached_tables().len();
    engine.clear_cache();
    println!("Cleared {n} cached table(s); the next query re-parses them.");
}

/// `.timeinfo`: the capture's time range and packet count.
async fn time_info(engine: &QueryEngine) {
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
                    .and_then(|a| if a.is_null(0) { None } else { Some(a.value(0)) });

                // Extract end timestamp
                let end_ts = batch
                    .column(1)
                    .as_any()
                    .downcast_ref::<TimestampMicrosecondArray>()
                    .and_then(|a| if a.is_null(0) { None } else { Some(a.value(0)) });

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
                        println!("  Duration:  {}", format_duration_us(duration));
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

/// `.hexdump <frame>`: a hex dump of one frame's bytes.
async fn hexdump(engine: &QueryEngine, frame_num: u64) {
    use arrow::array::{Array, BinaryArray};

    let query = format!("SELECT raw_data FROM frames WHERE frame_number = {frame_num}");
    match engine.query(&query).await {
        Ok(batches) => {
            let has_data = batches.first().map(|b| b.num_rows() > 0).unwrap_or(false);

            if !has_data {
                println!("Frame {frame_num} not found.");
            } else if let Some(batch) = batches.first() {
                let raw_data = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<BinaryArray>()
                    .and_then(|a| if a.is_null(0) { None } else { Some(a.value(0)) });

                if let Some(data) = raw_data {
                    print!("{}", format_hexdump(frame_num, data));
                } else {
                    println!("Frame {frame_num} has no data.");
                }
            }
        }
        Err(e) => eprintln!("Error: {e}"),
    }
}

/// `.stats`: packets, bytes, time range and protocol distribution.
async fn stats(engine: &QueryEngine) {
    use arrow::array::{Array, Int64Array, StringArray};

    // Query basic stats from frames
    let stats_query =
        "SELECT COUNT(*) as packets, SUM(CAST(length AS BIGINT)) as bytes FROM frames";
    match engine.query(stats_query).await {
        Ok(batches) => {
            if let Some(batch) = batches.first() {
                let packets = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<Int64Array>()
                    .and_then(|a| {
                        if a.is_null(0) {
                            None
                        } else {
                            Some(a.value(0) as u64)
                        }
                    })
                    .unwrap_or(0);
                let bytes = batch
                    .column(1)
                    .as_any()
                    .downcast_ref::<Int64Array>()
                    .and_then(|a| {
                        if a.is_null(0) {
                            None
                        } else {
                            Some(a.value(0) as u64)
                        }
                    })
                    .unwrap_or(0);

                println!("Capture Statistics:");
                println!("  Packets:    {}", format_count(packets));
                println!("  Bytes:      {}", format_bytes_decimal(bytes));
            }
        }
        Err(e) => eprintln!("Error querying stats: {e}"),
    }

    // Query time range
    let time_query = "SELECT MIN(timestamp) as start_ts, MAX(timestamp) as end_ts FROM frames";
    if let Ok(batches) = engine.query(time_query).await {
        if let Some(batch) = batches.first() {
            use arrow::array::TimestampMicrosecondArray;
            let start_ts = batch
                .column(0)
                .as_any()
                .downcast_ref::<TimestampMicrosecondArray>()
                .and_then(|a| if a.is_null(0) { None } else { Some(a.value(0)) });
            let end_ts = batch
                .column(1)
                .as_any()
                .downcast_ref::<TimestampMicrosecondArray>()
                .and_then(|a| if a.is_null(0) { None } else { Some(a.value(0)) });

            if let (Some(start), Some(end)) = (start_ts, end_ts) {
                let duration_us = end - start;
                println!("  Duration:   {}", format_duration_us(duration_us));
                println!("  Start:      {}", format_timestamp_us(start));
                println!("  End:        {}", format_timestamp_us(end));
            }
        }
    }

    // Query protocol distribution
    let proto_query = r#"
        SELECT 'TCP' as proto, COUNT(*) as cnt FROM tcp
        UNION ALL SELECT 'UDP', COUNT(*) FROM udp
        UNION ALL SELECT 'ICMP', COUNT(*) FROM icmp
        UNION ALL SELECT 'DNS', COUNT(*) FROM dns
        UNION ALL SELECT 'HTTP', COUNT(*) FROM http
        UNION ALL SELECT 'TLS', COUNT(*) FROM tls
        ORDER BY cnt DESC
    "#;
    if let Ok(batches) = engine.query(proto_query).await {
        let mut total: u64 = 0;
        let mut protos: Vec<(String, u64)> = Vec::new();

        for batch in &batches {
            let proto_col = batch.column(0).as_any().downcast_ref::<StringArray>();
            let count_col = batch.column(1).as_any().downcast_ref::<Int64Array>();

            if let (Some(protos_arr), Some(counts_arr)) = (proto_col, count_col) {
                for i in 0..batch.num_rows() {
                    if !protos_arr.is_null(i) && !counts_arr.is_null(i) {
                        let proto = protos_arr.value(i).to_string();
                        let count = counts_arr.value(i) as u64;
                        if count > 0 {
                            total += count;
                            protos.push((proto, count));
                        }
                    }
                }
            }
        }

        if !protos.is_empty() {
            println!();
            println!("Protocol Distribution:");
            for (proto, count) in protos {
                let pct = if total > 0 {
                    count as f64 / total as f64 * 100.0
                } else {
                    0.0
                };
                println!("  {:<10} {:>10}  ({:.1}%)", proto, format_count(count), pct);
            }
        }
    }
}

/// `.top <col> [N]`: the most frequent values of a column.
async fn top(engine: &QueryEngine, column: String, limit: usize) {
    use arrow::array::{Array, Int64Array};

    // Build query - try to detect if column contains IPs
    let display_col = if column.contains("ip") && !column.contains("ip6") {
        format!("ip4_to_string({column}) as {column}")
    } else if column.contains("ip6") {
        format!("ip6_to_string({column}) as {column}")
    } else if column.contains("mac") {
        format!("mac_to_string({column}) as {column}")
    } else {
        column.clone()
    };

    // Try frames table first, then specific protocol tables
    let tables = ["frames", "ipv4", "tcp", "udp", "dns"];
    let mut found = false;

    for table in tables {
        let query = format!(
            "SELECT {display_col}, COUNT(*) as count FROM {table} WHERE {column} IS NOT NULL GROUP BY {column} ORDER BY count DESC LIMIT {limit}"
        );

        match engine.query(&query).await {
            Ok(batches) => {
                if batches.first().map(|b| b.num_rows() > 0).unwrap_or(false) {
                    found = true;
                    println!("Top {limit} {column} values (from {table}):");

                    for batch in &batches {
                        let val_col = batch.column(0);
                        let count_col = batch.column(1).as_any().downcast_ref::<Int64Array>();

                        if let Some(counts) = count_col {
                            for i in 0..batch.num_rows() {
                                let value = format_arrow_value(val_col, i);
                                let count = if counts.is_null(i) {
                                    0
                                } else {
                                    counts.value(i) as u64
                                };
                                println!("  {:<20} {:>10}", value, format_count(count));
                            }
                        }
                    }
                    break;
                }
            }
            Err(_) => continue,
        }
    }

    if !found {
        eprintln!("Column '{column}' not found in any table");
    }
}

/// `.histogram <col>`: the distribution of a numeric column in ten buckets.
async fn histogram(engine: &QueryEngine, column: String) {
    use arrow::array::{Array, Float64Array, Int64Array};

    // First get min/max to determine bucket size
    let tables = ["frames", "ipv4", "tcp", "udp"];
    let mut found = false;

    for table in tables {
        let range_query = format!(
            "SELECT MIN(CAST({column} AS DOUBLE)) as min_val, MAX(CAST({column} AS DOUBLE)) as max_val FROM {table} WHERE {column} IS NOT NULL"
        );

        if let Ok(batches) = engine.query(&range_query).await {
            if let Some(batch) = batches.first() {
                if batch.num_rows() == 0 {
                    continue;
                }

                let min_val = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<Float64Array>()
                    .and_then(|a| if a.is_null(0) { None } else { Some(a.value(0)) });
                let max_val = batch
                    .column(1)
                    .as_any()
                    .downcast_ref::<Float64Array>()
                    .and_then(|a| if a.is_null(0) { None } else { Some(a.value(0)) });

                if let (Some(min_v), Some(max_v)) = (min_val, max_val) {
                    if min_v == max_v {
                        continue;
                    }

                    found = true;
                    let range = max_v - min_v;
                    let bucket_size = (range / 10.0).max(1.0);

                    let hist_query = format!(
                        "SELECT FLOOR(CAST({column} AS DOUBLE) / {bucket_size}) * {bucket_size} as bucket, COUNT(*) as count \
                         FROM {table} WHERE {column} IS NOT NULL \
                         GROUP BY bucket ORDER BY bucket"
                    );

                    if let Ok(hist_batches) = engine.query(&hist_query).await {
                        // Collect all buckets and find max count
                        let mut buckets: Vec<(f64, u64)> = Vec::new();
                        let mut max_count: u64 = 0;

                        for hb in &hist_batches {
                            let bucket_col = hb.column(0).as_any().downcast_ref::<Float64Array>();
                            let count_col = hb.column(1).as_any().downcast_ref::<Int64Array>();

                            if let (Some(buckets_arr), Some(counts_arr)) = (bucket_col, count_col) {
                                for i in 0..hb.num_rows() {
                                    if !buckets_arr.is_null(i) && !counts_arr.is_null(i) {
                                        let bucket = buckets_arr.value(i);
                                        let count = counts_arr.value(i) as u64;
                                        max_count = max_count.max(count);
                                        buckets.push((bucket, count));
                                    }
                                }
                            }
                        }

                        if !buckets.is_empty() {
                            println!("{column} distribution (from {table}):");
                            for (bucket, count) in &buckets {
                                let end = bucket + bucket_size;
                                let bar = render_bar(*count, max_count, 30);
                                println!(
                                    "  {:>8.0}-{:<8.0} {} {:>10}",
                                    bucket,
                                    end,
                                    bar,
                                    format_count(*count)
                                );
                            }
                        }
                    }
                    break;
                }
            }
        }
    }

    if !found {
        eprintln!("Column '{column}' not found or not numeric");
    }
}

/// A command the REPL does not know.
fn unknown(s: String) {
    eprintln!("Unknown command: {s}");
    eprintln!("Type .help for available commands");
}

/// A SQL statement: run it, print its result and keep it for `.export`.
async fn sql(
    engine: &QueryEngine,
    formatter: &OutputFormatter,
    options: &ReplOptions,
    query: String,
    last_result: &mut Option<Vec<RecordBatch>>,
) {
    let pb = options.progress_bar.as_ref();
    match run_statement(engine, pb, &query).await {
        Ok(QueryOutput { batches, stats }) => {
            let mut stdout = io::stdout();
            if let Err(e) = formatter.write_batches(&batches, &mut stdout) {
                eprintln!("Error writing output: {e}");
            }
            if options.show_stats {
                print_parse_stats(&stats);
            }
            *last_result = Some(batches);
        }
        Err(e) => {
            eprintln!("Error: {e}");
        }
    }
}

/// `.export <file> [query]`: write the query's result, or the last result,
/// to a file.
async fn export(
    engine: &QueryEngine,
    options: &ReplOptions,
    filename: String,
    query_opt: Option<String>,
    last_result: &Option<Vec<RecordBatch>>,
) {
    let pb = options.progress_bar.as_ref();
    // Determine export format from filename
    let path = PathBuf::from(&filename);
    let format = ExportFormat::from_extension(&path).unwrap_or(ExportFormat::Parquet);

    // Get batches to export
    let batches_result = if let Some(query) = query_opt {
        // Run the provided query
        run_statement(engine, pb, &query)
            .await
            .map(|out| out.batches)
    } else if let Some(batches) = last_result {
        // Use last result
        Ok(batches.clone())
    } else {
        eprintln!("No previous query result to export. Run a query first or provide one.");
        return;
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
