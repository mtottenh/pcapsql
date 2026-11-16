//! The listings the CLI prints: protocols, SQL functions, schemas, tables and
//! the REPL's help.

use crate::query::{tables, udf, views};
use pcapsql_core::{default_registry, Protocol};

pub fn list_protocols() {
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

pub fn list_udfs() {
    println!("Available SQL Functions (UDFs)");
    println!("{:=<70}", "");
    println!();

    for (category, funcs) in udf::info::udfs_by_category() {
        println!("{}:", category.as_str());
        println!("{:-<70}", "");
        println!("{:<22} {:<25} Description", "Function", "Returns");
        println!("{:-<70}", "");

        for f in &funcs {
            println!(
                "{:<22} {:<25} {}",
                f.signature, f.return_type, f.description
            );
        }
        println!();
    }

    println!("Examples:");
    println!("{:-<70}", "");
    println!();
    println!("  -- Convert IP addresses for display");
    println!("  SELECT ip4_to_string(src_ip), ip4_to_string(dst_ip) FROM ipv4;");
    println!();
    println!("  -- Filter by CIDR range");
    println!("  SELECT * FROM ipv4 WHERE ip_in_cidr(src_ip, '192.168.0.0/16');");
    println!();
    println!("  -- TCP flag analysis");
    println!("  SELECT * FROM tcp WHERE has_tcp_flag(tcp_flags, 'SYN');");
    println!();
    println!("  -- Protocol distribution");
    println!("  SELECT ip_proto_name(protocol), COUNT(*) FROM ipv4 GROUP BY protocol;");
    println!();
    println!("  -- Latency histogram");
    println!("  SELECT hdr_percentile(hdr_histogram(length), 0.99) as p99 FROM frames;");
    println!();
    println!("Table functions (not listed above): tumble(source, size),");
    println!("hop(source, slide, size) and session(source, key_column, gap) add");
    println!("window_start / window_end for time-windowed GROUP BY, e.g.");
    println!(
        "  SELECT window_start, COUNT(*) FROM tumble(frames, INTERVAL '10' SECOND) GROUP BY 1;"
    );
    println!("See the README section \"Window Functions\".");
}

pub fn show_schema() {
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

pub(super) fn print_help() {
    println!("Commands:");
    println!("  .help            Show this help");
    println!("  .tables          List available tables");
    println!("  .schema          Show table schemas");
    println!("  .protocols       List registered protocols");
    println!("  .udfs            List available SQL functions");
    println!("  .export <file> [query]  Export to file (format inferred from extension)");
    println!("  .timeinfo        Show capture time information");
    println!("  .hexdump <frame> Hex dump of packet data");
    println!("  .stats           Show capture statistics");
    println!("  .top <col> [N]   Show top N values for column (default: 10)");
    println!("  .histogram <col> Show value distribution (alias: .hist)");
    println!("  .cachestats      Show cached tables and last query's parse stats (alias: .cs)");
    println!("  .cachestats reset Clear the table cache");
    println!("  .quit            Exit");
    println!();
    println!("Export formats: .parquet, .json/.jsonl, .csv, .sqlite/.db");
    println!("SQL queries end with a semicolon (;)");
}

pub(super) fn print_tables() {
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
