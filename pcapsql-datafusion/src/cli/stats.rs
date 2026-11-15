//! The parse and cache statistics the CLI prints (`--stats`, `.cachestats`).

use super::format::format_bytes_binary;
use crate::query::QueryEngine;
use crate::{ParseStats, ServedFrom};

/// `.cachestats`: what the engine's table cache holds, then the parse
/// statistics of the last query (`--stats` format).
pub(super) fn print_cache_stats(engine: &QueryEngine) {
    use crate::query::RetentionPolicy;
    match engine.retention() {
        RetentionPolicy::None => {
            println!("Retention: none (one-shot mode; nothing is cached between queries)");
        }
        RetentionPolicy::CacheOnTouch => {
            let cached = engine.cached_tables();
            if cached.is_empty() {
                println!("Table cache: empty (tables are cached on first touch)");
            } else {
                println!("Table cache ({} table(s), column-aware):", cached.len());
                for t in &cached {
                    println!(
                        "  {:<16} {:>10} rows  {:>3} columns",
                        t.name, t.rows, t.columns
                    );
                }
            }
        }
    }
    print_parse_stats(&engine.last_parse_stats());
}

pub fn print_parse_stats(stats: &ParseStats) {
    print_parse_stats_ext(stats, false);
}

/// `interrupted`: the scan was cut short by Ctrl-C, not by a LIMIT.
pub(super) fn print_parse_stats_ext(stats: &ParseStats, interrupted: bool) {
    eprintln!();
    match stats.served_from {
        ServedFrom::PlanOnly => {
            eprintln!(
                "Parse passes: {} (plan only: no scan was executed{})",
                stats.parse_passes,
                if stats.parse_passes > 0 {
                    format!(
                        "; the capture time range was established by a header-only pass over {} packets",
                        stats.packets_scanned
                    )
                } else {
                    String::new()
                }
            );
            return;
        }
        ServedFrom::Cache => {
            eprintln!("Parse passes: 0 (served from cache)");
            return;
        }
        ServedFrom::Index => {
            eprintln!("Parse passes: 0 (answered from the boundary index)");
            return;
        }
        ServedFrom::Parse => {}
    }
    eprintln!(
        "Parse passes: {}  (partitions: {}, packets scanned: {}{})",
        stats.parse_passes,
        stats.partitions,
        stats.packets_scanned,
        if stats.complete_scan {
            ""
        } else if interrupted {
            ", stopped by Ctrl-C"
        } else {
            ", stopped early by LIMIT"
        }
    );
    if !stats.stream_tables.is_empty() {
        eprintln!(
            "Stream analysis (single partition, same pass): {}",
            stats.stream_tables.join(", ")
        );
    }
    if stats.late_rows > 0 {
        eprintln!(
            "Late rows dropped (window already emitted): {}",
            stats.late_rows
        );
    }
    if stats.windows_forced > 0 {
        eprintln!(
            "Windows emitted early by the memory limit: {}",
            stats.windows_forced
        );
    }
    let mut rows: Vec<_> = stats.rows_built.iter().filter(|(_, n)| **n > 0).collect();
    rows.sort();
    for (table, n) in rows {
        match stats.overflow_peak_bytes.get(table.as_str()) {
            Some(b) if *b > 0 => eprintln!(
                "  {table}: {n} rows (buffered up to {} past the stream bound, summed over partitions)",
                format_bytes_binary(*b)
            ),
            _ => eprintln!("  {table}: {n} rows"),
        }
    }
}
