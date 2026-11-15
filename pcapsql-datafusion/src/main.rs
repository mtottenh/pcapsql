//! pcapsql CLI entry point.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;

use datafusion::sql::parser::DFParser;
use pcapsql_core::{KeyLog, PacketSource, StdinPacketSource};
use pcapsql_datafusion::cli::{
    list_protocols, list_udfs, print_parse_stats, run_continuous, run_repl, show_schema, Args,
    ExportFormat, Exporter, InputSource, OutputFormatter, ReplOptions,
};
use pcapsql_datafusion::query::{bpf, EngineOptions, ProgressFn, QueryEngine, SourceSpec};
use pcapsql_datafusion::QueryOutput;

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

    if args.list_udfs {
        list_udfs();
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

    // Input: `--stdin` or `-` read the capture from standard input;
    // otherwise a file path or cloud URL is required.
    let input_source = if args.stdin || args.continuous {
        InputSource::Stdin
    } else {
        let pcap_file_arg = args.file.as_ref().context(
            "PCAP file required (or --stdin to read the capture from standard input). \
             Use --help for usage.",
        )?;
        InputSource::parse(&pcap_file_arg.to_string_lossy())
    };
    let source_name = input_source.display_name();

    // The SQL of a one-shot invocation: `-e`, else the contents of `-f`.
    let one_shot_sql: Option<String> = match (&args.query, &args.query_file) {
        (Some(query), _) => Some(query.clone()),
        (None, Some(query_file)) => Some(
            std::fs::read_to_string(query_file)
                .with_context(|| format!("Failed to read query file: {}", query_file.display()))?,
        ),
        (None, None) => None,
    };
    let one_shot = one_shot_sql.is_some();

    // Standard input can be read once, so it is a one-shot query of exactly
    // one statement: the REPL would read its SQL from the same stdin, and a
    // second statement would find the capture gone.
    if input_source.is_stdin() {
        let Some(sql) = &one_shot_sql else {
            anyhow::bail!(
                "reading the capture from stdin needs a one-shot query (-e <SQL> or -f <FILE>): \
                 the interactive REPL would read its SQL from the same stdin.\n\
                 Example: tcpdump -U -w - -i eth0 | pcapsql --stdin -e \"SELECT count(*) FROM frames\""
            );
        };
        if let Ok(statements) = DFParser::parse_sql(sql) {
            if statements.len() != 1 {
                anyhow::bail!(
                    "stdin can be read once: the query must be exactly one statement (found {})",
                    statements.len()
                );
            }
        }
    }

    // Optional progress spinner driven by the parse callback. Parsing happens
    // at query time, so the spinner runs during each query: once for a
    // one-shot query (`-e` / `-f`), and per statement in the REPL, where it
    // is reset before the query and cleared before the result is printed.
    // The packet count is the bar's position, which is what `{per_sec}` is
    // computed from.
    let progress_bar = if args.progress {
        let pb = indicatif::ProgressBar::new_spinner();
        pb.set_style(
            indicatif::ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] {pos} packets parsed ({per_sec})",
            )
            .expect("valid template")
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ "),
        );
        Some(pb)
    } else {
        None
    };
    let progress_cb: Option<ProgressFn> = progress_bar.clone().map(|pb| {
        Arc::new(move |count: u64| {
            pb.set_position(count);
        }) as ProgressFn
    });

    let seconds = |s: f64, what: &str| -> Result<std::time::Duration> {
        if !(s.is_finite() && s >= 0.0) {
            anyhow::bail!("{what} must be a non-negative number of seconds, got {s}");
        }
        Ok(std::time::Duration::from_secs_f64(s))
    };
    if args.continuous && (args.output.is_some() || args.export_format.is_some()) {
        anyhow::bail!(
            "--continuous prints each window as it closes; exporting to a file (-o, \
             --export-format) is not supported — redirect stdout (--format csv) instead"
        );
    }
    let allowed_lateness = seconds(args.allowed_lateness, "--allowed-lateness")?;
    let flush_interval = seconds(args.flush_interval, "--flush-interval")?;
    let idle_timeout = args
        .idle_timeout
        .map(|s| seconds(s, "--idle-timeout"))
        .transpose()?;
    let memory_limit = args
        .memory_limit
        .as_deref()
        .map(parse_memory_size)
        .transpose()?;
    let on_memory_limit: pcapsql_datafusion::query::MemoryLimitPolicy = args
        .on_memory_limit
        .parse()
        .map_err(|e: String| anyhow::anyhow!("--on-memory-limit: {e}"))?;

    let spec = match &input_source {
        #[cfg(feature = "cloud")]
        InputSource::CloudUrl(url) => {
            if args.verbose > 0 {
                eprintln!("Opening cloud source: {url}");
            }
            SourceSpec::Url(url.clone())
        }
        InputSource::LocalFile(path) => SourceSpec::Path(path.clone()),
        InputSource::Stdin => {
            // A terminal on stdin means nothing is piped in: say so instead
            // of blocking on a header that never comes.
            if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                anyhow::bail!(
                    "--stdin: standard input is a terminal, not a pipe; nothing would be read.\n\
                     Pipe a capture in, e.g. tcpdump -U -w - -i eth0 | pcapsql --stdin -e \"SELECT count(*) FROM frames\""
                );
            }
            // Reads the capture header now (blocking until the producer has
            // written it); the packets are read by the query.
            let source = StdinPacketSource::stdin()
                .context("Failed to read a capture header from standard input")?;
            if args.verbose > 0 {
                eprintln!(
                    "Reading the capture from stdin: {:?}, compression {}, link type {}",
                    source.format(),
                    source.compression(),
                    source.link_type()
                );
            }
            SourceSpec::Sequential(source)
        }
    };

    // One-shot invocations retain nothing; the REPL caches touched tables.
    let retention = if one_shot {
        pcapsql_datafusion::query::RetentionPolicy::None
    } else {
        pcapsql_datafusion::query::RetentionPolicy::CacheOnTouch
    };

    let opts = EngineOptions {
        batch_size: args.batch_size,
        retention,
        keylog,
        mmap: !args.no_mmap,
        fuse_frame_joins: !args.no_fuse_joins,
        progress: if args.continuous { None } else { progress_cb },
        continuous: args.continuous,
        allowed_lateness,
        flush_interval,
        idle_timeout,
        memory_limit,
        on_memory_limit,
        #[cfg(feature = "cloud")]
        cloud: pcapsql_datafusion::query::CloudSourceOptions {
            endpoint: args.cloud_endpoint.clone(),
            anonymous: args.cloud_anonymous,
            chunk_size: Some(args.cloud_chunk_size),
        },
        ..Default::default()
    };

    let engine = QueryEngine::open(spec, opts)
        .await
        .with_context(|| format!("Failed to open PCAP source: {source_name}"))?;
    // `open` no longer parses; the spinner ticks during `query` below and is
    // cleared once the one-shot query has run.
    let finish_progress = || {
        if let Some(pb) = &progress_bar {
            pb.finish_and_clear();
        }
    };

    let formatter = OutputFormatter::new(args.format);

    // Parse BPF filter if provided
    let bpf_filter = if let Some(ref filter_str) = args.filter {
        Some(
            bpf::parse_bpf_filter(filter_str)
                .with_context(|| format!("Invalid BPF filter: {filter_str}"))?,
        )
    } else {
        None
    };

    // Continuous query over a live stream (--continuous).
    if args.continuous {
        let query = one_shot_sql.expect("--continuous implies --stdin, which needs -e/-f");
        let query = bpf::apply_bpf_filter(&query, &bpf_filter);
        return run_continuous(&engine, &query, &formatter, &args, progress_bar).await;
    }

    // One-shot query (-e / -f)
    if let Some(query) = one_shot_sql {
        let query = bpf::apply_bpf_filter(&query, &bpf_filter);
        let output = engine.execute(&query).await;
        finish_progress();
        let QueryOutput { batches, stats } = output?;

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

        // Show parse/partition stats if requested
        if args.show_stats {
            print_parse_stats(&stats);
        }

        return Ok(());
    }

    // Interactive REPL
    run_repl(
        &engine,
        &formatter,
        &source_name,
        ReplOptions {
            show_stats: args.show_stats,
            progress_bar,
        },
    )
    .await
}

/// `--memory-limit`: a byte count with an optional unit, `512MiB`, `2GB`,
/// `1G`, `1073741824`. Binary and decimal units are both accepted and mean
/// what they say.
fn parse_memory_size(s: &str) -> Result<usize> {
    let s = s.trim();
    let split = s
        .find(|c: char| !c.is_ascii_digit() && c != '.' && c != '_')
        .unwrap_or(s.len());
    let (number, unit) = s.split_at(split);
    let number: f64 = number
        .replace('_', "")
        .parse()
        .map_err(|_| anyhow::anyhow!("--memory-limit: '{s}' is not a size"))?;
    let multiplier: f64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1.0,
        "k" | "kib" => 1024.0,
        "kb" => 1e3,
        "m" | "mib" => 1024.0 * 1024.0,
        "mb" => 1e6,
        "g" | "gib" => 1024.0 * 1024.0 * 1024.0,
        "gb" => 1e9,
        "t" | "tib" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        "tb" => 1e12,
        other => anyhow::bail!("--memory-limit: unknown unit '{other}' in '{s}'"),
    };
    let bytes = number * multiplier;
    if bytes.is_nan() || bytes < 1.0 {
        anyhow::bail!("--memory-limit: '{s}' must be at least one byte");
    }
    Ok(bytes as usize)
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

#[cfg(test)]
mod memory_size_tests {
    use super::parse_memory_size;

    #[test]
    fn units_are_what_they_say() {
        assert_eq!(parse_memory_size("1073741824").unwrap(), 1 << 30);
        assert_eq!(parse_memory_size("512MiB").unwrap(), 512 << 20);
        assert_eq!(parse_memory_size("512M").unwrap(), 512 << 20);
        assert_eq!(parse_memory_size("2GB").unwrap(), 2_000_000_000);
        assert_eq!(parse_memory_size("2 GiB").unwrap(), 2 << 30);
        assert_eq!(parse_memory_size("1.5k").unwrap(), 1536);
        assert_eq!(parse_memory_size("64kb").unwrap(), 64_000);
    }

    #[test]
    fn rejects_nonsense() {
        for bad in ["", "abc", "0", "-1M", "3 parsecs"] {
            assert!(parse_memory_size(bad).is_err(), "{bad}");
        }
    }
}
