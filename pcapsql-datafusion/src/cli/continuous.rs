//! `--continuous`: a query over a live stream, printed window by window.

use std::io;

use anyhow::Result;

use super::format::format_timestamp_us;
use super::stats::print_parse_stats_ext;
use super::{Args, OutputFormatter};
use crate::query::QueryEngine;

/// Run a continuous query: print every emitted window as it arrives, until
/// the input ends, an error, or Ctrl-C.
///
/// Then the query is finished: the source releases the producer if it is
/// waiting for input on a quiet pipe (uncompressed stdin is read from its
/// descriptor, so this is immediate) and its statistics are collected. The
/// wait is bounded anyway, so a source that cannot be released (a compressed
/// stream, whose decompressor hides the descriptor) still lets the process
/// leave with its output flushed.
pub async fn run_continuous(
    engine: &QueryEngine,
    query: &str,
    formatter: &OutputFormatter,
    args: &Args,
    progress_bar: Option<indicatif::ProgressBar>,
) -> Result<()> {
    use futures::StreamExt;

    let mut stream = engine.execute_stream(query).await?;
    if let Some(pb) = &progress_bar {
        pb.set_style(
            indicatif::ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] {msg}")
                .expect("valid template")
                .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ "),
        );
        pb.set_message("waiting for the first window");
        pb.enable_steady_tick(std::time::Duration::from_millis(200));
    }
    let mut stdout = io::stdout();
    let mut header_written = false;
    let mut rows: u64 = 0;
    let mut interrupted = false;
    let mut failure: Option<crate::error::Error> = None;
    // One signal future for the whole loop: a SIGINT that lands while a
    // batch is being written is remembered, not lost.
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    loop {
        tokio::select! {
            next = stream.next() => match next {
                Some(Ok(batch)) => {
                    rows += batch.num_rows() as u64;
                    if let Some(pb) = &progress_bar {
                        pb.suspend(|| formatter.write_incremental(&batch, &mut stdout, &mut header_written))?;
                        let watermark = stream
                            .watermark_us()
                            .map(format_timestamp_us)
                            .unwrap_or_else(|| "-".to_string());
                        let forced = match stream.windows_forced() {
                            0 => String::new(),
                            n => format!(", {n} forced by the memory limit"),
                        };
                        pb.set_message(format!(
                            "{rows} rows in {} windows{forced}, watermark {watermark}, {} late rows",
                            stream.windows_emitted(),
                            stream.late_rows()
                        ));
                    } else {
                        formatter.write_incremental(&batch, &mut stdout, &mut header_written)?;
                    }
                    io::Write::flush(&mut stdout)?;
                }
                Some(Err(e)) => {
                    failure = Some(e);
                    break;
                }
                None => break,
            },
            _ = &mut ctrl_c => {
                interrupted = true;
                break;
            }
        }
    }
    if let Some(pb) = &progress_bar {
        pb.finish_and_clear();
    }
    io::Write::flush(&mut stdout)?;
    // Only a source that cannot be released waits this long (see above).
    let grace = std::time::Duration::from_secs(5);
    match tokio::time::timeout(grace, stream.finish()).await {
        Ok(Ok(stats)) => {
            if args.show_stats {
                print_parse_stats_ext(&stats, interrupted);
            }
        }
        Ok(Err(e)) => {
            if failure.is_none() && !interrupted {
                failure = Some(e);
            } else {
                eprintln!("{e}");
            }
        }
        Err(_) => {
            if args.show_stats {
                eprintln!(
                    "Parse statistics unavailable: the input is still open and the reader \
                     could not be released ({rows} rows printed)"
                );
            }
            // The runtime's shutdown would wait for the blocked reader.
            let _ = io::Write::flush(&mut io::stderr());
            std::process::exit(if interrupted {
                130
            } else {
                i32::from(failure.is_some())
            });
        }
    }
    if let Some(e) = failure {
        return Err(e.into());
    }
    if interrupted {
        // 130: the conventional status after SIGINT.
        std::process::exit(130);
    }
    Ok(())
}
