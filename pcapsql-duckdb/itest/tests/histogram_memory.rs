//! `hdr_histogram` frees the states of its groups.
//!
//! The test measures the memory of the process, so it is alone in its file: `cargo test` runs a
//! file's tests in one process, at the same time. That every state DuckDB made is destroyed,
//! on any number of threads, is counted exactly for a guarded aggregate function in
//! `guard_aggregate.rs`; this is the same for the histograms themselves, by what the process
//! holds.

#![cfg(target_os = "linux")]

use duckdb_neo::{Parameters, Result};
use pcapsql_duckdb_itest::{connect, rows};

/// The resident memory of this process, in bytes.
fn resident_bytes() -> u64 {
    let statm = std::fs::read_to_string("/proc/self/statm").unwrap();
    let pages: u64 = statm.split_whitespace().nth(1).unwrap().parse().unwrap();
    pages * 4096
}

/// Running an aggregation with many groups again and again does not grow the process.
#[test]
fn the_states_of_many_groups_are_freed() -> Result<()> {
    let connection = connect()?;
    // One thread, so that what one run frees is what the next run is given: with several, the
    // allocator keeps freed memory per thread, and the process grows without a leak.
    connection.execute("SET threads = 1", Parameters::None)?;
    // 60,000 groups. A histogram is 2 KiB of counts from its first value on (and more once it
    // holds a value above 255), so the states of one run are some 120 MiB.
    let sql = "SELECT count(*), sum(hdr_count(h)), max(hdr_max(h))
               FROM (SELECT i % 60000 AS g, hdr_histogram(i % 200) AS h
                     FROM range(240000) t(i) GROUP BY g)";
    let run = || rows(&connection, sql);
    let expected: Vec<String> = ["60000", "240000", "199"].map(String::from).to_vec();
    assert_eq!(run()?, [expected]);
    // The allocator keeps what the first runs needed; later runs reuse it if it was freed.
    run()?;
    let before = resident_bytes();
    for _ in 0..8 {
        assert_eq!(run()?.len(), 1);
    }
    let grown = resident_bytes().saturating_sub(before);
    // Eight runs that leaked their states would add eight times 120 MiB.
    assert!(
        grown < 64 << 20,
        "the process grew by {} MiB over eight runs",
        grown >> 20
    );
    Ok(())
}
