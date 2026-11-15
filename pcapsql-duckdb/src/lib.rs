//! pcapsql for DuckDB: the functions the `pcapsql` extension registers, on the DuckDB C API v2.
//!
//! This crate is the engine glue. It is linked into two artifacts:
//!
//! - `ext/`, the loadable extension (`pcapsql.duckdb_extension`), which contains only the
//!   entrypoint and calls [`register`];
//! - `itest/`, a test crate that links DuckDB and registers the same entrypoint statically, so
//!   that the functions are covered by ordinary `cargo test`.
//!
//! What is registered today:
//!
//! ```sql
//! SELECT * FROM pcap_protocols();          -- name, description, field_count
//! SELECT ip4('192.168.1.1');               -- 3232235777
//! SELECT ip4_to_string(3232235777);        -- 192.168.1.1
//! ```
//!
//! See `docs/duckdb-v2-extension-roadmap.md` for the plan this follows.

// The only unsafe code the extension needs is in the entrypoint that `ext/` and `itest/` expand
// from `duckdb-neo`'s macro.
#![deny(unsafe_code)]

pub mod engine;
pub mod kernels;

pub use engine::register;
