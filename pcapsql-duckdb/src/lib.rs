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
//! SELECT ip_in_cidr(ip4('10.1.2.3'), '10.0.0.0/8'), tcp_flags_str(18), ip_proto_name(6);
//! SELECT format_mac(mac('aabbccddeeff'));  -- aa:bb:cc:dd:ee:ff
//! ```
//!
//! That is `pcap_protocols()`, the sixteen scalar functions and the six `format_*` macros; the
//! README lists them. The scalar functions have no logic here: they are loops over the kernels
//! of `pcapsql_core::format`.
//!
//! See `docs/duckdb-v2-extension-roadmap.md` for the plan this follows.

// The only unsafe code the extension needs is in the entrypoint that `ext/` and `itest/` expand
// from `duckdb-neo`'s macro.
#![deny(unsafe_code)]

pub mod engine;

pub use engine::register;
