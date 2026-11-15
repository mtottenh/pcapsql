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
//! SELECT * FROM read_tcp('capture.pcap') WHERE dst_port = 443;
//! SELECT * FROM read_pcap('capture.pcapng.gz', protocol := 'dns');
//! SELECT filename, count(*) FROM read_dns(['a.pcap', 'b/*.pcapng'], filename := true) GROUP BY ALL;
//! SELECT count(*) FROM 'capture.pcap' WHERE frame_number <= 1000;
//! SELECT timestamp, ip4_to_string(src_ip_v4), dst_port FROM read_tcp_packets('capture.pcap');
//! SELECT * FROM pcap_protocols();          -- name, description, field_count, kind
//! SELECT * FROM pcap_views();              -- name, description, protocol, column_count
//! SELECT * FROM pcap_schema('tcp');        -- column_name, column_type, nullable
//! SELECT ip4('192.168.1.1');               -- 3232235777
//! SELECT ip4_to_string(3232235777);        -- 192.168.1.1
//! SELECT ip_in_cidr(ip4('10.1.2.3'), '10.0.0.0/8'), tcp_flags_str(18), ip_proto_name(6);
//! SELECT format_mac(mac('aabbccddeeff'));  -- aa:bb:cc:dd:ee:ff
//! ```
//!
//! That is the scan functions (`read_pcap`, one `read_<table>` per table and one
//! `read_<proto>_packets` per packets view), `pcap_protocols()`, `pcap_views()` and
//! `pcap_schema()`, the sixteen scalar functions and the six `format_*` macros; the README
//! lists them. None of them has logic of its own. The scan functions run the shared scan layer,
//! `pcapsql_core::scan`, which the DataFusion engine runs too: the tables and columns are those
//! of `pcapsql_core::scan::Catalog`, the views those of `pcapsql_core::scan::PacketsView` (each
//! a join the scan layer evaluates frame by frame, in the same pass), and its driver decides
//! what every row holds. The scalar functions are loops over the kernels of
//! `pcapsql_core::format`.
//!
//! What is here is the DuckDB side: `engine::table` is the table function behind every scan
//! function, [`engine::writer::ChunkWriter`] stores the rows of the scan layer in a DuckDB
//! chunk, [`engine::fs::DuckFile`] reads a capture through DuckDB's file system,
//! [`engine::types`] maps the catalogue's column kinds to DuckDB types, `engine::pushdown`
//! turns the filters DuckDB offers a scan into the scan layer's frame predicate, and
//! `engine::replacement` answers a capture path named where a table is expected.
//!
//! See `docs/duckdb-v2-extension-roadmap.md` for the plan this follows.

// Unsafe code is confined to two audited places, each of which says why it is sound:
// `engine::writer`, which stores values through the raw pointers of DuckDB's vectors, and one
// function of `engine::scalar`, `values_without_nulls`, which borrows the values of a flat
// vector without NULLs as a slice. `make check_unsafe` (scripts/check-unsafe.sh) fails for a
// third. The entrypoint that `ext/` and `itest/` expand from `duckdb-neo`'s macro is outside
// this crate.
#![deny(unsafe_code)]

pub mod engine;

pub use engine::register;
