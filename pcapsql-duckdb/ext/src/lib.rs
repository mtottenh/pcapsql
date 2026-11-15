//! The loadable `pcapsql` extension: the DuckDB C API v2 entrypoint and nothing else.
//!
//! Everything the extension registers is in `pcapsql_duckdb`, so that the in-process tests in
//! `itest/` exercise the same code through a statically registered entrypoint.

use duckdb_neo::{duckdb_entrypoint_c_api_v2, extension::Extension};

// `api_version` names the DuckDB release the `duckdb-neo` pin targets. The loader checks the
// exact release against the metadata footer (C_STRUCT_UNSTABLE), which the Makefile stamps.
#[duckdb_entrypoint_c_api_v2(extension_name = "pcapsql", api_version = "v2.0.0")]
fn entrypoint(extension: &Extension) -> duckdb_neo::Result<()> {
    pcapsql_duckdb::register(extension)
}
