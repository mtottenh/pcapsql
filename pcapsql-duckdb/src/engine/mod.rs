//! DuckDB engine glue: the only module tree that names `duckdb_neo`.
//!
//! The DuckDB C API v2 is unstable and `duckdb-neo` follows it release by release, so everything
//! that touches either is kept below this module. `scripts/check-neo-containment.sh` enforces
//! that in CI.

// Public: what the in-process tests (`itest/`) drive on their own, beside the functions
// `register` registers.
pub mod fs;
pub mod guard;
pub mod types;
pub mod writer;

mod copy;
mod listing;
mod macros;
mod pushdown;
mod relation;
mod replacement;
mod scalar;
mod settings;
mod table;

use duckdb_neo::{extension::Extension, Result};

/// Register every pcapsql function with the extension that is being loaded.
pub fn register(extension: &Extension) -> Result<()> {
    listing::register(extension)?;
    // Before the scan functions, which read them.
    settings::register(extension)?;
    table::register(extension)?;
    // After `read_pcap`, which it answers with.
    replacement::register(extension)?;
    scalar::register(extension)?;
    // After the scalars and `pcap_time_range`: the macro bodies call them.
    macros::register(extension)?;
    copy::register(extension)
}
