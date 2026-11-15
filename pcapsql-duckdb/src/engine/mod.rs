//! DuckDB engine glue: the only module tree that names `duckdb_neo`.
//!
//! The DuckDB C API v2 is unstable and `duckdb-neo` follows it release by release, so everything
//! that touches either is kept below this module. `scripts/check-neo-containment.sh` enforces
//! that in CI.

pub mod guard;
mod registry;
mod scalar;

use duckdb_neo::{Result, extension::Extension};

/// Register every pcapsql function with the extension that is being loaded.
pub fn register(extension: &Extension) -> Result<()> {
    registry::register(extension)?;
    scalar::register(extension)
}
