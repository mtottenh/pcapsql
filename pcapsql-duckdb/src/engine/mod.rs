//! DuckDB engine glue: the only module tree that names `duckdb_neo`.
//!
//! The DuckDB C API v2 is unstable and `duckdb-neo` follows it release by release, so everything
//! that touches either is kept below this module. `scripts/check-neo-containment.sh` enforces
//! that in CI.

pub mod fs;
pub mod guard;
mod macros;
mod registry;
mod scalar;
pub mod types;
pub mod writer;

use duckdb_neo::{extension::Extension, Result};

/// Register every pcapsql function with the extension that is being loaded.
pub fn register(extension: &Extension) -> Result<()> {
    registry::register(extension)?;
    scalar::register(extension)?;
    // After the scalars: the macro bodies call them.
    macros::register(extension)
}
