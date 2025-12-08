//! pcapsql-duckdb: DuckDB extension for PCAP analysis.
//!
//! This extension provides virtual tables for querying PCAP files using SQL.
//!
//! ## Usage
//!
//! ```sql
//! -- Load the extension
//! LOAD 'pcapsql.duckdb_extension';
//!
//! -- Query a PCAP file (to be implemented in Task 12)
//! SELECT * FROM read_pcap('capture.pcap', 'tcp') LIMIT 10;
//! ```

mod duckdb_schema;
mod error;

pub use duckdb_schema::{protocol_columns, to_duckdb_column, to_duckdb_type};
pub use error::DuckDbError;
pub use pcapsql_core;

// Required imports for the duckdb_entrypoint_c_api macro
use duckdb::ffi;
use duckdb::Connection;
use duckdb_loadable_macros::duckdb_entrypoint_c_api;

/// Extension name.
pub const EXTENSION_NAME: &str = "pcapsql";

/// Extension version.
pub const EXTENSION_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Extension entry point called by DuckDB when loading.
///
/// Registers all table functions and scalar functions.
#[duckdb_entrypoint_c_api(ext_name = "pcapsql")]
pub unsafe fn pcapsql_init(con: Connection) -> duckdb::Result<(), Box<dyn std::error::Error>> {
    // Log extension loading
    tracing::info!(
        "Loading {} v{} extension",
        EXTENSION_NAME,
        EXTENSION_VERSION
    );

    // Table functions will be registered in Task 12-14
    // UDFs will be registered in Task 15

    // Suppress unused variable warning for now
    let _ = con;

    Ok(())
}

/// Get extension metadata.
pub fn extension_info() -> (&'static str, &'static str) {
    (EXTENSION_NAME, EXTENSION_VERSION)
}

/// Re-export our Result type under a different name to avoid conflicts
pub type PcapsqlResult<T> = std::result::Result<T, DuckDbError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extension_info() {
        let (name, version) = extension_info();
        assert_eq!(name, "pcapsql");
        assert!(!version.is_empty());
    }
}
