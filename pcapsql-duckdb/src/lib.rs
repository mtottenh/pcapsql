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
//! -- List available protocols
//! SELECT * FROM pcap_protocols();
//!
//! -- Show schema for a protocol
//! SELECT * FROM pcap_schema('tcp');
//!
//! -- Use protocol-specific functions (recommended)
//! SELECT * FROM read_tcp('capture.pcap') LIMIT 10;
//! SELECT * FROM read_dns('capture.pcap');
//!
//! -- Or use the generic read_pcap function
//! SELECT * FROM read_pcap('capture.pcap', 'tcp') LIMIT 10;
//!
//! -- Read all frames (raw packet metadata)
//! SELECT * FROM read_pcap('capture.pcap', 'frames');
//!
//! -- Join protocols
//! SELECT t.src_port, t.dst_port, d.query_name
//! FROM read_tcp('capture.pcap') t
//! JOIN read_dns('capture.pcap') d USING (frame_number);
//! ```

mod duckdb_schema;
mod error;
mod udf;
mod vtab;

pub use duckdb_schema::{protocol_columns, to_duckdb_column, to_duckdb_type};
pub use error::DuckDbError;
pub use pcapsql_core;
pub use vtab::{
    register_all, register_protocol_tables, register_read_pcap, register_registry,
    PcapProtocolsVTab, PcapSchemaVTab, ReadPcapVTab,
};

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

    // Register all table functions
    vtab::register_all(&con)?;

    // Register all scalar functions (UDFs)
    udf::register_all(&con)?;

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
