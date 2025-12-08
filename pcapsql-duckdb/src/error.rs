//! DuckDB-specific error types.

use thiserror::Error;

/// Errors that can occur in the DuckDB extension.
#[derive(Error, Debug)]
pub enum DuckDbError {
    #[error("Schema conversion error: {0}")]
    Schema(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("PCAP error: {0}")]
    Pcap(#[from] pcapsql_core::PcapError),

    #[error("Protocol error: {0}")]
    Protocol(#[from] pcapsql_core::ProtocolError),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Extension error: {0}")]
    Extension(String),
}
