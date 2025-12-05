//! Error types for pcapsql.

use thiserror::Error;

/// Main error type for pcapsql operations.
#[derive(Error, Debug)]
pub enum Error {
    /// Error reading or parsing PCAP file
    #[error("PCAP error: {0}")]
    Pcap(#[from] PcapError),

    /// Error during protocol parsing
    #[error("Protocol parse error: {0}")]
    Protocol(#[from] ProtocolError),

    /// Error during SQL query execution
    #[error("Query error: {0}")]
    Query(#[from] QueryError),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors related to PCAP file reading.
#[derive(Error, Debug)]
pub enum PcapError {
    /// File not found
    #[error("File not found: {path}")]
    FileNotFound { path: String },

    /// Invalid PCAP format
    #[error("Invalid PCAP format: {reason}")]
    InvalidFormat { reason: String },

    /// Unsupported link type
    #[error("Unsupported link type: {link_type}")]
    UnsupportedLinkType { link_type: u16 },

    /// Truncated packet
    #[error("Truncated packet at frame {frame}: expected {expected} bytes, got {actual}")]
    TruncatedPacket {
        frame: u64,
        expected: usize,
        actual: usize,
    },
}

/// Errors related to protocol parsing.
#[derive(Error, Debug)]
pub enum ProtocolError {
    /// Packet too short for protocol header
    #[error("{protocol}: packet too short (need {needed} bytes, have {have})")]
    PacketTooShort {
        protocol: &'static str,
        needed: usize,
        have: usize,
    },

    /// Invalid header field value
    #[error("{protocol}: invalid {field}: {reason}")]
    InvalidField {
        protocol: &'static str,
        field: &'static str,
        reason: String,
    },

    /// Checksum mismatch
    #[error("{protocol}: checksum mismatch (expected {expected:#x}, got {actual:#x})")]
    ChecksumMismatch {
        protocol: &'static str,
        expected: u16,
        actual: u16,
    },
}

/// Errors related to SQL query execution.
#[derive(Error, Debug)]
pub enum QueryError {
    /// SQL syntax error
    #[error("SQL syntax error: {0}")]
    Syntax(String),

    /// Unknown table
    #[error("Unknown table: {table}")]
    UnknownTable { table: String },

    /// Unknown column
    #[error("Unknown column: {column} in table {table}")]
    UnknownColumn { table: String, column: String },

    /// DataFusion error
    #[error("Query execution error: {0}")]
    Execution(String),

    /// Arrow error
    #[error("Arrow error: {0}")]
    Arrow(String),
}

impl From<datafusion::error::DataFusionError> for QueryError {
    fn from(err: datafusion::error::DataFusionError) -> Self {
        QueryError::Execution(err.to_string())
    }
}

impl From<arrow::error::ArrowError> for QueryError {
    fn from(err: arrow::error::ArrowError) -> Self {
        QueryError::Arrow(err.to_string())
    }
}

/// Result type alias using our Error type.
pub type Result<T> = std::result::Result<T, Error>;
