//! Error types for pcapsql-datafusion.
//!
//! This module provides error types specific to the DataFusion integration,
//! while re-exporting core error types from pcapsql-core.

use thiserror::Error;

// Re-export core error types
pub use pcapsql_core::error::{PcapError, ProtocolError};
pub use pcapsql_core::Error as CoreError;

/// Main error type for pcapsql-datafusion operations.
#[derive(Error, Debug)]
pub enum Error {
    /// Error from pcapsql-core (PCAP reading, protocol parsing)
    #[error(transparent)]
    Core(#[from] CoreError),

    /// Error during SQL query execution
    #[error("Query error: {0}")]
    Query(#[from] QueryError),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
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

impl From<datafusion::error::DataFusionError> for Error {
    fn from(err: datafusion::error::DataFusionError) -> Self {
        Error::Query(QueryError::from(err))
    }
}

impl From<arrow::error::ArrowError> for Error {
    fn from(err: arrow::error::ArrowError) -> Self {
        Error::Query(QueryError::from(err))
    }
}

// Allow conversion from our Error to pcapsql_core Error for ? operator
impl From<Error> for pcapsql_core::Error {
    fn from(err: Error) -> Self {
        match err {
            Error::Core(e) => e,
            Error::Query(e) => pcapsql_core::Error::Io(std::io::Error::other(e.to_string())),
            Error::Io(e) => pcapsql_core::Error::Io(e),
        }
    }
}

/// Result type alias using our Error type.
pub type Result<T> = std::result::Result<T, Error>;
