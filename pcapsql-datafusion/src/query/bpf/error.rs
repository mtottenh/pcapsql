//! Error types for BPF filter parsing.

use thiserror::Error;

/// Errors that can occur during BPF filter parsing.
#[derive(Debug, Error)]
pub enum BpfError {
    /// Parse error with context
    #[error("Parse error: {message}")]
    ParseError { message: String },

    /// Invalid IP address
    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(String),

    /// Invalid CIDR notation
    #[error("Invalid CIDR notation: {0}")]
    InvalidCidr(String),

    /// Invalid port number
    #[error("Invalid port number: {0}")]
    InvalidPort(String),

    /// Unknown protocol
    #[error("Unknown protocol: {0}")]
    UnknownProtocol(String),

    /// Unexpected end of input
    #[error("Unexpected end of input")]
    UnexpectedEof,

    /// Empty filter
    #[error("Empty filter expression")]
    EmptyFilter,
}

impl BpfError {
    /// Create a parse error with a message.
    pub fn parse_error(message: impl Into<String>) -> Self {
        BpfError::ParseError {
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = BpfError::InvalidPort("99999".to_string());
        assert_eq!(err.to_string(), "Invalid port number: 99999");

        let err = BpfError::InvalidIpAddress("not.an.ip".to_string());
        assert_eq!(err.to_string(), "Invalid IP address: not.an.ip");

        let err = BpfError::parse_error("unexpected token");
        assert_eq!(err.to_string(), "Parse error: unexpected token");
    }
}
