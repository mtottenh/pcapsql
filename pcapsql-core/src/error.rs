//! Error types for pcapsql-core.
//!
//! This module provides structured error types for all pcapsql-core operations:
//!
//! - [`enum@Error`] - Main error enum that wraps all error types
//! - [`PcapError`] - Errors from PCAP file reading
//! - [`ProtocolError`] - Errors from protocol parsing
//!
//! All errors implement `std::error::Error` and can be converted to `anyhow::Error`.

use thiserror::Error;

/// Main error type for pcapsql-core operations.
#[derive(Error, Debug)]
pub enum Error {
    /// Error reading or parsing PCAP file
    #[error("PCAP error: {0}")]
    Pcap(#[from] PcapError),

    /// Error during protocol parsing
    #[error("Protocol parse error: {0}")]
    Protocol(#[from] ProtocolError),

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

/// Result type alias using our Error type.
pub type Result<T> = std::result::Result<T, Error>;
