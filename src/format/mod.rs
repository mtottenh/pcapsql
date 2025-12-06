//! Value formatting utilities for network addresses.
//!
//! Provides formatting functions for displaying network addresses in human-readable form:
//! - IPv4 addresses (UInt32 -> dotted-decimal string)
//! - IPv6 addresses (16 bytes -> RFC 5952 string)
//! - MAC addresses (6 bytes -> colon-separated hex)
//!
//! These functions are used by the CLI output formatter to automatically format
//! address columns for display while keeping the underlying binary storage for
//! efficient filtering and range queries.

mod address;

pub use address::{detect_address_column, format_ipv4, format_ipv6, format_mac, AddressKind};
