//! Convenient re-exports for common usage.
//!
//! This module provides a curated set of the most commonly used types
//! from pcapsql-core, allowing you to import them with a single `use` statement.
//!
//! # Example
//!
//! ```rust,no_run
//! use pcapsql_core::prelude::*;
//!
//! // Create a protocol registry with all built-in parsers
//! let registry = default_registry();
//!
//! // Protocol registry and parsing are now available
//! ```

// Schema types
pub use crate::schema::{DataKind, FieldDescriptor, ProtocolSchema};

// Protocol types
pub use crate::protocol::{
    default_registry, parse_packet, BuiltinProtocol, FieldValue, ParseContext, ParseResult,
    PayloadMode, Protocol, ProtocolRegistry,
};

// I/O types
pub use crate::io::{FilePacketReader, FilePacketSource, PacketReader, PacketSource, RawPacket};

// Cache types
pub use crate::cache::{LruParseCache, NoCache, ParseCache};

// Error types
pub use crate::error::{Error, Result};
