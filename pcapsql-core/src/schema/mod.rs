//! Engine-agnostic schema types.
//!
//! This module provides types that describe protocol field schemas
//! without depending on any specific SQL engine (Arrow, DuckDB, etc.).
//!
//! # Example
//!
//! ```rust
//! use pcapsql_core::schema::{DataKind, FieldDescriptor};
//!
//! // Define a protocol's schema
//! let fields = vec![
//!     FieldDescriptor::frame_number(),
//!     FieldDescriptor::new("version", DataKind::UInt8),
//!     FieldDescriptor::nullable("payload", DataKind::Binary),
//! ];
//! ```

mod field;
mod kind;

pub use field::FieldDescriptor;
pub use kind::DataKind;

/// A protocol's complete schema.
pub type ProtocolSchema = Vec<FieldDescriptor>;
