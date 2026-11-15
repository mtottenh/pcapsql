//! The engine-neutral scan layer.
//!
//! **Unstable API.** This module is the part of the scan path that the SQL
//! frontends (`pcapsql-datafusion`, the DuckDB extension) share. It is being
//! built up step by step and its types may change in any release, without a
//! deprecation period. Nothing here depends on Arrow or on a SQL engine.
//!
//! So far it holds the [`catalog`]: which tables exist and which columns
//! they have.

pub mod catalog;
mod tables;

pub use catalog::{
    Catalog, ColId, ColKind, ColumnDef, ColumnSource, StreamTable, TableDef, TableId, TableKind,
    TimestampUnit, UnsupportedKind,
};
