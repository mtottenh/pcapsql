//! Row sinks: where a scan's rows are stored.
//!
//! **Unstable API** (see the [module](super) documentation).
//!
//! A [`RowSink`] stores the rows of one output of a scan in an engine's own
//! format (Arrow builders, a DuckDB data chunk). The scan layer decides what
//! every cell holds ([`write_value`](super::write_value) and the row
//! writers of `row.rs`); a sink only stores values that already
//! have the column's kind. Each engine therefore gets the same cells by
//! construction.
//!
//! The methods are typed, one per kind of value, rather than one
//! `put(column, cell)`: the code that writes a row is generic over the sink,
//! so each arm of the coercion calls a concrete store with nothing left for
//! the sink to match on.

use std::ops::ControlFlow;

use super::plan::OutCol;

/// The sink has no room for another row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Full;

/// Stores one output's rows.
///
/// A row is written as one call per column, in column order
/// ([`OutputPlan::columns`](super::OutputPlan::columns)), then
/// [`end_row`](Self::end_row). The call for a column is [`null`](Self::null)
/// or the method of the column's [`ColKind`](super::ColKind):
///
/// | Kind | Method |
/// |---|---|
/// | `Bool` | [`bool`](Self::bool) |
/// | `U8`, `U16`, `U32`, `U64` | [`u8`](Self::u8), [`u16`](Self::u16), [`u32`](Self::u32), [`u64`](Self::u64) |
/// | `I8`, `I64` | [`i8`](Self::i8), [`i64`](Self::i64) |
/// | `F64` | [`f64`](Self::f64) |
/// | `Str` | [`str`](Self::str) |
/// | `Bin` | [`bytes`](Self::bytes) |
/// | `Fixed(n)` | [`fixed`](Self::fixed), with exactly `n` bytes |
/// | `TsMicros`, `TsNanos` | [`timestamp`](Self::timestamp), in the kind's unit |
/// | `ListU16`, `ListU32`, `ListStr`, `ListFixed(n)` | [`list`](Self::list), then the [`ListSink`] |
///
/// The methods cannot fail: anything that can (building a record batch)
/// happens when the engine takes the rows, outside the packet loop. A sink
/// may panic when a call does not fit the column's kind; the writers in
/// `row.rs` never make such a call.
pub trait RowSink {
    /// NULL, for a column of any kind.
    fn null(&mut self, col: OutCol);
    /// A `Bool` value.
    fn bool(&mut self, col: OutCol, v: bool);
    /// A `U8` value.
    fn u8(&mut self, col: OutCol, v: u8);
    /// A `U16` value.
    fn u16(&mut self, col: OutCol, v: u16);
    /// A `U32` value.
    fn u32(&mut self, col: OutCol, v: u32);
    /// A `U64` value.
    fn u64(&mut self, col: OutCol, v: u64);
    /// An `I8` value.
    fn i8(&mut self, col: OutCol, v: i8);
    /// An `I64` value.
    fn i64(&mut self, col: OutCol, v: i64);
    /// An `F64` value.
    fn f64(&mut self, col: OutCol, v: f64);
    /// A `Str` value. It may be empty and may contain NUL.
    fn str(&mut self, col: OutCol, v: &str);
    /// A `Bin` value. It may be empty.
    fn bytes(&mut self, col: OutCol, v: &[u8]);
    /// A `Fixed(n)` value; `v.len() == n` has been checked. A sink that
    /// stores fixed-size and variable-size bytes alike need not implement
    /// it.
    #[inline]
    fn fixed(&mut self, col: OutCol, v: &[u8]) {
        self.bytes(col, v);
    }
    /// A timestamp, in the unit of the column's kind (`TsMicros` or
    /// `TsNanos`).
    fn timestamp(&mut self, col: OutCol, v: i64);

    /// The writer of one list cell.
    type List<'s>: ListSink
    where
        Self: 's;

    /// Start a list cell (not NULL; a NULL cell is [`null`](Self::null)).
    /// The items go to the returned writer and [`ListSink::finish`] closes
    /// the cell; a writer dropped without `finish` leaves the row
    /// incomplete.
    fn list(&mut self, col: OutCol) -> Self::List<'_>;

    /// Close the row. `Break(Full)`: the row was stored and no further row
    /// fits; the rows must be taken out of the sink before the next one is
    /// written. A sink reports `Full` exactly when it reaches its capacity,
    /// never before.
    fn end_row(&mut self) -> ControlFlow<Full>;
}

/// Stores the items of one list cell, in order. The item methods follow the
/// list's kind: `ListU16` [`u16`](Self::u16), `ListU32` [`u32`](Self::u32),
/// `ListStr` [`str`](Self::str), `ListFixed(n)` [`bytes`](Self::bytes); any
/// of them can hold NULL items.
pub trait ListSink {
    /// A NULL item.
    fn null(&mut self);
    /// An item of a `ListU16`.
    fn u16(&mut self, v: u16);
    /// An item of a `ListU32`.
    fn u32(&mut self, v: u32);
    /// An item of a `ListStr`.
    fn str(&mut self, v: &str);
    /// An item of a `ListFixed(n)`; `v.len() == n` has been checked.
    fn bytes(&mut self, v: &[u8]);
    /// Close the cell.
    fn finish(self);
}
