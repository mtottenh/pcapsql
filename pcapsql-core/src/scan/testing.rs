//! Test support for sinks: a sink that records what it is given, and the
//! conformance suite every [`RowSink`] must pass.
//!
//! **Unstable API** (see the [module](super) documentation). This module is
//! compiled into the library so that the crates implementing a sink can run
//! the suite from their own tests; nothing on the scan path uses it.
//!
//! A sink implementation runs the suite by implementing [`SinkHarness`] and
//! calling [`run_conformance`] from a test.

use std::ops::ControlFlow;

use super::catalog::{ColKind, ColumnSource};
use super::plan::{OutCol, OutColumn};
use super::sink::{Full, ListSink, RowSink};

/// One stored cell, in engine-neutral form.
#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    /// NULL.
    Null,
    /// A `Bool` column's value.
    Bool(bool),
    /// A `U8` column's value.
    U8(u8),
    /// A `U16` column's value, or an item of a `ListU16`.
    U16(u16),
    /// A `U32` column's value, or an item of a `ListU32`.
    U32(u32),
    /// A `U64` column's value.
    U64(u64),
    /// An `I8` column's value.
    I8(i8),
    /// An `I64` column's value.
    I64(i64),
    /// An `F64` column's value.
    F64(f64),
    /// A `Str` column's value, or an item of a `ListStr`.
    Str(String),
    /// A `Bin` or `Fixed` column's value, or an item of a `ListFixed`.
    Bytes(Vec<u8>),
    /// A timestamp column's value, in the column's unit.
    Timestamp(i64),
    /// A list column's value.
    List(Vec<Cell>),
}

/// A [`RowSink`] that records every row as [`Cell`]s and checks the calls
/// it receives: every column written exactly once per row, in column order,
/// through the method of the column's kind, with fixed-size values of the
/// right length, and never a row beyond its capacity. Any violation panics.
#[derive(Debug)]
pub struct RecordingSink {
    kinds: Box<[ColKind]>,
    capacity: Option<usize>,
    rows: Vec<Vec<Cell>>,
    row: Vec<Cell>,
}

impl RecordingSink {
    /// A sink for an output with these columns that is full after
    /// `capacity` rows (`None`: never).
    pub fn new(columns: &[OutColumn], capacity: Option<usize>) -> Self {
        let kinds: Vec<ColKind> = columns.iter().map(|c| c.kind).collect();
        Self::of_kinds(&kinds, capacity)
    }

    /// [`new`](Self::new), from the columns' kinds alone.
    pub fn of_kinds(kinds: &[ColKind], capacity: Option<usize>) -> Self {
        assert_ne!(capacity, Some(0), "a sink holds at least one row");
        Self {
            kinds: kinds.into(),
            capacity,
            rows: Vec::new(),
            row: Vec::with_capacity(kinds.len()),
        }
    }

    /// The number of complete rows held.
    pub fn rows(&self) -> usize {
        self.rows.len()
    }

    /// True when no further row fits before the rows are taken.
    pub fn is_full(&self) -> bool {
        self.capacity.is_some_and(|c| self.rows.len() >= c)
    }

    /// Take the complete rows out, leaving the sink empty.
    ///
    /// # Panics
    ///
    /// If a row is partly written.
    pub fn take_rows(&mut self) -> Vec<Vec<Cell>> {
        assert!(self.row.is_empty(), "a row is partly written");
        std::mem::take(&mut self.rows)
    }

    /// Check that the next cell is column `col` and that `accepts` its
    /// kind, then store it.
    fn put(&mut self, col: OutCol, cell: Cell, accepts: impl FnOnce(ColKind) -> bool) {
        assert!(!self.is_full(), "a row is written to a full sink");
        let index = usize::from(col.0);
        assert_eq!(
            index,
            self.row.len(),
            "column {index} is written out of order"
        );
        let kind = *self
            .kinds
            .get(index)
            .unwrap_or_else(|| panic!("the output has no column {index}"));
        assert!(
            accepts(kind),
            "column {index} of kind {kind:?} cannot store {cell:?}"
        );
        self.row.push(cell);
    }
}

impl RowSink for RecordingSink {
    fn null(&mut self, col: OutCol) {
        self.put(col, Cell::Null, |_| true);
    }
    fn bool(&mut self, col: OutCol, v: bool) {
        self.put(col, Cell::Bool(v), |k| k == ColKind::Bool);
    }
    fn u8(&mut self, col: OutCol, v: u8) {
        self.put(col, Cell::U8(v), |k| k == ColKind::U8);
    }
    fn u16(&mut self, col: OutCol, v: u16) {
        self.put(col, Cell::U16(v), |k| k == ColKind::U16);
    }
    fn u32(&mut self, col: OutCol, v: u32) {
        self.put(col, Cell::U32(v), |k| k == ColKind::U32);
    }
    fn u64(&mut self, col: OutCol, v: u64) {
        self.put(col, Cell::U64(v), |k| k == ColKind::U64);
    }
    fn i8(&mut self, col: OutCol, v: i8) {
        self.put(col, Cell::I8(v), |k| k == ColKind::I8);
    }
    fn i64(&mut self, col: OutCol, v: i64) {
        self.put(col, Cell::I64(v), |k| k == ColKind::I64);
    }
    fn f64(&mut self, col: OutCol, v: f64) {
        self.put(col, Cell::F64(v), |k| k == ColKind::F64);
    }
    fn str(&mut self, col: OutCol, v: &str) {
        self.put(col, Cell::Str(v.to_string()), |k| k == ColKind::Str);
    }
    fn bytes(&mut self, col: OutCol, v: &[u8]) {
        self.put(col, Cell::Bytes(v.to_vec()), |k| k == ColKind::Bin);
    }
    fn fixed(&mut self, col: OutCol, v: &[u8]) {
        self.put(
            col,
            Cell::Bytes(v.to_vec()),
            |k| matches!(k, ColKind::Fixed(n) if usize::from(n) == v.len()),
        );
    }
    fn timestamp(&mut self, col: OutCol, v: i64) {
        self.put(col, Cell::Timestamp(v), ColKind::is_timestamp);
    }

    type List<'s> = RecordingList<'s>;

    fn list(&mut self, col: OutCol) -> RecordingList<'_> {
        let kind = self.kinds.get(usize::from(col.0)).copied();
        assert!(
            matches!(
                kind,
                Some(
                    ColKind::ListU16 | ColKind::ListU32 | ColKind::ListStr | ColKind::ListFixed(_)
                )
            ),
            "column {} of kind {kind:?} is not a list",
            col.0
        );
        RecordingList {
            sink: self,
            col,
            kind: kind.expect("checked"),
            items: Vec::new(),
        }
    }

    fn end_row(&mut self) -> ControlFlow<Full> {
        assert!(!self.is_full(), "a row is written to a full sink");
        assert_eq!(
            self.row.len(),
            self.kinds.len(),
            "a row ended with columns missing"
        );
        let row = std::mem::replace(&mut self.row, Vec::with_capacity(self.kinds.len()));
        self.rows.push(row);
        if self.is_full() {
            ControlFlow::Break(Full)
        } else {
            ControlFlow::Continue(())
        }
    }
}

/// The list writer of a [`RecordingSink`].
#[derive(Debug)]
pub struct RecordingList<'s> {
    sink: &'s mut RecordingSink,
    col: OutCol,
    kind: ColKind,
    items: Vec<Cell>,
}

impl RecordingList<'_> {
    fn item(&mut self, cell: Cell, accepted: bool) {
        assert!(
            accepted,
            "a list of kind {:?} cannot store the item {cell:?}",
            self.kind
        );
        self.items.push(cell);
    }
}

impl ListSink for RecordingList<'_> {
    fn null(&mut self) {
        self.items.push(Cell::Null);
    }
    fn u16(&mut self, v: u16) {
        self.item(Cell::U16(v), self.kind == ColKind::ListU16);
    }
    fn u32(&mut self, v: u32) {
        self.item(Cell::U32(v), self.kind == ColKind::ListU32);
    }
    fn str(&mut self, v: &str) {
        self.item(Cell::Str(v.to_string()), self.kind == ColKind::ListStr);
    }
    fn bytes(&mut self, v: &[u8]) {
        let fits = matches!(self.kind, ColKind::ListFixed(n) if usize::from(n) == v.len());
        self.item(Cell::Bytes(v.to_vec()), fits);
    }
    fn finish(self) {
        let cell = Cell::List(self.items);
        self.sink.put(self.col, cell, |_| true);
    }
}

/// What the conformance suite needs from a sink implementation.
pub trait SinkHarness {
    /// The sink under test.
    type Sink: RowSink;

    /// A new, empty sink for an output with these columns that reports
    /// [`Full`] when it holds `capacity` rows.
    fn new_sink(&mut self, columns: &[OutColumn], capacity: usize) -> Self::Sink;

    /// Take everything the sink holds, as engine-neutral cells (one `Vec`
    /// per row, one [`Cell`] per column; a `Fixed` value is
    /// [`Cell::Bytes`]), and leave it empty and ready for more rows.
    fn drain(&mut self, sink: &mut Self::Sink) -> Vec<Vec<Cell>>;
}

/// The [`SinkHarness`] of [`RecordingSink`].
#[derive(Debug, Default)]
pub struct RecordingHarness;

impl SinkHarness for RecordingHarness {
    type Sink = RecordingSink;

    fn new_sink(&mut self, columns: &[OutColumn], capacity: usize) -> RecordingSink {
        RecordingSink::new(columns, Some(capacity))
    }

    fn drain(&mut self, sink: &mut RecordingSink) -> Vec<Vec<Cell>> {
        sink.take_rows()
    }
}

/// The capacities the suite runs every case at.
pub const CONFORMANCE_CAPACITIES: [usize; 4] = [1, 2, 7, 2048];

/// The columns of the suite's table: one of every kind, all nullable but
/// the first.
fn conformance_columns() -> Vec<OutColumn> {
    let kinds = [
        ("id", ColKind::U64),
        ("bool", ColKind::Bool),
        ("u8", ColKind::U8),
        ("u16", ColKind::U16),
        ("u32", ColKind::U32),
        ("u64", ColKind::U64),
        ("i8", ColKind::I8),
        ("i64", ColKind::I64),
        ("f64", ColKind::F64),
        ("str", ColKind::Str),
        ("bin", ColKind::Bin),
        ("fixed6", ColKind::Fixed(6)),
        ("fixed16", ColKind::Fixed(16)),
        ("ts_micros", ColKind::TsMicros),
        ("ts_nanos", ColKind::TsNanos),
        ("list_u16", ColKind::ListU16),
        ("list_u32", ColKind::ListU32),
        ("list_str", ColKind::ListStr),
        ("list_fixed16", ColKind::ListFixed(16)),
    ];
    kinds
        .iter()
        .enumerate()
        .map(|(i, (name, kind))| OutColumn {
            name,
            kind: *kind,
            nullable: i != 0,
            source: ColumnSource::Field(name),
        })
        .collect()
}

/// Row `id` of the suite's table. The rows cycle through five shapes:
/// ordinary values, all NULL, extreme values, empty values (empty string,
/// blob and lists, a string that is only NULs), and lists mixing items with
/// NULLs.
fn conformance_row(id: u64) -> Vec<Cell> {
    let s = |text: &str| Cell::Str(text.to_string());
    let low = id as u8;
    let mut row = vec![Cell::U64(id)];
    match id % 5 {
        0 => row.extend([
            Cell::Bool(id.is_multiple_of(2)),
            Cell::U8(low),
            Cell::U16(id as u16),
            Cell::U32(id as u32),
            Cell::U64(id.wrapping_mul(0x9E37_79B9_7F4A_7C15)),
            Cell::I8(low as i8),
            Cell::I64(-(id as i64)),
            Cell::F64(id as f64 + 0.5),
            Cell::Str(format!("row {id} \u{00e9}\u{4e16}")),
            Cell::Bytes(vec![low, 0, 0xFF]),
            Cell::Bytes(vec![low; 6]),
            Cell::Bytes(vec![low; 16]),
            Cell::Timestamp(1_700_000_000_000_000 + id as i64),
            Cell::Timestamp(1_700_000_000_000_000_000 + id as i64),
            Cell::List(vec![Cell::U16(1), Cell::U16(id as u16)]),
            Cell::List(vec![Cell::U32(id as u32)]),
            Cell::List(vec![s("a.example"), s("b")]),
            Cell::List(vec![Cell::Bytes(vec![low; 16])]),
        ]),
        1 => row.extend(std::iter::repeat_n(Cell::Null, 18)),
        2 => row.extend([
            Cell::Bool(true),
            Cell::U8(u8::MAX),
            Cell::U16(u16::MAX),
            Cell::U32(u32::MAX),
            Cell::U64(u64::MAX),
            Cell::I8(i8::MIN),
            Cell::I64(i64::MIN),
            Cell::F64(f64::MIN_POSITIVE),
            // Interior NUL: part of the string, not its end.
            s("nul\0inside\0"),
            Cell::Bytes(vec![0; 300]),
            Cell::Bytes(vec![0xFF; 6]),
            Cell::Bytes(vec![0; 16]),
            Cell::Timestamp(i64::MAX),
            Cell::Timestamp(i64::MIN),
            Cell::List((0..40).map(Cell::U16).collect()),
            Cell::List(vec![Cell::U32(u32::MAX), Cell::U32(0)]),
            Cell::List(vec![s("nul\0inside"), s("x".repeat(200).as_str())]),
            Cell::List(vec![Cell::Bytes(vec![0xFF; 16]), Cell::Bytes(vec![0; 16])]),
        ]),
        3 => row.extend([
            Cell::Bool(false),
            Cell::U8(0),
            Cell::U16(0),
            Cell::U32(0),
            Cell::U64(0),
            Cell::I8(0),
            Cell::I64(0),
            Cell::F64(-0.0),
            s(""),
            Cell::Bytes(vec![]),
            Cell::Bytes(vec![0; 6]),
            Cell::Bytes(vec![0; 16]),
            Cell::Timestamp(0),
            Cell::Timestamp(0),
            Cell::List(vec![]),
            Cell::List(vec![]),
            Cell::List(vec![]),
            Cell::List(vec![]),
        ]),
        _ => row.extend([
            Cell::Null,
            Cell::U8(1),
            Cell::Null,
            Cell::U32(1),
            Cell::Null,
            Cell::I8(1),
            Cell::Null,
            Cell::F64(1.0),
            s("\0"),
            Cell::Null,
            Cell::Bytes(vec![1; 6]),
            Cell::Null,
            Cell::Timestamp(-1),
            Cell::Null,
            Cell::List(vec![Cell::Null, Cell::U16(2), Cell::Null]),
            Cell::List(vec![Cell::Null]),
            Cell::List(vec![s(""), Cell::Null, s("z")]),
            Cell::List(vec![Cell::Null, Cell::Bytes(vec![7; 16]), Cell::Null]),
        ]),
    }
    row
}

/// Write `row` to `sink` through the methods of each column's kind.
fn write_cells<S: RowSink>(sink: &mut S, columns: &[OutColumn], row: &[Cell]) -> ControlFlow<Full> {
    assert_eq!(columns.len(), row.len());
    for (index, (column, cell)) in columns.iter().zip(row).enumerate() {
        let col = OutCol(index as u16);
        match (column.kind, cell) {
            (_, Cell::Null) => sink.null(col),
            (ColKind::Bool, Cell::Bool(v)) => sink.bool(col, *v),
            (ColKind::U8, Cell::U8(v)) => sink.u8(col, *v),
            (ColKind::U16, Cell::U16(v)) => sink.u16(col, *v),
            (ColKind::U32, Cell::U32(v)) => sink.u32(col, *v),
            (ColKind::U64, Cell::U64(v)) => sink.u64(col, *v),
            (ColKind::I8, Cell::I8(v)) => sink.i8(col, *v),
            (ColKind::I64, Cell::I64(v)) => sink.i64(col, *v),
            (ColKind::F64, Cell::F64(v)) => sink.f64(col, *v),
            (ColKind::Str, Cell::Str(v)) => sink.str(col, v),
            (ColKind::Bin, Cell::Bytes(v)) => sink.bytes(col, v),
            (ColKind::Fixed(_), Cell::Bytes(v)) => sink.fixed(col, v),
            (ColKind::TsMicros | ColKind::TsNanos, Cell::Timestamp(v)) => sink.timestamp(col, *v),
            (
                ColKind::ListU16 | ColKind::ListU32 | ColKind::ListStr | ColKind::ListFixed(_),
                Cell::List(items),
            ) => {
                let mut list = sink.list(col);
                for item in items {
                    match item {
                        Cell::Null => list.null(),
                        Cell::U16(v) => list.u16(*v),
                        Cell::U32(v) => list.u32(*v),
                        Cell::Str(v) => list.str(v),
                        Cell::Bytes(v) => list.bytes(v),
                        other => panic!("{other:?} is not a list item"),
                    }
                }
                list.finish();
            }
            (kind, cell) => panic!("a {kind:?} column cannot store {cell:?}"),
        }
    }
    sink.end_row()
}

/// Write `rows` to a sink of `capacity` and check what comes out: `Full`
/// exactly when the sink holds `capacity` rows, every drain holding exactly
/// the rows written since the previous one, in order and unchanged, and the
/// sink usable again after each drain.
fn fill_and_drain<H: SinkHarness>(
    h: &mut H,
    columns: &[OutColumn],
    capacity: usize,
    rows: &[Vec<Cell>],
) {
    let case = format!("{} columns at capacity {capacity}", columns.len());
    let mut sink = h.new_sink(columns, capacity);
    assert_eq!(
        h.drain(&mut sink),
        Vec::<Vec<Cell>>::new(),
        "{case}: a new sink is not empty"
    );
    let mut held = 0;
    let mut drained = 0;
    for (n, row) in rows.iter().enumerate() {
        let flow = write_cells(&mut sink, columns, row);
        held += 1;
        if held < capacity {
            assert!(
                flow.is_continue(),
                "{case}: Full after {held} rows (row {n})"
            );
            continue;
        }
        assert!(
            flow.is_break(),
            "{case}: no Full with {held} rows held (row {n})"
        );
        let got = h.drain(&mut sink);
        assert_eq!(
            got.len(),
            held,
            "{case}: a full sink did not hold its capacity"
        );
        assert_eq!(
            got,
            rows[drained..drained + held],
            "{case}: rows {drained}.."
        );
        drained += held;
        held = 0;
    }
    // The partial rest, then nothing.
    let got = h.drain(&mut sink);
    assert_eq!(got, rows[drained..], "{case}: the final partial drain");
    assert_eq!(
        h.drain(&mut sink),
        Vec::<Vec<Cell>>::new(),
        "{case}: a drained sink is not empty"
    );
    // Still usable after the last drain.
    if let Some(row) = rows.first() {
        let flow = write_cells(&mut sink, columns, row);
        assert_eq!(flow.is_break(), capacity == 1, "{case}: reuse after drain");
        assert_eq!(
            h.drain(&mut sink),
            std::slice::from_ref(row),
            "{case}: reuse after drain"
        );
    }
}

/// The sink conformance suite. Panics on the first violation.
///
/// It checks, at each of [`CONFORMANCE_CAPACITIES`]:
///
/// - every column kind, with values and with NULL, read back unchanged:
///   extreme integers, empty strings and blobs, strings containing NUL,
///   fixed-size values, timestamps in both units;
/// - list cells: NULL, empty, long, and with NULL items between values;
/// - [`Full`] reported exactly when the sink holds its capacity, neither
///   earlier nor later, with the row that filled it stored;
/// - a sink reused after it was drained, at capacity and partly filled;
/// - an output without columns, which still counts its rows;
/// - an output of a single column of each kind, so that no kind depends on
///   a neighbour.
pub fn run_conformance<H: SinkHarness>(h: &mut H) {
    let columns = conformance_columns();
    for capacity in CONFORMANCE_CAPACITIES {
        // Enough rows for two full drains and a partial one, and every row
        // shape at least twice.
        let count = (2 * capacity + capacity / 2 + 1).max(11) as u64;
        let rows: Vec<Vec<Cell>> = (0..count).map(conformance_row).collect();
        fill_and_drain(h, &columns, capacity, &rows);

        // Rows without columns: only their number is stored.
        let empty: Vec<Vec<Cell>> = vec![Vec::new(); count as usize];
        fill_and_drain(h, &[], capacity, &empty);
    }

    // Each kind alone (index 0 is the non-nullable id).
    for (index, column) in columns.iter().enumerate().skip(1) {
        let rows: Vec<Vec<Cell>> = (0..10)
            .map(|id| vec![conformance_row(id).swap_remove(index)])
            .collect();
        for capacity in [1, 7] {
            fill_and_drain(h, std::slice::from_ref(column), capacity, &rows);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_sink_conforms() {
        run_conformance(&mut RecordingHarness);
    }

    #[test]
    fn full_exactly_at_capacity() {
        let mut sink = RecordingSink::of_kinds(&[ColKind::U8], Some(2));
        sink.u8(OutCol(0), 1);
        assert!(sink.end_row().is_continue());
        sink.null(OutCol(0));
        assert_eq!(sink.end_row(), ControlFlow::Break(Full));
        assert!(sink.is_full());
        assert_eq!(sink.take_rows(), vec![vec![Cell::U8(1)], vec![Cell::Null]]);
        assert!(!sink.is_full());
    }

    #[test]
    #[should_panic(expected = "full sink")]
    fn writing_to_a_full_sink_panics() {
        let mut sink = RecordingSink::of_kinds(&[ColKind::U8], Some(1));
        sink.u8(OutCol(0), 1);
        let _ = sink.end_row();
        sink.u8(OutCol(0), 2);
    }

    #[test]
    #[should_panic(expected = "cannot store")]
    fn a_value_of_the_wrong_kind_panics() {
        let mut sink = RecordingSink::of_kinds(&[ColKind::U8], None);
        sink.u16(OutCol(0), 1);
    }

    #[test]
    #[should_panic(expected = "cannot store")]
    fn a_fixed_value_of_the_wrong_length_panics() {
        let mut sink = RecordingSink::of_kinds(&[ColKind::Fixed(6)], None);
        sink.fixed(OutCol(0), &[1, 2, 3]);
    }

    #[test]
    #[should_panic(expected = "columns missing")]
    fn a_short_row_panics() {
        let mut sink = RecordingSink::of_kinds(&[ColKind::U8, ColKind::U8], None);
        sink.u8(OutCol(0), 1);
        let _ = sink.end_row();
    }

    #[test]
    #[should_panic(expected = "out of order")]
    fn a_column_out_of_order_panics() {
        let mut sink = RecordingSink::of_kinds(&[ColKind::U8, ColKind::U8], None);
        sink.u8(OutCol(1), 1);
    }
}
