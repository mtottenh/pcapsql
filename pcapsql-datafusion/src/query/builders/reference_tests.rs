//! The Arrow sink against Arrow's own builders: random rows written through
//! [`ArrowSink`] give, batch for batch, the arrays that appending the same
//! cells to an `arrow::array` builder gives, down to the bytes of the value
//! and validity buffers.

use std::ops::ControlFlow;
use std::sync::Arc;

use arrow::array::{
    Array, ArrayRef, BinaryBuilder, BooleanBuilder, FixedSizeBinaryBuilder, Float64Builder,
    Int64Builder, Int8Builder, ListBuilder, StringBuilder, TimestampMicrosecondBuilder,
    TimestampNanosecondBuilder, UInt16Builder, UInt32Builder, UInt64Builder, UInt8Builder,
};
use arrow::record_batch::RecordBatch;
use pcapsql_core::scan::testing::Cell;
use pcapsql_core::scan::{ColKind, ColumnSource, Full, ListSink, OutCol, OutColumn, RowSink};
use pcapsql_testgen::SplitMix64;

use super::ArrowSink;

const KINDS: [ColKind; 20] = [
    ColKind::Bool,
    ColKind::U8,
    ColKind::U16,
    ColKind::U32,
    ColKind::U64,
    ColKind::I8,
    ColKind::I64,
    ColKind::F64,
    ColKind::TsMicros,
    ColKind::TsNanos,
    ColKind::Fixed(1),
    ColKind::Fixed(4),
    ColKind::Fixed(6),
    ColKind::Fixed(16),
    ColKind::Str,
    ColKind::Bin,
    ColKind::ListU16,
    ColKind::ListU32,
    ColKind::ListStr,
    ColKind::ListFixed(4),
];

/// Which rows of a column are NULL.
#[derive(Clone, Copy, Debug)]
enum Nulls {
    None,
    All,
    /// The first row written.
    First,
    /// The last row written.
    Last,
    /// The first row of every full batch.
    BatchStarts,
    /// The last row of every full batch.
    BatchEnds,
    /// Each row with this chance in 256.
    Random(u8),
}

const PATTERNS: [Nulls; 9] = [
    Nulls::None,
    Nulls::All,
    Nulls::First,
    Nulls::Last,
    Nulls::BatchStarts,
    Nulls::BatchEnds,
    Nulls::Random(4),
    Nulls::Random(128),
    Nulls::Random(250),
];

impl Nulls {
    fn is_null(self, row: usize, rows: usize, capacity: usize, rng: &mut SplitMix64) -> bool {
        match self {
            Nulls::None => false,
            Nulls::All => true,
            Nulls::First => row == 0,
            Nulls::Last => row + 1 == rows,
            Nulls::BatchStarts => row.is_multiple_of(capacity),
            Nulls::BatchEnds => row % capacity == capacity - 1,
            Nulls::Random(chance) => rng.next_u64() % 256 < u64::from(chance),
        }
    }
}

fn bytes(rng: &mut SplitMix64, len: usize) -> Vec<u8> {
    (0..len).map(|_| rng.next_u64() as u8).collect()
}

fn text(rng: &mut SplitMix64) -> String {
    let len = rng.next_in_range(0, 12);
    (0..len)
        .map(|_| char::from(b'a' + (rng.next_u64() % 26) as u8))
        .collect()
}

/// A value of a column of `kind`.
fn value(rng: &mut SplitMix64, kind: ColKind) -> Cell {
    let n = rng.next_u64();
    let items = |rng: &mut SplitMix64, item: fn(&mut SplitMix64) -> Cell| {
        let len = rng.next_in_range(0, 4);
        let cells = (0..len).map(|_| match rng.next_u64() % 5 {
            0 => Cell::Null,
            _ => item(rng),
        });
        Cell::List(cells.collect())
    };
    match kind {
        ColKind::Bool => Cell::Bool(n.is_multiple_of(2)),
        ColKind::U8 => Cell::U8(n as u8),
        ColKind::U16 => Cell::U16(n as u16),
        ColKind::U32 => Cell::U32(n as u32),
        ColKind::U64 => Cell::U64(n),
        ColKind::I8 => Cell::I8(n as i8),
        ColKind::I64 => Cell::I64(n as i64),
        ColKind::F64 => Cell::F64(n as i64 as f64 / 7.0),
        ColKind::TsMicros | ColKind::TsNanos => Cell::Timestamp(n as i64),
        ColKind::Fixed(width) => Cell::Bytes(bytes(rng, usize::from(width))),
        ColKind::Str => Cell::Str(text(rng)),
        ColKind::Bin => {
            let len = rng.next_in_range(0, 20);
            Cell::Bytes(bytes(rng, len))
        }
        ColKind::ListU16 => items(rng, |rng| Cell::U16(rng.next_u64() as u16)),
        ColKind::ListU32 => items(rng, |rng| Cell::U32(rng.next_u64() as u32)),
        ColKind::ListStr => items(rng, |rng| Cell::Str(text(rng))),
        ColKind::ListFixed(width) => {
            let len = rng.next_in_range(0, 4);
            let cells = (0..len).map(|_| match rng.next_u64() % 5 {
                0 => Cell::Null,
                _ => Cell::Bytes(bytes(rng, usize::from(width))),
            });
            Cell::List(cells.collect())
        }
    }
}

/// Write `row` to the sink, a call per column in column order.
fn write_row(sink: &mut ArrowSink, row: &[Cell]) -> ControlFlow<Full> {
    for (index, cell) in row.iter().enumerate() {
        let col = OutCol(index as u16);
        match cell {
            Cell::Null => sink.null(col),
            Cell::Bool(v) => sink.bool(col, *v),
            Cell::U8(v) => sink.u8(col, *v),
            Cell::U16(v) => sink.u16(col, *v),
            Cell::U32(v) => sink.u32(col, *v),
            Cell::U64(v) => sink.u64(col, *v),
            Cell::I8(v) => sink.i8(col, *v),
            Cell::I64(v) => sink.i64(col, *v),
            Cell::F64(v) => sink.f64(col, *v),
            Cell::Str(v) => sink.str(col, v),
            Cell::Timestamp(v) => sink.timestamp(col, *v),
            Cell::Bytes(v) => match sink.schema().field(index).data_type() {
                arrow::datatypes::DataType::Binary => sink.bytes(col, v),
                _ => sink.fixed(col, v),
            },
            Cell::List(items) => {
                let mut list = sink.list(col);
                for item in items {
                    match item {
                        Cell::U16(v) => list.u16(*v),
                        Cell::U32(v) => list.u32(*v),
                        Cell::Str(v) => list.str(v),
                        Cell::Bytes(v) => list.bytes(v),
                        _ => list.null(),
                    }
                }
                list.finish();
            }
        }
    }
    sink.end_row()
}

/// Column `index` of `rows` as Arrow's builder of the kind's type builds
/// it, one append per cell.
fn reference(kind: ColKind, rows: &[Vec<Cell>], index: usize) -> ArrayRef {
    let cells = rows.iter().map(|row| &row[index]);
    macro_rules! primitive {
        ($builder:ty, $cell:path) => {{
            let mut builder = <$builder>::new();
            for cell in cells {
                match cell {
                    $cell(v) => builder.append_value(*v),
                    _ => builder.append_null(),
                }
            }
            Arc::new(builder.finish())
        }};
    }
    macro_rules! list {
        ($values:expr, $cell:path, $append:expr) => {{
            let mut builder = ListBuilder::new($values);
            for cell in cells {
                let Cell::List(items) = cell else {
                    builder.append_null();
                    continue;
                };
                for item in items {
                    match item {
                        $cell(v) => $append(builder.values(), v),
                        _ => builder.values().append_null(),
                    }
                }
                builder.append(true);
            }
            Arc::new(builder.finish())
        }};
    }
    match kind {
        ColKind::Bool => primitive!(BooleanBuilder, Cell::Bool),
        ColKind::U8 => primitive!(UInt8Builder, Cell::U8),
        ColKind::U16 => primitive!(UInt16Builder, Cell::U16),
        ColKind::U32 => primitive!(UInt32Builder, Cell::U32),
        ColKind::U64 => primitive!(UInt64Builder, Cell::U64),
        ColKind::I8 => primitive!(Int8Builder, Cell::I8),
        ColKind::I64 => primitive!(Int64Builder, Cell::I64),
        ColKind::F64 => primitive!(Float64Builder, Cell::F64),
        ColKind::TsMicros => primitive!(TimestampMicrosecondBuilder, Cell::Timestamp),
        ColKind::TsNanos => primitive!(TimestampNanosecondBuilder, Cell::Timestamp),
        ColKind::Str => {
            let mut builder = StringBuilder::new();
            for cell in cells {
                match cell {
                    Cell::Str(v) => builder.append_value(v),
                    _ => builder.append_null(),
                }
            }
            Arc::new(builder.finish())
        }
        ColKind::Bin => {
            let mut builder = BinaryBuilder::new();
            for cell in cells {
                match cell {
                    Cell::Bytes(v) => builder.append_value(v),
                    _ => builder.append_null(),
                }
            }
            Arc::new(builder.finish())
        }
        ColKind::Fixed(width) => {
            let mut builder = FixedSizeBinaryBuilder::new(i32::from(width));
            for cell in cells {
                match cell {
                    Cell::Bytes(v) => builder.append_value(v).expect("the column's width"),
                    _ => builder.append_null(),
                }
            }
            Arc::new(builder.finish())
        }
        ColKind::ListU16 => list!(
            UInt16Builder::new(),
            Cell::U16,
            |b: &mut UInt16Builder, v: &u16| b.append_value(*v)
        ),
        ColKind::ListU32 => list!(
            UInt32Builder::new(),
            Cell::U32,
            |b: &mut UInt32Builder, v: &u32| b.append_value(*v)
        ),
        ColKind::ListStr => list!(
            StringBuilder::new(),
            Cell::Str,
            |b: &mut StringBuilder, v: &String| b.append_value(v)
        ),
        ColKind::ListFixed(width) => list!(
            FixedSizeBinaryBuilder::new(i32::from(width)),
            Cell::Bytes,
            |b: &mut FixedSizeBinaryBuilder, v: &Vec<u8>| b
                .append_value(v)
                .expect("the list's width")
        ),
    }
}

/// `batch` holds `rows` as the builders build them: the same arrays, and
/// for a column of fixed width the same bytes, with a validity bitmap
/// exactly when the batch has a NULL in the column.
fn assert_is_reference(batch: &RecordBatch, kinds: &[ColKind], rows: &[Vec<Cell>], what: &str) {
    assert_eq!(batch.num_rows(), rows.len(), "{what}");
    assert_eq!(batch.num_columns(), kinds.len(), "{what}");
    for (index, kind) in kinds.iter().enumerate() {
        let what = format!("{what}, column {index} ({kind:?})");
        let got = batch.column(index);
        let want = reference(*kind, rows, index);
        assert_eq!(got.data_type(), want.data_type(), "{what}");
        assert_eq!(got.to_data(), want.to_data(), "{what}");
        assert_eq!(got.null_count(), want.null_count(), "{what}");
        assert_eq!(got.nulls().is_some(), want.nulls().is_some(), "{what}");
        let bitmap = |array: &ArrayRef| array.nulls().map(|n| n.buffer().as_slice().to_vec());
        assert_eq!(bitmap(got), bitmap(&want), "{what}: validity bytes");
        let fixed_width = !matches!(
            kind,
            ColKind::Str
                | ColKind::Bin
                | ColKind::ListU16
                | ColKind::ListU32
                | ColKind::ListStr
                | ColKind::ListFixed(_)
        );
        if fixed_width {
            let (got, want) = (got.to_data(), want.to_data());
            assert_eq!(got.offset(), 0, "{what}");
            assert_eq!(got.buffers().len(), 1, "{what}");
            assert_eq!(
                got.buffers()[0].as_slice(),
                want.buffers()[0].as_slice(),
                "{what}: value bytes"
            );
        }
    }
}

/// Write `rows` rows of `kinds` with these NULLs through a sink of
/// `capacity` rows, taking a batch whenever the sink is full and, with a
/// chance of `flush` in 256 after each row, before it is; every batch must
/// be the builders'.
fn check(seed: u64, kinds: &[ColKind], nulls: &[Nulls], capacity: usize, rows: usize, flush: u8) {
    let what = format!("seed {seed}, capacity {capacity}, {rows} rows, {nulls:?}");
    let mut rng = SplitMix64::new(seed);
    let columns: Vec<OutColumn> = kinds
        .iter()
        .map(|kind| OutColumn {
            name: "c",
            kind: *kind,
            nullable: true,
            source: ColumnSource::Field("c"),
        })
        .collect();
    let mut sink = ArrowSink::new(&columns, capacity);
    let mut held: Vec<Vec<Cell>> = Vec::new();
    let mut taken = 0;
    for row in 0..rows {
        let cells: Vec<Cell> = kinds
            .iter()
            .zip(nulls)
            .map(|(kind, nulls)| {
                if nulls.is_null(row, rows, capacity, &mut rng) {
                    Cell::Null
                } else {
                    value(&mut rng, *kind)
                }
            })
            .collect();
        let full = write_row(&mut sink, &cells).is_break();
        held.push(cells);
        assert_eq!(full, held.len() == capacity, "{what}: row {row}");
        if full || rng.next_u64() % 256 < u64::from(flush) {
            let batch = sink.take_batch().expect("the batch builds").expect("rows");
            assert_is_reference(&batch, kinds, &held, &format!("{what}, rows to {row}"));
            taken += held.len();
            held.clear();
        }
    }
    match sink.take_batch().expect("the batch builds") {
        Some(batch) => assert_is_reference(&batch, kinds, &held, &format!("{what}, the rest")),
        None => assert!(held.is_empty(), "{what}"),
    }
    assert_eq!(taken + held.len(), rows, "{what}");
    assert!(sink.take_batch().unwrap().is_none(), "{what}");
}

/// Every kind of column alone, with each pattern of NULLs (none, all, the
/// first row, the last, the first and the last of every batch, random), in
/// batches of several sizes around a byte of bitmap, with and without
/// batches taken before the sink is full.
#[test]
fn each_kind_equals_its_builder_for_every_pattern_of_nulls() {
    let mut seed = 0;
    for kind in KINDS {
        for nulls in PATTERNS {
            for capacity in [1, 2, 7, 8, 9, 20] {
                for flush in [0, 40] {
                    seed += 1;
                    // Two full batches and a partial one, or one less row.
                    let rows = 2 * capacity + capacity / 2 + (seed % 2) as usize;
                    check(seed, &[kind], &[nulls], capacity, rows, flush);
                }
            }
        }
    }
}

/// Rows of several columns of random kinds, each with its own pattern of
/// NULLs.
#[test]
fn random_rows_equal_the_builders() {
    for seed in 1000..1300 {
        let mut rng = SplitMix64::new(seed);
        let width = rng.next_in_range(1, 10);
        let kinds: Vec<ColKind> = (0..width)
            .map(|_| KINDS[rng.next_in_range(0, KINDS.len() - 1)])
            .collect();
        let nulls: Vec<Nulls> = (0..width)
            .map(|_| PATTERNS[rng.next_in_range(0, PATTERNS.len() - 1)])
            .collect();
        let capacity = [1, 3, 8, 16, 17, 64, 100][rng.next_in_range(0, 6)];
        let rows = rng.next_in_range(0, 3 * capacity + 5);
        let flush = [0, 0, 8, 80][rng.next_in_range(0, 3)];
        check(seed, &kinds, &nulls, capacity, rows, flush);
    }
}

/// A batch without NULLs after one with NULLs has no bitmap, and the other
/// way round: the validity of a batch is that batch's alone.
#[test]
fn validity_does_not_carry_over_to_the_next_batch() {
    let columns = [OutColumn {
        name: "c",
        kind: ColKind::U32,
        nullable: true,
        source: ColumnSource::Field("c"),
    }];
    let mut sink = ArrowSink::new(&columns, 4);
    let mut batch = |nulls: [bool; 4]| {
        for (row, null) in nulls.into_iter().enumerate() {
            match null {
                true => sink.null(OutCol(0)),
                false => sink.u32(OutCol(0), row as u32),
            }
            let _ = sink.end_row();
        }
        let batch = sink.take_batch().unwrap().unwrap();
        let column = batch.column(0);
        (column.nulls().is_some(), column.null_count())
    };
    assert_eq!(batch([false; 4]), (false, 0));
    assert_eq!(batch([false, false, false, true]), (true, 1));
    assert_eq!(batch([false; 4]), (false, 0));
    assert_eq!(batch([true; 4]), (true, 4));
    assert_eq!(batch([false; 4]), (false, 0));
}
