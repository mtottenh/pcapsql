//! Rows: what every cell of a scan's output holds.
//!
//! **Unstable API** (see the [module](super) documentation).
//!
//! This is the only place a parsed [`FieldValue`] meets a column kind.
//! [`write_value`] turns a value into the column's [`ColKind`] (or NULL) and
//! hands it to a [`RowSink`]; [`write_layer_row`] and [`write_frame_row`]
//! write a whole row from a packet and one of its parsed layers. All of it is
//! generic over the sink and inlined into the caller, so a row costs the
//! same as it did when the coercion was written against Arrow builders.

use std::fmt::{self, Write as _};
use std::net::IpAddr;
use std::ops::ControlFlow;

use super::catalog::{ColKind, ColumnSource};
use super::plan::{OutCol, OutColumn};
use super::sink::{Full, ListSink, RowSink};
use crate::io::PacketRef;
use crate::{FieldHint, FieldValue, ParseResult};

/// Write `value` to column `col` of kind `kind`.
///
/// The value is converted to the column's kind when it can be represented
/// there, and is NULL otherwise. Integers are never wrapped or truncated: a
/// value that does not fit the column is NULL.
///
/// | Column kind | Accepted value | Anything else |
/// |---|---|---|
/// | `U8` | `UInt8`; `UInt16/32/64` if it fits | NULL |
/// | `U16` | `UInt16`, `UInt8`; `UInt32/64` if it fits | NULL |
/// | `U32` | `UInt32`, `UInt8/16`; `UInt64` if it fits; an IPv4 address as its number | NULL |
/// | `U64` | `UInt64`, `UInt8/16/32` | NULL |
/// | `I8` | `Int8`; `Int64` if it fits | NULL |
/// | `I64` | `Int64`, `Int8`, `UInt8/16/32`; `UInt64` if it fits | NULL |
/// | `F64` | `Float64`; any integer | NULL |
/// | `Bool` | `Bool` | NULL |
/// | `Str` | `Str`, `OwnedString`; addresses, numbers and booleans as text | NULL |
/// | `Bin` | `Bytes`, `OwnedBytes` | NULL |
/// | `Fixed(n)` | `Bytes`/`OwnedBytes` of length `n`; a MAC address (`n` = 6); an IPv6 address (`n` = 16) | NULL, a wrong length included |
/// | `TsMicros`, `TsNanos` | `Int64`; `UInt64` if it fits | NULL |
/// | `ListU16` | a list; items `UInt16`, `UInt8` | a non-list is a NULL cell, any other item a NULL item |
/// | `ListU32` | a list; items `UInt32`, `UInt8/16`, an IPv4 address | same |
/// | `ListStr` | a list; items as for `Str` | same |
/// | `ListFixed(n)` | a list; items as for `Fixed(n)` | same |
///
/// An empty list is an empty list, not NULL.
#[inline]
pub fn write_value<S: RowSink>(sink: &mut S, col: OutCol, kind: ColKind, value: &FieldValue<'_>) {
    match kind {
        ColKind::U8 => {
            let v = match value {
                FieldValue::UInt8(v) => Some(*v),
                FieldValue::UInt16(v) => u8::try_from(*v).ok(),
                FieldValue::UInt32(v) => u8::try_from(*v).ok(),
                FieldValue::UInt64(v) => u8::try_from(*v).ok(),
                _ => None,
            };
            match v {
                Some(v) => sink.u8(col, v),
                None => sink.null(col),
            }
        }
        ColKind::U16 => {
            let v = match value {
                FieldValue::UInt16(v) => Some(*v),
                FieldValue::UInt8(v) => Some(u16::from(*v)),
                FieldValue::UInt32(v) => u16::try_from(*v).ok(),
                FieldValue::UInt64(v) => u16::try_from(*v).ok(),
                _ => None,
            };
            match v {
                Some(v) => sink.u16(col, v),
                None => sink.null(col),
            }
        }
        ColKind::U32 => {
            let v = match value {
                FieldValue::UInt32(v) => Some(*v),
                FieldValue::UInt8(v) => Some(u32::from(*v)),
                FieldValue::UInt16(v) => Some(u32::from(*v)),
                FieldValue::UInt64(v) => u32::try_from(*v).ok(),
                FieldValue::IpAddr(IpAddr::V4(v4)) => Some(u32::from(*v4)),
                _ => None,
            };
            match v {
                Some(v) => sink.u32(col, v),
                None => sink.null(col),
            }
        }
        ColKind::U64 => {
            let v = match value {
                FieldValue::UInt64(v) => Some(*v),
                FieldValue::UInt8(v) => Some(u64::from(*v)),
                FieldValue::UInt16(v) => Some(u64::from(*v)),
                FieldValue::UInt32(v) => Some(u64::from(*v)),
                _ => None,
            };
            match v {
                Some(v) => sink.u64(col, v),
                None => sink.null(col),
            }
        }
        ColKind::I8 => {
            let v = match value {
                FieldValue::Int8(v) => Some(*v),
                FieldValue::Int64(v) => i8::try_from(*v).ok(),
                _ => None,
            };
            match v {
                Some(v) => sink.i8(col, v),
                None => sink.null(col),
            }
        }
        ColKind::I64 => {
            let v = match value {
                FieldValue::Int64(v) => Some(*v),
                FieldValue::Int8(v) => Some(i64::from(*v)),
                FieldValue::UInt8(v) => Some(i64::from(*v)),
                FieldValue::UInt16(v) => Some(i64::from(*v)),
                FieldValue::UInt32(v) => Some(i64::from(*v)),
                FieldValue::UInt64(v) => i64::try_from(*v).ok(),
                _ => None,
            };
            match v {
                Some(v) => sink.i64(col, v),
                None => sink.null(col),
            }
        }
        ColKind::F64 => {
            let v = match value {
                FieldValue::Float64(v) => Some(*v),
                FieldValue::Int8(v) => Some(f64::from(*v)),
                FieldValue::Int64(v) => Some(*v as f64),
                FieldValue::UInt8(v) => Some(f64::from(*v)),
                FieldValue::UInt16(v) => Some(f64::from(*v)),
                FieldValue::UInt32(v) => Some(f64::from(*v)),
                FieldValue::UInt64(v) => Some(*v as f64),
                _ => None,
            };
            match v {
                Some(v) => sink.f64(col, v),
                None => sink.null(col),
            }
        }
        ColKind::Bool => match value {
            FieldValue::Bool(v) => sink.bool(col, *v),
            _ => sink.null(col),
        },
        ColKind::Str => match value {
            FieldValue::Str(v) => sink.str(col, v),
            FieldValue::OwnedString(v) => sink.str(col, v.as_str()),
            other => {
                if !with_text(other, |text| sink.str(col, text)) {
                    sink.null(col);
                }
            }
        },
        ColKind::Bin => match value {
            FieldValue::Bytes(v) => sink.bytes(col, v),
            FieldValue::OwnedBytes(v) => sink.bytes(col, v.as_slice()),
            _ => sink.null(col),
        },
        ColKind::Fixed(n) => {
            let mut octets = [0u8; 16];
            match fixed_bytes(value, usize::from(n), &mut octets) {
                Some(v) => sink.fixed(col, v),
                None => sink.null(col),
            }
        }
        ColKind::TsMicros | ColKind::TsNanos => {
            let v = match value {
                FieldValue::Int64(v) => Some(*v),
                FieldValue::UInt64(v) => i64::try_from(*v).ok(),
                _ => None,
            };
            match v {
                Some(v) => sink.timestamp(col, v),
                None => sink.null(col),
            }
        }
        ColKind::ListU16 => match value {
            FieldValue::List(items) => {
                let mut list = sink.list(col);
                for item in items {
                    match item {
                        FieldValue::UInt16(v) => list.u16(*v),
                        FieldValue::UInt8(v) => list.u16(u16::from(*v)),
                        _ => list.null(),
                    }
                }
                list.finish();
            }
            _ => sink.null(col),
        },
        ColKind::ListU32 => match value {
            FieldValue::List(items) => {
                let mut list = sink.list(col);
                for item in items {
                    match item {
                        FieldValue::UInt32(v) => list.u32(*v),
                        FieldValue::UInt16(v) => list.u32(u32::from(*v)),
                        FieldValue::UInt8(v) => list.u32(u32::from(*v)),
                        FieldValue::IpAddr(IpAddr::V4(v4)) => list.u32(u32::from(*v4)),
                        _ => list.null(),
                    }
                }
                list.finish();
            }
            _ => sink.null(col),
        },
        ColKind::ListStr => match value {
            FieldValue::List(items) => {
                let mut list = sink.list(col);
                for item in items {
                    match item {
                        FieldValue::Str(v) => list.str(v),
                        FieldValue::OwnedString(v) => list.str(v.as_str()),
                        other => {
                            if !with_text(other, |text| list.str(text)) {
                                list.null();
                            }
                        }
                    }
                }
                list.finish();
            }
            _ => sink.null(col),
        },
        ColKind::ListFixed(n) => match value {
            FieldValue::List(items) => {
                let mut list = sink.list(col);
                for item in items {
                    let mut octets = [0u8; 16];
                    match fixed_bytes(item, usize::from(n), &mut octets) {
                        Some(v) => list.bytes(v),
                        None => list.null(),
                    }
                }
                list.finish();
            }
            _ => sink.null(col),
        },
    }
}

/// `value` as the `n` bytes of a fixed-size column: bytes of exactly that
/// length, a MAC address when `n` is 6, an IPv6 address when `n` is 16
/// (its octets go through `octets`). `None` for anything else, a value of
/// another length included.
#[inline]
fn fixed_bytes<'v>(
    value: &'v FieldValue<'_>,
    n: usize,
    octets: &'v mut [u8; 16],
) -> Option<&'v [u8]> {
    let bytes: &[u8] = match value {
        FieldValue::MacAddr(mac) => mac.as_slice(),
        FieldValue::Bytes(v) => v,
        FieldValue::OwnedBytes(v) => v.as_slice(),
        FieldValue::IpAddr(IpAddr::V6(v6)) => {
            *octets = v6.octets();
            octets.as_slice()
        }
        _ => return None,
    };
    (bytes.len() == n).then_some(bytes)
}

/// A string assembled on the stack. Long enough for every address and
/// integer; a longer text (a float with hundreds of digits) does not fit and
/// the write fails.
struct StackText {
    len: usize,
    bytes: [u8; 64],
}

impl fmt::Write for StackText {
    #[inline]
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len + s.len();
        let room = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
        room.copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Hand `text` to `store` as a string, without a heap allocation when it is
/// short.
#[inline]
fn with_display(text: impl fmt::Display, store: impl FnOnce(&str)) {
    let mut stack = StackText {
        len: 0,
        bytes: [0; 64],
    };
    if write!(stack, "{text}").is_ok() {
        // Only whole `&str`s were copied in, so this is valid UTF-8.
        if let Ok(s) = std::str::from_utf8(&stack.bytes[..stack.len]) {
            return store(s);
        }
    }
    store(&text.to_string());
}

/// The text a string column stores for a value that is not a string: an
/// address, a number or a boolean, formatted. `false` (and `store` not
/// called) for a value with no text form (NULL, bytes, a list).
#[inline]
fn with_text(value: &FieldValue<'_>, store: impl FnOnce(&str)) -> bool {
    match value {
        FieldValue::Str(v) => store(v),
        FieldValue::OwnedString(v) => store(v.as_str()),
        FieldValue::IpAddr(v) => with_display(v, store),
        FieldValue::MacAddr(mac) => with_display(
            format_args!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            ),
            store,
        ),
        FieldValue::UInt8(v) => with_display(v, store),
        FieldValue::UInt16(v) => with_display(v, store),
        FieldValue::UInt32(v) => with_display(v, store),
        FieldValue::UInt64(v) => with_display(v, store),
        FieldValue::Int8(v) => with_display(v, store),
        FieldValue::Int64(v) => with_display(v, store),
        FieldValue::Float64(v) => with_display(v, store),
        FieldValue::Bool(v) => store(if *v { "true" } else { "false" }),
        FieldValue::Null
        | FieldValue::Bytes(_)
        | FieldValue::OwnedBytes(_)
        | FieldValue::List(_) => return false,
    }
    true
}

/// Where a column's value comes from, checked against the column's kind
/// once so that writing a row does not have to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    FrameNumber,
    TimestampMicros,
    TimestampNanos,
    CapturedLen,
    OriginalLen,
    LinkType,
    RawData,
    EncapDepth,
    TunnelType,
    TunnelId,
    /// A parser field, by its short name.
    Field(&'static str),
    /// No per-packet source, or one the column's kind cannot store.
    Null,
}

impl Source {
    fn of(column: &OutColumn) -> Self {
        match (column.source, column.kind) {
            (ColumnSource::FrameNumber, ColKind::U64) => Source::FrameNumber,
            (ColumnSource::Timestamp, ColKind::TsMicros) => Source::TimestampMicros,
            (ColumnSource::Timestamp, ColKind::TsNanos) => Source::TimestampNanos,
            (ColumnSource::CapturedLen, ColKind::U32) => Source::CapturedLen,
            (ColumnSource::OriginalLen, ColKind::U32) => Source::OriginalLen,
            (ColumnSource::LinkType, ColKind::U16) => Source::LinkType,
            (ColumnSource::RawData, ColKind::Bin) => Source::RawData,
            (ColumnSource::EncapDepth, ColKind::U8) => Source::EncapDepth,
            (ColumnSource::TunnelType, ColKind::Str) => Source::TunnelType,
            (ColumnSource::TunnelId, ColKind::U64) => Source::TunnelId,
            (ColumnSource::Field(name), _) => Source::Field(name),
            _ => Source::Null,
        }
    }
}

#[derive(Clone, Debug)]
struct Cell {
    source: Source,
    kind: ColKind,
    /// Where the field was found in the previous row.
    hint: FieldHint,
}

/// How the columns of one output are filled, with the per-column lookup
/// state that makes finding a parser field cheap.
///
/// A parser emits its fields in a fixed order, so a column's field is almost
/// always where it was in the previous row; the resolver remembers that
/// position per column ([`ParseResult::get_hinted`]). It therefore serves
/// one stream of rows of one output: make one per output per partition.
///
/// The packet-record and parse-context columns (`frame_number`, `timestamp`,
/// `length`, `original_length`, `link_type`, `raw_data`, `encap_depth`,
/// `tunnel_type`, `tunnel_id`) are written in the kind the catalogue
/// declares for them. A column that declares another kind for such a source
/// is NULL, as is a column with no per-packet source.
#[derive(Clone, Debug)]
pub struct FieldResolver {
    cells: Box<[Cell]>,
}

impl FieldResolver {
    /// The resolver for an output with these columns
    /// ([`OutputPlan::columns`](super::OutputPlan::columns)).
    pub fn new(columns: &[OutColumn]) -> Self {
        Self {
            cells: columns
                .iter()
                .map(|column| Cell {
                    source: Source::of(column),
                    kind: column.kind,
                    hint: FieldHint::default(),
                })
                .collect(),
        }
    }

    /// The number of columns.
    pub fn len(&self) -> usize {
        self.cells.len()
    }

    /// True for an output without columns (a row count).
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }
}

/// Write the row of one parsed layer of `packet`: a row of a protocol
/// table.
///
/// Parser fields come from `layer` (an absent field is NULL), the
/// encapsulation columns from its parse context, and `frame_number` (and the
/// opt-in `timestamp`) from the packet. Returns [`RowSink::end_row`]'s
/// answer.
#[inline]
pub fn write_layer_row<S: RowSink>(
    sink: &mut S,
    resolver: &mut FieldResolver,
    packet: &PacketRef<'_>,
    layer: &ParseResult<'_>,
) -> ControlFlow<Full> {
    for (index, cell) in resolver.cells.iter_mut().enumerate() {
        let col = OutCol(index as u16);
        match cell.source {
            Source::Field(name) => match layer.get_hinted(name, &mut cell.hint) {
                Some(value) => write_value(sink, col, cell.kind, value),
                None => sink.null(col),
            },
            Source::FrameNumber => sink.u64(col, packet.frame_number),
            Source::EncapDepth => sink.u8(col, layer.encap_depth),
            Source::TunnelType => match layer.tunnel_type.as_str() {
                Some(name) => sink.str(col, name),
                None => sink.null(col),
            },
            Source::TunnelId => match layer.tunnel_id {
                Some(id) => sink.u64(col, id),
                None => sink.null(col),
            },
            Source::TimestampMicros => sink.timestamp(col, packet.timestamp_ns / 1_000),
            Source::TimestampNanos => sink.timestamp(col, packet.timestamp_ns),
            Source::CapturedLen => sink.u32(col, packet.captured_len),
            Source::OriginalLen => sink.u32(col, packet.original_len),
            Source::LinkType => sink.u16(col, packet.link_type),
            Source::RawData => sink.bytes(col, packet.data),
            Source::Null => sink.null(col),
        }
    }
    sink.end_row()
}

/// Write the row of `packet` itself: a row of `frames`.
///
/// Every column comes from the packet record; a column with any other
/// source is NULL. Returns [`RowSink::end_row`]'s answer.
#[inline]
pub fn write_frame_row<S: RowSink>(
    sink: &mut S,
    resolver: &mut FieldResolver,
    packet: &PacketRef<'_>,
) -> ControlFlow<Full> {
    for (index, cell) in resolver.cells.iter().enumerate() {
        let col = OutCol(index as u16);
        match cell.source {
            Source::FrameNumber => sink.u64(col, packet.frame_number),
            Source::TimestampMicros => sink.timestamp(col, packet.timestamp_ns / 1_000),
            Source::TimestampNanos => sink.timestamp(col, packet.timestamp_ns),
            Source::CapturedLen => sink.u32(col, packet.captured_len),
            Source::OriginalLen => sink.u32(col, packet.original_len),
            Source::LinkType => sink.u16(col, packet.link_type),
            Source::RawData => sink.bytes(col, packet.data),
            Source::EncapDepth
            | Source::TunnelType
            | Source::TunnelId
            | Source::Field(_)
            | Source::Null => sink.null(col),
        }
    }
    sink.end_row()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::testing::{Cell as C, RecordingSink};
    use crate::scan::{Catalog, ScanPlan, TableScan, TimestampUnit};
    use crate::TunnelType;
    use smallvec::SmallVec;

    const COL: OutCol = OutCol(0);

    /// The cell `kind` stores for `value`.
    fn cell(kind: ColKind, value: &FieldValue<'_>) -> C {
        let mut sink = RecordingSink::of_kinds(&[kind], None);
        write_value(&mut sink, COL, kind, value);
        assert!(sink.end_row().is_continue());
        sink.take_rows().remove(0).remove(0)
    }

    fn v4() -> FieldValue<'static> {
        FieldValue::IpAddr("192.0.2.1".parse().unwrap())
    }

    fn v6() -> FieldValue<'static> {
        FieldValue::IpAddr("2001:db8::1".parse().unwrap())
    }

    const MAC: FieldValue<'static> = FieldValue::MacAddr([0x02, 0, 0, 0, 0, 0x01]);

    #[test]
    fn unsigned_columns_narrow_only_when_the_value_fits() {
        use FieldValue as V;
        assert_eq!(cell(ColKind::U8, &V::UInt8(7)), C::U8(7));
        assert_eq!(cell(ColKind::U8, &V::UInt16(255)), C::U8(255));
        assert_eq!(cell(ColKind::U8, &V::UInt16(256)), C::Null);
        assert_eq!(cell(ColKind::U8, &V::UInt32(0x1_0005)), C::Null);
        assert_eq!(cell(ColKind::U8, &V::UInt64(9)), C::U8(9));
        assert_eq!(cell(ColKind::U8, &V::Int64(7)), C::Null);

        assert_eq!(cell(ColKind::U16, &V::UInt8(7)), C::U16(7));
        assert_eq!(cell(ColKind::U16, &V::UInt32(65_535)), C::U16(65_535));
        assert_eq!(cell(ColKind::U16, &V::UInt32(65_536)), C::Null);
        assert_eq!(cell(ColKind::U16, &V::UInt64(u64::MAX)), C::Null);

        assert_eq!(cell(ColKind::U32, &V::UInt16(7)), C::U32(7));
        assert_eq!(cell(ColKind::U32, &V::UInt64(5_000_000_000)), C::Null);
        assert_eq!(cell(ColKind::U32, &v4()), C::U32(0xC000_0201));
        assert_eq!(cell(ColKind::U32, &v6()), C::Null);

        assert_eq!(cell(ColKind::U64, &V::UInt8(7)), C::U64(7));
        assert_eq!(cell(ColKind::U64, &V::UInt64(u64::MAX)), C::U64(u64::MAX));
        assert_eq!(cell(ColKind::U64, &V::Int64(7)), C::Null);
        assert_eq!(cell(ColKind::U64, &V::Null), C::Null);
    }

    #[test]
    fn signed_and_float_columns() {
        use FieldValue as V;
        assert_eq!(cell(ColKind::I8, &V::Int8(-3)), C::I8(-3));
        assert_eq!(cell(ColKind::I8, &V::Int64(-128)), C::I8(-128));
        assert_eq!(cell(ColKind::I8, &V::Int64(128)), C::Null);
        assert_eq!(cell(ColKind::I8, &V::UInt8(1)), C::Null);

        assert_eq!(cell(ColKind::I64, &V::Int8(-3)), C::I64(-3));
        assert_eq!(
            cell(ColKind::I64, &V::UInt32(u32::MAX)),
            C::I64(0xFFFF_FFFF)
        );
        assert_eq!(cell(ColKind::I64, &V::UInt64(7)), C::I64(7));
        assert_eq!(cell(ColKind::I64, &V::UInt64(u64::MAX)), C::Null);
        assert_eq!(cell(ColKind::I64, &V::Float64(1.0)), C::Null);

        assert_eq!(cell(ColKind::F64, &V::Float64(1.5)), C::F64(1.5));
        assert_eq!(cell(ColKind::F64, &V::Int8(-3)), C::F64(-3.0));
        assert_eq!(cell(ColKind::F64, &V::UInt64(4)), C::F64(4.0));
        assert_eq!(cell(ColKind::F64, &V::Bool(true)), C::Null);

        assert_eq!(cell(ColKind::Bool, &V::Bool(true)), C::Bool(true));
        assert_eq!(cell(ColKind::Bool, &V::UInt8(1)), C::Null);
    }

    #[test]
    fn string_columns_format_addresses_numbers_and_booleans() {
        use FieldValue as V;
        let s = |text: &str| C::Str(text.to_string());
        assert_eq!(cell(ColKind::Str, &V::Str("abc")), s("abc"));
        assert_eq!(cell(ColKind::Str, &V::Str("")), s(""));
        assert_eq!(cell(ColKind::Str, &V::OwnedString("xyz".into())), s("xyz"));
        assert_eq!(cell(ColKind::Str, &v4()), s("192.0.2.1"));
        assert_eq!(cell(ColKind::Str, &v6()), s("2001:db8::1"));
        assert_eq!(cell(ColKind::Str, &MAC), s("02:00:00:00:00:01"));
        assert_eq!(
            cell(ColKind::Str, &V::UInt64(u64::MAX)),
            s("18446744073709551615")
        );
        assert_eq!(cell(ColKind::Str, &V::Int8(-3)), s("-3"));
        assert_eq!(cell(ColKind::Str, &V::Float64(1.5)), s("1.5"));
        assert_eq!(cell(ColKind::Str, &V::Bool(false)), s("false"));
        assert_eq!(cell(ColKind::Str, &V::Bytes(b"ab")), C::Null);
        assert_eq!(cell(ColKind::Str, &V::List(vec![])), C::Null);
        assert_eq!(cell(ColKind::Str, &V::Null), C::Null);
    }

    /// The text of a value is what `FieldValue::as_string` returns, also
    /// when it is too long for the stack buffer.
    #[test]
    fn text_matches_as_string() {
        use FieldValue as V;
        let widest_v6 = "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255";
        let values = [
            v4(),
            v6(),
            V::IpAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()),
            V::IpAddr(widest_v6.parse().unwrap()),
            MAC,
            V::UInt8(0),
            V::UInt16(u16::MAX),
            V::UInt32(u32::MAX),
            V::UInt64(u64::MAX),
            V::Int8(i8::MIN),
            V::Int64(i64::MIN),
            V::Float64(0.1),
            V::Float64(f64::MAX),
            V::Float64(f64::MIN_POSITIVE),
            V::Float64(f64::NAN),
            V::Float64(f64::NEG_INFINITY),
            V::Bool(true),
        ];
        for value in &values {
            let expected = value.as_string().unwrap();
            assert_eq!(cell(ColKind::Str, value), C::Str(expected.clone()));
            assert_eq!(
                cell(ColKind::ListStr, &V::List(vec![value.clone()])),
                C::List(vec![C::Str(expected)])
            );
        }
    }

    #[test]
    fn binary_columns_take_bytes_only() {
        use FieldValue as V;
        assert_eq!(cell(ColKind::Bin, &V::Bytes(&[1, 2])), C::Bytes(vec![1, 2]));
        assert_eq!(cell(ColKind::Bin, &V::Bytes(&[])), C::Bytes(vec![]));
        assert_eq!(
            cell(ColKind::Bin, &V::OwnedBytes(vec![3])),
            C::Bytes(vec![3])
        );
        assert_eq!(cell(ColKind::Bin, &MAC), C::Null);
        assert_eq!(cell(ColKind::Bin, &V::Str("ab")), C::Null);
    }

    /// D7: a value of the wrong length for a fixed-size column is NULL.
    #[test]
    fn fixed_columns_take_exactly_their_length() {
        use FieldValue as V;
        let mac = C::Bytes(vec![0x02, 0, 0, 0, 0, 0x01]);
        assert_eq!(cell(ColKind::Fixed(6), &MAC), mac);
        assert_eq!(
            cell(ColKind::Fixed(6), &V::Bytes(&[1, 2, 3, 4, 5, 6])),
            C::Bytes(vec![1, 2, 3, 4, 5, 6])
        );
        assert_eq!(
            cell(ColKind::Fixed(6), &V::OwnedBytes(vec![9; 6])),
            C::Bytes(vec![9; 6])
        );
        assert_eq!(cell(ColKind::Fixed(6), &V::Bytes(&[1, 2, 3])), C::Null);
        assert_eq!(cell(ColKind::Fixed(6), &V::Bytes(&[0; 16])), C::Null);
        assert_eq!(cell(ColKind::Fixed(6), &v6()), C::Null);
        assert_eq!(cell(ColKind::Fixed(6), &v4()), C::Null);

        let mut octets = vec![0u8; 16];
        octets[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        octets[15] = 1;
        assert_eq!(cell(ColKind::Fixed(16), &v6()), C::Bytes(octets));
        assert_eq!(cell(ColKind::Fixed(16), &MAC), C::Null);
        assert_eq!(
            cell(ColKind::Fixed(16), &V::OwnedBytes(vec![1; 6])),
            C::Null
        );
        assert_eq!(cell(ColKind::Fixed(16), &V::Bytes(&[])), C::Null);
    }

    /// D8: an unsigned value above `i64::MAX` is NULL in a timestamp column,
    /// not a wrapped negative timestamp.
    #[test]
    fn timestamp_columns_reject_values_above_i64_max() {
        use FieldValue as V;
        for kind in [ColKind::TsMicros, ColKind::TsNanos] {
            assert_eq!(cell(kind, &V::Int64(-5)), C::Timestamp(-5));
            assert_eq!(cell(kind, &V::UInt64(7)), C::Timestamp(7));
            assert_eq!(
                cell(kind, &V::UInt64(i64::MAX as u64)),
                C::Timestamp(i64::MAX)
            );
            assert_eq!(cell(kind, &V::UInt64(i64::MAX as u64 + 1)), C::Null);
            assert_eq!(cell(kind, &V::UInt64(u64::MAX)), C::Null);
            assert_eq!(cell(kind, &V::UInt32(7)), C::Null);
        }
    }

    #[test]
    fn list_columns_keep_items_and_nulls() {
        use FieldValue as V;
        let items = V::List(vec![
            V::UInt16(7),
            V::UInt8(3),
            V::UInt32(9),
            V::Str("a.example"),
            V::OwnedString("b".into()),
            V::Bytes(&[0xAA; 16]),
            V::OwnedBytes(vec![1, 2]),
            v4(),
            v6(),
            MAC,
            V::Bool(true),
            V::Null,
        ]);
        let s = |text: &str| C::Str(text.to_string());
        let n = C::Null;
        assert_eq!(
            cell(ColKind::ListU16, &items),
            C::List(vec![
                C::U16(7),
                C::U16(3),
                n.clone(),
                n.clone(),
                n.clone(),
                n.clone(),
                n.clone(),
                n.clone(),
                n.clone(),
                n.clone(),
                n.clone(),
                n.clone(),
            ])
        );
        assert_eq!(
            cell(ColKind::ListU32, &items),
            C::List(vec![
                C::U32(7),
                C::U32(3),
                C::U32(9),
                n.clone(),
                n.clone(),
                n.clone(),
                n.clone(),
                C::U32(0xC000_0201),
                n.clone(),
                n.clone(),
                n.clone(),
                n.clone(),
            ])
        );
        assert_eq!(
            cell(ColKind::ListStr, &items),
            C::List(vec![
                s("7"),
                s("3"),
                s("9"),
                s("a.example"),
                s("b"),
                n.clone(),
                n.clone(),
                s("192.0.2.1"),
                s("2001:db8::1"),
                s("02:00:00:00:00:01"),
                s("true"),
                n.clone(),
            ])
        );
        // D7: an item of the wrong length is a NULL item; the list keeps
        // its length.
        let C::List(fixed) = cell(ColKind::ListFixed(16), &items) else {
            panic!("not a list");
        };
        assert_eq!(fixed.len(), 12);
        let stored: Vec<usize> = (0..12).filter(|i| fixed[*i] != C::Null).collect();
        assert_eq!(stored, [5, 8]);
        assert_eq!(fixed[5], C::Bytes(vec![0xAA; 16]));

        for kind in [
            ColKind::ListU16,
            ColKind::ListU32,
            ColKind::ListStr,
            ColKind::ListFixed(16),
        ] {
            assert_eq!(cell(kind, &V::List(vec![])), C::List(vec![]));
            assert_eq!(cell(kind, &V::Null), C::Null);
            assert_eq!(cell(kind, &V::UInt16(1)), C::Null);
        }
    }

    fn layer<'a>(fields: &[(&'static str, FieldValue<'a>)]) -> ParseResult<'a> {
        ParseResult {
            fields: fields.iter().cloned().collect(),
            remaining: &[],
            child_hints: SmallVec::new(),
            error: None,
            encap_depth: 0,
            tunnel_type: TunnelType::None,
            tunnel_id: None,
        }
    }

    /// The columns of `table` (`columns` by name, or every default column)
    /// as a compiled plan resolves them.
    fn out_columns(table: &str, columns: Option<&[&str]>, unit: TimestampUnit) -> Vec<OutColumn> {
        let catalog = Catalog::builtin();
        let (id, def) = catalog.table(table).unwrap();
        let ids = match columns {
            Some(names) => names.iter().map(|n| def.column(n).unwrap().0).collect(),
            None => def.default_columns().map(|(id, _)| id).collect(),
        };
        let plan = ScanPlan {
            tables: vec![TableScan::new(id, ids)],
            timestamps: unit,
            ..Default::default()
        };
        let compiled = plan.compile(catalog, &crate::default_registry()).unwrap();
        compiled.outputs()[0].columns.to_vec()
    }

    const PACKET: PacketRef<'static> = PacketRef {
        frame_number: 42,
        timestamp_ns: 1_700_000_000_123_456_789,
        captured_len: 4,
        original_len: 60,
        link_type: 1,
        data: &[0xDE, 0xAD, 0xBE, 0xEF],
    };

    #[test]
    fn frame_row_comes_from_the_packet_record() {
        let columns = out_columns("frames", None, TimestampUnit::Micros);
        let mut resolver = FieldResolver::new(&columns);
        let mut sink = RecordingSink::new(&columns, None);
        assert!(write_frame_row(&mut sink, &mut resolver, &PACKET).is_continue());
        let names: Vec<&str> = columns.iter().map(|c| c.name).collect();
        assert_eq!(
            names,
            [
                "frame_number",
                "timestamp",
                "length",
                "original_length",
                "link_type",
                "raw_data"
            ]
        );
        assert_eq!(
            sink.take_rows(),
            vec![vec![
                C::U64(42),
                C::Timestamp(1_700_000_000_123_456),
                C::U32(4),
                C::U32(60),
                C::U16(1),
                C::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            ]]
        );

        // The same row in nanoseconds.
        let columns = out_columns("frames", Some(&["timestamp"]), TimestampUnit::Nanos);
        assert_eq!(columns[0].kind, ColKind::TsNanos);
        let mut resolver = FieldResolver::new(&columns);
        let mut sink = RecordingSink::new(&columns, None);
        let _ = write_frame_row(&mut sink, &mut resolver, &PACKET);
        assert_eq!(
            sink.take_rows(),
            vec![vec![C::Timestamp(1_700_000_000_123_456_789)]]
        );
    }

    #[test]
    fn layer_row_takes_fields_context_and_frame_number() {
        let names = [
            "frame_number",
            "src_port",
            "dst_port",
            "length",
            "encap_depth",
            "tunnel_type",
            "tunnel_id",
        ];
        let columns = out_columns("udp", Some(&names), TimestampUnit::Micros);
        let mut resolver = FieldResolver::new(&columns);
        let mut sink = RecordingSink::new(&columns, None);

        let outer = layer(&[
            ("src_port", FieldValue::UInt16(50_000)),
            ("dst_port", FieldValue::UInt16(4789)),
        ]);
        let mut inner = layer(&[
            // Another order, and one field more: the hints must follow.
            ("length", FieldValue::UInt16(20)),
            ("dst_port", FieldValue::UInt16(53)),
            ("src_port", FieldValue::UInt16(1234)),
        ]);
        inner.encap_depth = 1;
        inner.tunnel_type = TunnelType::Vxlan;
        inner.tunnel_id = Some(77);

        for l in [&outer, &inner, &outer] {
            assert!(write_layer_row(&mut sink, &mut resolver, &PACKET, l).is_continue());
        }
        let outer_row = vec![
            C::U64(42),
            C::U16(50_000),
            C::U16(4789),
            C::Null,
            C::U8(0),
            C::Null,
            C::Null,
        ];
        assert_eq!(
            sink.take_rows(),
            vec![
                outer_row.clone(),
                vec![
                    C::U64(42),
                    C::U16(1234),
                    C::U16(53),
                    C::U16(20),
                    C::U8(1),
                    C::Str("vxlan".into()),
                    C::U64(77),
                ],
                outer_row,
            ]
        );
    }

    /// The opt-in `timestamp` of a protocol table is the packet's, in the
    /// plan's unit.
    #[test]
    fn layer_row_has_the_opt_in_timestamp() {
        for (unit, expected) in [
            (TimestampUnit::Micros, 1_700_000_000_123_456),
            (TimestampUnit::Nanos, 1_700_000_000_123_456_789),
        ] {
            let columns = out_columns("udp", Some(&["timestamp", "src_port"]), unit);
            let mut resolver = FieldResolver::new(&columns);
            let mut sink = RecordingSink::new(&columns, None);
            let l = layer(&[("src_port", FieldValue::UInt16(1))]);
            let _ = write_layer_row(&mut sink, &mut resolver, &PACKET, &l);
            assert_eq!(
                sink.take_rows(),
                vec![vec![C::Timestamp(expected), C::U16(1)]]
            );
        }
    }

    /// Every column of every per-packet table has a source its kind can
    /// store: none falls back to NULL.
    #[test]
    fn every_builtin_column_has_a_writable_source() {
        for (_, table) in Catalog::builtin().tables() {
            if table.is_stream() {
                continue;
            }
            for (_, def) in table.columns() {
                let column = OutColumn {
                    name: def.name,
                    kind: def.kind,
                    nullable: def.nullable,
                    source: def.source,
                };
                assert_ne!(
                    Source::of(&column),
                    Source::Null,
                    "{}.{}",
                    table.name,
                    def.name
                );
            }
        }
    }

    #[test]
    fn zero_column_rows_count() {
        let mut resolver = FieldResolver::new(&[]);
        assert!(resolver.is_empty());
        let mut sink = RecordingSink::new(&[], Some(2));
        assert!(write_frame_row(&mut sink, &mut resolver, &PACKET).is_continue());
        assert!(write_layer_row(&mut sink, &mut resolver, &PACKET, &layer(&[])).is_break());
        assert_eq!(sink.take_rows(), vec![Vec::<C>::new(), vec![]]);
    }
}
