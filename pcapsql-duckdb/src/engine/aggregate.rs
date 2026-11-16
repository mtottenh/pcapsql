//! The aggregate function `hdr_histogram(value)`: a histogram of the values of a group, as the
//! `BLOB` the `hdr_*` scalar functions read (`engine::scalar`).
//!
//! ```sql
//! SELECT hdr_percentile(h, 0.99), hdr_max(h)
//! FROM (SELECT hdr_histogram(length) AS h FROM read_frames('capture.pcap'));
//! SELECT dst_port, hdr_ascii(hdr_histogram(length)) FROM read_tcp('capture.pcap') GROUP BY ALL;
//! ```
//!
//! Like the scalar functions, it has no logic of its own: the state of a group is a
//! `pcapsql_core::format::histogram::HdrHistogram`, the kernel the DataFusion engine's function
//! of this name wraps too, and the result is that kernel's serialized form. A histogram one
//! engine made is one the other reads.
//!
//! | Callback | Work |
//! |---|---|
//! | `init` | An empty histogram |
//! | `update` | Record the value of every row that is not NULL in the histogram of its group |
//! | `combine` | Merge the histogram of a partial state into another (parallel aggregation, windows) |
//! | `finalize` | Serialize the histogram of each group |
//! | `destroy` | `duckdb-neo` drops the state, which frees the histogram |
//!
//! All of them run under the panic guard, `init` too ([`guard::Aggregate`]).
//!
//! # Values
//!
//! The argument is declared `ANY` and `bind` accepts the types that are numbers ([`Input`]):
//! the integers of every width, `HUGEINT` and `UHUGEINT` included, `FLOAT`, `DOUBLE` and
//! `DECIMAL`. Each is read as it is stored, so no value passes through a type that cannot hold
//! it. Anything else is refused when the statement is bound, with a message that names the
//! type. (One function with one `ANY` parameter, not one function per type: DuckDB 2.0.0
//! cannot add a second aggregate function of a name through the C API.)
//!
//! What is recorded of a value is the kernel's business: an unsigned integer as it is, a
//! negative number not at all, the integer part of a number with a fraction, NaN not at all,
//! and what is larger than a `u64` as the largest `u64`. NULL is not recorded.
//!
//! A group without a value (every row NULL, or no row: an aggregate without `GROUP BY` over
//! no rows) is an empty histogram, not NULL, as in the DataFusion engine: `hdr_count` of it is
//! 0.
//!
//! # Bytes
//!
//! The bytes of the result are those of the kernel: equal for equal values when one worker
//! recorded them all, and possibly different in one field of the header when DuckDB combined
//! several partial states that had values (see the kernel's documentation). Every `hdr_*`
//! function answers the same for both.
//!
//! # States DuckDB does not destroy
//!
//! A state owns its histogram, and `destroy` frees it. DuckDB 2.0.0 calls `destroy` for the
//! states of the groups it returns, and not for those of groups a grouped aggregation never
//! returns (a `LIMIT` without an `ORDER BY`, a failure while groups are combined or
//! returned): their histograms stay allocated. `itest/tests/guard_aggregate.rs` counts it and
//! says where in DuckDB it is decided; the README says what would avoid it.

use duckdb_neo::{
    aggregate::ReturnTypeHandle,
    bind_arguments::BindArguments,
    connection::Context,
    data_chunk::VectorCollection,
    enums::{AggregateFunctionProperty, LogicalTypeID},
    error::DuckDBError,
    extension::Extension,
    logical_type::LogicalType,
    signature::{FunctionDocumentationBuilder, FunctionParameter, SignatureBuilder},
    types::{
        Any, BlobValue, DecimalContainer, DecimalSignature, HugeDecimal, HugeInt, LongDecimal,
        ShortDecimal, UHugeInt, WordDecimal,
    },
    vector::{ReadableNativeElement, Unknown, Vector},
    DuckDBType, Error, Result,
};
use pcapsql_core::format::histogram::{HdrHistogram, HistogramError};

use super::guard::{self, Aggregate, Slots, SourceSlots};
use super::scalar::readable;

/// The SQL name of the function.
const NAME: &str = "hdr_histogram";

pub(super) fn register(extension: &Extension) -> Result<()> {
    let documentation = FunctionDocumentationBuilder::new()
        .description(
            "A histogram of the values of a group, as the BLOB the hdr_* functions read. \
             NULL and negative values are not recorded; fractions are cut off.",
        )
        .add_example("", "hdr_percentile(hdr_histogram(length), 0.99)");
    let signature = SignatureBuilder::new()
        .param(FunctionParameter::new::<Any>("value"))
        .return_type(BlobValue::logical_type(extension)?)
        .documentation(documentation);
    guard::aggregate_function(NAME, signature, Histogram)
        // The histogram of a group does not depend on the order of its rows, so DuckDB need
        // not keep one for it.
        .set_property(AggregateFunctionProperty::AggregateOrderDependent(false))
        .register(extension)
}

/// `hdr_histogram`.
struct Histogram;

/// How the values of a call are stored: what `bind` learned from the type of the argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Input {
    I8,
    I16,
    I32,
    I64,
    I128,
    U8,
    U16,
    U32,
    U64,
    U128,
    F32,
    F64,
    /// A `DECIMAL` of this width, whose stored integer is the value times ten to this scale.
    Decimal(DecimalSignature),
    /// The type of a bare `NULL`: there is no value to record.
    Null,
}

impl Input {
    /// The way to read an argument of `logical_type`; `None` for a type that is not a number.
    fn of(logical_type: &LogicalType) -> Result<Option<Self>> {
        Ok(Some(match logical_type.id()? {
            LogicalTypeID::TinyInt => Self::I8,
            LogicalTypeID::SmallInt => Self::I16,
            LogicalTypeID::Integer => Self::I32,
            LogicalTypeID::BigInt => Self::I64,
            LogicalTypeID::HugeInt => Self::I128,
            LogicalTypeID::UTinyInt => Self::U8,
            LogicalTypeID::USmallInt => Self::U16,
            LogicalTypeID::UInteger => Self::U32,
            LogicalTypeID::UBigInt => Self::U64,
            LogicalTypeID::UHugeInt => Self::U128,
            LogicalTypeID::Float => Self::F32,
            LogicalTypeID::Double => Self::F64,
            LogicalTypeID::Decimal => {
                Self::Decimal(DecimalSignature::from_logical_type(logical_type)?)
            }
            LogicalTypeID::SqlNull => Self::Null,
            _ => return Ok(None),
        }))
    }
}

/// The value of a `HUGEINT`.
fn huge(value: &HugeInt) -> i128 {
    (i128::from(value.upper) << 64) | i128::from(value.lower)
}

/// The value of a `UHUGEINT`, or the largest `i128` for one above it: either way more than a
/// histogram holds, which records it as its largest value.
fn unsigned_huge(value: &UHugeInt) -> i128 {
    let value = (u128::from(value.upper) << 64) | u128::from(value.lower);
    i128::try_from(value).unwrap_or(i128::MAX)
}

/// Record the value of every row of `data` that is not NULL in the histogram of its group.
fn record_rows<I>(
    data: &mut VectorCollection,
    states: &mut Slots<'_, '_, HdrHistogram>,
    record: impl for<'a> Fn(&mut HdrHistogram, I::Ref<'a>),
) -> Result<()>
where
    I: ReadableNativeElement + 'static,
{
    let values = readable(data.get_vector_at_mut::<I>(0)?)?;
    for (row, value) in values.reader()?.iter().enumerate() {
        if let Some(value) = value {
            record(states.get_mut(row)?, value);
        }
    }
    Ok(())
}

/// [`record_rows`] for a `DECIMAL` stored as `I`: the integer part of the value, which is the
/// stored integer without its last `scale` digits. A negative value is not recorded, also one
/// whose integer part is zero.
fn record_decimals<I>(
    data: &mut VectorCollection,
    states: &mut Slots<'_, '_, HdrHistogram>,
    scale: u8,
) -> Result<()>
where
    I: DecimalContainer + 'static,
    I: for<'a> ReadableNativeElement<Ref<'a> = &'a I>,
{
    // At most 10^38, the widest DECIMAL there is.
    let unit = 10_i128.pow(u32::from(scale));
    record_rows::<I>(data, states, |histogram, value: &I| {
        let stored = value.to_i128();
        if stored >= 0 {
            histogram.record_wide(stored / unit);
        }
    })
}

/// The error of a kernel, as the function's.
fn kernel_error(error: HistogramError) -> Error {
    Error {
        code: DuckDBError::QueryExecutor,
        message: format!("{NAME}: {error}"),
    }
}

impl Aggregate for Histogram {
    type BindData = Input;
    type State = HdrHistogram;

    fn bind(
        &self,
        _context: &Context,
        arguments: BindArguments<'_>,
        _result_type: ReturnTypeHandle<'_>,
    ) -> Result<Input> {
        let logical_type = arguments.logical_type(0)?;
        Input::of(&logical_type)?.ok_or_else(|| {
            let name = logical_type
                .to_text()
                .unwrap_or_else(|_| "this type".to_owned());
            Error::invalid_input(format!(
                "{NAME}: the values must be numbers (an integer type, FLOAT, DOUBLE or DECIMAL), \
                 not {name}"
            ))
        })
    }

    fn init(&self, _bind_data: Option<&Input>) -> HdrHistogram {
        HdrHistogram::default()
    }

    fn update(
        &self,
        input: Option<&Input>,
        data: &mut VectorCollection,
        mut states: Slots<'_, '_, HdrHistogram>,
    ) -> Result<()> {
        let input = input.ok_or_else(|| {
            Error::invalid_input(format!("{NAME}: DuckDB gave update no bind data"))
        })?;
        let states = &mut states;
        match *input {
            Input::I8 => record_rows::<i8>(data, states, |h, v| h.record_signed((*v).into())),
            Input::I16 => record_rows::<i16>(data, states, |h, v| h.record_signed((*v).into())),
            Input::I32 => record_rows::<i32>(data, states, |h, v| h.record_signed((*v).into())),
            Input::I64 => record_rows::<i64>(data, states, |h, v| h.record_signed(*v)),
            Input::I128 => record_rows::<HugeInt>(data, states, |h, v| h.record_wide(huge(v))),
            Input::U8 => record_rows::<u8>(data, states, |h, v| h.record((*v).into())),
            Input::U16 => record_rows::<u16>(data, states, |h, v| h.record((*v).into())),
            Input::U32 => record_rows::<u32>(data, states, |h, v| h.record((*v).into())),
            Input::U64 => record_rows::<u64>(data, states, |h, v| h.record(*v)),
            Input::U128 => {
                record_rows::<UHugeInt>(data, states, |h, v| h.record_wide(unsigned_huge(v)))
            }
            Input::F32 => record_rows::<f32>(data, states, |h, v| h.record_float((*v).into())),
            Input::F64 => record_rows::<f64>(data, states, |h, v| h.record_float(*v)),
            // The integer DuckDB stores a DECIMAL of this width in.
            Input::Decimal(DecimalSignature { width, scale }) => match width {
                0..=4 => record_decimals::<ShortDecimal>(data, states, scale),
                5..=9 => record_decimals::<WordDecimal>(data, states, scale),
                10..=18 => record_decimals::<LongDecimal>(data, states, scale),
                _ => record_decimals::<HugeDecimal>(data, states, scale),
            },
            Input::Null => Ok(()),
        }
    }

    fn combine(
        &self,
        _bind_data: Option<&Input>,
        source: &SourceSlots<'_, '_, HdrHistogram>,
        mut target: Slots<'_, '_, HdrHistogram>,
    ) -> Result<()> {
        for index in 0..target.len() {
            let source = source.get(index)?;
            // Most states of a parallel aggregation are of groups a worker did not see.
            if !source.is_empty() {
                target.get_mut(index)?.merge(source).map_err(kernel_error)?;
            }
        }
        Ok(())
    }

    fn finalize(
        &self,
        _bind_data: Option<&Input>,
        states: &[&HdrHistogram],
        result: Vector<'_, Unknown>,
        result_offset: usize,
    ) -> Result<()> {
        let mut result = result.cast::<BlobValue>()?;
        let mut writer = result.writer()?;
        // One buffer for the chunk: the vector copies what it is given.
        let mut bytes = Vec::new();
        for (index, histogram) in states.iter().enumerate() {
            bytes.clear();
            histogram.serialize_into(&mut bytes).map_err(kernel_error)?;
            writer.set(result_offset + index, &bytes)?;
        }
        Ok(())
    }
}
