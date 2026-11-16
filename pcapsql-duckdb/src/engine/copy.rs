//! `COPY ... TO 'x.pcap' (FORMAT pcap)`: the rows of a query as a classic pcap file.
//!
//! ```sql
//! COPY (SELECT * FROM read_frames('in.pcap') WHERE length > 1000 ORDER BY frame_number)
//!   TO 'out.pcap' (FORMAT pcap);
//! ```
//!
//! The file is written by `pcapsql_core::io::PcapWriter`; what is here is the contract between
//! a query and that writer, and the DuckDB side of it.
//!
//! # Columns
//!
//! A row is a packet. The columns are found by name (in any letter case), not by position,
//! and are the ones the `frames` table has, so `SELECT * FROM read_frames(...)` is a valid
//! input:
//!
//! | Column | Type | |
//! |---|---|---|
//! | `raw_data` | `BLOB` | required: the bytes of the packet |
//! | `timestamp` | a `TIMESTAMP` type | required: when it was captured |
//! | `original_length` | an integer type | optional: the length on the wire. NULL or absent: the length of `raw_data` |
//! | `link_type` | an integer type | optional: the link-layer type. NULL or absent: that of the file |
//!
//! Every other column is ignored (`frame_number` and `length` among them: the captured length
//! of a record is the length of its `raw_data`). A missing required column and a column of
//! these names with another type are errors at bind, before anything is read or written. NULL
//! in a required column is an error that names the row.
//!
//! # Options
//!
//! - `LINKTYPE`: the link-layer type of the file, a number or a name (`ETHERNET`,
//!   `LINUX_SLL`, ...). Without it the file has the link type of its first row, and Ethernet
//!   when that has none. A pcap file has one link type: a row with another one is an error.
//! - `SNAPLEN`: the snapshot length in the header (default 262144). A longer packet is cut to
//!   it and keeps its original length.
//! - `PRECISION`: `'ns'` or `'us'`, the unit of the timestamps in the file. The default is the
//!   unit of the `timestamp` column, so nothing is lost unasked: nanoseconds for
//!   `TIMESTAMP_NS` (what `read_frames` returns), microseconds for the other types. `'us'`
//!   for a nanosecond column drops what is below a microsecond.
//!
//! The file is not compressed, and a name that says it is (`x.pcap.gz`) is refused. DuckDB
//! chooses this format by itself for a file whose name ends in `.pcap` or `.pcap.gz`.
//!
//! # Order and threads
//!
//! DuckDB 2.0.0 runs a copy function of the C API as a sink that is not parallel
//! (`PhysicalCopyToFile` with `parallel = false`): one thread hands it the chunks of the query
//! in the order the query produces them, whatever `threads` is, and cuts a batch per chunk.
//! [`PcapCopy::flush`] writes the rows of a batch in that order, so the file has the rows in
//! the order of the query: that of its `ORDER BY`, and without one whatever order the plan
//! happens to produce. The first row, and the row numbers in error messages, are in that order
//! too. With `PER_THREAD_OUTPUT` or `PARTITION_BY` DuckDB writes several files from several
//! threads; each file has its own [`Output`], and DuckDB never flushes two batches of one
//! file at once.
//!
//! # Failure
//!
//! The statement fails on the first error. What becomes of the file is DuckDB's doing: it
//! removes a file the statement created, and writes over an existing local file by way of a
//! temporary file that it moves into place at the end, so a failed statement leaves an
//! existing file as it was. With `USE_TMP_FILE false`, or on a remote file system, a part of
//! the output may remain.

use std::io::BufWriter;
use std::sync::{Mutex, MutexGuard};

use duckdb_neo::{
    column_data_collection::ColumnDataCollection,
    connection::Context,
    copy_function::{
        CopyToBindInfo, CopyToFunctionCallbacks, CopyToStatistics, CopyToStatisticsCallbacks,
    },
    data_chunk::DataChunkRef,
    error::DuckDBError,
    extension::Extension,
    logical_type::{LogicalType, LogicalTypeID},
    types::{
        BlobValue, TimestampMsValue, TimestampNsValue, TimestampSecValue, TimestampTzValue,
        TimestampValue,
    },
    value::Value,
    vector::VectorReader,
    DuckDBType, Error, Result,
};
use pcapsql_core::io::{
    link_type_from_name, PcapWriteError, PcapWriteOptions, PcapWriter, TimestampPrecision,
    DEFAULT_SNAPLEN,
};

use super::fs::DuckSink;
use super::guard;

/// The name of the format: `(FORMAT pcap)`.
const FORMAT: &str = "pcap";

/// The link type of a file whose rows and options name none.
const LINKTYPE_ETHERNET: u16 = 1;

pub(super) fn register(extension: &Extension) -> Result<()> {
    guard::copy_function(FORMAT, PcapCopy)
        // Of the files DuckDB names itself (`PARTITION_BY`, `PER_THREAD_OUTPUT`).
        .with_fallback_extension(FORMAT)
        .with_statistics()
        .register(extension)
}

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::invalid_input(format!("pcap COPY: {message}"))
}

/// Declares the types a column may have (`$kind`) and a reader of such a column in a chunk
/// (`$reader`), whose values are all read as `i128`.
macro_rules! typed_column {
    (
        $(#[$doc:meta])*
        $kind:ident, $reader:ident {
            $($variant:ident($native:ty): $id:ident => $value:expr),+ $(,)?
        }
    ) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum $kind {
            $($variant),+
        }

        impl $kind {
            fn of(id: LogicalTypeID) -> Option<Self> {
                match id {
                    $(LogicalTypeID::$id => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }

        enum $reader<'a> {
            $($variant(VectorReader<'a, $native>)),+
        }

        impl<'a> $reader<'a> {
            fn new(chunk: &'a DataChunkRef<'_>, (index, kind): (usize, $kind)) -> Result<Self> {
                Ok(match kind {
                    $($kind::$variant => {
                        Self::$variant(chunk.get_vector_at::<$native>(index)?.reader()?)
                    })+
                })
            }

            fn get(&self, row: usize) -> Result<Option<i128>> {
                Ok(match self {
                    $(Self::$variant(reader) => reader.get(row)?.map($value),)+
                })
            }
        }
    };
}

typed_column! {
    /// The type of the `timestamp` column. A value is read as nanoseconds since 1970.
    TimeKind, Times {
        Nanos(TimestampNsValue): TimestampNs => |time| i128::from(time.0),
        Micros(TimestampValue): Timestamp => |time| i128::from(time.0) * 1_000,
        // An instant in UTC, as the others are taken to be.
        MicrosTz(TimestampTzValue): TimestampTz => |time| i128::from(time.0) * 1_000,
        Millis(TimestampMsValue): TimestampMs => |time| i128::from(time.0) * 1_000_000,
        Seconds(TimestampSecValue): TimestampSec => |time| i128::from(time.0) * 1_000_000_000,
    }
}

impl TimeKind {
    /// The unit of a file that keeps what a column of this type holds.
    const fn precision(self) -> TimestampPrecision {
        match self {
            Self::Nanos => TimestampPrecision::Nanos,
            Self::Micros | Self::MicrosTz | Self::Millis | Self::Seconds => {
                TimestampPrecision::Micros
            }
        }
    }
}

typed_column! {
    /// The type of an `original_length` or `link_type` column.
    IntKind, Ints {
        U8(u8): UTinyInt => |value| i128::from(*value),
        U16(u16): USmallInt => |value| i128::from(*value),
        U32(u32): UInteger => |value| i128::from(*value),
        U64(u64): UBigInt => |value| i128::from(*value),
        I8(i8): TinyInt => |value| i128::from(*value),
        I16(i16): SmallInt => |value| i128::from(*value),
        I32(i32): Integer => |value| i128::from(*value),
        I64(i64): BigInt => |value| i128::from(*value),
    }
}

/// What a statement binds: where the columns of a packet are among those of the query, and
/// its options.
#[derive(Debug)]
pub(super) struct Bound {
    raw_data: usize,
    timestamp: (usize, TimeKind),
    original_length: Option<(usize, IntKind)>,
    link_type: Option<(usize, IntKind)>,
    /// The `LINKTYPE` option.
    file_link_type: Option<u16>,
    snaplen: u32,
    precision: TimestampPrecision,
}

/// The index of the column `name` and what `kind` makes of its type.
fn column<K>(
    name: &str,
    index: usize,
    logical_type: &LogicalType,
    kind: impl FnOnce(LogicalTypeID) -> Option<K>,
    expected: &str,
) -> Result<(usize, K)> {
    let kind = kind(logical_type.id()?).ok_or_else(|| {
        invalid(format_args!(
            "the column {name} is {}: it must be {expected}",
            logical_type
                .to_text()
                .unwrap_or_else(|_| "of another type".to_owned())
        ))
    })?;
    Ok((index, kind))
}

fn bind_columns(info: &CopyToBindInfo) -> Result<Bound> {
    const INTEGER: &str = "an integer of at most 64 bits";
    let mut raw_data = None;
    let mut timestamp = None;
    let mut original_length = None;
    let mut link_type = None;
    let mut names = Vec::new();
    // DuckDB has made the names unique, whatever their letter case (`raw_data`, `RAW_DATA_1`).
    for index in 0..info.column_count()? {
        let (name, logical_type) = info.get_column(index)?;
        names.push(name.to_owned());
        let of = &logical_type;
        match name.to_ascii_lowercase().as_str() {
            "raw_data" => {
                let blob = |id| (id == LogicalTypeID::Blob).then_some(());
                raw_data = Some(column(name, index, of, blob, "BLOB")?);
            }
            "timestamp" => {
                timestamp = Some(column(
                    name,
                    index,
                    of,
                    TimeKind::of,
                    "TIMESTAMP_NS, TIMESTAMP, TIMESTAMP_MS, TIMESTAMP_S or TIMESTAMPTZ",
                )?);
            }
            "original_length" => {
                original_length = Some(column(name, index, of, IntKind::of, INTEGER)?);
            }
            "link_type" => link_type = Some(column(name, index, of, IntKind::of, INTEGER)?),
            _ => {}
        }
    }
    let (Some((raw_data, ())), Some(timestamp)) = (raw_data, timestamp) else {
        return Err(invalid(format_args!(
            "the query must have a column raw_data (BLOB, the bytes of a packet) and a column \
             timestamp (TIMESTAMP_NS or another TIMESTAMP type); original_length and link_type \
             (integers) are optional and other columns are ignored. It has: {}. \
             The columns of read_frames() are the ones wanted: \
             COPY (SELECT * FROM read_frames('in.pcap')) TO 'out.pcap' (FORMAT pcap)",
            names.join(", ")
        )));
    };
    Ok(Bound {
        raw_data,
        timestamp,
        original_length,
        link_type,
        file_link_type: None,
        snaplen: DEFAULT_SNAPLEN,
        precision: timestamp.1.precision(),
    })
}

/// The value of the option `name` as text: `1`, `ETHERNET`, `true` for an option without a
/// value.
fn option_text(context: &Context, name: &str, value: &Value) -> Result<String> {
    value
        .cast(context, &String::logical_type(context)?)?
        .get::<String>()?
        .ok_or_else(|| invalid(format_args!("the option {name} is NULL")))
}

fn bind_options(context: &Context, info: &CopyToBindInfo, bound: &mut Bound) -> Result<()> {
    for index in 0..info.option_count()? {
        let (name, value) = info.get_option(index)?;
        let name = name.to_ascii_uppercase();
        let text = option_text(context, &name, &value)?;
        let text = text.trim();
        match name.as_str() {
            "LINKTYPE" => {
                let link_type = match text.parse::<u16>() {
                    Ok(number) => Some(number),
                    Err(_) => link_type_from_name(text),
                };
                bound.file_link_type = Some(link_type.ok_or_else(|| {
                    invalid(format_args!(
                        "LINKTYPE '{text}' is neither a number from 0 to 65535 nor a link type \
                         this extension has a name for (ETHERNET, RAW, LINUX_SLL, LINUX_SLL2, \
                         NETLINK, IEEE802_11_RADIOTAP, ...): give the number of \
                         https://www.tcpdump.org/linktypes.html"
                    ))
                })?);
            }
            "SNAPLEN" => {
                bound.snaplen = text
                    .parse::<u32>()
                    .ok()
                    .filter(|&snaplen| snaplen > 0)
                    .ok_or_else(|| {
                        invalid(format_args!(
                            "SNAPLEN '{text}' is not a number of bytes from 1 to {}",
                            u32::MAX
                        ))
                    })?;
            }
            "PRECISION" => {
                bound.precision = match text.to_ascii_lowercase().as_str() {
                    "ns" | "nanosecond" | "nanoseconds" => TimestampPrecision::Nanos,
                    "us" | "microsecond" | "microseconds" => TimestampPrecision::Micros,
                    _ => {
                        return Err(invalid(format_args!(
                            "PRECISION '{text}' is neither 'ns' (nanoseconds) nor 'us' \
                             (microseconds)"
                        )))
                    }
                };
            }
            _ => {
                return Err(invalid(format_args!(
                    "unknown option {name}: the options of the format are LINKTYPE, SNAPLEN and \
                     PRECISION"
                )))
            }
        }
    }
    Ok(())
}

/// The endings of a file name that say the file is compressed.
const COMPRESSED: [&str; 6] = [".gz", ".zst", ".zstd", ".bz2", ".xz", ".lz4"];

/// DuckDB chooses this format for `x.pcap.gz` too, by the `pcap` in the name, and the file
/// would be a plain pcap file that tools take for a compressed one.
fn refuse_compressed_name(path: &str) -> Result<()> {
    let lower = path.to_ascii_lowercase();
    match COMPRESSED.iter().find(|ending| lower.ends_with(*ending)) {
        Some(ending) => Err(invalid(format_args!(
            "the output is not compressed, and '{path}' says it is: name the file without \
             '{ending}'"
        ))),
        None => Ok(()),
    }
}

/// Where the link type of a file comes from, for the message about a row that has another.
#[derive(Debug, Clone, Copy)]
enum LinkTypeOrigin {
    Option,
    FirstRow,
    Default,
}

impl LinkTypeOrigin {
    const fn text(self) -> &'static str {
        match self {
            Self::Option => "the LINKTYPE option",
            Self::FirstRow => "that of the first row",
            Self::Default => "Ethernet, as the first row has none",
        }
    }
}

type Sink = BufWriter<DuckSink>;

#[derive(Debug)]
enum State {
    /// Open and empty: the header waits for the first row, which may say the link type.
    Created(Sink),
    Writing(PcapWriter<Sink>),
    /// Closed, or given up on after an error.
    Done,
}

/// One output file of a statement.
#[derive(Debug)]
pub(super) struct Output {
    path: String,
    state: State,
    /// The link type of the file, once the header says it.
    link_type: Option<(u16, LinkTypeOrigin)>,
    /// Rows written.
    rows: u64,
    /// Bytes written, once the file is closed.
    bytes: u64,
}

impl Output {
    fn io_error(&self, error: impl std::fmt::Display) -> Error {
        Error {
            code: DuckDBError::IoGeneral,
            message: format!("pcap COPY: cannot write {}: {error}", self.path),
        }
    }

    /// Write the header of the file, for a first row of link type `of_row`, and return the
    /// link type of the file.
    fn start(&mut self, bound: &Bound, of_row: Option<u16>) -> Result<(u16, LinkTypeOrigin)> {
        let State::Created(sink) = std::mem::replace(&mut self.state, State::Done) else {
            return Err(self.io_error("the file is closed"));
        };
        let link_type = match (bound.file_link_type, of_row) {
            (Some(link_type), _) => (link_type, LinkTypeOrigin::Option),
            (None, Some(link_type)) => (link_type, LinkTypeOrigin::FirstRow),
            (None, None) => (LINKTYPE_ETHERNET, LinkTypeOrigin::Default),
        };
        let options = PcapWriteOptions {
            link_type: link_type.0,
            snaplen: bound.snaplen,
            precision: bound.precision,
        };
        let writer = PcapWriter::new(sink, options).map_err(|error| self.io_error(error))?;
        self.state = State::Writing(writer);
        self.link_type = Some(link_type);
        Ok(link_type)
    }

    /// Append the rows of `chunk`.
    fn write_chunk(&mut self, bound: &Bound, chunk: &DataChunkRef<'_>) -> Result<()> {
        let data = chunk.get_vector_at::<BlobValue>(bound.raw_data)?.reader()?;
        let times = Times::new(chunk, bound.timestamp)?;
        let original_lengths = bound
            .original_length
            .map(|column| Ints::new(chunk, column))
            .transpose()?;
        let link_types = bound
            .link_type
            .map(|column| Ints::new(chunk, column))
            .transpose()?;

        for row in 0..chunk.row_count()? {
            // As a person counts them, in the order they are written.
            let number = self.rows + 1;
            let data = data
                .get(row)?
                .ok_or_else(|| invalid(format_args!("row {number} has no raw_data (NULL)")))?;
            let time = times
                .get(row)?
                .ok_or_else(|| invalid(format_args!("row {number} has no timestamp (NULL)")))?;

            let of_row = match &link_types {
                Some(link_types) => link_types.get(row)?,
                None => None,
            }
            .map(|link_type| {
                u16::try_from(link_type).map_err(|_| {
                    invalid(format_args!(
                        "row {number} has the link_type {link_type}, which is not a link type \
                         (0 to 65535)"
                    ))
                })
            })
            .transpose()?;
            let (of_file, origin) = match self.link_type {
                Some(link_type) => link_type,
                None => self.start(bound, of_row)?,
            };
            if let Some(of_row) = of_row.filter(|&of_row| of_row != of_file) {
                return Err(invalid(format_args!(
                    "row {number} has the link type {of_row}, and the link type of the file is \
                     {of_file} ({}). A pcap file has one link type: select the rows of one, or \
                     write a file per link type with (FORMAT pcap, PARTITION_BY (link_type), \
                     WRITE_PARTITION_COLUMNS)",
                    origin.text()
                )));
            }

            let original_length = match &original_lengths {
                Some(original_lengths) => original_lengths.get(row)?,
                None => None,
            };
            let original_length = match original_length {
                Some(length) => u32::try_from(length).map_err(|_| {
                    invalid(format_args!(
                        "row {number} has the original_length {length}, which is not a length \
                         a pcap file can store (0 to {})",
                        u32::MAX
                    ))
                })?,
                None => u32::try_from(data.len()).map_err(|_| {
                    invalid(format_args!(
                        "row {number} has {} bytes of raw_data, more than a pcap file can say",
                        data.len()
                    ))
                })?,
            };

            let State::Writing(writer) = &mut self.state else {
                return Err(self.io_error("the file is closed"));
            };
            let out_of_range = || {
                invalid(format_args!(
                    "row {number} has a timestamp a pcap file cannot store: its range is \
                     1970-01-01 00:00:00 to 2106-02-07 06:28:15 UTC"
                ))
            };
            let time = i64::try_from(time).map_err(|_| out_of_range())?;
            match writer.write_packet(time, original_length, data) {
                Ok(()) => self.rows = number,
                Err(PcapWriteError::TimestampOutOfRange { .. }) => return Err(out_of_range()),
                Err(PcapWriteError::Io(error)) => return Err(self.io_error(error)),
            }
        }
        Ok(())
    }

    /// Write what is buffered and close the file. A file without rows gets its header here.
    fn finish(&mut self, bound: &Bound) -> Result<()> {
        if self.link_type.is_none() {
            self.start(bound, None)?;
        }
        let State::Writing(writer) = std::mem::replace(&mut self.state, State::Done) else {
            return Err(self.io_error("the file is closed"));
        };
        self.bytes = writer.bytes_written();
        writer
            .finish()
            .and_then(|sink| sink.into_inner().map_err(|error| error.into_error()))
            .map_err(|error| self.io_error(error))?
            .close()
            .map_err(|error| self.io_error(error.message))
    }
}

/// The state of an output file, which a panic in another callback may have left half
/// written: that is an error of the statement, not a second panic.
fn lock(output: &Mutex<Output>) -> Result<MutexGuard<'_, Output>> {
    output
        .lock()
        .map_err(|_| invalid("an earlier error left the output file unusable"))
}

/// The copy function `pcap`.
#[derive(Debug)]
pub(super) struct PcapCopy;

impl CopyToFunctionCallbacks for PcapCopy {
    // DuckDB wants it `Sync`. One thread at a time flushes a file, so nothing waits here.
    type InitData = Mutex<Output>;
    type BindData = Bound;
    // Nothing is prepared ahead of the flush: the first row decides the header of the file,
    // and the rows are numbered in the order they are written.
    type BatchData = ();

    fn bind(&self, context: &Context, bind_info: &CopyToBindInfo) -> Result<Bound> {
        refuse_compressed_name(&bind_info.file_path()?)?;
        let mut bound = bind_columns(bind_info)?;
        bind_options(context, bind_info, &mut bound)?;
        Ok(bound)
    }

    fn init(&self, context: &Context, _bound: &Bound, file_path: &str) -> Result<Mutex<Output>> {
        Ok(Mutex::new(Output {
            path: file_path.to_owned(),
            state: State::Created(DuckSink::create(context, file_path)?),
            link_type: None,
            rows: 0,
            bytes: 0,
        }))
    }

    fn batch(
        &self,
        _context: &Context,
        _bound: &Bound,
        _output: &Mutex<Output>,
        _input: &ColumnDataCollection<'_>,
    ) -> Result<()> {
        Ok(())
    }

    fn flush(
        &self,
        context: &Context,
        bound: &Bound,
        output: &Mutex<Output>,
        input: &ColumnDataCollection<'_>,
        _batch: &mut (),
    ) -> Result<()> {
        let mut output = lock(output)?;
        let mut scan = input.to_scan(context)?;
        while let Some(chunk) = scan.next_chunk()? {
            output.write_chunk(bound, &chunk)?;
        }
        Ok(())
    }

    fn finalize(&self, _context: &Context, bound: &Bound, output: &Mutex<Output>) -> Result<()> {
        lock(output)?.finish(bound)
    }
}

impl CopyToStatisticsCallbacks for PcapCopy {
    /// For `RETURN_STATS`, after [`finalize`](CopyToFunctionCallbacks::finalize).
    fn statistics(
        &self,
        _context: &Context,
        _bound: &Bound,
        output: &Mutex<Output>,
    ) -> Result<CopyToStatistics> {
        let output = lock(output)?;
        Ok(CopyToStatistics {
            row_count: usize::try_from(output.rows).ok(),
            file_size: usize::try_from(output.bytes).ok(),
        })
    }
}
