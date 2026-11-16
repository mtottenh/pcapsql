//! Benchmark: emitting rows from a DuckDB V2 table function (duckdb-neo 0.20000.2, DuckDB 2.0.0)
//! by (a) direct vector writes and (b) Arrow RecordBatch -> V2 Arrow importer -> vector_reference.
//!
//! Both functions take the rows from the same generator through the same row buffer, so the
//! difference between them is the materialisation path only.

use std::sync::Arc;
use std::time::Instant;

use arrow::array::{
    Array, ArrayRef, BinaryBuilder, BooleanBuilder, ListBuilder, StringBuilder, StructArray,
    TimestampNanosecondBuilder, UInt16Builder, UInt32Builder, UInt64Builder,
};
use arrow::datatypes::{DataType, Field, Fields, Schema, TimeUnit};
use arrow::ffi::{FFI_ArrowArray, FFI_ArrowSchema};

use duckdb_neo::{
    DuckDBType, Parameters, Result,
    arrow::{ArrowArray, ArrowImporter, ArrowSchema},
    bind_arguments::BindArgument,
    connection::{Connection, Context},
    data_chunk::DataChunkRef,
    environment::{Environment, StorageLocation},
    error::Error,
    signature::{FunctionParameter, SignatureBuilder},
    table_function::{BindFunctionHandle, ExecColumnInfo, InitColumnData, TableFunctionBuilder, TableFunctionCallbacks},
    types::{BlobValue, List, TimestampNsValue},
    vector::Unknown,
};

const VECTOR_SIZE: usize = 2048;

/// Wall time spent inside the exec callbacks of the functions below, to separate producing the
/// vectors from the rest of the query.
static EXEC_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct ExecTimer(Instant);
impl Drop for ExecTimer {
    fn drop(&mut self) {
        EXEC_NS.fetch_add(self.0.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------------------------
// Row generator: shaped like a pcapsql protocol table.
// ---------------------------------------------------------------------------------------------

const C_FRAME: usize = 0; // UBIGINT
const C_TS: usize = 1; // TIMESTAMP_NS
const C_SPORT: usize = 2; // USMALLINT
const C_DPORT: usize = 3; // USMALLINT
const C_SEQ: usize = 4; // UINTEGER
const C_ACK: usize = 5; // UINTEGER, 1/7 NULL
const C_FLAG: usize = 6; // BOOLEAN
const C_NAME: usize = 7; // VARCHAR, 3..16 bytes
const C_HOST: usize = 8; // VARCHAR, ~22 bytes, 1/5 NULL
const C_PAYLOAD: usize = 9; // BLOB, 40 bytes
const C_OPTS: usize = 10; // LIST<UINTEGER>, 0..3 elements, 1/11 NULL
const NCOLS: usize = 11;

const NAMES: [&str; NCOLS] = [
    "frame_number",
    "ts",
    "src_port",
    "dst_port",
    "seq",
    "ack",
    "flag",
    "name",
    "host",
    "payload",
    "opts",
];

const PROTO_NAMES: [&str; 4] = ["tcp", "udp", "icmpv6", "http/1.1-upgrade"];
const NULL_LEN: u8 = 0xff;

#[derive(Clone, Copy)]
struct Row {
    frame: u64,
    ts: i64,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: Option<u32>,
    flag: bool,
    name: u8,
    host_len: u8,
    host: [u8; 32],
    payload: [u8; 40],
    opts_len: u8,
    opts: [u32; 3],
}

impl Row {
    #[inline]
    fn host(&self) -> Option<&str> {
        (self.host_len != NULL_LEN)
            .then(|| unsafe { std::str::from_utf8_unchecked(&self.host[..self.host_len as usize]) })
    }
    #[inline]
    fn opts(&self) -> Option<&[u32]> {
        (self.opts_len != NULL_LEN).then(|| &self.opts[..self.opts_len as usize])
    }
}

#[inline]
fn gen_row(i: u64) -> Row {
    let seq = (i as u32).wrapping_mul(2_654_435_761);
    let mut host = [0u8; 32];
    let host_len = if i % 5 == 4 {
        NULL_LEN
    } else {
        host[..5].copy_from_slice(b"host-");
        let mut n = i % 100_000;
        let mut digits = [0u8; 6];
        let mut d = 0;
        loop {
            digits[d] = b'0' + (n % 10) as u8;
            d += 1;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        let mut pos = 5;
        while d > 0 {
            d -= 1;
            host[pos] = digits[d];
            pos += 1;
        }
        host[pos..pos + 12].copy_from_slice(b".example.com");
        (pos + 12) as u8
    };
    let mut payload = [0u8; 40];
    for (j, chunk) in payload.chunks_exact_mut(8).enumerate() {
        chunk.copy_from_slice(&i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(j as u64).to_le_bytes());
    }
    let opts_len = if i % 11 == 10 { NULL_LEN } else { (i % 4) as u8 };
    Row {
        frame: i + 1,
        ts: 1_700_000_000_000_000_000 + (i as i64) * 1000 + (i % 7) as i64,
        sport: (i.wrapping_mul(7919) % 65536) as u16,
        dport: [80u16, 443, 53, 8080][(i % 4) as usize],
        seq,
        ack: if i % 7 == 3 { None } else { Some(seq ^ 0xdead_beef) },
        flag: i % 3 == 0,
        name: (i % 4) as u8,
        host_len,
        host,
        payload,
        opts_len,
        opts: [seq, seq.wrapping_mul(3), seq.wrapping_mul(5)],
    }
}

/// Fill the row buffer with up to `max` rows starting at `*next`; returns the number of rows.
#[inline(never)]
fn fill_rows(rows: &mut Vec<Row>, next: &mut u64, total: u64, max: usize) -> usize {
    rows.clear();
    let n = ((total - *next) as usize).min(max);
    for i in 0..n as u64 {
        rows.push(gen_row(*next + i));
    }
    *next += n as u64;
    n
}

fn declare_columns(context: &Context, bind: &BindFunctionHandle<'_>) -> Result<()> {
    bind.add_result_column(NAMES[C_FRAME], &u64::logical_type(context)?)?;
    bind.add_result_column(NAMES[C_TS], &TimestampNsValue::logical_type(context)?)?;
    bind.add_result_column(NAMES[C_SPORT], &u16::logical_type(context)?)?;
    bind.add_result_column(NAMES[C_DPORT], &u16::logical_type(context)?)?;
    bind.add_result_column(NAMES[C_SEQ], &u32::logical_type(context)?)?;
    bind.add_result_column(NAMES[C_ACK], &u32::logical_type(context)?)?;
    bind.add_result_column(NAMES[C_FLAG], &bool::logical_type(context)?)?;
    bind.add_result_column(NAMES[C_NAME], &String::logical_type(context)?)?;
    bind.add_result_column(NAMES[C_HOST], &String::logical_type(context)?)?;
    bind.add_result_column(NAMES[C_PAYLOAD], &BlobValue::logical_type(context)?)?;
    bind.add_result_column(NAMES[C_OPTS], &List::<u32>::logical_type(context)?)?;
    Ok(())
}

fn projection(column_data: &InitColumnData<'_>) -> Result<Vec<usize>> {
    let proj: Result<Vec<usize>> = (0..column_data.count()?).map(|k| column_data.get_column_index(k)).collect();
    if std::env::var_os("BENCH_DEBUG").is_some() {
        eprintln!("projection {proj:?}");
    }
    proj
}

fn arg_u64(arguments: &[BindArgument], index: usize) -> Result<u64> {
    arguments[index]
        .value
        .as_ref()
        .and_then(|v| v.get::<i64>().ok().flatten())
        .map(|v| v as u64)
        .ok_or_else(|| Error::invalid_input(format!("argument {index} must be a non-null BIGINT")))
}

// ---------------------------------------------------------------------------------------------
// (a) Direct vector writes
// ---------------------------------------------------------------------------------------------

struct Total(u64);

struct DirectState {
    next: u64,
    rows: Vec<Row>,
    proj: Vec<usize>,
}

struct GenDirect;

impl TableFunctionCallbacks for GenDirect {
    type BindData = Total;
    type LocalState = DirectState;
    type GlobalState = ();

    fn bind(&self, context: &Context, arguments: Vec<BindArgument>, bind: BindFunctionHandle<'_>) -> Result<Total> {
        declare_columns(context, &bind)?;
        Ok(Total(arg_u64(&arguments, 0)?))
    }

    fn init_local_state(
        &self,
        _context: &Context,
        _bind: &Total,
        _global: Option<&()>,
        column_data: InitColumnData<'_>,
    ) -> Result<Option<DirectState>> {
        Ok(Some(DirectState {
            next: 0,
            rows: Vec::with_capacity(VECTOR_SIZE),
            proj: projection(&column_data)?,
        }))
    }

    fn exec(
        &self,
        _context: &Context,
        bind: &Total,
        local: Option<&mut DirectState>,
        _global: Option<&()>,
        mut output: DataChunkRef<'_>,
        _column_info: ExecColumnInfo<'_>,
    ) -> Result<()> {
        let _timer = ExecTimer(Instant::now());
        let st = local.unwrap();
        let n = fill_rows(&mut st.rows, &mut st.next, bind.0, VECTOR_SIZE);
        let rows = &st.rows[..n];
        if st.proj.is_empty() {
            // Not reached in practice: DuckDB 2.0.0 asks for column 0 even for count(*).
            return output.get_vector_at_mut::<Unknown>(0)?.set_size(n);
        }
        macro_rules! fixed {
            ($k:expr, $ty:ty, $get:expr) => {{
                let mut v = output.get_vector_at_mut::<$ty>($k)?;
                // SAFETY: every row is written below.
                unsafe { v.set_size_uninit(n)? };
                let mut w = v.writer()?;
                for (i, r) in rows.iter().enumerate() {
                    w.set(i, &$get(r))?;
                }
            }};
        }
        for (k, &c) in st.proj.iter().enumerate() {
            match c {
                C_FRAME => fixed!(k, u64, |r: &Row| r.frame),
                C_TS => fixed!(k, TimestampNsValue, |r: &Row| TimestampNsValue(r.ts)),
                C_SPORT => fixed!(k, u16, |r: &Row| r.sport),
                C_DPORT => fixed!(k, u16, |r: &Row| r.dport),
                C_SEQ => fixed!(k, u32, |r: &Row| r.seq),
                C_FLAG => fixed!(k, bool, |r: &Row| r.flag),
                C_ACK => {
                    let mut v = output.get_vector_at_mut::<u32>(k)?;
                    unsafe { v.set_size_uninit(n)? };
                    let mut w = v.writer()?;
                    for (i, r) in rows.iter().enumerate() {
                        w.set_option(i, r.ack.as_ref())?;
                    }
                }
                C_NAME => {
                    let mut v = output.get_vector_at_mut::<String>(k)?;
                    unsafe { v.set_size_uninit(n)? };
                    let mut w = v.writer()?;
                    for (i, r) in rows.iter().enumerate() {
                        w.set(i, PROTO_NAMES[r.name as usize])?;
                    }
                }
                C_HOST => {
                    let mut v = output.get_vector_at_mut::<String>(k)?;
                    unsafe { v.set_size_uninit(n)? };
                    let mut w = v.writer()?;
                    for (i, r) in rows.iter().enumerate() {
                        w.set_option(i, r.host())?;
                    }
                }
                C_PAYLOAD => {
                    let mut v = output.get_vector_at_mut::<BlobValue>(k)?;
                    unsafe { v.set_size_uninit(n)? };
                    let mut w = v.writer()?;
                    for (i, r) in rows.iter().enumerate() {
                        w.set(i, &r.payload[..])?;
                    }
                }
                C_OPTS => {
                    let elements: usize = rows.iter().map(|r| r.opts().map_or(0, |o| o.len())).sum();
                    let mut v = output.get_vector_at_mut::<List<u32>>(k)?;
                    v.set_size(n)?;
                    v.set_child_size(elements)?;
                    let mut w = v.list_writer()?;
                    for (i, r) in rows.iter().enumerate() {
                        match r.opts() {
                            Some(o) => w.set_elements(i, o.iter().map(Some))?,
                            None => w.set_null(i)?,
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// (b) Arrow RecordBatch -> V2 Arrow importer -> vector_reference
// ---------------------------------------------------------------------------------------------

/// Same shape as pcapsql-datafusion's `DynamicBuilder`: one arrow-rs builder per column, appended row by row.
enum ColBuilder {
    U64(UInt64Builder),
    Ts(TimestampNanosecondBuilder),
    U16(UInt16Builder),
    U32(UInt32Builder),
    Bool(BooleanBuilder),
    Utf8(StringBuilder),
    Binary(BinaryBuilder),
    ListU32(ListBuilder<UInt32Builder>),
}

fn arrow_type(c: usize) -> DataType {
    match c {
        C_FRAME => DataType::UInt64,
        C_TS => DataType::Timestamp(TimeUnit::Nanosecond, None),
        C_SPORT | C_DPORT => DataType::UInt16,
        C_SEQ | C_ACK => DataType::UInt32,
        C_FLAG => DataType::Boolean,
        C_NAME | C_HOST => DataType::Utf8,
        C_PAYLOAD => DataType::Binary,
        C_OPTS => DataType::List(Arc::new(Field::new("item", DataType::UInt32, true))),
        _ => unreachable!(),
    }
}

fn new_builder(c: usize, cap: usize) -> ColBuilder {
    match c {
        C_FRAME => ColBuilder::U64(UInt64Builder::with_capacity(cap)),
        C_TS => ColBuilder::Ts(TimestampNanosecondBuilder::with_capacity(cap)),
        C_SPORT | C_DPORT => ColBuilder::U16(UInt16Builder::with_capacity(cap)),
        C_SEQ | C_ACK => ColBuilder::U32(UInt32Builder::with_capacity(cap)),
        C_FLAG => ColBuilder::Bool(BooleanBuilder::with_capacity(cap)),
        C_NAME | C_HOST => ColBuilder::Utf8(StringBuilder::with_capacity(cap, cap * 32)),
        C_PAYLOAD => ColBuilder::Binary(BinaryBuilder::with_capacity(cap, cap * 64)),
        C_OPTS => ColBuilder::ListU32(ListBuilder::new(UInt32Builder::with_capacity(cap))),
        _ => unreachable!(),
    }
}

/// Row-wise append, as `ProtocolBatchBuilder::add_parsed_row` does.
#[inline]
fn append_row(proj: &[usize], builders: &mut [ColBuilder], r: &Row) {
    for (&c, b) in proj.iter().zip(builders.iter_mut()) {
        match (c, b) {
            (C_FRAME, ColBuilder::U64(b)) => b.append_value(r.frame),
            (C_TS, ColBuilder::Ts(b)) => b.append_value(r.ts),
            (C_SPORT, ColBuilder::U16(b)) => b.append_value(r.sport),
            (C_DPORT, ColBuilder::U16(b)) => b.append_value(r.dport),
            (C_SEQ, ColBuilder::U32(b)) => b.append_value(r.seq),
            (C_ACK, ColBuilder::U32(b)) => b.append_option(r.ack),
            (C_FLAG, ColBuilder::Bool(b)) => b.append_value(r.flag),
            (C_NAME, ColBuilder::Utf8(b)) => b.append_value(PROTO_NAMES[r.name as usize]),
            (C_HOST, ColBuilder::Utf8(b)) => b.append_option(r.host()),
            (C_PAYLOAD, ColBuilder::Binary(b)) => b.append_value(&r.payload[..]),
            (C_OPTS, ColBuilder::ListU32(b)) => match r.opts() {
                Some(o) => {
                    b.values().append_slice(o);
                    b.append(true);
                }
                None => b.append(false),
            },
            _ => unreachable!(),
        }
    }
}

fn finish(builders: &mut [ColBuilder]) -> Vec<ArrayRef> {
    builders
        .iter_mut()
        .map(|b| -> ArrayRef {
            match b {
                ColBuilder::U64(b) => Arc::new(b.finish()),
                ColBuilder::Ts(b) => Arc::new(b.finish()),
                ColBuilder::U16(b) => Arc::new(b.finish()),
                ColBuilder::U32(b) => Arc::new(b.finish()),
                ColBuilder::Bool(b) => Arc::new(b.finish()),
                ColBuilder::Utf8(b) => Arc::new(b.finish()),
                ColBuilder::Binary(b) => Arc::new(b.finish()),
                ColBuilder::ListU32(b) => Arc::new(b.finish()),
            }
        })
        .collect()
}

struct ArrowBatcher {
    proj: Vec<usize>,
    fields: Fields,
    builders: Vec<ColBuilder>,
    batch_rows: usize,
    /// Re-create the builders with full capacity after every batch instead of letting them regrow.
    reserve: bool,
}

impl ArrowBatcher {
    fn new(proj: Vec<usize>, batch_rows: usize, reserve: bool) -> Self {
        let fields: Fields = proj
            .iter()
            .map(|&c| Field::new(NAMES[c], arrow_type(c), true))
            .collect::<Vec<_>>()
            .into();
        let builders = proj.iter().map(|&c| new_builder(c, batch_rows)).collect();
        Self {
            proj,
            fields,
            builders,
            batch_rows,
            reserve,
        }
    }

    fn schema(&self) -> Schema {
        Schema::new(self.fields.clone())
    }

    /// Build one batch as a struct array (what `RecordBatch` exports through the C Data Interface).
    fn build(&mut self, rows: &[Row]) -> StructArray {
        for r in rows {
            append_row(&self.proj, &mut self.builders, r);
        }
        let columns = finish(&mut self.builders);
        if self.reserve {
            self.builders = self.proj.iter().map(|&c| new_builder(c, self.batch_rows)).collect();
        }
        StructArray::new(self.fields.clone(), columns, None)
    }
}

fn export_schema(schema: &Schema) -> Result<ArrowSchema> {
    let ffi = FFI_ArrowSchema::try_from(schema).map_err(|e| Error::invalid_input(e.to_string()))?;
    // SAFETY: both types are the Arrow C Data Interface `ArrowSchema` struct.
    Ok(unsafe { ArrowSchema::from_raw(std::mem::transmute::<FFI_ArrowSchema, duckdb_neo::ffi::ArrowSchema>(ffi)) })
}

fn export_array(array: &StructArray) -> ArrowArray {
    let ffi = FFI_ArrowArray::new(&array.to_data());
    // SAFETY: both types are the Arrow C Data Interface `ArrowArray` struct.
    unsafe { ArrowArray::from_raw(std::mem::transmute::<FFI_ArrowArray, duckdb_neo::ffi::ArrowArray>(ffi)) }
}

/// An importer kept across exec calls. duckdb-neo ties `ArrowImporter` to the lifetime of the callback's
/// `&Context`; DuckDB's own comment (capi_v2_arrow.cpp) says the context is the same one for the whole
/// connection, so the lifetime is erased here. This is the part duckdb-neo does not express safely.
struct CachedImporter(ArrowImporter<'static>);
// SAFETY: used by one worker at a time through `&mut LocalState`.
unsafe impl Send for CachedImporter {}

fn new_importer<'c>(context: &'c Context, schema: &Schema, limit: Option<usize>) -> Result<ArrowImporter<'c>> {
    ArrowImporter::new(context, export_schema(schema)?, limit)
}

struct ArrowBind {
    total: u64,
    batch_rows: usize,
    /// 0: importer cached in local state; 1: importer created in every exec call; 2: as 0, with the
    /// builders re-reserved after every batch; 3: as 0, but the importer has no chunk-size limit.
    mode: u64,
}

struct ArrowState {
    next: u64,
    rows: Vec<Row>,
    batcher: ArrowBatcher,
    importer: Option<CachedImporter>,
}

struct GenArrow;

fn reference_chunk(output: &mut DataChunkRef<'_>, importer: &mut ArrowImporter<'_>) -> Result<bool> {
    let Some(chunk) = importer.next_chunk()? else {
        return Ok(false);
    };
    for k in 0..chunk.col_count() {
        let source = chunk.get_vector_at::<Unknown>(k)?;
        let target = output.get_vector_at_mut::<Unknown>(k)?;
        // SAFETY: the referenced buffers are reference counted and keep the Arrow array alive; nothing
        // writes to either vector afterwards.
        unsafe { target.reference(source)? };
    }
    Ok(true)
}

impl TableFunctionCallbacks for GenArrow {
    type BindData = ArrowBind;
    type LocalState = ArrowState;
    type GlobalState = ();

    fn bind(&self, context: &Context, arguments: Vec<BindArgument>, bind: BindFunctionHandle<'_>) -> Result<ArrowBind> {
        declare_columns(context, &bind)?;
        let batch_rows = arg_u64(&arguments, 1)? as usize;
        let mode = arg_u64(&arguments, 2)?;
        if mode == 1 && batch_rows > VECTOR_SIZE {
            return Err(Error::invalid_input("mode 1 needs batch_rows <= 2048"));
        }
        Ok(ArrowBind {
            total: arg_u64(&arguments, 0)?,
            batch_rows,
            mode,
        })
    }

    fn init_local_state(
        &self,
        context: &Context,
        bind: &ArrowBind,
        _global: Option<&()>,
        column_data: InitColumnData<'_>,
    ) -> Result<Option<ArrowState>> {
        let batcher = ArrowBatcher::new(projection(&column_data)?, bind.batch_rows, bind.mode == 2);
        let importer = if bind.mode != 1 && !batcher.proj.is_empty() {
            let limit = (bind.mode != 3).then_some(VECTOR_SIZE);
            let importer = new_importer(context, &batcher.schema(), limit)?;
            // SAFETY: see `CachedImporter`.
            Some(CachedImporter(unsafe {
                std::mem::transmute::<ArrowImporter<'_>, ArrowImporter<'static>>(importer)
            }))
        } else {
            None
        };
        Ok(Some(ArrowState {
            next: 0,
            rows: Vec::with_capacity(bind.batch_rows),
            batcher,
            importer,
        }))
    }

    fn exec(
        &self,
        context: &Context,
        bind: &ArrowBind,
        local: Option<&mut ArrowState>,
        _global: Option<&()>,
        mut output: DataChunkRef<'_>,
        _column_info: ExecColumnInfo<'_>,
    ) -> Result<()> {
        let _timer = ExecTimer(Instant::now());
        let st = local.unwrap();
        if st.batcher.proj.is_empty() {
            let n = fill_rows(&mut st.rows, &mut st.next, bind.total, VECTOR_SIZE);
            return output.get_vector_at_mut::<Unknown>(0)?.set_size(n);
        }
        if bind.mode == 1 {
            let n = fill_rows(&mut st.rows, &mut st.next, bind.total, st.batcher.batch_rows);
            if n == 0 {
                return output.get_vector_at_mut::<Unknown>(0)?.set_size(0);
            }
            let batch = st.batcher.build(&st.rows[..n]);
            let mut importer = new_importer(context, &st.batcher.schema(), Some(VECTOR_SIZE))?;
            importer.append_consumed(export_array(&batch), true)?;
            if !reference_chunk(&mut output, &mut importer)? {
                return Err(Error::api_error("importer produced no chunk"));
            }
            return Ok(());
        }
        let importer = &mut st.importer.as_mut().unwrap().0;
        loop {
            if reference_chunk(&mut output, importer)? {
                return Ok(());
            }
            let n = fill_rows(&mut st.rows, &mut st.next, bind.total, st.batcher.batch_rows);
            if n == 0 {
                return output.get_vector_at_mut::<Unknown>(0)?.set_size(0);
            }
            let batch = st.batcher.build(&st.rows[..n]);
            importer.append_consumed(export_array(&batch), true)?;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------------------------

fn query_one(conn: &Connection, sql: &str) -> Result<String> {
    let wrapped = format!("SELECT CAST(row_ AS VARCHAR) FROM ({sql}) AS row_");
    let mut result = conn.query(wrapped.as_str(), Parameters::None)?;
    let chunk = result.next_chunk()?.ok_or_else(|| Error::api_error("no result"))?;
    let out = chunk
        .get_vector_at::<String>(0)?
        .reader()?
        .get(0)?
        .unwrap_or("NULL")
        .to_owned();
    drop(chunk);
    result.drain()?;
    Ok(out)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let n: u64 = args.get(1).map_or(10_000_000, |s| s.parse().unwrap());
    let reps: usize = args.get(2).map_or(5, |s| s.parse().unwrap());

    let env = Environment::new()?;
    let instance = env.open(StorageLocation::InMemory)?;
    let conn = instance.connect()?;
    println!("duckdb library version: {}", query_one(&conn, "SELECT version() AS v, source_id FROM pragma_version()")?);
    conn.execute("SET threads = 1", Parameters::None)?;

    TableFunctionBuilder::new(
        "gen_direct",
        SignatureBuilder::new().param(FunctionParameter::new::<i64>("n")),
        GenDirect,
    )
    .with_projection_pushdown(true)
    .register(&conn)?;
    // The same implementation under a second name: a control for run-to-run noise.
    TableFunctionBuilder::new(
        "gen_direct2",
        SignatureBuilder::new().param(FunctionParameter::new::<i64>("n")),
        GenDirect,
    )
    .with_projection_pushdown(true)
    .register(&conn)?;
    TableFunctionBuilder::new(
        "gen_arrow",
        SignatureBuilder::new()
            .param(FunctionParameter::new::<i64>("n"))
            .param(FunctionParameter::new::<i64>("batch_rows"))
            .param(FunctionParameter::new::<i64>("mode")),
        GenArrow,
    )
    .with_projection_pushdown(true)
    .register(&conn)?;

    // -- native baselines (no DuckDB) --------------------------------------------------------
    {
        let mut rows = Vec::with_capacity(VECTOR_SIZE);
        let mut best = f64::MAX;
        let mut check = 0u64;
        for _ in 0..reps {
            let (mut next, t) = (0u64, Instant::now());
            check = 0;
            while fill_rows(&mut rows, &mut next, n, VECTOR_SIZE) > 0 {
                check = check.wrapping_add(rows.iter().map(|r| r.frame ^ r.seq as u64).sum::<u64>());
                std::hint::black_box(&rows);
            }
            best = best.min(t.elapsed().as_secs_f64());
        }
        println!(
            "native: row generation only {:8.1} M rows/s, {:6.1} ns/row (check {check})",
            n as f64 / best / 1e6,
            best / n as f64 * 1e9
        );
        for (label, reserve, export) in [("arrow build", false, false), ("arrow build, builders re-reserved", true, false), ("arrow build + FFI export", false, true)] {
        let mut batcher = ArrowBatcher::new((0..NCOLS).collect(), VECTOR_SIZE, reserve);
        let mut best = f64::MAX;
        for _ in 0..reps {
            let (mut next, t) = (0u64, Instant::now());
            loop {
                let k = fill_rows(&mut rows, &mut next, n, VECTOR_SIZE);
                if k == 0 {
                    break;
                }
                let batch = batcher.build(&rows[..k]);
                if export {
                    std::hint::black_box(export_array(&batch));
                } else {
                    std::hint::black_box(&batch);
                }
            }
            best = best.min(t.elapsed().as_secs_f64());
        }
        println!(
            "native: generation + {label} (all 11 cols, 2048 rows/batch) {:8.1} M rows/s, {:6.1} ns/row",
            n as f64 / best / 1e6,
            best / n as f64 * 1e9
        );
        }
    }

    // -- correctness ---------------------------------------------------------------------------
    let small = n.min(300_000);
    for (label, arrow) in [
        ("arrow cached importer, 2048-row batches", format!("gen_arrow({small}, 2048, 0)")),
        ("arrow cached importer, 8192-row batches", format!("gen_arrow({small}, 8192, 0)")),
        ("arrow cached importer, 3000-row batches", format!("gen_arrow({small}, 3000, 0)")),
        ("arrow importer per exec, 2048-row batches", format!("gen_arrow({small}, 2048, 1)")),
    ] {
        let a = query_one(
            &conn,
            &format!("SELECT count(*) AS c FROM (SELECT * FROM gen_direct({small}) EXCEPT ALL SELECT * FROM {arrow})"),
        )?;
        let b = query_one(
            &conn,
            &format!("SELECT count(*) AS c FROM (SELECT * FROM {arrow} EXCEPT ALL SELECT * FROM gen_direct({small}))"),
        )?;
        let c = query_one(&conn, &format!("SELECT count(*) AS c FROM {arrow}"))?;
        println!("equality over {small} rows [{label}]: direct-arrow={a} arrow-direct={b} arrow rows={c}");
    }
    println!("sample: {}", query_one(&conn, "SELECT * FROM gen_arrow(11, 2048, 0) OFFSET 10")?);
    println!("types:  {}", query_one(&conn, "SELECT string_agg(column_type, ',') AS t FROM (DESCRIBE SELECT * FROM gen_arrow(1, 2048, 0))")?);

    if args.get(3).map(String::as_str) == Some("unbounded") {
        // Importer without a chunk-size limit: one 8192-row chunk referenced into the 2048-capacity output chunk.
        for sql in [
            format!("SELECT count(*) AS c, sum(frame_number) AS a, sum(length(host)) AS b, sum(len(opts)) AS d FROM gen_arrow({small}, 8192, 3)"),
            format!("SELECT count(*) AS c, sum(frame_number) AS a, sum(length(host)) AS b, sum(len(opts)) AS d FROM gen_direct({small})"),
            format!("SELECT count(*) AS c FROM (SELECT * FROM gen_direct({small}) EXCEPT ALL SELECT * FROM gen_arrow({small}, 8192, 3))"),
            format!("SELECT count(*) AS c FROM (SELECT * FROM gen_arrow({small}, 8192, 3) WHERE ack IS NULL AND host LIKE '%7.example.com' ORDER BY seq LIMIT 5)"),
        ] {
            match query_one(&conn, &sql) {
                Ok(out) => println!("unbounded: {out}   <- {sql}"),
                Err(e) => println!("unbounded: ERROR {}   <- {sql}", e.message),
            }
        }
        return Ok(());
    }

    // -- fixed cost per chunk: one row per RecordBatch, so the per-row work is negligible --------
    {
        let chunks = 200_000u64;
        let all = "count(frame_number) AS a, count(ts) AS b, count(src_port) AS d, count(dst_port) AS e, count(seq) AS f, count(ack) AS g, count(flag) AS h, count(name) AS i, count(host) AS j, count(payload) AS k, count(opts) AS l";
        for (label, select) in [("1 column (u64)", "count(*) AS c"), ("11 columns", all)] {
            for (mode_label, mode) in [("importer cached", 0), ("importer per exec", 1)] {
                let mut best = f64::MAX;
                for _ in 0..reps {
                    EXEC_NS.store(0, std::sync::atomic::Ordering::Relaxed);
                    query_one(&conn, &format!("SELECT {select} FROM gen_arrow({chunks}, 1, {mode})"))?;
                    best = best.min(EXEC_NS.load(std::sync::atomic::Ordering::Relaxed) as f64);
                }
                println!(
                    "fixed cost per chunk, arrow path, {label}, {mode_label}: {:.2} us per exec call ({:.2} ns/row if spread over 2048 rows)",
                    best / chunks as f64 / 1e3,
                    best / chunks as f64 / 2048.0
                );
            }
        }
    }

    // -- timings -------------------------------------------------------------------------------
    // "light" queries only count the values, so the query adds almost nothing on top of producing the
    // vectors; "heavy" queries read every value (sums, lengths, hashes).
    let queries = [
        ("count(*) (the scan still asks for column 0, frame_number u64)", "count(*) AS c"),
        (
            "fixed-width x6, light (u64, ts_ns, 2x u16, 2x u32 one nullable)",
            "count(frame_number) AS a, count(ts) AS b, count(src_port) AS d, count(dst_port) AS e, count(seq) AS f, count(ack) AS g",
        ),
        (
            "fixed-width x6, heavy",
            "count(*) AS c, sum(frame_number) AS a, sum(epoch_ns(ts)) AS b, sum(src_port) AS d, sum(dst_port) AS e, sum(seq) AS f, sum(ack) AS g, count(ack) AS h",
        ),
        ("bool x1, light", "count(flag) AS a"),
        ("bool x1, heavy", "count(*) AS c, count(*) FILTER (WHERE flag) AS a"),
        ("strings x2 (name 3-16 B, host ~22 B), light", "count(name) AS a, count(host) AS b"),
        (
            "strings x2, heavy",
            "count(*) AS c, sum(length(name)) AS a, sum(length(host)) AS b, count(host) AS d, sum(hash(name)) AS e, sum(hash(host)) AS f",
        ),
        ("blob x1 (40 B), light", "count(payload) AS a"),
        ("blob x1, heavy", "count(*) AS c, sum(octet_length(payload)) AS a, sum(hash(payload)) AS b"),
        ("list<u32> x1, light", "count(opts) AS a"),
        ("list<u32> x1, heavy", "count(*) AS c, sum(len(opts)) AS a, count(opts) AS b, sum(hash(opts)) AS d"),
        (
            "all 11 columns, light",
            "count(frame_number) AS a, count(ts) AS b, count(src_port) AS d, count(dst_port) AS e, count(seq) AS f, count(ack) AS g, count(flag) AS h, count(name) AS i, count(host) AS j, count(payload) AS k, count(opts) AS l",
        ),
        (
            "all 11 columns, heavy",
            "count(*) AS c, sum(frame_number) AS a, sum(epoch_ns(ts)) AS b, sum(src_port) AS d, sum(dst_port) AS e, sum(seq) AS f, sum(ack) AS g, count(ack) AS h, count(*) FILTER (WHERE flag) AS i, sum(length(name)) AS j, sum(length(host)) AS k, count(host) AS l, sum(hash(name)) AS m, sum(hash(host)) AS o, sum(octet_length(payload)) AS p, sum(hash(payload)) AS q, sum(len(opts)) AS r, count(opts) AS s, sum(hash(opts)) AS t",
        ),
    ];
    let sources = [
        ("direct", format!("gen_direct({n})")),
        ("direct (2nd registration)", format!("gen_direct2({n})")),
        ("arrow/cached/2048", format!("gen_arrow({n}, 2048, 0)")),
        ("arrow/cached/8192", format!("gen_arrow({n}, 8192, 0)")),
        ("arrow/per-exec/2048", format!("gen_arrow({n}, 2048, 1)")),
        ("arrow/cached+reserve/2048", format!("gen_arrow({n}, 2048, 2)")),
        ("stored table (consume only)", "stored".to_string()),
    ];
    conn.execute(format!("CREATE TEMP TABLE stored AS SELECT * FROM gen_direct({n})").as_str(), Parameters::None)?;
    println!("\nrows per query: {n}, repetitions: {reps} (sources interleaved within each repetition), threads=1");
    println!("columns: M rows/s and whole-query ns/row from the fastest run (median run in brackets); ns/row spent inside the exec callback, fastest (median)");
    let only = args.get(3).and_then(|a| a.strip_prefix("only:"));
    for (label, select) in queries {
        if only.is_some_and(|o| !label.contains(o)) {
            continue;
        }
        println!("\n== {label}");
        let mut times = vec![Vec::new(); sources.len()];
        let mut execs = vec![Vec::new(); sources.len()];
        let mut outs = vec![String::new(); sources.len()];
        for rep in 0..reps {
            // a different pseudo-random order in every repetition, so that no source always runs first or
            // always follows the same other source
            let mut order: Vec<usize> = (0..sources.len()).collect();
            let mut seed = 0x9E37_79B9_7F4A_7C15u64.wrapping_mul(rep as u64 + 1);
            for i in (1..order.len()).rev() {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                order.swap(i, (seed >> 33) as usize % (i + 1));
            }
            for s in order {
                EXEC_NS.store(0, std::sync::atomic::Ordering::Relaxed);
                let t = Instant::now();
                outs[s] = query_one(&conn, &format!("SELECT {select} FROM {}", sources[s].1))?;
                times[s].push(t.elapsed().as_secs_f64());
                execs[s].push(EXEC_NS.load(std::sync::atomic::Ordering::Relaxed) as f64 / 1e9);
            }
        }
        for (s, (name, _)) in sources.iter().enumerate() {
            times[s].sort_by(|a, b| a.partial_cmp(b).unwrap());
            execs[s].sort_by(|a, b| a.partial_cmp(b).unwrap());
            let (best, median) = (times[s][0], times[s][times[s].len() / 2]);
            let (exec_best, exec_median) = (execs[s][0], execs[s][execs[s].len() / 2]);
            let same = if outs[s] == outs[0] { "equal to direct" } else { "MISMATCH" };
            println!(
                "{name:<28} {:8.2} M rows/s | query {:6.1} ns/row (median {:6.1}) | in exec {:6.1} ns/row (median {:6.1}) | result {same}",
                n as f64 / best / 1e6,
                best / n as f64 * 1e9,
                median / n as f64 * 1e9,
                exec_best / n as f64 * 1e9,
                exec_median / n as f64 * 1e9
            );
            if same == "MISMATCH" {
                println!("   got {}\n   ref {}", outs[s], outs[0]);
            }
        }
        println!("   result: {}", outs[0]);
    }
    Ok(())
}
