# Arrow importer as the row-emission path for `pcapsql-duckdb`: viability and cost

Date: 2026-11-15. Target: DuckDB 2.0.0 (`d54cbbe3df`), `duckdb-neo` 0.20000.2.

Question: instead of writing DuckDB vectors directly, could the table function's `exec` build Arrow
RecordBatches with the DataFusion frontend's builders and hand them to DuckDB through the V2 Arrow
importer (`arrow_importer_append(consume=true)` + `vector_reference`)?

## 1. Verdict

**Viable with caveats, and it is not low-overhead: it is slower than direct writes.**

- It works. A benchmark table function that emits rows this way returned results equal to a
  direct-write function over 300,000 rows of 11 columns (`EXCEPT ALL` in both directions) and in
  13 aggregate queries over 10 million rows. DuckDB's own test suite contains the same pattern.
- It costs about twice the time in the `exec` callback. For an 11-column row shaped like a pcapsql
  protocol table, direct writes took 41 to 51 ns/row in `exec` and the Arrow path 94 to 122 ns/row,
  both including about 14 ns/row of row generation. Whole-query throughput was 17 to 22 M rows/s
  direct against 9 to 10 M rows/s via Arrow when the query only counts values, and 9 to 10 against
  5 to 6 M rows/s when it sums and hashes every value.
- "Zero-copy" is true only for the data buffers of fixed-width columns. It saves one 16 KB `memcpy`
  per column per chunk. The cost of the path is elsewhere: filling Arrow builders value by value
  (the same work as a direct write, into a different buffer), fresh allocations for every batch,
  and per-row conversion on import for strings, blobs, lists and booleans.
- `duckdb-neo` exposes every function needed, but not safely: three `unsafe` constructs are
  required (section 3.4).
- A chunk larger than 2048 rows referenced into the output is a fatal error that invalidates the
  database, so the importer must be created with a batch size of at most 2048.

Recommendation: keep the roadmap's direct column writer (section 5.3 of
`docs/duckdb-v2-extension-roadmap.md`). The Arrow path is a workable stopgap for a spike, since it
is correct, but it is the slower design and it brings the `arrow` crates into the extension. How
much the difference matters next to packet parsing was not measured (section 8).

## 2. Per-type copy table

"Aliased" means the DuckDB vector's data pointer is the Arrow buffer. Source for every row:
[`src/function/table/arrow_conversion.cpp` at v2.0.0](https://github.com/duckdb/duckdb/blob/v2.0.0/src/function/table/arrow_conversion.cpp),
line numbers below. "Run" means the type was exercised in the benchmark and compared against direct
writes; the other rows are from reading the source only.

| Arrow type | DuckDB type | What the importer does | Evidence |
|---|---|---|---|
| UInt8/16/32/64, Int8/16/32/64, Float32/64 | same-width numeric | **Aliased**: `DirectConversion` (434-441) calls `SetVectorData` (85-93), which is `FlatVector::SetData(ptr)` when the pointer is aligned to the value size, and a `memcpy` when it is not | Run for u16, u32, u64; source for the rest |
| Timestamp(ns, no tz) | TIMESTAMP_NS | **Aliased** (`DirectConversion`, case list 917-936); schema mapping `tsn:` in `arrow_duck_schema.cpp` 143-144 | Run |
| Timestamp(us, no tz) | TIMESTAMP | **Aliased** (same case list; `tsu:` at 145-146) | Source |
| Timestamp(us, tz) / Timestamp(ns, tz) | TIMESTAMP_TZ / TIMESTAMP_TZ_NS | **Aliased** for these two units (1093-1095, 1128-1130); other units are converted row by row | Source |
| Boolean | BOOLEAN | **Converted**: bit-unpack loop into one byte per row (894-916) | Run |
| Validity bitmap (any type) | validity mask | **Copied** when `null_count != 0`: `memcpy` of `rows/8` bytes, or a shifted copy when the slice offset is not a multiple of 8 (95-127). Nothing is copied when the array has no nulls | Run (nullable u32, string, list) |
| Utf8 | VARCHAR | **Per-row conversion, payload not copied for long values**: `SetVectorString` (389-402) writes a 16-byte `string_t` per row into a buffer DuckDB allocates. Values of 12 bytes or less are copied inline; longer values store a pointer into the Arrow data buffer plus a 4-byte prefix (`string_type.hpp` 45-66) | Run |
| LargeUtf8 | VARCHAR | Same, with 64-bit offsets (947-954) | Source |
| Utf8View | VARCHAR | Per-row loop (404-432); inline views are copied, long views point into the Arrow variadic buffers; the view buffer is copied first if it is not 16-byte aligned | Source |
| Binary / LargeBinary | BLOB | Same as Utf8 (`z`/`Z` at `arrow_duck_schema.cpp` 181-186) | Run for Binary |
| FixedSizeBinary(n) | **BLOB** (not a fixed-size type) | Per-row `string_t` (969-988). 6-byte MAC addresses are copied inline; 16-byte IPv6 addresses point into the Arrow buffer | Source |
| List\<T\> | LIST | **Offsets converted**: one 16-byte `list_entry_t` per row from the 32-bit offsets (160-186). `ListVector::Reserve` allocates a child buffer (265) that an aliased child then replaces. The child is converted by the rules above: aliased for List\<UInt16\>/List\<UInt32\>, per-element `string_t` for List\<Utf8\>, List\<Binary\>, List\<FixedSizeBinary\> | Run for List\<UInt32\>; source for the rest |
| Dictionary | type of the values | Supported. Values are converted to a DuckDB vector and the indices copied into a selection vector (1483-1565). The importer uses a fresh scan state per chunk, so the dictionary is decoded again for every chunk (`capi_v2_arrow.cpp` 180-182) | Source |

What the DataFusion builders emit (read in `pcapsql-datafusion/src/query/arrow_schema.rs` 19-37 and
`builders/protocol.rs` 17-36): UInt8, UInt16, UInt32, UInt64, Int8, Int32, Int64, Float64, Boolean,
Utf8, Binary, FixedSizeBinary(n), Timestamp(Microsecond, no tz), and List of UInt16, UInt32, Utf8,
Binary or FixedSizeBinary. **Every one of these has a conversion case; none is unsupported.** They
do not emit LargeUtf8, Utf8View or dictionary arrays.

Differences from the roadmap's column plan (section 4.2) that reuse would have to resolve:

- The builders truncate the nanosecond timestamp to microseconds
  (`builders/protocol.rs`, `timestamp_ns / 1_000` in `add_frame_from_raw`), so the column would be
  TIMESTAMP, not TIMESTAMP_NS.
- `encap_depth` is UInt8 in the builders; the roadmap says USMALLINT.
- FixedSizeBinary columns arrive as BLOB. The declared DuckDB column type must match the imported
  type exactly, or `vector_reference` fails (section 3.2).
- The builders are `pub(crate)` parts of `pcapsql-datafusion`, which depends on DataFusion and
  tokio. They would have to move to a crate without those dependencies.

## 3. Mechanics

### 3.1 Ownership and lifetimes (read in source)

- `arrow_importer_append(consume=true)` moves the `ArrowArray` into a
  `shared_ptr<ArrowArrayWrapper>` and clears the caller's `release`
  ([`capi_v2_arrow.cpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/main/capi/v2/capi_v2_arrow.cpp) 398-431).
- `arrow_importer_next_chunk` allocates a new `DataChunk`, converts one slice of the array into it,
  and returns it (433-479, `CV2ConvertArrowSlice` 168-229). Every converted vector buffer gets an
  `ArrowAuxiliaryData` holding the shared pointer (`arrow_conversion.cpp` 1324-1326), so the buffers
  keep the Arrow array alive.
- `vector_reference` is `Vector::Reference`, which shares the source's reference-counted buffer
  (`capi_v2_vector.cpp` 124-138, `vector.cpp` 110-117). After referencing, the imported chunk can be
  destroyed in the same `exec` call, and so can the importer. The Arrow array is released when the
  last vector that references it is reset, which is a later call on DuckDB's side. The spec says the
  same: "the chunks stay valid after the importer is destroyed"
  ([`arrow.yaml`](https://github.com/duckdb/duckdb/blob/v2.0.0/api_spec/v2/arrow/arrow.yaml) 160-180).
- Consequence: each batch's buffers are allocated by arrow-rs and freed through its release callback
  after DuckDB is done. The builders cannot reuse their buffers from one batch to the next.
- The importer keeps a pointer to the client context and "must not outlive it. Within one connection
  the context is the same throughout, so an importer created in a bind callback is usable from the
  matching exec callback" (`arrow.yaml` 89-106; `capi_v2_arrow.cpp` 25-27). An importer "must not be
  used from two threads at once" (`arrow.yaml` 60-61), so it belongs in per-thread local state.

### 3.2 Referencing into the output chunk (verified by running)

- `exec` takes the next imported chunk, references each of its vectors into the output chunk's
  vector at the same position, and drops the imported chunk. The engine reads the row count from the
  first output vector after the callback (`capi_v2_func_table.cpp` 615-622); `Reference` carries the
  source's size over, so no `set_size` call is needed.
- The logical types must be equal, or `vector_reference` returns an input error
  (`capi_v2_vector.cpp` 131-135). The benchmark's Arrow schema imported as
  `UBIGINT, TIMESTAMP_NS, USMALLINT, USMALLINT, UINTEGER, UINTEGER, BOOLEAN, VARCHAR, VARCHAR, BLOB, UINTEGER[]`.
- **Chunk size.** With the importer created without a batch-size limit and an 8192-row batch, the
  first query failed with `INTERNAL Error: Vector::SetSize out of range - trying to set size to 8192
  for vector with capacity 2048`, and every later query on the instance failed with `FATAL Error:
  ... database has been invalidated`. The importer must be created with `batch_size <= 2048`.
- DuckDB's own tests do this from a table function: `arrow_roundtrip_range` in
  [`test/api/capi/v2/test_capi_v2_arrow.cpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/test/api/capi/v2/test_capi_v2_arrow.cpp)
  225-370 creates the importer in bind, and in exec appends with `consume=true, flush=true` (line
  102), references the imported vectors into the output (365-366) and destroys the imported chunk.
  It covers BIGINT and VARCHAR only, single-threaded, 5000 rows (800-810).

### 3.3 Batch size and slicing (read in source; 2048, 3000 and 8192 rows per batch run)

`capi_v2_arrow.cpp` 433-479:

- One array is in flight. `next_chunk` slices it lazily into chunks of at most `batch_size` rows.
  Appending while rows remain is an error (403-406), so `exec` must drain before it appends again.
- A tail shorter than `batch_size` is **copied** into a pending chunk and joined with the head of the
  next array, also by copy, unless the append passed `flush=true`. With `flush=true` the tail comes
  out as a short zero-copy chunk.
- Implication for the builders: produce batches of at most 2048 rows and append each with
  `flush=true` (one batch, one chunk), or produce larger batches, create the importer with
  `batch_size = 2048`, still pass `flush=true`, and return one slice per `exec` call. Batches of
  8192 rows were not faster than batches of 2048 in the benchmark.

### 3.4 What `duckdb-neo` wraps (read in the crate source; used in the benchmark)

`duckdb-neo` covers all of it; raw `libduckdb-sys` calls are not needed. Three places need `unsafe`:

1. **Importer lifetime.** `ArrowImporter<'ctx>` borrows the callback's `&Context` (`src/arrow.rs`
   232-236, 242), and `TableFunctionCallbacks::LocalState` must be `Any + Send`
   (`src/table_function/mod.rs` 784), so an importer cannot be stored in local state as written. The
   benchmark transmuted it to `ArrowImporter<'static>` and wrapped it in a type with
   `unsafe impl Send`, relying on DuckDB's statement that the context is the same for the whole
   connection. That worked. The safe alternative is a new importer in every `exec` call, which costs
   1 to 10 µs per chunk (section 4.3).
2. **`Vector::reference`** is an `unsafe fn` (`src/vector/mod.rs` 500-512).
3. **C Data Interface structs.** `ArrowArray::from_raw` and `ArrowSchema::from_raw` are `unsafe` and
   take the crate's own `ffi::ArrowArray` / `ffi::ArrowSchema`; the arrow-rs `FFI_ArrowArray` and
   `FFI_ArrowSchema` have to be transmuted into them. The crate's own test does the same
   (`src/arrow.rs` 358-362).

Also relevant: `ArrowImporter::new` releases the schema it is given, `append_consumed` is the safe
`consume=true` call (285-296), and `next_chunk` returns an owned `DataChunk<'static>` (314-322).
Imported vectors are read-only (comment at 390).

### 3.5 Projection, filters, multi-file

- **Projection pushdown.** The output chunk holds only the projected columns, in projected order.
  The imported chunk must have exactly those columns, so the batch has to be built for the projected
  schema and the importer created after the projection is known, in `init_local_state` or the first
  `exec`, not in bind as the upstream test does. `ProtocolBatchBuilder::with_schema` takes a schema
  and resolves columns by name, so a projected schema can be passed to it (read, not run).
- **`count(*)`.** DuckDB 2.0.0 reported projection `[0]` for `SELECT count(*)` in the benchmark: the
  scan still asks for column 0, so one column is always built.
- **Filter pushdown.** Independent of the emission path. Accepted filters have to be applied before
  a row is appended to the builders; imported vectors cannot be edited afterwards.
- **Multi-file wrapper.** The wrapper calls the single-file function's `exec` with its own
  intermediate chunk, which it resets before each call and then passes to `FinalizeChunk`
  (`multi_file_function.hpp` 941-958, `table_function_multi_file.cpp` 364-377). Nothing in that path
  looks incompatible with referenced vectors. **Not run.**

## 4. Measurements

### 4.1 Setup

- Benchmark source:
  `/tmp/claude-0/-home-user-pcapsql/63511ecd-5277-5da7-8b86-33469acc1e01/scratchpad/arrow_bench/src/main.rs`
  (scratchpad; copy it somewhere durable if it should be kept). Raw output of the run reported here:
  `/tmp/claude-0/-home-user-pcapsql/63511ecd-5277-5da7-8b86-33469acc1e01/scratchpad/arrow_bench/run_final.log`.
- Machine: KVM guest, 4 vCPUs of an Intel Xeon at 2.10 GHz, 15 GB RAM, Ubuntu 24.04.5, kernel
  6.18.44. rustc 1.97.0, release profile with `opt-level = 3`, thin LTO, one codegen unit.
- `duckdb-neo` 0.20000.2 with default features, `libduckdb-sys` 1.20000.2, `arrow` 57.3.2 with
  `default-features = false, features = ["ffi"]`. DuckDB linked as the prebuilt 2.0.0 shared
  library; the program printed `v2.0.0`, source id `d54cbbe3df`.
- The `buildtime-download` feature could not fetch the library: its pinned URL is on
  `install.duckdb.org`, which the proxy refuses. The same archive name was downloaded from the
  GitHub release and passed in with `DUCKDB_LIB_DIR`. `bundled` was not tried.

```sh
mkdir libduckdb_v200 && cd libduckdb_v200
curl -L -o libs.tar.gz https://github.com/duckdb/duckdb/releases/download/v2.0.0/duckdb-shared-libs-linux-amd64.tar.gz
tar xzf libs.tar.gz        # sha256 of the archive: 993ad89e7dfca66cd6da994c2cad090c2fc160ddf9f550498a098ab4bb13cfb1
cd ../arrow_bench
DUCKDB_LIB_DIR=$PWD/../libduckdb_v200 DUCKDB_DOWNLOAD_LIB=0 cargo build --release
LD_LIBRARY_PATH=$PWD/../libduckdb_v200 ./target/release/arrow_bench 10000000 5            # the run below
LD_LIBRARY_PATH=$PWD/../libduckdb_v200 ./target/release/arrow_bench 300000 1 unbounded    # the >2048-row failure
```

Design:

- Two table functions registered on a connection, both with projection pushdown, `SET threads = 1`.
  Columns: `frame_number` UBIGINT, `ts` TIMESTAMP_NS, `src_port`/`dst_port` USMALLINT, `seq`
  UINTEGER, `ack` UINTEGER (1/7 NULL), `flag` BOOLEAN, `name` VARCHAR (3 to 16 bytes), `host`
  VARCHAR (about 22 bytes, 1/5 NULL), `payload` BLOB (40 bytes), `opts` UINTEGER[] (0 to 3 elements,
  1/11 NULL).
- Both fill the same row buffer from the same generator, 2048 rows at a time. `gen_direct` writes
  the projected columns with `duckdb-neo`'s typed writers. `gen_arrow` appends row by row to one
  arrow-rs builder per projected column (the shape of pcapsql's `DynamicBuilder`), finishes a
  `StructArray`, exports it, appends it with `consume=true, flush=true`, and references the imported
  vectors into the output.
- `gen_arrow` variants: importer cached in local state with 2048-row or 8192-row batches; importer
  created in every `exec`; cached importer with the builders re-created at full capacity after every
  batch.
- 10,000,000 rows per query, 5 repetitions, sources run in a different pseudo-random order in each
  repetition. `gen_direct` is registered twice; the second registration is a control for noise. The
  time spent inside `exec` is accumulated separately from the whole query time.
- "Light" queries only `count()` each column, so nearly all the time is producing the vectors.
  "Heavy" queries sum, measure and hash every value.

### 4.2 Results (verified by running)

Correctness: `gen_direct EXCEPT ALL gen_arrow` and the reverse returned 0 rows over 300,000 rows for
2048-, 3000- and 8192-row batches with a cached importer and for 2048-row batches with an importer
per `exec`. All 13 timed queries returned the same result from every source.

Time inside `exec`, ns per row, fastest of 5 runs. Row generation alone measured 14.3 ns/row
natively in this run and is included in every figure.

| Query (projected columns) | direct | direct, control | Arrow, cached importer, 2048 | Arrow, 8192-row batches | Arrow, importer per exec | Arrow, builders re-reserved |
|---|---|---|---|---|---|---|
| `count(*)` (1 column, u64) | 14.8 | 14.6 | 21.3 | 20.0 | 20.0 | 19.8 |
| 6 fixed-width, light | 21.5 | 20.9 | 41.8 | 35.1 | 38.3 | 35.7 |
| 6 fixed-width, heavy | 18.4 | 21.4 | 38.7 | 35.5 | 43.6 | 44.7 |
| 1 bool, light | 13.9 | 14.3 | 17.7 | 17.9 | 20.0 | 20.2 |
| 2 strings, light | 24.0 | 29.2 | 40.7 | 44.4 | 42.7 | 33.7 |
| 2 strings, heavy | 28.5 | 29.5 | 44.1 | 45.8 | 45.9 | 40.5 |
| 1 blob (40 B), light | 18.3 | 18.9 | 28.8 | 30.0 | 28.1 | 25.9 |
| 1 list\<u32\>, light | 15.2 | 17.3 | 21.4 | 22.1 | 22.3 | 21.1 |
| all 11, light | 40.6 | 50.9 | 95.4 | 105.8 | 95.3 | 93.6 |
| all 11, heavy | 46.5 | 51.1 | 117.9 | 108.4 | 121.8 | 101.4 |

Whole-query throughput, million rows per second, fastest of 5 runs:

| Query | direct | direct, control | Arrow, cached importer, 2048 | Arrow, 8192-row batches | Arrow, importer per exec | Arrow, builders re-reserved |
|---|---|---|---|---|---|---|
| `count(*)` | 66.1 | 66.7 | 46.2 | 49.2 | 49.1 | 49.7 |
| 6 fixed-width, light | 39.9 | 41.6 | 22.7 | 27.2 | 24.9 | 26.6 |
| 6 fixed-width, heavy | 34.8 | 29.9 | 20.1 | 21.7 | 18.1 | 17.3 |
| 2 strings, heavy | 18.0 | 17.4 | 13.8 | 13.5 | 13.4 | 14.7 |
| all 11, light | 21.8 | 17.4 | 9.9 | 8.9 | 9.9 | 10.1 |
| all 11, heavy | 9.6 | 8.7 | 5.2 | 5.7 | 5.2 | 5.9 |

Reading the numbers:

- Noise is large on this shared VM. The two registrations of the same direct function differ by up
  to 10 ns/row (40.6 against 50.9), and median runs were often 5 to 25% slower than the fastest. Differences
  between the four Arrow variants are inside that noise. The direct-against-Arrow gap is not: it is
  present in every query.
- Net of generation, 11 columns cost about 26 to 37 ns/row direct and about 79 to 108 ns/row via
  Arrow.
- Even the best case for zero-copy, six fixed-width columns, is slower via Arrow by 14 to 21 ns/row.

### 4.3 Where the Arrow path's time goes (verified by running)

- Native, no DuckDB, all 11 columns in 2048-row batches: generation 14.3 ns/row; generation plus
  Arrow builders 64.2 ns/row; plus FFI export 68.5 ns/row. So the builders alone cost about 50
  ns/row, more than the whole direct write. Across five runs of this measurement the builder figure
  ranged from 45 to 76 ns/row.
- Re-creating the builders with full capacity after each batch did not help reliably (75.3 ns/row
  natively in this run, and within noise in the queries).
- Fixed cost per chunk, measured with one row per RecordBatch so that per-row work vanishes:

| Columns | Importer cached | Importer created per exec |
|---|---|---|
| 1 (u64) | 1.20 µs per chunk | 2.16 µs per chunk |
| 11 | 9.64 µs per chunk (4.7 ns/row at 2048 rows) | 19.49 µs per chunk (9.5 ns/row at 2048 rows) |

  This covers the export, the importer's fresh `DataChunk` and scan states, `duckdb-neo`'s wrappers
  for the imported chunk, the references, and releasing the previous batch. With small batches it
  understates the allocation cost of full-size buffers.

Not separated by measurement: how the remaining 25 to 50 ns/row splits between import conversion
and allocation. No profiler was available (`perf` is not installed).

## 5. Fixed per-batch work (read in source)

Per batch, on the Rust side: `finish()` on every builder (the builder gives up its buffers, so the
next batch allocates and regrows), a `StructArray`, `to_data()`, and `FFI_ArrowArray::new`, which
allocates the C structs and their private data for the struct and every child.

Per chunk, on the DuckDB side (`capi_v2_arrow.cpp` 168-229):

- a new `DataChunk` initialised with buffers for every column (174), which aliased columns then
  discard;
- one `ArrowArrayScanState` per column (182) and one `ArrowAuxiliaryData` per converted buffer;
- the per-type conversion from section 2.

Per importer, once: `PopulateArrowTableSchema` resolves every column's type and reads the catalog for
extension types (`arrow.cpp` 22-48). Creating the importer per `exec` repeats this plus the schema
export every chunk.

## 6. Dependency and stability cost

- **`arrow` versions in the workspace `Cargo.lock`** (read): `arrow` 57.3.1, required by
  `pcapsql-datafusion` and DataFusion 51, and `arrow` 60.0.0, required by the legacy `duckdb`
  1.20000.0 crate that the current `pcapsql-duckdb` depends on. `duckdb-neo` has no `arrow`
  dependency (only a dev-dependency on `arrow-array` 60), so the rewrite removes the second copy.
  The Arrow path would add one back. The C Data Interface is the boundary, so the version does not
  have to match anything in DuckDB; using 57 would share the DataFusion frontend's copy.
- **Binary size** (measured): a `cdylib` that builds one batch with every builder kind
  `DynamicBuilder` uses and exports it through `arrow::ffi` was 600,096 bytes stripped, against
  279,744 bytes for a `cdylib` without `arrow`, both with `lto = true, codegen-units = 1`. About
  320 KB. The `arrow` facade crate compiles 11 `arrow-*` crates (86 packages in the probe's lock
  file); depending on `arrow-array`, `arrow-schema`, `arrow-buffer` and `arrow-data` directly would
  reduce build time, not measured.
- **API churn** (read; `main` fetched 2026-11-15): the five `arrow_importer_*` functions have the
  same signatures at v2.0.0 and on `main`. The diff of `capi_v2_arrow.cpp` touches only
  `arrow_exporter_create` and `statement_execute_arrow`, whose string parameters changed. `vector_reference`
  is unchanged. The whole V2 API remains unstable.
- **Conversion code churn** (read): `arrow_conversion.cpp` differs between v2.0.0 and `main` in 68
  lines. The changes are fixes for struct and union children under lists, run-end-encoded children
  of arrays, a check that string offsets do not decrease, and removal of an empty-list shortcut in
  the list path. So the shared engine code still gets correctness fixes; the list path pcapsql would
  use is among the places touched.
- **Known issues**: the unauthenticated GitHub search API returned no issues or pull requests for
  `arrow_importer` in `duckdb/duckdb` or `ArrowImporter` in `duckdb/duckdb-rs`. That search is not
  exhaustive.

## 7. The baseline: direct writes in `duckdb-neo` (read in the crate; used in the benchmark)

- `output.get_vector_at_mut::<T>(k)` gives a typed vector; `set_size(n)` or the unsafe
  `set_size_uninit(n)`; `writer()` fetches the data pointer and validity mask once
  (`src/vector/writer.rs` 78-108). `set`, `set_option` and `set_null` are `#[inline(always)]`
  bounds-checked stores (298-331): one store plus a validity-bit test per value, no FFI call.
  `write_slice` copies a whole slice.
- VARCHAR and BLOB: `set(i, &str)` / `set(i, &[u8])` build the 16-byte value in place. Values of 12
  bytes or less are inline with no FFI call. Longer values make one `duckdb_v2_arena_allocate` call
  each and one `memcpy` (`src/bytes.rs` 83-140, `src/arena.rs` 13-15).
- LIST: `set_child_size(total)` once, then `list_writer()` and `set_elements(row, iter)` or
  `set_entry` (`src/vector/list_writer.rs` 100-185).
- TIMESTAMP_NS is `TimestampNsValue(i64)`, BLOB is `BlobValue`, lists are `List<T>`. This answers
  U8 in the roadmap's section 9: all three have typed writers, and the arena is reachable from the
  writer (`VectorWriter::arena`, `src/vector/writer.rs` 637-644).
- One mutable vector borrow at a time, unless `get_vector_array_mut::<N>` is used with a
  compile-time count. The benchmark therefore wrote column by column from a row buffer. A row-wise
  writer over a runtime-sized set of columns would need that array call or its own unsafe wrapper.
- Measured cost in the benchmark: about 2.4 to 3.3 ns per value averaged over the 11-column row
  (26 to 37 ns/row net of generation), with the long-string FFI call included.

## 8. Verified, read, inferred

Verified by running code:

- The Arrow path works from a `duckdb-neo` table function registered on a connection, single thread,
  with projection pushdown, for u64, TIMESTAMP_NS, u16, u32 with NULLs, bool, Utf8 with NULLs,
  Binary, and List\<u32\> with NULLs; results equal to direct writes.
- All timings in section 4, the fatal error for chunks above 2048 rows, the imported DuckDB types,
  the projection `[0]` for `count(*)`, the binary-size probe, and that an importer kept in local
  state across `exec` calls works.

Read in source, not run:

- Conversion behaviour for FixedSizeBinary, Float64, signed integers, microsecond and
  timezone-carrying timestamps, LargeUtf8, Utf8View, dictionaries, and lists of strings, blobs or
  fixed-size binary.
- Ownership through `ArrowAuxiliaryData`, the pending-rows copy path when `flush` is false, the
  multi-file wrapper's intermediate chunk, the v2.0.0-to-`main` differences.

Inferred:

- arrow-rs buffers are aligned well enough that the aliasing branch of `SetVectorData` is always
  taken. This rests on arrow-rs allocating with 64-byte alignment; the unaligned copy path was not
  observed or ruled out by measurement.
- The cost relative to a real scan. Packet parsing in pcapsql costs far more than the benchmark's
  14 ns/row generator, so the 50 to 70 ns/row that the Arrow path adds for 11 columns is a smaller
  share of a real scan than the factor of two seen here. No parse cost was measured, so the size of
  that share is unknown.

Not verified at all:

- Parallel scans: one importer per worker with `threads > 1`, and release of Arrow buffers on a
  different thread from the one that built them.
- The path inside a loadable extension rather than an in-process registration, and under the
  multi-file wrapper.
- Memory behaviour: peak memory and allocator fragmentation from handing every batch's buffers to
  DuckDB.
