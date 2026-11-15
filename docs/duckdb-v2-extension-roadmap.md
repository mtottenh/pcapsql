# Design and roadmap: `pcapsql-duckdb` on the DuckDB C API v2

Status: adopted 2026-11-15; implementation in progress (section 8 tracks it).

Companion documents:

- [`shared-scan-layer-design.md`](shared-scan-layer-design.md): the design of
  `pcapsql_core::scan`, the scan layer both frontends use. Step ids `S0` to
  `S7` below refer to its migration plan.
- [`reports/DuckDB V2 C API for pcapsql.md`](../reports/DuckDB%20V2%20C%20API%20for%20pcapsql.md)
  and `research_notes/DuckDB V2 C API for pcapsql/`: background research,
  including the Arrow importer benchmark.

The `duckdb-neo` API names used below were checked against the published
source of `duckdb-neo` 0.20000.2. Engine behaviour the design depends on is
listed in [section 10](#10-things-to-verify-in-the-p0-spike) with its
verification status.

## 1. Goals and non-goals

Goals, in priority order:

1. A loadable extension that loads in the current DuckDB release (2.0.0 today),
   is built and load-tested in CI, and returns correct results.
2. All file I/O through DuckDB's file system, so local paths, `s3://`,
   `https://` and any other registered file system work, and
   `enable_external_access` / `allowed_directories` are honoured.
3. Use what V2 offers a reader: projection pushdown, parallel scans with
   per-thread state, multi-file reading (globs, lists, `filename`), filter
   pushdown on frame number and timestamp, progress, `FROM 'x.pcap'`.
4. No scan logic in the extension. Tables, coercion, routing, predicates and
   partitioning come from `pcapsql_core::scan`, shared with the DataFusion
   frontend; the extension is engine glue only, so V2 API churn before
   stabilisation touches few files.
5. Distribution through DuckDB community extensions.

Non-goals for this roadmap:

- Supporting DuckDB 1.x. V2 does not exist there and an extension cannot
  target V1 and V2 at once.
- One binary across DuckDB versions. Until V2 has a stable band, each DuckDB
  release needs its own build (section 9).
- Stream-level tables (`tcp_connections`, `tls_sessions`, `http_messages`,
  `http2`) and TLS decryption in the reader phases. They are backlog (P8);
  the shared layer already covers their design (S4c).

## 2. Decisions

| # | Decision | Reason |
|---|---|---|
| D1 | Target V2 directly through `duckdb-neo`; no intermediate V1 build | Maintainer decision. No released users to break; V2 is where the reader features are |
| D2 | One scan layer, `pcapsql_core::scan`, used by both frontends | The DuckDB crate's failure mode is drift from DataFusion; sharing makes semantics equal by construction |
| D3 | The extension writes DuckDB vectors directly (`ChunkWriter: RowSink`). The Arrow importer is not used | Measured at about half the throughput of direct writes (9 to 10 against 17 to 22 M rows/s for an 11-column table), zero-copy only for fixed-width buffers, needs `unsafe` anyway, and batches above 2,048 rows invalidate the database. See `research_notes/.../arrow_importer_viability.md` |
| D4 | Column names and types come from the shared catalogue, i.e. the DataFusion tables | IPv4 is UINTEGER, IPv6 and MAC are fixed-length BLOB, names are unprefixed, `encap_depth` is UTINYINT. The existing scalars (`ip4_to_string(UINTEGER)`, `ip_in_cidr`) already assume this typing |
| D5 | `timestamp` is a column of every scan table in DuckDB. DataFusion's protocol tables are unchanged | DuckDB cannot fuse a join against `frames`, so without the column a time-aware query scans the capture twice. With projection pushdown an unselected column costs nothing. DataFusion already serves this through the `*_packets` views and frame-join fusion, and adding a column there would change `SELECT *` for released users. The catalogue carries the column with `default = false`; each engine decides whether to expose it |
| D6 | DuckDB timestamps are TIMESTAMP_NS; DataFusion stays on microseconds | Core has nanoseconds; the old extension truncated them. Unit is a per-plan setting (`ScanPlan::timestamps`) |
| D7 | Coercion change: a value of the wrong length for a fixed-size binary column becomes NULL, and so does a wrong-length item of a fixed-size binary list | Today the Arrow append error is discarded: for a column the batch then fails later with a length mismatch, and for a list the item silently disappears, shortening the list. One malformed field should not fail a query or shift a list |
| D8 | Coercion change: an unsigned 64-bit value above `i64::MAX` written to a timestamp column becomes NULL | Today it wraps to a negative timestamp. This matches the rule the builders already apply to integer narrowing: out of range is NULL, never wrapped |

| D9 | The extension does its own multi-file handling; DuckDB's multi-file wrapper is not used in 2.0.0 | The P0 spike showed the wrapper does not forward named parameters to the wrapped function (so `protocol :=` and `strict :=` would be lost) and never calls its `pushdown_filter` (so frame and time pushdown would be lost). Both matter more than `hive_partitioning` and `union_by_name` |
| D10 | The DuckDB crates stay on edition 2021 with `rust-version = "1.88"` | `duckdb-neo` does not require edition 2024 of its dependents |

D7 and D8 change DataFusion output in corner cases only. They land in S4a
with a regression test each and a CHANGELOG entry. The S0 coercion snapshot
(`pcapsql-datafusion/src/query/builders/coercion.snap`) records today's
behaviour for every column type and value kind; at S4a its diff must be
exactly the lines D7 and D8 describe (the `(no value appended)` cells, the
shortened fixed-size binary lists, and `Timestamp(us) <- UInt64(MAX)`).

## 3. Constraints that shape the design

| Constraint | Consequence |
|---|---|
| Every V2 function is unstable; a binary loads only in the exact DuckDB build it targets | Pin `duckdb-neo` with `=`; rebuild and re-release per DuckDB release; stamp `C_STRUCT_UNSTABLE` |
| `main` already changed V2 string parameters and added functions after the 2.0.0 tag | Confine `duckdb-neo` usage to `engine/`; budget an upgrade pass per release |
| Filter-pushdown and expression API is expected to change before stabilisation | Translate expressions to `pcapsql_core::scan::FramePredicate` in one file; the scan never sees `Expression` |
| A panic in a `duckdb-neo` callback becomes an INTERNAL error that invalidates the database | Wrap our callback bodies in `catch_unwind` and return an ordinary error; build with `panic = "unwind"` |
| `Context` and `FileSystem<'link>` are callback-scoped; `File` is `Send`, not `Sync`, and may outlive the callback | Never store a `Context` or `FileSystem`; each worker opens its own `File` and keeps it in local state |
| `build-extension` and `build-extension-static` are mutually exclusive features | The loadable crate and the in-process test crate cannot be built in one `cargo` invocation (section 4) |
| `duckdb-neo` needs Rust 1.88, edition 2024 | The DuckDB crates set their own `rust-version`; the workspace stays on edition 2021 |
| Neither C API decompresses | Keep core's `DecompressReader` (gzip, zstd); compressed files are read sequentially |
| The scan layer is shared with the released DataFusion CLI | Every change to it runs the DataFusion suite, golden corpus and scan benchmark |

## 4. Crate layout

```
pcapsql-core/src/
  io/        + Pause, process_packets_flow, ReadPacketReader<R>, StreamHeader::probe
  format/    + UDF kernels shared by both engines
  scan/      catalogue, plan, predicates, sink trait, coercion, routing, driver, partitioning

pcapsql-duckdb/
  Cargo.toml              # rlib "pcapsql_duckdb": engine glue, no extension feature chosen here
  src/
    lib.rs                # pub fn register(ext_or_conn) -> Result<()>
    engine/               # the only code that imports duckdb_neo
      table.rs            # TableFunctionCallbacks impls, builder wiring
      types.rs            # ColKind -> DuckDB logical type
      writer.rs           # ChunkWriter: RowSink over a DataChunkRef
      fs.rs               # DuckFile: Read adapter over duckdb_neo::file::File
      pushdown.rs         # Expression -> FramePredicate
      scalar.rs, macros.rs, replacement.rs, options.rs, registry.rs
      guard.rs            # catch_unwind + error conversion for every callback
  ext/                    # cdylib "pcapsql": entrypoint only, feature build-extension
  ext-wasm/               # staticlib, added in P7
  itest/                  # in-process tests: build-extension-static + linked libduckdb
  test/sql/               # sqllogictest files run against the built artifact
  Makefile                # includes extension-ci-tools c_api_extensions makefiles
```

Notes:

- `ext/` contains only the `#[duckdb_entrypoint_c_api_v2(extension_name =
  "pcapsql", api_version = "v2.0.0")]` function, which calls
  `pcapsql_duckdb::register`.
- `itest/` links DuckDB into a test binary and registers the same entrypoint
  with `register_static_extension`. This gives ordinary `cargo test` coverage
  of bind, scan, chunk writing and scalars. It is excluded from the
  workspace's default members and built in its own CI step, because of the
  mutually exclusive features. It also runs the shared sink conformance suite
  against `ChunkWriter`.
- `scripts/append_metadata.py` and the hand-written Makefile are deleted in
  favour of `extension-ci-tools` (`CAPI_VERSION=2`, `USE_UNSTABLE_C_API=1`,
  `TARGET_DUCKDB_VERSION=v2.0.0`).

## 5. SQL surface

### 5.1 Table functions

| Function | Notes |
|---|---|
| `read_pcap(files, protocol := 'frames', ...)` | Generic entry; schema depends on `protocol` |
| `read_<table>(files, ...)` for every protocol table in the catalogue | Generated from the catalogue at load, not a hand-kept list |
| `pcap_protocols()`, `pcap_schema(protocol)` | Read the same catalogue the scans use |

`files` is a path, a glob, or a list of either (P5). `protocol` moves from
the second positional argument to a named parameter, leaving the files as
the only positional one. This is a breaking change to an extension that has
no releases.

Named parameter common to all scan functions:

| Parameter | Default | Meaning |
|---|---|---|
| `strict` | `false` | `true` turns a truncated capture into an error; default matches core and the CLI (warn and stop) |
| `filename` | `false` | `true` adds a `filename` VARCHAR column (P5) |

Every occurrence of a protocol in a frame is a row, as in DataFusion; the
outermost one is `WHERE encap_depth = 0`. This resolves the old extension's
`read_pcap` / `read_tcp` inconsistency without a parameter.

`hive_partitioning` and `union_by_name` are not offered (D9); every file of
one call has the same schema by construction.

### 5.2 Columns

Columns are the catalogue's (D4), in this order:

| Table | Columns |
|---|---|
| `frames` | `frame_number` UBIGINT, `timestamp` TIMESTAMP_NS, `length` UINTEGER, `original_length` UINTEGER, `link_type` USMALLINT, plus whatever else the catalogue's `frames` table has |
| protocol tables | `frame_number` UBIGINT, `timestamp` TIMESTAMP_NS (D5), the protocol's fields, `encap_depth` UTINYINT, `tunnel_type` VARCHAR, `tunnel_id` UBIGINT |

`frame_number` comes from the reader's position, not an extension-side
counter. Type mapping from `ColKind` is in `engine/types.rs`; lists map to
`LIST`, fixed-size binary to `BLOB`.

### 5.3 Scalars, macros, replacement scan, settings

- The 16 existing scalar functions become vector wrappers over kernels in
  `pcapsql_core::format` (S6), reading inputs through the vector reader API
  so constant and dictionary vectors are handled. DataFusion's UDFs call the
  same kernels.
- The six `format_*` macros are registered with `MacroFunctionBuilder`
  (extension-owned), replacing `CREATE OR REPLACE MACRO` on the load
  connection.
- A replacement scan maps `FROM 'x.pcap'`, `.pcapng`, `.cap` and their `.gz` /
  `.zst` forms to `read_pcap(path)`.
- One setting to start with: `pcapsql_index_cache_dir` (section 6.4).

## 6. Scan architecture

### 6.1 Callback mapping

One generic implementation `PcapScan` of `TableFunctionCallbacks`, registered
once per table with the table name as instance data.

| Callback | Work |
|---|---|
| `bind` | Resolve the table in the catalogue, declare columns, open the file once and `StreamHeader::probe` it (format, link type, compression), record its size, set a cardinality estimate, store `BindData { path, table, header, file_size, predicate: Mutex<FramePredicate> }` |
| `pushdown_filter` | Translate offered filters into `FramePredicate`; accept the ones enforced exactly (6.5) |
| `init_global_state` | Build a `ScanPlan` from the projected columns and `compile` it; `plan_ranges`; create the `PartitionQueue` and progress counters |
| `max_threads` | Number of partitions, capped; 1 for compressed or unindexed sources |
| `init_local_state` | Allocate the worker's scratch state; no file yet |
| `claim_batch` | `PartitionQueue::claim`, open a `File`, wrap it in `ReadPacketReader::at` or `::sequential`, build a `PartitionScan`, store it in local state |
| `exec` | One `PartitionScan::step` into a `ChunkWriter` over the output chunk |
| `partition_data` | Report the partition ordinal as batch index, so output keeps frame order under parallelism |
| `progress` | Bytes consumed across workers divided by total bytes |

### 6.2 File access

`engine::fs::DuckFile` wraps `duckdb_neo::file::File` and implements
`std::io::Read` with an internal buffer (default 1 MiB, larger for remote
paths as reported by `FileSystem::is_remote`). Each reader owns one `File`,
opened inside the callback that needs it from that callback's `Context`.

Core's `PacketSource` cannot be implemented directly, because
`sequential_reader(&self)` has no way to receive a `Context`. The extension
uses `ReadPacketReader<DuckFile>` (S1) instead. No `std::fs` call remains in
`pcapsql-duckdb`; a clippy `disallowed-types` rule enforces it.

### 6.3 Projection, the row writer and chunk boundaries

`init_global_state` maps the projected column indices to
`TableScan::columns`. `ScanPlan::compile` produces the `ParseScope` (the
table's protocol plus its dependency closure, with a field projection) and
the `OutputPlan`. A query that touches only `frame_number`, `timestamp` or
`frames` columns parses no protocol at all.

`ChunkWriter` implements the shared `RowSink`: it fetches each output
vector's data pointer and validity mask once per `exec`, stores typed values
by slot, and allocates strings and blobs from the vector's arena. It never
sees a `FieldValue`; coercion happens once, in core, for both engines.

Chunk boundaries are handled by the shared driver. When the chunk is full in
the middle of a frame that yields several rows, the reader pauses before
that packet and the next `exec` resumes at the first unwritten row. No parsed
rows are kept in local state, a chunk is never overfilled, and there is no
`"batch full"` pseudo-error.

### 6.4 Parallelism and the boundary index

Partitioning uses core's `BoundaryIndex` (a header-only pass that records a
checkpoint every 65,536 frames) and the shared `partition_target` thresholds,
so both engines gate parallelism the same way.

| Source | Behaviour |
|---|---|
| Local, uncompressed | Build the index in `init_global_state` when `partition_target` says the file is large enough; partition; `max_threads` = partitions |
| Remote, uncompressed | Partition only if a cached index exists; otherwise scan sequentially on one thread and, if the cache is enabled, write the index as a by-product |
| Compressed | One partition, one thread |

Index persistence is opt-in through `pcapsql_index_cache_dir`. The cache is
read and written through DuckDB's file system, keyed by path, size and
header hash as core already does, so no file is written next to a capture
without the user asking.

With several files (D9), the partition queue holds every file's partitions
in file order, so `claim_batch` distributes work across and within files and
the batch index keeps the output in file-then-frame order.

### 6.5 Filter pushdown

`engine/pushdown.rs` recognises comparisons and `BETWEEN`-style conjunctions
between `frame_number` or `timestamp` and a constant, and folds them into a
`FramePredicate`. Everything else is left to DuckDB.

The predicate is used in two ways:

- **Trimming.** `plan_ranges` drops partitions wholly outside the ranges
  using index checkpoints; with no index, a `frame_number` upper bound still
  ends the scan early.
- **Exact row filter.** `FramePredicate::accepts` checks each packet before
  parsing, so accepted predicates are enforced exactly, as V2 requires.

Predicates on parsed protocol fields are not accepted in this
roadmap: the shared `RowPredicate` is conservative, and V2 requires accepted
filters to be exact.

### 6.6 Errors, panics, logging

- I/O and format errors return a `duckdb_neo::Error` from the callback. `exec`
  no longer treats errors as end of data.
- A capture that ends mid-record follows core: stop, and emit a warning
  through `Log::log_on_context`. With `strict := true` it is an error.
- `engine/guard.rs` runs every callback body under `catch_unwind` and converts
  a panic into an ordinary error naming the callback.
- `tracing` output is routed to DuckDB's log through the context where one is
  available.

## 7. Changes in `pcapsql-core`

| ID | Change | Step | State before this roadmap |
|---|---|---|---|
| C1 | `ReadPacketReader<R: Read>` (sequential, and at a `PacketRange`), public `StreamHeader::probe`, exported synthetic-header functions | S1 | `GenericPcapReader<R: Read>` already public; the range logic was private to `FilePacketReader` |
| C2 | `PacketReader::process_packets_flow` with `Pause::{After, Before}`; `process_packets` becomes a provided method | S1 | A callback error could stop after a packet, never before one |
| C3 | Index build and (de)serialisation without a `Path` | none | Already there: `build_boundary_index<R: Read>`, `to_bytes` / `from_bytes` |
| C4 | Column-to-field lookup behind one shared `FieldResolver` | S4a | `get_hinted` exists; a fixed slot index is not possible because parsers push fields conditionally |
| C5 | Encapsulation depth available to consumers | none | Already there: `ParseResult::encap_depth` |
| C6 | `pcapsql_core::scan`: catalogue, plan, predicates, sink, coercion, routing, driver, partitioning | S2 to S5, S7 | Lives in `pcapsql-datafusion`, tied to Arrow and DataFusion types |
| C7 | UDF kernels in `pcapsql_core::format` | S6 | Duplicated in both frontends and already diverged |

C6 moves code out of the DataFusion crate; it is not purely additive.

## 8. Roadmap and progress

Each phase ends with the listed exit checks passing in CI. P0 is independent
of P1. P3 to P6 are independent of each other after P2 and can be reordered.

| Phase | State |
|---|---|
| P0 Spike and scaffolding | done: artifact builds and loads in the DuckDB 2.0.0 CLI, 35 in-process tests, CI workflow written (not yet run on GitHub) |
| P1 Core seams and shared scan layer | S0, S1, S2, S3, S6 done; S4a in progress; S5 next. Scan benchmark numbers for S1 onward still to be taken |
| P2 to P9 | not started |

### P0: Spike and scaffolding

- Create the crate layout of section 4 with one real table function
  (`pcap_protocols()`) and one real scalar.
- Adopt `extension-ci-tools`; produce `pcapsql.duckdb_extension` for
  `linux_amd64`; add a CI job that downloads DuckDB 2.0.0 and loads it.
- Stand up `itest/` with a statically registered extension and one query.
- Resolve the items in section 10 and record the answers there.
- Fix the manifest drift: `duckdb-neo = "=0.20000.2"`, remove `duckdb`,
  `libduckdb-sys` and `duckdb-loadable-macros` 0.1. The old `vtab/` and `udf/`
  glue cannot compile against the new dependencies and is removed here; its
  pure helper functions stay until S6 moves them to core.

Exit: CI builds the artifact, `LOAD` succeeds in DuckDB 2.0.0, one `itest`
query passes, section 10 is filled in.

### P1: Core seams and shared scan layer

Steps from `shared-scan-layer-design.md` section 5, in order:

| Step | Content |
|---|---|
| S0 | Scan-level benchmark; coercion snapshot test over the existing Arrow builders |
| S1 | Reader seam (C1, C2) |
| S2 | Catalogue in core; DataFusion schemas derived from it |
| S3 | `ScanPlan`, `RowPredicate`, `FramePredicate` |
| S4a | `RowSink`, coercion, routing for protocol tables and `frames`; `ArrowSink` in DataFusion; D7 and D8 |
| S5 | `PartitionScan` driver, `partition_target`, `PartitionQueue` |
| S6 | UDF kernels in core (independent; any time) |

Exit: DataFusion suite and golden corpus unchanged apart from D7 and D8; scan
benchmark shows no regression against S0; the sink conformance and
pull-equivalence suites pass in core; a core test reads a capture,
sequentially and at a partition offset, through a custom `Read` with no
`std::fs` in the reader path.

### P2: Sequential reader on V2

- `PcapScan` with bind, global and local init, exec; one thread; no pushdown.
- `DuckFile`; all opens through DuckDB's file system.
- `ChunkWriter` passing the sink conformance suite; `engine/types.rs`.
- Error and truncation behaviour of section 6.6; panic guard.
- Catalogue-driven registration; `pcap_protocols`, `pcap_schema`.
- Scalar wrappers over the shared kernels; macros.
- Tests: per-table golden results over `testdata/` in `itest/`, and a
  differential test comparing DuckDB output with the DataFusion CLI for the
  same queries, normalising only the timestamp unit and the D5 column.

Exit: every protocol table matches DataFusion on the corpus; the three defects
inferred by the audit (NULL `answer_ip6s`, over-capacity chunk, silent
truncation) have regression tests.

### P3: Projection pushdown, cardinality, progress

- `with_projection_pushdown(true)`; map projected indices to
  `TableScan::columns` (the `ParseScope` comes from `compile`).
- Cardinality estimate at bind (exact when a cached index gives a frame
  count).
- Progress callback from `ScanStats`.

Exit: a test asserts that a `frame_number`-only query runs no protocol
parser; benchmark shows the expected drop against P2 for narrow projections.

### P4: Parallel scans

- Index build, `plan_ranges`, `PartitionQueue`; `claim_batch`; `max_threads`.
- `partition_data` batch indices for order preservation.
- `pcapsql_index_cache_dir` and cache I/O through DuckDB's file system.

Exit: results identical to the single-threaded scan on the corpus at 1, 2 and
8 threads, including row order without `ORDER BY`; benchmark shows scaling on
a large uncompressed capture.

### P5: Multi-file, replacement scan, remote

- Own multi-file handling (D9): the positional argument accepts a VARCHAR or
  a LIST of VARCHAR; each entry is expanded with `FileSystem::glob` at bind;
  every file is probed; the partition queue spans the files; `filename :=
  true` adds the column.
- Replacement scan targeting our function directly.
- Remote tests: `httpfs` against a local HTTP server and an S3-compatible
  store, reusing the setup of the existing cloud-integration workflow;
  buffer-size tuning for remote reads.

Exit: glob, list, `filename` and `FROM 'x.pcap'` tests pass; an `s3://` capture
is read with credentials supplied only through a DuckDB secret.

### P6: Filter pushdown

- S7 in core (`FramePredicate` in the driver, trimming in `plan_ranges`).
- `engine/pushdown.rs`.

Exit: `EXPLAIN` shows accepted filters removed from the plan for direct
single-file calls; a time-window query on an indexed capture reads only the
overlapping partitions; results equal the unfiltered scan plus a DuckDB
filter.

### P7: Distribution and documentation

- Full platform matrix via `extension-ci-tools` (`linux_amd64`, `linux_arm64`,
  `osx_arm64`, `windows_amd64`); `ext-wasm/` and `wasm_eh` if the dependency
  set allows.
- Community-extensions descriptor (`language: Rust`, `build: cargo`,
  `requires_toolchains: "rust;python3"`).
- README section, function reference, CHANGELOG entry, release workflow.
- Upgrade runbook (section 9) written down and exercised once.

Exit: `INSTALL pcapsql FROM community; LOAD pcapsql;` works on the supported
platforms.

### P8: Backlog after the reader

Not scheduled.

- `read_<proto>_packets(files)`: the DataFusion `*_packets` views as fused
  scans (S4b). One pass, no join; this is also how several protocol tables
  share one parse in DuckDB.
- Stream tables and TLS decryption (S4c, plus a keylog named parameter or
  secret).
- Remaining DataFusion UDFs, as wrappers once their kernels are in core.
- `COPY ... TO 'x.pcap'`.

### P9: Follow V2 to stability

- When a DuckDB release adds them: statistics callback (min/max of
  `timestamp` and `frame_number` from the index) and the `file_row_number`
  virtual column.
- When DuckDB marks table functions and the file system stable: switch the
  stamp from `C_STRUCT_UNSTABLE` to `C_STRUCT`, drop per-release rebuilds, and
  set the minimum DuckDB version.

## 9. Tracking an unstable API

- **Pin.** `duckdb-neo = "=0.20000.x"`. `TARGET_DUCKDB_VERSION` in the
  Makefile and the pin move together in one commit.
- **Canary.** A scheduled CI job builds against `duckdb-rs` `main` and is
  allowed to fail. Its purpose is to show upcoming breakage early.
- **Upgrade runbook per DuckDB release.** Bump the pin and target; fix
  `engine/`; run `itest/` and the sqllogictests; tag; update the community
  descriptor's `ref`.
- **Containment check.** A CI grep fails the build if `duckdb_neo` is
  imported outside `engine/`, `ext/` and `itest/`.
- **Expected cost.** Until stabilisation, users on a new DuckDB release have
  no pcapsql build until we publish one.

## 10. Things to verify in the P0 spike

Answers marked "ran" are backed by a test in `pcapsql-duckdb/itest/tests/` or
by the make targets in `pcapsql-duckdb/Makefile`.

| ID | Question | Answer |
|---|---|---|
| U1 | Does a `C_STRUCT_UNSTABLE` neo extension built with `extension-ci-tools` load in the stock DuckDB 2.0.0 CLI? | Yes (ran: `make release load_test_release`). Without `-unsigned` the load is refused, as expected until the extension is signed by the community repository |
| U2 | Can `itest/` link DuckDB without compiling it from source, and how long does it take? | Yes (ran). `buildtime-download` needs `install.duckdb.org`; instead `scripts/fetch-duckdb.sh` takes the checksum-pinned shared library from the GitHub release. About 40 s from clean on 4 cores; 972 MB of build output |
| U3 | Can `ext/` and `itest/` select different `duckdb-neo` features? | Yes (ran). The library crate has features `loadable` (default) and `static`; `itest/` is excluded from the workspace and uses `static`. The workspace commands CI runs need no DuckDB library |
| U4 | May a `File` opened in `claim_batch` or `init_local_state` be used from later `exec` calls on that worker? | Yes (ran, 1 and 4 threads). `enable_external_access = false` refuses the open |
| U5 | May several chunks share a batch index? | Yes (ran). With indices reported, `SELECT *`, `CREATE TABLE AS`, `INSERT` and `LIMIT` keep batch order on 4 threads. A decreasing index on one worker is an ordinary error; the same index on two workers corrupts order silently or raises INTERNAL. Without `partition_data`, an ordered query scans on one thread |
| U6 | Does the multi-file wrapper pass through our `pushdown_filter`, `claim_batch` and named parameters? | Partly (ran). It claims our batches, honours `max_threads` and forwards the projection; glob, list, directory and `filename` work. It does not forward named parameters and never calls `pushdown_filter`. Hence D9 |
| U7 | Do `s3://` and `https://` opens through `FileSystem` pick up secrets? | Not answered: `httpfs` cannot be installed where `extensions.duckdb.org` is unreachable. Opens of such paths correctly report that `httpfs` is needed. To be tested in CI or on a machine with access (P5) |
| U8 | Which vector writers exist, and are pointers stable for one `exec`? | Ran. Checked writers for UBIGINT, TIMESTAMP_NS, VARCHAR, BLOB, BOOLEAN, UINTEGER, LIST(UINTEGER), LIST(VARCHAR) and NULLs; a raw path (`as_mut_ptr`, `validity_mut`, `arena()`). Data pointers stay put while a chunk is written; growing a LIST child moves the child's. Chunk capacity is 2,048; the row count is the first vector's size; setting it past capacity is not refused and can invalidate the database |
| U9 | Can a replacement scan pass a named parameter? | Yes when it targets our function directly (ran); not through the multi-file wrapper |
| U10 | Does the stack compile for `wasm32-unknown-emscripten`? | Partly: `duckdb-neo` and `libduckdb-sys` type-check; `ring` and `zstd-sys` need `emcc`, which was not installed, so `pcapsql-core` was not checked |
| U11 | Does `pcap_parser` re-deliver a block that was not consumed? | Yes (ran: `pause_before_redelivers_the_same_packet`, for legacy records, EPBs and SPBs) |
| U12 | Is the Arrow importer a better way to emit rows than direct writes? | No (D3) |

## 11. Risks

| Risk | Mitigation |
|---|---|
| V2 breaks at every DuckDB release until stabilised | Section 9; `engine/` containment |
| The shared-layer steps precede P2, and a regression there affects the released DataFusion CLI | Per-step gates: full DataFusion suite, golden corpus, S0 scan benchmark; one step per commit |
| The hot path gets slower behind the sink abstraction | S0 first; generics and `#[inline]` on the per-value path; compare at S4a and S5 |
| Filter-pushdown API is redesigned | Only `pushdown.rs` depends on it; P6 is last of the reader phases and can wait for 2.1 |
| DuckDB's multi-file wrapper cannot carry our named parameters or filter pushdown in 2.0.0 | D9: own multi-file handling; revisit the wrapper when a DuckDB release forwards both |
| A chunk reported larger than its capacity, or one batch index used by two workers, raises INTERNAL and invalidates the database (seen in the spike) | `ChunkWriter` reports `Full` at the chunk's capacity and the shared driver never overfills; batch indices come from one `PartitionQueue` |
| A panic invalidates the user's database | `guard.rs`; fuzz corpus run through `itest/` |
| Index build over a remote file is a full sequential read | Remote files partition only from a cached index (6.4) |
| DuckDB 2.1 changes arrive mid-roadmap | Canary job; finish P2 before chasing new API |
| CI cost of linking DuckDB for `itest/` | U2; fall back to sqllogictests against the CLI only |
