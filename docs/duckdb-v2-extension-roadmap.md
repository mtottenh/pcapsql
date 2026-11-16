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
      table/              # the scan functions
        mod.rs            # TableFunctionCallbacks impls, builder wiring, the scan's state
        args.rs           # signature, the files argument and its expansion, named parameters
        layout.rs         # the partitions of a file, the row estimate
        reader.rs         # the reader stack of a partition
        report.rs         # log lines, read and truncation errors
      types.rs            # ColKind -> DuckDB logical type
      writer.rs           # ChunkWriter: RowSink over a DataChunkRef
      fs.rs               # DuckFile: Read adapter over duckdb_neo::file::File; DuckSink: Write
      copy.rs             # COPY ... TO (FORMAT pcap): the rows of a query to core's PcapWriter
      pushdown.rs         # Expression -> FramePredicate
      relation.rs         # the tables and views the engine reads, as scan plans
      listing.rs          # pcap_protocols(), pcap_views(), pcap_schema()
      scalar/             # the scalar functions: loops over the kernels of core
      macros.rs, replacement.rs, settings.rs
      guard.rs            # catch_unwind + error conversion for every callback
  ext/                    # cdylib "pcapsql": entrypoint only, feature build-extension
  itest/                  # in-process tests: build-extension-static + linked libduckdb
  test/sql/               # sqllogictest files run against the built artifact
  community/              # descriptor for DuckDB's community-extensions repository (P7)
  scripts/                # DuckDB release download, load test, containment, pin and reference checks, canary
  Makefile                # includes extension-ci-tools c_api_extensions makefiles
```

`ext-wasm/`, a `staticlib` for the WebAssembly platforms, was planned for P7
and is not there: see U10.

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
| `read_<proto>_packets(files, ...)` for every view of `pcapsql_core::scan::views` (P8) | The DataFusion `*_packets` views, each one fused scan: one pass, no join. Generated from the view definitions at load |
| `read_tcp_connections`, `read_tls_sessions`, `read_http_messages`, `read_http2` `(files, ..., keylog := NULL)` (P8) | The stream tables of the catalogue: one partition per file, no filter pushdown. `keylog` (also on `read_pcap`) names a TLS key log; without it the setting `pcapsql_keylog` does |
| `pcap_protocols()`, `pcap_schema(protocol)` | Read the same catalogue the scans use. `pcap_schema` also takes a view |
| `pcap_views()` (P8) | The views: `name`, `description`, `protocol`, `column_count`. Not rows of `pcap_protocols()`, whose result is unchanged |

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

As built, the surface is listed in
[`duckdb-extension-reference.md`](duckdb-extension-reference.md), which is
checked against the artifact. It differs from this section in the settings:
there are five (`pcapsql_parallel_scan`, `pcapsql_parallel_min_file_size`,
`pcapsql_index_stride`, `pcapsql_filter_pushdown`, `pcapsql_keylog`) and no
`pcapsql_index_cache_dir`, because there is no index cache (P4).

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

As built (P4, and section 8.2): there is no index cache and no
`pcapsql_index_cache_dir`, so the index of a capture that is split is built
by a pass over it at the start of every scan. Because that pass is on one
thread, a file of several is split only for its share of the threads (its
share of the bytes of the files that can be split, rounded: files of one size
on as many threads are not split, and a compressed or remote file takes no
share), and with an upper bound on `frame_number` the pass ends at the bound.

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

As built (P6): single comparisons, and conjunctions of them, are accepted.
Two bounds on one column reach the callback as one `BETWEEN` node, combined
by DuckDB's optimizer whether or not the query says `BETWEEN`, and the C API
has no accessor for whether its bounds are inclusive. Such a node is read as
the inclusive range, which holds every row the filter keeps, and folded into
the `FramePredicate` without being accepted: the scan trims and filters by
it, and DuckDB still applies the real filter to the rows. An accessor for the
inclusivity (or the node arriving as two comparisons) would let it be
accepted.

Since then nothing is accepted. An accepted filter is gone from DuckDB's plan
and lives only in the bind data, which DuckDB's `common_subplan` optimizer
does not compare: two scans of one file with different accepted filters in
one statement serialized alike and were merged, and both returned the rows of
one. Every filter now stays in the plan, as a range does; the scan still
filters by all of them, so what is read is the same.

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
| C5 | Encapsulation depth available to consumers | none | Already there: `LayerRef::encap_depth` (`ParseResult::encap_depth` when this was written) |
| C6 | `pcapsql_core::scan`: catalogue, plan, predicates, sink, coercion, routing, driver, partitioning | S2 to S5, S7 | Lives in `pcapsql-datafusion`, tied to Arrow and DataFusion types |
| C7 | UDF kernels in `pcapsql_core::format` | S6 | Duplicated in both frontends and already diverged |

C6 moves code out of the DataFusion crate; it is not purely additive.

## 8. Roadmap and progress

Each phase ends with the listed exit checks passing in CI. P0 is independent
of P1. P3 to P6 are independent of each other after P2 and can be reordered.

| Phase | State |
|---|---|
| P0 Spike and scaffolding | done. The CI workflow is written and has not yet run on GitHub |
| P1 Core seams and shared scan layer | done: S0 to S5, S6 and S7. Scan benchmark, pre-S1 code against S5, three interleaved runs each on an idle machine (thin LTO on both sides): one-shot queries equal or up to 10 percent faster; parse passes within the run-to-run spread, with the plain UDP pass 4 to 7 percent slower at the median and one VXLAN case 10 percent slower against a baseline that itself varied by 19 percent. The pre-allocation was restored later (section 8.1), with the other fixes of the performance review |
| P2 Sequential reader | done: `read_<table>` and `read_pcap`, scalars, macros, `pcap_schema`, `pcap_protocols`. 45 golden-corpus queries match the DataFusion snapshots; every table matches the core driver cell by cell |
| P3 Projection, cardinality, progress | done, the benchmark exit check with it (section 8.2): a row count costs 51 to 88 percent of all columns and one column 49 to 93 percent, on one thread. Since the run the layers under the table are parsed with no field, which lowers the floor (8.2). The cardinality is an estimate from the file size |
| P4 Parallel scans | done for local uncompressed captures, the benchmark exit check with it (section 8.2): a scan that parses a protocol is 1.8 to 2.7 times faster on four threads than on one, and four files 3.2 to 3.7 times. The index is rebuilt per scan (no cache: the file API exposes no modification time to validate one), by a pass on one thread that costs what counting the frames costs; it is what keeps the efficiency at 45 to 68 percent, and a `LIMIT` on a large capture waits for it |
| P5 Multi-file, replacement scan, remote | done except the remote exit check: lists, globs, `filename`, and `FROM 'x.pcap'`, with the partition queue spanning the files. The HTTP test is written and has not run: `make remote_test_release` (`scripts/remote-test.sh`) reads captures through `httpfs` from a local HTTP server that answers Range requests and compares them with the files, and `duckdb.yml` and the `verify` job of `duckdb-dist.yml` run it, failing if `httpfs` cannot be installed. `httpfs` could not be installed where it was written, so there only the server was tested (with curl) and the test takes its skip path; until the first GitHub run no `http://` capture has been read. No `s3://` capture has been read, no secret tried (U7), and remote buffer sizes are untuned |
| P6 Filter pushdown | done, with two limits found on the way. DuckDB 2.0.0 hands two bounds on one column to the scan as a single `BETWEEN` node whose inclusivity the C API does not expose, so a range is used to narrow the read but not accepted: `EXPLAIN` still shows the filter for a time window. And `plan_ranges` keeps the last checkpoint window of an indexed capture unless an upper frame bound excludes it, so a time window never rules out a whole file |
| P7 Distribution and documentation | done as far as it can be without running on GitHub or submitting anything. Workflows for `linux_amd64`, `linux_arm64`, `osx_arm64` and `windows_amd64` (build through `extension-ci-tools`, then a load test of each artifact), release assets on a tag, the community descriptor, the function reference with a check against the artifact, the upgrade runbook with its dry run, and a canary. None of the new workflows has run on GitHub, and the descriptor has not been submitted, so the exit check is open. `windows_amd64` was added after P7, once `pcapsql-core` compiled for Windows (U13); it has not been built on a runner either, and no job loads its artifact. WebAssembly is not built (U10) |
| P8 Backlog | first item done: `read_<proto>_packets(files)` for the 21 `*_packets` views that are a join within one encapsulation level, as fused scans of the shared layer (S4b), with `pcap_views()`. Each equals the DataFusion SQL view of its name (DataFusion test over 23 captures) and the DuckDB join of the `read_<table>` functions (itest over 24 captures, 1 and 4 threads, split and not, pushdown on and off); the 14 golden-corpus queries over these views now match the DataFusion snapshots too (59 compared in all). `packets`, `tunneled_packets`, `ip4_in_ip6` and `ip6_in_ip6` are not fusable shapes and are not offered. A view is 2.4 to 4.8 times faster than its join and needs a twelfth to a forty-fifth of the memory (section 8.2). Second item done: the stream tables (`read_tcp_connections`, `read_tls_sessions`, `read_http_messages`, `read_http2`, and through `read_pcap`) and TLS decryption with a key log (`keylog := 'path'`, or the setting `pcapsql_keylog`). Each equals the shared scan layer cell by cell (itest over 8 captures, one of 5,000 connections) and the 6 golden-corpus queries over stream tables match the DataFusion snapshots (65 compared in all); decryption is tested on a generated TLS 1.3 + HTTP/2 capture only. `COPY ... TO 'x.pcap' (FORMAT pcap)` is done as well (section 8.1), and so are the capture-relative time functions (`pcap_time_range(files)` and the macros `start_time(files)`, `end_time(files)`, `relative_time(ts, files)`; section 8.1) and the `hdr_*` histogram functions (section 8.1), which completes the UDF item: every DataFusion UDF is in the extension except the six date and time helpers that DuckDB has of its own. The other items are not started |
| P9 Follow V2 to stability | not started |

### 8.1 Review follow-ups and what remains

After P7 the code had two reviews, one of architecture and one of
performance. Their work is tracked here because it cuts across the phases.

Done:

| Item | Result |
|---|---|
| Core hygiene | The manifest's accidental Unix-only dependencies (which is what kept Windows from compiling), seven unused dependencies, declared minimum Rust versions, four needless `unsafe impl Send`, the reader loop's parameter lists, `io/index`, `io/cloud` and `io/stdin` split, dead parser code |
| DataFusion structure | `query/mod.rs`, `query/streaming/mod.rs` and `main.rs` split; the test corpus in `pcapsql-testgen`; a `--filter` splice that was wrong or panicked on non-ASCII text |
| A race in the streaming exchange | A queued batch could be returned ahead of one in the channel, so an un-`ORDER`ed streaming query could come out of capture order. Found by a test that failed once in thirty runs |
| Per-packet allocation | The list of a packet's layers is kept by the partition scan: 1 allocation of 7.8 kB per packet became 0 for `frames` and `udp` |
| Parser dispatch | Typed hints and per-parent tables in place of string-keyed candidate scans: a `udp` scan went from 5,338 to 3,919 instructions per packet |
| In-place field storage | The second half of the parser work. Every parser writes its fields through a `FieldSink` into a per-partition `ParseBuf` (one field vector, one layer vector, a `bumpalo` arena for constructed values) and returns a small `Parsed`; `FieldValue` is `Copy` (24 bytes, was 32) and owns nothing; consumers read a `LayerRef`. The 1,000-byte `ParseResult`, its moves, its drops and its `SmallVec` spills are gone. Instructions per packet through `PartitionScan` into a sink that stores nothing (callgrind, bench profile): `udp` 3,930 to 2,529, `tcp` 6,439 to 4,036, `dns` 10,643 to 7,135, `http` 11,436 to 7,959, `frames` 619 to 593. Allocations per packet: `tcp` 1 to 0, `http` 1 to 0, `dns` 9 to 4 (what `simple-dns` allocates for the message; `tests/parse_alloc.rs` holds the scan to exactly that). The scan benchmark (`cargo bench -p pcapsql-datafusion --bench scan`, thin LTO, three interleaved runs of each build on a shared machine, medians for 20,000 packets): the parse passes are 22 to 40 percent faster (`udp/mmap/1` 11.7 → 8.5 ms, `tcp_options/mmap/1` 20.4 → 12.3 ms, `vxlan/mmap/1` 26.6 → 20.1 ms) and the one-shot queries 29 to 39 percent (`count_udp` 8.7 → 5.3 ms), except `with_payload` (7.3 → 6.9 ms, inside the run-to-run spread). No `unsafe`. The standard `Allocator` trait (stable in Rust 1.100) is not used: the minimum Rust version is below it, and so is the extension's CI toolchain |
| Projection below the table | A scan's parse scope projects every protocol it parses to the fields something reads (a table's columns and row predicate, a fused join's columns and filter, stream analysis), so the layers under the queried table carry no field; `ethernet`, `linux_sll`, `sll2`, `vlan`, `ipv4` and `ipv6` have a projected parse as `tcp`, `udp` and `dns` had, and an empty projection is no field for all nine (it was every field). A projection is a bit set over the parser's field list, resolved once per scope: a parser asks about a field by position, not by name. Instructions per packet (as above): a row count of `ethernet` over UDP frames 2,362 to 2,103, of `tcp` 3,154 to 2,240, of `dns` 6,351 to 4,790; one field of `udp` 2,421 to 2,206; 23 of the 24 fields of `tcp` 6,178 to 3,905 (the full parse: 3,827). `tests/projection_equivalence.rs` compares every projected layer of the fuzz corpus and the golden captures with the full parse |
| Arrow sink | Builders start each batch at the size of the last: no reallocation in steady state |
| Typed columns in the Arrow sink | A fixed-width column (booleans, integers, floats, timestamps, fixed-size binary) is a vector of values and a validity bitmap that does not exist until the column's first NULL of a batch; storing a value is a push and touches no bitmap, and the batch's array is built over the vector without a copy (`builders/fixed.rs`). Arrow 57's builders already build their bitmap lazily; what they cost was a call of 39 instructions per value, 55 once the batch had a NULL, not inlined into the row writer. Text, binary and list columns keep Arrow's builders. Instructions per packet through `PartitionScan` into `ArrowSink`s of every column (callgrind, bench profile, `examples/sink_cost.rs`; in brackets the same scan into a sink that stores nothing): `frames`+`ipv4`+`udp` 5,472 to 4,896 (3,441), `udp` 3,376 to 3,246 (2,855), `frames`+`ipv4`+`tcp` 8,168 to 7,163 (4,714), `tcp` 6,089 to 5,530 (4,128), every per-packet table over mixed frames 14,197 to 13,012 (10,259): 4 to 12 percent of the scan, and 25 to 29 percent of what the sink adds (60 to 43 instructions per cell). The scan benchmark (thin LTO, six interleaved runs of each build on a shared, loaded machine, medians for 20,000 packets): the single-partition parse passes are 12 to 18 percent faster (`udp/mmap/1` 8.67 → 7.44 ms, `tcp_options/mmap/1` 12.94 → 10.57 ms, `vxlan/mmap/1` 17.20 → 14.42 ms); the four-partition passes and the one-shot queries are inside the run-to-run spread. Arrays byte for byte those of the builders (a test against them over random rows); no snapshot changed |
| Text kernels | IPv4, IPv6 and MAC text without `fmt`; hex decoded into a buffer the caller keeps. The row writer's IPv6 text and the MAC formatters that were left in `FieldValue`, `dhcp` and `icmpv6` go through them too |
| Scalars | DataFusion UDFs parse a constant argument once; DuckDB's scalar loops are generic over their kernel, and a constant-pattern match is a SIMD compare over the rows of a chunk that are not NULL, a 64-row word of the validity mask at a time (the second of two audited `unsafe` places) |
| Reader | No `BufReader` under the parser's own buffer |
| Benchmarks | A thin-LTO bench profile, so they link on a small machine; the `with_payload` case runs again |
| One set of name tables | The parsers' name columns read the tables of `pcapsql_core::format::names` and keep none of their own, so `icmp.type_name` is `icmp_type_name(type)`; a number without a name carries the number (`Unknown (n)`, `Type n`), which changes column values (CHANGELOG). A lookup returns a `Copy` `Name` and allocates nothing; `protocol/name_columns_tests.rs` checks every name column against its table over every number |
| The DataFusion scan path (S4c) | The stream tables (`tcp_connections`, `tls_sessions`, `http_messages`, `http2`) are outputs of the shared scan layer: `PartitionScan` reassembles the TCP streams while it reads and writes the tables through `RowSink` when the capture ends (`scan/stream.rs`), decrypting TLS with the key log given to `PartitionScan::with_keylog`. DataFusion's Arrow builders (`stream_tables.rs`) and the scan's frame observer are gone; `providers/shared.rs` is six modules; a pass keeps its tables by `OutputId` and takes its parameters as a `PassOptions`. Rows unchanged: no snapshot changed. Instructions per packet through `PartitionScan` into a sink that stores nothing: `frames` 593 to 555, `udp` 2,529 to 2,415, `tcp` 4,036 to 3,922; one iteration of a scan benchmark within 0.3 percent in instructions, and the benchmark's wall-clock medians within its run-to-run spread (design, section 5.1.2) |
| Stream tables and TLS decryption in the extension (P8) | `read_tcp_connections`, `read_tls_sessions`, `read_http_messages`, `read_http2` and `read_pcap(protocol := ...)` of them: a stream output of the shared layer, one partition per file whatever the settings, no filter taken over, `connection_id` per file. A key log (`keylog := 'path'`, else the setting `pcapsql_keylog`) is read through DuckDB's file system at bind and given to `PartitionScan::with_keylog`; no message or log record repeats its content. `http2.connection_id`, always NULL before, is the TCP connection's id in both engines, and `tls_sessions.version` of a TLS 1.3 session read with a key log is no longer `TLS 1.2`. Open: a scan cannot be cancelled while it reads a file (the C API has no way to ask, and an empty chunk does not make DuckDB look); the C API v2 has no secret types, so the key log is a path. TLS 1.2: the next row |
| TLS 1.2 decryption, and HTTP/1.x inside TLS | TLS 1.2 was never decrypted (each side's encrypted `Finished` was skipped, so every later record was checked with a sequence number one too low); neither was any record or HTTP/2 frame that did not end with its segment or record. Fixed, with `is_decrypted` and the TLS 1.3 handshake as stacks batch it. Decrypted HTTP/1.x is in `http_messages`, by ALPN; the `tls` packet table has rows for encrypted records; raw-IP captures (`LINKTYPE_IPV4`, `LINKTYPE_IPV6`) are parsed. Tested with every AEAD suite the decryption has (11 of TLS 1.2, 3 of TLS 1.3) on captures sealed by code that shares nothing with it, on three kept captures in all three frontends, and on Wireshark's `tls12-dsb.pcapng`. Open: CBC and CCM suites (reported, not decrypted), TLS 1.3 0-RTT and `KeyUpdate`, the secrets of a pcapng Decryption Secrets Block (not read), `LINKTYPE_RAW`, responses to `HEAD` |
| Name and address-classification scalars in the extension (P8) | The sixteen `*_name` functions of the command-line tool that the extension lacked (`icmp_type_name`, `icmp_code_name(type, code)`, `dns_class_name`, `dscp_name`, `tls_version_name`, ...) and its eight tests of an address (`is_private_ip`, `is_multicast_ip6`, `mac_is_broadcast`, ...), as loops over the kernels that were already in `pcapsql_core::format`: 40 scalar functions. `engine/scalar.rs` became `engine/scalar/` (`map.rs`, `pattern.rs`, `plain.rs` with the audited `valid`); no `unsafe` added. A `BLOB` of the wrong length is NULL, as for the other functions. Open then, done since: the capture-relative time functions and the `hdr_*` histogram functions (the next two rows) |
| Capture time in the extension (P8) | `pcap_time_range(files, strict := false)`: one row per file with `filename`, `start_time`, `end_time` (`TIMESTAMP_NS`, NULL without frames), `frames`, `duration`, `link_type`, `truncated`, from one pass over the records through core's packet reader (no parser runs; compressed captures too; several files on several threads). The extension keeps no index between statements, so no call is answered without the pass. The DataFusion functions `start_time()`, `end_time()`, `relative_time(ts)` are macros that take the files (`start_time(files)`, `end_time(files)`, `relative_time(ts, files)`, seconds as `DOUBLE`), each a scalar subquery over that function: DuckDB 2.0.0 plans it as one common subplan, so a query with `relative_time` in its projection and its filter reads the files once for the range (an itest counts the scans in the plan). No name clashes with a DuckDB 2.0.0 function. The golden-corpus queries of the time functions now match the DataFusion snapshots (67 compared in all). Different from DataFusion: nanoseconds, and NULL for a capture without frames where DataFusion answers the epoch. Open: a filter on `relative_time` is not pushed into the scan; the range is read again by every statement |
| Histograms in the extension (P8) | The aggregate `hdr_histogram(value)` and the scalars `hdr_count`, `hdr_min`, `hdr_max`, `hdr_mean`, `hdr_stdev`, `hdr_percentile`, `hdr_buckets`, `hdr_ascii`: 48 scalar functions and 1 aggregate function. The kernels moved from the DataFusion crate to `pcapsql_core::format::histogram` (core feature `histogram`, off by default: `hdrhistogram` 7.6 needs Rust 1.88, core 1.87); DataFusion's UDFs are wrappers of them, their tests unchanged. Both engines are tested against the kernels (synthetic columns of every number type, 25 real captures on 1 and 4 threads) and against each other (5 golden-corpus queries, one the serialized histogram byte for byte; 72 compared in all). `engine/aggregate.rs` is the aggregate, one function with an `ANY` parameter (DuckDB 2.0.0 cannot add a second aggregate of a name through the C API), `engine/guard.rs` guards aggregate callbacks, `init` included (`duckdb-neo` aborts on a panic there; the guard keeps each state in a slot that can hold the panic instead), `engine/nested.rs` writes `LIST(STRUCT)` vectors through `duckdb-neo`'s checked writers; no `unsafe` added. `check-reference.sh` now counts scalar, aggregate and macro functions against the reference. Different from DataFusion: one argument (its extra ones are ignored there), a non-number is a bind error, `DECIMAL` and `HUGEINT` are recorded. Bytes of a histogram combined from partial states can differ in one header field (HdrHistogram stores the highest value it has room for, which depends on the merges); answers do not. Open: DuckDB 2.0.0 does not destroy the states of groups a grouped aggregation never returns (`LIMIT` without `ORDER BY`, a failure while groups are combined or returned), so those histograms are not freed (pinned by an itest; a pool owned by the bind data would avoid it); the six date and time helpers are DuckDB's own functions, listed in the reference |
| `COPY ... TO 'x.pcap' (FORMAT pcap)` in the extension (P8) | The rows of a query as a classic pcap file. The writer is `pcapsql_core::io::PcapWriter` (new: any `io::Write`, little-endian, microsecond or nanosecond magic, one link type, cut at the snapshot length); `engine/copy.rs` is the contract and the DuckDB side, `engine/fs.rs` has the `Write` over DuckDB's file system (`DuckSink`), `guard::copy_function` the panic guard. Columns by name (`raw_data` and `timestamp` required, `original_length` and `link_type` optional, the rest ignored); options `LINKTYPE`, `SNAPLEN`, `PRECISION`, whose default is the unit of the `timestamp` column, so a copy of `read_frames` is a nanosecond file. A row of another link type, NULL bytes or timestamp and a timestamp outside 1970 to 2106 fail the statement and name the row. Round trip tested over the 25 captures of the fuzzing corpus and generated ones; a whole little-endian microsecond capture copies byte for byte with `PRECISION 'us'` and its own snapshot length. What DuckDB 2.0.0 does with it: the C API sets no execution mode, so the copy is a `PhysicalCopyToFile` whose sink is not parallel: one thread, chunks in the order of the query, a batch per chunk, no temporary file on a remote path; `duckdb_functions()` lists no copy functions, so `check-reference.sh` probes the format for its options. Open: pcapng output (several link types, comments), compressed output (a name ending in `.gz` is refused), `FILE_SIZE_BYTES` (DuckDB refuses it for a C API format), and no remote path has been written |

Remaining, in the order intended:

1. Done: the scan-layer polish in core and the DuckDB engine clean-up
   (`thiserror` plan errors, the frame-predicate algebra in core, table
   descriptions in the catalogue, `scan::testing` behind a feature,
   `engine/table/` split).
2. Done: the DataFusion scan path, in the table above.
3. Done: typed columns in the Arrow sink, in the table above.
4. Done: a benchmark run of the whole (P3 projection, P4 scaling, a view
   against its join, and the rest of the extension), in section 8.2, with
   four costs it found removed. What it shows to do next is an index that
   does not cost a pass over the capture before every split scan.
5. Done: the UDFs of P8, in the table above (the capture-relative time
   functions and the `hdr_*` histogram functions were the last). The six
   date and time helpers (`strftime`, `datetime`, `date`, `time`, `epoch`,
   `epoch_ms`) are not registered: DuckDB's `strftime`, casts to `DATE` and
   `TIME`, `epoch` and `epoch_ms` do the same, and the reference lists the
   spelling of each.
6. The S3 half of the P5 remote test, once the HTTP half has run.

Decisions taken:

- A constant-pattern match over a chunk with NULLs is a SIMD compare over
  the rows that are not NULL (done, in the table above).
- The CLI's entry points stay public items of the `pcapsql-datafusion`
  library (`cli::run_repl` and others).
- A strict partitioned scan checks the capture's tail up front, so `strict`
  with `LIMIT` differs between a split and an unsplit scan. Kept, and
  documented.
- WebAssembly builds are deferred.

Needs the repository's owner: a first run of the workflows on GitHub (none
has run), and the submission of the community descriptor.

### 8.2 Benchmark run

Item 4 of the list above: the extension as a whole, measured once, with the
exit checks of P3 and P4 that were waiting for it. Four costs it found were
removed on the way ("What changed on the way" below; the numbers of record
are those after). It is one run on one machine over generated captures; what
that leaves out is at the end.

**Machine.** A Firecracker VM with 4 cores of an Intel Xeon at 2.10 GHz (the
hypervisor shows no model), 16 GB of memory, Linux 6.18.44, nothing else
running. Captures are on ext4 on a virtio disk and were in the page cache
for every run: no number here has disk reads in it.

**Builds.** The DuckDB 2.0.0 command-line shell from GitHub; the extension
of this commit from `make release` (the release profile: fat LTO, one
codegen unit); `rustc` 1.97.0. The command-line tool (DataFusion) of the
same commit with thin LTO and 16 codegen units, because its fat-LTO link
does not fit in this machine's memory; its numbers are a little behind what
a release build would give.

**Method.** `pcapsql-duckdb/scripts/bench.py` runs each point in a new shell
six times and drops the first; the tables have the median and, in brackets,
the smallest and largest of the five. The time is that of the statement
(the shell's `.timer`), without starting the shell and loading the
extension. Before a point the script waits until less than 5 percent of the
machine's CPU time is in use. Threads are set with `SET threads`; the
command-line tool has no such setting and was held to 1 or 4 cores with
`taskset`, its time being that of the process. A query whose result would be
many rows is an aggregate over them, so that no time goes into printing:
"all columns" is `SELECT count(COLUMNS(*))`, which makes the scan produce
every column and DuckDB look at each. Peak memory is the largest resident
set of the shell (about 42 MiB of it are DuckDB and the extension before
any capture is read). `perf` is not available in the VM; instructions are
counted with cachegrind instead, on one thread, as the count for a capture
of 500,000 packets minus that for one of 100,000, divided by 400,000. Two
counts of one query differ by up to 5 percent.

**Captures**, written by a generator over the frame builders of
`pcapsql_testgen::corpus` (kept out of the repository; classic pcap with
microsecond timestamps, one frame every 100 microseconds):

| File | Packets | Bytes | Content |
|---|---|---|---|
| `mixed10m.pcap` | 10,000,000 | 2,718,962,354 | Ethernet/IPv4. 4,548,294 TCP segments of 283,884 HTTP/1.1 connections (handshake, request, a response of 1 to 8 segments of 600 bytes with their acknowledgements, close), 64 open at a time; 5,451,706 UDP datagrams, 1,817,026 of them DNS queries and responses with 5,000 names, the rest 64 to 600 bytes of payload |
| `mixed2m5.pcap` | 2,500,000 | 679,551,009 | The first quarter of the same stream. Four files of it for the scans of several files; the same packets as pcapng (723,293,192 bytes), gzip (62,255,545) and zstd (42,952,906). The payloads are constant bytes, so the compressed files are far smaller than a real capture's would be |
| `tcpopts10m.pcap` | 10,000,000 | 1,500,000,028 | TCP segments of 64 bytes in the cycle of `benches/scan.rs`: a SYN with MSS, SACK permitted, timestamps and window scale; a segment with timestamps and two SACK blocks; a segment without options |
| `tls100k.pcap` | 1,600,000 | 166,900,024 | The fixture `tls13_http2.pcap` (TLS 1.3 carrying HTTP/2, 16 frames) 100,000 times with a client address each, 256 connections interleaved; one key log decrypts all |

#### Projection (P3)

`mixed10m.pcap` except where `tcpopts` says the other capture; seconds on
one thread, and instructions per packet of the capture (not per row).

| Query | Columns | 1 thread, s | Of all columns | Instructions per packet |
|---|---|---|---|---|
| `read_frames` | `count(*)` | 0.72 (0.68..0.75) | 57% | 693 |
| | `sum(length)` | 0.86 (0.70..0.89) | 67% | 942 |
| | all but `raw_data` | 0.91 (0.80..0.92) | 71% | 912 |
| | `raw_data` only | 1.19 (1.02..1.22) | 93% | 902 |
| | all 6 | 1.28 (1.11..1.39) | 100% | 1,243 |
| `read_udp` | `count(*)` | 1.97 (1.78..2.65) | 88% | 2,411 |
| | `dst_port` | 2.10 (1.94..2.16) | 93% | 2,345 |
| | all 9 | 2.25 (2.19..2.39) | 100% | 2,571 |
| `read_tcp` | `count(*)` | 2.20 (2.14..2.69) | 76% | 2,510 |
| | `dst_port` | 2.21 (2.15..2.47) | 76% | 2,473 |
| | all 29 | 2.90 (2.80..3.26) | 100% | 3,559 |
| `read_tcp`, `tcpopts` | `count(*)` | 2.02 (1.88..2.19) | 51% | 2,645 |
| | 1 field | 1.94 (1.91..2.15) | 49% | 2,865 |
| | 4 fields | 2.48 (2.29..2.72) | 63% | 3,272 |
| | 12 fields | 3.23 (3.12..3.62) | 82% | 4,486 |
| | 20 fields | 3.43 (3.34..3.80) | 87% | 4,701 |
| | all 29 | 3.95 (3.75..4.28) | 100% | 5,437 |
| `read_dns` | `count(*)` | 2.65 (2.46..2.81) | 78% | 3,089 |
| | `transaction_id` | 2.78 (2.65..2.88) | 81% | 3,049 |
| | `query_name` | 3.05 (2.93..3.14) | 89% | 3,231 |
| | all 27 | 3.42 (3.22..3.44) | 100% | 3,589 |
| `read_ethernet` | `count(*)` | | | 2,371 |
| `read_ipv4` | `count(*)` | | | 2,337 |

Reading:

- The cost falls with the projection in every table: a row count costs 51
  to 88 percent of all columns, one column 49 to 93 percent (the two are
  the same within the spread of the runs). `frames` and a TCP capture with
  options gain most (the packet bytes are not copied, the options are not
  decoded), `udp` least.
- Most of a protocol scan is not the table's own fields. Counting the rows
  of `ethernet` costs 2,371 instructions per packet against 693 for
  `frames`: the walk through the layers of a frame runs in full for every
  protocol table, since a tunnel further down may carry the protocol again,
  and `ethernet`, `ipv4` and `ipv6` extract all their fields whatever is
  asked (only `tcp`, `udp` and `dns` have a projected parse). That is the
  floor a projection cannot go below, and why a narrow projection of `udp`
  saves a tenth.
- P3's exit check asked for "the expected drop against P2 for narrow
  projections". P2 produced every column whatever the query used, which is
  the "all" rows here. The drop is there and is 7 to 51 percent; nothing
  had said how large to expect it. The check is taken as met, with the
  floor above as what it leaves.

**Projection below the table**, after the run (design document of the
shared scan layer, 3.6.2). Every protocol a scan parses is projected to the
fields something reads, so the layers under the table are parsed with no
field: `ethernet`, `linux_sll`, `sll2`, `vlan`, `ipv4` and `ipv6` have a
projected parse, as `tcp`, `udp` and `dns` had. A projection is a bit set
over the parser's field list that the parser asks by position, so the plan
projects a table however many of its fields are read. Measured on a capture
of the same kinds of traffic as `mixed10m.pcap` (Ethernet/IPv4; of every 11
frames 5 TCP segments with a timestamp option, among them HTTP requests and
responses, 4 UDP datagrams to a port without a parser and 2 DNS messages),
one thread, before and after. The run above counted the whole shell with
cachegrind; here DuckDB's idle threads made two such counts of one query
differ by more than the change, so these are callgrind's counts of the scan
alone (DuckDB's `CV2TableExec`, the C API's exec callback, with the
extension's `exec` under it), which repeat to 0.01 percent: instructions per
packet of the capture, for 100,000 packets minus 20,000, over 80,000.

| Query | Columns | Before | After |
|---|---|---|---|
| `read_frames` | `count(*)` | 888 | 886 |
| `read_ethernet` | `count(*)` | 2,426 | 2,169 |
| | `src_mac` | 2,547 | 2,315 |
| `read_ipv4` | `count(*)` | 2,440 | 2,169 |
| | `ttl` | 2,453 | 2,216 |
| `read_udp` | `count(*)` | 2,350 | 2,122 |
| | `dst_port` | 2,399 | 2,147 |
| | all 9 | 2,580 | 2,383 |
| `read_tcp` | `count(*)` | 2,600 | 2,320 |
| | `dst_port` | 2,683 | 2,357 |
| | 12 of its 24 fields | 3,417 | 2,772 |
| | 23 of them | 3,599 | 3,441 |
| | all 24 | 3,632 | 3,418 |
| | all 29 columns | 3,720 | 3,505 |
| `read_dns` | `count(*)` | 3,243 | 2,681 |
| | `transaction_id` | 3,284 | 2,691 |
| | `query_name` | 3,530 | 2,935 |
| | all 27 | 3,925 | 3,423 |

The floor of a protocol scan falls by a tenth (`ethernet`, `ipv4`, `udp`,
`tcp`) to a sixth (`dns`): one column of `udp`, `tcp` or `dns` now costs
less than a row count did. 23 of the 24 fields of `tcp`, projected now and
parsed in full before (the threshold of "What changed on the way" below),
cost 23 instructions more than all 24.

#### Scaling with threads (P4)

`mixed10m.pcap` (and `tcpopts10m.pcap`), all columns unless said. The first
column is the scan that is not split, on one thread; the speed-up is
against it.

| Query | Not split, 1 thread, s | 2 threads | 3 threads | 4 threads, s | Speed-up | Efficiency | CPU s at 4 |
|---|---|---|---|---|---|---|---|
| `read_frames`, `count(*)` | 0.79 (0.69..0.90) | 1.04 | 0.89 | 0.79 (0.78..0.81) | 1.0 | 25% | 1.37 |
| `read_frames` | 1.27 (1.18..1.38) | 1.25 | 1.02 | 0.95 (0.94..0.99) | 1.3 | 33% | 1.95 |
| `read_udp` | 2.24 (2.17..2.46) | 1.76 | 1.37 | 1.26 (1.21..1.35) | 1.8 | 45% | 2.96 |
| `read_tcp` | 3.06 (2.91..3.29) | 2.17 | 1.68 | 1.43 (1.37..1.58) | 2.1 | 53% | 3.65 |
| `read_tcp`, `tcpopts` | 4.17 (3.64..5.14) | 2.73 | 1.96 | 1.54 (1.49..1.59) | 2.7 | 68% | 4.65 |
| `read_dns` | 3.46 (3.28..3.56) | 2.38 | 1.85 | 1.49 (1.43..1.66) | 2.3 | 58% | 3.94 |
| `read_tcp_packets` | 4.00 (3.67..4.09) | 2.64 | 2.04 | 1.64 (1.52..1.81) | 2.4 | 61% | 4.52 |
| `read_tcp`, `GROUP BY dst_port` | 2.36 (2.26..2.41) | 1.78 | 1.39 | 1.23 (1.21..1.26) | 1.9 | 48% | 3.61 |

With `pcapsql_parallel_scan = false` every row is its first column on any
number of threads (0.76 to 4.22 s on four). Peak memory is 42 to 46 MiB on
one thread and 46 to 49 MiB on four for every scan of a packet table, the
`GROUP BY` at 59 MiB: a scan holds a read buffer per worker and no rows.

Reading:

- A scan that parses a protocol is 1.8 to 2.7 times faster on four threads,
  at 45 to 68 percent efficiency. A scan of `frames` gains a third, its
  row count nothing.
- What is missing is one thing. A capture has no index, so
  `init_global_state` reads it once on one thread for the places to split
  it at, before any worker starts, and keeps nothing for the next
  statement (section 6.4; the file API has no modification time to
  validate a cache with). That pass costs about 0.6 s for this capture
  (0.22 s per GB, 60 ns per packet), which is the difference in CPU time
  between four threads and one, and the time of `count(*)` over `frames`.
  The times fit `0.6 s + (time on one thread) / threads` to within a
  tenth.
- P4's exit check asked that a "benchmark shows scaling on a large
  uncompressed capture". It does for scans that parse, and the check is
  taken as met; the ceiling is as described.

The same pass is why a query that needs little of a capture is slower on
several threads than on one:

| Query | 1 thread, s | 4 threads, s | 4 threads, not split |
|---|---|---|---|
| `SELECT * FROM read_tcp(...) LIMIT 10` | 0.01 | 0.61 (0.55..0.64) | 0.01 |
| `SELECT * FROM read_frames(...) LIMIT 100000` | 0.01 | 0.64 (0.57..0.72) | 0.01 |

A `LIMIT` is not known to the scan, and the reference now says how to avoid
the pass. The cure is an index that is built while the first partitions are
scanned, or kept between statements; the command-line tool, which keeps one
beside the capture, shows what that is worth (the table of the two engines,
below). Neither is a small change, and neither was made here.

Several files (`mixed2m5.pcap` four times; `read_tcp` with all columns
unless said):

| Files | 1 thread, s | 2 threads | 4 threads, s | 4 threads, not split |
|---|---|---|---|---|
| 4, `read_frames` `count(*)` | 0.71 (0.68..0.82) | 0.41 | 0.22 (0.19..0.27) | 0.19 |
| 4 | 2.95 (2.72..3.03) | 1.56 | 0.80 (0.79..0.86) | 0.83 |
| 4, `read_udp` | 2.26 (1.96..2.92) | 1.17 | 0.64 (0.58..0.77) | 0.68 |
| 3 | 2.24 (2.15..2.49) | | 0.84 (0.77..0.91) | 0.76 |
| 2 | 1.54 (1.24..1.63) | | 0.69 (0.66..0.73) | 0.78 |
| 1 | 0.81 (0.75..0.86) | | 0.36 (0.33..0.39) | |
| `mixed10m.pcap` and three of 5 to 136 MB | 3.35 (2.96..3.46) | | 1.48 (1.41..1.58) | 2.85 |

Files are partitions without a pass, so four files on four threads are 3.2
to 3.7 times faster than on one. Before this run each of them was split in
four after a pass over it, and the same three queries took 0.80, 1.45 and
1.27 s on four threads: slower than with the setting off.

`pcapsql_index_stride` and `pcapsql_parallel_min_file_size` (four threads):

| `pcapsql_index_stride` | `read_tcp`, s | `read_frames` `count(*)`, s |
|---|---|---|
| 1,024 | 1.35 (1.29..1.43) | 0.86 (0.78..0.87) |
| 4,096 | 1.41 (1.39..1.47) | |
| 16,384 | 1.48 (1.44..1.51) | |
| 65,536 (default) | 1.48 (1.39..1.63) | 0.82 (0.80..0.86) |
| 262,144 | 1.44 (1.41..1.48) | |
| 1,048,576 | 1.59 (1.48..1.66) | |
| 4,194,304 | 1.91 (1.86..1.96) | 0.94 (0.90..0.98) |

| Capture (`read_tcp`) | 1 thread, ms | 4 threads, not split | Default (4 MiB) | Minimum 0 | Minimum 0, stride 4,096 |
|---|---|---|---|---|---|
| 5.5 MB, 20,000 packets | 13 (12..17) | 12 (10..14) | 14 (12..19) | 16 (12..18) | 15 (11..16) |
| 27 MB, 100,000 packets | 43 (31..63) | 37 (33..45) | 37 (33..43) | 40 (33..58) | 27 (22..41) |
| 136 MB, 500,000 packets | 174 (132..185) | 164 (133..220) | 92 (78..106) | 100 (90..104) | 91 (79..92) |

The stride does not matter until it leaves fewer checkpoints than threads
(10 million frames have three at 4,194,304). A capture is split from 4 MiB,
but one of a few strides is split in few, uneven parts: the 27 MB capture
(100,000 frames, two parts at the default stride) gains only with a smaller
stride, and a capture of a few megabytes gains nothing either way. The
defaults are left as they are.

Formats and compression (`mixed2m5`, 2.5 million packets):

| File | `read_frames` `count(*)`, 1 thread, s | 4 threads | `read_tcp`, 1 thread | 4 threads | `read_udp`, 1 thread | 4 threads |
|---|---|---|---|---|---|---|
| `.pcap` | 0.24 (0.18..0.27) | 0.20 (0.20..0.22) | 0.80 (0.69..0.96) | 0.43 (0.37..0.45) | 0.61 (0.51..0.72) | 0.33 (0.32..0.39) |
| `.pcapng` | 0.34 (0.28..0.37) | 0.34 (0.30..0.36) | 0.85 (0.79..1.00) | 0.53 (0.50..0.59) | 0.70 (0.60..0.72) | 0.49 (0.45..0.49) |
| `.pcap.gz` | 0.58 (0.51..0.68) | 0.61 (0.57..0.64) | 1.17 (0.93..1.33) | 1.18 (1.03..1.44) | 0.99 (0.88..1.05) | 0.94 (0.92..1.05) |
| `.pcap.zst` | 0.34 (0.29..0.36) | 0.35 (0.35..0.54) | 0.97 (0.88..1.07) | 0.89 (0.78..0.98) | 0.68 (0.61..0.71) | 0.72 (0.60..0.74) |

A compressed capture is one partition, as designed: four threads change
nothing. pcapng costs 0.1 s more to read than classic pcap and its pass
about as much again, so it scales less (1.6 against 1.9 for `read_tcp`).

#### A view against its join (P8)

`mixed10m.pcap`. The 5-table join is the view's definition (`frames`, the
anchor, `ethernet`, `ipv4`, `ipv6`); the join "by hand" is what one writes
without the view, three or four tables on `frame_number`.

| Query | 1 thread, s | 4 threads, s | Peak memory MiB, 1 / 4 threads |
|---|---|---|---|
| `read_tcp_packets`, all 20 columns | 4.21 (3.54..4.41) | 1.72 (1.69..2.02) | 43 / 48 |
| The same as its 5-table join | 16.00 (15.88..17.20) | 8.28 (8.05..8.56) | 1,929 / 1,937 |
| `read_tcp_packets`, 12 columns | 3.60 (3.44..3.91) | 1.68 (1.63..1.78) | 43 / 47 |
| `read_frames` `JOIN` `read_ipv4` `JOIN` `read_tcp`, the same 12 | 9.54 (9.38..10.45) | 4.64 (4.50..4.92) | 1,094 / 1,100 |
| `read_tcp_packets`, bytes and packets `GROUP BY dst_ip_v4` | 3.29 (2.94..3.38) | 1.44 (1.34..1.76) | 61 / 74 |
| The same over the 3-table join | 7.98 (7.55..9.04) | 4.19 (4.10..4.34) | 727 / 741 |
| `read_udp_packets`, all 15 columns | 3.39 (3.05..3.59) | 1.52 (1.44..1.60) | 43 / 48 |
| The same as its 5-table join | 15.34 (14.78..16.16) | 7.09 (6.97..7.55) | 1,501 / 1,508 |
| `read_dns_packets`, all 33 columns | 4.61 (4.53..4.88) | 1.97 (1.87..2.14) | 43 / 49 |
| `read_frames` `JOIN` `read_ipv4` `JOIN` `read_udp` `JOIN` `read_dns` | 12.88 (11.89..13.19) | 5.93 (5.80..6.18) | 1,286 / 1,293 |

The view and the join return the same rows: `EXCEPT ALL` in both directions
is empty for `read_tcp_packets` against its 5-table join (1,136,213 rows of
`mixed2m5.pcap`), for its 12 columns against the 3-table join, and for
`read_udp_packets` against its join (1,363,787 rows), on one thread and on
four. A view is 2.4 to 4.8 times faster than the join it stands for and
needs a twelfth to a forty-fifth of the memory: the join reads the capture
once per table and builds hash tables of its rows, the view reads it once
and keeps nothing.

#### Filter pushdown (P6)

`SELECT count(*), count(dst_port) FROM read_tcp('mixed10m.pcap') WHERE ...`;
about 45,500 rows each. "Read" is the packets the scan's readers delivered
(its DEBUG records), of which those the filter rejects are not parsed.

| Filter | Pushdown, 1 thread, s | Packets read | Pushdown, 4 threads, s | Packets read | No pushdown, 1 thread | 4 threads |
|---|---|---|---|---|---|---|
| `frame_number BETWEEN 5000001 AND 5100000` | 0.36 (0.32..0.55) | 5,100,000 | 0.33 (0.31..0.34) | 119,264 | 2.46 | 1.27 |
| `frame_number <= 100000` | 0.03 (0.02..0.04) | 100,000 | 0.03 (0.02..0.03) | 100,000 | 2.42 | 1.18 |
| `frame_number > 9900000` | 0.62 (0.59..0.65) | 10,000,000 | 0.63 (0.59..0.66) | 104,064 | 2.29 | 1.18 |
| `timestamp` in 10 s of the 1,000 | 0.61 (0.58..0.61) | 10,000,000 | 0.60 (0.58..0.62) | 169,600 | 2.23 | 1.22 |
| `timestamp >=` the last 10 s | 0.58 (0.57..0.60) | 10,000,000 | 0.61 (0.59..0.64) | 104,064 | 2.20 | 1.27 |

Without pushdown every scan reads and parses the 10 million packets. With
it the filter costs what reading costs: a range of frame numbers is read up
to its end, and a window of time costs one reading of the capture, either
as the scan itself (one thread: packets outside the window are read and not
parsed) or as the pass before it (several threads: only the checkpoint
windows that overlap are then scanned, and the last one of the capture).
That is 4 times faster than without on one thread and 2 times on four, and
no faster than 0.6 s for this capture however narrow the window: the same
missing index as above.

#### Stream tables (P8)

| Query | 1 thread, s | 4 threads, s | Peak memory MiB | Rows |
|---|---|---|---|---|
| `read_tcp_connections('mixed10m.pcap')`, 3 columns | 5.69 (5.50..6.07) | 5.68 (5.60..6.17) | 535 | 283,884 |
| all columns | 5.92 (5.55..6.26) | | 536 | |
| `read_http_messages('mixed10m.pcap')`, 3 columns | 6.04 (5.49..6.28) | 6.15 (5.94..6.25) | 488 | 567,713 |
| all columns | 6.11 (5.86..6.48) | | 488 | |
| `read_tcp_connections` of the four files | 6.12 (5.79..6.58) | 1.67 (1.64..1.83) | 188 / 510 | 283,964 |
| `read_tls_sessions('tls100k.pcap')` | 1.99 (1.66..2.13) | | 670 | 100,000 |
| with the key log | 5.24 (5.04..5.62) | | 1,546 | 100,000, all decrypted |
| `read_http2('tls100k.pcap')`, key log, 2 columns | 4.98 (4.94..5.44) | 5.23 (4.93..5.56) | 1,509 | 800,000 |
| all columns | 6.17 (5.84..7.01) | | 1,510 | |
| `read_tcp_connections('tls100k.pcap')` | 1.91 (1.85..2.05) | | 644 | 100,000 |
| `read_tcp('tls100k.pcap')`, for scale | 0.57 (0.50..0.65) | | 43 | 1,600,000 |

A stream table costs two to three times the packet table of the same
capture (reassembly), is one partition per file whatever the threads
(several files do spread), and holds what it has reassembled until the
capture ends, when the rows are written: 1.8 kB per connection of the HTTP
capture, 6.3 kB per connection of the TLS capture, 16 kB per decrypted
session. Nothing is released when a connection closes. Decryption is three
fifths of the time of `read_http2` (5.0 s against 1.9 s for the connections
alone): 31 microseconds per session, each of which is 1.7 kB of capture.

#### `COPY ... TO 'x.pcap'`

From `mixed10m.pcap` to a file on the same disk.

| Statement | Frames written | Bytes | 1 thread, s | CPU s | 4 threads, s | CPU s |
|---|---|---|---|---|---|---|
| `SELECT * FROM read_frames(...)` | 10,000,000 | 2,718,962,354 | 6.76 (5.85..7.33) | 4.25 | 7.60 (7.31..8.46) | 4.91 |
| `... WHERE length < 100` | 4,800,793 | 397,432,092 | 2.40 (2.08..2.82) | 2.22 | 2.62 (2.53..2.66) | 2.45 |
| frames of TCP to port 80 (a semi join with `read_tcp`) | 2,699,933 | 217,208,951 | 5.06 (4.79..5.74) | 4.93 | 4.11 (4.00..4.41) | 6.81 |
| For scale: `read_frames`, all columns, no copy | | | 1.32 (1.24..1.77) | 1.32 | 0.98 (0.93..1.03) | 2.01 |

An unfiltered copy writes 400 MB/s (640 MB per second of CPU); the wall
clock has 2.5 s of waiting for the disk in it, which another disk would
change. The filtered copy reads 1.1 GB/s of capture and writes 166 MB/s.
Threads do not help: the sink is not parallel in DuckDB 2.0.0 (section 8.1)
and a scan that feeds it runs on one thread. The copy itself is 3 s of CPU
for 10 million rows above the scan, 300 ns per packet.

#### The two engines, and Parquet

The same queries over `mixed10m.pcap` in the extension and in the
command-line tool (DataFusion). The tool maps the capture and keeps an
index beside it (`mixed10m.pcap.idx`, 5 kB) from its first run; the last
column is DuckDB over a Parquet file of `read_tcp_packets` (4,548,294 rows,
89 MB, written in 2.7 s on four threads), which is what the engine costs
when nothing is parsed.

| Query | DuckDB, 1 thread, s | Tool, 1 core | DuckDB, 4 threads, s | Tool, 4 cores | Parquet, 1 / 4 threads |
|---|---|---|---|---|---|
| `count(*)` of `frames` | 0.82 (0.69..0.82) | 0.03 | 0.82 (0.75..0.95) | 0.03 | |
| `count(*)` of `tcp` | 2.22 (2.04..2.29) | 2.07 (1.99..2.27) | 1.18 (1.14..1.28) | 0.61 (0.58..0.68) | |
| `tcp`, `GROUP BY dst_port` (40,001 groups) | 2.31 (2.21..2.39) | 2.26 (2.09..2.33) | 1.25 (1.21..1.38) | 0.69 (0.68..0.85) | 36 / 22 ms |
| `udp`, a filter that keeps 53 rows | 2.07 (2.01..2.29) | 1.96 (1.83..2.10) | 1.24 (1.14..1.28) | 0.56 (0.55..0.68) | |
| `dns`, queries `GROUP BY query_name` | 3.18 (3.05..3.46) | 2.82 (2.62..3.08) | 1.48 (1.35..1.62) | 0.92 (0.86..1.01) | |
| `tcp_packets`, `GROUP BY dst_ip_v4` (284,077 groups) | 2.72 (2.43..2.92) | 3.03 (2.95..3.03) | 1.39 (1.33..1.42) | 0.89 (0.86..0.93) | 63 / 30 ms |
| `tcp_packets`, a filter that keeps 74 rows | 2.87 (2.73..3.00) | 2.89 (2.73..3.04) | 1.41 (1.38..1.81) | 0.85 (0.77..0.98) | 27 / 14 ms |
| `tcp_connections` | 6.11 (5.44..6.22) | 5.96 (5.46..6.20) | 5.94 (5.66..6.20) | 6.12 (5.78..6.26) | |

- On one thread the two are within 13 percent of each other, either way:
  they run the same scan layer, and the engine above it is a few percent of
  the time.
- On four the tool is 1.6 to 2.2 times faster, by the pass: with its index
  file removed before each run `count(*)` of `tcp` takes it 1.11 s
  (1.09..1.18), the extension 1.18. The index also answers `count(*)` of
  `frames` without reading the capture.
- The tool's peak resident set is 2.6 GiB, which is the mapped capture;
  with `--no-mmap` it is 58 MiB at the same speed. The extension's is 46 MiB.
- Over Parquet the same aggregates take 14 to 63 ms: parsing packets is 97
  to 99 percent of a query over a capture, in either engine. A capture that is
  queried often is worth converting.

#### What changed on the way

Each was a cost the run showed, with a contained cure (CHANGELOG):

| Finding | Cause | Before | After |
|---|---|---|---|
| A row count of `tcp` or `dns` costs more than one column | The plan projects no field; the three parsers with a projected parse read an empty projection as "all fields" | `tcpopts` `count(*)`: 2.53 s, 3,196 instructions per packet; `dns`: 2.87 s, 3,336 | 2.02 s, 2,645; 2.65 s, 3,089 |
| A projection of most of a table's fields costs more than none | A parser asks the projection about every field of every packet (`tcp`: 51 questions), and an answer compares the name with each name of its length | 21 of the 24 fields of `tcp`: 5.08 s; 23: 7,256 instructions per packet, all 24: 5,338 | A table is projected only when at most half of its fields are read: 3.56 s; 5,087 |
| Four files on four threads are slower than with `pcapsql_parallel_scan = false` | Every file was split for all the threads, after a pass over each on one thread | `read_tcp`: 1.45 s (not split: 0.90); `read_frames` `count(*)`: 0.80 s (0.21) | A file is split for its share of the threads: 0.80 s, 0.22 s |
| `WHERE frame_number <= 100000` takes 20 times longer on four threads than on one | The pass read the whole capture before a scan of its beginning | 0.65 s (one thread: 0.03); `BETWEEN 5000001 AND 5100000`: 0.62 s | The pass ends at the bound: 0.03 s; 0.33 s |

Since the run, the projection below the table (section 8.1, the row after
the projection results above) covers the first finding and makes the second
cure unneeded: every parser with a projected parse reads an empty projection
as no field, and a projection is a bit set the parser asks by position, so
the plan projects a table whatever the number of its fields read, and the
threshold is gone.

Tried and not kept:

- A table lookup for the projection's answers (a slot from a name's length
  and six of its bytes, one comparison) cost more per answer than the walk
  over a short list, since the compiler does not fold the slot of a literal
  name: a projection of one field of `tcp` went from 2,826 to 3,866
  instructions per packet. The cure for the second finding is therefore in
  the plan, not in the lookup.
- `ChunkWriter::put` marks every value it stores valid, although a vector
  handed to `exec` starts all valid (the mark is a load and a compare, not a
  store). Without the mark the scans above count 0 to 4 percent fewer
  instructions (`tcpopts`, all columns: 5,415 to 5,216; the others inside
  the 5 percent two counts differ by). The C API does not promise the
  all-valid mask: it comes from DuckDB resetting the chunk it hands to a
  table function (`DataChunk::Reset`), which is its implementation and no
  documented property, and `duckdb-neo`'s `set_size` keeps the validity a
  row had. Left as it is.

#### What this leaves

Not good, in the order of what it costs:

1. The pass before a split (scaling at half efficiency, `LIMIT`, time
   windows, `frames`). An index built while the scan runs, or kept, is the
   next thing worth doing to the reader.
2. Done since the run: projection reaches the layers under the table
   ("Projection below the table" after the projection results above).
3. Stream tables keep every connection until the capture ends: 0.5 GB for
   284,000 connections, 1.5 GB for 100,000 decrypted sessions.
4. `COPY` writes on one thread.

Not measured: more than four cores (the check of P4 names eight threads,
which were run for equality only); real captures, whose packet sizes and
protocol mix differ from the generator's; reads from a disk or over a
network (every capture was cached; `httpfs` cannot be installed here);
other platforms; TLS 1.2 and captures with large TLS records; a fat-LTO
build of the command-line tool; hardware counters (cachegrind counts
instructions, not cycles or cache misses).

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
(Both met; the benchmark is section 8.2.)

### P4: Parallel scans

- Index build, `plan_ranges`, `PartitionQueue`; `claim_batch`; `max_threads`.
- `partition_data` batch indices for order preservation.
- `pcapsql_index_cache_dir` and cache I/O through DuckDB's file system.

Exit: results identical to the single-threaded scan on the corpus at 1, 2 and
8 threads, including row order without `ORDER BY`; benchmark shows scaling on
a large uncompressed capture. (Both met; the benchmark is section 8.2, on
four cores, with the ceiling the index pass puts on it.)

### P5: Multi-file, replacement scan, remote

- Own multi-file handling (D9): the positional argument accepts a VARCHAR or
  a LIST of VARCHAR; each entry is expanded with `FileSystem::glob` at bind;
  every file is probed; the partition queue spans the files; `filename :=
  true` adds the column.
- Replacement scan targeting our function directly.
- Remote tests: `httpfs` against a local HTTP server and an S3-compatible
  store, reusing the setup of the existing cloud-integration workflow;
  buffer-size tuning for remote reads.
  - HTTP: written, not yet run. `scripts/remote-test.sh` (`make
    remote_test_release`) starts `scripts/range-http-server.py` on 127.0.0.1
    (GET, HEAD and Range, with a log of every request) over legacy, pcapng,
    gzip and zstd captures and a generated capture of 28 MB, and in the
    release's shell with `httpfs` loaded compares `frames`, protocol tables
    and a `*_packets` view read from the URL with the file, row for row
    (`EXCEPT ALL` both ways); it checks `filename`, a list of URLs, a URL
    and a file in one list, `FROM 'http://...'`, one partition for a URL
    (from the scan's DEBUG record), a pushed-down `frame_number` filter,
    `LIMIT`, a 404 as an error that names the URL, that
    `enable_external_access = false` refuses the URL with no request made,
    and that every capture was requested from the server. A pushed-down
    frame range and `LIMIT` must end the read: no byte range either asks
    for may reach the second half of the 28 MB capture, and neither may
    fetch as many bytes as it holds. Whether `httpfs` asks for ranges is
    printed, not required. Without `httpfs` it exits with 77 and the make
    target passes; with `--require-httpfs`, which the workflows pass, that
    is a failure. Verified where it was written: the server (36 curl checks,
    `make remote_test_server`), the skip path, and the script's SQL and
    parsing with file paths in place of URLs. Not verified: anything that
    needs `httpfs`, which is the test itself. The texts it expects from
    DuckDB for a 404 (the URL in the message) are assumptions until the
    first run.
  - S3: open. The cloud-integration workflow's LocalStack service, a bucket
    filled with the same captures and a `CREATE SECRET (TYPE s3, ENDPOINT
    ..., URL_STYLE 'path', USE_SSL false)` would do it, in a job of its own;
    it was left until the HTTP test has run once, since nothing of it can be
    tried without `httpfs`.


Exit: glob, list, `filename` and `FROM 'x.pcap'` tests pass; an `s3://` capture
is read with credentials supplied only through a DuckDB secret. (The first
half is met. The second is open: see the S3 item above and U7.)

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

As built:

- `.github/workflows/duckdb-dist.yml` calls the reusable workflow of
  `extension-ci-tools` at the commit the submodule is at, on the
  `v2.0-cyanoptera` branch, which is what community-extensions builds DuckDB
  2.0.0 with. That branch has a `build_directory` input, so the build runs in
  `pcapsql-duckdb/` and the repository needs no Makefile at its root. The
  submodule was on `main` before P7 and was moved to the branch.
- The reusable workflow runs the SQL tests on `osx_arm64` (and, since U13
  was resolved, `windows_amd64`) only, so a second
  job downloads each artifact on a runner of its platform and runs
  `test/sql` and `scripts/load-test.sh` against it.
- `release.yml` calls the same workflow for a tag and attaches one archive
  per platform to the GitHub release, after the release exists.
- The supported platforms are `linux_amd64`, `linux_arm64` and `osx_arm64`
  (U10, U13); `windows_amd64` was added when U13 was resolved.
- `pcapsql-duckdb/community/description.yml` with `repo.build_directory`; its
  `repo.ref` is a placeholder until a release commit exists.
- `docs/duckdb-extension-reference.md`, and `make check_reference_release`,
  which asks DuckDB what the artifact registered and compares.
- `docs/duckdb-upgrade-runbook.md`; `make check_pins`; `make canary` and
  `duckdb-canary.yml`.

### P8: Backlog after the reader

Not scheduled.

- **Done.** `read_<proto>_packets(files)`: the DataFusion `*_packets` views
  as fused scans (S4b). One pass, no join; this is also how several protocol
  tables share one parse in DuckDB. Decisions taken on the way:
  - The view definitions live in `pcapsql_core::scan::views`
    (`PacketsView`), not in the extension: members, joins, column names and
    the three computed columns (`COALESCE`, the `transport` label, the
    `icmpv6.type IN (...)` filter of `ndp_packets` and `mld_packets`) are
    data the fused evaluator understands. DataFusion's SQL views are
    unchanged and remain the reference; a test on that side fails if the two
    drift.
  - Column names and collisions follow the DataFusion views exactly
    (`src_ip_v4`, `udp_length`, ...). The only difference is the engine's
    timestamp unit (`TIMESTAMP_NS`).
  - `pcap_protocols()` keeps listing tables only; views are listed by the
    new `pcap_views()`, and `pcap_schema()` and `read_pcap(protocol := ...)`
    accept a view name.
  - The four DataFusion views that join across encapsulation levels or need
    a full join (`packets`, `tunneled_packets`, `ip4_in_ip6`, `ip6_in_ip6`)
    are left out rather than approximated. They would need non-equi depth
    conditions (`depth = depth - 1`) and full joins in the fused evaluator.
  - Open: an arbitrary set of tables in one pass (a user-defined fused
    scan) is not exposed. (A view against the join it replaces is measured
    in section 8.2.)
- **Done.** Stream tables and TLS decryption (S4c, plus a keylog named
  parameter). Decisions taken on the way:
  - A stream table is a table like the others: `read_<table>(files)`,
    `read_pcap(files, protocol := ...)`, a row of `pcap_protocols()` with
    `kind = 'stream'`, the columns of `pcap_schema()`. Nothing in `exec` is
    particular to it; the plan (`ScanPlan::streams`) and the layout (one
    partition per file) are.
  - Each file of a call is a scan of its own, so `connection_id` starts again
    in every file, as `frame_number` does; `filename := true` tells the files
    apart. One reassembly across files would make the files one capture,
    which their order and their overlap do not say they are.
  - The key log is a path, in the `keylog` parameter or the setting
    `pcapsql_keylog` (the parameter wins; `''` is "none"). A DuckDB secret
    was not possible: the C API v2 of DuckDB 2.0.0 has no function for
    secret types or secret lookup, and `duckdb-neo` 0.20000.2 none either.
  - `read_pcap` accepts `keylog` for a packet table or a view and ignores it
    (the file is not opened); the `read_<table>` functions of packet tables
    do not have the parameter.
  - Open: cancelling during the read of a file (no interrupt query in the
    C API; returning empty chunks was tried and DuckDB does not look), a
    `LIMIT` that ends the read (the tables are complete only at the end),
    TLS 1.2 decryption (untested), HTTP/1.x inside TLS (not parsed).
- **Done.** The DataFusion UDFs: the name and address-classification
  scalars, the capture-relative time functions and the `hdr_*` histogram
  functions (section 8.1). Not registered, because DuckDB has them: the six
  date and time helpers, whose DuckDB spellings are in the reference.
  Decisions taken on the way:
  - The capture is an argument of the time functions (`start_time(files)`),
    which are macros over a table function, `pcap_time_range(files)`; no
    name needed a `pcap_` prefix.
  - The histogram kernels live in core behind a feature, and the serialized
    form is HdrHistogram's own, unchanged, so the engines exchange
    histograms. It is not canonical: a histogram merged from parts can
    differ from a recorded one in one header field.
  - `hdr_buckets` returns DataFusion's list of structs; the writer for it
    uses `duckdb-neo`'s checked nested writers.
  - Open: the aggregate states DuckDB 2.0.0 does not destroy (section 8.1).
- **Done.** `COPY ... TO 'x.pcap' (FORMAT pcap)` (section 8.1). Decisions
  taken on the way:
  - The input is matched by name, not position, with the names of `frames`,
    and columns that are not a packet's are ignored, so `SELECT *` of
    `read_frames` works; a missing required column is refused at bind.
  - The unit of the file follows the type of the `timestamp` column unless
    `PRECISION` is given, so no timestamp loses precision unasked. The price
    is that a copy of a microsecond capture is a nanosecond file by default.
  - The link type is the `LINKTYPE` option, else that of the first row, else
    Ethernet, and the header is written with the first row. A row of
    another link type is an error, not a second file: `PARTITION_BY
    (link_type)` is DuckDB's way to several files.
  - Nothing is prepared in the batch callback: the sink is not parallel in
    DuckDB 2.0.0, and the first row and the row numbers of the messages
    depend on the order of the flushes.
  - `pcapsql-testgen` keeps its own capture writer (no dependencies, and it
    writes big-endian and malformed files); the new writer is in core.
  - `COPY ... FROM` is not offered: the table functions read.
  - Open: pcapng and compressed output.

### P9: Follow V2 to stability

- When a DuckDB release adds them: statistics callback (min/max of
  `timestamp` and `frame_number` from the index) and the `file_row_number`
  virtual column.
- When DuckDB marks table functions and the file system stable: switch the
  stamp from `C_STRUCT_UNSTABLE` to `C_STRUCT`, drop per-release rebuilds, and
  set the minimum DuckDB version.

## 9. Tracking an unstable API

- **Pin.** `duckdb-neo = "=0.20000.x"`. `TARGET_DUCKDB_VERSION` in the
  Makefile and the pin move together in one commit, with the other places
  that name the release; `make check_pins` fails when they disagree.
- **Canary.** `duckdb-canary.yml` runs `scripts/canary.sh` weekly against the
  newest `duckdb-neo` on crates.io and against `duckdb-rs` `main`. It is a
  workflow of its own that nothing depends on. Its purpose is to show
  upcoming breakage early.
- **Upgrade runbook per DuckDB release.**
  [`duckdb-upgrade-runbook.md`](duckdb-upgrade-runbook.md): bump the pin and
  target; fix `engine/`; run `itest/` and the sqllogictests; tag; update the
  community descriptor's `ref`. It was walked once against 2.0.0 (no newer
  release existed) and records what that showed.
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
| U7 | Do `s3://` and `https://` opens through `FileSystem` pick up secrets? | Not answered: `httpfs` cannot be installed where `extensions.duckdb.org` is unreachable. Opens of such paths correctly report that `httpfs` is needed. A test of `http://` opens through `httpfs` exists and runs in CI (`scripts/remote-test.sh`, P5) but has not run yet, and it needs no secret; `s3://` with a secret is not tested by anything |
| U8 | Which vector writers exist, and are pointers stable for one `exec`? | Ran. Checked writers for UBIGINT, TIMESTAMP_NS, VARCHAR, BLOB, BOOLEAN, UINTEGER, LIST(UINTEGER), LIST(VARCHAR) and NULLs; a raw path (`as_mut_ptr`, `validity_mut`, `arena()`). Data pointers stay put while a chunk is written; growing a LIST child moves the child's. Chunk capacity is 2,048; the row count is the first vector's size; setting it past capacity is not refused and can invalidate the database |
| U9 | Can a replacement scan pass a named parameter? | Yes when it targets our function directly (ran); not through the multi-file wrapper |
| U10 | Does the stack compile for `wasm32-unknown-emscripten`? | Not shown, and WebAssembly is left out of the platform matrix (P7). Checked with `cargo check --target wasm32-unknown-emscripten`: every Rust-only dependency type-checks, including `duckdb-neo`, `libduckdb-sys`, `netlink-packet-route`, `memmap2`, `pcap-parser` and `tls-parser`. `ring` and `zstd-sys` compile C and need `emcc`; the Emscripten SDK was not installed (about 1 GB), so `pcapsql-core` and the extension were not checked. Beyond compiling, three things are missing: an `ext-wasm/` `staticlib` crate for `emcc -sSIDE_MODULE=2` to link (the `cdylib` in `ext/` is not what `extension-ci-tools` links for Wasm); a DuckDB-Wasm build that loads `C_STRUCT_UNSTABLE` extensions of exactly 2.0.0; and a way to load the result in CI, since the distribution workflow has no test step for Wasm. `ring` is in core for TLS decryption, which the extension does not use, so a core feature that drops it would remove one of the two C dependencies. To pick this up: install emsdk, run the `cargo check` above for `pcapsql-duckdb-ext`, then add `ext-wasm/` after the `crates/wasm` of DuckDB's Rust template |
| U11 | Does `pcap_parser` re-deliver a block that was not consumed? | Yes (ran: `pause_before_redelivers_the_same_packet`, for legacy records, EPBs and SPBs) |
| U12 | Is the Arrow importer a better way to emit rows than direct writes? | No (D3) |
| U13 | Does the stack compile for Windows? (asked in P7) | No (ran: `cargo check --target x86_64-pc-windows-gnu -p pcapsql-duckdb-ext`, with MinGW for the C dependencies). Two causes, both in `pcapsql-core`. Its manifest has `[target.'cfg(unix)'.dependencies]` above `tracing`, `smallvec`, `compact_str`, `tls-parser`, `nom`, `md5`, `ring`, `hpack` and the netlink crates, so on Windows none of them is a dependency; only `libc` was meant to be there. With that table moved to the end, `netlink-packet-route` 0.21 fails to compile (`std::os::unix`, `libc::AF_*`): it is a Unix-only crate, used by the `netlink` and `rtnetlink` parsers. Nothing past that was reached. `windows_amd64` is therefore excluded from the workflows and from the community descriptor. Supporting it needs a change to core (move the table; put the netlink parsers behind `cfg(unix)` or a feature, which removes two tables on Windows), which is a decision about the released library and was not made in P7. **Resolved after P7**: the target table now holds `libc` alone at the end of the manifest, and `netlink-packet-route` and `netlink-packet-utils` are gone (nothing used them; the netlink parsers need `netlink-packet-core` only, which is portable, so no table is lost). `cargo check --target x86_64-pc-windows-gnu --all-targets` is clean for `pcapsql-core`, `pcapsql-duckdb` and `pcapsql-duckdb-ext`, and `cargo build` links `pcapsql.dll`. `windows_amd64` (MSVC) is back in the workflow and the descriptor on that evidence; it has not been built or loaded on a Windows runner. `windows_amd64_mingw` stays excluded: `extension-ci-tools` skips the SQL tests there |
| U14 | Can community-extensions build an extension that is not at the root of its repository? (asked in P7) | Yes, by reading its build scripts: `repo.build_directory` in the descriptor is passed as the `build_directory` input of the reusable workflow on the `v2.0-cyanoptera` branch of `extension-ci-tools`, which runs every make target there and mounts the repository root into the Linux build container. Not run |

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
| The distribution and release workflows were written without a run on GitHub | `duckdb-dist.yml` runs on pushes to `main`, so a failure shows before a tag; the release job for the extension's assets is separate from the package jobs and cannot fail them |
| The Windows build is unproven (U13) | `windows_amd64` is built by the distribution workflow since `pcapsql-core` compiles for Windows, checked by cross-compiling for `x86_64-pc-windows-gnu` only. Its first run on a runner decides; the load-test job does not cover it |
