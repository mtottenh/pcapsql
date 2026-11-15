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
      fs.rs               # DuckFile: Read adapter over duckdb_neo::file::File
      pushdown.rs         # Expression -> FramePredicate
      relation.rs         # the tables and views the engine reads, as scan plans
      listing.rs          # pcap_protocols(), pcap_views(), pcap_schema()
      scalar.rs, macros.rs, replacement.rs, settings.rs
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
there are four (`pcapsql_parallel_scan`, `pcapsql_parallel_min_file_size`,
`pcapsql_index_stride`, `pcapsql_filter_pushdown`) and no
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
| P3 Projection, cardinality, progress | done except the benchmark exit check. The cardinality is an estimate from the file size |
| P4 Parallel scans | done for local uncompressed captures; the index is rebuilt per scan (no cache: the file API exposes no modification time to validate one) |
| P5 Multi-file, replacement scan, remote | done except the remote exit check: lists, globs, `filename`, and `FROM 'x.pcap'`, with the partition queue spanning the files. The HTTP test is written and has not run: `make remote_test_release` (`scripts/remote-test.sh`) reads captures through `httpfs` from a local HTTP server that answers Range requests and compares them with the files, and `duckdb.yml` and the `verify` job of `duckdb-dist.yml` run it, failing if `httpfs` cannot be installed. `httpfs` could not be installed where it was written, so there only the server was tested (with curl) and the test takes its skip path; until the first GitHub run no `http://` capture has been read. No `s3://` capture has been read, no secret tried (U7), and remote buffer sizes are untuned |
| P6 Filter pushdown | done, with two limits found on the way. DuckDB 2.0.0 hands two bounds on one column to the scan as a single `BETWEEN` node whose inclusivity the C API does not expose, so a range is used to narrow the read but not accepted: `EXPLAIN` still shows the filter for a time window. And `plan_ranges` keeps the last checkpoint window of an indexed capture unless an upper frame bound excludes it, so a time window never rules out a whole file |
| P7 Distribution and documentation | done as far as it can be without running on GitHub or submitting anything. Workflows for `linux_amd64`, `linux_arm64`, `osx_arm64` and `windows_amd64` (build through `extension-ci-tools`, then a load test of each artifact), release assets on a tag, the community descriptor, the function reference with a check against the artifact, the upgrade runbook with its dry run, and a canary. None of the new workflows has run on GitHub, and the descriptor has not been submitted, so the exit check is open. `windows_amd64` was added after P7, once `pcapsql-core` compiled for Windows (U13); it has not been built on a runner either, and no job loads its artifact. WebAssembly is not built (U10) |
| P8 Backlog | first item done: `read_<proto>_packets(files)` for the 21 `*_packets` views that are a join within one encapsulation level, as fused scans of the shared layer (S4b), with `pcap_views()`. Each equals the DataFusion SQL view of its name (DataFusion test over 23 captures) and the DuckDB join of the `read_<table>` functions (itest over 24 captures, 1 and 4 threads, split and not, pushdown on and off); the 14 golden-corpus queries over these views now match the DataFusion snapshots too (59 compared in all). `packets`, `tunneled_packets`, `ip4_in_ip6` and `ip6_in_ip6` are not fusable shapes and are not offered. Not benchmarked. The other items are not started |
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
| Arrow sink | Builders start each batch at the size of the last: no reallocation in steady state |
| Text kernels | IPv4, IPv6 and MAC text without `fmt`; hex decoded into a buffer the caller keeps. The row writer's IPv6 text and the MAC formatters that were left in `FieldValue`, `dhcp` and `icmpv6` go through them too |
| Scalars | DataFusion UDFs parse a constant argument once; DuckDB's scalar loops are generic over their kernel, and a constant-pattern match is a SIMD compare over the rows of a chunk that are not NULL, a 64-row word of the validity mask at a time (the second of two audited `unsafe` places) |
| Reader | No `BufReader` under the parser's own buffer |
| Benchmarks | A thin-LTO bench profile, so they link on a small machine; the `with_payload` case runs again |

Remaining, in the order intended:

1. Scan-layer polish in core and the DuckDB engine clean-up: `thiserror`
   on the plan errors, the observer's own error type, the frame-predicate
   algebra in core, table descriptions in the catalogue, `scan::testing`
   behind a feature, a plan the driver cannot run refused, `engine/table.rs`
   split, type tests by id.
2. The DataFusion scan path: stream tables on the shared layer (S4c) so
   that the legacy builders in `stream_tables.rs` go, `providers/shared.rs`
   split and keyed by output id.
3. Typed columns in the Arrow sink (fixed-width columns as vectors with a
   lazily built validity bitmap).
4. A benchmark run of the whole (P3 projection, P4 scaling, a view against
   its join), recorded here.
5. P8: stream tables and TLS decryption in the extension, the remaining
   UDFs as wrappers, `COPY ... TO 'x.pcap'`.
6. The S3 half of the P5 remote test, once the HTTP half has run.

Open decisions for the maintainer:

- The parsers' own name tables and `pcapsql_core::format::names` disagree
  for unknown codes (`UNKNOWN` against `Unknown (n)`); making the parsers
  use the shared tables changes existing column values.
- A constant-pattern match over a chunk with NULLs falls back to the
  per-row loop; covering it needs a second kind of `unsafe` (slices over
  all-valid words).
- The CLI's entry points became public items of the `pcapsql-datafusion`
  library (`cli::run_repl` and others) when `main.rs` was split.
- A strict partitioned scan checks the capture's tail up front, so `strict`
  with `LIMIT` differs between a split and an unsplit scan.

Needs the repository's owner: a first run of the workflows on GitHub (none
has run), and the submission of the community descriptor.

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
    and that every capture was requested from the server. How many bytes
    `LIMIT` and a filter fetch, and whether `httpfs` asks for ranges, are
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
  - Open: a benchmark of a view scan against the join it replaces; an
    arbitrary set of tables in one pass (a user-defined fused scan) is not
    exposed.
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
