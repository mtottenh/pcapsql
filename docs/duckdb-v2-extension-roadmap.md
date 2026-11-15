# Design and roadmap: `pcapsql-duckdb` on the DuckDB C API v2

Status: proposal, 2026-11-15. Decision taken: go directly to the V2 C API
(`duckdb_v2.h`) through the upstream `duckdb-neo` crate, and do not build an
intermediate V1 version.

Background research is in
[`reports/DuckDB V2 C API for pcapsql.md`](../reports/DuckDB%20V2%20C%20API%20for%20pcapsql.md)
and `research_notes/DuckDB V2 C API for pcapsql/`. The `duckdb-neo` API names
used below were checked against the published source of `duckdb-neo`
0.20000.2. Nothing in this document has been compiled or run yet; every claim
about engine behaviour that the design depends on is listed in
[section 9](#9-things-to-verify-in-the-p0-spike) and is verified in P0 before
later phases start.

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
4. A thin engine-facing layer, so V2 API churn before stabilisation touches
   few files.
5. Distribution through DuckDB community extensions.

Non-goals for this roadmap:

- Supporting DuckDB 1.x. V2 does not exist there and an extension cannot
  target V1 and V2 at once.
- One binary across DuckDB versions. Until V2 has a stable band, each DuckDB
  release needs its own build (section 8).
- Stream-level tables (`tcp_connections`, `tls_sessions`, `http_messages`,
  `http2`) and TLS decryption. They are listed as backlog in P8, after the
  reader is solid.

## 2. Constraints that shape the design

| Constraint | Consequence |
|---|---|
| Every V2 function is unstable; a binary loads only in the exact DuckDB build it targets | Pin `duckdb-neo` with `=`; rebuild and re-release per DuckDB release; stamp `C_STRUCT_UNSTABLE` |
| `main` already changed V2 string parameters and added functions after the 2.0.0 tag | Confine `duckdb-neo` usage to one module tree (`engine/`); budget an upgrade pass per release |
| Filter-pushdown and expression API is expected to change before stabilisation | Translate expressions to our own predicate type in one file; the scan never sees `Expression` |
| A panic in a `duckdb-neo` callback becomes an INTERNAL error that invalidates the database | Wrap our callback bodies in `catch_unwind` and return an ordinary error; build with `panic = "unwind"` |
| `Context` and `FileSystem<'link>` are callback-scoped; `File` is `Send`, not `Sync`, and may outlive the callback | Never store a `Context` or `FileSystem`; each worker opens its own `File` and keeps it in local state |
| `build-extension` and `build-extension-static` are mutually exclusive features | The loadable crate and the in-process test crate cannot be built in one `cargo` invocation (section 3) |
| `duckdb-neo` needs Rust 1.88, edition 2024 | The DuckDB crates set their own `rust-version`; the workspace stays on edition 2021 |
| Neither C API decompresses | Keep core's `DecompressReader` (gzip, zstd); compressed files are read sequentially |

## 3. Crate layout

```
pcapsql-duckdb/
  Cargo.toml              # rlib "pcapsql_duckdb": all logic, no extension feature chosen here
  src/
    lib.rs                # pub fn register(ext_or_conn) -> Result<()>
    engine/               # the only code that imports duckdb_neo
      table.rs            # TableFunctionCallbacks impls, builder wiring
      pushdown.rs         # Expression -> ScanPredicate
      fs.rs               # DuckFile: Read adapter over duckdb_neo::file::File
      writer.rs           # typed column writers into DataChunkRef
      scalar.rs, macros.rs, replacement.rs, options.rs, registry.rs
      guard.rs            # catch_unwind + error conversion for every callback
    scan/                 # engine-neutral, unit-testable without DuckDB
      plan.rs             # projected columns -> ParseScope + column plan
      predicate.rs        # ScanPredicate (frame / time ranges), range trimming
      partition.rs        # partition queue, claim logic
      schema.rs           # core DataKind -> logical column description
      source.rs           # open-sequential / open-at over any Read
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
  of bind, scan, chunk writing and scalars, which the current crate cannot
  have. It is excluded from the workspace's default members and built in its
  own CI step, because of the mutually exclusive features.
- `scripts/append_metadata.py` and the hand-written Makefile are deleted in
  favour of `extension-ci-tools` (`CAPI_VERSION=2`, `USE_UNSTABLE_C_API=1`,
  `TARGET_DUCKDB_VERSION=v2.0.0`).

## 4. SQL surface

### 4.1 Table functions

| Function | Notes |
|---|---|
| `read_pcap(files, protocol := 'frames', ...)` | Generic entry; schema depends on `protocol` |
| `read_<proto>(files, ...)` for every parser in core's registry | Generated from the registry at load, not a hand-kept list |
| `pcap_protocols()`, `pcap_schema(protocol)` | Derived from the same schema mapping the scans use |

`files` is a path, a glob, or a list of either (multi-file wrapper, P5).
`protocol` moves from the second positional argument to a named parameter;
the multi-file wrapper requires the file to be the only positional parameter.
This is a breaking change to an extension that has no releases.

Named parameters common to all scan functions:

| Parameter | Default | Meaning |
|---|---|---|
| `all_layers` | `true` | Emit every occurrence of the protocol in a frame (tunnels). `false` emits the outermost only. Resolves today's `read_pcap` / `read_tcp` inconsistency |
| `strict` | `false` | `true` turns a truncated capture into an error; default matches core and the CLI (warn and stop) |

Engine-provided once wrapped: `filename`, `hive_partitioning`,
`union_by_name`.

### 4.2 Columns

Every scan table starts with the same three columns:

| Column | Type | Source |
|---|---|---|
| `frame_number` | UBIGINT | reader position, not an extension-side counter |
| `timestamp` | TIMESTAMP_NS | core's nanosecond timestamp, no truncation |
| `encap_depth` | USMALLINT | 0 for the outermost occurrence of the protocol |

Then the parser's fields. `frames` adds `length`, `original_length`,
`link_type`.

Decisions to confirm in P2 (recommendations given):

- **Column names.** Today they are dotted (`"dns.answer_ip4s"`) and must be
  quoted. Recommendation: drop the protocol prefix (`answer_ip4s`), since the
  table already names the protocol.
- **Type mapping.** Follow core's `DataKind` exactly, with a column-typed
  writer that coerces the `FieldValue` to the declared kind. This fixes the
  NULL `dns.answer_ip6s` list (IP elements in lists) and the stale
  `format_ip4(src_ip)` doc example. `TimestampMicros` fields map to
  TIMESTAMP.

### 4.3 Scalars, macros, replacement scan, settings

- The 16 existing scalar functions are ported to `duckdb_neo::scalar`, reading
  inputs through the vector reader API so constant and dictionary vectors are
  handled.
- The six `format_*` macros are registered with `MacroFunctionBuilder`
  (extension-owned), replacing `CREATE OR REPLACE MACRO` on the load
  connection.
- A replacement scan maps `FROM 'x.pcap'`, `.pcapng`, `.cap` and their `.gz` /
  `.zst` forms to `read_pcap(path)`.
- One setting to start with: `pcapsql_index_cache_dir` (section 5.4).

## 5. Scan architecture

### 5.1 Callback mapping

One generic implementation `PcapScan` of `TableFunctionCallbacks`, registered
once per protocol with the protocol name as instance data.

| Callback | Work |
|---|---|
| `bind` | Resolve protocol, declare columns, open the file once to read the header (format, link type, compression, size), set a cardinality estimate, store `BindData { path, protocol, header, file_size, predicate: Mutex<ScanPredicate> }` |
| `pushdown_filter` | Translate offered filters into `ScanPredicate`; accept the ones we enforce exactly (5.5) |
| `init_global_state` | Build the `ScanPlan` from projected columns; decide partitioning; create the partition queue and progress counters |
| `max_threads` | Number of partitions, capped; 1 for compressed or unindexed sources |
| `init_local_state` | Allocate the worker's row writer and scratch buffers; no file yet |
| `claim_batch` | Pop the next partition, open a `File`, construct the reader at that range, store both in local state |
| `exec` | Pull packets, parse with the plan's `ParseScope`, write up to chunk capacity |
| `partition_data` | Report the partition ordinal as batch index, so output keeps frame order under parallelism |
| `progress` | Bytes consumed across workers divided by total bytes |

### 5.2 File access

`engine::fs::DuckFile` wraps `duckdb_neo::file::File` and implements
`std::io::Read` with an internal buffer (default 1 MiB, larger for remote
paths as reported by `FileSystem::is_remote`). Each reader owns one `File`,
opened inside the callback that needs it from that callback's `Context`.

Core's `PacketSource` cannot be implemented directly, because
`sequential_reader(&self)` has no way to receive a `Context`. Instead the
extension uses two constructors added to core in P1:

- open a sequential reader over any `Read`, returning header metadata;
- open a reader at a `PacketRange` over a `Read` already positioned at the
  range's byte offset, given the header metadata.

`FilePacketSource` and `CloudPacketSource` are reimplemented on top of these
so there is one code path. No `std::fs` call remains in `pcapsql-duckdb`; a
clippy `disallowed-types` rule enforces it.

### 5.3 Projection and the row writer

`init_global_state` maps the projected column indices to:

- a `ParseScope` restricted to the protocol plus its dependency closure, with
  a field projection for that protocol. A query that touches only
  `frame_number`, `timestamp` or `frames` columns parses no protocol at all;
- a `ColumnPlan`: for each output vector, the field slot and a typed writer.

The writer fetches each vector's data pointer and validity mask once per
chunk, writes by column type, and allocates strings and blobs from the
vector's arena. The per-row `HashMap` walk and per-string `CString` go away.

Chunk boundaries: `exec` stops when the next frame's rows would not fit the
chunk's capacity and keeps that frame's parsed rows in local state for the
next call. This removes the `"batch full"` string-matched pseudo-error and the
possible over-capacity write for tunnelled frames. It needs a pull-style or
`ControlFlow`-returning read call in core (P1).

### 5.4 Parallelism and the boundary index

Partitioning uses core's `BoundaryIndex` (a header-only pass that records a
checkpoint every 65,536 frames).

| Source | Behaviour |
|---|---|
| Local, uncompressed | Build the index in `init_global_state` when the file is large enough to benefit; partition; `max_threads` = partitions |
| Remote, uncompressed | Partition only if a cached index exists; otherwise scan sequentially on one thread and, if the cache is enabled, write the index as a by-product |
| Compressed | One partition, one thread |

Index persistence is opt-in through `pcapsql_index_cache_dir`. The cache is
read and written through DuckDB's file system, keyed by path, size and
header hash as core already does, so no file is written next to a capture
without the user asking.

Across files, the multi-file wrapper distributes files to threads; within a
file our `claim_batch` distributes partitions.

### 5.5 Filter pushdown

`engine/pushdown.rs` recognises comparisons and `BETWEEN`-style conjunctions
between `frame_number` or `timestamp` and a constant, and folds them into
`ScanPredicate { frames: Range, time_ns: Range }`. Everything else is left to
DuckDB.

The predicate is used in two ways:

- **Trimming.** Partitions wholly outside the ranges are dropped using index
  checkpoints; with no index, a `frame_number` upper bound still ends the scan
  early.
- **Exact row filter.** Each packet's frame number and timestamp are checked
  before parsing, so accepted predicates are enforced exactly, as V2 requires.

When the function is wrapped by a multi-file function, DuckDB offers the
filters as hints and reapplies them itself; the same code path then only
skips work. Predicates on parsed protocol fields are not accepted in this
roadmap: they would save row materialisation only, not parsing.

### 5.6 Errors, panics, logging

- I/O and format errors return a `duckdb_neo::Error` from the callback. `exec`
  no longer treats errors as end of data.
- A capture that ends mid-record follows core: stop, and emit a warning
  through `Log::log_on_context`. With `strict := true` it is an error.
- `engine/guard.rs` runs every callback body under `catch_unwind` and converts
  a panic into an ordinary error naming the callback.
- `tracing` output is routed to DuckDB's log through the context where one is
  available.

## 6. Changes needed in `pcapsql-core`

| ID | Change | Used by |
|---|---|---|
| C1 | Public constructors: sequential reader over any `Read`, and reader at a `PacketRange` over a positioned `Read`; move `FilePacketSource` and `CloudPacketSource` onto them | 5.2 |
| C2 | A read call that lets the consumer stop without an error and without consuming the next packet (pull-style `next_packet`, or a callback returning `ControlFlow`) | 5.3 |
| C3 | `build_boundary_index` and index (de)serialisation usable with a caller-supplied reader and byte sink, with no `Path` assumption | 5.4 |
| C4 | Slot-indexed field access for a parser's output (field order fixed by `schema_fields()`), so writers do not look fields up by name | 5.3 |
| C5 | Expose per-layer encapsulation depth in parse results if it is not already available to consumers | 4.2 |

C1 to C3 are prerequisites; C4 and C5 can land during P2. All are additive and
also benefit the DataFusion frontend.

## 7. Roadmap

Each phase ends with the listed exit checks passing in CI. Phases P3 to P6 are
independent of each other after P2 and can be reordered.

### P0: Spike and scaffolding

- Create the crate layout of section 3 with a trivial table function and one
  scalar.
- Adopt `extension-ci-tools`; produce `pcapsql.duckdb_extension` for
  `linux_amd64`; add a CI job that downloads DuckDB 2.0.0 and loads it.
- Stand up `itest/` with a statically registered extension and one query.
- Resolve every item in section 9 and record the answers in this document.
- Fix the manifest drift: `duckdb-neo = "=0.20000.2"`, remove `duckdb`,
  `libduckdb-sys` and `duckdb-loadable-macros` 0.1.

Exit: CI builds the artifact, `LOAD` succeeds in DuckDB 2.0.0, one `itest`
query passes, section 9 is filled in.

### P1: Core seams

- C1, C2, C3 with unit tests in `pcapsql-core`; DataFusion suite unchanged and
  green.

Exit: a core test reads a capture, sequentially and at a partition offset,
through a custom `Read` implementation with no `std::fs` in the reader path.

### P2: Sequential reader on V2

- `PcapScan` with bind, global and local init, exec; one thread; no pushdown.
- `DuckFile`; all opens through DuckDB's file system.
- Schema of section 4.2, typed writer, chunk carry-over, C4, C5.
- Error and truncation behaviour of section 5.6; panic guard.
- Registry-driven registration; `pcap_protocols`, `pcap_schema`.
- Port scalars and macros.
- Delete `vtab/`, `udf/`, `macros.rs`, `duckdb_schema.rs` of the old crate.
- Tests: per-protocol golden results over `testdata/` in `itest/`, and a
  differential test comparing DuckDB output with the DataFusion CLI for the
  same queries.

Exit: every protocol table matches DataFusion on the corpus; the three defects
inferred by the audit (NULL `answer_ip6s`, over-capacity chunk, silent
truncation) have regression tests.

### P3: Projection pushdown, cardinality, progress

- `with_projection_pushdown(true)`; `ScanPlan` and `ParseScope` per 5.3.
- Cardinality estimate at bind (exact when a cached index gives a frame
  count).
- Progress callback.

Exit: a test asserts that a `frame_number`-only query runs no protocol
parser; benchmark shows the expected drop against P2 for narrow projections.

### P4: Parallel scans

- Index build and partition queue; `claim_batch`; `max_threads`.
- `partition_data` batch indices for order preservation.
- `pcapsql_index_cache_dir` and cache I/O through DuckDB's file system.

Exit: results identical to the single-threaded scan on the corpus at 1, 2 and
8 threads, including row order without `ORDER BY`; benchmark shows scaling on
a large uncompressed capture.

### P5: Multi-file, replacement scan, remote

- Register single-file functions as `read_<proto>_file`; wrap each with
  `MultiFileFunctionBuilder` under the public name; `TableGetBindInfoCallbacks`
  if the wrapper needs it for column mapping.
- Replacement scan.
- Remote tests: `httpfs` against a local HTTP server and an S3-compatible
  store, reusing the setup of the existing cloud-integration workflow;
  buffer-size tuning for remote reads.

Exit: glob, list, `filename` and `FROM 'x.pcap'` tests pass; an `s3://` capture
is read with credentials supplied only through a DuckDB secret.

### P6: Filter pushdown

- `engine/pushdown.rs`, `ScanPredicate`, partition trimming and exact row
  filter per 5.5.

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
- Upgrade runbook (section 8) written down and exercised once.

Exit: `INSTALL pcapsql FROM community; LOAD pcapsql;` works on the supported
platforms.

### P8: Backlog after the reader

Not scheduled; each needs its own design.

- `<proto>_packets`-style table macros joining lower layers.
- Stream tables and TLS decryption (keylog path as a named parameter or
  secret).
- Remaining DataFusion UDFs.
- `COPY ... TO 'x.pcap'`.
- Sharing one parse across several protocol tables in a single query.

### P9: Follow V2 to stability

- When a DuckDB release adds them: statistics callback (min/max of
  `timestamp` and `frame_number` from the index) and the `file_row_number`
  virtual column.
- When DuckDB marks table functions and the file system stable: switch the
  stamp from `C_STRUCT_UNSTABLE` to `C_STRUCT`, drop per-release rebuilds, and
  set the minimum DuckDB version.

## 8. Tracking an unstable API

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

## 9. Things to verify in the P0 spike

| ID | Question | Why it matters |
|---|---|---|
| U1 | Does a `C_STRUCT_UNSTABLE` neo extension built with `extension-ci-tools` load in the stock DuckDB 2.0.0 CLI on our CI image? | Basic viability |
| U2 | Can `itest/` link DuckDB without compiling it from source (`buildtime-download`), and how long does the job take? | CI time |
| U3 | Does the workspace build cleanly with `ext/` and `itest/` selecting different `duckdb-neo` features, when built in separate invocations? | Crate layout |
| U4 | May a `File` opened in `claim_batch` or `init_local_state` be used from later `exec` calls on that worker? | 5.1, 5.2 |
| U5 | Are several chunks with the same batch index accepted by `partition_data`, or must each chunk have its own? | 5.1 order preservation |
| U6 | Does the multi-file wrapper call our single-file `pushdown_filter` with hint filters, and does it use our `claim_batch` for intra-file parallelism? | 5.4, 5.5 |
| U7 | Do `s3://` and `https://` opens through `FileSystem` pick up secrets, and what read sizes perform acceptably? | Goal 2 |
| U8 | Which DuckDB vector type and writer does `duckdb-neo` expose for TIMESTAMP_NS, BLOB and LIST columns, and is arena allocation available from `DataChunkRef`? | 5.3 |
| U9 | Can a replacement scan pass through a default `protocol` and still allow the multi-file options? | 4.3 |
| U10 | Does the neo crate compile for `wasm32-unknown-emscripten` with core's compression dependencies? | P7 |

## 10. Risks

| Risk | Mitigation |
|---|---|
| V2 breaks at every DuckDB release until stabilised | Section 8; `engine/` containment |
| Filter-pushdown API is redesigned | Only `pushdown.rs` depends on it; P6 is last of the reader phases and can wait for 2.1 |
| Multi-file wrapper is immature (no in-tree test upstream) | P5 keeps the single-file functions public as `read_<proto>_file`, so the reader works without the wrapper |
| A panic invalidates the user's database | `guard.rs`; fuzz corpus run through `itest/` |
| Index build over a remote file is a full sequential read | Remote files partition only from a cached index (5.4) |
| DuckDB 2.1 changes arrive mid-roadmap | Canary job; finish P2 before chasing new API |
| CI cost of linking DuckDB for `itest/` | U2; fall back to sqllogictests against the CLI only |
