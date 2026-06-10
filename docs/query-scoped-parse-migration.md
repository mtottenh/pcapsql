# Migration plan: query-scoped parsing

**Status:** P0–P6 implemented (PRs #99–#105). P5/P6 scoped as noted in their sections.
**Baseline:** stack tip `21c2834` (stage 9, PR #97); all `file:line` references are anchors into that commit and will drift — symbols are authoritative.
**Relates to:** #88 (epic), closes #83 and #86, preserves the invariants behind #84/#85/#87.

---

## 1. Problem statement

The engine binds **all** parsing and **all** Arrow materialization to engine
construction, before any query exists, and retains everything for the life of
the engine:

- `QueryEngine::with_streaming_source_partitions` runs `run_shared_parse`
  (`query/mod.rs:294`) to completion — every packet, every protocol layer,
  every table, every column — then registers providers over the finished
  batches. `ProtocolScanExec::execute` merely streams pre-built batches and
  applies `batch.project()` after the fact (`scan_exec.rs:113-125`).
- The frames builder copies every packet's bytes into the `raw_data` Binary
  column unconditionally (`builders/protocol.rs:519`) — a second in-RAM copy
  of the capture, even for `SELECT count(*)`.
- `filters` and `limit` are ignored by both providers (`provider.rs:48-49`,
  `protocol_provider.rs:85-86`); `supports_filters_pushdown` is not
  implemented. By the time DataFusion calls `scan(projection, filters,
  limit)`, all the work has already happened. **No pushdown can ever reach a
  parse that has already run.**

Three places where the code now contradicts itself:

1. `with_streaming` docs promise *"packets are read on-demand … bounded
   memory usage"* (`query/mod.rs:248-251`). The implementation materializes
   the entire capture.
2. The `--streaming` CLI help promises *"supports filter/limit pushdown …
   packets are read on-demand during query execution"* (`cli/args.rs:138-143`).
   Neither is true.
3. The `--stats` help says *"Useful for tuning --cache-size"*
   (`cli/args.rs:193-198`) — the cache and `--cache-size` were deleted in
   stage 4 (#92).

And the codebase carries an architecture it never adopted — machinery built
for demand-driven parsing, stranded because the eager engine has no query to
scope against:

| Orphaned component | Location | Call sites in production |
|---|---|---|
| `parse_packet_pruned` | `protocol/mod.rs:263` | 0 |
| `parse_packet_projected` | `protocol/mod.rs` (referenced at `:459`) | 0 |
| `parse_packet_pruned_projected` | `protocol/mod.rs:437` | 0 |
| `compute_required_protocols`, `should_continue_parsing` | `protocol/pruning.rs:47,99` | 0 |
| `ProjectionConfig` | `protocol/projection.rs:29` | 0 |
| `FilterEvaluator` | `query/filter.rs` (re-exported `query/mod.rs:37`) | 0 |
| `QueryEngine::auto` + `STREAMING_THRESHOLD_BYTES` | `query/mod.rs:402,72` | 0 |
| `build_tcp_connections_batch`, `build_tls_sessions_batch`, `build_http_messages_batch` + schemas | `query/tables/{tcp_connections,tls_sessions,http_messages}.rs` (exported `tables/mod.rs:54,69,72`) | 0 |
| `FramesBatchBuilder`, `frames_schema` | `query/frames.rs` (re-exported `query/mod.rs:38`) | 0 |
| `NormalizedBatchSet::add_packet` (legacy `RawPacket` path) + `ProtocolBatchBuilder::add_frame` | `builders/normalized.rs:80`, `builders/protocol.rs:445` | 0 (tests only) |

This plan replaces the architecture **and** deletes every superseded path in
the same phase that obsoletes it. No parallel APIs, no transition flags that
outlive their phase, no "old path kept just in case."

## 2. Design principles

1. **The query scopes the work.** Parsing happens at query time, restricted
   to the protocols, columns, predicates, and row limits the optimized plan
   actually demands.
2. **Retention is a policy, not a default.** One-shot queries retain nothing;
   the REPL caches per-table results as a side effect of queries that touch
   them.
3. **Every phase deletes what it replaces.** A phase is not done until the
   code it supersedes is gone, including its exports, flags, help text, and
   tests of removed behavior.
4. **Every phase is independently green.** `cargo fmt --check`, `clippy
   --workspace --all-targets -D warnings`, `cargo test --workspace`,
   `cargo check -p pcapsql-datafusion --features s3 --tests`, plus the golden
   query corpus (§7) and benchmark gates (§8).
5. **Invariants are non-negotiable** (§7): one parse pass per query,
   1-vs-N partition equivalence, frame-number ordering, identical SQL
   results across phases.

## 3. End-state architecture

```
                       ── per query ──
SQL ─► DataFusion logical plan; optimizer pushes projection / filters /
       fetch into TableScan nodes (provider returns Inexact pushdown)
            │
            ▼  harvest TableScans → QueryNeeds
       ParseScope { protocol closure, per-protocol field projection,
                    predicates (one-shot only), fetch (one-shot only) }
            │
            ▼
       Parse drivers — one per partition (existing partition machinery,
       zone-map chunk skipping); callback loop over PacketRef:
         parse_packet(registry, link_type, data, &scope)
         → FilterEvaluator pre-Arrow row skip (one-shot)
         → subscribed builders only; raw_data never copied (offsets)
            │  bounded channel per (table × partition); overflow → tracked
            ▼  in-memory buffer (never deadlock, degrades to today)
       ProtocolScanExec::execute(i) = RecordBatchReceiverStream
            │
            ▼
       DataFusion pulls; RetentionPolicy::CacheOnTouch tees full-column
       table batches into the engine cache for the REPL
```

### 3.1 Public API end state

```rust
// pcapsql-datafusion
pub enum SourceSpec { Path(PathBuf), Url(String) }            // local | cloud
pub enum RetentionPolicy { None, CacheOnTouch }               // one-shot | REPL
pub struct EngineOptions {
    pub batch_size: usize,
    pub target_partitions: Option<usize>,                     // None = available_parallelism
    pub retention: RetentionPolicy,
    pub keylog: Option<Arc<KeyLog>>,
    pub mmap: bool,                                           // local default: true
    pub cloud: CloudOptions,                                  // endpoint/anonymous/chunk_size
    pub progress: Option<Arc<dyn Fn(u64) + Send + Sync>>,     // packets seen
}
impl QueryEngine {
    pub async fn open(spec: SourceSpec, opts: EngineOptions) -> Result<Self>;
    pub async fn query(&self, sql: &str) -> Result<Vec<RecordBatch>>;
    pub fn last_parse_stats(&self) -> ParseStats;             // replaces parse_pass_count/partition_count
}
```

```rust
// pcapsql-core — ONE parse entry point
pub struct ParseScope { /* Full, or { required: closure set, fields: per-protocol projection } */ }
pub fn parse_packet<'a>(
    registry: &ProtocolRegistry, link_type: u16, data: &'a [u8], scope: &ParseScope,
) -> Vec<(&'static str, ParseResult<'a>)>;
```

Eight constructors collapse to one. Four parse functions collapse to one.
Two `TableProvider`s collapse to one. There is no eager mode: on small files,
`CacheOnTouch` converges to today's behavior after the first queries, without
a second code path.

### 3.2 The retention/pushdown policy matrix

This single table resolves the cache-coherence question that otherwise makes
scoped parsing unsound for the REPL:

| | Protocol pruning | Column projection | Predicates at parse | LIMIT early-stop | Retained |
|---|---|---|---|---|---|
| `RetentionPolicy::None` (one-shot CLI) | yes | yes | yes (Inexact — DataFusion re-checks) | yes | nothing |
| `RetentionPolicy::CacheOnTouch` (REPL) | yes (touched tables) | no — full columns per touched table | no | no | per-table batches |

Rationale: a cached table must satisfy **any** later query, so the REPL caches
full-column, unfiltered tables (reuse is trivially sound; a later query
touching a cached table re-parses nothing). One-shot pushes everything down
because nothing is reused. Predicates are always re-checked by DataFusion
(`Inexact`), so parse-time filtering can never change results.

### 3.3 What survives unchanged

The source/reader/index layer (stages 2–7 of the current stack) is already
the right shape for this architecture and is untouched except for two small
additions (a `byte_offset` on `PacketRef` in P5, checkpoint presence sets in
P6): zero-copy callback reader, `SeekablePacketSource` partitioning,
`BoundaryIndex` + sidecar, compression handling in the sources
(`source.rs:434-439`, `cloud.rs:828`) with single-partition fallback for
compressed streams (`source.rs:408-412`). The sorted-by-`frame_number` +
sort-merge-join design and the schemas also survive — they are load-bearing
for the bounded-exchange design in P3.

---

## 4. Phases

Each phase = one stacked PR (P3 may be two). Per-phase sections list:
**goal → changes → deletions → tests → gate**. Deletion lists are exhaustive
at file/symbol granularity.

### P0 — Truth, baselines, and dead-code removal

*Goal: make the codebase stop lying, delete code that is dead today, and
freeze the measurements every later phase is judged against.*

Changes:
- Add `benches/` (Criterion) with the baseline suite (§8) over committed
  `pcapsql-testgen` fixture specs: `l4_only`, `tls_heavy`, `dns_heavy`,
  `payload_heavy` at two sizes.
- Add the **golden query corpus** test (§7): fixed-seed captures × a query
  list covering every table and view, results snapshotted. Every later phase
  must produce byte-identical results.
- Rewrite `with_streaming` rustdoc (`query/mod.rs:247-261`) to describe what
  the code does today (eager parallel load), so P2/P3 change docs and code
  together, not docs first.
- Fix `--stats` help (`cli/args.rs:193-198`): describe current output;
  `--cache-size` reference removed (flag is repurposed for `ParseStats` in P2).

Deletions:

| Item | Location |
|---|---|
| `QueryEngine::auto` (zero callers) | `query/mod.rs:402-425` |
| `STREAMING_THRESHOLD_BYTES` (only user was `auto`) | `query/mod.rs:70-72` |
| `build_tcp_connections_batch` + `tcp_connections_schema` + module (zero callers; tables are not registered for SQL — `tables/mod.rs:108-139` excludes them) | `query/tables/tcp_connections.rs`, exports `tables/mod.rs:69` |
| `build_tls_sessions_batch` + `tls_sessions_schema` + module | `query/tables/tls_sessions.rs`, export `tables/mod.rs:72` |
| `build_http_messages_batch` + `http_messages_schema` + module | `query/tables/http_messages.rs`, export `tables/mod.rs:54` |
| `FramesBatchBuilder` + `frames_schema` + module (zero callers; `tables/frames.rs` owns the real schema) | `query/frames.rs`, export `query/mod.rs:38` |
| `NormalizedBatchSet::current_batches` (unused accessor) | `builders/normalized.rs:197` |

P4 re-introduces stream tables as *real, queryable* tables built by a
subscriber; today's builders were never reachable from SQL and their shape
(post-hoc batch conversion of a second pass) is not the shape P4 needs.
Deleting now follows principle 3; git history preserves the column designs.

Tests: golden corpus added; benches added; tests of deleted items removed.
Gate: standard gates; benchmark baselines recorded in the PR description.

### P1 — One engine path

*Goal: a single constructor and a single provider; the in-memory duplicate
engine and the legacy whole-file reader are deleted. Behavior is otherwise
unchanged (still eager — the binding move is P2).*

Changes:
- `QueryEngine::open(SourceSpec, EngineOptions)`: builds
  `MmapPacketSource` (local default) / `FilePacketSource` (`mmap: false` or
  mmap failure) / `CloudPacketSource` (`Url`), then runs the existing eager
  shared parse. Small files take the same path as large ones (mmap +
  `SeekCost::Free` partitioning ≥ the old in-memory path).
- `keylog` becomes `EngineOptions.keylog`; when set, `open` runs the existing
  `StreamTableBuilder` second pass (its deletion is P4's job) and registers
  `http2` batches via `ProtocolTableProvider::in_memory`
  (`protocol_provider.rs:46`) — the duplicate provider is not needed for this.
- Port `StreamTableBuilder::process_pcap` from `PcapReader::open(path)`
  (`stream_tables.rs:58`) to `source.sequential_reader()`, removing the last
  consumer of `PcapReader`. Compression parity is held by the sources
  (`source.rs:434-439`); compressed inputs already degrade to a single
  partition (`source.rs:408-412`).
- `EngineOptions.progress`: the parse loop counts packets through an
  `AtomicU64` + callback, replacing the `indicatif` spinner wired into
  `load_normalized_packets`; the CLI keeps `--progress` and renders the bar.
- CLI (`main.rs:66-137`): mode-selection `match` collapses to
  `SourceSpec`/`EngineOptions` construction. `--streaming` is deleted (there
  is one path now); `--mmap` becomes `--no-mmap` (mmap default).
- REPL/`run_repl` and one-shot both consume `QueryEngine::open`.

Deletions:

| Item | Location |
|---|---|
| `QueryEngine::new`, `with_progress`, `with_keylog`, `with_streaming`, `with_streaming_source`, `with_streaming_source_partitions`, `with_cloud_source` (all folded into `open`) | `query/mod.rs:99-387` |
| `load_normalized_packets` | `query/mod.rs:431-492` |
| `extract_timestamp_range` (shared pass already tracks the range — `query/mod.rs:308`) | `query/mod.rs:497-532` |
| `PcapTableProvider` + module (in-memory engine's provider; `MemorySourceConfig` registration path) | `query/provider.rs`, export `query/mod.rs:39` |
| `PcapReader` (legacy whole-file reader; double-open/redetect — **closes #83**) + its `lib.rs`/prelude exports | `pcapsql-core/src/pcap/reader.rs` |
| `RawPacket`-based builder APIs: `NormalizedBatchSet::add_packet`, `ProtocolBatchBuilder::add_frame`; tests rewritten against `PacketRef` | `builders/normalized.rs:80-112`, `builders/protocol.rs:445-477` |
| `RawPacket` itself if the above leaves zero consumers (verify `pcapsql-core` exports; `pcapsql-duckdb` does not use it) | `io/source.rs:115` |
| CLI `--streaming` flag + help (`args.rs:138-144`); `indicatif` dependency if unused after | `cli/args.rs`, `Cargo.toml` |

Tests: `engine_shared_parse.rs` and `cloud_integration.rs` move from
`with_streaming_source_partitions` to `open` with explicit
`target_partitions`; golden corpus must not change.
Gate: standard + golden + benches within noise of P0 (this phase must not
regress; mmap-for-small-files may improve `engine_build`).

### P2 — The binding move: query-scoped parse

*Goal: parsing happens per query, scoped by the optimized plan. The
construction-time parse is gone. The four parse entry points become one.
Closes #86 (filter pushdown reaches the parse).*

Changes:
- `ProtocolTableProvider::supports_filters_pushdown` → `Inexact` for
  supported predicate shapes, so the optimizer places filters into
  `TableScan.filters` and **keeps** re-checking them.
- `QueryEngine::query`: plan first (`SessionState::create_logical_plan` +
  `optimize`), walk `TableScan` nodes, harvest per-table
  `projection`/`filters`/`fetch` into `QueryNeeds`; map table set →
  protocol closure (`compute_required_protocols`), columns →
  `ProjectionConfig`, predicates → `FilterEvaluator` predicates, `fetch` →
  row caps — per the policy matrix (§3.2). Then run the (still-eager-internals)
  shared parse **scoped**, register/refresh providers, execute the physical
  plan.
- **Parse API unification** in `pcapsql-core`: `parse_packet` gains
  `scope: &ParseScope`; the bodies of `parse_packet_pruned`,
  `parse_packet_projected`, and `parse_packet_pruned_projected` fold into it.
  `pcapsql-duckdb` call sites (`vtab/read_pcap.rs:228`,
  `vtab/protocol_tables.rs:179`) pass `ParseScope::full()` in this phase (its
  vtabs receive DuckDB projection info and can adopt scoping as follow-up).
- `NormalizedBatchSet::new(batch_size, subscriptions)`: builders exist only
  for subscribed tables; within a table, only subscribed columns get builders
  (`RetentionPolicy::None`) — `scan` returns batches already in projected
  shape, replacing `ProtocolScanExec`'s post-hoc `batch.project()`
  (`scan_exec.rs:120-125`). `raw_data` is built only when projected (interim
  until P5 removes the copy entirely).
- `SharedParseState` becomes per-query `QueryParseResult`;
  `RetentionPolicy::CacheOnTouch` keeps a `table → Vec<Vec<RecordBatch>>`
  cache (full columns, unfiltered) consulted before parsing; a query touching
  only cached tables parses nothing.
- `ParseStats { packets_scanned, rows_built: per table, partitions,
  parse_passes }` replaces `parse_pass_count`/`partition_count`
  (`query/mod.rs:566-577`); CLI `--stats` prints it (help fixed in P0).
- `create_session_context`: `target_partitions` from
  `EngineOptions.target_partitions.unwrap_or(available_parallelism)`,
  replacing the hardcoded `2` (`query/mod.rs:79`); the 1-vs-N equivalence
  suite and golden corpus guard ordering/SMJ behavior.
- `ProtocolScanExec` implements `statistics()` with exact row counts (free
  after the scoped parse).

Deletions:

| Item | Location |
|---|---|
| `parse_packet_pruned`, `parse_packet_projected`, `parse_packet_pruned_projected` as public entry points (logic folded into `parse_packet(.., &ParseScope)`) | `protocol/mod.rs:263-`, `:437-` |
| Construction-time parse: the `run_shared_parse` call and frame-count/timestamp bootstrapping in `open` (time-UDF registration moves to first query / lazily from `ParseStats`) | `query/mod.rs:294-309` |
| `parse_pass_count`, `partition_count` (superseded by `last_parse_stats`) | `query/mod.rs:560-577` |
| Post-hoc projection in `execute` (batches are born projected) | `scan_exec.rs:120-125` |
| The "registered table must pre-exist in shared state" assumption in `ProtocolTableProvider::partitions` (`TableSource::Shared` arm re-keyed to the per-query state) | `protocol_provider.rs:59-65` |

Pruning, projection, and filter modules stop being vestigial — they become
the implementation of `ParseScope`. `FilterEvaluator` finally gets callers.

Tests: `engine_shared_parse.rs` re-targets the invariant — *one parse pass
per query* (was: per engine); add scoped-parse tests (`SELECT src_port FROM
tcp` must not run the TLS parser — assert via `ParseStats.rows_built` and a
registry instrumentation hook); REPL cache-reuse test (second query over a
touched table ⇒ `packets_scanned == 0`); golden corpus unchanged.
Gate: standard + golden + benches: `query_selective` and `engine_build` must
improve materially (`engine_build` becomes ~source-open); `query_full_scan`
within noise; REPL second-query latency within noise of P1.

### P3 — Streaming execution: bounded memory for one-shot

*Goal: `RetentionPolicy::None` never materializes a table; the
bounded-memory promise deleted from the docs in P0 becomes true. LIMIT stops
reading the file early.*

Changes:
- `run_shared_parse`'s internals (`shared.rs:153-246`) are replaced by
  `run_parse_drivers`: per-partition `std::thread` drivers push completed
  `RecordBatch`es into bounded per-(table × partition) channels
  (`tokio::sync::mpsc` bridged by DataFusion's `RecordBatchReceiverStream`).
  `ProtocolScanExec::execute(i)` returns the receiver stream; pre-built-batch
  serving (`scan_exec.rs:113-130`) is rewritten.
- **Overflow policy (the deadlock answer):** `try_send`; on a full channel the
  driver moves the batch into a tracked per-table overflow buffer and
  continues. Divergent consumption (e.g., a hash-join build side draining one
  table first — `prefer_hash_join = false` is a preference, not a guarantee)
  degrades to P2's memory behavior for that table instead of deadlocking.
  Overflowed bytes are reported in `ParseStats`. Frame-ordered co-consumption
  under SMJ keeps buffers small in the common case.
- LIMIT early-stop: each driver checks an `AtomicBool` set when every
  subscribed table has satisfied its `fetch`; drivers stop reading the source.
- `CacheOnTouch` uses the same drivers, draining streams to completion and
  teeing into the cache — one execution path for both policies.
- Self-join note: two scans of one table become two receivers on one parse
  stream (broadcast with per-receiver overflow), or — simpler and chosen
  here — the planner-walk detects duplicate table refs and pins that table to
  buffered mode. Add a regression test either way.

Deletions:

| Item | Location |
|---|---|
| Materialize-then-serve internals of the shared pass: partition result collection, `tables: HashMap<String, Vec<Vec<RecordBatch>>>` reorganization | `shared.rs:153-246` |
| `SharedParseState` + accessors (`table_partitions`, `num_partitions`, `parse_passes`, `timestamp_range_us`, `total_frames`) — replaced by the per-query exchange + `ParseStats` + cache | `shared.rs:37-76` |
| `TableSource::Shared` enum arm (providers hold the exchange/cache handle) | `protocol_provider.rs:29-34` |

Tests: memory ceiling test (synthetic 1 GB-scale capture; assert peak
`bytes_allocated` via an allocator-counter feature stays `O(channels ×
batch_size)`, not `O(capture)`); LIMIT early-stop test (assert
`packets_scanned < total` via `ParseStats`); hash-join-forced overflow test
(flip `prefer_hash_join`, assert completion + overflow metric > 0); golden
corpus + 1-vs-N equivalence unchanged.
Gate: standard + golden + benches: `query_limit` order-of-magnitude better;
peak RSS on `payload_heavy` bounded; throughput benches within noise of P2.

### P4 — Stream analysis joins the single pass

*Goal: the keylog/HTTP-2 second read of the capture is deleted; TCP
reassembly becomes a subscriber of the same parse pass. Stream tables return
as real, queryable tables.*

Changes:
- `StreamSubscriber` consumes the per-packet callback **with the already-parsed
  layers** (`Vec<(&str, ParseResult)>`) — deleting `StreamTableBuilder`'s
  private re-parse of Ethernet/IP/TCP inside `process_packet`
  (`stream_tables.rs:84-`). Feeds `StreamManager` (reassembly → TLS decrypt →
  HTTP/2) exactly as today.
- Ordering constraint made explicit: stream reassembly requires whole-capture
  sequential order, so a `QueryNeeds` touching stream tables forces
  `partitions = 1` for that query (recorded in `ParseStats`; partitioned
  reassembly with connection handoff is future work, out of scope).
- `tcp_connections`, `tls_sessions`, `http_messages` come back as registered
  tables (added to `tables/mod.rs::all_table_names`), built by the subscriber;
  `http2` stops being a keylog-only special case
  (`query/mod.rs` interim registration from P1 deleted). Scoping maps these
  tables → "stream" requirement → subscriber attached + single partition.
- `EngineOptions.keylog` is consumed by the subscriber configuration.

Deletions:

| Item | Location |
|---|---|
| `StreamTableBuilder::process_pcap` (second full read) and its embedded Ethernet/IPv4/TCP mini-parser | `stream_tables.rs:57-…` |
| The P1 interim: keylog second-pass invocation + `ProtocolTableProvider::in_memory` http2 registration in `open` | `query/mod.rs` (P1 form) |
| `ProtocolTableProvider::in_memory` + the `TableSource` enum entirely, if the http2 interim was its last consumer (empty tables are served by the exchange with zero batches) | `protocol_provider.rs:29-57` |

Tests: keylog/HTTP-2 integration tests assert identical results to the
two-pass implementation (golden corpus gains a keylog fixture in this phase);
single-partition forcing asserted via `ParseStats`; stream tables get golden
entries.
Gate: standard + golden; keylog end-to-end wall-clock should drop ~2× on
IO-bound captures (one read, one parse).

### P5 — `raw_data` / heavy-column materialization is projection-gated

*Goal: the capture's bytes are never duplicated into Arrow unless a query
projects them.*

**Delivered:** the parse-time copy elimination landed in **P2** as a side
effect of column-scoped building — the frames builder only has a `raw_data`
builder when `raw_data` is in the subscribed columns, so an unprojected
`raw_data` is never copied. P5 closes the remaining gap on the
`CacheOnTouch` (REPL) path: the cache was holding **full** columns on first
touch (including the huge `raw_data` and unused wide-table columns). P5
makes the cache **column-aware** — it caches exactly the columns a query
touches, treats a later subset query as a hit, and re-parses + widens on a
column miss. So `raw_data` (and any heavy/unused column) stays out of the
cache until actually selected.

*Deferred (optional):* byte-offset / `BinaryView` zero-copy so that even a
query that **does** project `raw_data` references the mmap buffer instead of
copying. This needs reader byte-offset plumbing + per-source range reads +
a compressed-source fallback; the memory contract above does not depend on
it, so it is left as a follow-up rather than shipped half-built.

Original plan (superseded by the above):

Changes:
- `PacketRef` gains `byte_offset: u64` (`io/source.rs:34-48`; the readers
  already track record offsets for the index — `index.rs` consumes
  `consumed()` the same way).
- The frames builder stores `(byte_offset, captured_len)`; when `raw_data` is
  projected, the scan materializes the column per batch from the source: mmap
  slice copy for local, `reader_at`/range request for cloud (cost documented;
  it is the price of asking for payloads over a network — today's cost is
  paying it always). `hexdump` and the `packets` view exercise this path.
- Schema is unchanged externally (`raw_data: Binary`); a follow-up may adopt
  `BinaryView` over mmap-backed buffers for true zero-copy (out of scope).

Deletions:

| Item | Location |
|---|---|
| Unconditional `raw_data` byte copy: `append_binary(packet.data)` path and the `raw_data` arm of the frames builder | `builders/protocol.rs:483-523` (P2-evolved form) |
| `DynamicBuilder::append_binary` if the frames `raw_data` arm was its only caller | `builders/protocol.rs:320-325` |

Tests: golden corpus (includes `raw_data`-projecting queries) byte-identical;
cloud `raw_data` projection integration test.
Gate: standard + golden; `payload_heavy` `engine_build`/`query_no_payload`
peak memory drops by ~capture size; `query_with_payload` regression bounded
and documented.

### P6 — Index-derived statistics (zone-map analysis)

*Goal: use the boundary index to avoid work selective queries don't need.*

**Delivered:** a pure `count(*) FROM frames` (frames only, no columns, no
filter, no limit) is answered from the boundary index's `packet_count` — a
header-only scan, persisted in the sidecar — with **zero packet parsing**.
`SeekablePacketSource::frame_count()` exposes it (mmap/file/cloud; `None`
for compressed/non-seekable, which fall back to a parse).

**Analyzed and deferred, with rationale (not shipped, to avoid speculative
or half-built code):**

- *Timestamp-range chunk skipping* — the index already records per-checkpoint
  `min_ts`/`max_ts`, so it is viable, but it needs (a) extracting timestamp
  bounds from the optimized plan and (b) a source/index API to map those to
  skippable partitions. A scoped follow-up.
- *Protocol-presence zone maps* — would let `FROM dns` skip regions with no
  DNS, but the index is a **header-only** scan; recording protocol presence
  requires partially parsing every packet at index-build time, making index
  builds materially heavier. Whether that pays off is workload-dependent;
  per the performance audit's own discipline (don't optimize speculatively)
  this is deferred until measured.
- *Sidecar reuse* — already implemented (the sources read/write the sidecar
  with a length/mtime/header-hash validity guard); no work needed.

Original plan (superseded by the above):

Changes:
- `Checkpoint` (`index.rs:41-52`) gains a protocol-presence set for its
  window (registry-stable protocol ids; `min_ts`/`max_ts` already exist).
  Sidecar format bumps to `PCSQIDX\x02`; v1 sidecars are rebuilt (existing
  validity-guard machinery).
- Drivers consult the index per checkpoint window: skip windows where
  `required ∩ present = ∅` (e.g. `FROM dns` over a capture region with no
  UDP/53) or where a pushed timestamp predicate excludes `[min_ts, max_ts]`.
  Skipped windows are counted in `ParseStats`.
- `statistics()` upgraded with index-derived totals where the index is
  present (exact `frames` row count pre-parse).

Deletions: none (pure extension — the only phase without them).

Tests: index round-trip for v2; skip-correctness property test (results with
zone maps == results with `index_stride = ∞`, across the proptest capture
space); golden corpus unchanged.
Gate: standard + golden; `query_selective_sparse` (rare protocol in a big
capture) shows order-of-magnitude `packets_scanned` reduction in `ParseStats`.

---

## 5. Aggregate deletion manifest

Everything removed by this migration, by phase:

| Phase | Deleted | Approx. LOC |
|---|---|---|
| P0 | `QueryEngine::auto`, `STREAMING_THRESHOLD_BYTES`, `query/frames.rs`, `query/tables/{tcp_connections,tls_sessions,http_messages}.rs` (as dead exports), `current_batches` | ~700 |
| P1 | 7 `QueryEngine` constructors, `load_normalized_packets`, `extract_timestamp_range`, `query/provider.rs` (`PcapTableProvider`), `pcapsql-core/src/pcap/reader.rs` (`PcapReader`), `RawPacket` builder APIs (+ `RawPacket` if orphaned), `--streaming` flag, `indicatif` (likely) | ~900 |
| P2 | `parse_packet_pruned`/`_projected`/`_pruned_projected` as separate functions, construction-time parse, `parse_pass_count`/`partition_count`, post-hoc `batch.project()` | ~350 |
| P3 | `SharedParseState` + materialize-then-serve internals of `shared.rs`, `TableSource::Shared` | ~250 |
| P4 | `StreamTableBuilder::process_pcap` + embedded mini-parser, keylog interim wiring, `ProtocolTableProvider::in_memory`/`TableSource` | ~300 |
| P5 | Unconditional `raw_data` copy path, `append_binary` | ~30 |

Net effect on the public surface: `QueryEngine` 8 constructors → 1; parse
entry points 4 → 1; `TableProvider` impls 2 → 1; CLI mode flags
(`--streaming`, `--mmap`) → 1 (`--no-mmap`); zero orphaned exports.

## 6. Behavior changes (user-visible)

| What | Before | After (phase) |
|---|---|---|
| `pcapsql query f.pcap "…"` first-result latency | full parse of capture up front | scoped parse of only what the query needs (P2), streaming + LIMIT early-stop (P3) |
| Memory, one-shot | O(parsed capture) + raw_data copy | O(batch × channels) (P3), no payload copy (P5) |
| REPL first query per table | instant after slow startup | startup ~instant; first query touching a table pays its scoped parse; later queries on cached tables instant (P2) |
| `--streaming`, `--mmap` | mode flags | removed / `--no-mmap` (P1) |
| `--stats` | stale cache text | `ParseStats`: packets scanned/skipped, rows built, partitions, overflow (P2+) |
| Compressed captures | via legacy `PcapReader` in-memory path | via sources, single-partition (P1; existing source support) |
| Keylog/HTTP-2 | second full file read | same pass, single partition (P4) |
| `tcp_connections`/`tls_sessions`/`http_messages` | unreachable from SQL | real tables (P4) |
| Queries on stream tables | n/a | forced single-partition (P4, documented) |

Library consumers: `pcapsql-datafusion`'s constructor surface changes in P1
(pre-1.0 crate; CHANGELOG entry per phase). `pcapsql-core`'s `parse_packet`
gains a parameter in P2 (`pcapsql-duckdb` updated in the same PR).

## 7. Invariants and how they're guarded

1. **One parse pass per query** — `engine_shared_parse.rs` asserts via
   `ParseStats.parse_passes` (P2 re-targets the existing test; the property
   behind #84/#85 holds *per query* instead of per engine).
2. **1-vs-N partition equivalence** — `pcapsql-core/tests/partition_equivalence.rs`
   (proptest) runs unchanged through every phase; P3 extends it through the
   exchange (engine-level 1-vs-N already exists in `engine_shared_parse.rs`
   and `cloud_integration.rs`).
3. **Identical SQL results across phases** — the P0 golden corpus: fixed-seed
   testgen captures × queries covering every table, every view, joins,
   aggregates, `raw_data` projection, LIMIT, and (from P4) keylog fixtures.
   Snapshot comparison; any diff fails the phase.
4. **Ordering** — `frame_number` ordering remains declared
   (`scan_exec.rs:66-82`) and `prefer_existing_sort` stays; the golden corpus
   includes `ORDER BY`-sensitive join queries to catch regressions when
   `target_partitions` is unpinned (P2).

## 8. Benchmark gates

Criterion suite added in P0, run per phase; numbers recorded in each PR:

| Bench | Measures | Phase it must move |
|---|---|---|
| `engine_open` | time + peak alloc to `open()` | P2 (collapses to source open) |
| `query_selective` | `SELECT src_port FROM tcp WHERE dst_port=443` on `tls_heavy` | P2 (pruning), P6 (skipping) |
| `query_full_scan` | `SELECT count(*) FROM frames` | must *not* regress (P1–P6) |
| `query_limit` | `SELECT … LIMIT 10` on large capture | P3 (early-stop) |
| `query_payload` / `query_no_payload` | with/without `raw_data` projection on `payload_heavy` | P5 (memory) |
| `repl_second_query` | repeat query, `CacheOnTouch` | must not regress (P2+) |
| `keylog_e2e` | HTTP-2 over TLS fixture | P4 (single pass) |
| `parse_throughput` | packets/sec, full scope, 1..N partitions | must not regress; P2 unpins partitions |

## 9. Risks and open decisions

| Risk | Phase | Mitigation / decision |
|---|---|---|
| SMJ correctness once `target_partitions` is unpinned | P2 | golden corpus + equivalence suites; if a plan regression appears, pin per-query when stream tables/joins demand it rather than re-pinning globally |
| Plan-walk misses a table ref (subquery, view expansion, UDTF) | P2 | harvest from the *optimized* plan (views inlined); fallback: any unrecognized scan ⇒ `ParseScope::full()` for that query — correctness never depends on the harvest |
| Exchange deadlock under non-SMJ plans | P3 | overflow-to-buffer policy (never blocks); metric + test that forces a hash join |
| Self-join double-consumption | P3 | duplicate-ref detection ⇒ buffered mode for that table; regression test |
| Time-UDF bootstrap (`register_time_udfs_eager` needs capture time range before first query) | P2 | derive lazily: index `min_ts`/`max_ts` when present (free), else first parse populates; document one-query staleness window or resolve in P6 via index |
| Cloud `raw_data` projection cost | P5 | per-batch coalesced range GETs; documented; only paid when projected |
| REPL cache growth (no eviction) | P2 | accepted initially (matches today's ceiling — today caches *everything* up front); `EngineOptions` memory ceiling is future work |
| `pcapsql-duckdb` drift | P2 | same-PR update; its own projection pushdown via `ParseScope` is a tracked follow-up |

## 10. Issue mapping

- **Closes #83** (P1 — `PcapReader` deleted; sources own open/detect once).
- **Closes #86** (P2 — filters/limit reach the parse; `Inexact` pushdown).
- **#84/#85** — invariant preserved per query (§7.1); no reopen.
- **#87** — partitioned parallelism retained through P3's drivers; execution
  parallelism additionally unpinned in P2.
- **#88 epic** — phases filed as sub-issues P0–P6 on acceptance of this plan.
