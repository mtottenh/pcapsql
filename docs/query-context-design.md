# Design: query-scoped prepared tables (#123) and plan-only statements (#124)

**Status:** approved with changes (independent review incorporated); implemented
as the `feat/query-context-{1,2,3,4}` stack (PR 5 not shipped).
**Baseline:** `main` @ `16e39db` (includes #113/#114/#115). `file:line` anchors
are into that commit under `pcapsql-datafusion/src/query/`; symbols are
authoritative. DataFusion references are to the 51.0.0 crates.

## 1. Problem

`QueryEngine::query` (`mod.rs:543`) prepares tables into one engine-global
`EngineTables` (`providers/protocol_provider.rs:58`) and every
`ProtocolTableProvider` resolves that map by table *name* at
physical-planning time (`protocol_provider.rs:193`). The query's identity is
never carried into DataFusion, so two in-flight queries share one mutable
slot per table. `QueryEngine` is `Send + Sync`, nothing documents the
restriction, and the CLI is sequential, so the exposure is library callers.

Concrete interleavings (A and B are concurrent `query()` futures on one engine).
Every failure lives in a query's **install → `create_physical_plan` window**
(`mod.rs:648-680` / `:669-680`): once `scan` has run, the exec owns an `Arc`
to its batches or receiver slots and later clears cannot reach it.

| # | Policy | Interleaving | Failure |
|---|---|---|---|
| I1 | `None` | A `install_streams` (`mod.rs:648`) → B pre-harvest `clear()` (`mod.rs:565`) → A `create_physical_plan` (`mod.rs:680`) | A: "table … was not prepared" (`protocol_provider.rs:193-199`) |
| I2 | `None` | A installs stream `udp` → B harvests the same table; `build_subscription` sees `self.tables.contains` (`mod.rs:792`) and skips it → B's scan takes A's receiver slot | second `execute` of that partition: "stream … already consumed" (`scan_exec.rs:199-208`); if B runs first it **silently returns rows built under A's predicate/LIMIT** |
| I3 | `CacheOnTouch` | A materializes `frames{length,raw_data}`, B concurrently `frames{length}`; B's `install` (`mod.rs:669`) lands after A's and replaces the wider entry | A: "column 'raw_data' … was not materialized" (`protocol_provider.rs:210-215`); cache narrowed |
| I4 | both | A's post-execution `clear()` (`mod.rs:750`) or `ClearStreamsOnDrop` on A's cancellation (`mod.rs:343`) | B's entries vanish between install and planning |
| I5 | `None` | A takes the `count(*)` fast path and installs a 0-column `frames` (`mod.rs:611`); B's `SELECT length FROM frames` sees `contains("frames")` | B: "column 'length' … was not materialized" |
| I6 | both | `last_stats` written at `mod.rs:645/654/670/746` | `last_parse_stats()` reports the other query |
| I7 | both | both call `ensure_time_range` (`mod.rs:510`) | duplicate header-only pass (benign) |

EXPLAIN (#124): `harvest_table_needs` (`mod.rs:289`) uses
`apply_with_subqueries`, which descends into `LogicalPlan::Explain.plan`, so
the needs are non-empty. Under `CacheOnTouch` the whole subscription is
materialized synchronously (`mod.rs:660`) just to print a plan; under `None`
producers are spawned (`mod.rs:647`), DataFusion's `handle_explain` builds
the inner physical plan (calling `scan`, which does **not** take receivers)
and the producers run until the guard drop at `mod.rs:698` lets them observe
`consumer_gone` — with #114's bounded exchange they park in
`Pacer::wait_until` after 4 batches/table, but still read for the planning
duration. DDL and statements have no scans and are harmless today, but go
through the same prepare path.

Side finding: `self.ctx.execute_logical_plan(optimized)` +
`df.create_physical_plan()` (`mod.rs:674-682`) runs the optimizer a second
time on an already optimized plan (`SessionState::create_physical_plan`
optimizes first, `session_state.rs:666-676`). The executed plan is therefore
not literally the one `harvest_table_needs` read.

## 2. Target architecture

### 2.1 Principle

Split `EngineTables` into two things with different lifetimes:

```rust
/// Engine-global, CacheOnTouch only. Entries only ever widen (§2.3).
pub struct TableCache { entries: RwLock<HashMap<String, Arc<TableData>>> }

/// One per query(). Immutable after prepare. Owned by the query future.
#[derive(Default)]
pub struct QueryTables { tables: HashMap<String, Arc<PreparedTable>> }   // Batches | Stream
```

A query *prepares* a `QueryTables` (cache snapshot + its own parse output or
stream receivers), hands it to DataFusion for exactly this query, and drops it
when done. Nothing a query does is visible to another query except cache
widening.

### 2.2 Carrying the per-query context into the providers

**Option A — per-query `SessionContext` with per-query provider
registration.** Rejected: the ~25 views are registered by `CREATE VIEW` SQL on
the context (`mod.rs:840-853`) and live in its catalog; they would be
re-planned per query (SQL parse + plan of every view) or the catalog shared
while table registrations differ — a shared mutable registry again.

**Option B — query id carried in the plan.** Mangle table names
(`frames__q17`) or wrap `TableScan` in an `Extension` node. Rejected: views
reference bare names, `TableScan` has no user slot, and a per-query
`TableSource` would require rewriting view plans after inlining.

**Option C (chosen) — per-query `SessionState` carrying `QueryTables` as a
`SessionConfig` extension.** `SessionConfig` has typed extensions
(`with_extension`/`set_extension`/`get_extension`, datafusion-execution
`config.rs:537-591`) and `Session::config()` exposes them (datafusion-session
`session.rs:77`). The physical planner passes its `&SessionState` straight
into `TableProvider::scan` (`physical_planner.rs:452-469`); views are
**inlined at logical planning** (`LogicalPlanBuilder::scan_with_filters_fetch`,
datafusion-expr `builder.rs:517`), so by physical planning every protocol
scan — including those behind `tcp_packets` or `packets` — is a plain
`TableScan` on our provider and receives the same state.

```rust
// mod.rs — the per-query path
let mut state = self.ctx.state();                       // clone of the shared state
let plan = state.create_logical_plan(sql).await?;
let optimized = state.optimize(&plan)?;
let (prepared, producers, stats) = self.prepare(&optimized).await?;   // Arc<QueryTables>
// Plan for the partitions the query actually has (#122): a scan with fewer
// partitions than target_partitions is round-robin repartitioned and, with
// no ORDER BY, loses its frame_number ordering before the final merge.
state.config_mut().options_mut().execution.target_partitions =
    session_target_partitions(prepared.partitions(), self.parallelism); // k, or parallelism.max(2) for k <= 1
state.config_mut().set_extension(prepared.clone());
let result = async {
    let physical = state.query_planner().create_physical_plan(&optimized, &state).await?; // no 2nd optimize
    let physical = merge_ordered_partitions(physical);
    collect(physical, state.task_ctx()).await            // plan + TaskContext owned here
}.await;                                                 // captured, not `?`-ed
drop(state); drop(prepared);                             // last holders → untaken receivers drop
let stats = fold(stats, join_all(producers).await)?;     // fail closed, as today
```

```rust
// protocol_provider.rs
async fn scan(&self, state: &dyn Session, projection, _f, _l) -> DFResult<Arc<dyn ExecutionPlan>> {
    let Some(q) = state.config().get_extension::<QueryTables>() else {
        // No query context (EXPLAIN, DDL, direct `engine.context()` use):
        // plan-only exec over the full schema; `execute` fails clearly.
        return Ok(ProtocolScanExec::plan_only(self.table_name.clone(), self.schema.clone(),
                                              projection.cloned(), self.default_partitions));
    };
    // A query context that lacks this table means the harvest missed a scan:
    // a hard error at planning time, never a silent plan-only exec.
    let prepared = q
        .get(&self.table_name)
        .ok_or_else(|| exec_err("table '{}' was not prepared for this query", self.table_name))?;
    self.scan_prepared(&prepared, projection)
}
```

Plan-only scans are therefore only ever produced when **no** query context is
present (EXPLAIN, DDL, direct `engine.context()` use).

Holders of the `Arc<QueryTables>` (all owned by the `query()` future):
`prepared`; `state` (its `SessionConfig`); the `Arc<TaskContext>` built by
`state.task_ctx()` (`TaskContext::from(&SessionState)` clones the config,
`session_state.rs:1969-1981`); and, indirectly, every `ProtocolScanExec`
holding a receiver-slot `Arc`. The plan and the `TaskContext` are moved into
`collect`, so they are gone when it returns; `prepared` and `state` are dropped
explicitly before the producers are joined. Dropping the future anywhere drops
all of them, the receivers close, `BatchReceiver::drop` bumps the pacer and a
parked producer leaves `may_proceed` via `consumer_gone` — ownership replaces
`ClearStreamsOnDrop`.

Checked against the required interactions:

- *Planning cost:* `ctx.state()` is a clone the code already pays; one
  optimizer pass instead of two.
- *Views:* unchanged (inlined before our provider is reached).
- *`count(*)` fast path:* writes the row-count-only `frames` into
  `QueryTables`, never into the cache (fixes I5).
- *Duplicate-scan → materialize rule:* unchanged; both scans get the same
  `Arc<TableData>` from the query's own `QueryTables`.
- *Stream subscriber pinning:* unchanged; materialized stream tables go to
  `QueryTables` and, under `CacheOnTouch`, into the cache like any table.
- *REPL cache:* `TableCache` stays shared; a query snapshots the entries it
  hits at `build_subscription` time, so a concurrent widening can never remove
  a column a running query planned against (fixes I3).
- *Time range:* `CaptureTimeRange` stays engine-global (monotone atomics);
  `ensure_time_range` runs under a `tokio::sync::Mutex<()>` (I7).
- *Stats:* folded into a local `ParseStats`, written once (§4).

### 2.3 Widen-only cache

`TableCache::install` replaces an entry only when the new column set is a
superset of the current one. Two concurrent first-touch misses both parse
(wasted work, never wrong). With A `{a,b}` and B `{a,c}` installed
concurrently, the second install is discarded (its query still runs on its own
snapshot) and a later `{c}` query re-parses the union `{a,b,c}`. Documented in
the rustdoc; de-duplicating in-flight fills is a follow-up.

Residual: `materialize` runs its partition threads synchronously on a tokio
worker (`shared.rs:357`); concurrency makes this more visible. Moving it under
`spawn_blocking` is the optional PR 5.

## 3. EXPLAIN, DDL and statements

Classify the **unoptimized** top-level node before preparing anything:

| Top node (datafusion-expr `plan.rs`) | Class | Handling |
|---|---|---|
| `Explain` | plan-only | `optimize` (for display), **no prepare**; `query_planner().create_physical_plan` on the per-query state **without** the extension → plan-only scans |
| `Ddl` (except CTAS), `Statement` (except `Execute`), `DescribeTable` | no-scan | `self.ctx.execute_logical_plan(plan)` + `collect` — DDL must mutate the shared catalog; nothing prepared |
| `Ddl(CreateMemoryTable)` with an input that scans a capture table (CTAS) | unsupported | clear error. `SessionContext::create_memory_table` executes the input with `self.state()` and no extension (`context/mod.rs:854-868`), which would hit the plan-only `execute`. Supporting it means running the input per-query and registering a `MemTable` on the shared context — a follow-up |
| `Statement::Execute` | unsupported | clear error (the prepared plan is run by `execute_logical_plan` without our context) |
| `Analyze`, `Copy`, `Dml` | query | harvest the input, prepare, run. `INSERT INTO mem SELECT … FROM frames` is planned by the physical planner (`physical_planner.rs:571`) with our state and works |
| anything else | query | current path |

The providers need no parse to resolve schemas: `ProtocolTableProvider::schema`
is the static full schema (`protocol_provider.rs:158`), so logical planning and
EXPLAIN's inner physical plan (`handle_explain` → `create_initial_plan`) both
work. `ProtocolScanExec::plan_only` is a `ScanSource::Unprepared` variant: it
reports `UnknownPartitioning(default_partitions)` (the engine's nominal
parallelism), the `frame_number` ordering, `Precision::Absent` statistics,
displays as `mode=plan-only`, and its `execute` returns
`Execution("… was not prepared for this query; run through QueryEngine::query")`.

`ParseStats` gains `served_from: ServedFrom { Parse, Cache, Index, PlanOnly }`
so a plan-only statement, a cache hit and the `count(*)` index fast path are
distinguishable (`parse_passes == 0` for all three); `--stats` prints
"Parse passes: 0 (plan only: no scan was executed)". `EXPLAIN ANALYZE` runs
the real parse and reports it. Accepted and documented: `EXPLAIN` of a query
using `start_time()` still runs `ensure_time_range` so the folded constant in
the displayed plan is faithful — free from the index, one header-only pass on
a source without one (compressed); `ensure_time_range` returns that pass's
statistics and the query folds them into its own (`parse_passes`,
`packets_scanned`), so the cost is reported, not hidden. Deferred: EXPLAIN's displayed
physical plan omits `merge_ordered_partitions` (pre-existing).

## 4. API, semantics and migration

**Concurrency contract (rustdoc on `QueryEngine`):** `query`/`execute` may be
called concurrently from any number of tasks on one engine. Each query parses
what it needs on its own context. Under `CacheOnTouch`, concurrent first-touch
queries of one table may each parse it; the cache converges to the widest
column set (§2.3). `context()` is shared: DDL through it is visible to all
queries; data queries through it build (EXPLAIN works) but fail at execute
with the message above.

**Stats:**

```rust
pub struct QueryOutput { pub batches: Vec<RecordBatch>, pub stats: ParseStats }
impl QueryEngine {
    pub async fn execute(&self, sql: &str) -> Result<QueryOutput, Error>;
    pub async fn query(&self, sql: &str) -> Result<Vec<RecordBatch>, Error> { /* execute().batches */ }
    /// Stats of the most recently *completed* query on this engine: exact for
    /// sequential use (CLI, REPL, existing tests); under concurrency use `execute()`.
    pub fn last_parse_stats(&self) -> ParseStats;
}
```

`last_stats` is written once, after the producers are folded, atomically with
the result. The one-shot CLI moves to `execute()` and prints `output.stats`;
the REPL keeps `last_parse_stats()` for `.cachestats`.

**Breaking (pre-1.0, CHANGELOG):** `EngineTables` → `TableCache` +
`QueryTables` (re-exported from `providers`); `ProtocolTableProvider::new`
takes `default_partitions` instead of the tables handle; `ParseStats.served_from`
(a struct-literal break for anyone constructing `ParseStats`).

**Short-term mitigation (PR 1):** `query_lock: tokio::sync::Mutex<()>` held for
the whole of `query()` (cancel-safe) plus the rustdoc line "queries on one
engine are serialized". Ten lines, turns every interleaving in §1 into
serialization, no golden-corpus risk, removed by PR 4. Independent of the
EXPLAIN fix (PR 2).

## 5. Test plan

New file `tests/engine_query_context.rs` (own small UDP fixture), plus
additions to `golden_corpus.rs`.

1. **Forced overlap (both policies), shown failing on baseline.** Engine with
   a `progress` callback (runs on the producer/parse thread; it only signals a
   `tokio::sync::mpsc::UnboundedSender`). Query A is deliberately expensive to
   *plan* (a `CASE` with thousands of arms over `frames.length`, plus
   `raw_data` under `CacheOnTouch`), so its install → physical-plan window is
   hundreds of milliseconds (measured: a second optimizer pass over 3000
   `CASE` arms takes ~320 ms in a debug build; B's whole parse 6–11 ms).
   Under `None` B (`SELECT count(*) FROM udp`) is started when A's parse has
   read every packet (the 3 batches fit the 4-batch exchange, so the
   producer finishes before A plans) and its pre-harvest `clear()` lands in
   A's window. Under `CacheOnTouch` B (`SELECT length FROM frames`) must read
   the cache *before* A installs and install *after*: it is started at A's
   first progress chunk, misses, and its own parse — recognisable as the
   second pass, whose running total restarts at the first chunk — is parked
   until A's final chunk, so B's narrower install lands inside A's window.
   Baseline: I1 ("not prepared") / I3 ("column … not materialized") on every
   run. PR 1: B waits on the lock. PR 3+: isolation; PR 4 additionally
   checks that A's wider cache entry survives B's install.
   Plus a JoinSet stress run (8 tasks × 20 rounds over a mixed query set
   incl. self-join, fast path, stream table, time UDF) compared to a
   sequential baseline.
2. **Plan-only, fresh engines per case:** `EXPLAIN SELECT * FROM frames`,
   `EXPLAIN … JOIN …` under both policies → output contains `ProtocolScanExec`
   and `plan-only`, `served_from == PlanOnly && parse_passes == 0 &&
   packets_scanned == 0`; `EXPLAIN ANALYZE` → `parse_passes == 1`; `EXPLAIN`
   of a time-UDF query on a gzip copy (no boundary index) → `PlanOnly` with
   `parse_passes == 1` and `packets_scanned == N` (the bootstrap), then 0 on
   the next statement; `CREATE VIEW` → plan-only, then a
   `SELECT` from it parses; `DESCRIBE frames` → plan-only; CTAS over `frames`
   → clear error; `CREATE TABLE t (…)` + `INSERT INTO t SELECT … FROM frames`
   → works; `engine.context().sql("SELECT … FROM frames")` → EXPLAIN works,
   `collect` fails with the "not prepared" message.
3. **Cancellation (stable tokio):** `#[test]` building a runtime with
   `max_blocking_threads(1)` and `target_partitions = 1`. The progress
   callback parks the producer on a `std` `Mutex`/`Condvar` gate and signals
   the test. Variant (a) *inside `collect`*: `batch_size` smaller than the
   first progress chunk so a batch is already in flight; the test aborts the
   spawned query task (`JoinHandle::abort`, which drops the future at its
   next await), releases the gate, and the next query must complete within
   20 s (a leaked producer would hold the only blocking thread). Variant (b)
   *before the first send*: `batch_size` larger than the capture, same
   protocol. Both pass on baseline (drop guard) and on PR 3
   (ownership), guarding the guard's removal.
4. **Golden corpus:** snapshots byte-identical under both policies; a new pass
   issues the corpus concurrently (`JoinSet`) on one engine per policy and
   compares to the same snapshots, excluding `FRESH_ENGINE_QUERIES`
   (`q24`/`q25` must be the first query on an engine).
5. `streaming_memory.rs` and `engine_shared_parse.rs` unchanged.

## 6. Implementation plan

| PR | Content | Files | Risk |
|---|---|---|---|
| 1 | `query_lock` + concurrency rustdoc; this document at `docs/query-context-design.md`; test (1) | `query/mod.rs`, `lib.rs`, `CHANGELOG.md`, `docs/`, `tests/engine_query_context.rs` | none; CLI throughput unchanged |
| 2 (Closes #124) | §3 classification; `ScanSource::Unprepared`/`plan_only`; providers tolerate a missing table; `ParseStats.served_from`; CLI text; test (2) | `query/mod.rs`, `providers/{scan_exec,protocol_provider,shared}.rs`, `main.rs`, tests | pre-split "missing" means "absent from `EngineTables`", so a cached table under `CacheOnTouch` shows `mode=batches` — test (2) uses fresh engines |
| 3 | `TableCache`/`QueryTables` split; extension-based `scan`; per-query `SessionState`; `query_planner().create_physical_plan`; delete `ClearStreamsOnDrop` and the `None` pre/post clears; fast path → `QueryTables`; lock kept; test (3) | `providers/protocol_provider.rs`, `providers/mod.rs`, `query/mod.rs`, tests | mechanical; judged by golden corpus + §5.5; cancellation now relies on ownership (test 3) |
| 4 (Closes #123) | `execute()`/`QueryOutput`; widen-only cache; `ensure_time_range` mutex; CLI `--stats` via `execute`; remove `query_lock`; stress test; concurrent corpus pass | `query/mod.rs`, `providers/protocol_provider.rs`, `main.rs`, `CHANGELOG.md`, tests | duplicate first-touch parses under `CacheOnTouch` (accepted, documented) |
| 5 (optional) | `materialize` under `spawn_blocking`; de-duplicate in-flight fills | `query/mod.rs`, `providers/shared.rs` | re-baseline `streaming_memory.rs` if thread accounting shifts |

Each PR is green on `fmt`, `clippy -D warnings`, `cargo test --workspace`
(golden corpus byte-identical).
