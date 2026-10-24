# Continuous mode: removing the PR #142 limitations

PR #142 (`feat/continuous-mode`) lists three limitations:

1. Joins, and so every `*_packets` view, are rejected in continuous mode.
2. Teardown relies on the process exiting: a producer blocked in `read()` on
   an idle pipe can't be stopped, so `drop(engine)` isn't enough.
3. The fused aggregate's state is bounded by closed windows but isn't
   accounted in the memory pool.

This document gives the root causes, what was tried, and the designs that
remove them. Section 0 is the one to read if you only read one.

---

## 0. The picture

The parser turns one packet into N normalized tables, each on its own channel,
and SQL re-joins them on `frame_number`. That is a warehouse model and it is
right for batch queries over a file. Streaming engines don't do it: Flink and
ksqlDB treat a packet as one event with nested fields; Suricata EVE, Arkime and
`tshark -T fields` emit one wide record; Zeek writes per-protocol logs but
never joins them in-stream. Once the source is unbounded, the N-channel model
is behind every limitation above and one the PR did not list:

- **Joins.** There is nothing to join if the parser emits the frame-aligned row
  itself, or if one operator reads the N channels knowing they come from one
  ordered parse.
- **Sparse-side stall.** `tcp_packets` has `LEFT JOIN ipv6`. On an IPv4-only
  feed the `ipv6` channel never carries a row, so any streaming join waits for
  it for ever. Flink calls this *source idleness*; its answer is a per-source
  watermark. Here the equivalent is a **frontier** (§1.6).
- **Teardown.** The producer has no clock: it runs only when a byte arrives.
- **Memory.** Nothing sets a memory limit, so accounting would enforce nothing
  until one exists.

The continuous mode that #142 adds is on the standard path: event time,
watermark = `max_ts - lateness`, late rows dropped and counted, and a plan
shape fused into a streaming window aggregate. That is the Dataflow/Flink
model, and it is how Arroyo (Rust, DataFusion-based) does it too. The pieces
below extend it; none of them changes it.

---

## 1. Joins (limitation 1)

### 1.1 Root cause, checked against DataFusion 51

In continuous mode `target_partitions = 1`. The physical planner builds a
`SortMergeJoinExec` only when `target_partitions > 1`
(`physical_planner.rs:1381`), so a continuous session gets a `CollectLeft`
`HashJoinExec`. `JoinSelection` then sees two unbounded incremental inputs and
converts it to a `SymmetricHashJoinExec`.
`optimizer.allow_symmetric_joins_without_pruning` defaults to `true`, so the
sanity check accepts a symmetric join that has nothing to prune on, and an
equi-join on `frame_number` gives the pruner nothing. Both sides are kept for
ever.

### 1.2 What the `feat/continuous-smj-joins` branch tried

Three facts made a sort-merge join look like a one-day fix:

- `SortMergeJoinExec` is `EmissionType::Incremental` with boundedness from its
  children (`sort_merge_join/exec.rs:302`), so it passes the sanity check on
  unbounded inputs.
- Every scan declares `frame_number ASC` (`scan_exec.rs:167`).
- A single partition satisfies `HashPartitioned` (`partitioning.rs:162`), so
  no repartition is inserted.

The branch adds `streaming::join::PreferSortMergeJoin`, a physical rule before
`JoinSelection` that converts a hash join of two unbounded inputs ordered on
the join keys into a sort-merge join; sets
`allow_symmetric_joins_without_pruning = false`; and replaces the
`name().contains("Join")` gate with a property gate (sort-merge joins and hash
joins with a bounded build side pass). `tumble(udp_packets, …)` plans and runs,
and the `arp_packets` test emits per closed window with exact results.

It also found three things that make a sort-merge join the wrong operator for
this, which the tests on that branch pin down:

1. **Output cadence is row-count based.** The join hands a batch on only when
   it holds `execution.batch_size` joined rows (8192) or at end of input
   (`sort_merge_join/stream.rs:671`). A continuous query needs every joined
   row when the join can release it, so the branch sets `batch_size = 1` for
   plans that contain one. Measured on a 300 000-packet capture piped through
   `--continuous`, debug build: `tumble(frames)` 0.27 s; `tumble(udp_packets)`
   through four sort-merge joins 31.7 s. One-row batches through four joins
   and the aggregate cost about 100×. ~9 500 packets/s in debug is not a live
   capture rate.
2. **One-frame lag.** The buffered side learns that a key is complete only
   when it sees the next key (`PollingRest`), so the last frame delivered is
   held until the frame after it arrives. On a feed that goes quiet, the held
   frame can miss its window if `idle_timeout` closes it, and is then counted
   late.
3. **Sparse-side stall**, as predicted: `udp_packets` on an IPv4 feed closes
   its windows only at end of input.

A fourth finding is a bug independent of continuous mode: the sort-merge join
polls its buffered child again after that child returned `None`, and the scan's
`unfold` stream panicked on it. The scan stream is now `.fuse()`d.

**Conclusion:** keep the branch's planning changes (the property gate, the
no-prune setting, the fuse) and replace the sort-merge join with an operator
built for this input. The conversion rule stays as the fallback for joins the
new operator does not take.

### 1.3 The three kinds of join

| Kind | Example | Mechanism | State |
|---|---|---|---|
| **A. Frame join** | every `*_packets` view; `tcp JOIN ipv4 USING (frame_number)` | `FrameJoinExec` (§1.4), later parser-side fusion (§1.5) | one frontier's worth |
| **B. Stream ⋈ bounded table** | enrich with an asset CSV, `VALUES`, a parquet lookup | the existing `CollectLeft` hash join, bounded side as build | the bounded table |
| **C. Stream ⋈ stream, time-bounded** | DNS answer → TCP SYN to that IP within 30 s | `SymmetricHashJoinExec` with an interval filter on timestamps | bounded by the interval |

B works once the gate is a property gate. A and C are below.

### 1.4 `FrameJoinExec`: a merge join that knows its inputs share a producer

An n-ary operator over N frame-ordered inputs of one parse, replacing a tree of
`Inner` / `Left` equi-joins on `frame_number` with optional member-local `ON`
conjuncts (the tunnel views need `AND inner_v4.encap_depth > 0`). It relies on
two facts the N-channel model can guarantee and a sort-merge join cannot use:

- **A frame's rows never straddle two batches of one table.** The builder
  must finish a batch only at a packet boundary (today `try_build` runs after
  every row, so a packet with two `ipv4` rows can split). One-line change in
  `NormalizedBatchSet::add_packet_from_ref`.
- **The frontier** (§1.6): the producer publishes `F` = every row of every
  subscribed table for frames ≤ F has been delivered.

Per poll it drains whatever is ready on every input, then emits every frame
≤ `min(F, max frame seen on each input that has rows pending)`:
inner members with no row drop the frame, left members with no row contribute
nulls, and several rows of one member for one frame give the cartesian product
(SQL semantics; IP-in-IP has two `ipv4` rows). State is one frontier's worth
of rows per side. It emits per input batch, so there is no row-count cadence,
no one-frame lag, and a quiet `ipv6` does not stall it because `F` advances
without it.

Planning: a physical rule, before `JoinSelection`, matching the join tree
bottom-up; the properties are `Incremental`, `Unbounded`, single partition,
ordered by `frame_number`. The tumble projection above it then fuses with no
change to `streaming/mod.rs`, which already walks through projections.

Out of scope: `FULL` / `RIGHT`, non-equality conditions across members, `OR`
in `ON`, a join to a bounded table (kind B, above or below it). Those leave
the tree alone and the fallback handles them.

### 1.5 Parser-side fusion — done (`feat/frame-join-fusion`)

Once fusion was the committed end state, §1.4 and §1.6 became throwaway work
and were skipped; fusion landed directly, in `pcapsql-datafusion/src/query/
fusion/` and `builders/fused.rs`:

- `FuseFrameJoins`, a logical `OptimizerRule` appended last to the default
  rules of a `RetentionPolicy::None` session. Top-down over the optimized
  plan it matches a tree of inner/left joins whose leaves are protocol-table
  scans (under `SubqueryAlias`, column-only `Projection`, `Filter` on an
  inner side, and the `Limit` copies the limit pushdown leaves on preserved
  sides) with `ON` exactly `frame_number = frame_number` (+ `encap_depth`),
  and replaces it with `Projection(re-qualifying aliases) → [Filter] →
  TableScan(FrameJoinProvider)`, plus the outermost `Limit` found in the
  tree. The output schema is the join's, qualifiers included, so nothing
  above notices. Not matched: `FULL` joins (the `packets` view), join
  filters, non-column keys, a `Limit` on one leaf, a join above the window.
- `FusedBatchBuilder`, a slot of `NormalizedBatchSet` like a protocol table:
  per packet it evaluates the joins over the frame's own layers (indices into
  `parsed`, flat tuple buffers reused across packets, no per-frame
  allocation) with exact inner/left semantics, and appends the rows. Row cap
  (a pushed `fetch`) and the time-based flush apply as for any table. The
  fused table is one more entry of the subscription, exchange, `QueryTables`
  and `--stats`.
- The scan declares the root member's `frame_number` (and `encap_depth`)
  as output ordering, so capture order survives partitions without a sort.

Measured on a 2 000 000-packet UDP capture (136 MB file, release build,
partitions chosen by the engine for the CPU set; `--no-fuse-joins` is the
previous design):

| CPUs | parse `udp` alone | fused `udp_packets` | DataFusion joins | RSS fused / joins |
|---|---|---|---|---|
| 1 | 1.73 s | 2.11 s | 2.37 s | 171 / 236 MB |
| 4 | 0.75 s | 0.74 s | 1.92 s | 171 / 246 MB |
| 8 | 0.46 s | 0.51 s | 1.79 s | 172 / 261 MB |

Fusion keeps the partitioned parse (it is a slot of every partition's batch
set) and scales with it; the join path stops scaling once the parse is done
because the merges run on one thread. The SMJ experiment of §1.2 took 31.7 s
for 300 000 packets in debug; fused, the same run takes 3.8 s against 3.3 s
for parsing `udp` alone. A continuous `tumble(udp_packets)` over a live pipe
closes windows as the watermark passes them; `LIMIT n` over a view returns
while the pipe stays open. The golden corpus runs every view on the
materialized (join) engine and the streaming (fused) engine and requires
identical output: that is the differential test, for free, and it gained the
matcher's edge cases (same table under two aliases, ORDER BY the root's depth,
LIMIT with OFFSET, a derived table's own LIMIT under a left join, a left join
under a LIMIT, a view joined with its own member).

### 1.5.1 Performance follow-ups (from the `rust-performance-review` pass)

Not part of fusion, but what the per-packet profile is made of, in priority
order; all behind existing APIs:

1. `parse_packet` dispatch is name-keyed: `find_parser` scans all ~27
   parsers per layer, `can_parse` does linear `&str` hint lookups,
   `should_run_parser` hashes and string-compares per layer, `projections.get`
   hashes again. Fix: enum hint keys (or pointer-compared `&'static str`),
   candidates indexed by parent protocol, `ParseScope` resolved once per pass
   into parser-indexed arrays, projection bitmasks.
2. `ProtocolBatchBuilder::add_parsed_row` resolves every cell by name per row
   (HashMap iteration plus four string compares per column, then a linear
   field scan). Port the fused builder's pre-resolved `Source` per column.
3. `ParseResult::get(name)` per cell: add a position hint (parsers emit
   fields in a fixed order), in both builders.
4. `List*` builder arms allocate a `Vec`/`String` per cell (DNS, TLS);
   append through `values()` as `ListOfFixedSizeBinary` already does.
5. `slots: HashMap<String, _>` hashed per packet; `parse_packet` allocates a
   `Vec` of ~1 KB `ParseResult`s per packet; continuous mode's `chunk = 1`
   pays per-packet bookkeeping (`all_capped`, `Instant::now`).

Keep as is: `DynamicBuilder`'s enum dispatch (a match, not a vtable),
`BuiltinProtocol`'s enum, the builder capacity hints, `Arc` clones per
partition/batch. Verify with `cargo flamegraph` on a release build before
doing any of it.

Two bugs found on the way, both now fixed: a query whose only table is a
fused join had an empty `subscription.tables`, which sent it down the
materialize path (parse to EOF, no flushes); and DataFusion's limit pushdown
plants `Limit` copies inside the join tree, which the matcher first treated as
a break in the tree (partial fusion) and then as droppable (losing the LIMIT).

The `encap_depth` semantic decision went into step 0 (`fix/views-encap-depth`):
views join layers of the same level, so the fused builder never needs a
cartesian product over depths, though it would compute one correctly.

### 1.6 Frontier

`frontier: Arc<AtomicU64>` on `QueryTables`, written by the producer after each
`flush_partial` (every builder is empty, so the claim holds) and at end of
input, and on every idle tick (§2) so a quiet feed still advances it. An
operator that has drained a table's channel and reads `F` knows the table has
nothing pending at or below `F`. This is the per-source watermark of Flink,
specialized to frame numbers.

### 1.7 Stream ⋈ stream with a time bound (C)

Two different tables of one parse (the self-join refusal stays), joined with an
interval on timestamps. Both scans must declare `timestamp ASC`, and only when
the producer **enforces** it (clamp to a running maximum and count, or send
out-of-order rows to `late_rows`); never declare an ordering the data breaks.
With that, DataFusion's symmetric hash join prunes on the interval filter and
the `allow_symmetric_joins_without_pruning = false` check accepts it; a join
without such a bound fails at planning with DataFusion's own message. An
aggregate over such a join needs `match_window_chain` to accept the window
node above a join. Lowest priority.

---

## 2. Teardown (limitation 2)

### 2.1 Root cause

`StdinPacketReader` is
`GenericPcapReader<HeadFill<DecompressReader<Box<dyn Read + Send>>>>`. The
bottom `read()` blocks with no timeout, and the producer notices a dropped
receiver only after the next packet. A related gap: `stream_partition` checks
`flush_interval` only after a packet, so rows that arrive just before a quiet
period stay in the builders; if `--idle-timeout` then closes their window they
are counted **late** when the next packet flushes them.

### 2.2 Design: `poll` with a cancel fd

Before each `read()` on a pipe, `poll([stdin, cancel], flush_tick)`:

- **`poll`, not `epoll`.** Two or three fds, so epoll's advantages (O(1) with
  thousands of fds, persistent registration, edge-triggered mode) do not apply;
  it costs an extra fd and setup, and is Linux-only (`kqueue` on BSD/macOS).
  `poll` is POSIX and one call.
- **Cancel fd.** An `eventfd` on Linux, the read end of a self-pipe elsewhere.
  Dropping the `QueryStream`/engine writes one byte and `poll` returns at once:
  cancellation is immediate, not bounded by the tick. The tick is only for
  flushing.
- **Timeout in `poll`**, not a `timerfd`; one timer is enough.
- **No `O_NONBLOCK` on stdin.** The flag lives on the shared open file
  description (the shell, a sibling in the pipeline). `poll` on a blocking fd
  avoids it: readable means `read` will not block on a pipe. Reopening
  `/proc/self/fd/0` gives a pipe a fresh description, but is Linux-only.
- **Not** `close()` from another thread (does not unblock `read()` on Linux),
  **not** `pthread_kill` + `EINTR` (racy, and std retries `Interrupted`),
  **not** tokio's async stdin (a blocking thread pool underneath).
- A regular file as stdin always polls readable, so behavior is unchanged.
- `rustix::event::poll` on Unix; the pump thread (`sync_channel` +
  `recv_timeout`) stays for Windows and `from_reader` in tests.

### 2.3 Where the timeout surfaces

`pcap-parser`'s reader is a resumable state machine (`Incomplete` →
`refill()`, `pcap_stream.rs:531`), so the timeout does not need a hook under
`Read`. `process_packets` returns `Progress::{Packets(n), Idle, Eof}`; on
`Idle` the loop in `stream_partition` flushes partial batches (closing the
late-row gap), checks the cancel flag, and publishes the frontier. `refill()`
loses the `io::ErrorKind`, so the reader records "last read timed out" in a
flag the loop reads. Confirm that `refill()` leaves its buffer untouched on an
error before relying on it; the code shape says it does.

### 2.4 Effect and tests

`finish()` returns without a timeout; the CLI drops `std::process::exit(0)` and
the "statistics unavailable" message; `--idle-timeout` is safe to recommend.
Tests: two packets then a quiet pipe, window emitted after `idle_timeout` with
both rows and `late_rows == 0`; drop with the pipe open and idle, `finish()`
completes within two ticks; a tick that lands mid-record parses the packet
once.

---

## 3. Memory (limitation 3) — done (`feat/continuous-memory`)

What landed, on top of the fusion branch:

- `EngineOptions::memory_limit` / `--memory-limit SIZE` build the session on a
  `RuntimeEnv` with a greedy pool of that size. `StreamingWindowAggregateExec`
  registers a `MemoryConsumer` and, after every input batch, `try_resize`s to
  the state's weight: accumulator `size()`s, frozen slice states, row keys, a
  fixed per-entry overhead (recomputed over the whole state per batch, which
  is cheap at batch cadence and robust against freezes). `state_bytes` is a
  gauge; `QueryStream::state_bytes()` reads it.
- `MemoryLimitPolicy::{Error, CloseOldest}` / `--on-memory-limit`: on a
  failed resize, `Error` returns `ResourcesExhausted` naming bytes, open
  windows, group entries and what to change; `CloseOldest` emits the oldest
  pending window (sliced hop: through its end) until the state fits, counting
  `windows_forced` (`ParseStats`, `--stats`, `--progress`); if the newest
  window alone does not fit, it errors.
- Hop slicing: a hop whose size is a multiple of its slide is fed one row per
  packet with *slice* bounds (`HopAssignExec` with size = slide, same schema)
  and aggregated per `(slice, group)`. A window `w` closes at
  `w + size <= horizon` and merges the `size / slide` slices it covers: each
  slice's live accumulators are frozen into `state()` (which consumes them,
  so a fresh live set takes later rows), the frozen pieces are kept until the
  slice's last window (the one starting at it) is emitted, and the window's
  fresh accumulators `merge_batch` every piece of every covered slice. A row
  is counted late once per already-closed window containing its slice, as the
  per-window expansion did. Exact for every DataFusion aggregate (the
  Partial/Final contract); order-sensitive ones without `ORDER BY` may list
  elements in slice order. Hops with a non-multiple size, and tumble, keep the
  per-window path.

Tests: exact `sum/min/max/avg` through slice merging; the non-multiple hop
still expands; both policies, with the limit set between one and two windows
of state measured on an unlimited engine (`state_bytes()`), so the tests do
not hard-code accumulator sizes.

The design as planned before implementation follows.

Accounting through `MemoryPool` is the DataFusion-standard mechanism and
should be done (register a `MemoryConsumer` in `execute()` as
`windowing/session.rs:277` does; track size incrementally per touched
`(window, group)` with `Accumulator::size()` plus key and node overhead;
`try_resize` once per input batch; release per emitted window). Two things
matter more:

- **Hop windows multiply state by `size / slide`.** The standard fix is
  slicing (panes: Li et al. 2005; Scotty, Cutty): one accumulator set per
  slide, merged into the `size / slide` windows at emission with
  `Accumulator::state()` + `merge_batch()`, which DataFusion accumulators
  implement for Partial/Final already. State and update cost drop by that
  factor.
- **Group cardinality** is the dimension that grows (`GROUP BY` 5-tuple).
  Windows close in order, so state is `(1 + lateness / size) × groups`.

With a limit (`--memory-limit`, `RuntimeEnvBuilder::with_memory_limit`), the
policy when a reservation fails is `--on-memory-limit error` (default: name the
open window count, the largest window's group count and the limit; suggest a
smaller window, lower lateness or fewer group columns, and for hop the
`size / slide` factor) or `close-oldest` (load shedding in the Aurora/Borealis
sense: emit the oldest windows early, count them in `windows_forced`, set
`closed_through` so later rows count as late). Flink and Spark grow or spill
instead; spilling is overkill for a CLI whose state lives until the window
closes.

---

## Order

Branches are stacked linearly in the `pcapsql-pr142` worktree, each on the
previous: `fix/views-encap-depth` → `feat/continuous-teardown` →
`feat/frame-join-fusion` → `feat/continuous-memory`.

| Step | Delivers | Status |
|---|---|---|
| 0. Views join layers of the same encapsulation level | correct per-level rows; the semantics fusion reproduces | done, `47a633b` |
| 1. Cancel descriptor in the reader's `poll`, cap flush, raw stdin fd (§2) | limitation 2; `--stdin … LIMIT` on an open pipe; stdin's 8 KiB buffer | done, `d6a6b86` |
| 2. Parser-side fusion (§1.5) | limitation 1 for every view and hand-written frame join, batch and continuous | done |
| 3. Hop slicing + accounting + limit (§3) | limitation 3 | next |
| — Frontier (§1.6), `FrameJoinExec` (§1.4) | superseded by fusion | dropped |
| — Property gate + SMJ fallback (§1.2) | stream ⋈ bounded table; what fusion does not take | kept on `feat/continuous-smj-joins`, not merged |
| — Ordered timestamps + interval joins (§1.7) | stream ⋈ stream | out of scope |

## Nearby gaps not in #142

- `-o` is refused; with step 1 a per-batch `FileSink` (CSV/NDJSON) is simple.
- `LIMIT n` above the fused aggregate is streamable: allow a `GlobalLimitExec`
  above the fused exec in the shape check.
- `session()` windows: a per-key gap timeout driven by the watermark makes them
  streamable; after §3, since session state is per key.
