# Design: one engine-neutral scan layer for the DataFusion and DuckDB frontends

Status: adopted 2026-11-15. Decisions taken on the points this document left
open are recorded in
[`duckdb-v2-extension-roadmap.md`](duckdb-v2-extension-roadmap.md) section 2:
the Arrow-import route is not used (DuckDB gets its own `ChunkWriter` sink, no
`pcapsql-arrow` crate), the per-table `timestamp` column is exposed by DuckDB
only, the two coercion changes of section 3.5 are accepted, and the `Layers`
option of section 3.3 is not needed in the first version. Where this document
and the roadmap differ, the roadmap wins.

Written as a proposal against HEAD `7290dd0`. Nothing here had been compiled
when it was written. Signatures were checked by reading the core types they use
(`PacketReader`, `PacketRef`, `PacketRange`, `ParseResult`, `FieldValue`,
`FieldHint`, `ParseScope`, `ProtocolRegistry`, `DataKind`, `BoundaryIndex`,
`StreamHeader`). All `path:line` references are to that commit.

## Recommendation

Move the scan logic that is engine-neutral in concept out of
`pcapsql-datafusion/src/query` into a new module **`pcapsql_core::scan`** (no
new crate, no new dependency, no feature flag), and make both frontends thin
adapters over it. The module owns the table catalogue, the scan plan
(`ScanPlan`, today `ParseSubscription`), the predicate IR, the
`FieldValue` to column coercion, per-frame routing (protocol tables, fused
joins, row caps), the stream-table observer, partition planning, and one
resumable per-partition driver `PartitionScan<R>::step<S: RowSink>()`. A sink
only stores already-coerced typed cells; it never sees a `FieldValue`. Push
and pull are the same loop: the driver returns `Step::Flush(output)` when a
sink is full, and the caller decides what that means (DataFusion hands the
batch to its exchange and calls `step` again; DuckDB returns the chunk and
calls `step` on the next `exec`). The only generic parameters are the reader
`R` and the sink `S`; everything per query stays non-generic. The DuckDB
roadmap's `pcapsql-duckdb/src/scan/` tree is dropped, and three of its five
core changes turn out to exist already. The Arrow builders stay in
`pcapsql-datafusion` unless the Arrow-import route for DuckDB proves viable,
in which case they move to a small `pcapsql-arrow` crate and DuckDB uses that
sink instead of writing its own; nothing else in this design changes.

Two findings shaped this more than expected:

- The existing hot path has **no `dyn` dispatch to remove**. Readers are
  generic (`process_packets<F>` makes `PacketReader` non-object-safe,
  `io/source.rs:206-210`), parsers are enum-dispatched
  (`protocol/registry.rs:170-200`), builders are an enum
  (`builders/protocol.rs:17-37`). The goal for the shared layer is to keep
  that property across a new abstraction boundary, not to gain speed from it.
  The measurable costs today are elsewhere (section 2).
- The existing benchmarks **do not measure the code this refactor touches**
  (section 2.3). A scan-level benchmark has to be added first.

---

## 1. Inventory

Classes: **(a)** engine-neutral logic, **(b)** Arrow-specific but
DataFusion-independent, **(c)** DataFusion-specific. Line counts are
non-test lines unless stated.

### 1.1 `pcapsql-datafusion/src/query`

| File | Lines (total / non-test) | (a) | (b) | (c) | Coupling points |
|---|---|---|---|---|---|
| `providers/shared.rs` | 946 / 946 | ~520: `TableSubscription`, `ParseSubscription`, `parse_scope()` (68-200); `decide_ranges`, thresholds, `auto_target_partitions` (39-63, 323-361); `parse_partition` loop (378-439); `stream_partition` loop incl. timeout/cancel/flush handling (696-790); `OpenReader` (656-682) | ~120: `table_schema()` (205-223), `TableData` (228-243), `PartitionOutput.batches`, `assemble_pass` (444-516) | ~300: `StreamingHandle`, `start_streaming_parse` with `tokio::spawn_blocking` and exchanges (646-651, 795-871), `ParseStats`/`ServedFrom` engine reporting (245-304) | `SchemaRef`, `RecordBatch` (19-20); `FilterEvaluator` in `TableSubscription.predicate` (74); `Arc<FrameJoinSpec>` whose `schema` is Arrow (82); `HashSet<String>` column sets resolved against the Arrow schema (72, 205-222); `tokio::task::JoinHandle` (21) |
| `filter.rs` | 406 / 276 | ~180: `CompareOp`, `SimplePredicate`, `field_as_i64`/`field_as_str`, `matches_result` (20-151, minus `from_datafusion`) | 0 | ~95: `CompareOp::from_datafusion` (32-42), `try_from_exprs`, `expr_is_pushable`, `convert_*` (164-275) | `Expr`, `BinaryExpr`, `Operator`, `ScalarValue` (14-15). The IR itself is already Arrow-free; only its construction is not. Semantics are stated in Arrow terms ("the way the Arrow column would compare", 90-93) but are really about the logical column kind |
| `builders/protocol.rs` | 907 / 702 | ~80: `ParsedSource`, `FrameSource` (468-490) and their resolution from column names (533-554); the row loops (603-614, 629-650) | ~620: `DynamicBuilder` (17-466), batch build/reset (671-700) | 0 | The coercion rules (153-367) are (a) in meaning but written as Arrow builder calls. `tables::get_table_schema` (518) returns an Arrow `Schema` |
| `builders/normalized.rs` | 614 / 435 | ~250: `TableSlot` caps and done-ness (66-92), `slot_for_layer` (204-217), `add_packet_from_ref` routing (258-352), `all_capped` (377-379), `row_count` | ~60: `BatchSink::Accumulate`, `RowBuilder` enum (21-63), `finish_inner` | ~125: `BatchSink::Stream`, `may_proceed`, `deliver`, `Pacer` use (224-252), `flush_partial` (356-370) | `RecordBatch` (13); `BatchSender`/`Pacer` (16); `FilterEvaluator` (12). Routing is welded to "a full builder yields a `RecordBatch` that is delivered inside the packet callback" (286-292) |
| `builders/fused.rs` | 222 / 222 | ~130: `Source` (16-28), `RowRef` markers (32-36), the per-frame join evaluation (99-155) | ~90: `DynamicBuilder` use, `build` (156-221) | 0 | `Arc<FrameJoinSpec>` and its Arrow `schema` (42, 74-79) |
| `stream_tables.rs` | 743 / 696 | ~330: `StreamSubscriber::new/observe` (35-103), `TcpSegment::from_layers` (245-294), `tls_sessions()` fold (171-213), ordering (164-168), helpers (296-350, 654-696) | ~340: four hand-written batch builders (352-650), `chunked` (219-232) | ~25: `TableData` result | `RecordBatch`, typed Arrow builders (17-22); schemas fetched by name from `tables` (108) |
| `fusion/mod.rs` | 709 / 709 | ~75: `JoinKind`, `Member`, `MemberJoin`, `FusedColumn`, `member_fields`, `describe` (71-165) | ~10: `FrameJoinSpec.schema: SchemaRef` (118) | ~620: `FrameJoinProvider`, `FuseFrameJoins` optimizer rule, plan matching and rewriting (168-709) | `SchemaRef` inside the spec |
| `arrow_schema.rs` | 288 / 158 | 0 | ~120: `DataKind` to `DataType` (13-58), address-column detection (60-127) | ~30: `field_value_to_scalar` (128+) | Correct home already; stays |
| `tables/` (33 files) | 2953 | The table list, stream-table list, pseudo-column rules, prefix stripping (`mod.rs:108-230`), and the descriptor/table drift test (`mod.rs:259-327`) are (a) in content | all column lists are written as Arrow `Field`s | 0 | **The table catalogue's source of truth is Arrow code in the DataFusion crate.** DuckDB cannot produce the same tables without it |
| `providers/exchange.rs` | 440 / 314 | 0 (the wait rule is specific to how DataFusion polls) | 0 | 314 | `RecordBatch`, `DFResult`, `tokio::sync::mpsc`, `Notify` (44-47) |
| `providers/scan_exec.rs`, `protocol_provider.rs`, `mod.rs` | 352 + 430 + 100 | 0 | ~40 (`TableCache` column-set logic is Arrow-schema based) | rest | `ExecutionPlan`, `TableProvider`, `Session` |
| `query/mod.rs` | 1916 | ~60: the multi-scan and cache-union rules in `build_subscription` (1786-1858) are policy, not engine code | 0 | rest: `QueryEngine`, `harvest_table_needs` (585-639), `ParseSource` (387-498) | `LogicalPlan`, `Expr` in `TableNeeds` (556-570) |
| `streaming/`, `windowing/` | 1558 + 1823 | window maths already lives in `pcapsql_core::windowing` | 0 | all | physical plan operators |
| `udf/` (18 files) | 7811 / ~5400 | ~1700: pure kernels, e.g. `format_tcp_flags`/`check_tcp_flag` (`tcp.rs:100-181`), `ip_proto_to_name`/`ethertype_to_name`/`dscp`/`ecn` (`protocol.rs:110-482`), DNS/ICMP name tables (`dns.rs:99-295`, `icmp.rs:115-538`), CIDR and class tests (`ipv4.rs:258-302`, `ipv6.rs:245-298`), MAC parse/format/class (`mac.rs:187-268`), hex (`hex.rs:86-165`), histogram rendering (`histogram.rs:333-440`) | ~2500: array downcasts and collection in every `invoke_with_args` (e.g. `tcp.rs:83-97`) | ~1200: `ScalarUDFImpl`/`AggregateUDFImpl` boilerplate, signatures, registration (`mod.rs:175-380`), `CaptureTimeRange` time UDFs | Kernels return `String` per row; none takes Arrow types |
| `views/` (24 files) | 1892 | The join shapes are (a) and equal `FrameJoinSpec` in content | 0 | SQL text in DataFusion's dialect with DataFusion UDF names | |
| `bpf/` | 1436 | `ast.rs`, `parser.rs` (879) | 0 | `sql.rs` (352) emits DataFusion SQL | Not needed by this design |

Totals for the scan path proper (`providers/shared.rs`, `filter.rs`,
`builders/*`, `stream_tables.rs`, the spec part of `fusion`, `tables/`):
about 6,900 non-test lines, of which roughly **1,600 are neutral logic,
4,200 are Arrow-typed (2,950 of them the table column lists), and 1,100 are
DataFusion-specific**.

### 1.2 Old `pcapsql-duckdb` (3,732 lines; all replaced)

| File | Lines | Class | What survives as an idea |
|---|---|---|---|
| `vtab/read_pcap.rs`, `vtab/protocol_tables.rs` | 522 + 569 | DuckDB v1 specific; ~250 lines duplicated between them | Nothing. The read loop pauses by returning a fake error matched by string (audit section 2) |
| `vtab/batch_builder.rs` | 431 | DuckDB v1 | The list-column child-vector bookkeeping maps onto `ListSink` (section 3.4) |
| `vtab/registry.rs`, `duckdb_schema.rs` | 407 + 49 | DuckDB v1; a second `DataKind` mapping | Replaced by one `ColKind` mapping |
| `udf/*` | 1449 | ~230 lines of pure kernels (`protocol.rs:303-505`, `cidr.rs:162-235`, `address.rs:338-355`) duplicated from DataFusion and already diverged: `ip_proto_to_string` knows 11 protocols and falls back to `PROTO{n}` (`pcapsql-duckdb/src/udf/protocol.rs:413-429`) where DataFusion's `ip_proto_to_name` is the IANA table (`udf/protocol.rs:110-306`); `dns_rcode` takes `u16` in one and `u8` in the other | Kernels move to core (section 3.9) |

### 1.3 What core already provides (affects the roadmap's C1 to C5)

| Roadmap item | State in core today |
|---|---|
| C1 reader over any `Read` | `GenericPcapReader<R: Read>` is public with `with_format` and `with_format_starting_at` (`io/pcap_stream.rs:263-306`, exported `io/mod.rs:39`). `StdinPacketSource::from_reader` already probes and reads any `Read + Send + 'static` sequentially (`io/stdin.rs:384`). Missing: a public `PacketReader` over `R` with the `end_frame` logic that is private to `FilePacketReader` (`io/source.rs:487-507`), a public probe (`probe_stream` is private), and exports for `synth_legacy_header`/`synth_pcapng_header` (`io/index.rs:655,671`, not in `io/mod.rs:33-36`) |
| C2 stop without consuming | Half there: a callback error stops the loop and the delivered packet counts as consumed, documented and tested (`io/pcap_stream.rs:408-415, 723-760`). There is no way to stop *before* a packet |
| C3 index without `Path` | Done: `build_boundary_index<R: Read>` (`io/index.rs:444`), `BoundaryIndex::to_bytes`/`from_bytes` (`io/index.rs:250, 289`), `matches_source` (`io/index.rs:167`) |
| C4 slot-indexed field access | Not as described. Parsers push `(&'static str, FieldValue)` conditionally (`protocol/udp.rs:102-113`), so a field's position is not fixed by `schema_fields()`. What exists is `LayerRef::get_hinted` (`ParseResult::get_hinted` when this was written) with a per-column `FieldHint` (`protocol/context.rs:206-224, 322-351`): one pointer compare when the field is where it was in the previous row |
| C5 encapsulation depth | Done: `ParseResult.encap_depth`, `tunnel_type`, `tunnel_id` (`protocol/context.rs:247-254`); since section 3.6.1 they are methods of `LayerRef` |

---

## 2. Hot-path analysis

### 2.1 Per packet (DataFusion today)

| Step | Where | Dispatch | Hashing / allocation / string work |
|---|---|---|---|
| Read record, build `PacketRef` | `io/pcap_stream.rs:481-520` via `FilePacketReader::process_packets` (`io/source.rs:487-507`) | static; `F` monomorphised | none per packet (buffer refills only) |
| Timestamp min/max | `providers/shared.rs:395-401` | | |
| `parse_packet` | `protocol/mod.rs:329-410` | enum over 27 parsers (`registry.rs:170-200`); candidate lists per parent (`registry.rs:574-599`; since then tables keyed by hint and value, `Protocol::dispatch` and `ProtocolRegistry::find_next`, with no `can_parse` call per layer) | **One heap allocation per packet**: `Vec::with_capacity(8)` of `(&'static str, ParseResult)` (`mod.rs:337`). A replica of the type definitions measures `FieldValue` 32 B, field entry 48 B, `ParseResult` 960 B, so the allocation is 7.8 kB and every pushed layer is a 976 B move. Scope lookup is a `OnceLock` read (`mod.rs:292-299`), no hashing. Hints are found by string compare over at most 4 entries (`context.rs:154-157`); `result.hint("tunnel_type")` runs on every layer (`mod.rs:390`) (since then hints are an array indexed by `HintKey`: a lookup is a bit test and a load). A failed parse allocates a `String` (`context.rs:245`) |
| Stream observer (only when stream tables are subscribed) | `stream_tables.rs:72-103, 245-294` | static | 10 unhinted `result.get(name)` string scans per TCP packet; `process_segment` returns a `Vec` |
| Route frame row | `builders/normalized.rs:266-295` | enum `RowBuilder` | `self.protocol_name != "frames"` string compare per packet (`protocol.rs:597`) |
| Route each layer | `normalized.rs:298-324` | | `slot_for_layer`: pointer compare over the layer names seen so far (206-217) |
| Predicate | `filter.rs:122-141` | enum `SimplePredicate`, recursive `Box` | **unhinted** `result.get(field)`: linear string compares over the layer's fields, per conjunct, per row (125, 131) |
| Fused joins | `builders/fused.rs:112-125` | | `m.table == "frames"` and `*name == m.table` are `String` compares per member per layer per packet |
| Progress | `shared.rs:411-413` | `Arc<dyn Fn(u64)>` once per 1024 packets | atomic add |

### 2.2 Per row and per value

| Step | Where | Cost |
|---|---|---|
| Per column: source select | `protocol.rs:629-650` | match on `ParsedSource` (jump) |
| Field lookup | `context.rs:337-351` | hit: one pointer + length compare. **Miss (an optional field that is absent, e.g. `tcp.mss`): a full linear scan with string compares, every row** |
| Coerce and append | `protocol.rs:153-367` | match on `DynamicBuilder` variant (jump), then match on `FieldValue` variant (predictable branch), then the typed Arrow append |
| `IpAddr`/`MacAddr`/number into a `Utf8` column | `protocol.rs:238-247` | `to_string()` / `format!` allocation per value |
| Pseudo-columns | `protocol.rs:631-644`, `370-416` | each `append_u64`/`append_u8`/... re-checks the builder variant with `if let` |
| Batch flush | `protocol.rs:671-692` | `RecordBatch::try_new`; every builder is dropped and re-created with `capacity * 32` bytes for strings (686-689), although `finish()` already leaves an Arrow builder reusable |
| Delivery | `normalized.rs:244-252` | exchange send, or `Vec::push`; may block on the `Pacer` |

So per value the dispatch is already "one jump plus one predictable branch".
A generic sink cannot beat that; a `dyn` sink would add an indirect call per
value on top of it (20 to 36 columns per row for `tcp`/`tls`). That is the
case for static dispatch here: it preserves the status quo.

### 2.3 What the benchmarks measure

Harness: Criterion, `pcapsql-datafusion/benches/baseline.rs` (192 lines), one
generated capture of 20,000 Ethernet/IPv4/UDP frames (18-19, 48-62).

| Bench | What it actually exercises |
|---|---|
| `parse_throughput/full_parse_udp` (91-111) | `parse_packet` alone with `ParseScope::full()`. No reader, no routing, no builders |
| `engine_open/eager_full` (115-127) | Source open (the eager parse it was named for is gone) |
| `query/*` (134-190) | Engine built once with `..Default::default()` (79-87), i.e. `RetentionPolicy::CacheOnTouch` (`query/mod.rs:304`). After warm-up every iteration is a cache hit (or the index fast path for `full_scan_count`), so these time DataFusion over cached batches, not the scan |

Gates: `docs/query-scoped-parse-migration.md` section 8 defines the benches a
phase "must move" or "must not regress", recorded by hand in each PR. CI only
compiles them (`.github/workflows/ci.yml:35-36`); nothing runs or compares
them. Section 8 also lists `keylog_e2e`, per-fixture payload benches and
`parse_throughput` at 1..N partitions, none of which exist in
`baseline.rs`.

Consequence: **no existing benchmark would notice a regression in routing,
coercion or batch building.** Step S0 of the migration adds one.

Correctness guards that do cover the scan path: `pcapsql-core/tests/partition_equivalence.rs`
(reader level, proptest), `tests/engine_shared_parse.rs` (one pass, 1-vs-N,
scoping, LIMIT early stop, hash-join deadlock, ordering), `tests/golden_corpus.rs`
(77 snapshots), `tests/streaming_memory.rs`, `tests/continuous.rs`,
`tests/stdin_source.rs`, and the unit tests in `builders/` and `filter.rs`.

---

## 3. Proposed architecture

```
pcapsql-core
  io/        + Pause, PacketReader::process_packets_flow, ReadPacketReader<R>, StreamHeader::probe
  format/    + UDF kernels (names, flags, cidr, mac, hex)
  scan/      NEW, no dependencies beyond core's
    catalog.rs    TableDef, ColumnDef, ColKind, ColumnSource, Catalog
    plan.rs       ScanPlan, TableScan, FusedScan, CompiledScan, OutputPlan
    predicate.rs  RowPredicate, FramePredicate, CompiledPredicate
    sink.rs       RowSink, ListSink, Full
    row.rs        write_value / write_layer_row / write_frame_row   (generic, #[inline])
    route.rs      route_frame: tables, caps, fused, resume cursors  (generic over S)
    fused.rs      FusedEval: per-frame join tuples                  (non-generic)
    stream.rs     StreamObserver, StreamTables                      (non-generic + generic emit)
    partition.rs  partition_target, plan_ranges, PartitionQueue     (non-generic)
    driver.rs     PartitionScan<R>, Step, ScanStats

pcapsql-datafusion            pcapsql-duckdb
  ArrowSink: RowSink            engine/writer.rs  ChunkWriter<'chunk>: RowSink
  Expr -> RowPredicate          engine/pushdown.rs Expression -> FramePredicate
  harvest -> ScanPlan           bind/init -> ScanPlan
  exchange, Pacer, ScanExec     claim_batch -> PartitionQueue + ReadPacketReader<DuckFile>
  push loop over step()         exec -> one step()
```

### 3.1 Core reader seam (replaces roadmap C1 and C2)

```rust
// io/pcap_stream.rs
/// What the reader does with the packet the callback was just shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pause {
    /// The packet is consumed. The next call starts at the following record.
    After,
    /// The packet is not consumed and its frame number is given back.
    /// The next call delivers the same packet again.
    Before,
}

#[derive(Debug, Clone, Copy)]
pub struct Delivered {
    /// Packets consumed by this call (a `Pause::Before` packet is not counted).
    pub consumed: usize,
    pub paused: Option<Pause>,
}

// io/source.rs
pub trait PacketReader: Send + Unpin {
    fn process_packets_flow<F>(&mut self, max: usize, f: F) -> Result<Delivered, Error>
    where
        F: FnMut(PacketRef<'_>) -> ControlFlow<Pause>;

    /// Existing method, now provided. Same contract as today: a callback
    /// error stops the loop and the delivered packet is consumed.
    fn process_packets<F>(&mut self, max: usize, mut f: F) -> Result<usize, Error>
    where
        F: FnMut(PacketRef<'_>) -> Result<(), Error>,
    {
        let mut err = None;
        let d = self.process_packets_flow(max, |p| match f(p) {
            Ok(()) => ControlFlow::Continue(()),
            Err(e) => { err = Some(e); ControlFlow::Break(Pause::After) }
        })?;
        match err { Some(e) => Err(e), None => Ok(d.consumed) }
    }
    // position, set_read_timeout, take_read_timeout, cancelled, link_type: unchanged
}
```

`Pause::Before` is implemented in the two loops of `pcap_stream.rs`
(`process_legacy_packets` 481-558, `process_pcapng_packets` 560-712): skip
`reader.consume(offset)` and undo `*frame_number += 1`. All four readers
(`FilePacketReader`, `MmapPacketReader` `io/mmap.rs:364`, `CloudPacketReader`,
`StdinPacketReader` `io/stdin.rs:532`) wrap `GenericPcapReader`, so each
forwards one more method. To verify in the unit test: `pcap_parser`'s
`next()` returns the same block again when `consume` was not called (this is
its `next`/`consume` contract, and `read_legacy_header_link_type` already
relies on it: it returns on the first packet block without consuming it,
`pcap_stream.rs:353-356`).

```rust
// io/read_source.rs (new)
/// A PacketReader over any `Read`: the shape `FileInner` has today (source.rs:248).
pub struct ReadPacketReader<R: Read> {
    inner: GenericPcapReader<DecompressReader<Chain<Cursor<Vec<u8>>, R>>>,
    link_type: u32,
    end_frame: Option<u64>,
}
impl<R: Read + Send> ReadPacketReader<R> {
    /// Whole capture. `head` is what `StreamHeader::probe` already consumed.
    pub fn sequential(read: R, header: &StreamHeader, head: Vec<u8>) -> Result<Self, Error>;
    /// `read` is positioned at `range.start.byte_offset`. Uncompressed captures only.
    pub fn at(read: R, format: PcapFormat, index: &BoundaryIndex, range: &PacketRange)
        -> Result<Self, Error>;
}
impl<R: Read + Send> PacketReader for ReadPacketReader<R> { /* source.rs:487-520 moved */ }

impl StreamHeader {
    /// Detect compression, format, link type from the head of a stream
    /// (stdin.rs `probe_stream`, made public).
    pub fn probe<R: Read>(read: &mut R) -> Result<(StreamHeader, Vec<u8>), Error>;
}
pub type FilePacketReader = ReadPacketReader<std::fs::File>;
```

`GenericPcapReader` already carries `unsafe impl<R: Read + Send> Send`
(`pcap_stream.rs:714`), so `ReadPacketReader<DuckFile>` is `Send` when
`DuckFile` is, as a DuckDB local state requires.

### 3.2 Catalogue: one logical schema for both engines

```rust
// scan/catalog.rs
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)] pub struct TableId(pub u16);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)] pub struct ColId(pub u16);  // index into TableDef::columns
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)] pub struct OutCol(pub u16); // ordinal in a scan's output

/// Flat, `Copy` column kind: what a sink can store. Built from `DataKind`
/// at catalogue construction, so an unsupported kind fails there, not as a
/// silently mistyped column (today's Utf8 fallback, builders/protocol.rs:81-88).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColKind {
    Bool, U8, U16, U32, U64, I8, I64, F64, Str, Bin, Fixed(u16),
    TsMicros, TsNanos,
    ListU16, ListU32, ListStr, ListBin, ListFixed(u16),
}
// As built there is no conversion from or to `DataKind`: the column lists
// name their kinds, and a test compares them with the parsers' descriptors.

/// Where a column's value comes from. Today three private enums say the same
/// thing: ParsedSource and FrameSource (builders/protocol.rs:470-490) and
/// fused::Source (builders/fused.rs:16-28).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColumnSource {
    FrameNumber, Timestamp, CapturedLen, OriginalLen, LinkType, RawData,  // PacketRef
    EncapDepth, TunnelType, TunnelId,                                     // the layer's parse context
    Field(&'static str),                                                  // parser field, short name
}

pub struct ColumnDef {
    pub name: &'static str,
    pub kind: ColKind,
    pub nullable: bool,
    pub source: ColumnSource,
    /// Part of `SELECT *`. `false` marks columns an engine may opt into
    /// (DuckDB's per-table `timestamp`, roadmap 4.2) without changing the
    /// DataFusion tables or the golden snapshots.
    pub default: bool,
}
pub enum TableKind { Frames, Protocol, Stream }  // a stream table is told from the others by its name
pub struct TableDef {
    pub name: &'static str,
    pub description: &'static str,  // the line a frontend lists the table with (`pcap_protocols()`)
    pub kind: TableKind,
    pub columns: Box<[ColumnDef]>,
    /// Columns the rows are ordered by (ProtocolScanExec::PROTOCOL_ORDERING today).
    pub ordering: &'static [&'static str],
}
pub struct Catalog { /* tables: Vec<TableDef>, by_name */ }
impl Catalog {
    pub fn builtin() -> &'static Catalog;
    pub fn table(&self, name: &str) -> Option<(TableId, &TableDef)>;
    pub fn get(&self, id: TableId) -> &TableDef;
    pub fn tables(&self) -> impl Iterator<Item = (TableId, &TableDef)>;
}
```

The column lists are the current `tables/*.rs` contents re-expressed with
`ColKind`. They are kept as explicit lists, not derived from
`Protocol::schema_fields()`: a crude textual comparison of descriptor order
against table column order matches for 17 of 27 protocols only (three differ
because of `NOT_EXPOSED_AS_COLUMNS`, `tables/mod.rs:237-247`; for `gtp`,
`http`, `ospf` the sets have equal size but the order looked different), and
addresses are typed in the tables (`UInt32`, `FixedSizeBinary(16)`,
`FixedSizeBinary(6)`) while descriptors say `String` (`tables/mod.rs:249-258`).
Deriving would change `SELECT *` and the golden snapshots.

DataFusion keeps `arrow_schema.rs` and maps `TableDef` to an Arrow `Schema`;
DuckDB maps `ColKind` to logical types in `engine/`. `pcap_schema()` and
`pcap_protocols()` read the same catalogue.

### 3.3 Scan plan and predicate IR

```rust
// scan/plan.rs
pub enum Layers { All, Outermost }            // roadmap 4.1 `all_layers`

pub struct TableScan {
    pub table: TableId,
    /// Output columns in output order. DataFusion passes schema order (as
    /// today, shared.rs:211-221); DuckDB passes its projected column order.
    pub columns: Vec<ColId>,
    /// Conservative row filter on the table's own layer.
    pub predicate: Option<RowPredicate>,
    /// Row cap from a pushed-down LIMIT (per partition).
    pub fetch: Option<u64>,
    pub layers: Layers,
}
pub struct FusedMember { pub table: TableId, pub join: Option<MemberJoin> } // fusion/mod.rs:79-100
pub struct FusedScan {
    pub members: Vec<FusedMember>,
    pub columns: Vec<(u16, ColId)>,           // (member, column of that member's table)
    pub fetch: Option<u64>,
}
#[derive(Default)]
pub struct ScanPlan {
    pub tables: Vec<TableScan>,               // at most one per table in v1 (as today)
    pub fused: Vec<FusedScan>,
    pub streams: Vec<TableScan>,              // tables of TableKind::Stream
    pub frames: FramePredicate,               // exact, applied before parsing
    pub timestamps: TsUnit,                   // Micros (DataFusion) | Nanos (DuckDB)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)] pub struct OutputId(pub u16);

impl ScanPlan {
    /// Resolve everything a packet loop must not look up: the ParseScope
    /// (shared.rs:138-200 moved here), per-output column plans, layer routing.
    pub fn compile(&self, catalog: &Catalog, registry: &ProtocolRegistry)
        -> Result<CompiledScan, PlanError>;
    /// Until the driver builds stream tables (S4c), `compile` refuses a plan
    /// that has any (it would give them no rows), and a frontend that builds
    /// them itself, from a `FrameObserver`, compiles with this.
    pub fn compile_with_streams(&self, catalog: &Catalog, registry: &ProtocolRegistry)
        -> Result<CompiledScan, PlanError>;
}
pub struct OutColumn { pub name: &'static str, pub kind: ColKind, pub nullable: bool, pub source: ColumnSource }
pub struct OutputPlan { pub table: Option<TableId>, pub columns: Box<[OutColumn]> /* + private routing */ }
pub struct CompiledScan { /* scope: ParseScope, outputs: Box<[OutputPlan]>, ... */ }
impl CompiledScan {
    pub fn scope(&self) -> &ParseScope;
    pub fn outputs(&self) -> &[OutputPlan];        // tables, then fused, in plan order
    pub fn stream_outputs(&self) -> &[OutputPlan];
    /// Stream tables need the capture in order (shared.rs:536-541).
    pub fn requires_single_partition(&self) -> bool;
}
```

```rust
// scan/predicate.rs
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmpOp { Eq, NotEq, Lt, LtEq, Gt, GtEq }
#[derive(Clone, Debug, PartialEq)]
pub enum Literal { Int(i64), Str(Box<str>) }

/// Conservative field predicate: may only drop a row on a positively false
/// comparison (filter.rs:7-12). The engine re-checks.
#[derive(Clone, Debug)]
pub enum RowPredicate {
    Cmp { column: ColId, op: CmpOp, value: Literal },
    And(Vec<RowPredicate>),
}
impl RowPredicate {
    /// `None` when nothing can drop a row (replaces `is_always_true`).
    pub fn compile(&self, table: &TableDef) -> Option<CompiledPredicate>;
}
pub struct CompiledPredicate { /* flat terms: source, FieldHint, op, literal */ }
impl CompiledPredicate {
    pub fn keeps(&mut self, layer: LayerRef<'_, '_>) -> bool;   // hinted lookups
}

/// Exact predicate on packet metadata, enforced before parsing.
#[derive(Clone, Debug)]
pub struct FramePredicate {
    pub frames: (Bound<u64>, Bound<u64>),
    pub time_ns: (Bound<i64>, Bound<i64>),
}
impl FramePredicate {
    pub fn all() -> Self;
    pub fn is_all(&self) -> bool;
    #[inline] pub fn accepts(&self, p: &PacketRef<'_>) -> bool;
    /// No later frame can match: the scan can end (frame numbers ascend).
    pub fn past_end(&self, frame_number: u64) -> bool;
    pub fn may_overlap(&self, range: &PacketRange, time_ns: Option<(i64, i64)>) -> bool;
}
```

Front-ends:

| Engine | Function | Lives in | Notes |
|---|---|---|---|
| DataFusion | `fn row_predicate(exprs: &[Expr], table: &TableDef) -> Option<RowPredicate>` and `fn is_pushable(expr: &Expr, table: &TableDef) -> bool` | `pcapsql-datafusion/src/query/filter.rs` (what remains of it: 164-275 retargeted) | Column names resolve to `ColId` at conversion. Side benefit: predicates on `encap_depth`/`tunnel_id` become evaluable from the `ParseResult` context; today they convert to a field lookup that always misses (`filter.rs:125-134`) and are still reported `Inexact` |
| DuckDB | `fn frame_predicate(filters: &[Expression]) -> (FramePredicate, Vec<Accepted>)` | `engine/pushdown.rs` | Only `frame_number` and `timestamp` ranges, because V2 requires accepted filters to be exact (roadmap 5.5). The conservative `RowPredicate` is not offered to DuckDB as an accepted filter |

Exactness is carried by the type: `FramePredicate` is exact, `RowPredicate`
is conservative. An engine that needs exact field predicates later adds a
third type rather than a flag.

### 3.4 Sinks

```rust
// scan/sink.rs
/// The sink has no room for another row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Full;

/// Stores one output's rows. Called once per column per row, in column
/// order, with values already coerced to the column's `ColKind`
/// (`OutputPlan::columns[col]`), then `end_row`. Infallible: anything that
/// can fail (building a RecordBatch) happens when the engine takes the
/// rows, outside the packet loop.
pub trait RowSink {
    fn null(&mut self, col: OutCol);
    fn bool(&mut self, col: OutCol, v: bool);
    fn u8(&mut self, col: OutCol, v: u8);
    fn u16(&mut self, col: OutCol, v: u16);
    fn u32(&mut self, col: OutCol, v: u32);
    fn u64(&mut self, col: OutCol, v: u64);
    fn i8(&mut self, col: OutCol, v: i8);
    fn i64(&mut self, col: OutCol, v: i64);
    fn f64(&mut self, col: OutCol, v: f64);
    fn str(&mut self, col: OutCol, v: &str);
    /// `Bin`, and `Fixed(n)` with `v.len() == n` already checked.
    fn bytes(&mut self, col: OutCol, v: &[u8]);
    /// In the unit of the column's kind (`TsMicros` or `TsNanos`).
    fn timestamp(&mut self, col: OutCol, v: i64);

    type List<'s>: ListSink where Self: 's;
    /// Start a list cell. Items go to the returned writer; `finish` closes it.
    fn list(&mut self, col: OutCol) -> Self::List<'_>;

    /// Close the row. `Break(Full)`: the row was stored and no further row fits.
    fn end_row(&mut self) -> ControlFlow<Full>;
}
pub trait ListSink {
    fn null(&mut self);
    fn u16(&mut self, v: u16);
    fn u32(&mut self, v: u32);
    fn str(&mut self, v: &str);
    fn bytes(&mut self, v: &[u8]);
    fn finish(self);
}
```

Typed methods rather than one `put(col, Cell)` so that, after
monomorphisation, each arm of the coercion match calls a concrete store with
no second match in the sink.

How each sink stores without matching on type per value:

| Sink | Construction (once) | Per value |
|---|---|---|
| `ArrowSink` (DataFusion) | From `&[OutColumn]`: one typed `Vec` per builder type (`u16s: Vec<UInt16Builder>`, `strs: Vec<StringBuilder>`, ...) and `slot: Box<[u16]>` mapping `OutCol` to the index in its type's vector | `self.u16s[self.slot[col]].append_value(v)`: one load, no `match`. Lists keep a small enum (items are few) |
| `ChunkWriter<'chunk>` (DuckDB) | Per `exec`: fetch each output vector's data pointer and validity mask once (roadmap 5.3) | `*data[col].cast::<u16>().add(row) = v`; strings and blobs go to the vector's arena; lists track child offset per column |

`ArrowSink` additionally has, outside the trait:
`fn rows(&self) -> usize` and
`fn take_batch(&mut self) -> Result<Option<RecordBatch>, Error>` (the
zero-column case keeps its row count, `protocol.rs:674-683`). Builders are
reused across batches.

### 3.5 Coercion: one implementation, above the sink

`scan/row.rs` holds the only place a `FieldValue` meets a column kind:

```rust
#[inline]
pub(crate) fn write_value<S: RowSink>(sink: &mut S, col: OutCol, kind: ColKind, v: &FieldValue<'_>);
```

The rules are today's `DynamicBuilder::append_field_value`
(`builders/protocol.rs:153-367`), made normative. Both engines get them by
construction, which removes the DuckDB defects that come from writing by
value type (audit section 3: NULL `answer_ip6s`, VARCHAR IP addresses).

| Column kind | Accepted `FieldValue` | Otherwise |
|---|---|---|
| `U8` | `UInt8`; `UInt16/32/64` if it fits | NULL (never wrapped; test at `protocol.rs:728-748`) |
| `U16` | `UInt16`, `UInt8`; `UInt32/64` if it fits | NULL |
| `U32` | `UInt32`, `UInt8`, `UInt16`; `UInt64` if it fits; `IpAddr::V4` as `u32::from` | NULL (including `IpAddr::V6`) |
| `U64` | `UInt64`, `UInt8/16/32` | NULL (including `Int64`) |
| `I8` | `Int8`; `Int64` if it fits | NULL |
| `I64` | `Int64`, `Int8`, `UInt8/16/32`; `UInt64` if it fits | NULL |
| `F64` | `Float64`; any integer `as f64` | NULL |
| `Bool` | `Bool` | NULL |
| `Str` | `Str`; `IpAddr` and `MacAddr` formatted; numbers, floats and bools via `to_string` | NULL (`Bytes`, `List`) |
| `Bin` | `Bytes` | NULL (including `MacAddr`) |
| `Fixed(n)` | `MacAddr` (n = 6), `IpAddr::V6` (n = 16), `Bytes` of length n | NULL. **Change:** a wrong length is NULL; today the Arrow error is discarded (`let _ =`, `protocol.rs:256-264`) and the batch fails later |
| `TsMicros` | `Int64`; `UInt64` | NULL. **Change:** a `UInt64` above `i64::MAX` is NULL; today it wraps (`protocol.rs:278`) |
| `ListU16` | list; items `UInt16`, `UInt8` | non-list or `Null` gives a NULL cell; other items are NULL items; an empty list stays empty (test at `protocol.rs:753-811`) |
| `ListU32` | items `UInt32`, `UInt16`, `UInt8`, `IpAddr::V4` | same |
| `ListStr` | items `Str`, anything `as_string()` accepts | same |
| `ListBin` | items `Bytes` | same |
| `ListFixed(n)` | items `Bytes`, `IpAddr::V6`, `MacAddr` of length n | same |
| any | field absent, or `FieldValue::Null` | NULL |

Pseudo-columns: `frame_number` u64, never NULL; `encap_depth` u8;
`tunnel_type` `Option<&'static str>` from `TunnelType::as_str`
(`context.rs:62-75`); `tunnel_id` `Option<u64>`; frames `timestamp` is
`timestamp_ns / 1_000` for `TsMicros` (`protocol.rs:607`) or the nanosecond
value for `TsNanos`; `length`/`original_length` u32; `link_type` u16;
`raw_data` bytes.

Sanctioned differences between the engines, to be normalised in differential
tests: timestamp unit (`ScanPlan::timestamps`) and any opt-in non-default
columns. Nothing else.

**Field lookup (the real content of roadmap C4).** Column to field
resolution stays inside `row.rs` behind one private type, so the strategy can
change without touching sinks or engines:

```rust
pub(crate) struct FieldResolver { hints: Box<[FieldHint]> }   // one per output column
```

Version 1 is today's `get_hinted`. A measured follow-up replaces the
miss path (absent optional fields cost a full scan per row, section 2.2) with
a present-field-driven walk plus a written-columns bitmask for NULL fill.
Having parsers emit numeric field ids instead of names would make this a
plain index, but it touches all 27 parsers and is not proposed.

### 3.6 The resumable partition scan

```rust
// scan/driver.rs
pub enum Step {
    /// `max_packets` were consumed; nothing to hand on.
    More,
    /// Output `0` must be taken now: its sink is full, or it reached its row
    /// cap and holds a final partial batch (normalized.rs:282-290).
    Flush(OutputId),
    /// Every output is capped or closed (normalized.rs:377-379).
    Done,
    /// End of the range.
    End,
}
#[derive(Clone, Debug, Default)]
pub struct ScanStats { pub packets: u64, pub min_ts_ns: i64, pub max_ts_ns: i64, pub rows: Box<[u64]> }

pub struct PartitionScan<R: PacketReader> {
    reader: R,
    plan: Arc<CompiledScan>,
    registry: Arc<ProtocolRegistry>,
    cursors: Box<[OutputCursor]>,       // rows emitted (fetch), rows emitted of the current frame, resolver, closed
    observer: Option<StreamObserver>,
    current_frame_observed: bool,
    stats: ScanStats,
}
impl<R: PacketReader> PartitionScan<R> {
    pub fn new(reader: R, plan: Arc<CompiledScan>, registry: Arc<ProtocolRegistry>,
               observer: Option<StreamObserver>) -> Self;

    /// Read and route packets until a sink must be flushed, `max_packets`
    /// were consumed, every output is done, or the range ends.
    /// `sinks[i]` is the sink of `plan.outputs()[i]`.
    pub fn step<S: RowSink>(&mut self, sinks: &mut [S], max_packets: usize) -> Result<Step, Error>;

    /// The consumer of this output is gone; stop producing for it.
    pub fn close_output(&mut self, output: OutputId);
    pub fn reader(&self) -> &R;
    pub fn reader_mut(&mut self) -> &mut R;       // read timeouts, cancellation (shared.rs:715-748)
    pub fn stats(&self) -> &ScanStats;
    pub fn finish(self) -> (ScanStats, Option<StreamTables>);
}
```

The body of `step` is small and is the only place where both generic
parameters meet:

```rust
let d = reader.process_packets_flow(max_packets, |packet| {
    if !plan.frames.accepts(&packet) { return ControlFlow::Continue(()); }
    let layers = parse_packet(registry, packet.link_type, packet.data, plan.scope()); // non-generic
    if let Some(o) = observer { /* observe once per frame */ }
    route_frame(plan, cursors, sinks, &packet, &layers)                               // generic over S
})?;
```

**Resume rule (multi-row frames, tunnels).** `route_frame` writes the
frame's rows output by output: the frame row, each matching layer in order,
each fused tuple. Every output keeps `emitted_in_frame`. Rows with an index
below it are skipped. When `end_row` returns `Break(Full)`:

- if no row of this frame remains for any output, return `Pause::After`;
- otherwise record the counts and return `Pause::Before`. The reader does
  not consume the packet. The next `step` gets the same packet, parses it
  again (deterministic), skips the rows already written and continues.

`emitted_in_frame` resets when the packet is consumed. This gives:

| Property | Why it holds |
|---|---|
| A chunk is never overfilled | every row is followed by `end_row`; the sink says `Full` exactly at capacity |
| No row lost or duplicated | rows have a deterministic index within the frame; the cursor is the index of the next unwritten one |
| No packet re-read from I/O | the record is still in the reader's buffer; cost is one extra `parse_packet` per flush (1 in 2,048 packets at DuckDB's chunk size, 1 in 10,000 at DataFusion's default batch size, `query/mod.rs:303`) |
| No bound on rows per frame | a frame with more rows than a whole chunk (thousands of stacked VLAN tags in a crafted packet) spans several chunks through the same cursor. A "carry the frame's rows in local state" design (roadmap 5.3) needs owned copies or a bound |
| Side effects happen once | stream observation is guarded by `current_frame_observed`; packet count and progress use `Delivered::consumed`; row caps count written rows only |

**Push (DataFusion).** The body of `parse_partition`/`stream_partition`
(`shared.rs:378-439, 696-790`) becomes:

```rust
loop {
    match scan.step(&mut sinks, 1024) {
        Ok(Step::More) => { progress(); if interval_elapsed { flush_all_partial() } }
        Ok(Step::Flush(o)) => {
            if let Some(batch) = sinks[o.0 as usize].take_batch()? {
                if exchange.deliver(o, batch) == ConsumerGone { scan.close_output(o) }  // may block on the Pacer
            }
        }
        Ok(Step::Done) => { capped = true; break }
        Ok(Step::End) => break,
        Err(_) if scan.reader().cancelled() => { capped = true; break }
        Err(_) if scan.reader_mut().take_read_timeout() => { flush_all_partial(); continue }
        Err(e) => return Err(e.into()),
    }
}
```

`deliver` is today's `NormalizedBatchSet::deliver`/`may_proceed`
(`normalized.rs:224-252`), unchanged and still in the DataFusion crate; it
needs to see all of a partition's senders, which is why delivery sits in the
loop and not inside a sink. Behavioural difference: a fused batch is exactly
`batch_size` rows instead of up to one frame more (`fused.rs:156-157,
195-200`). Batch boundaries are not observable in query results.

**Pull (DuckDB).**

```rust
// exec
let mut writer = ChunkWriter::new(&mut chunk, plan.outputs()[0].columns());
let step = local.scan.step(std::slice::from_mut(&mut writer), usize::MAX)?;
chunk.set_len(writer.rows());
// Step::Flush => return, same partition next call.  Step::End => claim the next partition.
```

A stream table in pull mode is a blocking source: the first `exec` runs the
pass to `Step::End` with no table outputs, `finish()` yields `StreamTables`,
and later calls drain it with a row cursor (section 3.8).

### 3.6.1 Field storage as built

The scan above was first built on `parse_packet` as it was: every parser
returned a `ParseResult` (1,000 bytes: a `SmallVec` of sixteen 48-byte
fields, the remaining bytes, 152 bytes of hints, an error `String`, the
tunnel context), the walk moved it into a `Vec` of layers, and the scan
dropped that `Vec`'s contents after the packet's rows were written. A
`FieldValue` could own its data (`OwnedString`, `OwnedBytes`, `List(Vec)`),
so the drop was a loop over every field, TCP's twenty-four fields spilled
the `SmallVec` to the heap for every segment, and a DNS name was copied
into a `CompactString`. After the dispatch tables, that was what a parse
cost: `memcpy` and drop glue were about half of a `udp` scan's instructions.

Since then (`protocol/layers.rs`):

- `FieldValue<'a>` is `Copy` and owns nothing: `Str(&'a str)`,
  `Bytes(&'a [u8])` and `List(&'a [FieldValue<'a>])` are slices of the
  packet, of an arena, or static. It is 24 bytes and a field entry 40.
- A `ParseBuf`, one per partition scan, holds one vector for the fields of
  every layer of the packet, one for the layers (each a range of the field
  vector with its tunnel context, payload and error), and a `bumpalo`
  arena. `ParseBuf::for_packet` resets the arena and lends the three out as
  a `PacketLayers` whose lifetime is the packet's; taking the buffer by
  `&mut` is what lets the borrow checker prove that no value of the last
  packet is still alive. The vectors change element lifetime the way
  `LayerBuf` did (collecting an emptied `vec::IntoIter` in place): there is
  no `unsafe`.
- A parser writes its fields through a `FieldSink` (`push`; `str`,
  `format`, `list`, `ListBuilder` and `TextBuilder` for what it
  constructs, all in the arena; `name` for the text of a table of
  `format::names`, which is static for a number with a name) and returns a
  `Parsed { remaining, child_hints, status }`. `Status::Error` makes the
  walk truncate the field vector back to where the layer began;
  `Status::Partial` keeps the fields and stops the walk.
- `parse_packet(registry, link_type, data, scope, &mut buf)` returns the
  `PacketLayers`. `FrameObserver::observe`, `Router::route_frame` and the
  fused joins take `&PacketLayers`; `write_layer_row` and
  `CompiledPredicate::keeps` take a `LayerRef` (name, fields, `get`,
  `get_hinted`, `encap_depth`, `tunnel_type`, `tunnel_id`, `payload`,
  `error`). `LayerRef::new` and `PacketLayers::push_layer` build a layer by
  hand, for tests.
- Forgetting a packet is two length stores and a pointer reset.

The stream layer keeps values past their packets, so a `ParsedMessage`
holds `stream::OwnedFieldValue`, an enum of its own.

Measured with `pcapsql-core/examples/parse_cost.rs`, per packet through
`PartitionScan` into a sink that stores nothing (callgrind, bench
profile), before and after:

| Table (frame) | Instructions | Allocations |
|---|---|---|
| `frames` | 619 to 593 | 0 to 0 |
| `udp` | 3,930 to 2,529 | 0 to 0 |
| `tcp` (timestamp option) | 6,439 to 4,036 | 1 to 0 |
| `dns` (one answer) | 10,643 to 7,135 | 9 to 4 |
| `http` (a `GET`) | 11,436 to 7,959 | 1 to 0 |

What `dns` still allocates is `simple-dns`'s own (its record vectors and
the labels of each name); `tests/parse_alloc.rs` counts
`simple_dns::Packet::parse` on the same message and holds the scan to
exactly that, and holds `frames`, `udp`, `tcp` (SACK blocks and assembled
option texts included) and `http` to nothing. The remaining cost of a
`udp` scan is the walk itself (context and hints, about 950 instructions
for three layers), the router and row writer (460) and the three parsers
(450).

### 3.7 Where static dispatch matters, and how the generics stay contained

| Frequency | Code | Dispatch |
|---|---|---|
| per value | `RowSink` typed methods, `write_value`, `FieldResolver` | static, `#[inline]`; must be monomorphised into `route_frame` |
| per row | `end_row`, `CompiledPredicate::keeps`, row caps | static; `keeps` is non-generic |
| per packet | reader callback, `parse_packet`, `FramePredicate::accepts`, `StreamObserver::observe`, `FusedEval::tuples` | reader callback static (as today); the rest non-generic functions in core |
| per flush (batch or chunk) | `take_batch`, exchange delivery, DuckDB `exec` callback, progress callback | `dyn` or FFI is fine |
| per partition | open reader, `PartitionQueue::claim` | `dyn` is fine |
| per query | plan compile, catalogue, partition planning, `ParseSource` (`query/mod.rs:387`) | `dyn` is fine |

Generic parameters: `R` (reader) on `PartitionScan`, `S` (sink) on `step`.
Sinks of one pass are homogeneous, so the multi-table case is `&mut [S]` and
needs no router trait, no tuple of sinks and no third parameter.

Instantiations of the generic code (`step` + `route_frame` + `write_*`):

| Crate | `R` | `S` | Count |
|---|---|---|---|
| DataFusion | `FilePacketReader`, `MmapPacketReader`, `CloudPacketReader`, `StdinPacketReader` | `ArrowSink` | 4 (today `parse_partition` and `stream_partition` are each instantiated per reader: 8) |
| DuckDB | `ReadPacketReader<DuckFile>` | `ChunkWriter` | 1 |
| tests | `ReadPacketReader<Cursor<Vec<u8>>>` | `RecordingSink` | 1 |

Kept non-generic on purpose: plan compilation, predicate evaluation, fused
tuple computation (only the emit loop is generic), stream reassembly,
partition planning. `parse_packet` and `keeps` are non-generic functions
called across the crate boundary; the release profile already has
`lto = true, codegen-units = 1` (`Cargo.toml` `[profile.release]`), and the
small ones get `#[inline]`.

Rejected: a row writer generated per protocol (27 tables times sinks of
straight-line code). It would remove the per-value jump, but needs parsers to
emit typed structs and multiplies code size.

### 3.8 Stream tables and frame-join fusion

```rust
// scan/stream.rs  (stream_tables.rs:35-213, 245-350 moved; no Arrow)
pub struct StreamObserver { /* StreamManager, Vec<ParsedMessage>, wanted */ }
impl StreamObserver {
    pub fn new(wanted: &[StreamTable], keylog: Option<Arc<KeyLog>>) -> Self;
    pub fn observe(&mut self, packet: &PacketRef<'_>,
                   layers: &PacketLayers<'_, '_>) -> Result<(), Error>;
    pub fn finish(self) -> StreamTables;
}
pub struct StreamTables { /* connections, tls sessions, http messages, http2 messages, in table order */ }
impl StreamTables {
    pub fn rows(&self, table: StreamTable) -> usize;
    /// Write rows from `cursor` until the table ends or the sink is full.
    /// Returns the next cursor.
    pub fn emit<S: RowSink>(&self, table: StreamTable, columns: &[OutColumn],
                            cursor: usize, sink: &mut S) -> usize;
}
```

The four Arrow batch builders (`stream_tables.rs:352-650`) become four row
writers over `RowSink`, driven by the catalogue's column list instead of
positional `ArrayRef` vectors. DataFusion calls `emit` into an `ArrowSink`
and chunks by `batch_size` as `chunked` does today (219-232). The pass is
still pinned to one partition (`CompiledScan::requires_single_partition`).

```rust
// scan/fused.rs  (builders/fused.rs:99-155 moved)
pub(crate) struct FusedEval { member_rows: Vec<Vec<RowRef>>, tuples: Vec<RowRef>, next: Vec<RowRef> }
impl FusedEval {
    /// The frame's join tuples, `members` slots each. Non-generic.
    pub(crate) fn tuples(&mut self, plan: &FusedPlan,
                         layers: &PacketLayers<'_, '_>) -> &[RowRef];
}
```

`FusedPlan` stores member tables as resolved ids, removing the per-packet
`String` compares (section 2.1). `FrameJoinSpec` in the DataFusion crate
keeps its Arrow `schema` and optimizer rule and converts to `FusedScan` when
the subscription is built.

DuckDB has no optimizer hook in the C API (research note
`table_function_and_filesystem_api.md`, "no ... optimizer extension"), so it
cannot rewrite joins. It can still use fusion directly: each `*_packets`
view is a fixed `FusedScan`, so a `read_tcp_packets(file)` table function is
one pass with no join. That turns two roadmap P8 items ("`<proto>_packets`
table macros", "sharing one parse across several protocol tables") into
catalogue entries.

### 3.9 Partition planning and UDF kernels

```rust
// scan/partition.rs
pub struct PartitionPolicy { pub free_min_bytes: u64, pub cheap_min_bytes: u64, pub range_min_bytes: u64 }
impl Default for PartitionPolicy { /* 1 MiB, 4 MiB, 16 MiB: shared.rs:40, 47, 63 */ }

/// How many partitions to ask for (shared.rs:52-60 and 329-350 as one pure function).
pub fn partition_target(cost: SeekCost, size_bytes: u64, requested: Option<usize>,
                        parallelism: usize, policy: &PartitionPolicy) -> usize;

/// Ranges to scan: the index's partitions minus those the predicate excludes
/// (frame bounds exactly; time bounds by the checkpoints' min/max, index.rs:68-71).
pub fn plan_ranges(index: Option<&BoundaryIndex>, want: usize, frames: &FramePredicate) -> Vec<PacketRange>;

pub struct PartitionQueue { ranges: Box<[PacketRange]>, next: AtomicUsize }
impl PartitionQueue {
    pub fn new(ranges: Vec<PacketRange>) -> Self;
    /// The partition ordinal doubles as DuckDB's batch index.
    pub fn claim(&self) -> Option<(usize, &PacketRange)>;
    pub fn len(&self) -> usize;
}
```

DataFusion's `decide_ranges` keeps its fallback to one partition when the
index cannot be built (`shared.rs:351-360`) and calls `partition_target`.
Trimming by time range is new for both engines (the scoped-parse plan's P6
was never implemented in DataFusion).

UDF kernels go to `pcapsql_core::format` next to the existing
`format_ipv4`/`format_ipv6`/`format_mac` (`format/address.rs:32-90`):

```rust
// format/names.rs, flags.rs, cidr.rs, mac.rs, hex.rs
pub fn ip_proto_name(proto: u8) -> Cow<'static, str>;
pub fn ethertype_name(ethertype: u16) -> Cow<'static, str>;
pub fn dns_type_name(qtype: u16) -> Cow<'static, str>;
pub fn dns_rcode_name(rcode: u16) -> Cow<'static, str>;
pub fn icmp_type_name(t: u8) -> Cow<'static, str>;
pub fn icmp_code_name(t: u8, code: u8) -> Cow<'static, str>;
pub fn write_tcp_flags(flags: u16, out: &mut impl core::fmt::Write) -> core::fmt::Result;
pub fn has_tcp_flag(flags: u16, name: &str) -> bool;
pub fn parse_cidr_v4(cidr: &str) -> Option<(u32, u32)>;       // (network, mask)
pub fn ipv4_in_cidr(ip: u32, network: u32, mask: u32) -> bool;
pub fn parse_cidr_v6(cidr: &str) -> Option<([u8; 16], u32)>;
pub fn ipv6_in_prefix(ip: &[u8], network: &[u8; 16], prefix_len: u32) -> bool;
pub fn parse_mac(s: &str) -> Option<[u8; 6]>;
pub fn write_hex(bytes: &[u8], out: &mut impl core::fmt::Write) -> core::fmt::Result;
pub fn parse_hex(s: &str) -> Option<Vec<u8>>;
```

Scalars in, scalars or a writer out; no vectors. Each engine keeps its own
vectorised wrapper (null handling, constant arguments, registration). The
`Cow`/writer shapes also remove the `String` per row the name functions
allocate today. Not moved: the HDR histogram aggregate (state and
serialisation are engine-shaped; only `render_ascii`/`log_buckets` are
kernels and they depend on `hdrhistogram`), the `strftime` family (uses
`chrono`), and the capture-time UDFs.

---

## 4. Crate placement

| Option | For | Against |
|---|---|---|
| **`pcapsql_core::scan` module (recommended)** | No new published crate (the publish workflow releases `pcapsql-core` and `pcapsql-datafusion` only, `.github/workflows/publish-crates.yml`); needs no dependency core lacks; `ParseScope`, the reader seam and the catalogue's inputs are already there; core already hosts engine-neutral query support (`schema/`, `windowing/`, `format/detect_address_column`); both frontends already depend on core only | Core's public API grows and will churn while DuckDB lands. Mitigation: document `scan` as unstable until DuckDB P4 |
| New crate `pcapsql-scan` | API churn isolated from core's version; clearer "parsing vs tables" split | A third crate to publish and version in lockstep; no build-time gain (it depends on all of core and its generic code is instantiated downstream anyway); the reader seam and kernels still have to go into core |
| Leave it in `pcapsql-datafusion`, DuckDB depends on that | No move | Pulls `datafusion`, `arrow`, `tokio` into a DuckDB extension |

Dependency direction: `pcapsql-datafusion -> pcapsql-core`,
`pcapsql-duckdb -> pcapsql-core`. No feature flag is needed for `scan`.

| Crate | Keeps |
|---|---|
| `pcapsql-core` | Everything in section 3 |
| `pcapsql-datafusion` | `ArrowSink`, `arrow_schema.rs`, `Expr` to `RowPredicate`, plan harvest and the cache/multi-scan policy, `QueryTables`/`TableCache`, exchange and `Pacer`, `ProtocolScanExec`, the `FuseFrameJoins` rule and `FrameJoinSpec`, streaming window operators, views, UDF wrappers, BPF, CLI |
| `pcapsql-duckdb` | `engine/` only: callbacks, `DuckFile`, `ChunkWriter`, `Expression` to `FramePredicate`, `ColKind` to logical type, scalar wrappers, macros, replacement scan, panic guard |

**If DuckDB can consume Arrow batches** (V2 `arrow_importer_*`): `ArrowSink`
and `arrow_schema.rs` move to a new `pcapsql-arrow` crate that depends on
`arrow` but not `datafusion`; DuckDB's `exec` runs `step` into an `ArrowSink`
sized to the chunk capacity, then imports the batch; `ChunkWriter` is not
written. Consequences to weigh: DuckDB column types become whatever the
importer maps Arrow types to (so the 4.2 decisions are made by Arrow);
`duckdb-neo` builds against arrow 60 while this workspace pins 57
(`Cargo.toml`, research note `rust_ecosystem.md`), so the hand-off has to go
through the C Data Interface structs, whose ABI does not depend on the
arrow-rs version; and one more buffer hand-off per chunk unless the import is
zero-copy. Sections 3.1 to 3.3 and 3.5 to 3.9 are unaffected, and the
conformance suite (section 5.3) still applies to `ArrowSink`.

---

## 5. Migration plan

Every step is a separate PR that keeps `cargo fmt`, `clippy -D warnings`,
`cargo test --workspace` and the golden corpus green, and records the
benchmark numbers of S0.

### 5.1 Steps

| Step | Change | Guarded by (existing) | New tests | DuckDB phases it unblocks |
|---|---|---|---|---|
| **S0** Baselines | Add `benches/scan.rs`: (1) `run_shared_parse` over the 20k-packet capture for `frames`+`udp`+`ipv4`, all columns, 1 and 4 partitions; (2) the `query/*` cases under `RetentionPolicy::None` so they include the scan; (3) a tunnel-heavy and a TCP-options capture so list columns and absent optional fields are exercised. Add a table-driven coercion test over the existing `DynamicBuilder`: every `(DataType, FieldValue variant)` pair to its current output, as a snapshot | n/a | the two above | none; do first |
| **S1** Reader seam | `Pause`, `process_packets_flow`, `ReadPacketReader<R>`, public `StreamHeader::probe`, export synth-header functions; `FilePacketReader` becomes the alias | `partition_equivalence.rs`; `callback_error_consumes_the_delivered_packet` (`pcap_stream.rs:728`); `stdin_source.rs` | proptest: for any capture and any pause pattern (After/Before at arbitrary frames), each frame is delivered exactly once and in order, legacy and pcapng; `partition_equivalence` run through `ReadPacketReader<Cursor<Vec<u8>>>` | P1 (this is P1), P2 |
| **S2** Catalogue | `scan/catalog.rs`; port the 33 `tables/*.rs` column lists; DataFusion's `get_table_schema` becomes `to_arrow_schema(catalog.table(name))`; drift test moves to core | golden corpus (`SELECT *` order and types); `parser_field_descriptors_match_table_schemas` (`tables/mod.rs:260`); `every_table_column_type_has_a_builder` (`protocol.rs:711`) | for one commit, a test asserting the derived Arrow schema equals the legacy one for every table; then the legacy files are deleted | P2 (schema), `pcap_schema()` |
| **S3** Plan and predicate | `ScanPlan`, `CompiledScan`, `RowPredicate`, `FramePredicate`; `ParseSubscription` becomes a wrapper holding a `ScanPlan` plus the Arrow schemas derived from it; `FilterEvaluator` is replaced by the front-end functions; `FrameJoinSpec` gains `to_fused_scan()` | `filter.rs` tests (split: IR evaluation moves to core with hand-built IR, conversion stays); `normalized.rs` tests (544-613); `engine_shared_parse.rs` (`scoped_parse_builds_only_referenced_tables`, `cache_is_column_aware`); golden corpus | scope equivalence: for every golden query, the `ParseScope` compiled from the `ScanPlan` equals the one `parse_scope()` builds today (compare `required` and `projections`) | P3 |
| **S4a** Sink, coercion, routing (protocol tables and `frames`) | `RowSink`, `row.rs`, `route.rs`; `ProtocolBatchBuilder` becomes `ArrowSink`; `NormalizedBatchSet` keeps only delivery | S0 coercion snapshot (must be byte-identical except the two listed changes); golden corpus; `builders` unit tests; **S0 scan bench: no regression** | sink conformance suite (5.3) | P2 |
| **S5** Driver and partitioning | `PartitionScan`, `Step`; `parse_partition` and `stream_partition` become the push loop; `partition_target`, `PartitionQueue` | `engine_shared_parse.rs` (one pass, 1-vs-N, `streaming_limit_stops_scan_early`, `streaming_hash_join_completes_without_deadlock`, ordering tests at 499 and 575); `streaming_memory.rs`; `continuous.rs`; `stdin_source.rs` (timeouts, cancellation); S0 bench | pull-equivalence (5.3) | P2, P4 |
| **S6** Kernels | Move the shared kernels to `core::format`; DataFusion UDFs call them | UDF unit tests in each `udf/*.rs`; golden corpus queries using UDFs | kernel unit tests move with the kernels | P2 ("port scalars") |
| **S4b** Fused (**done**, see 5.1.1) | `scan/fused.rs`; delete `builders/fused.rs` | golden `f01`..`f06` and the view snapshots (fused under `RetentionPolicy::None` vs joins under `CacheOnTouch`) | conformance: fused rows at chunk capacity 1 | P8 only |
| **S4c** Stream tables | `scan/stream.rs`; `stream_tables.rs` shrinks to the `ArrowSink` call | `e2e_tls_http2.rs`; `http2_stream_table_is_on_demand`; golden stream snapshots | none beyond conformance | P8 only |
| **S7** Frame predicate and trimming | `plan_ranges` trimming; `FramePredicate` in the driver; optionally let DataFusion push `frame_number`/`timestamp` ranges on `frames` | golden corpus | results with trimming equal results without, over random ranges and strides | P6 |

Order: S0, S1, S2, S3, S4a, S5 are sequential. S6 is independent and can
start any time. S4b, S4c, S7 follow S5 in any order. DuckDB P0 (spike,
scaffolding, section 9 questions) depends on none of this and runs in
parallel.

### 5.1.1 S4b as built

Status: done. What was built, and where it departs from the sketch in 3.8:

- `scan/fused.rs` holds the evaluator moved from `builders/fused.rs`:
  `FusedState::join` (non-generic: member rows and join tuples of one frame)
  and `FusedState::write_row` (generic over the sink, inlined into the
  router). `Router` routes fused outputs after the frame's table rows, with
  the same cursor, row cap and redelivery as a table; the cursor of a fused
  output is the index of the frame's next joined row. `builders/fused.rs` and
  `builders/dynamic.rs` are deleted; DataFusion gives a fused output an
  `ArrowSink`.
- `FusedScan::columns` is a list of `FusedColumn { name, value }`, not of
  `(member, column)` pairs. A value is a member's column, a `Coalesce` of
  member columns or a `Present` label; a scan can carry an exact
  `FusedFilter`. These are what the `*_packets` views have beyond a plain
  join (`COALESCE(ip4.ttl, ip6.hop_limit)`, the `transport` label of
  `dns_packets`, `WHERE icmpv6.type IN (...)`), and with them a view is one
  `FusedScan` and nothing else. `COALESCE` asks the ordinary cell writer
  whether an argument is NULL (a probe sink), so it cannot disagree with what
  the argument's own column would hold.
- `scan/views.rs` defines the 21 views (`PacketsView`) once, for every
  frontend. DataFusion keeps its SQL views and its optimizer rule; its test
  `packets_views_equal_the_shared_fused_scans` compares each SQL view,
  evaluated by DataFusion's joins and by its fused path, with the core
  definition: same columns, same rows, same order by `(frame_number,
  encap_depth)`. No difference was found, so no view is defined differently
  in core. The four views that are not a join within one encapsulation level
  (`packets`, `tunneled_packets`, `ip4_in_ip6`, `ip6_in_ip6`) are not in
  core.
- Member tables are matched by name per frame (a `&'static str` compare per
  member and layer), not by a resolved id: the layer names of a parse result
  are names, and the compare is of a few bytes. A plan without fused scans
  tests one `Vec::is_empty` per frame.
- The table path was kept as it was, and that took two attributes. With a
  second caller of `write_value` for the same sink (the fused writer) the
  compiler stopped inlining it into `write_layer_row`, and a scan of four
  tables ran 11% more instructions; the row writer now calls an
  `#[inline(always)]` copy (`row::coerce`). And `Router::route_frame` is
  `#[inline(never)]`: inlined into the driver's packet callback it cost
  another 2%. Measured with a counting sink over 100,000 packets under
  `cachegrind`, against the commit before S4b: `frames` +0.6%, `udp` -0.3%,
  four tables +0.8%, six tables +0.2% instructions; wall-clock times do not
  differ beyond the noise of a shared machine. The S0 scan benchmark of the
  DataFusion crate was not run.
- Tests: `pcapsql-core/tests/fused_scan.rs` (every view and three made-up
  joins against a nested-loop join over the tables' rows; sink capacities 1,
  2, 3, 7, 2048; partitions; row caps and frame predicates), unit tests in
  `scan/plan.rs` and `scan/views.rs`.

### 5.2 Mapping to the DuckDB roadmap phases

| Phase | Needs | Can wait |
|---|---|---|
| P0 | nothing | everything |
| P1 | S1 (is P1) | |
| P2 sequential reader | S2, S3 (minimal plan), S4a, S5, S6 | S4b, S4c, S7 |
| P3 projection, cardinality, progress | S3; `ScanStats`/`Delivered` for progress | |
| P4 parallel | S5 (`partition_target`, `PartitionQueue`) | |
| P5 multi-file, remote | nothing shared | |
| P6 filter pushdown | S7 | |
| P8 backlog | S4b (packets functions), S4c (stream tables) | |

A shorter path exists: build `scan/` new for DuckDB and migrate DataFusion
onto it later. It is not recommended. For the time between, there would be
two implementations of routing and coercion, which is the duplication this
design exists to prevent, and the new code would start without the tests
that guard the old.

### 5.3 New test suites

**Sink conformance** (`pcapsql-core`, generic over a sink factory; run by
core with `RecordingSink`, by DataFusion with `ArrowSink`, by DuckDB's
`itest/` with `ChunkWriter`):

```rust
pub trait SinkHarness {
    type Sink: RowSink;
    fn new_sink(&mut self, columns: &[OutColumn], capacity: usize) -> Self::Sink;
    /// Take what the sink holds, as engine-neutral cells.
    fn drain(&mut self, sink: &mut Self::Sink) -> Vec<Vec<Cell>>;
}
pub fn run_conformance<H: SinkHarness>(h: &mut H);
```

Cases: every `ColKind` with NULL and non-NULL; empty, NULL and mixed lists;
empty strings and blobs; strings with interior NUL (the old DuckDB writer
nulled them); `Fixed` of exact length; capacity 1, 2, 7, 2048 with `Full`
reported exactly at capacity; a sink reused after a drain; zero-column
outputs (`count(*)`).

**Pull-equivalence** (core, no engine): for every testgen capture and every
table, scanning with `RecordingSink` at capacity `c` in {1, 2, 3, 2048}
through repeated `step` calls yields exactly the rows of an unbounded scan.
Includes tunnelled frames (several rows per frame) and a crafted frame with
more rows than `c`. This is the regression test for the old extension's
over-capacity chunk and duplicate-row defects.

**Differential** (roadmap P2 exit): the same queries through the DataFusion
CLI and DuckDB, normalising only the sanctioned differences of section 3.5.

---

## 6. Risks, things not to share, and size

### 6.1 Risks

| Risk | Mitigation |
|---|---|
| The hot path gets slower behind the abstraction (an un-inlined sink call per value, an extra bounds check) | S0 first; S4a and S5 compare against it; `#[inline]` on sink methods and `write_*`; typed slot vectors in `ArrowSink` |
| `Pause::Before` depends on `pcap_parser` re-delivering an unconsumed block | Unit test in S1 before anything builds on it. Fallback: hold the frame's remaining rows as owned values in the cursor (`FieldValue::to_owned`, `protocol/field.rs`), which costs copies only at chunk boundaries |
| The DataFusion refactor sits on the critical path of DuckDB P2 | P0 runs in parallel; S1 to S5 are about 6,700 touched lines, half of them mechanical |
| Golden snapshots shift when the catalogue is ported | The one-commit schema-equality test in S2 |
| Public API of `pcapsql-datafusion` breaks: `NormalizedBatchSet`, `FilterEvaluator`, `ParseSubscription`, `TableSubscription` are re-exported (`query/mod.rs:39-44`) | Pre-1.0; CHANGELOG entry per step, as the scoped-parse plan did |
| Core's public surface grows by a module that will churn | Mark `scan` unstable in its docs until DuckDB P4 |
| Two coercion changes (wrong-length `Fixed`, oversized `UInt64` timestamp) alter output in corner cases | Both are currently a late error or a wrapped value; called out in the S4a PR and covered by the S0 snapshot diff |
| Re-parsing a frame on resume is assumed deterministic | `parse_packet` has no state between calls; the pull-equivalence proptest checks it |

### 6.2 Not shared, and why

| Item | Reason |
|---|---|
| `exchange.rs`, `Pacer`, overflow accounting | They solve DataFusion pulling several tables from one producer (hash-join build side first). DuckDB instances are independent |
| `ProtocolScanExec`, `QueryTables`, `TableCache`, retention policy, plan harvest | Engine plumbing and REPL caching policy |
| `FuseFrameJoins` optimizer rule | Needs a logical-plan rewrite hook; DuckDB's C API has none. The join evaluation it targets is shared |
| Streaming window aggregate, windowing operators | Physical operators; the window arithmetic is already in `pcapsql_core::windowing` |
| View SQL | Dialect and UDF names differ. Share the join shape as `FusedScan`, not the text |
| HDR histogram aggregate, `strftime` family, capture-time UDFs | Engine-shaped state or extra dependencies |
| `DuckFile`, panic guard, registration, multi-file wrapper, index cache I/O | DuckDB lifetime rules (callback-scoped `Context`) |
| BPF to SQL | Not on the scan path. `bpf/ast.rs` and `parser.rs` could move later; out of scope |
| A per-packet layer buffer or visitor API replacing the 7.8 kB `Vec` | Worth doing and probably the largest single hot-path win, but it changes `parse_packet`'s signature for every caller and is independent of this refactor. Proposed as a separate, measured change after S5 |

### 6.3 Size per step (estimates from the line counts in section 1)

| Step | Files | Lines touched | Nature |
|---|---|---|---|
| S0 | 2 new | ~400 | new bench and test |
| S1 | 7 (`pcap_stream.rs`, `source.rs`, `mmap.rs`, `cloud.rs`, `stdin.rs`, `io/mod.rs`, new `read_source.rs`) | ~650 | ~250 new, the rest edits and moves |
| S2 | ~37 | ~3,300 | mechanical port of 2,950 lines; ~300 new |
| S3 | ~9 | ~1,100 | ~600 new in core; `filter.rs` 276 to ~130; `shared.rs` 68-224 rewritten |
| S4a | ~6 | ~1,800 | ~850 new in core; `protocol.rs` 702 to ~350; `normalized.rs` 435 to ~200 |
| S5 | ~4 | ~900 | ~500 new in core; `shared.rs` 946 to ~550 |
| S6 | ~14 | ~1,900 | ~1,000 moved; wrappers shrink |
| S4b | 3 | ~450 | move plus delete |
| S4c | 2 | ~1,000 | `stream_tables.rs` 696 to ~80; ~450 in core |
| S7 | 3 | ~350 | new |
| **Total** | | **~11,900** | about 5,000 of it mechanical moves |

---

## 7. Edits to `docs/duckdb-v2-extension-roadmap.md` if adopted

| Section | Edit |
|---|---|
| Header | Add a pointer to this document as the design of the scan layer |
| 1 Goals | Goal 4 ("thin engine-facing layer") now also means: no scan logic in the extension. In non-goals, note that stream tables remain out of the reader phases but need no new design (section 3.8 here) |
| 2 Constraints | Row "Filter-pushdown and expression API is expected to change": the target type is `pcapsql_core::scan::FramePredicate`. Add a row: the scan layer is shared with DataFusion, so changes to it run the DataFusion golden corpus |
| 3 Crate layout | Delete the `scan/` subtree (`plan.rs`, `predicate.rs`, `partition.rs`, `schema.rs`, `source.rs`). `engine/writer.rs` becomes "`ChunkWriter: RowSink`". Add `engine/types.rs` (`ColKind` to logical type). State that the crate is `engine/` plus registration |
| 4.2 Columns | Replace "Follow core's `DataKind` exactly" with "follow the shared catalogue". Consequences to state: names are already unprefixed there; IPv4 is UINTEGER and IPv6/MAC are BLOB of fixed length (matching the existing `ip4_to_string(UINTEGER)` scalars) rather than VARCHAR; `encap_depth` is UTINYINT, not USMALLINT; `tunnel_type` and `tunnel_id` come with every protocol table; `timestamp` on protocol tables is an opt-in catalogue column (`ColumnDef::default = false`); TIMESTAMP_NS is selected by `ScanPlan::timestamps` |
| 4.3 Scalars | The kernels come from `pcapsql_core::format`; the extension writes vector wrappers only. The 16 scalars then agree with DataFusion by construction |
| 5.1 Callback mapping | `init_global_state`: build `ScanPlan`, `compile`, `plan_ranges`, `PartitionQueue`. `claim_batch`: `PartitionQueue::claim` + `ReadPacketReader::at`/`sequential`, wrap in `PartitionScan`. `exec`: one `PartitionScan::step` into a `ChunkWriter` |
| 5.2 File access | The two constructors are `ReadPacketReader::sequential` and `::at`; header detection is `StreamHeader::probe` |
| 5.3 Projection and row writer | `ColumnPlan` is `OutputPlan`. Replace the chunk-boundary paragraph: no parsed rows are kept in local state; the driver pauses before the packet and resumes by row index (section 3.6 here) |
| 5.4 Parallelism | Gating thresholds come from `partition_target` (same values as DataFusion); the queue is `PartitionQueue` |
| 5.5 Filter pushdown | `ScanPredicate` is `FramePredicate`; trimming is `plan_ranges`; the exact row filter is `FramePredicate::accepts` in the driver |
| 6 Core changes | Rewrite the table: **C1** shrinks to `ReadPacketReader`, a public probe and two exports (`GenericPcapReader` is already generic over `Read`). **C2** is `process_packets_flow` with `Pause::{After, Before}`. **C3** is done (`build_boundary_index<R: Read>`, `to_bytes`/`from_bytes`); only cache-key plumbing remains in the extension. **C4** is redefined: no slot index exists or is planned; lookup is the shared `FieldResolver`. **C5** is done (`ParseResult::encap_depth`). Add **C6** `pcapsql_core::scan` (steps S2 to S5, S7) and **C7** kernels in `format` (S6). Drop "all are additive": C6 moves code out of the DataFusion crate |
| 7 P1 | Becomes "Core seams and shared scan layer": S0 to S5. Exit adds: DataFusion suite and scan bench unchanged; pull-equivalence and conformance suites pass in core |
| 7 P2 | "typed writer, chunk carry-over, C4, C5" becomes "`ChunkWriter` passing the sink conformance suite". Registry-driven registration reads the catalogue. Exit unchanged; the three audit defects are covered by conformance and pull-equivalence |
| 7 P3 | Reduces to enabling projection pushdown and mapping projected indices to `TableScan::columns`; the `ParseScope` comes from `compile` |
| 7 P4, P6 | Reference `PartitionQueue`, `plan_ranges`, `FramePredicate` (S7 is the prerequisite of P6) |
| 7 P8 | "`<proto>_packets` table macros" and "sharing one parse across several protocol tables" become fused-scan table functions (S4b); stream tables need S4c plus a keylog parameter. "Remaining DataFusion UDFs" become wrapper work once their kernels are in core |
| 9 Verify | Add U11: does `pcap_parser` re-deliver an unconsumed block (S1 test). Add U12: is the Arrow importer usable from `exec`, zero-copy, and what types does it produce (decides `ChunkWriter` vs `pcapsql-arrow`). Extend U8: are data and validity pointers stable for the duration of one `exec`, so `ChunkWriter` can fetch them once |
| 10 Risks | Add: the shared-layer steps precede P2; a regression there affects the released DataFusion CLI, mitigated by per-step gates |
