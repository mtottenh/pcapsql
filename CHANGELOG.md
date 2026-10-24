# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- A query over uncompressed standard input (or any uncompressed
  descriptor-backed stream) now releases its parser when it is done, instead
  of leaving it blocked in `read()` on a quiet pipe until the next byte:
  `PacketSource::cancel_reads` writes to a cancel descriptor (an `eventfd`, or
  a pipe) that the reader's `poll(2)` watches alongside the input.
  `QueryStream::finish()` and dropping a `QueryStream` cancel the query's
  reader, and so does `execute()` once its result is collected, so
  `--stdin ... LIMIT n` returns while the pipe stays open and a `--continuous`
  query stopped with Ctrl-C always prints its `--stats`. The CLI no longer
  has to `exit()` past a blocked reader. Two things on the way: stdin is read
  from its descriptor rather than through `io::stdin()`'s 8 KiB buffer, whose
  contents the `poll(2)` behind `--flush-interval` / `--idle-timeout` could
  not see (a feed of fewer than 8 KiB sat there until the next packet); and a
  table's partial batch is handed on the moment its `LIMIT` is reached rather
  than when the batch fills. A compressed stream still cannot be released
  (its decompressor hides the descriptor); such a producer stops at the next
  byte or end of input.

- The `http` table was never populated: it was registered, but no packet
  parser fed it, so `SELECT * FROM http` and the `http_packets` view returned
  no rows and the `packets` view's `http_*` columns were always NULL. A
  packet-level HTTP/1.x parser now parses the request/status line and the
  common headers from the TCP segment that starts a message (TCP sniffs the
  payload, so body segments and non-HTTP traffic on HTTP ports add no rows);
  the DuckDB extension gains `read_http`. Reassembled messages remain in the
  stream table `http_messages`
  ([#117](https://github.com/mtottenh/pcapsql/issues/117)).
- Review follow-ups from the 0.4.0 stack
  ([#126](https://github.com/mtottenh/pcapsql/issues/126)):
  - Ingestion: pcapng timestamps saturate instead of wrapping past the
    `i64` nanosecond range, honour `if_tsoffset`, and an undecodable
    `if_tsresol` is normalized to microseconds; an EPB whose interface id has
    no IDB is logged once; a Simple Packet Block's `captured_len` no longer
    includes the block's padding when `origlen > snaplen`; `reader_at` on a
    range starting at byte 0 (`PacketRange::whole()`) reads the source's own
    header instead of synthesizing one on top of it.
  - Boundary-index sidecar format v3: a payload checksum, `if_tsoffset` per
    interface and the object e-tag (cloud sources, where `last_modified` has
    one-second granularity); older sidecars are rebuilt, never misread;
    `validate()` rejects link types wider than 16 bits and undecodable
    `if_tsresol`; no sidecar is written next to captures under 1 MiB. Cloud
    pcapng open finds the first IDB behind other blocks instead of requiring
    it to follow the SHB directly.
  - Engine: builders never narrow an integer with a wrapping cast (a value
    that does not fit its column is NULL); parser field widths are pinned to
    the table schemas by a test (`gtp.sequence` is `UInt32`;
    `rtnetlink.hw_addr` is `FixedSizeBinary(6)` and populated); time-range
    UDFs are also detected in a `TableScan` that still carries a view plan;
    `--progress` and `--stats` work in the REPL and the spinner reports a
    real packets/s rate; `.cachestats` reports the engine's table cache and
    `.cachestats reset` clears it.
  - UDFs with integer parameters (`dscp_name`, `ecn_name`,
    `gtp_message_type_name`, `icmp_code_name`, `tls_version_name`,
    `ip4_to_string`, …) accept integer literals and columns of another
    integer width (`dscp_name(46)` plans); non-integer arguments are still
    rejected at planning.
  - A parser that fails without extracting any field no longer produces an
    all-NULL row in its protocol table (partial results keep their fields);
    MPLS label stacks are no longer counted as a tunnel (`encap_depth` stays
    0 and `tunnel_type` NULL for the inner IP layer; the `mpls` table is
    unchanged).
  - DuckDB extension: `read_linux_sll`, `read_sll2`, `read_netlink` and
    `read_rtnetlink` table functions.
  - Tests/CI: `cargo check --workspace --all-targets` (benches compile) and
    clippy over all targets in CI; the partition-equivalence property covers
    seven link types, coarse and binary `if_tsresol` values, up to four
    interfaces and three sections; the test generator rejects unrepresentable
    `if_tsresol` bytes instead of overflowing and keeps mixed-resolution
    captures monotonic.
  - Docs: `pcapsql-core` README and crate docs, `query/mod.rs` option docs,
    PKGBUILD version, changelog links.
- `ntp` table could not be materialized (its `Int8`/`Float64` columns had no
  builder); `poll`/`precision` are now signed, `root_delay`/`root_dispersion`
  are seconds, and the NTP timestamps are Unix seconds with their fraction;
  the DuckDB extension writes them with the column's width
  ([#116](https://github.com/mtottenh/pcapsql/issues/116)).
- `process_packets` now consumes a packet before propagating the callback's
  error, so a caller that pauses with an error resumes at the next record;
  the DuckDB extension no longer emits a duplicate row and drifts frame
  numbers every 2048 rows ([#118](https://github.com/mtottenh/pcapsql/issues/118)).
- The fuzz targets compile against the current `parse_packet` signature and
  CI checks the fuzz crate ([#119](https://github.com/mtottenh/pcapsql/issues/119)).
- The boundary-index scan applies the reader's 64 MiB buffer ceiling instead
  of growing without bound on a corrupt record header, and a capture whose
  index cannot be built is parsed in one partition instead of failing the
  query ([#120](https://github.com/mtottenh/pcapsql/issues/120)).
- Cloud sources work from a `current_thread` tokio runtime (blocking I/O runs
  on a dedicated runtime instead of `block_in_place`)
  ([#121](https://github.com/mtottenh/pcapsql/issues/121)).
- GRE transparent Ethernet bridging (NVGRE) reaches the inner Ethernet frame
  ([#125](https://github.com/mtottenh/pcapsql/issues/125)).
- `pcapsql-core/README.md` shows the current API.
- `QueryEngine::query` is safe to call concurrently on one engine: each
  query's prepared tables are scoped to that query, the `CacheOnTouch` cache
  only ever widens, and the capture time range is bootstrapped once, so
  queries from several tasks no longer fail with "table … was not prepared",
  "stream … already consumed" or "column … was not materialized", and the
  contract is documented on `QueryEngine`
  ([#123](https://github.com/mtottenh/pcapsql/issues/123); design in
  `docs/query-context-design.md`).
- `EXPLAIN`, DDL (`CREATE VIEW`, …), `DESCRIBE` and session statements no
  longer parse the capture: `EXPLAIN` is planned over plan-only scans and
  displayed, statements run on the shared context, and `--stats` /
  `ParseStats.served_from` say so. `ServedFrom::{Parse, Cache, Index,
  PlanOnly}` also lets `--stats` tell the `count(*)` index fast path from a
  cache hit; the new `ParseStats.served_from` field breaks code that builds
  `ParseStats` with a struct literal. `EXPLAIN ANALYZE` still executes. An
  `EXPLAIN` of a time-UDF query on a source without a boundary index
  (compressed) still pays the one-time header-only time-range pass, which is
  now reported in the stats. A data query issued directly on
  `engine.context()` fails at execution rather than at planning;
  `CREATE TABLE … AS SELECT` over a capture table and `EXECUTE` are rejected
  with a clear message ([#124](https://github.com/mtottenh/pcapsql/issues/124)).
- Un-`ORDER BY`ed queries come back in capture order when the boundary index
  yields fewer parse partitions than the engine's parallelism (a ~300k-frame
  capture at the default 65536-frame checkpoint stride parses in 5 partitions
  on an 8-core machine). DataFusion round-robin repartitioned such a scan up
  to `target_partitions` above a filter or projection and, with no `ORDER BY`,
  dropped the scan's `frame_number` ordering with it, so the final merge fell
  back to arrival order and rows came out interleaved across partitions (a
  `LIMIT` returned arbitrary frames). Each query now plans on the partition
  count its tables actually have, so no scan with more than one partition is
  repartitioned; a one-partition scan keeps the engine's parallelism, which
  is order-safe ([#122](https://github.com/mtottenh/pcapsql/issues/122)).
- Port-only parsers no longer outrank the HTTP payload sniff: a TCP segment
  whose payload starts an HTTP/1.x message is parsed as `http` whatever its
  ports (plaintext HTTP to 8443, 993, 995 or 465 was a `tls` error row;
  from source port 53 or 123 to port 80 it was a `dns`/`ntp` error row).
  `Protocol::can_parse` now has two documented tiers, `PORT_PRIORITY_MAX`
  (100) for a match on port numbers alone and `CONTENT_PRIORITY` (200) for
  a match the parent layer confirmed in the payload, and a registry test
  pins every port-only parser below the content tier. The port-based
  parsers also check the transport before claiming a segment: DNS, NTP,
  DHCP, GTP and VXLAN require UDP (DNS also accepts TCP, where it now strips
  the two-byte length prefix instead of misparsing it), and BGP, SSH and
  TLS require TCP (UDP 443 is QUIC's, which the `tls` port match used to
  shadow) ([#134](https://github.com/mtottenh/pcapsql/issues/134)).

### Changed

- **The `*_packets` views join layers of the same encapsulation level.** Each
  view is anchored on its protocol table (`tcp` for `tcp_packets`, `dns` for
  `dns_packets`, …) and joins `ethernet`, `ipv4`/`ipv6` and the transport on
  `(frame_number, encap_depth)` instead of `frame_number` alone. Before, a TCP
  segment inside an IP-in-IP, VXLAN or GTP tunnel produced one row per IP
  header in the frame, pairing the outer tunnel addresses with the inner
  ports — a segment that does not exist — and so double-counted tunnelled
  traffic in every `count(*)` and `sum()` over a view (the GTP-U frame of the
  golden corpus was four rows). Now it is one row carrying the addresses the
  segment travels between; the outer header remains in `tunneled_packets` and
  the protocol tables, and a level with no link-layer header (inside IP-in-IP
  or GRE) has NULL `src_mac`/`dst_mac`. Untunnelled captures are unchanged.
  The unified `packets` view is one row per encapsulation level of the frame
  (each depth with an IPv4, IPv6, ARP or Ethernet header), every layer in the
  row taken from that level: a VXLAN frame carrying TCP is an outer UDP row
  and an inner TCP row, and the outer level of an IP-in-IP or GRE frame has
  `protocol` NULL (`ip_protocol` names the tunnel). Every `*_packets` view and
  `packets` gain trailing `encap_depth` and `tunnel_type` columns.

- One-shot (streaming) queries now run the parse behind a bounded exchange
  with backpressure: a producer waits for a slow consumer instead of
  buffering, and only queues batches of a table while DataFusion is parked
  waiting on another table of the same pass (hash-join build side, sorted
  join input), which is inherent to that plan. That queueing is reported per
  table in `--stats` and `ParseStats`
  ([#107](https://github.com/mtottenh/pcapsql/issues/107)).
- A query's prepared tables are now scoped to that query: `QueryEngine::query`
  plans each query on its own copy of the session state carrying a
  `QueryTables` extension that the table providers read, instead of
  engine-global `EngineTables`. `EngineTables` is replaced by `TableCache`
  (the `CacheOnTouch` cache) and `QueryTables`; `ProtocolTableProvider::new`
  takes the nominal partition count instead of a tables handle. A cancelled
  query releases its stream producers by ownership of its receivers.
  **Behaviour change:** a data query issued directly on `engine.context()`
  used to succeed on a `CacheOnTouch` engine once an earlier `query()` had
  cached the table (and to fail at planning otherwise); it now always fails at
  execution with "table … was not prepared for this query" — run queries
  through `QueryEngine::query` / `execute`. A time-UDF query on a source
  without a boundary index reports its header-only time-range pass in the
  stats (groundwork for
  [#123](https://github.com/mtottenh/pcapsql/issues/123)).

### Added

- **Fused joins: the parser emits a view's joined row itself.** Under
  `RetentionPolicy::None` (every one-shot, `--stdin` and `--continuous` run) a
  tree of inner and left joins of protocol tables on `frame_number` (and
  `encap_depth`) — every `*_packets` view, hand-written joins of that shape,
  a view joined with a table it does not already contain, with `WHERE`
  filters on inner sides and the query's `LIMIT` — is replaced at planning by
  a scan of a synthetic table
  that the parse pass builds per packet from the frame's own layers, with
  exact inner/left semantics and no join operator left in the plan
  (`fusion::FuseFrameJoins`, `FusedBatchBuilder`). The golden corpus checks
  every view against the REPL's join path. Consequences: a continuous query
  can window a view (`tumble(dns_packets, …)`), which a join over a stream
  could not do; a one-shot view query over 300 000 packets runs in the time
  of parsing its member tables plus about a third, where the joins it
  replaces cost more than the parse; and `--stats` reports the fused table
  (`fused_frames_tcp_ethernet_ipv4_ipv6_…`) instead of its members. Not fused,
  and still DataFusion joins over the fused part: `FULL` joins (the unified
  `packets` view), other join conditions, the same table under two aliases
  (a view joined with one of its own members included), a derived table's
  own `LIMIT` on one side, a join above a window. The `CacheOnTouch` engine (the
  REPL) keeps the per-table cache and the joins; `--no-fuse-joins`
  (`EngineOptions::fuse_frame_joins`) turns fusion off for a run.
- Parser fields that the DataFusion tables dropped are now columns, and the
  engine agrees with the DuckDB table functions, which already exposed every
  parser field. The new columns sit next to the related existing ones, so
  `SELECT *` on these tables returns more columns *and* the existing columns
  move position (name the columns you rely on). The `bgp_packets`,
  `ospf_packets` and `gtp_packets` views append the same columns after their
  existing ones ([#138](https://github.com/mtottenh/pcapsql/issues/138)):
  - `bgp`: `my_as_4byte`, `capabilities`, `withdrawn_routes`,
    `withdrawn_count`, `origin`, `origin_name`, `as_path`, `as_path_length`,
    `next_hop`, `med`, `local_pref`, `atomic_aggregate`, `aggregator_as`,
    `aggregator_ip`, `nlri`, `nlri_count`, `error_code`, `error_code_name`,
    `error_subcode`, `afi`, `safi`. The list-valued attributes
    (`capabilities`, `withdrawn_routes`, `as_path`, `nlri`) are strings as the
    parser formats them: comma-separated names and prefixes, space-separated
    AS numbers with an AS_SET in braces.
  - `ospf`: `neighbor_count`, `dd_interface_mtu`, `dd_options`, `dd_flags`,
    `dd_sequence`, `dd_lsa_count`, `lsu_lsa_count`, `lsa_ack_count`, and the
    first LSA header of a DD, LSU or LSAck packet: `lsa_age`, `lsa_type`,
    `lsa_type_name`, `lsa_id`, `lsa_advertising_router`, `lsa_sequence`.
  - `gtp`: `npdu`, `extension_headers` (the GTPv1 chain as comma-separated
    `Name(0xNN)` entries), `extension_header_count`, and the GTPv2-C
    `piggyback` and `teid_present` flags.
  - `ipv6`: `ext_hop_by_hop`, `ext_routing`, `ext_fragment`,
    `ext_destination`, `frag_offset`, `frag_more`, `frag_id`, `routing_type`,
    `segments_left`.
  The `mpls`, `gre` and `vxlan` validity, derived-length and name fields stay
  out of the DataFusion tables (see `NOT_EXPOSED_AS_COLUMNS`).
- The capture can be piped in: `pcapsql --stdin` (or `-` as the capture
  argument) reads pcap or pcapng, optionally gzip/zstd compressed, from
  standard input, e.g. `tcpdump -U -w - -i eth0 port 53 | pcapsql --stdin -e
  "SELECT ... FROM dns_packets"`. Stdin is read sequentially to end of input
  in one parse pass, so it takes a one-shot query (`-e`/`-f`, one statement;
  no REPL) and the time-range functions are not available before the pass; any one
  query may still join any tables, stream tables included. The library gets
  `StdinPacketSource` (`PacketSource` only, built from stdin or any
  `Read + Send`), `SourceSpec::Stdin` / `SourceSpec::Sequential`, and
  `run_shared_parse_sequential` / `run_streaming_parse_sequential`, the
  single-partition pass that the seekable entry points now share.
- Stream-analysis tables `tcp_connections`, `tls_sessions` and `http_messages`
  (one row per TCP connection, TLS handshake and HTTP/1.x message, reassembled
  from TCP streams), alongside `http2`. Stream analysis is now a subscriber of
  the single packet pass: a query mixing stream and packet tables reads the
  capture once (it runs as one partition, reported by `--stats`)
  ([#108](https://github.com/mtottenh/pcapsql/issues/108)).
- Linux SLL2 cooked captures (LINKTYPE 276, the default for `tcpdump -i any`
  with libpcap >= 1.10) are parsed: new `sll2` table with `interface_index`,
  reachable from `ipv4`/`ipv6`/`netlink` under protocol pruning
  ([#111](https://github.com/mtottenh/pcapsql/issues/111)).
- `QueryEngine::execute` returns a query's batches together with its own
  `ParseStats` (`QueryOutput`), which is what concurrent callers should use;
  `last_parse_stats()` reports the most recently completed query. The one-shot
  CLI prints `--stats` from it.
- `pcapsql_core::windowing`: engine-agnostic time-window primitives over
  microsecond timestamps — tumbling and hopping window assignment (floor
  aligned, so timestamps before the epoch are placed correctly), per-key
  session detection that accepts events in any order, and bounded
  out-of-orderness watermarks with every-event / every-N-events /
  every-N-microseconds evaluation and late-event counting.
- `tumble(source, size)`, `hop(source, slide, size)` and
  `session(source, key_column, gap)` table functions add `window_start` /
  `window_end` columns to `frames` or a `*_packets` view (or to any table or
  view with a `Timestamp(Microsecond)` column named as the second argument)
  for time-windowed `GROUP BY`. They expand into the query plan when the SQL
  is planned, so the source is parsed with only the columns the query uses,
  `WHERE` clauses on source columns reach the parser, un-`ORDER BY`ed rows
  stay in capture order and `EXPLAIN` shows the expanded plan. Session
  detection accepts input in any order (joins, parallel partitions); null
  timestamps yield null window bounds. Windowing a protocol table without a
  timestamp (`tumble(tcp, …)`) is a planning error that names the view to use;
  so is a hop with more than 10,000 windows per row. `session` buffers its
  pruned input (accounted to the memory pool) before emitting.
- Continuous queries over a live capture: `pcapsql --continuous -e "SELECT
  window_start, count(*) FROM tumble(frames, INTERVAL '10' SECOND) GROUP BY 1"`
  (implies `--stdin`) treats the piped capture as an unbounded stream and
  prints each window as soon as the stream's event time has passed its end
  (plus `--allowed-lateness`, default 1 s). A `GROUP BY window_start` over
  `tumble()` / `hop()` is planned as a fused `StreamingWindowAggregateExec`
  with per-(window, group) state, a per-row watermark and bounded memory;
  rows for an already emitted window are dropped and counted (`late_rows` in
  `ParseStats`, `--stats`). Partial batches are handed on after
  `--flush-interval` (default 1 s) — the wait for input is a `poll(2)` on the
  descriptor (`StdinPacketSource::stdin` / `from_fd_reader`,
  `PacketReader::set_read_timeout`), so held packets are delivered on time
  on a quiet feed; `--idle-timeout N` closes open windows after N seconds
  without input; CSV/JSON headers print once; Ctrl-C prints `--stats` and
  exits with status 130. Library: `EngineOptions { continuous, allowed_lateness,
  flush_interval, idle_timeout }` and `QueryEngine::execute_stream(sql) ->
  QueryStream` (a `Stream` of batches owning the query's context; `finish()`
  returns its `ParseStats`), usable on any engine. Queries that need the
  whole stream (`ORDER BY`, `count(DISTINCT)`, joins — including the
  `*_packets` views —, `session()`, aggregates without `GROUP BY
  window_start`, stream tables) are rejected at planning with a message
  naming the supported shape (also by `EXPLAIN`); `WHERE` on source or window
  columns, `HAVING`, `DISTINCT` and `LIMIT` fuse. The source of a continuous
  query is `frames`.

## [0.4.0] - 2026-10-23

The ingestion layer and the query engine were rebuilt in two stacked series of
pull requests: Stage 2–8 (#90–#96) make the reader trustworthy and the parse
parallel; P0–P6 (#98–#105) move parsing from engine open to query time and
scope it to what each query needs.

### Added

- **Parallel parsing**: a capture is parsed once per query, split at record
  boundaries from a persisted boundary index and parsed on all cores, locally
  (mmap, file) and over S3/GCS/Azure byte ranges; results are identical to a
  single-partition parse and come back in capture order ([#93](https://github.com/mtottenh/pcapsql/pull/93), [#94](https://github.com/mtottenh/pcapsql/pull/94), [#95](https://github.com/mtottenh/pcapsql/pull/95), [#96](https://github.com/mtottenh/pcapsql/pull/96); closes [#84](https://github.com/mtottenh/pcapsql/issues/84), [#85](https://github.com/mtottenh/pcapsql/issues/85), [#87](https://github.com/mtottenh/pcapsql/issues/87)).
- **Query-scoped parsing**: only the tables, columns and protocols a query
  references are parsed; filters are applied during parsing (`Inexact`
  pushdown, re-checked by DataFusion) and `LIMIT` stops the scan early
  ([#101](https://github.com/mtottenh/pcapsql/pull/101); closes [#86](https://github.com/mtottenh/pcapsql/issues/86)).
- **Streaming one-shot queries**: `pcapsql file -e …` streams batches to the
  query as they are parsed instead of materializing every table first; the REPL
  caches the columns a query touches on first use ([#102](https://github.com/mtottenh/pcapsql/pull/102), [#104](https://github.com/mtottenh/pcapsql/pull/104)).
- `count(*) FROM frames` is answered from the boundary index without parsing
  packets ([#105](https://github.com/mtottenh/pcapsql/pull/105)).
- The keylog/HTTP-2 stream pass runs on demand, only for queries that
  reference `http2` ([#103](https://github.com/mtottenh/pcapsql/pull/103)).
- `--stats` reports parse passes, partitions, packets scanned, early stop and
  rows built per table.
- Golden query corpus, partition-equivalence property suite, a deterministic
  PCAP/PCAPNG generator crate (`pcapsql-testgen`) and Criterion baselines
  ([#90](https://github.com/mtottenh/pcapsql/pull/90), [#99](https://github.com/mtottenh/pcapsql/pull/99)).
- DSCP/ECN name UDFs and histogram UDFs ([#106](https://github.com/mtottenh/pcapsql/pull/106)); network classification UDFs ([#77](https://github.com/mtottenh/pcapsql/pull/77)); protocol enumeration UDFs ([#76](https://github.com/mtottenh/pcapsql/pull/76)); UDF documentation and `--list-udfs` ([#68](https://github.com/mtottenh/pcapsql/pull/68)).
- Nightly fuzz workflow ([#67](https://github.com/mtottenh/pcapsql/pull/67)).

### Fixed

- Legacy nanosecond-resolution captures were decoded as microseconds; PCAPNG
  `if_tsresol` (decimal and power-of-two) was ignored; format detection
  depended on host byte order ([#91](https://github.com/mtottenh/pcapsql/pull/91); closes [#79](https://github.com/mtottenh/pcapsql/issues/79), [#80](https://github.com/mtottenh/pcapsql/issues/80), [#81](https://github.com/mtottenh/pcapsql/issues/81)).
- Truncated or oversized records no longer spin or grow the read buffer without
  bound; truncation is reported ([#91](https://github.com/mtottenh/pcapsql/pull/91); closes [#82](https://github.com/mtottenh/pcapsql/issues/82)).
- The legacy `PcapReader` double-open/re-decompress path is gone ([#100](https://github.com/mtottenh/pcapsql/pull/100); closes [#83](https://github.com/mtottenh/pcapsql/issues/83)).
- `gtp.sequence` is now `UInt32` (GTPv2 sequence numbers are 24 bits and were
  truncated).
- `SELECT * FROM http2` on a capture with decrypted HTTP/2 traffic failed
  because the registered and produced schemas disagreed.

### Changed

- **CLI**: `--streaming` is removed (there is one engine path); `--mmap` is
  now the default and `--no-mmap` disables it; `--cache-size`,
  `--track-streams`, `--max-stream-memory`, `--stream-timeout` and the
  `cache_stats()` table function are removed ([#92](https://github.com/mtottenh/pcapsql/pull/92), [#99](https://github.com/mtottenh/pcapsql/pull/99), [#100](https://github.com/mtottenh/pcapsql/pull/100)).
- **Library API**: `QueryEngine::open(SourceSpec, EngineOptions)` replaces the
  eight constructors; `parse_packet` takes a `ParseScope`; `PacketSource` is a
  sequential base trait with an opt-in `SeekablePacketSource`; `RawPacket`
  and `GenericPcapReader::next_packet` are gone in favour of the zero-copy
  `PacketRef` callback API; timestamps are nanoseconds (`timestamp_ns`)
  throughout, converted to the microsecond Arrow column at the builder.
- **`http2` table**: columns now match what the stream pass produces
  (`connection_id` added; `request_headers`, `response_headers`, `settings`,
  `debug_data`, `stream_state` removed, they were never populated).
- Reading a local capture writes a `<capture>.idx` boundary-index sidecar next
  to it; remote objects cache theirs under `$PCAPSQL_INDEX_CACHE`,
  `$XDG_CACHE_HOME/pcapsql/index` or `~/.cache/pcapsql/index`.
- `pcap-parser` 0.17.

## [0.3.1] - 2026-01-02

### Added

- **DateTime UDFs** ([#65](https://github.com/mtottenh/pcapsql/issues/65), [#66](https://github.com/mtottenh/pcapsql/pull/66)): `strftime`, `datetime`, `date`, `time`, `epoch`, `epoch_ms`
- Remaining P2 application-protocol fuzz targets ([#63](https://github.com/mtottenh/pcapsql/pull/63), [#64](https://github.com/mtottenh/pcapsql/pull/64))

## [0.3.0] - 2026-01-01

### Added

- **BPF filter syntax** ([#34](https://github.com/mtottenh/pcapsql/pull/34)): tcpdump-style filters such as `tcp port 80` or `host 192.168.1.1 and udp`
- **SQLite export** ([#33](https://github.com/mtottenh/pcapsql/pull/33)): `--output results.db`
- **Statistics commands** ([#32](https://github.com/mtottenh/pcapsql/pull/32)): `.stats`, `.top`, `.histogram`
- **S3 / cloud storage** ([#56](https://github.com/mtottenh/pcapsql/pull/56)): read captures from S3, GCS and Azure Blob Storage
- **Fuzz testing infrastructure** ([#57](https://github.com/mtottenh/pcapsql/pull/57)): cargo-fuzz with 8 targets

### Fixed

- OSPF: handle malformed packets gracefully ([#58](https://github.com/mtottenh/pcapsql/issues/58), [#62](https://github.com/mtottenh/pcapsql/pull/62))
- CI: distribution support and publish workflow

## [0.2.0] - 2025-12-31

### Added

- **Time UDFs**: New functions for capture time analysis ([#28](https://github.com/mtottenh/pcapsql/issues/28))
  - `start_time()` - Returns capture start timestamp
  - `end_time()` - Returns capture end timestamp
  - `relative_time(timestamp)` - Returns seconds from capture start
- **REPL**: `.timeinfo` command to display capture timing information ([#24](https://github.com/mtottenh/pcapsql/pull/24))
- **Protocols**: Netlink and Linux SLL support ([#23](https://github.com/mtottenh/pcapsql/pull/23))
  - Netlink protocol parser (LINKTYPE_NETLINK)
  - rtnetlink parser for NETLINK_ROUTE family
  - Linux SLL (cooked capture) link layer support
- **Packaging**: Published to crates.io (`pcapsql-core`, `pcapsql-datafusion`)

### Fixed

- Link type detection in streaming mode

### Changed

- Crate metadata updated for crates.io publishing

## [0.1.0] - 2024-12-29

### Added

- Initial release
- **Protocol Parsing**: 25+ protocols including Ethernet, VLAN, ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, DNS, DHCP, TLS, SSH, HTTP, NTP, QUIC, BGP, OSPF, GRE, MPLS, GTP, IPsec, VXLAN
- **Encapsulation Support**: VXLAN, GRE, MPLS, GTP, IP-in-IP tunnel parsing
- **TLS Decryption**: TLS 1.2/1.3 decryption using SSLKEYLOGFILE (NSS format)
- **HTTP/2 Analysis**: Full HTTP/2 frame parsing with HPACK header decompression
- **TCP Stream Reassembly**: Connection tracking with out-of-order segment handling
- **SQL Interface**: Query PCAP files using SQL via Apache DataFusion
- **Export Formats**: Parquet, CSV, JSON output
- **Performance Features**: Memory-mapped I/O, streaming mode, parse caching
- **CLI**: Interactive REPL with tab completion and history
- **Packaging**: .deb (Debian/Ubuntu), .rpm (Fedora/Rocky), AUR (Arch Linux)

[Unreleased]: https://github.com/mtottenh/pcapsql/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/mtottenh/pcapsql/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/mtottenh/pcapsql/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/mtottenh/pcapsql/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/mtottenh/pcapsql/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mtottenh/pcapsql/releases/tag/v0.1.0
