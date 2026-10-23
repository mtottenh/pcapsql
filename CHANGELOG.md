# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

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

### Changed

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

### Fixed

- `QueryEngine::query` calls on one engine are serialized by an async mutex,
  so concurrent queries from several tasks no longer interfere with each
  other's prepared tables ("table … was not prepared", "stream … already
  consumed", "column … was not materialized"). This is the short-term fix for
  [#123](https://github.com/mtottenh/pcapsql/issues/123); the query-scoped
  design that lets independent queries run in parallel is in
  `docs/query-context-design.md`.
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

[0.2.0]: https://github.com/mtottenh/pcapsql/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mtottenh/pcapsql/releases/tag/v0.1.0
