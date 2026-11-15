# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **DuckDB extension: a test that reads captures over HTTP.**
  `make remote_test_release` (`scripts/remote-test.sh`) serves captures from
  a local HTTP server with Range support (`scripts/range-http-server.py`) and
  reads them in the DuckDB shell through `httpfs`: every kind of table equals
  the file's, row for row, for legacy, pcapng, gzip, zstd and a generated
  28 MB capture; `filename`, lists of URLs, one partition per URL, a
  pushed-down `frame_number` filter, `LIMIT`, a 404 and
  `enable_external_access = false` are checked, and the server's log shows
  what was fetched. `duckdb.yml` and the `verify` job of `duckdb-dist.yml`
  run it and fail if `httpfs` cannot be installed; elsewhere the target
  reports a skip. Not yet run: `httpfs` could not be installed where it was
  written, so only the server and the skip path were exercised. The README
  has a section on remote files.
- **`--format raw`.** Prints only the values: no header, no quoting or
  escaping, columns separated by tabs, one row per line. A multi-line text
  value such as `hdr_ascii(...)` output prints as rendered, and a row that
  already ends in a newline gets no second one.
- **`pcapsql-core`: a packet reader over any `Read`.** `ReadPacketReader`
  reads a capture from bytes the caller opened itself, from the first frame
  (`sequential`, compressed or not, after `StreamHeader::probe`) or over one
  partition of an uncompressed capture (`at`, with a `BoundaryIndex`). It is
  the reader behind `FilePacketSource`, and what a host with its own file
  system (the DuckDB extension) uses instead of a `PacketSource`.
- **`pcapsql-core`: a consumer can stop a reader without an error.**
  `PacketReader::process_packets_flow` takes a callback returning
  `ControlFlow<Pause>`: `Pause::After` stops after the packet,
  `Pause::Before` leaves it to be delivered again by the next call, with the
  same frame number. A consumer with a bounded output (a fixed-size chunk)
  can therefore stop exactly where it ran out of room.
- **`pcapsql-core`: the table catalogue.** `scan::Catalog::builtin()` lists
  every table with its columns: name, kind (`ColKind`), nullability and where
  the value comes from (`ColumnSource`: the packet record, the parse context,
  a parser field, or stream analysis). It has no Arrow types, so a second SQL
  frontend (the DuckDB extension) gets the same tables, column order and
  typing as the DataFusion one. Timestamp columns are declared in
  microseconds and an engine picks its unit (`TimestampUnit`). Protocol
  tables carry a `timestamp` column marked as opt-in (`ColumnDef::default`
  is `false`) for engines that cannot fuse a join against `frames`. The
  `scan` module is unstable API.
- **`pcapsql-core`: the scalar function kernels, in `pcapsql_core::format`.**
  The engine-independent logic of the SQL scalar functions now lives in core,
  for any engine built on it (the DuckDB extension) to wrap: protocol number
  names (`names`: IP protocol, EtherType, DSCP, ECN, DNS type/class/rcode,
  ICMP and ICMPv6 type and code, BGP, GTP, OSPF, NTP, TLS), TCP flags
  (`write_tcp_flags`, `has_tcp_flag`, `tcp_flag_mask`), IPv4/IPv6 parsing,
  CIDR membership and address classes (`cidr`), MAC parsing and classes
  (`mac`), and hex (`write_hex`, `parse_hex`). A kernel takes one value and
  returns a scalar, a `Cow<'static, str>` that borrows whenever the text is a
  fixed name, or writes to a `fmt::Write` sink; null handling and
  registration stay with the engine. Also new: `write_ipv4`, `write_ipv6`
  and `write_mac` (the `format_*` functions without the `String`), and
  `dns_opcode_name`, which no SQL function uses yet.
- **DuckDB extension (C API v2): the scalar functions and the `format_*`
  macros.** The sixteen scalar functions of the extension for DuckDB 1.x are
  back, with the same names and signatures: `ip4`, `ip4_to_string`, `ip6`,
  `ip6_to_string`, `mac`, `mac_to_string`, `ip_in_cidr`, `ip6_in_cidr`,
  `tcp_flags_str`, `has_tcp_flag`, `dns_type_name`, `dns_rcode_name`,
  `ip_proto_name`, `ethertype_name`, `pcap_hex` and `pcap_unhex`. Each is a
  vector loop over a `pcapsql_core::format` kernel, so the extension has no
  copy of the logic and answers as the DataFusion engine does. Constant,
  dictionary and NULL inputs are handled; a NULL or unusable argument (text
  that is not an address, a BLOB of the wrong length, text that is not CIDR
  notation) gives NULL, never an error. A literal CIDR network or flag name
  is parsed once per chunk. `format_ip4`, `format_ip6`, `format_mac` and
  their `_list` forms are registered as macros of the extension rather than
  created with `CREATE MACRO` on the loading connection, and the list forms
  use `lambda x: ...`, since DuckDB 2.0 rejects the `x -> ...` form by
  default.
- **`pcapsql-core`: the scan plan and its predicates.** `scan::ScanPlan`
  says what one pass over a capture must produce: table scans (output
  columns as `ColId`s in output order, an optional row predicate, an
  optional row cap), fused joins on `frame_number` (`FusedScan`), stream
  tables, and the unit of timestamp columns. `ScanPlan::compile` checks it
  against the catalogue (`PlanError`) and resolves what a packet loop must
  not look up per packet (`CompiledScan`): the `ParseScope`, each output's
  columns with their kind in the plan's timestamp unit, and whether the pass
  must run as one partition (stream tables). `scan::RowPredicate` is the
  conservative parse-time filter (`column <op> literal` joined by `AND`,
  bound to a table's columns): it drops a row only on a positively false
  comparison, and compiles to a `CompiledPredicate` that looks fields up by
  remembered position. `scan::FramePredicate` is an exact range of frame
  numbers and timestamps; no scan applies it yet. `ParseScope` gains the
  `required()` and `projections()` accessors, `Catalog` gains `try_get`.
- **`pcapsql-core`: row sinks, and one place that decides what a cell
  holds.** A frontend stores rows by implementing `scan::RowSink` (a typed,
  infallible method per kind of value, a `ListSink` for list cells, and
  `end_row`, which answers `Full` when no further row fits).
  `scan::write_value` converts a parsed `FieldValue` to a column's `ColKind`
  or NULL (the rules the Arrow builders had, now documented on the
  function), and `write_layer_row` / `write_frame_row` write a whole row of
  a protocol table or of `frames` with a `FieldResolver`, which remembers
  per column where its field was in the previous row. Every frontend
  therefore stores the same cells. Formatting an address or a number into a
  string column no longer allocates for text of up to 64 bytes.
- **`pcapsql-core`: routing.** `scan::Router` writes one frame's rows to
  the sinks of a `CompiledScan`'s `frames` and protocol-table outputs, with
  each output's row predicate and row cap. It works with sinks of any size:
  an output whose sink is full, or that reached its row cap, is handed to
  the caller (`take_flush`), and a frame whose rows did not all fit
  (`Routed::Redeliver`; a tunnelled packet has several rows in one table) is
  routed again without losing or repeating a row. Fused joins are routed
  too (see "fused joins" below).
- **`pcapsql-core`: `scan::testing`.** `RecordingSink` records rows as
  engine-neutral `Cell`s and checks how it is called, and
  `run_conformance` is the suite a `RowSink` implementation runs from its
  own tests (every kind with and without NULL, lists, empty and
  NUL-containing strings, `Full` exactly at capacity, reuse after a drain,
  outputs without columns). The module is behind the cargo feature
  `testing`, which a crate turns on in its dev-dependencies.
- **`pcapsql-core`: the scan driver.** `scan::PartitionScan` reads one
  partition of a `CompiledScan` (a whole capture, or one range of it) step
  by step: `step(sinks, max_packets)` reads packets, parses them with the
  plan's scope and routes their rows, and returns when the caller has
  something to do (`scan::Step`): `Flush(output)` when an output's sink is
  full or the output reached its row cap, `More` after `max_packets`,
  `Done` when every output is capped or closed (the rest of the partition
  is not read), `End` at the end of the partition. The scan resumes where
  it stopped, so an engine that pushes batches to its consumer loops over
  `step`, and one whose consumer pulls a fixed-size chunk calls it once per
  chunk. Whatever the size of the sinks, no sink is written to beyond its
  capacity and no row is lost or written twice; a frame whose rows did not
  all fit is shown again by the reader (`Pause::Before`) and may have more
  rows than a sink holds. `ScanStats` counts the packets consumed, their
  timestamp range and the rows written per output. A `scan::FrameObserver`
  (a type parameter, `NoObserver` by default) is shown every frame exactly
  once, parsed, before its rows are routed: the hook for what a frontend
  still builds itself (fused joins, stream reassembly).
- **`pcapsql-core`: partition planning.** `scan::partition_target` decides
  how many partitions a capture is worth from what a seek costs
  (`SeekCost`), its size, a requested count and the available parallelism,
  with the thresholds of `scan::PartitionPolicy` (1 MiB for a memory map
  left to itself, 4 MiB for a local file, 16 MiB for a remote object).
  `scan::PartitionQueue` hands the partitions of a scan out to any number
  of workers, each exactly once and in capture order, with its ordinal.
- **DuckDB extension (C API v2): `pcap_schema(protocol)`, and the building
  blocks of the packet readers.** `pcap_schema('tcp')` lists the columns a
  scan of a table returns (`column_name`, `column_type`, `nullable`), from
  the shared catalogue, with the type DuckDB shows for each: timestamps are
  `TIMESTAMP_NS`, IPv4 addresses `UINTEGER`, MAC and IPv6 addresses `BLOB`,
  lists `USMALLINT[]`, `UINTEGER[]`, `VARCHAR[]` or `BLOB[]`, and every
  protocol table has a `timestamp` column after `frame_number`. The readers
  themselves (`read_pcap`, `read_<protocol>`) are not registered yet; three
  parts of them are in place. `engine::types` maps each column kind of the
  catalogue to a DuckDB logical type. `engine::writer::ChunkWriter` is the
  scan layer's `RowSink` over a table function's output chunk: values go
  straight into DuckDB's vectors (strings and blobs inline or into the
  vector's arena, list items into the list's child vector), it reports `Full`
  at the chunk's capacity of 2,048 rows and refuses a row past it, and it
  passes the sink conformance suite of `pcapsql_core::scan::testing` through
  real chunks. `engine::fs::DuckFile` is a buffered `Read` over a file opened
  through DuckDB's file system (1 MiB at a time, 4 MiB for a remote file), at
  the start of the file or at a byte offset, so that a capture is read with
  core's `ReadPacketReader` and DuckDB's access rules
  (`enable_external_access`, `allowed_directories`) decide what may be
  opened. The extension's sources use no `std::fs`; a `clippy.toml` scoped to
  the extension and `make check` enforce it.
- **`pcapsql-core`: scans restricted to a range of frames or of time.** A
  plan's `scan::FramePredicate` (bounds on the frame number and on the
  packet timestamp, each inclusive, exclusive or absent) is now applied by
  the scan driver, exactly: `PartitionScan::step` gives rows for the packets
  the predicate accepts and for no others, so an engine can treat a filter
  it turned into one as done. A rejected packet is consumed without being
  parsed, routed, counted against a row cap or shown to the `FrameObserver`.
  Frame numbers ascend, so the scan ends (`Step::End`) once the last frame
  the upper bound admits is consumed, without reading the packet behind it
  (on a live capture that packet might never arrive); timestamps need not
  ascend, so a time bound selects packets but never ends a scan. A predicate
  nothing can satisfy (`FramePredicate::is_empty`) reads nothing.
  `ScanStats::packets` still counts every packet consumed, `skipped` (new)
  those of them the predicate rejected, and the timestamp range is that of
  the accepted packets. `CompiledScan::frames` exposes the predicate.
  A plan with stream tables cannot have one
  (`PlanError::StreamFramePredicate`): a stream table is assembled from
  every packet of the capture.
- **`pcapsql-core`: partition trimming.** `scan::plan_ranges(index, want,
  frames)` gives the ranges to scan for a frame predicate: the boundary
  index's partition ranges, each shrunk to the checkpoint windows that can
  hold a matching packet and left out when none can. Frame bounds trim
  exactly; time bounds by the smallest and largest timestamp the index
  recorded per window, each window on its own since timestamps need not
  ascend. The last window of a capture is ruled out by the upper frame bound
  only (a capture that grew since it was indexed has packets there the index
  knows nothing of). Trimmed ranges still start and end on checkpoints. The
  result is unchanged for a predicate that accepts everything, and is the
  whole capture as one range without an index. `pcapsql-datafusion` has no
  frame predicate yet and behaves as before.
- **DuckDB extension (C API v2): the scan functions.**
  `read_<table>(file)` for `frames` and each of the 27 protocol tables, and
  `read_pcap(file, protocol := 'frames')`, read a capture: legacy pcap or
  pcapng, plain or compressed with gzip or zstd, opened through DuckDB's file
  system. They are one table function over the shared scan layer
  (`pcapsql_core::scan`), so tables, columns, cell values and row order are
  those of the DataFusion engine, with timestamps as `TIMESTAMP_NS` and a
  `timestamp` column on every protocol table. Only the columns a query uses
  are produced and only the protocols and fields they need are parsed
  (projection pushdown): a query of `frames` parses nothing. A scan runs on
  one thread and returns rows in capture order; it gives DuckDB a row
  estimate from the file size and its progress in bytes read. A capture that
  ends inside a record returns its complete packets and logs a warning
  through DuckDB's log (the DuckDB shell prints it); the named parameter
  `strict := true` makes it an error. A read error, a damaged record and a
  damaged compressed stream fail the query in either mode. A missing file, a
  file that is not a capture, an unknown protocol and a NULL argument are
  errors at bind. One file per call: lists and globs are not accepted yet.

- **`pcapsql-core`: a reader says when a capture ends inside a record.**
  `PacketReader::truncated()` is true when the last read stopped because the
  record after the last complete one declares more bytes than the input has
  left: a capture cut short, or one still being written. Until now that end
  could not be told from the clean end of a capture except by the warning
  the reader logs, which it still does. `GenericPcapReader` records it, the
  file, memory-map, object-store, stdin and `ReadPacketReader` readers
  forward it, and a `PartitionScan` gives it through `reader()`. It is a
  provided method that answers `false`, so other implementations are
  unaffected; a reader of a range that has an end stops at that frame and
  never sees the end of the input. Nothing in `pcapsql-datafusion` reads it.
- **DuckDB extension (C API v2): parallel scans.** A local, uncompressed
  capture of 4 MiB or more is split into as many partitions as DuckDB has
  threads and scanned by that many workers. The partitions are cut at the
  checkpoints of core's `BoundaryIndex`, which one pass over the record
  headers builds when the query starts, with the thresholds of
  `partition_target`, as in the DataFusion engine. Rows, and their order
  without an `ORDER BY`, are those of a scan on one thread: each worker
  claims the next partition from a `PartitionQueue` and reports its ordinal
  to DuckDB as the batch index, which keeps `SELECT`, `LIMIT`,
  `CREATE TABLE AS` and `INSERT` in capture order. Compressed captures,
  captures on a remote file system and captures with a damaged record are
  read on one thread as before. A truncated capture is reported once, by the
  worker that reads its end; with `strict := true` a partitioned scan checks
  the end of the capture when it starts, so that the error does not depend
  on which worker gets where first. An error in one worker fails the query
  once and stops the others. Three settings: `pcapsql_parallel_scan`
  (`false` reads every capture on one thread), and for experiments
  `pcapsql_parallel_min_file_size` and `pcapsql_index_stride`. With debug
  logging, a scan logs how it was split and why, and each partition which
  worker scanned it. The index is rebuilt by every scan: the cache of
  `pcapsql_index_cache_dir` is not there yet.
- **DuckDB extension (C API v2): several captures in one call, `filename`,
  and `FROM 'capture.pcap'`.** The positional argument of `read_pcap` and of
  every `read_<table>` is a path, a glob pattern, or a list of either:
  `read_tcp('captures/*.pcap')`, `read_dns(['a.pcap', 'b/*.pcapng.gz'])`.
  The entries are expanded through DuckDB's file system when the statement
  is bound and every file is opened and probed there, so a pattern that
  matches nothing, a missing file or a file that is not a capture is an
  error that names it. Files are read in the order of the list, and those of
  one pattern in ascending order of their paths; a file listed twice is read
  twice. The partitions of all files form one queue that the threads take
  from, so the scan is spread across files and within large ones, and the
  rows still come back in file and capture order without an `ORDER BY`.
  `frame_number` starts at 1 in each file. `filename := true` adds a
  `filename VARCHAR` column after the table's columns; like any column it
  is only produced when the query uses it. A truncated file is reported on
  its own, by name, and the files after it are read. A replacement scan
  reads a table name that ends in `.pcap`, `.pcapng` or `.cap` (optionally
  `.gz` or `.zst`, any case) as `read_pcap` of that path or pattern; a
  table or view of that name comes first. DuckDB's multi-file reader is not
  used (it forwards neither named parameters nor filters), so
  `hive_partitioning` and `union_by_name` are not offered.
- **DuckDB extension (C API v2): filter pushdown on `frame_number` and
  `timestamp`.** A scan takes over the filters DuckDB offers it that are
  exactly a range of frame numbers or of timestamps (core's
  `FramePredicate`): a comparison (`=`, `<`, `<=`, `>`, `>=`) of
  `frame_number` or `timestamp` with a constant, in either order, and any
  `AND` of them. DuckDB no longer evaluates those; the scan enforces them
  before a packet is parsed. A constant is only used in the type DuckDB
  compares the stored value with (a `UBIGINT`, a `TIMESTAMP_NS`, or a
  `HUGEINT` against the widened frame number), so nothing is rounded: a
  `TIMESTAMP`, `DATE` or text constant has been converted to nanoseconds by
  DuckDB, and a filter on a cast of the column (`timestamp::DATE`,
  `frame_number < 2.5`) is left to DuckDB, as are `<>`, `IN`, `OR` and
  filters on other columns. Two bounds on one column reach the scan as a
  single `BETWEEN` whose inclusivity DuckDB 2.0.0's C API does not expose:
  the scan narrows its read by the inclusive range and leaves the filter
  with DuckDB, so a time window reads as little, and `EXPLAIN` still shows
  its filter. What is saved: a capture read as one partition ends its read
  after the last frame an upper frame bound admits (`frame_number <= 1000`
  on a compressed capture reads 1,000 packets); a capture read in partitions
  is planned with `plan_ranges`, which leaves out the checkpoint windows
  whose frame numbers or recorded timestamps cannot match; a filter no frame
  satisfies opens no file. With several files a `frame_number` filter
  applies to each file's own numbering. A prepared statement with parameters
  is planned again by DuckDB at each execution, and its filter is taken over
  then. `pcapsql_filter_pushdown = false` leaves every filter to DuckDB. The
  scan's debug log records name the predicate and count the packets it
  rejected.
- **DuckDB extension: distribution.** The extension is built for
  `linux_amd64`, `linux_arm64` and `osx_arm64` by DuckDB's
  `extension-ci-tools` (`.github/workflows/duckdb-dist.yml`, the build
  DuckDB's community-extensions repository runs), and each artifact is then
  loaded in DuckDB 2.0.0 on a runner of its platform. A release tag attaches
  one archive per platform to the GitHub release
  (`pcapsql-duckdb-extension-<tag>-duckdb-<DuckDB version>-<platform>.tar.gz`)
  with a checksum file. `pcapsql-duckdb/community/description.yml` is the
  descriptor for `INSTALL pcapsql FROM community`; it has not been
  submitted. `windows_amd64` is in the build matrix too, but has not run on
  a Windows runner. WebAssembly is not built.
- **DuckDB extension: documentation.** A function reference,
  `docs/duckdb-extension-reference.md`, which `make check_reference_release`
  compares with what the built artifact registers in DuckDB; a section in the
  README; and `docs/duckdb-upgrade-runbook.md`, the procedure for moving the
  extension to a new DuckDB release, with `make check_pins` (every place that
  names the DuckDB release agrees) and `make canary` (build against the
  newest `duckdb-neo`, also a weekly workflow).
- **`pcapsql-core`: fused joins.** A `scan::FusedScan` (a join of `frames`
  and protocol tables on `frame_number`, optionally on `encap_depth` too,
  inner or left) is now an output of a pass like a table: `scan::Router`
  evaluates the join over each frame's own layers and writes the joined rows
  to the output's `RowSink`, with the output's row cap, into sinks of any
  size (a frame with more joined rows than a sink holds is redelivered and
  continues where it stopped), in partitions, under the plan's frame
  predicate. The rows are exactly those of the SQL join, every match
  included, in capture order. A fused scan's columns are `FusedColumn`s: a
  member's column (optionally renamed), `FusedValue::Coalesce` (the first
  member column that is not NULL) or `FusedValue::Present` (a label by which
  left-joined members have a row), and it can carry an exact `FusedFilter`
  (`member.column IN (...)`). The evaluator is the one the DataFusion engine
  had (`FusedBatchBuilder`), made generic over the sink; a plan without a
  fused scan pays one test per frame for it.
- **`pcapsql-core`: the `*_packets` views, in `scan::views`.**
  `PacketsView::all()` defines 21 views (`tcp_packets`, `udp_packets`,
  `dns_packets`, `http_packets`, `tls_packets`, `ssh_packets`,
  `quic_packets`, `arp_packets`, `icmp_packets`, `icmpv6_packets`,
  `ndp_packets`, `mld_packets`, `dhcp_packets`, `ntp_packets`,
  `gre_packets`, `mpls_packets`, `vxlan_packets`, `gtp_packets`,
  `ipsec_packets`, `bgp_packets`, `ospf_packets`) as fixed fused scans with
  named columns, so that an engine that cannot fuse joins itself still gets
  each of them in one pass (`PacketsView::scan`). They are the SQL views of
  the same names of the DataFusion engine, column for column and row for
  row; that engine's SQL stays the reference and its tests compare the two
  over 23 captures. `packets`, `tunneled_packets`, `ip4_in_ip6` and
  `ip6_in_ip6` are not defined here: they join layers of different
  encapsulation levels or need a full join.
- **DuckDB extension (C API v2): `read_<proto>_packets(files)` and
  `pcap_views()`.** One table function per view of `scan::views`, with the
  arguments and the behaviour of every scan function (`strict`, `filename`,
  lists and patterns of files, partitioned scans that keep capture order,
  filters on `frame_number` and `timestamp` applied while reading):
  `read_tcp_packets('x.pcap')` returns each TCP segment with the frame's
  timestamp and the MAC and IP addresses of its own encapsulation level, in
  one pass over the capture, where the join of `read_frames`, `read_tcp`,
  `read_ethernet`, `read_ipv4` and `read_ipv6` reads it five times. The rows
  are those of that join, which the tests run in DuckDB and compare.
  `read_pcap(files, protocol := 'tcp_packets')` reads a view by name,
  `pcap_schema('tcp_packets')` lists its columns, and `pcap_views()` lists
  the views (`name`, `description`, `protocol`, `column_count`).
  `pcap_protocols()` is unchanged: it lists the tables. An unknown name's
  error now also points to `pcap_views()`.

### Changed

- **`pcapsql-core` builds for Windows.** Its manifest listed most
  dependencies under `[target.'cfg(unix)'.dependencies]` by accident, and
  depended on the Unix-only `netlink-packet-route` without using it. Checked
  by cross-compiling for `x86_64-pc-windows-gnu`; the read timeout and
  cancellation of a stdin source remain Unix-only. The DuckDB extension is
  built for `windows_amd64` as a result.
- **Minimum Rust versions are declared.** `pcapsql-core` needs Rust 1.87
  (`is_multiple_of`), `pcapsql-datafusion` 1.88 (DataFusion 51) and
  `pcapsql-testgen` 1.73; the DuckDB crates already declared 1.88. Cargo
  now refuses an older compiler with that message instead of a compile error.
- **Unused dependencies removed**: `anyhow`, `netlink-packet-route` and
  `netlink-packet-utils` from `pcapsql-core`; `serde`, `bytes`,
  `datafusion-catalog` and `datafusion-datasource` from `pcapsql-datafusion`.
- **`pcapsql-core`: the `scan` API is tightened** (it is unstable). Its
  items have one path each, `scan::Name`: the submodules but `testing` are
  private. `ScanPlan::compile` refuses a plan with stream tables
  (`PlanError::StreamsNotBuilt`), which the scan driver would give no rows;
  a frontend that builds them itself calls `compile_with_streams`.
  `FrameObserver` has an associated `Error`, which `PartitionScan::step`
  returns. `PlanError` converts into `pcapsql_core::Error` (`Error::Plan`).
  `FramePredicate` gains `none`, `frame_number`, `timestamp_ns` and
  `intersect`; `TableDef` a `description`. Gone, for want of a user:
  `StreamTable` (`TableKind::Stream` is a unit variant), `UnsupportedKind`,
  `ColKind::data_kind` and `TryFrom<&DataKind> for ColKind`.
- **A stream reassembly failure is reported as what it is.** The CLI's
  message read "I/O error: Query error: Query execution error: Stream
  processing error: ..."; the "I/O error: " in front is gone.
- **DuckDB extension: the message of a truncated capture** names the last
  complete frame and no longer counts the bytes after it: the scan now takes
  the truncation from the packet reader (`PacketReader::truncated`) instead
  of comparing byte counts.
- **`pcapsql-core`: `PacketReader` implementations provide
  `process_packets_flow`.** `process_packets` is now a provided method on top
  of it, with its behaviour unchanged. `FilePacketReader` is an alias of
  `ReadPacketReader<File>`.
- **`pcapsql-datafusion`: table schemas come from the core catalogue.**
  `query::tables::get_table_schema` and its siblings render
  `scan::Catalog::builtin()` as Arrow; the tables, their columns and
  `SELECT *` are unchanged. The per-table `*_table_schema()` functions,
  `encap_fields`, `frame_number_field` and the `STREAM_TABLES` constant
  (now `stream_table_names()`) are gone from the library.
- **DuckDB extension: the scalar functions answer as DataFusion does.**
  Compared with the extension for DuckDB 1.x: `tcp_flags_str(0)` is the empty
  string, not `NONE`; `ip_proto_name` knows the IANA table instead of 11
  protocols and gives `Proto 200`, not `PROTO200`, for an unassigned number;
  `dns_type_name` knows 51 record types instead of 20; `dns_rcode_name` gives
  `RCODE<n>` above 255 instead of naming the low byte; `ethertype_name` uses
  the DataFusion spellings (`PPPoE Discovery`, `EAP over LAN`,
  `MPLS Multicast`, ...); `mac()` accepts the bare 12-digit form and
  surrounding whitespace; `pcap_unhex()` accepts surrounding whitespace and a
  `0x` prefix.
- **DuckDB extension: the scan functions differ from those for DuckDB 1.x.**
  `protocol` is a named parameter of `read_pcap`
  (`read_pcap('x.pcap', protocol := 'tcp')`), no longer its second argument.
  `read_pcap(..., protocol := 'tcp')` and `read_tcp(...)` return the same
  rows, one per occurrence of the protocol in a packet (`encap_depth = 0` is
  the outermost); they used to differ for tunnelled packets. Column names and
  types are the DataFusion engine's: no protocol prefix, IPv4 addresses as
  `UINTEGER`, MAC and IPv6 addresses as `BLOB`. Timestamps are `TIMESTAMP_NS`
  and no longer lose the nanoseconds of a capture that has them.
- **DuckDB extension: `pcap_protocols()` reads the shared catalogue.** It
  lists `frames` and the 27 protocol tables, as before, and gains a fourth
  column, `kind` (`frames` or `protocol`). `field_count` is now the number of
  columns of the table, the ones `pcap_schema()` lists (`frame_number`,
  `timestamp` and the encapsulation columns included), where it was the
  number of fields of the protocol's parser; `frames` has 6, with `raw_data`,
  not 5. The catalogue's stream tables (`tcp_connections`, `tls_sessions`,
  `http_messages`, `http2`) are not listed, since the extension does not read
  them.
- **The scalar SQL functions call the core kernels.** `ip_proto_name()`,
  `tcp_flags_str()`, `ip_in_cidr()`, `mac()`, `hex()` and the rest of the
  network, protocol and utility functions are now Arrow wrappers over
  `pcapsql_core::format`, with the same result for every input. The name
  functions no longer allocate a `String` per row for a known value, and
  `tcp_flags_str()` and `hex()` write into the output column directly.
- **`pcapsql-datafusion`: the parse subscription and the pushed-down filters
  are built on the core scan plan.** Queries and their results are
  unchanged. In the library:
  - `FilterEvaluator` is gone. `query::row_predicate(exprs, table)` converts
    a scan's filter expressions into a `scan::RowPredicate` for a catalogue
    table and `query::is_pushable(expr, table)` says whether an expression
    contributes to one. `CompareOp` and `SimplePredicate` are replaced by
    `scan::CmpOp`, `scan::Literal` and `scan::RowPredicate`.
  - `ParseSubscription` wraps a `scan::ScanPlan` (`plan()`) and no longer
    has public fields. It is filled with `subscribe_table`,
    `subscribe_fused` and `subscribe_stream_table`, which fail on an unknown
    table or column and on a table subscribed twice; `tables_full` returns a
    `Result` for the same reason. `table_schema` moved to
    `CompiledSubscription`, which `ParseSubscription::compile(registry)`
    returns and `NormalizedBatchSet::new` and `new_streaming` now take
    (both are infallible).
  - `TableSubscription::predicate` is an `Option<scan::RowPredicate>`.
  - `fusion::JoinKind` and `fusion::MemberJoin` are re-exports of the core
    types; `FrameJoinSpec::to_fused_scan` replaces `member_fields`.
  - A pushed-down comparison on `encap_depth`, `tunnel_type` or `tunnel_id`
    is now evaluated at parse time, from the layer's encapsulation context.
    Before, it was accepted and never dropped a row. DataFusion applies the
    filter again either way.
  - A table subscribed with every one of its field columns named is parsed
    unprojected, as one subscribed without a column list already was.
- **`pcapsql-datafusion`: `frames` and the protocol tables are built
  through the core scan layer.** The rows a packet adds, and what each cell
  holds, come from `scan::Router` and `scan::write_value`; apart from the
  two fixes below, query results are unchanged. In the library:
  - `query::builders::ArrowSink` is the Arrow `scan::RowSink`: builders kept
    per Arrow type and reused across batches, `take_batch()` for the rows
    held (an output without columns keeps its row count), `rows()` and
    `is_full()`. It replaces `ProtocolBatchBuilder`, which is gone together
    with its `add_parsed_row` and `add_frame_from_raw`; a row is written
    with `scan::write_layer_row` / `write_frame_row`.
  - `NormalizedBatchSet` keeps its interface. It now holds a `Router` and
    an `ArrowSink` per table and adds only delivery, backpressure and the
    time-based flush. A batch is never larger than the batch size, also when
    a frame with several rows in one table straddles the boundary.
  - `query::arrow_schema::arrow_type_to_col_kind` is the inverse of
    `col_kind_to_arrow_type`.
  - Fused joins are built through the scan layer too (see "fused joins are
    built by the core scan layer" below).
- **`pcapsql-datafusion`: a parse pass runs on the core scan driver.** Each
  partition of a pass, materialized or streamed, is a `scan::PartitionScan`
  that the engine steps, delivering a table's batch when the scan hands it
  out. Query results are unchanged, and so are progress reporting (per 1024
  packets), read timeouts, cancellation, the time-based flush of a
  continuous engine and the delivery rules of the exchange. What differs:
  - A partition whose tables have all reached their row cap (a pushed-down
    `LIMIT`), or lost their consumers, now stops at the frame that reached
    the last cap. Before, it read on to the end of the current chunk of
    1024 packets. `--stats` therefore reports fewer packets scanned for
    such a query, and on a live stream the producer no longer waits for
    packets nobody wants.
  - `NormalizedBatchSet` is reduced to what is specific to DataFusion:
    delivery (`deliver`) and the stream subscriber, which it feeds as the
    scan's `FrameObserver`. `new` and `new_streaming` also
    return the `ArrowSink`s the scan writes to, and `finish` /
    `finish_streaming` take them back. `add_packet_from_ref`,
    `flush_partial`, `all_capped` and `row_count` are gone (the scan's
    `step`, `output_done` and `ScanStats` replace them; `rows_built` gives
    the rows per table).
  - `CompiledSubscription::shared_scan` gives the compiled plan as an
    `Arc`.
  - The partition count comes from `scan::partition_target`, with the same
    decisions as before; `auto_target_partitions` is unchanged.
- **`pcapsql-datafusion`: fused joins are built by the core scan layer.** A
  join the optimizer fuses (a `*_packets` view under `--stdin`, a one-shot
  or a continuous query) is a `scan::FusedScan` output of the pass, written
  by the scan's `Router` into an `ArrowSink` like a table's rows. Query
  results are unchanged (the golden corpus compares fused results with
  DataFusion's own joins). What differs: a fused batch is never larger than
  the batch size (it could exceed it by the rows of one frame), and a fused
  join with a pushed-down `LIMIT` stops at the row that fills it instead of
  after the frame that does. In the library, `query::builders::
  FusedBatchBuilder` and the internal `DynamicBuilder` are gone, and
  `NormalizedBatchSet::take_fused_pending` with them (a fused join's
  partial batch is in its `ArrowSink`, like a table's);
  `FrameJoinSpec::to_fused_scan` is unchanged.
- **Performance: a scan no longer allocates for every packet.**
  `parse_packet` returned the layers in a new `Vec` with room for eight
  (7,808 bytes), also for a scan of `frames` alone, which parses nothing. A
  partition scan now keeps that storage from packet to packet
  (`protocol::LayerBuf` with the new `parse_packet_into`; `parse_packet` is
  unchanged for other callers) and asks for none when nothing is parsed.
  Measured through `PartitionScan` into a sink that stores nothing: 1.00
  allocation per packet before, 0 after (`tests/parse_alloc.rs` counts);
  `frames` 51 → 31 ns and 972 → 430 instructions per packet, `udp` 5,750 →
  5,230 instructions per packet. Results are unchanged.
- **Performance: IPv4 and MAC addresses are formatted without `fmt`.**
  `format::write_ipv4`, `write_mac`, `format_ipv4`, `format_mac` and the text
  a string column gets for an address write digits into a stack buffer and
  hand the sink one `&str`; all MAC formatting of the scan path is one
  function. Per call: `write_ipv4` 81 → 24 ns, `format_ipv4` 95 → 30 ns,
  `write_mac` 95 → 11 ns, `format_mac` 128 → 27 ns. The text is byte for
  byte what it was (lowercase hex, colons, no leading zeros in an octet),
  checked against the standard library for every pair of adjacent octets.
  IPv6 still goes through `std`.
- **Performance: the capture reader copies every byte once less.**
  `GenericPcapReader` put a 256 KiB `BufReader` under `pcap_parser`'s own
  256 KiB buffer; the source is now read straight into the parser's buffer.
  The `BufReader` read the source once per refill, as the parser does now,
  and never ahead of it, so files, pipes with a read timeout, decompressors
  and the DuckDB file system see the same number of reads and deliver the
  same packets. Reading `frames` from memory: 430 → 364 instructions per
  74-byte packet, and 202 → 102 ns (3,926 → 2,473 instructions) per
  1,442-byte packet.
- **`pcapsql-datafusion`: batch builders start at the size of the batch
  before.** Arrow builders give their buffers away with each batch, so every
  batch after the first regrew from empty: 0.257 reallocations per packet at
  1,024 rows a batch (`frames`+`ipv4`+`udp`), now 0. The `scan` benchmark's
  parse pass is 0 to 8% faster.
- **`pcapsql-datafusion`: UDFs parse a literal argument once.** At 8,192
  rows, `ip_in_cidr(col, '10.0.0.0/8')` 30 → 0.6 ns/row, `ip6_in_cidr` 64 →
  2.0, `has_tcp_flag` 8.1 → 0.7; `ip4_to_string`, `ip6_to_string` and
  `mac_to_string` write into the result without a `String` per row (11%, 24%
  and 33% faster). New `udf` benchmark.
- **DuckDB extension: scalar kernels are inlined into their vector loops**
  instead of called through function pointers. Over 20M rows on one thread:
  `ip_in_cidr` filter 4.8 → 3.6 ns/row (native expression: 2.6),
  `has_tcp_flag` 7.0 → 5.8, `tcp_flags_str` 45 → 23.
- **DuckDB extension: `ip_in_cidr` and `has_tcp_flag` with a literal pattern
  are a SIMD compare** over a chunk without NULLs: 15 → 7 instructions per
  row in the function; the whole filter query over 20M rows on one thread
  3.5 → 3.1 ns/row and 5.1 → 4.6 (native expressions: 2.3 and 3.9). The
  crate's second audited `unsafe` call; `make check_unsafe` pins the two.
- **DuckDB extension: `ip_in_cidr` and `has_tcp_flag` with a literal pattern
  keep the SIMD compare in a chunk with NULLs**: the values are read as slices
  of the rows of the 64-row words of the validity mask that have no NULL,
  words that are all NULL are skipped, and only words with both are read a row
  at a time; the slot of a NULL row is never read. With a third of the rows
  NULL in runs of 1,000 (the `tcp_flags` of packets that are not TCP) the
  functions execute 29 → 7 and 28 → 5 instructions per row, and a filter over
  20M rows on one thread takes 5.1 → 3.4 and 6.2 → 4.3 ns/row (native
  expressions: 2.3 and 1.4); with 1% of the rows NULL at random, 26 → 17 and
  25 → 15 instructions; chunks without NULLs, with 10% at random and behind a
  selection are within 3% of what they were. The audited `unsafe` of
  `engine::scalar` is now its module `valid` (three `unsafe`s, pinned by
  `make check_unsafe`), whose tests run under Miri.
- **Hex decoding without a `Vec` per value.** New
  `format::parse_hex_into(text, &mut Vec<u8>)` decodes into a buffer the
  caller keeps, by table lookup; `parse_hex` is a wrapper and accepts and
  rejects what it did. `pcap_unhex` in DuckDB: 61 → 26 ns/row over 20M
  16-digit strings on one thread (DuckDB's `unhex`: 36). `unhex` in
  DataFusion appends to a `BinaryBuilder` from one buffer.
- **DuckDB extension: `ip4_to_string` and `mac_to_string` store the text
  from a stack buffer** (`format::ipv4_text`, `mac_text`, now public)
  without a `String` in between: 24 → 21 ns/row (DuckDB's integer to
  `VARCHAR` cast: 19) and 32 → 26 over 20M rows on one thread, down from 69
  before the kernels stopped using `fmt`. `ip6_to_string` is still `std`'s
  formatting, at 82.
- **IPv6 text without `fmt`.** New `format::ipv6_text(bytes, &mut buf)`
  (with `IPV6_TEXT_LEN`) writes the RFC 5952 form into a buffer on the
  caller's stack; `write_ipv6` and `format_ipv6` use it, and `write_ipv6`
  hands its sink the address in one piece. The text is byte for byte what
  `std`'s `Display for Ipv6Addr` prints (Rust 1.97): the longest run of two
  or more zero groups as `::`, the first when several are as long, and
  IPv4-mapped addresses, and only those, with a dotted tail
  (`::ffff:192.0.2.1`); tested against `std` for every value of each group,
  every arrangement of zero groups and 400,000 sampled addresses. Per call
  over 1M random addresses: `write_ipv6` 128 → 32 ns, `format_ipv6` 189 →
  54. `ip6_to_string` in DuckDB stores the text from the buffer like
  `ip4_to_string`: `sum(length(ip6_to_string(addr)))` over 20M rows on one
  thread 184 → 83 ns/row (`hex(addr)` in its place: 65; reading the column
  alone: 31). The text a string column gets for an IPv6 *field value* in a
  scan (`scan/row.rs`) still goes through `std`.
- **Performance: a layer's parser is looked up in a table.** The parse loop
  asked the candidate parsers of each layer in turn (31 `can_parse` calls
  for an Ethernet/IPv4/UDP packet), and each compared hint names as strings.
  Hints are now keyed by an enum and stored in an array (`HintKey`, `Hints`),
  and every parser states its match as rules (`Protocol::dispatch`) that the
  registry files by hint key and value, per parent parser: a layer costs one
  or two lookups and no `can_parse` call. The parsers chosen are the same:
  debug builds check each choice against a scan of every `can_parse`, and
  tests compare whole parser chains over the fuzz corpus (76,926 packets,
  every parser) and the golden captures. Instructions per packet (callgrind,
  `pcapsql-core/examples/parse_cost.rs`), before → after: `parse_packet`
  at full scope, UDP 4,978 → 3,473, TCP 6,648 → 5,093, DNS 10,628 → 9,156;
  a scan into a sink that stores nothing, `udp` 5,338 → 3,919, `tcp` 8,050 →
  6,435, `dns` 12,030 → 10,639.
  API (`pcapsql-core`, unstable): `ParseContext::hint`, `insert_hint`,
  `set_hint` and `ParseResult::hint` take a `HintKey` instead of a `&str`;
  `ParseContext::hints` and `ParseResult::child_hints` are `Hints` instead
  of a `SmallVec` of `(&str, u64)` (`HintEntry` is gone), and a key holds
  one value; `Protocol::child_hint_keys` returns `HintKey`s;
  `Protocol::parse_gates` and `ParseGate` are replaced by
  `Protocol::dispatch` with `Dispatch`, `DispatchRule` and `Cond`.

### Fixed

- **`--filter` with non-ASCII text in the query.** The BPF filter is spliced
  into the query at the position of its `WHERE` (or of the clause a `WHERE`
  goes in front of), and that position was found in `query.to_uppercase()`,
  whose bytes are not the query's: upper-casing changes the length of some
  text (`ﬁ` becomes `FI`, `ı` becomes `I`). A query with such a character
  before the keyword had the filter spliced in a few bytes off, into the
  middle of a word, and any non-ASCII character outside parentheses, such
  as `SELECT 'é' AS label …`, made the keyword search panic. The search now
  runs over the bytes of an ASCII-upper-cased copy, which has the query's
  own offsets.

- **Streaming queries could return rows out of capture order.** In the
  bounded exchange between a parse pass and DataFusion, the consumer read
  the channel and then the overflow queue without the queue's lock. A
  producer could put one batch in the channel and queue the next between the
  two reads, and the queued batch was returned first. An un-`ORDER`ed query
  over a table larger than the exchange then came out with one batch ahead
  of an earlier one, about once in thirty runs on a loaded machine. Both
  reads are now made under the lock the producer holds while sending.

- A value of the wrong length for a fixed-size binary column (a MAC or IPv6
  address column given, say, a 3-byte value by a parser) is now NULL.
  Before, nothing was stored for it, the column came out one row short and
  the whole batch, and with it the query, failed.
- A wrong-length item of a list of fixed-size binaries (`dns.answer_ip6s`)
  is now a NULL item. Before, the item was dropped, which shortened the
  list and shifted the items after it.
- An unsigned 64-bit value above `i64::MAX` written to a timestamp column
  is now NULL. Before, it wrapped to a negative timestamp. No built-in
  parser emits such a value; this is the rule the integer columns already
  followed (out of range is NULL, never wrapped).

## [0.4.1] - 2026-10-24

The three limitations listed with continuous mode in 0.4.0 are gone: the
`*_packets` views join layers of the same encapsulation level and are fused
into the parse (so a continuous query can window a view), a query over a quiet
pipe releases its parser when it is done, and the streaming aggregate accounts
its state to a memory limit with hop windows aggregated per slice. The parser's
hot path is about three times faster on one core. Design and measurements:
`docs/streaming_windows/08-continuous-limitations.md`.

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

- **Parser hot path, about 3× faster on one core** (2M-packet `udp` query:
  1.72 s → 0.58 s; `udp_packets` 1.87 s → 0.68 s; 8 cores 0.46 s → 0.20 s).
  Each parser declares the hints it needs and emits, so a layer asks only the
  parsers that can follow it instead of all 27; the parse scope resolves once
  per registry; protocol table columns resolve their source once and look
  fields up by their position in the previous row (`ParseResult::get_hinted`);
  list cells append straight into the values builder; the batch set indexes
  its table slots. Debug builds compare every dispatch with a full scan.
  `Protocol::parse_projected` takes a `FieldSet` instead of `HashSet<String>`,
  and layers returned by `parse_packet` carry empty `child_hints`.

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

- **Memory limit and sliced hop windows for continuous queries.**
  `--memory-limit SIZE` (`EngineOptions::memory_limit`) gives the engine a
  DataFusion memory pool of that size; the streaming window aggregate
  registers a consumer and accounts its state (open windows × groups ×
  accumulators, frozen slice states, keys) to it after every batch. When the
  state does not fit, `--on-memory-limit error` (the default) fails the query
  naming the state, the open windows and the groups, and
  `--on-memory-limit close-oldest` emits the oldest open windows before their
  time until it fits, counted in `ParseStats::windows_forced`, `--stats` and
  `--progress`; a row for such a window arriving later is late. Independently
  of the limit, a `hop()` whose size is a multiple of its slide is now
  aggregated per slice (one slide's worth of rows) and the slices are merged
  through the accumulators' intermediate state when a window closes, so each
  row updates one accumulator instead of `size / slide` and a slice holds
  one accumulator set plus one frozen state; the per-window path remains for
  other hops, for `tumble()`, and when anything other than the window group
  columns reads `window_start` / `window_end`.
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

[Unreleased]: https://github.com/mtottenh/pcapsql/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/mtottenh/pcapsql/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/mtottenh/pcapsql/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/mtottenh/pcapsql/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/mtottenh/pcapsql/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/mtottenh/pcapsql/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mtottenh/pcapsql/releases/tag/v0.1.0
