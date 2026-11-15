# pcapsql-duckdb

The pcapsql extension for DuckDB, on the DuckDB C API v2 through
[`duckdb-neo`](https://crates.io/crates/duckdb-neo). The plan it follows is
[`docs/duckdb-v2-extension-roadmap.md`](../docs/duckdb-v2-extension-roadmap.md).

Every function of the C API v2 is still unstable, so a build loads in exactly
one DuckDB release: **2.0.0** today. `TARGET_DUCKDB_VERSION` in the `Makefile`,
the `duckdb-neo` pin in the `Cargo.toml` files and
`scripts/duckdb-release.sha256` name that release and change together.

## Layout

| Path | What it is |
|---|---|
| `src/` | Library `pcapsql_duckdb`: what the extension registers. `duckdb_neo` is used only under `src/engine/`, and no file is opened except through DuckDB's file system (`src/engine/fs.rs`) |
| `ext/` | The loadable extension, a `cdylib` named `pcapsql` that holds only the entrypoint |
| `itest/` | In-process tests: links libduckdb, registers the same entrypoint statically, runs SQL from `cargo test` |
| `test/sql/` | sqllogictest files, run against the built `pcapsql.duckdb_extension` |
| `extension-ci-tools/` | Git submodule with DuckDB's makefiles and the script that stamps the extension metadata |

`itest/` is a cargo workspace of its own. It needs `duckdb-neo`'s
`build-extension-static` feature, the loadable extension needs
`build-extension`, and the two exclude each other.

## Build and test

Requirements: Rust 1.88 or later, Python 3 with `venv`, GNU Make, Git, curl.

```sh
git submodule update --init pcapsql-duckdb/extension-ci-tools
cd pcapsql-duckdb

make configure          # once: Python venv with DuckDB 2.0.0 and its SQL test runner
make release            # build/release/pcapsql.duckdb_extension
make test_release       # test/sql against the artifact, in DuckDB's Python package
make load_test_release  # LOAD the artifact in the DuckDB command-line shell
make itest              # in-process tests against libduckdb
make check              # duckdb_neo containment; no std::fs in the extension; fmt and clippy for itest/
```

`make debug`, `make test_debug` and `make load_test_debug` do the same for an
unoptimised build. `make itest ITEST_ARGS="--test guard"` passes arguments to
`cargo test`.

The DuckDB shell and library used by `load_test_*` and `itest` are downloaded
from the DuckDB GitHub release into `.duckdb-release/` (override with
`PCAPSQL_DUCKDB_CACHE`) and checked against `scripts/duckdb-release.sha256`.

The crates also build with the rest of the workspace (`cargo build --workspace`,
`cargo test --workspace`), which needs no DuckDB library: that covers the
library's unit tests, not the SQL behaviour.

`clippy.toml` forbids `std::fs` and the path queries of `std::path` in `src/`
and `ext/` (clippy's `disallowed_types` and `disallowed_methods`); it applies
to these two crates only, and `itest/` has an empty one of its own because the
tests write their fixtures with `std::fs`. `scripts/check-no-std-fs.sh`, part
of `make check`, looks for the same by text without a build.

## Load

The artifact is unsigned, so DuckDB has to be started with `-unsigned`, and
`LOAD` takes an absolute path:

```sh
duckdb -unsigned -c "LOAD '$PWD/build/release/pcapsql.duckdb_extension'; SELECT * FROM pcap_protocols();"
```

## Usage

A capture is read with a table function: `read_<table>(file)` for one table,
or `read_pcap(file, protocol := '<table>')`, which reads `frames` unless a
protocol is named. `pcap_protocols()` lists the tables and
`pcap_schema('<table>')` the columns of one.

```sql
-- One row per packet: frame_number, timestamp, length, original_length, link_type, raw_data
SELECT * FROM read_pcap('capture.pcap') LIMIT 10;

-- One row per TCP header, with the frame's number and timestamp
SELECT frame_number, timestamp, src_port, dst_port, tcp_flags_str(flags) AS flags
FROM read_tcp('capture.pcap')
WHERE dst_port = 443;

-- The same table through the generic function
SELECT count(*) FROM read_pcap('capture.pcap', protocol := 'tcp');

-- Addresses are numbers and bytes; the scalar functions and macros print and test them
SELECT format_ip4(src_ip) AS src, format_ip4(dst_ip) AS dst, count(*) AS packets
FROM read_ipv4('capture.pcapng.gz')
WHERE ip_in_cidr(src_ip, '10.0.0.0/8')
GROUP BY ALL ORDER BY packets DESC;

-- DNS answers are lists
SELECT query_name, format_ip4_list(answer_ip4s) AS a, format_ip6_list(answer_ip6s) AS aaaa
FROM read_dns('capture.pcap')
WHERE NOT is_query AND answer_count > 0;

-- Tables of one capture join on frame_number
SELECT d.query_name, format_ip4(i.src_ip) AS client
FROM read_dns('capture.pcap') d
JOIN read_ipv4('capture.pcap') i USING (frame_number)
WHERE d.is_query AND i.encap_depth = d.encap_depth;

-- Views make a capture look like a database
CREATE VIEW tcp AS SELECT * FROM read_tcp('capture.pcap');
```

**Files.** The file is opened through DuckDB's file system, so DuckDB's
access rules apply (`enable_external_access`, `allowed_directories`). Legacy
pcap and pcapng are read, plain or compressed with gzip or zstd; the format
and the compression are recognised from the first bytes of the file, not from
its name. One file per call: a list of files or a glob is not accepted yet.

**Rows.** `frames` has a row per packet. A protocol table has a row per
occurrence of the protocol in a packet, so a tunnelled packet (VXLAN, GRE,
GTP, IP-in-IP) has several rows in `ethernet`, `ipv4` or `udp`: `encap_depth`
is 0 for the outermost and counts up, and `tunnel_type` and `tunnel_id` name
the enclosing tunnel. `WHERE encap_depth = 0` selects the outermost headers.
Rows come back in capture order, without an `ORDER BY` and on any number of
threads.

**Columns.** Every table starts with `frame_number` and `timestamp`
(`TIMESTAMP_NS`, as exact as the capture records it), so a protocol table
needs no join with `frames` for the time of a packet. Only the columns a query
uses are produced, and only the protocols and fields they need are parsed: a
query of `frames`, or `count(*)` and `frame_number` of it, parses no protocol.

**Truncated captures.** A capture that ends inside a record (a capture cut
short, or one still being written) returns the rows of its complete packets
and writes a warning to DuckDB's log, which the DuckDB shell prints with the
result. With `strict := true` it is an error instead:

```sql
SELECT count(*) FROM read_frames('still-being-written.pcap', strict := true);
-- Invalid Input Error: read_frames: 'still-being-written.pcap' is truncated: the capture ends
-- inside the record that follows frame 17, the last complete one; ...
```

A query that stops early (a `LIMIT`) may never get to the end of the capture.
A scan on one thread then reports nothing, with or without `strict`. A scan in
partitions (below) has a worker at the end of the capture from the start: the
warning may or may not be logged, and with `strict := true` the end of the
capture is checked when the scan starts, so the query fails whatever it goes
on to read.

Any other problem with the file (it cannot be read, a record or a compressed
stream is damaged) fails the query in either mode: a scan does not end early
without saying so.

**Parallel scans.** A local, uncompressed capture of 4 MiB or more is split
into as many partitions as DuckDB has threads, and each partition is scanned
by one thread. The rows are the same and in the same order as on one thread:
the scan tells DuckDB which partition a chunk of rows is from, and DuckDB
keeps the partitions in order wherever order matters (a plain `SELECT`,
`LIMIT`, `CREATE TABLE AS`, `INSERT`). To find where a capture can be cut, the
scan first reads the header of every record, once, when the query starts; that
pass reads the whole file, so the first row of a large capture that is not in
the page cache takes as long as reading it. Compressed captures and captures
on a remote file system (`s3://`, `https://`) are read on one thread, and so
is a capture with a damaged record, which is reported where the scan gets to
it.

| Setting | Default | Meaning |
|---|---|---|
| `pcapsql_parallel_scan` | `true` | `false` reads every capture on one thread, as `SET threads = 1` does for the whole query |
| `pcapsql_parallel_min_file_size` | 4194304 | The size in bytes from which a capture is split |
| `pcapsql_index_stride` | 65536 | Frames between two places a capture can be cut at. A capture of no more frames than this is not split, and none is split into more parts than it has such places |

The last two are for experiments and tests; the defaults are those of the
DataFusion engine.

**Diagnostics.** With `CALL enable_logging(level = 'debug')`, each scan writes
a record of type `pcapsql` to `duckdb_logs` that names the columns it
produces, the protocols and fields it parses, and how many partitions it reads
and why; and one record per partition, with the worker that scanned it and the
number of packets it read.

## What is registered

The scan functions, one implementation registered under 29 names:

| Function | Result |
|---|---|
| `read_pcap(file, protocol := 'frames', strict := false)` | The rows of the table `protocol` names (any case); an unknown one is an error |
| `read_<table>(file, strict := false)` for each of the 28 tables of `pcap_protocols()` | The rows of that table: `read_frames`, `read_ethernet`, `read_ipv4`, `read_tcp`, `read_dns`, ... |

`file` is the only positional argument and must be a `VARCHAR` path;
`protocol` and `strict` are named parameters. `src/engine/table.rs` describes
which callback does what, how a capture is split into partitions and why the
rows keep their order.

Three settings, described under "Parallel scans" above: `pcapsql_parallel_scan`,
`pcapsql_parallel_min_file_size` and `pcapsql_index_stride`.

Two table functions, which list what the shared catalogue
(`pcapsql_core::scan::Catalog`) says the extension reads:

| Function | Result |
|---|---|
| `pcap_protocols()` | One row per table, sorted by name: `name`, `description`, `field_count` (the number of columns), `kind` (`frames` for the table of packets, `protocol` for a table of one protocol's layers) |
| `pcap_schema(protocol)` | One row per column of the table, in order: `column_name`, `column_type` (the DuckDB type), `nullable`. The name is matched in any case; an unknown one is an error |

The tables are `frames` and the 27 protocol tables. The catalogue's stream
tables (`tcp_connections`, `tls_sessions`, `http_messages`, `http2`) are not
listed: the extension does not read them yet.

Columns have the names and order of the DataFusion engine's tables, with two
differences. Timestamps are `TIMESTAMP_NS`, where DataFusion has microseconds.
And every protocol table has a `timestamp` column after `frame_number`, which
DataFusion leaves to a join with `frames`; DuckDB cannot turn that join into
one pass over the capture.

| Stored value | DuckDB type |
|---|---|
| Booleans | `BOOLEAN` |
| Unsigned integers of 8, 16, 32, 64 bits | `UTINYINT`, `USMALLINT`, `UINTEGER`, `UBIGINT` |
| Signed integers of 8, 64 bits | `TINYINT`, `BIGINT` |
| Floating point | `DOUBLE` |
| Text | `VARCHAR` |
| Bytes, of any or of a fixed length (a MAC address is 6, an IPv6 address 16) | `BLOB` |
| IPv4 addresses | `UINTEGER` |
| Packet timestamps | `TIMESTAMP_NS` |
| Lists | `USMALLINT[]`, `UINTEGER[]`, `VARCHAR[]`, `BLOB[]` |

Sixteen scalar functions. Each is a loop over a kernel of
`pcapsql_core::format`, the same kernels the DataFusion engine calls, so the
two engines give the same answer. A NULL argument gives NULL, and so does an
argument the function cannot use (text that is not an address, a BLOB of the
wrong length): no function raises an error for its input.

| Function | Result |
|---|---|
| `ip4(VARCHAR) -> UINTEGER` | The value of a dotted-quad IPv4 address |
| `ip4_to_string(UINTEGER) -> VARCHAR` | Dotted-quad text of an IPv4 address |
| `ip6(VARCHAR) -> BLOB` | The 16 bytes of an IPv6 address |
| `ip6_to_string(BLOB) -> VARCHAR` | RFC 5952 text of a 16-byte IPv6 address |
| `mac(VARCHAR) -> BLOB` | The 6 bytes of a MAC address written `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff` or `aabbccddeeff` |
| `mac_to_string(BLOB) -> VARCHAR` | Colon-separated lowercase hex of a 6-byte MAC address |
| `ip_in_cidr(UINTEGER, VARCHAR) -> BOOLEAN` | Whether an IPv4 address is in a network such as `'192.168.0.0/16'`; NULL if the text is not CIDR notation |
| `ip6_in_cidr(BLOB, VARCHAR) -> BOOLEAN` | Whether an IPv6 address is in a network such as `'fe80::/10'`; NULL if the text is not CIDR notation |
| `tcp_flags_str(USMALLINT) -> VARCHAR` | The set flags, lowest bit first: `SYN,ACK`. The empty string when none is set |
| `has_tcp_flag(USMALLINT, VARCHAR) -> BOOLEAN` | Whether the named flag (`'SYN'`, any case) is set; false for a name that is not a flag |
| `dns_type_name(USMALLINT) -> VARCHAR` | `A`, `AAAA`, ...; `TYPE<n>` for an unassigned type |
| `dns_rcode_name(USMALLINT) -> VARCHAR` | `NOERROR`, `NXDOMAIN`, ...; `RCODE<n>` for an unassigned code |
| `ip_proto_name(UTINYINT) -> VARCHAR` | `TCP`, `UDP`, ... from the IANA table; `Proto <n>` for an unassigned number |
| `ethertype_name(USMALLINT) -> VARCHAR` | `IPv4`, `ARP`, ...; the value as `0x88B5` for an unknown EtherType |
| `pcap_hex(BLOB) -> VARCHAR` | Lowercase hexadecimal text |
| `pcap_unhex(VARCHAR) -> BLOB` | The bytes hexadecimal text encodes; any case, surrounding whitespace and a `0x` prefix are accepted |

The integer arguments have exactly the type of the column they are meant for.
A literal that fits is accepted (`ip_proto_name(6)`); a column of another
integer type needs a cast (`ip4_to_string(x::UINTEGER)`).

Six macros, registered by the extension like the functions (they are not
`CREATE MACRO` statements run on a connection, and are not stored in a
database file):

| Macro | Definition |
|---|---|
| `format_ip4(ip)` | `ip4_to_string(ip)` |
| `format_ip6(ip)` | `ip6_to_string(ip)` |
| `format_mac(mac)` | `mac_to_string(mac)` |
| `format_ip4_list(ips)` | `list_transform(ips, lambda x: ip4_to_string(x))` |
| `format_ip6_list(ips)` | `list_transform(ips, lambda x: ip6_to_string(x))` |
| `format_mac_list(macs)` | `list_transform(macs, lambda x: mac_to_string(x))` |

## How a scan is built

The scan functions hold no scan logic. Which columns a table has, what a cell
holds, which rows a packet adds and where an output chunk ends are decided by
`pcapsql_core::scan`, which the DataFusion engine runs too; `src/engine/` is
the DuckDB side of it.

| Module | What it does |
|---|---|
| `table.rs` | `PcapScan`, the table function behind every scan function: binds the table and the file, maps DuckDB's projection to a `ScanPlan`, cuts the capture into partitions (core's `BoundaryIndex`, `partition_target` and `PartitionQueue`), has each worker claim a partition, and in each `exec` steps core's `PartitionScan` into a `ChunkWriter` until the chunk is full; reports the partition's ordinal as DuckDB's batch index |
| `settings.rs` | The three settings, and what a scan reads of DuckDB's (`threads`) |
| `types.rs` | The DuckDB logical type of each column kind of the catalogue (the table above), and the name DuckDB prints for it |
| `writer.rs` | `ChunkWriter`: stores the rows the shared scan layer produces (`pcapsql_core::scan::RowSink`) in the output chunk of one `exec` call |
| `fs.rs` | `DuckFile`: a buffered `std::io::Read` over a file opened through DuckDB's file system, for core's `ReadPacketReader` |

`ChunkWriter` writes each value straight into the DuckDB vector of its column:
fixed-width values through the vector's data pointer, strings and blobs inline
or into the vector's arena, list items into the list's child vector, NULLs
into the validity mask. It reports `Full` with the row that reaches the
chunk's capacity (2,048 rows) and refuses any row after that, because DuckDB
accepts an oversized chunk and then fails with an error that invalidates the
database. `finish` gives the chunk its row count; a writer dropped without it
leaves the chunk empty. For an output without columns it only counts: DuckDB
hands a scan at least one vector even for `count(*)`, and the rows of a vector
nobody wrote are NULL. It is the one module with `unsafe` code, and its header
states the invariants that make the pointer writes sound.

`DuckFile` reads 1 MiB at a time from a local file and 4 MiB from a remote
one, never more than the file holds. `DuckFile::open` starts at the first
byte, `DuckFile::open_at` at a byte offset (a partition of a capture), and
`seek` moves within an open file. An open that DuckDB does not allow
(`enable_external_access = false`, a path outside `allowed_directories`)
fails with DuckDB's error.

Tests, in `itest/`:

- `tests/scan.rs` compares what every scan function returns, cell by cell and
  in order, with the same capture read by the shared scan layer alone
  (`reference_rows` in `src/lib.rs`): every table over the six captures of the
  DataFusion golden corpus, and generated captures that span many chunks, are
  gzip- or zstd-compressed, are pcapng, or have nanosecond timestamps. It also
  covers the columns of every function against `pcap_schema()`, the arguments
  and their errors, projection, what a scan parses, and the progress it
  reports.
- `tests/scan_parallel.rs` runs the same queries on one partition and on
  several, at 1, 2, 4 and 8 threads, and compares rows and their order: every
  table of the corpus captures, generated captures of many chunks, tunnelled
  packets where a capture is cut, truncated and damaged captures, compressed
  ones, a capture that is damaged while it is being scanned, and plans that
  are run again. It reads back from DuckDB's log how each scan was split and
  which worker scanned which partition.
- `tests/golden_differential.rs` runs the queries of the DataFusion golden
  corpus over the same captures and compares with the snapshots committed in
  `pcapsql-datafusion/tests/golden/`. `build.rs` takes the captures and the
  queries from `pcapsql-datafusion/tests/golden_corpus.rs` itself. The file
  lists which queries are compared, which are not and why, and what is
  normalised (how NULL, BLOBs, lists and timestamps are printed, and the
  `timestamp` column DataFusion's protocol tables do not have).
- `tests/scan_regressions.rs` holds the regression tests for three defects of
  the extension for DuckDB 1.x: DNS AAAA answers lost from `answer_ip6s`, rows
  lost or repeated when a tunnelled packet met the end of a chunk, and a
  truncated or damaged capture read as if it were complete.
- `tests/chunk_writer.rs` runs the sink conformance suite of
  `pcapsql_core::scan::testing` against `ChunkWriter` through the test-only
  table function `chunk_rows` (`src/replay.rs`), which writes given rows with
  a `ChunkWriter` in each `exec` call; the cells are read back from the query
  result. It also covers every column type with and without NULL, lists that
  outgrow their child vector, strings with a NUL in them, nanosecond
  timestamps, scans of more than one chunk, projection, and a misused writer.
- `tests/duck_file.rs` counts the packets of real and generated captures,
  plain and gzip-compressed, with `StreamHeader::probe` and
  `ReadPacketReader::sequential` over a `DuckFile` kept in a table function's
  local state, and checks offsets, seeks and DuckDB's access rules.

### Differences from the extension for DuckDB 1.x

The scan functions:

- `protocol` is a named parameter of `read_pcap`, not its second argument:
  `read_pcap('x.pcap', protocol := 'tcp')`.
- `read_pcap(file, protocol := 'tcp')` and `read_tcp(file)` return the same
  rows, one per occurrence of the protocol in a packet. They used to differ
  for tunnelled packets.
- Columns are those of the DataFusion engine's tables: names without a
  protocol prefix, IPv4 addresses as `UINTEGER`, MAC and IPv6 addresses as
  `BLOB`, `encap_depth` as `UTINYINT`.
- Timestamps are `TIMESTAMP_NS` and keep the nanoseconds of a capture that
  has them, and every protocol table has the `timestamp` column.
- `strict` is new. A truncated capture used to end the scan without a word,
  and so did a read error.
- The file is opened through DuckDB's file system, so
  `enable_external_access = false` now stops a scan.

The scalar functions now answer as the DataFusion engine does:

- `tcp_flags_str(0)` is the empty string, not `NONE`.
- `ip_proto_name` knows the IANA table, not 11 protocols, and an unassigned
  number is `Proto 200`, not `PROTO200`.
- `dns_type_name` knows 51 record types, not 20 (`SPF`, `SVCB`, `NSEC3`, ...).
- `dns_rcode_name` gives `RCODE<n>` above 255, where it used to name the low
  byte (`dns_rcode_name(259)` was `NXDOMAIN`).
- `ethertype_name` spells some names differently: `PPPoE Discovery` for
  `PPPoE-Discovery`, `EAP over LAN` for `EAPoL`, `MPLS Multicast` for
  `MPLS-MC`, and others.
- `mac()` accepts the bare 12-digit form and surrounding whitespace.
- `pcap_unhex()` accepts surrounding whitespace and a `0x` prefix.

The listing functions now show the shared catalogue:

- `pcap_protocols()` has a fourth column, `kind`. `field_count` is the number
  of columns of the table (what `pcap_schema()` lists), where it was the
  number of fields of the parser; `frames` has 6, with `raw_data`, not 5.
- `pcap_schema()` lists the columns the readers will return, with the type
  DuckDB will show for each: it used to list the parser's field descriptors,
  which left out `timestamp` and the encapsulation columns, gave `frames` a
  `BIGINT` timestamp, and typed addresses as text.
