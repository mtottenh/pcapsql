# pcapsql-duckdb

The pcapsql extension for DuckDB, on the DuckDB C API v2 through
[`duckdb-neo`](https://crates.io/crates/duckdb-neo). The plan it follows is
[`docs/duckdb-v2-extension-roadmap.md`](../docs/duckdb-v2-extension-roadmap.md).

Every function of the C API v2 is still unstable, so a build loads in exactly
one DuckDB release: **2.0.0** today. `TARGET_DUCKDB_VERSION` in the `Makefile`,
the `duckdb-neo` pin in the `Cargo.toml` files,
`scripts/duckdb-release.sha256` and a few more places name that release and
change together: `make check_pins` fails when they disagree, and
[`docs/duckdb-upgrade-runbook.md`](../docs/duckdb-upgrade-runbook.md) is the
procedure for moving them.

Every function, parameter and setting is listed in
[`docs/duckdb-extension-reference.md`](../docs/duckdb-extension-reference.md).

## Layout

| Path | What it is |
|---|---|
| `src/` | Library `pcapsql_duckdb`: what the extension registers. `duckdb_neo` is used only under `src/engine/`, and no file is opened except through DuckDB's file system (`src/engine/fs.rs`) |
| `ext/` | The loadable extension, a `cdylib` named `pcapsql` that holds only the entrypoint |
| `itest/` | In-process tests: links libduckdb, registers the same entrypoint statically, runs SQL from `cargo test` |
| `test/sql/` | sqllogictest files, run against the built `pcapsql.duckdb_extension` |
| `extension-ci-tools/` | Git submodule with DuckDB's makefiles and the script that stamps the extension metadata, on the branch DuckDB's community-extensions repository builds this DuckDB release with |
| `community/` | The descriptor for DuckDB's community-extensions repository, and how to submit it |
| `scripts/` | What the make targets run: fetching the DuckDB release, the load test, and the checks |

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
make check_reference_release  # the function reference lists what the artifact registers
make itest              # in-process tests against libduckdb
make check              # duckdb_neo containment; no std::fs in the extension; the DuckDB pins agree;
                        # fmt and clippy for itest/
make canary             # build against the newest duckdb-neo on crates.io (CANARY=main: duckdb-rs main)
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

## Distribution

| Workflow | When | What |
|---|---|---|
| `duckdb.yml` | Every push and pull request | Builds for `linux_amd64` on the runner; SQL tests, load test, reference check, `itest`, the containment and pin checks |
| `duckdb-dist.yml` | Pushes to `main` that touch the extension; called by `release.yml` | Builds `linux_amd64`, `linux_arm64`, `osx_arm64` and `windows_amd64` with the reusable workflow of `extension-ci-tools` (Linux in its manylinux containers), then runs the SQL tests and the load test against each uploaded Linux and macOS artifact on a runner of its platform |
| `release.yml` | A `v*` tag | Calls `duckdb-dist.yml` and attaches `pcapsql-duckdb-extension-<tag>-duckdb-<DuckDB version>-<platform>.tar.gz` for each platform, and a `SHA256SUMS` file, to the GitHub release |
| `duckdb-canary.yml` | Weekly, and by hand | `scripts/canary.sh` against the newest `duckdb-neo` on crates.io and against `duckdb-rs` main |

`duckdb-dist.yml` is the build DuckDB's community-extensions repository runs
for [`community/description.yml`](community/description.yml): the same
reusable workflow, at the commit the submodule is at, with
`build_directory: pcapsql-duckdb`.

Platforms that are not built:

- **WebAssembly.** Not shown to build; see U10 in the roadmap.
- **`windows_amd64_mingw`.** The crates compile and link for
  `x86_64-pc-windows-gnu`, but `extension-ci-tools` skips the SQL tests on
  that platform, so nothing would test the artifact.
- `osx_amd64` and the musl variants are opt-in platforms of
  `extension-ci-tools` and are not opted into.

`windows_amd64` is built since `pcapsql-core` compiles for Windows (U13 in
the roadmap). That was checked by cross-compiling; the workflow has not run
on a Windows runner yet, and the load-test job does not cover the platform
(`scripts/fetch-duckdb.sh` knows no Windows archive).

## Usage

A capture is read with a table function: `read_<table>(files)` for one table,
or `read_pcap(files, protocol := '<table>')`, which reads `frames` unless a
protocol is named. `files` is a path, a glob pattern, or a list of either.
`pcap_protocols()` lists the tables and `pcap_schema('<table>')` the columns
of one. `read_<proto>_packets(files)` reads a protocol with the frame's
metadata and the addresses of the layers under it, in one pass
(`pcap_views()` lists these; see "Packets views" below).

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

-- The same without the join and with one read of the capture: a packets view
SELECT query_name, format_ip4(src_ip_v4) AS client, transport
FROM read_dns_packets('capture.pcap')
WHERE is_query;

-- TCP segments with their addresses, IPv4 or IPv6
SELECT timestamp, coalesce(format_ip4(src_ip_v4), format_ip6(src_ip_v6)) AS src, src_port,
       coalesce(format_ip4(dst_ip_v4), format_ip6(dst_ip_v6)) AS dst, dst_port,
       tcp_flags_str(flags) AS flags, ttl
FROM read_tcp_packets('captures/*.pcap')
WHERE dst_port = 443 AND encap_depth = 0;

-- Views make a capture look like a database
CREATE VIEW tcp AS SELECT * FROM read_tcp('capture.pcap');

-- Several captures: a pattern, a list, a list of patterns
SELECT count(*) FROM read_tcp('captures/*.pcap');
SELECT filename, count(*) AS queries
FROM read_dns(['monday/*.pcapng.gz', 'tuesday.pcap'], filename := true)
WHERE is_query
GROUP BY ALL;

-- A range of frames or a time window is applied while the capture is read
SELECT * FROM read_tcp('capture.pcap') WHERE frame_number <= 1000;
SELECT count(*) FROM read_dns('capture.pcap')
WHERE timestamp >= TIMESTAMP '2024-05-01 12:00:00' AND timestamp < TIMESTAMP '2024-05-01 12:05:00';

-- A capture file named where a table goes is read_pcap of it: its frames
SELECT count(*), min(timestamp), max(timestamp) FROM 'capture.pcap';
SELECT * FROM 'captures/*.pcapng.gz' WHERE length > 1400;
```

**Files.** Every file is listed and opened through DuckDB's file system, so
DuckDB's access rules apply (`enable_external_access`,
`allowed_directories`). Legacy pcap and pcapng are read, plain or compressed
with gzip or zstd; the format and the compression are recognised from the
first bytes of the file, not from its name.

**Several files.** The one positional argument is a path, a glob pattern
(`*`, `?`, `[...]`, and `**` for any depth of directories, as DuckDB's file
system matches them), or a list of paths and patterns. The files of one call
may differ in format and compression; all are read as the same table.

- The files are read in the order of the list; the files a pattern matches
  are read in ascending order of their paths, compared byte by byte (so
  `B.pcap` before `a.pcap`, and `a10.pcap` before `a9.pcap`).
- Nothing is removed: a file that is listed twice, or matched by two entries,
  is read twice.
- A pattern that matches no file is an error that names the pattern. So is a
  path that does not exist.
- Every file is opened when the statement is bound, before any row is read:
  one file that is not a capture fails the statement, with its path in the
  message.
- `frame_number` is the number of a frame within its file: it starts at 1 in
  each file. `(filename, frame_number)` identifies a frame of a call, and is
  what to join two tables of several captures on.
- `filename := true` adds a `filename VARCHAR` column after the table's
  columns, with the path of the file each row is from, as it was matched. It
  is a parameter of the call: `pcap_schema()` lists the columns of the table,
  without it.
- A view over a pattern lists the files each time it is queried, as a view
  over `read_csv('*.csv')` does: a file that has appeared since is read. A
  prepared statement reads the files that matched when it was prepared.

DuckDB's multi-file options (`hive_partitioning`, `union_by_name`) are not
offered.

**`FROM 'capture.pcap'`.** A table name that ends in `.pcap`, `.pcapng` or
`.cap`, optionally followed by `.gz` or `.zst`, in any case, is read as
`read_pcap('<name>')`, the `frames` table; a pattern with such an ending
(`'dir/*.pcap'`) reads every file it matches. Here the name decides, since
there is nothing else to go by; a capture under another name, another table,
`strict` and `filename` need the function. A table, a view or a common table
expression of that name comes first: DuckDB only asks the extension about a
name it does not find in the catalog. Names with a schema in front
(`main."x.pcap"`) are not answered.

**Rows.** `frames` has a row per packet. A protocol table has a row per
occurrence of the protocol in a packet, so a tunnelled packet (VXLAN, GRE,
GTP, IP-in-IP) has several rows in `ethernet`, `ipv4` or `udp`: `encap_depth`
is 0 for the outermost and counts up, and `tunnel_type` and `tunnel_id` name
the enclosing tunnel. `WHERE encap_depth = 0` selects the outermost headers.
Rows come back in capture order, and the files of a call one after the other
in the order they are read, without an `ORDER BY` and on any number of
threads.

**Columns.** Every table starts with `frame_number` and `timestamp`
(`TIMESTAMP_NS`, as exact as the capture records it), so a protocol table
needs no join with `frames` for the time of a packet. Only the columns a query
uses are produced, and only the protocols and fields they need are parsed: a
query of `frames`, or `count(*)` and `frame_number` of it, parses no protocol.

**Packets views.** `read_<proto>_packets(files)` returns one row per
occurrence of a protocol, as `read_<proto>` does, with more beside it: the
frame's `frame_number`, `timestamp` and (in some views) `length`, and columns
of the layers the protocol sits on, taken from the **same encapsulation
level** as the row. `read_tcp_packets` is every TCP segment with the MAC and
IP addresses it travels between and its ports and flags; for a segment inside
a tunnel those are the inner addresses. There are 21 of them, one per row of
`pcap_views()`: `tcp`, `udp`, `dns`, `http`, `tls`, `ssh`, `quic`, `arp`,
`icmp`, `icmpv6`, `ndp`, `mld`, `dhcp`, `ntp`, `gre`, `mpls`, `vxlan`, `gtp`,
`ipsec`, `bgp` and `ospf`, each followed by `_packets`.

- A view is a join, written once and evaluated by the scan: `tcp_packets` is
  `read_frames` joined with `read_tcp` on `frame_number`, and left-joined with
  `read_ethernet`, `read_ipv4` and `read_ipv6` on `(frame_number,
  encap_depth)`. The function returns exactly the rows of that join, in the
  order of the capture, from **one** read of the capture and without a join
  operator: every layer of a frame is at hand when the frame is parsed. Run as
  a join, the capture is read and parsed once per table.
- A layer a view joins as optional leaves NULL where a level has none (the
  MAC addresses inside an IP-in-IP tunnel, `src_ip_v6` of an IPv4 packet). A
  layer a view requires gives no row where it is missing: `tls_packets` is the
  TLS records over TCP.
- Where two layers have a column of the same name the view renames one, and
  the names are the view's own: `src_ip_v4` / `src_ip_v6` for the addresses,
  `udp_length` beside the frame's `length`, `tcp_flags` in `tls_packets`.
  `tcp_packets.ttl` is the TTL of an IPv4 packet and the hop limit of an IPv6
  one. `dns_packets.transport` is `UDP`, `TCP`, `DoT` or `DoH`, by the layers
  beside the DNS message, and its `src_port` / `dst_port` are those of
  whichever transport carries it. `ndp_packets` and `mld_packets` are the
  rows of `icmpv6_packets` with the message types of those protocols.
- A view function is a scan function: `files` is a path, a pattern or a list,
  `strict` and `filename` do what they do for a table, the rows keep capture
  order on any number of threads, captures are split into partitions, and
  filters on `frame_number` and `timestamp` are applied while the capture is
  read. `read_pcap(files, protocol := 'tcp_packets')` reads a view by name,
  and `pcap_schema('tcp_packets')` lists its columns.
- The views are those of the DataFusion engine, with the same names, columns
  and rows; the definitions are in `pcapsql_core::scan::views` and both
  engines' tests compare against them. (Timestamps are `TIMESTAMP_NS` here,
  as everywhere in the extension.) Four of DataFusion's views are **not**
  offered: `packets`, `tunneled_packets`, `ip4_in_ip6` and `ip6_in_ip6` join
  layers of different levels, or need a full join, and are not of the shape
  the scan evaluates.

**Filters.** A scan applies filters on `frame_number` and `timestamp` itself,
before a packet is parsed, and reads less of the capture for them. Everything
else in a `WHERE` clause is DuckDB's to apply to the rows the scan returns, as
before. The rows are the same either way.

What the scan filters by, returning exactly the rows the filter keeps:

- `frame_number` compared with a constant: `=`, `<`, `<=`, `>`, `>=`, with
  the constant on either side. Any integer will do (`frame_number > -1` is
  every frame, as it is in DuckDB).
- `timestamp` compared with a constant of a timestamp type, a `DATE`, or text
  DuckDB reads as a timestamp: `timestamp >= TIMESTAMP '2024-05-01 12:00:00'`,
  `timestamp < '2024-05-02'`. DuckDB converts the constant to nanoseconds, so
  the comparison is on the nanoseconds the capture records.
- Any `AND` of these.

What it filters by with a frame to spare at each end: two bounds on the same
column, which is what a range or a time window is, written as `BETWEEN` or as
two comparisons. DuckDB hands such a pair to the scan as one range without
saying whether its ends are included (the C API of DuckDB 2.0.0 does not
expose that), so the scan reads the range with both ends included.

Every filter also stays in DuckDB's plan, and `EXPLAIN` shows it: DuckDB
applies it to the rows the scan returns, which removes the frames at the ends
of a range and costs a comparison per returned row otherwise. A filter that
left the plan would be known only to the scan, and DuckDB, which tells two
scans apart by their plans, would take two scans of one file with different
filters in one statement (a `UNION ALL`, a join) for the same scan and give
both the rows of one.

What it leaves alone: `<>`, `IN`, `OR`, a comparison with another column or
with an expression, a filter on a cast of the column (`timestamp::DATE = ...`,
and `frame_number < 2.5`, where DuckDB casts the column), and filters on every
other column. A prepared statement's parameter is no obstacle: DuckDB plans
such a statement again for each execution, with the value in place.

What is saved:

- A capture read on one thread (compressed, remote, small, or `threads = 1`)
  is read from its start in any case; the read ends after the last frame an
  upper bound on `frame_number` admits. `WHERE frame_number <= 1000` on a
  20 GB `.pcap.gz` reads a thousand packets (not with `strict := true`: see
  "Truncated captures"). A bound on `timestamp` does not
  end the read (timestamps need not ascend), but the packets outside it are
  not parsed.
- A capture read in partitions (below) is only read where the filter can
  match: the pass that finds the places to cut records the smallest and
  largest timestamp between them, and the stretches the filter rules out are
  not read again. The stretch at the end of a capture is always read unless
  an upper bound on `frame_number` rules it out, in case packets were
  appended since. The stretches are `pcapsql_index_stride` frames long
  (65,536), so a time window saves reading within large captures; it does
  not let a scan of many small captures skip those outside the window.
- A filter no frame can satisfy (`frame_number < 1`) opens no file.

With several files, a filter on `frame_number` applies to the frames of each
file, which are numbered from 1: `frame_number <= 10` is the first ten frames
of every file.

`SET pcapsql_filter_pushdown = false` leaves every filter to DuckDB. The
setting is read when a statement is planned.

**Truncated captures.** A capture that ends inside a record (a capture cut
short, or one still being written) returns the rows of its complete packets
and writes a warning to DuckDB's log, which the DuckDB shell prints with the
result. With `strict := true` it is an error instead:

```sql
SELECT count(*) FROM read_frames('still-being-written.pcap', strict := true);
-- Invalid Input Error: read_frames: 'still-being-written.pcap' is truncated: the capture ends
-- inside the record that follows frame 17, the last complete one; ...
```

A query that stops early (a `LIMIT`, or a filter with an upper bound on
`frame_number`, which ends the read) may never get to the end of the capture.
Without `strict`, a scan on one thread then reports nothing, and a scan in
partitions (below), which has a worker at the end of the capture from the
start, may or may not log the warning.

With `strict := true` the whole capture must be intact, whatever the query
reads of it, on any number of threads: a scan in partitions checks the end of
the capture when it starts, and a scan on one thread whose read an upper bound
on `frame_number` ended reads on to the end of the file (without parsing) to
check it. Either way the query fails. That makes `WHERE frame_number <= 1000`
with `strict := true` read the whole capture. A `LIMIT` is the exception: a
scan on one thread that DuckDB stops calling once it has its rows does not
look further, so it returns them.

With several files each is treated on its own: the warning names the file,
there is one per truncated file, and the files after it are read in full.

Any other problem with a file (it cannot be read, a record or a compressed
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

With several files, the partitions of all of them are one queue, in file
order, that the threads take from: a large file is split as above, any other
file is one partition, and eight small captures are read by eight threads,
one each.

| Setting | Default | Meaning |
|---|---|---|
| `pcapsql_parallel_scan` | `true` | `false` reads every capture on one thread, as `SET threads = 1` does for the whole query |
| `pcapsql_parallel_min_file_size` | 4194304 | The size in bytes from which a capture is split |
| `pcapsql_index_stride` | 65536 | Frames between two places a capture can be cut at. A capture of no more frames than this is not split, and none is split into more parts than it has such places |
| `pcapsql_filter_pushdown` | `true` | `false` leaves every filter to DuckDB, which then applies it to the rows of a scan of the whole capture (see "Filters") |

The second and third are for experiments and tests; their defaults are those
of the DataFusion engine.

**Diagnostics.** With `CALL enable_logging(level = 'debug')`, each scan writes
a record of type `pcapsql` to `duckdb_logs` for every file, which names the
file, the columns the scan produces, the protocols and fields it parses, and
how many partitions it reads the file in and why, and the range of frame
numbers and timestamps (in nanoseconds) it filters by, if any; and one record
per partition, with the worker that scanned it, its file, the number of
packets it read and, under a filter, how many of them the filter rejected
unparsed.

## What is registered

[`docs/duckdb-extension-reference.md`](../docs/duckdb-extension-reference.md)
is the reference, checked against the built artifact by
`make check_reference_release`. This section adds where each part is
implemented and how it relates to the DataFusion engine.

The scan functions, one implementation registered under 50 names:

| Function | Result |
|---|---|
| `read_pcap(files, protocol := 'frames', strict := false, filename := false)` | The rows of the table or view `protocol` names (any case); an unknown one is an error |
| `read_<table>(files, strict := false, filename := false)` for each of the 28 tables of `pcap_protocols()` | The rows of that table: `read_frames`, `read_ethernet`, `read_ipv4`, `read_tcp`, `read_dns`, ... |
| `read_<view>(files, strict := false, filename := false)` for each of the 21 views of `pcap_views()` | The rows of that view (see "Packets views"): `read_tcp_packets`, `read_udp_packets`, `read_dns_packets`, ... |

`files` is the only positional argument: a `VARCHAR` path or pattern, or a
list of them. `protocol`, `strict` and `filename` are named parameters.
`src/engine/table.rs` describes which callback does what, how the files are
expanded, how a capture is split into partitions and why the rows keep their
order.

A replacement scan, which answers a table name that is a capture path
(`FROM 'x.pcap'`, see "Usage") with `read_pcap` of it.

Four settings: `pcapsql_parallel_scan`, `pcapsql_parallel_min_file_size` and
`pcapsql_index_stride`, described under "Parallel scans" above, and
`pcapsql_filter_pushdown`, under "Filters".

Three table functions, which list what the shared scan layer
(`pcapsql_core::scan`: its `Catalog` of tables and its `PacketsView`s) says
the extension reads:

| Function | Result |
|---|---|
| `pcap_protocols()` | One row per table, sorted by name: `name`, `description`, `field_count` (the number of columns), `kind` (`frames` for the table of packets, `protocol` for a table of one protocol's layers) |
| `pcap_views()` | One row per packets view, sorted by name: `name`, `description`, `protocol` (the table the view has one row per row of), `column_count` |
| `pcap_schema(protocol)` | One row per column of the table or view, in order: `column_name`, `column_type` (the DuckDB type), `nullable`. The name is matched in any case; an unknown one is an error |

The tables are `frames` and the 27 protocol tables. The catalogue's stream
tables (`tcp_connections`, `tls_sessions`, `http_messages`, `http2`) are not
listed: the extension does not read them yet. The views are not rows of
`pcap_protocols()`, which lists one table per parser and returns what it did
before there were views; they have a function of their own because a view is
not a table (it has no `field_count` of a parser, and it has a `protocol`).

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
| `table.rs` | `PcapScan`, the table function behind every scan function: binds the table or view (a view is one fused scan of the plan, `PacketsView::scan`, where a table is one table scan; nothing else differs), expands the files argument (`FileSystem::glob`) and probes every file, maps DuckDB's projection and the pushed-down predicate to a `ScanPlan`, cuts each capture into partitions and leaves out what the predicate rules out (core's `BoundaryIndex`, `partition_target` and `PartitionQueue`, one queue over all files), has each worker claim a partition, and in each `exec` steps core's `PartitionScan` into a `ChunkWriter` until the chunk is full; reports the partition's ordinal as DuckDB's batch index |
| `replacement.rs` | The replacement scan: which table names are capture paths, and `read_pcap` as the answer |
| `pushdown.rs` | Filter pushdown: reads the filter expressions DuckDB offers a scan and turns what they say about `frame_number` and `timestamp` into core's `FramePredicate`, which the scan filters by. It accepts none, so DuckDB keeps applying each; its header says why, lists every shape that is read exactly with the reason it is exact, and what is not read |
| `settings.rs` | The four settings, and what a scan reads of DuckDB's (`threads`) |
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
nobody wrote are NULL. One vector of a chunk can be a constant the scan layer
does not write: the `filename` column, which `finish` fills with the path of
the one file the rows of the chunk are from. It is the one module with
`unsafe` code, and its header states the invariants that make the pointer
writes sound.

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
- `tests/multi_file.rs` reads several captures in one call (a list, a
  pattern, a list of patterns; legacy and pcapng, plain, gzip and zstd) and
  compares, cell by cell and in order, with the rows of each file's own scan
  one after the other, at 1, 2, 4 and 8 threads, split into partitions and
  not. It covers the order of the files, a file read twice, what cannot be
  read, the `filename` column and its projection, a truncated file among
  whole ones, how the partitions of several files are spread, the
  replacement scan and what comes before it, and a view over a pattern.
- `tests/filter_pushdown.rs` runs random and chosen filters on `frame_number`
  and `timestamp` (and filters the scan must leave to DuckDB) with
  `pcapsql_filter_pushdown` on and off and compares the rows, at 1 and 4
  threads, split and not: generated captures with ascending, shuffled and
  pre-1970 timestamps, compressed ones, the corpus captures over every
  table, and several files at once. It also checks that `EXPLAIN` still
  shows every filter, that two differently filtered scans of one capture in
  one statement keep their own rows, which partitions and how many packets
  a scan reads for a time window and for a frame range (from the scan's log
  records), where the read of a gzip capture ends, prepared statements with
  parameters, and what a filter does to the report of a truncated capture.
- `tests/packets_views.rs` compares every `read_<proto>_packets` with the join
  it stands for, run by DuckDB over `read_<table>` functions (the SQL is
  generated from the view's definition), and cell by cell with the view read
  by the shared scan layer alone (`reference_view_rows`): over the corpus
  captures, a capture of the protocols the corpus lacks, 16 real captures and
  generated ones of several chunks, at 1 and 4 threads, split and not, whole
  and under filters on `frame_number` and `timestamp`, with the filters used
  by the scan and with DuckDB alone applying them. It also covers several
  files and `filename`, `strict`, `LIMIT`, what a filter saves, `pcap_views()`
  and `pcap_schema()` of a view. (That the definitions are DataFusion's views
  is checked on that side: `packets_views_equal_the_shared_fused_scans` in
  `pcapsql-datafusion/tests/golden_corpus.rs`.)
- `tests/golden_differential.rs` runs the queries of the DataFusion golden
  corpus over the same captures and compares with the snapshots committed in
  `pcapsql-datafusion/tests/golden/`, the queries over `*_packets` views
  included (a view is `read_<proto>_packets` here). The captures and the
  queries are `pcapsql_testgen::corpus`, which
  `pcapsql-datafusion/tests/golden_corpus.rs` uses too. The file
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
- Several captures are read by one call (a list, a glob pattern), with a
  `filename` column on request, and `FROM 'x.pcap'` reads a capture.
- Filters on `frame_number` and `timestamp` are applied by the scan.
- `read_<proto>_packets` and `pcap_views()` are new.
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
