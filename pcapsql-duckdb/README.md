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
make remote_test_release  # read captures over HTTP, through DuckDB's httpfs (skipped without it)
make itest              # in-process tests against libduckdb
make check              # duckdb_neo containment; no std::fs in the extension; unsafe code only in
                        # its two audited places; the DuckDB pins agree; fmt and clippy for itest/
make canary             # build against the newest duckdb-neo on crates.io (CANARY=main: duckdb-rs main)
```

`make debug`, `make test_debug`, `make load_test_debug` and
`make remote_test_debug` do the same for an unoptimised build. `make itest ITEST_ARGS="--test guard"` passes arguments to
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

-- TCP connections, TLS sessions, HTTP messages: tables built from reassembled streams
SELECT client_ip, server_ip, server_port, state, bytes_to_server, bytes_to_client
FROM read_tcp_connections('capture.pcap');
SELECT sni, version, cipher_suite FROM read_tls_sessions('capture.pcap');

-- With the TLS key log of the session (SSLKEYLOGFILE), the HTTP/2 inside it
SELECT h.method, h.authority, h.path, h.status, c.server_ip
FROM read_http2('capture.pcap', keylog := 'keys.log') h
JOIN read_tcp_connections('capture.pcap') c USING (connection_id)
WHERE h.frame_type = 'HEADERS';

-- A capture file named where a table goes is read_pcap of it: its frames
SELECT count(*), min(timestamp), max(timestamp) FROM 'capture.pcap';
SELECT * FROM 'captures/*.pcapng.gz' WHERE length > 1400;
```

**Files.** Every file is listed and opened through DuckDB's file system, so
DuckDB's access rules apply (`enable_external_access`,
`allowed_directories`). Legacy pcap and pcapng are read, plain or compressed
with gzip or zstd; the format and the compression are recognised from the
first bytes of the file, not from its name.

**Remote files.** The extension has no network code: a capture at a URL is
opened through the same file-system API, by whichever DuckDB extension serves
that kind of URL, so `read_pcap('https://example.org/a.pcap.gz')` and
`read_pcap('s3://bucket/a.pcap')` work once `httpfs` is loaded (`INSTALL
httpfs; LOAD httpfs;`, or DuckDB's autoloading), with the credentials of
DuckDB's secrets. Without it the open fails with DuckDB's error, which says
that `httpfs` is needed. A remote capture is read on one thread, front to
back, 4 MiB at a time; it is not indexed, because that would be a read of
the whole file before the first row. `enable_external_access = false`
refuses a URL as it refuses a path.

How this is tested: `make remote_test_release` (`scripts/remote-test.sh`)
serves legacy, pcapng, gzip and zstd captures and a generated one of 28 MB
from a local HTTP server that answers Range requests
(`scripts/range-http-server.py`), and in the DuckDB shell compares every kind
of table read from the URL with the same file read from disk, row for row;
it also checks `filename`, lists of URLs, that the scan of a URL is one
partition, a pushed-down `frame_number` filter, `LIMIT`, the error for a
URL that does not exist, and `enable_external_access`, and reads back from
the server's log what was requested. It needs `httpfs` from
extensions.duckdb.org; where that cannot be installed the target says so and
does nothing (`REMOTE_TEST_ARGS=--require-httpfs` makes that a failure, as
the workflows do). **It has not run yet**: the machine it was written on
cannot install `httpfs`, so only the server (`make remote_test_server`,
with curl) and the script's logic over local paths were exercised; its first
real run is the next run of `.github/workflows/duckdb.yml`. Nothing has read
`s3://`, and no secret has been tried (roadmap U7).

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

**Columns.** Every table of packets starts with `frame_number` and `timestamp`
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

**Stream tables.** `tcp_connections`, `tls_sessions`, `http_messages` and
`http2` are not rows of a packet: the scan reassembles the TCP streams of a
capture while it reads it, and these tables are what the streams held when
the capture ends. `read_tcp_connections(files)` has a row per connection,
`read_tls_sessions(files)` a row per connection that carried a TLS handshake,
`read_http_messages(files)` a row per HTTP/1.x request or response however
many packets it spans, and `read_http2(files)` a row per HTTP/2 frame of a
TLS stream that a key log decrypted. `pcap_protocols()` lists them with
`kind = 'stream'`, and `read_pcap(files, protocol := 'http2')` reads them
too. They are the tables of the same names of the DataFusion engine, built
by the same code (`pcapsql_core::scan`), and behave like the other tables
with these differences:

- Their first columns are `frame_number` (where the row begins or was
  complete: the first frame of a connection, the ClientHello's frame, the
  frame that completed a message) and `connection_id`. They have no
  `timestamp`; `tcp_connections` has `start_time` and `end_time`. The four
  tables of one capture join on `connection_id`, and each joins a packet
  table on `frame_number`.
- A capture is read in order, from its first packet, on one thread:
  reassembly cannot start in the middle. It is never split into partitions,
  whatever its size and `pcapsql_parallel_scan`. Several files are still read
  by several threads, one file each.
- **Each file is a scan of its own.** Connections are numbered within a
  capture, so `connection_id` starts at 1 in every file, as `frame_number`
  does. Over several files, add `filename := true` and treat
  `(filename, connection_id)` as the connection; join on both. A connection
  whose packets are spread over two files is two connections, each as much
  as its file shows.
- The rows come when the capture has been read to its end. A `LIMIT` does not
  shorten the read, `strict := true` always finds a truncated capture, and a
  query that is interrupted (Ctrl-C) stops only once the file that is being
  read has been read: DuckDB looks for an interrupt when rows come back, and
  the C API gives a scan no way to ask.
- No filter is taken over by the scan, since every packet goes into
  reassembly: DuckDB applies the whole `WHERE` clause to the rows.
  `pcapsql_filter_pushdown` changes nothing here.

**TLS decryption.** A TLS key log is the file a browser, curl or a server
writes when `SSLKEYLOGFILE` is set (NSS key log format). Given one, a scan of
a stream table decrypts the sessions the key log has the secrets of:
`tls_sessions.is_decrypted` says which, and `http2` has the HTTP/2 frames
they carried (without a key log `http2` is empty).

```sql
SELECT sni, is_decrypted FROM read_tls_sessions('capture.pcapng', keylog := 'keys.log');

-- For scans that cannot be given the parameter: views, prepared statements
SET pcapsql_keylog = 'keys.log';
CREATE VIEW http2 AS SELECT * FROM read_http2('capture.pcapng');
SELECT method, authority, path FROM http2 WHERE method IS NOT NULL;
```

- `keylog := 'path'` is a parameter of the four stream functions and of
  `read_pcap`. When a call does not give it (or gives NULL), the setting
  `pcapsql_keylog` is used; its default is empty, which is no key log. The
  parameter wins: `keylog := ''` reads without one whatever the setting is.
- `read_pcap` uses the parameter when `protocol` names a stream table. For a
  packet table or a view it accepts and ignores it, and does not open the
  file, just as the setting does not concern those scans. The functions of
  packet tables (`read_tcp`, `read_tls`, ...) do not have the parameter, and
  `FROM 'x.pcap'` reads `frames`, with or without the setting.
- The key log is opened through DuckDB's file system when the statement is
  bound, so it can be anywhere DuckDB can read and `enable_external_access`
  applies. The setting's file is not looked at when the setting is set: a
  wrong path fails the stream scans that use it, with a message that says the
  path came from the setting.
- A file that is not a key log is an error that names the file, the line and
  what was expected there. It never repeats a label, a client random or a
  secret: no key material goes into a message or DuckDB's log (the debug
  record of a scan says how many sessions the key log has secrets of).
- An entry with a label pcapsql does not read (`ECH_SECRET`, `ECH_CONFIG`,
  ...) is skipped, as Wireshark does, and counted in that debug record. A
  leading UTF-8 byte order mark is ignored. A malformed entry of a label it
  reads (bad hex, a wrong length, a missing field) is still an error.
- TLS 1.3 and TLS 1.2 are decrypted, for the cipher suites with
  AES-128-GCM, AES-256-GCM or ChaCha20-Poly1305 (the three TLS 1.3 suites
  with them, and those of TLS 1.2). A session with another suite (CBC,
  AES-CCM) is listed with `is_decrypted = false` and gives no rows. What a
  session carries is parsed as HTTP/2 (`read_http2`) or as HTTP/1.x
  (`read_http_messages`), by its ALPN protocol or, without one, by how the
  client starts. The tests read generated captures
  (`pcapsql-testgen/fixtures/`, each with its `.keys`): HTTP/2 over
  TLS 1.3, HTTP/2 and HTTP/1.1 over TLS 1.2; the other suites are tested in
  `pcapsql-core`. The reference lists what is not decrypted (0-RTT, records
  after a `KeyUpdate`, a key log without the TLS 1.3 handshake secrets).
- A DuckDB secret (`CREATE SECRET`) would be the natural home for a key log,
  but the C API v2 of DuckDB 2.0.0 has no function to register a secret type
  or to look a secret up, and `duckdb-neo` 0.20000.2 none either; hence a
  path.

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

**Writing a capture.** `COPY ... TO 'x.pcap' (FORMAT pcap)` writes the rows
of a query as a classic pcap file, a packet per row. The columns it takes
are those of `frames`, found by name, so the natural query is over
`read_frames`, filtered or joined with a protocol table:

```sql
-- The DNS traffic of a capture, as a capture
COPY (SELECT f.* FROM read_frames('in.pcapng') f
      WHERE frame_number IN (SELECT frame_number FROM read_dns('in.pcapng'))
      ORDER BY frame_number)
  TO 'dns.pcap' (FORMAT pcap);

-- An hour of several captures, in time order
COPY (SELECT * FROM read_frames('day/*.pcap.gz')
      WHERE timestamp >= TIMESTAMP '2024-03-01 12:00:00' AND timestamp < TIMESTAMP '2024-03-01 13:00:00'
      ORDER BY timestamp)
  TO 'noon.pcap' (FORMAT pcap);
```

`raw_data` (`BLOB`) and `timestamp` are required; `original_length` and
`link_type` are used when the query has them; every other column is ignored.
The options are `LINKTYPE` (a number or a name such as `LINUX_SLL`; the
default is the link type of the first row, or Ethernet), `SNAPLEN` (default
262144; a longer packet is cut and keeps its original length) and
`PRECISION` (`'ns'` or `'us'`). The reference has the details; in short:

- The file is little-endian classic pcap. Its timestamps are in the unit of
  the `timestamp` column unless `PRECISION` says otherwise, so a copy of
  `read_frames`, whose timestamps are `TIMESTAMP_NS`, is a nanosecond pcap
  file and loses nothing. `PRECISION 'us'` writes the microsecond format and
  drops what is below a microsecond.
- With `PRECISION 'us'` and the `SNAPLEN` of the input's header, the copy of
  a whole little-endian microsecond pcap file is that file, byte for byte.
- A pcap file has one link type. A row with another one fails the statement
  with a message that names the row; `PARTITION_BY (link_type)` with
  `WRITE_PARTITION_COLUMNS` writes a file per link type.
- NULL in `raw_data` or `timestamp`, and a timestamp outside 1970 to 2106,
  fail the statement and name the row. A result without rows is a capture
  without packets.
- The rows are written in the order the query produces them: say `ORDER BY`.
  Without one DuckDB 2.0.0 happens to feed a copy from one thread, so a scan
  and a filter keep capture order, but that is the plan's doing, not a
  promise.
- A statement that fails leaves no file behind, and leaves an existing file
  as it was (DuckDB writes to a temporary file first, unless
  `USE_TMP_FILE false`).
- Not there: pcapng output, compressed output (a name ending in `.gz` or
  `.zst` is refused, not written uncompressed), and `COPY ... FROM`, which
  the table functions cover.

## What is registered

[`docs/duckdb-extension-reference.md`](../docs/duckdb-extension-reference.md)
is the reference, checked against the built artifact by
`make check_reference_release`. This section adds where each part is
implemented and how it relates to the DataFusion engine.

The scan functions, one implementation registered under 54 names:

| Function | Result |
|---|---|
| `read_pcap(files, protocol := 'frames', strict := false, filename := false, keylog := NULL)` | The rows of the table or view `protocol` names (any case); an unknown one is an error |
| `read_<table>(files, strict := false, filename := false)` for each of the 28 tables of packets of `pcap_protocols()` | The rows of that table: `read_frames`, `read_ethernet`, `read_ipv4`, `read_tcp`, `read_dns`, ... |
| `read_<table>(files, strict := false, filename := false, keylog := NULL)` for each of its 4 stream tables | The rows of that table (see "Stream tables"): `read_tcp_connections`, `read_tls_sessions`, `read_http_messages`, `read_http2` |
| `read_<view>(files, strict := false, filename := false)` for each of the 21 views of `pcap_views()` | The rows of that view (see "Packets views"): `read_tcp_packets`, `read_udp_packets`, `read_dns_packets`, ... |

`files` is the only positional argument: a `VARCHAR` path or pattern, or a
list of them. `protocol`, `strict`, `filename` and `keylog` are named
parameters.
`src/engine/table/mod.rs` describes which callback does what, how the files are
expanded, how a capture is split into partitions and why the rows keep their
order.

A replacement scan, which answers a table name that is a capture path
(`FROM 'x.pcap'`, see "Usage") with `read_pcap` of it.

A copy format, `pcap`, for `COPY ... TO` (see "Writing a capture"). The
DataFusion engine has no counterpart; the file is written by
`pcapsql_core::io::PcapWriter`.

Five settings: `pcapsql_parallel_scan`, `pcapsql_parallel_min_file_size` and
`pcapsql_index_stride`, described under "Parallel scans" above,
`pcapsql_filter_pushdown`, under "Filters", and `pcapsql_keylog`, under "TLS
decryption".

Three table functions, which list what the shared scan layer
(`pcapsql_core::scan`: its `Catalog` of tables and its `PacketsView`s) says
the extension reads:

| Function | Result |
|---|---|
| `pcap_protocols()` | One row per table, sorted by name: `name`, `description`, `field_count` (the number of columns), `kind` (`frames` for the table of packets, `protocol` for a table of one protocol's layers, `stream` for a table built from TCP streams) |
| `pcap_views()` | One row per packets view, sorted by name: `name`, `description`, `protocol` (the table the view has one row per row of), `column_count` |
| `pcap_schema(protocol)` | One row per column of the table or view, in order: `column_name`, `column_type` (the DuckDB type), `nullable`. The name is matched in any case; an unknown one is an error |

A table function that summarizes captures, and three macros over it
(`src/engine/table/time_range.rs`, `src/engine/macros.rs`):

| Function | Result |
|---|---|
| `pcap_time_range(files, strict := false)` | One row per file: `filename`, `start_time` and `end_time` (`TIMESTAMP_NS`: the smallest and largest timestamp of a frame, NULL without frames), `frames`, `duration` (seconds), `link_type` (of the capture's header), `truncated` |
| `start_time(files)`, `end_time(files)` | The smallest `start_time` and the largest `end_time` of the files |
| `relative_time(ts, files)` | Seconds from `start_time(files)` to `ts`, a `DOUBLE` |

These are the DataFusion engine's `start_time()`, `end_time()` and
`relative_time(ts)`. There the capture is the session's; DuckDB has no
capture of the session, so here it is an argument, with the forms of the
files argument of a scan. A row of `pcap_time_range` is one pass over the
records of its file through core's packet reader: every record is read, none
is parsed, and several files are read on several threads. The extension
keeps no index of a capture between statements, so nothing knows the range
before that pass. A truncated capture gives the row of its complete frames
with `truncated` set, or an error with `strict := true`. Each macro is a
scalar subquery that does not depend on the row, which DuckDB 2.0.0 plans as
one common subplan however often the macro is written with the same files:
a query that uses `relative_time` in its projection and its filter reads
the files once for the range. Differences from the DataFusion functions:
the timestamps are `TIMESTAMP_NS`, so `relative_time` keeps the nanoseconds
of a capture that has them (on microsecond timestamps the two agree to the
last bit), and a capture without frames gives NULL where DataFusion answers
the Unix epoch.

The tables are `frames`, the 27 protocol tables and the 4 stream tables: the
whole catalogue. The views are not rows of `pcap_protocols()`, which lists
tables; they have a function of their own because a view is not a table (it
has no `field_count` of a parser, and it has a `protocol`).

Columns have the names and order of the DataFusion engine's tables, with two
differences. Timestamps are `TIMESTAMP_NS`, where DataFusion has microseconds
(`tcp_connections.start_time` and `end_time` included). And every protocol
table has a `timestamp` column after `frame_number`, which DataFusion leaves
to a join with `frames`; DuckDB cannot turn that join into one pass over the
capture. The stream tables have exactly DataFusion's columns.

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

Forty scalar functions. Each is a loop over a kernel of
`pcapsql_core::format`, the same kernels the DataFusion engine calls, so the
two engines give the same answer. A NULL argument gives NULL, and so does an
argument the function cannot use (text that is not an address, a BLOB of the
wrong length): no function raises an error for its input. An address is what
the tables store, a `UINTEGER` for IPv4 and a `BLOB` of 16 or 6 bytes for
IPv6 and MAC, so `is_private_ip(src_ip)` takes a column of `read_ipv4` as it
is. A function that names a number has text for every number: the name, or
text made of the number.

| Function | Result |
|---|---|
| `ip4(VARCHAR) -> UINTEGER` | The value of a dotted-quad IPv4 address |
| `ip4_to_string(UINTEGER) -> VARCHAR` | Dotted-quad text of an IPv4 address |
| `ip6(VARCHAR) -> BLOB` | The 16 bytes of an IPv6 address |
| `ip6_to_string(BLOB) -> VARCHAR` | RFC 5952 text of a 16-byte IPv6 address |
| `mac(VARCHAR) -> BLOB` | The 6 bytes of a MAC address written `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff` or `aabbccddeeff` |
| `mac_to_string(BLOB) -> VARCHAR` | Colon-separated lowercase hex of a 6-byte MAC address |
| `is_private_ip(UINTEGER) -> BOOLEAN` | Whether an IPv4 address is in an RFC 1918 network: `10.0.0.0/8`, `172.16.0.0/12` or `192.168.0.0/16` |
| `is_loopback_ip(UINTEGER) -> BOOLEAN` | Whether an IPv4 address is in `127.0.0.0/8` |
| `is_multicast_ip(UINTEGER) -> BOOLEAN` | Whether an IPv4 address is in `224.0.0.0/4` |
| `is_multicast_ip6(BLOB) -> BOOLEAN` | Whether a 16-byte IPv6 address is in `ff00::/8` |
| `is_link_local_ip6(BLOB) -> BOOLEAN` | Whether a 16-byte IPv6 address is in `fe80::/10` |
| `mac_is_broadcast(BLOB) -> BOOLEAN` | Whether a 6-byte MAC address is `ff:ff:ff:ff:ff:ff` |
| `mac_is_multicast(BLOB) -> BOOLEAN` | Whether a 6-byte MAC address is a group address (the lowest bit of its first byte), the broadcast address included |
| `mac_is_local(BLOB) -> BOOLEAN` | Whether a 6-byte MAC address is locally administered (the second-lowest bit of its first byte) |
| `ip_in_cidr(UINTEGER, VARCHAR) -> BOOLEAN` | Whether an IPv4 address is in a network such as `'192.168.0.0/16'`; NULL if the text is not CIDR notation |
| `ip6_in_cidr(BLOB, VARCHAR) -> BOOLEAN` | Whether an IPv6 address is in a network such as `'fe80::/10'`; NULL if the text is not CIDR notation |
| `tcp_flags_str(USMALLINT) -> VARCHAR` | The set flags, lowest bit first: `SYN,ACK`. The empty string when none is set |
| `has_tcp_flag(USMALLINT, VARCHAR) -> BOOLEAN` | Whether the named flag (`'SYN'`, any case) is set; false for a name that is not a flag |
| `ethertype_name(USMALLINT) -> VARCHAR` | `IPv4`, `ARP`, ...; the value as `0x88B5` for an unknown EtherType |
| `ip_proto_name(UTINYINT) -> VARCHAR` | `TCP`, `UDP`, ... from the IANA table; `Proto <n>` for an unassigned number |
| `dscp_name(UTINYINT) -> VARCHAR` | `CS0/BE`, `AF11`, `EF`, ... for the low six bits; `DSCP<n>` for a code point without a name |
| `ecn_name(UTINYINT) -> VARCHAR` | `Not-ECT`, `ECT(1)`, `ECT(0)` or `CE` for the low two bits |
| `icmp_type_name(UTINYINT) -> VARCHAR` | `Echo Request`, `Destination Unreachable`, ...; `Type <n>` for an unassigned type |
| `icmp_code_name(UTINYINT, UTINYINT) -> VARCHAR` | The code of that type: `Port Unreachable`, `TTL Exceeded in Transit`, ...; `No Code` for code 0 of a type without codes; otherwise text of the number, `Destination Unreachable (code <n>)` or `Code <n>` |
| `icmpv6_type_name(UTINYINT) -> VARCHAR` | `Neighbor Solicitation`, `Echo Request`, ...; `Type <n>` for an unassigned type |
| `icmpv6_code_name(UTINYINT, UTINYINT) -> VARCHAR` | The code of that type: `No Route to Destination`, `Hop Limit Exceeded in Transit`, ...; `No Code` and the text of the number as for `icmp_code_name` |
| `dns_type_name(USMALLINT) -> VARCHAR` | `A`, `AAAA`, ...; `TYPE<n>` for an unassigned type |
| `dns_class_name(USMALLINT) -> VARCHAR` | `IN`, `CH`, `HS`, `NONE`, `ANY`; `CLASS<n>` for another class |
| `dns_rcode_name(USMALLINT) -> VARCHAR` | `NOERROR`, `NXDOMAIN`, ...; `RCODE<n>` for an unassigned code |
| `bgp_message_type_name(UTINYINT) -> VARCHAR` | `OPEN`, `UPDATE`, `NOTIFICATION`, `KEEPALIVE`, `ROUTE-REFRESH`; `Unknown (<n>)` otherwise |
| `bgp_origin_name(UTINYINT) -> VARCHAR` | `IGP`, `EGP`, `INCOMPLETE`; `Unknown (<n>)` otherwise |
| `ospf_packet_type_name(UTINYINT) -> VARCHAR` | `Hello`, `Database Description`, `Link State Request`, `Link State Update`, `Link State Acknowledgment`; `Unknown (<n>)` otherwise |
| `ospf_lsa_type_name(UTINYINT) -> VARCHAR` | `Router-LSA`, `Network-LSA`, `AS-External-LSA`, ...; `Unknown (<n>)` otherwise |
| `gtp_message_type_name(UTINYINT) -> VARCHAR` | `Echo Request`, `Create PDP Context Request`, `G-PDU`, ...; `Unknown (<n>)` otherwise |
| `ntp_mode_name(UTINYINT) -> VARCHAR` | `Client`, `Server`, `Symmetric Active`, `Broadcast`, ...; `Unknown (<n>)` above 7 |
| `ntp_stratum_name(UTINYINT) -> VARCHAR` | `Unspecified`, `Primary Reference`, `Secondary (stratum <n>)` for 2 to 15, `Unsynchronized` for 16, `Reserved (<n>)` above |
| `tls_record_type_name(UTINYINT) -> VARCHAR` | `ChangeCipherSpec`, `Alert`, `Handshake`, `ApplicationData`, `Heartbeat`; `Unknown (<n>)` otherwise |
| `tls_version_name(USMALLINT) -> VARCHAR` | `SSL 3.0`, `TLS 1.0` to `TLS 1.3`; `Unknown (0x<hex>)` otherwise |
| `pcap_hex(BLOB) -> VARCHAR` | Lowercase hexadecimal text |
| `pcap_unhex(VARCHAR) -> BLOB` | The bytes hexadecimal text encodes; any case, surrounding whitespace and a `0x` prefix are accepted |

The integer arguments have exactly the type of the column they are meant for.
A literal that fits is accepted (`ip_proto_name(6)`); a column of another
integer type needs a cast (`ip4_to_string(x::UINTEGER)`).

Nine macros, registered by the extension like the functions (they are not
`CREATE MACRO` statements run on a connection, and are not stored in a
database file): the three of the capture time, above, and six that format
addresses:

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
| `table/` | `PcapScan`, the table function behind every scan function: binds the table or view (a view is one fused scan of the plan, `PacketsView::scan`, where a table is one table scan; nothing else differs), expands the files argument (`FileSystem::glob`) and probes every file, maps DuckDB's projection and the pushed-down predicate to a `ScanPlan`, cuts each capture into partitions and leaves out what the predicate rules out (core's `BoundaryIndex`, `partition_target` and `PartitionQueue`, one queue over all files), has each worker claim a partition, and in each `exec` steps core's `PartitionScan` into a `ChunkWriter` until the chunk is full; reports the partition's ordinal as DuckDB's batch index |
| `replacement.rs` | The replacement scan: which table names are capture paths, and `read_pcap` as the answer |
| `pushdown.rs` | Filter pushdown: reads the filter expressions DuckDB offers a scan and turns what they say about `frame_number` and `timestamp` into core's `FramePredicate`, which the scan filters by. It accepts none, so DuckDB keeps applying each; its header says why, lists every shape that is read exactly with the reason it is exact, and what is not read |
| `settings.rs` | The four settings, and what a scan reads of DuckDB's (`threads`) |
| `types.rs` | The DuckDB logical type of each column kind of the catalogue (the table above), and the name DuckDB prints for it |
| `writer.rs` | `ChunkWriter`: stores the rows the shared scan layer produces (`pcapsql_core::scan::RowSink`) in the output chunk of one `exec` call |
| `fs.rs` | `DuckFile`: a buffered `std::io::Read` over a file opened through DuckDB's file system, for core's `ReadPacketReader`. `DuckSink`: the `std::io::Write` of a file created through it, for core's `PcapWriter` |
| `copy.rs` | The copy format `pcap` (`COPY ... TO`): which columns of a query are a packet, the options, and the rows of each batch given to core's `PcapWriter` |

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
writes sound. The crate has one other place with `unsafe` code, the private
module `valid` of `engine::scalar::plain`: it borrows the values of rows of
a flat vector as a slice when none of those rows is NULL, so that `ip_in_cidr`
and `has_tcp_flag` with a literal pattern, and the tests of an IPv4 address
(`is_private_ip`, ...), compile to a SIMD compare. The slice is
the whole chunk when it has no validity mask, and otherwise the 64 rows of
each word of the mask without a NULL; the slot of a NULL row, which DuckDB
does not promise to initialise, is in no slice and is never read: the rows
of a word that are all NULL are skipped, and the rows of a word with some
NULLs (and every row of a chunk where most words are like that, or whose
values are behind a selection) go through `duckdb-neo`'s reader. The module's
comments say what the borrow requires and how it is met, and its tests, over
buffers whose NULL slots are left uninitialised, run under Miri
(`cargo +nightly miri test -p pcapsql-duckdb --lib valid`). `make
check_unsafe` fails if `unsafe` is allowed anywhere else, or if that module
has an `unsafe` other than its three.

`DuckFile` reads 1 MiB at a time from a local file and 4 MiB from a remote
one, never more than the file holds. `DuckFile::open` starts at the first
byte, `DuckFile::open_at` at a byte offset (a partition of a capture), and
`seek` moves within an open file. An open that DuckDB does not allow
(`enable_external_access = false`, a path outside `allowed_directories`)
fails with DuckDB's error. `DuckSink` is the `std::io::Write` of a file the
extension writes; `DuckSink::create` opens it behind a buffer of the same
sizes.

`copy.rs` has the DuckDB side of `COPY ... TO (FORMAT pcap)` and no knowledge
of the file format, which is `pcapsql_core::io::PcapWriter`'s (a writer to
any `std::io::Write`, with its own tests in core). `bind` finds the columns
of a packet among those of the query and reads the options; `init` opens the
output; `flush` scans the batch DuckDB hands it and gives each row to the
writer; `finalize` closes the file. The file header is written with the
first row, which may say the link type, or by `finalize` for a result
without rows. Nothing is prepared in the `batch` callback: DuckDB 2.0.0 runs
a copy function of the C API as a sink that is not parallel
(`PhysicalCopyToFile`, `parallel = false`: the C API sets no execution
mode), so one thread hands it the chunks of the query in their order, a
batch per chunk, and there is nothing to run ahead. The state of an output
file is behind a `Mutex` because DuckDB wants it `Sync`; with
`PER_THREAD_OUTPUT` and `PARTITION_BY` several files are written at once,
each with its own state, and DuckDB never flushes two batches of one file
at the same time.

Tests, in `itest/`:

- `tests/copy_pcap.rs` copies the frames of every capture of the fuzzing
  corpus (classic pcap of both byte orders, pcapng; Ethernet, Linux cooked,
  NFLOG, netlink) and of generated ones (gzip, zstd, pcapng, nanosecond
  timestamps) and compares what `read_frames` returns for the copy with what
  it returns for the input; with the unit and the snapshot length of the
  input, the copy of each little-endian microsecond capture of the corpus is
  the input byte for byte. It also covers filtered and joined queries, an
  empty result, every timestamp type and both units, columns in another
  order, case and integer type, NULL in each column, the link type of the
  file and a row with another, the snapshot length, the errors of bind and
  of a row (and that a failed statement leaves no file and does not touch an
  existing one), a capture of 60,000 frames scanned in partitions on four
  threads and copied in three orders, `RETURN_STATS`, `PER_THREAD_OUTPUT`
  and `PARTITION_BY`.
- `tests/guard_copy.rs` panics in each callback of a copy function
  registered through `guard::copy_function` and checks that the statement
  fails with an ordinary error and the connection keeps working.

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
- `tests/stream_tables.rs` compares the four stream tables with the shared
  scan layer cell by cell (`reference_rows`, and `reference_rows_decrypted`
  with a key log): over the corpus captures, the generated TLS 1.3 + HTTP/2
  capture, and one of 5,000 connections whose tables fill several chunks, at
  1 and 4 threads; compressed and pcapng captures; that a capture stays one
  partition under the settings that split a packet table's; projection;
  filters, which DuckDB applies and `EXPLAIN` still shows; several files and
  `connection_id` per file; truncation and `strict`; and the key log: the
  rows it gives, `keylog` against `pcapsql_keylog`, views and prepared
  statements, `read_pcap` with a packet table, and files that are missing,
  not text, or not a key log, whose content no message repeats.
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
- `tests/time_range.rs` compares `pcap_time_range` with what a scan of the
  frames finds over the captures of the fuzzing corpus and generated ones
  (nanoseconds, gzip and zstd, pcapng, frames out of time order, no frames,
  a broken tail, several files on one and four threads), checks the macros
  and their errors, and counts the `PCAP_TIME_RANGE` scans in the plan of a
  query that uses `relative_time` in its projection and its filter: one.
- `tests/golden_differential.rs` runs the queries of the DataFusion golden
  corpus over the same captures and compares with the snapshots committed in
  `pcapsql-datafusion/tests/golden/`, the queries over `*_packets` views
  (a view is `read_<proto>_packets` here) and over the stream tables
  included. The captures and the
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
