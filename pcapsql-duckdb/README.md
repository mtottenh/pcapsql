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

## What is registered

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

The packet readers (`read_pcap`, `read_<protocol>`) arrive with phase P2 of
the roadmap.

## Building blocks of the packet readers

The readers are not registered yet; what they are made of is in `src/engine/`
and tested on its own.

| Module | What it does |
|---|---|
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
