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
| `src/` | Library `pcapsql_duckdb`: what the extension registers. `duckdb_neo` is used only under `src/engine/` |
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
make check              # duckdb_neo containment; fmt and clippy for itest/
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

## Load

The artifact is unsigned, so DuckDB has to be started with `-unsigned`, and
`LOAD` takes an absolute path:

```sh
duckdb -unsigned -c "LOAD '$PWD/build/release/pcapsql.duckdb_extension'; SELECT * FROM pcap_protocols();"
```

## What is registered

One table function:

| Function | Result |
|---|---|
| `pcap_protocols()` | One row per protocol table: `name`, `description`, `field_count` |

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
