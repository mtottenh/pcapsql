# pcapsql DuckDB extension: function reference

Everything the `pcapsql` extension registers in DuckDB: table functions and
their parameters, scalar functions, macros, settings, and the replacement scan.

This page describes the extension as built from this tree, for DuckDB 2.0.0.
`make check_reference_release` in `pcapsql-duckdb/` compares it with what the
built artifact registers in the DuckDB shell and fails when a function, a
parameter or a setting is missing here, or is named here and not registered
(`pcapsql-duckdb/scripts/check-reference.sh`).

How the extension behaves beyond its signatures (file handling, filter
pushdown, parallel scans, truncated captures) is described in
[`pcapsql-duckdb/README.md`](../pcapsql-duckdb/README.md).

## Summary

| Kind | Count | Names |
|---|---|---|
| Scan table functions | 29 | `read_pcap`, and `read_<table>` for each of the 28 tables |
| Listing table functions | 2 | `pcap_protocols`, `pcap_schema` |
| Scalar functions | 16 | `ip4`, `ip4_to_string`, `ip6`, `ip6_to_string`, `mac`, `mac_to_string`, `ip_in_cidr`, `ip6_in_cidr`, `tcp_flags_str`, `has_tcp_flag`, `dns_type_name`, `dns_rcode_name`, `ip_proto_name`, `ethertype_name`, `pcap_hex`, `pcap_unhex` |
| Macros | 6 | `format_ip4`, `format_ip6`, `format_mac`, `format_ip4_list`, `format_ip6_list`, `format_mac_list` |
| Settings | 4 | `pcapsql_parallel_scan`, `pcapsql_parallel_min_file_size`, `pcapsql_index_stride`, `pcapsql_filter_pushdown` |
| Replacement scan | 1 | `FROM 'capture.pcap'` |

## Scan table functions

### `read_pcap(files, protocol := 'frames', strict := false, filename := false)`

Reads one table from one or more capture files. Without `protocol` it reads
`frames`, one row per packet.

```sql
SELECT * FROM read_pcap('capture.pcap') LIMIT 10;
SELECT count(*) FROM read_pcap('capture.pcap', protocol := 'tcp');
```

### `read_<table>(files, strict := false, filename := false)`

One function per table, equal to `read_pcap` with that `protocol`. The 28
tables and their functions:

| Function | Table | Columns | What a row is |
|---|---|---|---|
| `read_frames(files)` | `frames` | 6 | A packet: frame number, timestamp, lengths, link type, raw bytes |
| `read_ethernet(files)` | `ethernet` | 8 | Ethernet II frames (Layer 2) |
| `read_linux_sll(files)` | `linux_sll` | 12 | Linux cooked capture v1 (`tcpdump -i any`) |
| `read_sll2(files)` | `sll2` | 13 | Linux cooked capture v2 |
| `read_netlink(files)` | `netlink` | 17 | Linux netlink messages (nlmon captures) |
| `read_rtnetlink(files)` | `rtnetlink` | 29 | Linux rtnetlink (route, link and address messages) |
| `read_vlan(files)` | `vlan` | 9 | IEEE 802.1Q VLAN tags |
| `read_arp(files)` | `arp` | 15 | Address Resolution Protocol |
| `read_mpls(files)` | `mpls` | 11 | Multiprotocol Label Switching |
| `read_ipv4(files)` | `ipv4` | 19 | Internet Protocol version 4 |
| `read_ipv6(files)` | `ipv6` | 22 | Internet Protocol version 6 |
| `read_tcp(files)` | `tcp` | 29 | Transmission Control Protocol |
| `read_udp(files)` | `udp` | 9 | User Datagram Protocol |
| `read_icmp(files)` | `icmp` | 13 | Internet Control Message Protocol |
| `read_icmpv6(files)` | `icmpv6` | 30 | ICMPv6 |
| `read_dns(files)` | `dns` | 27 | Domain Name System |
| `read_dhcp(files)` | `dhcp` | 23 | Dynamic Host Configuration Protocol |
| `read_ntp(files)` | `ntp` | 18 | Network Time Protocol |
| `read_http(files)` | `http` | 31 | HTTP/1.x request and status lines with headers, per packet |
| `read_tls(files)` | `tls` | 41 | Transport Layer Security records |
| `read_ssh(files)` | `ssh` | 23 | Secure Shell Protocol |
| `read_quic(files)` | `quic` | 18 | QUIC |
| `read_vxlan(files)` | `vxlan` | 7 | Virtual Extensible LAN |
| `read_gre(files)` | `gre` | 13 | Generic Routing Encapsulation |
| `read_gtp(files)` | `gtp` | 16 | GPRS Tunneling Protocol |
| `read_ipsec(files)` | `ipsec` | 10 | IP Security (ESP and AH) |
| `read_bgp(files)` | `bgp` | 35 | Border Gateway Protocol |
| `read_ospf(files)` | `ospf` | 30 | Open Shortest Path First |

The column counts are those of `pcap_protocols()`; `pcap_schema('<table>')`
lists the columns of a table with their types.

The stream tables of the pcapsql command-line tool (`tcp_connections`,
`tls_sessions`, `http_messages`, `http2`) are not available in the extension.

### Parameters

| Parameter | Type | Default | On | Meaning |
|---|---|---|---|---|
| `files` | `VARCHAR` or `VARCHAR[]` | required | all | The only positional argument: a path, a glob pattern (`*`, `?`, `[...]`, `**`), or a list of paths and patterns. Files are opened through DuckDB's file system |
| `protocol` | `VARCHAR` | `'frames'` | `read_pcap` | The table to read, in any case. An unknown name is an error |
| `strict` | `BOOLEAN` | `false` | all | `true` makes a capture that ends inside a record an error. By default the complete packets are returned and a warning is logged |
| `filename` | `BOOLEAN` | `false` | all | `true` adds a `filename VARCHAR` column after the table's columns, with the path of the file each row is from |

```sql
SELECT count(*) FROM read_tcp('captures/*.pcap');
SELECT filename, count(*) FROM read_dns(['monday/*.pcapng.gz', 'tuesday.pcap'], filename := true) GROUP BY ALL;
SELECT count(*) FROM read_frames('still-being-written.pcap', strict := true);
```

### Input files

- Legacy pcap and pcapng, plain or compressed with gzip or zstd. Format and
  compression are recognised from the first bytes of the file, not its name.
- A pattern that matches nothing, a path that does not exist and a file that
  is not a capture are errors that name it. Every file is opened when the
  statement is bound.
- The files of a list are read in list order, the matches of a pattern in
  ascending byte order of their paths. A file named twice is read twice.

### Columns

| Table | Columns |
|---|---|
| `frames` | `frame_number UBIGINT`, `timestamp TIMESTAMP_NS`, `length UINTEGER`, `original_length UINTEGER`, `link_type USMALLINT`, `raw_data BLOB` |
| every protocol table | `frame_number UBIGINT`, `timestamp TIMESTAMP_NS`, the protocol's fields, `encap_depth UTINYINT`, `tunnel_type VARCHAR`, `tunnel_id UBIGINT` |

- `frame_number` starts at 1 in each file. With several files,
  `(filename, frame_number)` identifies a frame.
- A protocol table has one row per occurrence of the protocol in a packet. A
  tunnelled packet has several; `encap_depth` is 0 for the outermost.
- Rows are returned in capture order, file after file, on any number of
  threads.

Type mapping:

| Value | DuckDB type |
|---|---|
| Booleans | `BOOLEAN` |
| Unsigned integers | `UTINYINT`, `USMALLINT`, `UINTEGER`, `UBIGINT` |
| Signed integers | `TINYINT`, `BIGINT` |
| Floating point | `DOUBLE` |
| Text | `VARCHAR` |
| Bytes, MAC addresses (6 bytes), IPv6 addresses (16 bytes) | `BLOB` |
| IPv4 addresses | `UINTEGER` |
| Packet timestamps | `TIMESTAMP_NS` |
| Lists | `USMALLINT[]`, `UINTEGER[]`, `VARCHAR[]`, `BLOB[]` |

### Pushdown

- Projection: only the columns a query uses are produced, and only the
  protocols and fields they need are parsed.
- Filters: comparisons of `frame_number` or `timestamp` with a constant
  (`=`, `<`, `<=`, `>`, `>=`), and `AND`s of them, are applied by the scan
  before a packet is parsed. Two bounds on one column narrow what is read and
  are also still applied by DuckDB. Everything else is left to DuckDB. See
  `pcapsql_filter_pushdown`.

## Listing table functions

### `pcap_protocols()`

One row per table the extension reads, sorted by name.

| Column | Type | Meaning |
|---|---|---|
| `name` | `VARCHAR` | The table's name: the `protocol` of `read_pcap` and the suffix of its `read_<table>` function |
| `description` | `VARCHAR` | What the table holds |
| `field_count` | `UINTEGER` | The number of columns |
| `kind` | `VARCHAR` | `frames` for the table of packets, `protocol` for a protocol's table |

### `pcap_schema(protocol)`

One row per column of the table `protocol` (`VARCHAR`, any case; an unknown
name is an error), in column order. The argument must be a constant.

| Column | Type | Meaning |
|---|---|---|
| `column_name` | `VARCHAR` | The column's name |
| `column_type` | `VARCHAR` | Its DuckDB type |
| `nullable` | `BOOLEAN` | Whether it can be NULL |

The `filename` column is a parameter of a call and is not listed.

```sql
SELECT name, description FROM pcap_protocols();
SELECT * FROM pcap_schema('dns');
```

## Scalar functions

A NULL argument gives NULL, and so does an argument the function cannot use
(text that is not an address, a `BLOB` of the wrong length). No function
raises an error for its input. Integer arguments have exactly the type of the
column they are meant for: a literal that fits is accepted, a column of
another integer type needs a cast.

| Function | Returns | Result |
|---|---|---|
| `ip4(address VARCHAR)` | `UINTEGER` | The value of a dotted-quad IPv4 address |
| `ip4_to_string(address UINTEGER)` | `VARCHAR` | Dotted-quad text of an IPv4 address |
| `ip6(address VARCHAR)` | `BLOB` | The 16 bytes of an IPv6 address |
| `ip6_to_string(address BLOB)` | `VARCHAR` | RFC 5952 text of a 16-byte IPv6 address |
| `mac(address VARCHAR)` | `BLOB` | The 6 bytes of a MAC address written `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff` or `aabbccddeeff` |
| `mac_to_string(address BLOB)` | `VARCHAR` | Colon-separated lowercase hex of a 6-byte MAC address |
| `ip_in_cidr(address UINTEGER, cidr VARCHAR)` | `BOOLEAN` | Whether an IPv4 address is in a network such as `'192.168.0.0/16'`. NULL if `cidr` is not CIDR notation |
| `ip6_in_cidr(address BLOB, cidr VARCHAR)` | `BOOLEAN` | Whether an IPv6 address is in a network such as `'fe80::/10'`. NULL if `cidr` is not CIDR notation |
| `tcp_flags_str(flags USMALLINT)` | `VARCHAR` | The set flags, lowest bit first, comma-separated: `SYN,ACK`. The empty string when none is set |
| `has_tcp_flag(flags USMALLINT, flag VARCHAR)` | `BOOLEAN` | Whether the named flag (`'SYN'`, any case) is set. False for a name that is not a flag |
| `dns_type_name(qtype USMALLINT)` | `VARCHAR` | `A`, `AAAA`, ...; `TYPE<n>` for an unassigned type |
| `dns_rcode_name(rcode USMALLINT)` | `VARCHAR` | `NOERROR`, `NXDOMAIN`, ...; `RCODE<n>` for an unassigned code |
| `ip_proto_name(protocol UTINYINT)` | `VARCHAR` | `TCP`, `UDP`, ... from the IANA table; `Proto <n>` for an unassigned number |
| `ethertype_name(ethertype USMALLINT)` | `VARCHAR` | `IPv4`, `ARP`, ...; the value as `0x88B5` for an unknown EtherType |
| `pcap_hex(bytes BLOB)` | `VARCHAR` | Lowercase hexadecimal text |
| `pcap_unhex(hex VARCHAR)` | `BLOB` | The bytes hexadecimal text encodes. Any case; surrounding whitespace and a `0x` prefix are accepted |

```sql
SELECT ip4_to_string(src_ip), tcp_flags_str(flags)
FROM read_tcp('capture.pcap') JOIN read_ipv4('capture.pcap') USING (frame_number)
WHERE ip_in_cidr(src_ip, '10.0.0.0/8') AND has_tcp_flag(flags, 'SYN');
```

## Macros

Registered by the extension, not stored in a database file.

| Macro | Expands to |
|---|---|
| `format_ip4(ip)` | `ip4_to_string(ip)` |
| `format_ip6(ip)` | `ip6_to_string(ip)` |
| `format_mac(mac)` | `mac_to_string(mac)` |
| `format_ip4_list(ips)` | `list_transform(ips, lambda x: ip4_to_string(x))` |
| `format_ip6_list(ips)` | `list_transform(ips, lambda x: ip6_to_string(x))` |
| `format_mac_list(macs)` | `list_transform(macs, lambda x: mac_to_string(x))` |

## Settings

All are global.

| Setting | Type | Default | Meaning |
|---|---|---|---|
| `pcapsql_parallel_scan` | `BOOLEAN` | `true` | Scan a large local uncompressed capture in partitions, on several threads. `false` reads every capture on one thread |
| `pcapsql_parallel_min_file_size` | `UBIGINT` | `4194304` | The size in bytes from which a capture is scanned in partitions |
| `pcapsql_index_stride` | `UBIGINT` | `65536` | Frames between two places a capture can be split at. A capture of no more frames than this is not split |
| `pcapsql_filter_pushdown` | `BOOLEAN` | `true` | Apply filters on `frame_number` and `timestamp` in the scan. `false` leaves every filter to DuckDB |

```sql
SET pcapsql_parallel_scan = false;
```

## Replacement scan

A table name that ends in `.pcap`, `.pcapng` or `.cap`, optionally followed by
`.gz` or `.zst`, in any case, is read as `read_pcap` of that name: the
`frames` table. A pattern with such an ending reads every file it matches.

```sql
SELECT count(*), min(timestamp), max(timestamp) FROM 'capture.pcap';
SELECT * FROM 'captures/*.pcapng.gz' WHERE length > 1400;
```

A table, view or common table expression of that name takes precedence. Any
other table, `strict` and `filename` need the function.

## DuckDB facilities the extension uses

- File system: every open goes through DuckDB's, so `enable_external_access`
  and `allowed_directories` apply.
- Logging: a truncated capture is reported as a warning in DuckDB's log. With
  `CALL enable_logging(level = 'debug')`, each scan writes records of type
  `pcapsql` to `duckdb_logs` that describe what it read and how.
