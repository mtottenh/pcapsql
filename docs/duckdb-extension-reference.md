# pcapsql DuckDB extension: function reference

Everything the `pcapsql` extension registers in DuckDB: table functions and
their parameters, scalar functions, macros, settings, and the replacement scan.

This page describes the extension as built from this tree, for DuckDB 2.0.0.
`make check_reference_release` in `pcapsql-duckdb/` compares it with what the
built artifact registers in the DuckDB shell and fails when a function, a
parameter or a setting is missing here, or is named here and not registered
(`pcapsql-duckdb/scripts/check-reference.sh`).

How the extension behaves beyond its signatures (file handling, filter
pushdown, parallel scans, truncated captures, stream tables and TLS key logs)
is described in
[`pcapsql-duckdb/README.md`](../pcapsql-duckdb/README.md).

## Summary

| Kind | Count | Names |
|---|---|---|
| Scan table functions | 54 | `read_pcap`, `read_<table>` for each of the 32 tables (28 of packets, 4 of TCP streams), and `read_<view>` for each of the 21 `*_packets` views |
| Listing table functions | 3 | `pcap_protocols`, `pcap_views`, `pcap_schema` |
| Scalar functions | 16 | `ip4`, `ip4_to_string`, `ip6`, `ip6_to_string`, `mac`, `mac_to_string`, `ip_in_cidr`, `ip6_in_cidr`, `tcp_flags_str`, `has_tcp_flag`, `dns_type_name`, `dns_rcode_name`, `ip_proto_name`, `ethertype_name`, `pcap_hex`, `pcap_unhex` |
| Macros | 6 | `format_ip4`, `format_ip6`, `format_mac`, `format_ip4_list`, `format_ip6_list`, `format_mac_list` |
| Settings | 5 | `pcapsql_parallel_scan`, `pcapsql_parallel_min_file_size`, `pcapsql_index_stride`, `pcapsql_filter_pushdown`, `pcapsql_keylog` |
| Replacement scan | 1 | `FROM 'capture.pcap'` |

## Scan table functions

### `read_pcap(files, protocol := 'frames', strict := false, filename := false, keylog := NULL)`

Reads one table or one `*_packets` view from one or more capture files.
Without `protocol` it reads `frames`, one row per packet.

```sql
SELECT * FROM read_pcap('capture.pcap') LIMIT 10;
SELECT count(*) FROM read_pcap('capture.pcap', protocol := 'tcp');
SELECT * FROM read_pcap('capture.pcap', protocol := 'http2', keylog := 'keys.log');
```

### `read_<table>(files, strict := false, filename := false)`

One function per table, equal to `read_pcap` with that `protocol`. The 28
tables of packets and their functions (the four stream tables follow, under
"Stream tables"):

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

### `read_<view>(files, strict := false, filename := false)`

One function per `*_packets` view, equal to `read_pcap` with that view's name
as `protocol`. A view is a protocol's rows joined, in one pass over the
capture, with the frame's timestamp and the lower layers of the same
encapsulation level; its rows are those of the join of the corresponding
`read_<table>` functions on `frame_number`. Parameters, input files, ordering
and pushdown are those of every scan function. The 21 views:

| Function | View | Anchor table | Columns | What a row is |
|---|---|---|---|---|
| `read_arp_packets(files)` | `arp_packets` | `arp` | 15 | ARP requests and replies with Ethernet context |
| `read_bgp_packets(files)` | `bgp_packets` | `bgp` | 40 | BGP messages with TCP/IP context |
| `read_dhcp_packets(files)` | `dhcp_packets` | `dhcp` | 28 | DHCP messages with UDP/IP context |
| `read_dns_packets(files)` | `dns_packets` | `dns` | 33 | DNS queries and responses with transport detection (UDP/TCP/DoT/DoH) |
| `read_gre_packets(files)` | `gre_packets` | `gre` | 16 | GRE tunneled packets with IP context |
| `read_gtp_packets(files)` | `gtp_packets` | `gtp` | 21 | GTP tunneled packets with UDP/IP context |
| `read_http_packets(files)` | `http_packets` | `http` | 21 | HTTP requests and responses with TCP/IP context |
| `read_icmp_packets(files)` | `icmp_packets` | `icmp` | 16 | ICMP messages with IPv4 context |
| `read_icmpv6_packets(files)` | `icmpv6_packets` | `icmpv6` | 31 | ICMPv6 messages with IPv6 context (including NDP and MLD) |
| `read_ipsec_packets(files)` | `ipsec_packets` | `ipsec` | 13 | IPsec (ESP/AH) packets with IP context |
| `read_mld_packets(files)` | `mld_packets` | `icmpv6` | 13 | MLD messages (Multicast Listener Discovery queries and reports) |
| `read_mpls_packets(files)` | `mpls_packets` | `mpls` | 12 | MPLS labeled packets with Ethernet context |
| `read_ndp_packets(files)` | `ndp_packets` | `icmpv6` | 24 | NDP messages (Router/Neighbor Solicitation/Advertisement, Redirect) |
| `read_ntp_packets(files)` | `ntp_packets` | `ntp` | 23 | NTP messages with UDP/IP context |
| `read_ospf_packets(files)` | `ospf_packets` | `ospf` | 31 | OSPF routing messages with IPv4 context |
| `read_quic_packets(files)` | `quic_packets` | `quic` | 23 | QUIC packets with UDP/IP context |
| `read_ssh_packets(files)` | `ssh_packets` | `ssh` | 26 | SSH packets with TCP/IP context |
| `read_tcp_packets(files)` | `tcp_packets` | `tcp` | 20 | TCP packets with IP addresses and frame metadata |
| `read_tls_packets(files)` | `tls_packets` | `tls` | 17 | TLS records with TCP/IP context |
| `read_udp_packets(files)` | `udp_packets` | `udp` | 15 | UDP packets with IP addresses and frame metadata |
| `read_vxlan_packets(files)` | `vxlan_packets` | `vxlan` | 12 | VXLAN encapsulated frames with UDP/IP context |

Every table a view joins is parsed even when the query selects none of its
columns, because its rows decide which joined rows exist. The command-line
tool's views `packets`, `tunneled_packets`, `ip4_in_ip6` and `ip6_in_ip6`
are not available: they join layers of different encapsulation levels.

### Stream tables: `read_<table>(files, strict := false, filename := false, keylog := NULL)`

Four tables are not rows of a packet. They are built from the TCP streams of
a capture, which the scan reassembles while it reads, and hold what those
streams carried when the capture ends:

| Function | Table | Columns | What a row is |
|---|---|---|---|
| `read_tcp_connections(files)` | `tcp_connections` | 20 | A TCP connection: endpoints (the client sent the SYN), state, first and last frame, start and end time, packets and payload bytes each way |
| `read_tls_sessions(files)` | `tls_sessions` | 12 | A connection that carried a TLS handshake: version, cipher suite, SNI, ALPN, and whether a key log decrypted it |
| `read_http_messages(files)` | `http_messages` | 17 | An HTTP/1.x request or response of a reassembled stream, however many packets it spans |
| `read_http2(files)` | `http2` | 34 | An HTTP/2 frame of a decrypted TLS stream, with the request and response headers of `HEADERS` frames. Empty without a key log |

```sql
SELECT client_ip, server_ip, server_port, state, bytes_to_server, bytes_to_client
FROM read_tcp_connections('capture.pcap');
SELECT sni, version, is_decrypted FROM read_tls_sessions('capture.pcap', keylog := 'keys.log');
SELECT h.method, h.path, h.status, c.server_ip
FROM read_http2('capture.pcap', keylog := 'keys.log') h
JOIN read_tcp_connections('capture.pcap') c USING (connection_id);
```

They are read with the same functions and parameters as the other tables,
and differ in these ways:

- **Columns.** `frame_number` (the first frame of a connection, the frame of
  the ClientHello, the frame a message or an HTTP/2 frame was complete at),
  `connection_id`, the table's own columns, then `encap_depth` (always 0),
  `tunnel_type` and `tunnel_id` (always NULL): reassembly follows the
  innermost TCP flow. There is no `timestamp` column; `tcp_connections` has
  `start_time` and `end_time` (`TIMESTAMP_NS`).
- **`connection_id`** numbers the connections of one capture from 1, in the
  order they are first seen, and is the same connection in all four tables:
  they join on it. It starts again in each file: over several files a
  connection is its `filename` and `connection_id` (`filename := true`). A
  connection whose packets are in two files is two connections.
- **`frame_number`** joins a stream table to a packet table of the same
  capture, as between packet tables.
- **One thread per file.** A capture is read in order from its first packet,
  as one partition, whatever `pcapsql_parallel_scan` and its size are.
  Several files are read by several threads.
- **Rows come when the capture has been read.** A `LIMIT` does not shorten
  the read, and a query is cancelled (Ctrl-C) only once the file that is
  being read has been read.
- **Filters** are all applied by DuckDB, to the rows of a full read. None is
  taken over by the scan: every packet goes into reassembly.
- **`strict`**, compressed captures, patterns and lists, `filename` and
  projection work as for every scan function. A truncated capture is always
  found, since it is always read to its end.

### TLS decryption: `keylog`

A TLS key log is the file a TLS client or server writes when the environment
variable `SSLKEYLOGFILE` is set (NSS key log format: `CLIENT_RANDOM ...` lines
for TLS 1.2, `CLIENT_HANDSHAKE_TRAFFIC_SECRET ...` and its siblings for
TLS 1.3). With one, a scan of a stream table decrypts the TLS sessions the
key log has secrets of: `tls_sessions.is_decrypted` is true for them, and
`http2` has the HTTP/2 frames they carried.

- The key log is the `keylog` parameter of the call. When the call does not
  give it, or gives NULL, it is the setting `pcapsql_keylog`; when that is
  empty there is none. The parameter wins over the setting, and
  `keylog := ''` reads without a key log whatever the setting is.
- The setting is how a scan that cannot be given the parameter gets a key
  log: a view over `read_http2(...)`, a prepared statement.
- The file is opened through DuckDB's file system when the statement is
  bound, like a capture. A file that cannot be opened or is not a key log
  fails the statement; the message names the file and the line and repeats
  no label, random or secret of it. A key log without entries is accepted
  and decrypts nothing.
- One key log serves every file of a call. A session it has no secrets of is
  read as without a key log.
- Only the four stream functions and `read_pcap` have the parameter.
  `read_pcap` uses it when `protocol` is a stream table; for any other table
  or view it accepts the parameter and ignores it (the file is not opened),
  as every scan of a packet table ignores the setting. A `read_<table>`
  function of a packet table refuses it: it has no such parameter.
- The per-packet `tls` table is not affected: it is the handshake as it is on
  the wire. The replacement scan reads `frames` and is not affected either.
- What is tested end to end is TLS 1.3 with `TLS_AES_128_GCM_SHA256`
  carrying HTTP/2. `pcapsql-core` also derives keys for the other TLS 1.3
  suites and for TLS 1.2 (`CLIENT_RANDOM` lines), but no test decrypts such a
  capture, and `is_decrypted` is set from the TLS 1.3 `Finished` message: do
  not rely on TLS 1.2 decryption. Decrypted application data is parsed as
  HTTP/2; HTTP/1.x inside TLS is not parsed.

```sql
SET pcapsql_keylog = '/home/me/keys.log';
CREATE VIEW http2 AS SELECT * FROM read_http2('capture.pcapng');
SELECT method, authority, path FROM http2 WHERE method IS NOT NULL;
```

### Parameters

| Parameter | Type | Default | On | Meaning |
|---|---|---|---|---|
| `files` | `VARCHAR` or `VARCHAR[]` | required | all | The only positional argument: a path, a glob pattern (`*`, `?`, `[...]`, `**`), or a list of paths and patterns. Files are opened through DuckDB's file system |
| `protocol` | `VARCHAR` | `'frames'` | `read_pcap` | The table to read, in any case. An unknown name is an error |
| `strict` | `BOOLEAN` | `false` | all | `true` makes a capture that ends inside a record an error. By default the complete packets are returned and a warning is logged |
| `filename` | `BOOLEAN` | `false` | all | `true` adds a `filename VARCHAR` column after the table's columns, with the path of the file each row is from |
| `keylog` | `VARCHAR` | `NULL` | `read_pcap`, `read_tcp_connections`, `read_tls_sessions`, `read_http_messages`, `read_http2` | The path of a TLS key log to decrypt with. NULL or not given: the setting `pcapsql_keylog`. Empty: none. See "TLS decryption" |

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
| every stream table | `frame_number UBIGINT`, `connection_id UBIGINT`, the table's columns, `encap_depth UTINYINT`, `tunnel_type VARCHAR`, `tunnel_id UBIGINT` |

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
  `pcapsql_filter_pushdown`. A scan of a stream table takes no filter over.

## Listing table functions

### `pcap_protocols()`

One row per table the extension reads, sorted by name.

| Column | Type | Meaning |
|---|---|---|
| `name` | `VARCHAR` | The table's name: the `protocol` of `read_pcap` and the suffix of its `read_<table>` function |
| `description` | `VARCHAR` | What the table holds |
| `field_count` | `UINTEGER` | The number of columns |
| `kind` | `VARCHAR` | `frames` for the table of packets, `protocol` for a protocol's table, `stream` for a table built from TCP streams |

### `pcap_views()`

One row per `*_packets` view, sorted by name.

| Column | Type | Meaning |
|---|---|---|
| `name` | `VARCHAR` | The view's name: a `protocol` of `read_pcap` and the suffix of its `read_<view>` function |
| `description` | `VARCHAR` | What the view holds |
| `protocol` | `VARCHAR` | The table whose rows the view is built on |
| `column_count` | `UINTEGER` | The number of columns |

### `pcap_schema(protocol)`

One row per column of the table or view `protocol` (`VARCHAR`, any case; an unknown
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
| `pcapsql_keylog` | `VARCHAR` | empty | The path of the TLS key log a scan of a stream table decrypts with when its `keylog` parameter is not given. Empty: none. The file is opened when a scan is bound, not when the setting is set. NULL is refused |

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
other table, `strict`, `filename` and `keylog` need the function.

## DuckDB facilities the extension uses

- File system: every open goes through DuckDB's, so `enable_external_access`
  and `allowed_directories` apply.
- Logging: a truncated capture is reported as a warning in DuckDB's log. With
  `CALL enable_logging(level = 'debug')`, each scan writes records of type
  `pcapsql` to `duckdb_logs` that describe what it read and how.
