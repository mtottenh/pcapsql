# pcapsql DuckDB extension: function reference

Everything the `pcapsql` extension registers in DuckDB: table functions and
their parameters, scalar functions, an aggregate function, macros, settings,
the replacement scan, and the copy format.

This page describes the extension as built from this tree, for DuckDB 2.0.0.
`make check_reference_release` in `pcapsql-duckdb/` compares it with what the
built artifact registers in the DuckDB shell and fails when a function, a
parameter or a setting is missing here, or is named here and not registered
(`pcapsql-duckdb/scripts/check-reference.sh`). DuckDB lists no copy
functions, so the check asks the copy format itself: the format and each of
its options must be named here.

How the extension behaves beyond its signatures (file handling, filter
pushdown, parallel scans, truncated captures, stream tables and TLS key logs)
is described in
[`pcapsql-duckdb/README.md`](../pcapsql-duckdb/README.md).

## Summary

| Kind | Count | Names |
|---|---|---|
| Scan table functions | 54 | `read_pcap`, `read_<table>` for each of the 32 tables (28 of packets, 4 of TCP streams), and `read_<view>` for each of the 21 `*_packets` views |
| Listing table functions | 3 | `pcap_protocols`, `pcap_views`, `pcap_schema` |
| Capture summary table function | 1 | `pcap_time_range` |
| Scalar functions | 48 | `ip4`, `ip4_to_string`, `ip6`, `ip6_to_string`, `mac`, `mac_to_string`, `is_private_ip`, `is_loopback_ip`, `is_multicast_ip`, `is_multicast_ip6`, `is_link_local_ip6`, `mac_is_broadcast`, `mac_is_multicast`, `mac_is_local`, `ip_in_cidr`, `ip6_in_cidr`, `tcp_flags_str`, `has_tcp_flag`, `ethertype_name`, `ip_proto_name`, `dscp_name`, `ecn_name`, `icmp_type_name`, `icmp_code_name`, `icmpv6_type_name`, `icmpv6_code_name`, `dns_type_name`, `dns_class_name`, `dns_rcode_name`, `bgp_message_type_name`, `bgp_origin_name`, `ospf_packet_type_name`, `ospf_lsa_type_name`, `gtp_message_type_name`, `ntp_mode_name`, `ntp_stratum_name`, `tls_record_type_name`, `tls_version_name`, `pcap_hex`, `pcap_unhex`, `hdr_count`, `hdr_min`, `hdr_max`, `hdr_mean`, `hdr_stdev`, `hdr_percentile`, `hdr_buckets`, `hdr_ascii` |
| Aggregate functions | 1 | `hdr_histogram` |
| Macros | 9 | `format_ip4`, `format_ip6`, `format_mac`, `format_ip4_list`, `format_ip6_list`, `format_mac_list`, `start_time`, `end_time`, `relative_time` |
| Settings | 5 | `pcapsql_parallel_scan`, `pcapsql_parallel_min_file_size`, `pcapsql_index_stride`, `pcapsql_filter_pushdown`, `pcapsql_keylog` |
| Replacement scan | 1 | `FROM 'capture.pcap'` |
| Copy format | 1 | `FORMAT pcap`, for `COPY ... TO`, with the options `LINKTYPE`, `SNAPLEN` and `PRECISION` |

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
- The per-packet `tls` table is not affected: it is the records as they are
  on the wire. A record whose content is encrypted (application data, and
  before TLS 1.3 everything a side sends after its ChangeCipherSpec) is a
  row with the record's type and version and no handshake or alert column;
  application data has `has_app_data` and `app_data_length`. A segment that
  continues a record begun in an earlier one is not a row. The replacement
  scan reads `frames` and is not affected either.
- What is decrypted: TLS 1.3 (the four `*_TRAFFIC_SECRET` lines of a
  session) and TLS 1.2 (its `CLIENT_RANDOM` line), with the cipher suites
  that use AES-128-GCM, AES-256-GCM or ChaCha20-Poly1305: the three
  TLS 1.3 suites `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384` and
  `TLS_CHACHA20_POLY1305_SHA256`, and in TLS 1.2 the `ECDHE_RSA`,
  `ECDHE_ECDSA` and `DHE_RSA` suites with those three ciphers and the `RSA`
  suites with the two AES-GCM ones. Each is tested on generated captures
  (`pcapsql-core/tests/tls_fixtures.rs`); the extension's own tests read
  three of them (`pcapsql-testgen/fixtures/`: HTTP/2 over TLS 1.3, HTTP/2
  and HTTP/1.1 over TLS 1.2 with `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`).
- `is_decrypted` is true when at least one record of the session was
  decrypted and authenticated with the key log's secrets.
- What a decrypted session carries is parsed as HTTP/2 (rows of `read_http2`)
  or as HTTP/1.x (rows of `read_http_messages`, with those of HTTP in the
  clear), by the protocol the server selected with ALPN; without that, by
  whether the client starts with the HTTP/2 preface. Another protocol is
  decrypted and not parsed.
- What is not decrypted: a session with any other cipher suite (the CBC
  suites, AES-CCM), which is listed with `is_decrypted = false` and gives no
  rows, like one the key log has no secrets of; a TLS 1.3 session whose key
  log lacks the two handshake secrets; TLS 1.3 early data (0-RTT), and
  what a side sends after a TLS 1.3 `KeyUpdate`; a session whose handshake
  is not in the capture. A response to `HEAD` (which announces a
  `Content-Length` it does not send) is not a row of `http_messages`, in
  the clear or inside TLS.
- The secrets a pcapng capture carries itself (Decryption Secrets Blocks)
  are not read: the key log is a file of its own.

```sql
SET pcapsql_keylog = '/home/me/keys.log';
CREATE VIEW http2 AS SELECT * FROM read_http2('capture.pcapng');
SELECT method, authority, path FROM http2 WHERE method IS NOT NULL;
```

### Parameters

| Parameter | Type | Default | On | Meaning |
|---|---|---|---|---|
| `files` | `VARCHAR` or `VARCHAR[]` | required | all, and `pcap_time_range` | The only positional argument: a path, a glob pattern (`*`, `?`, `[...]`, `**`), or a list of paths and patterns. Files are opened through DuckDB's file system |
| `protocol` | `VARCHAR` | `'frames'` | `read_pcap` | The table to read, in any case. An unknown name is an error |
| `strict` | `BOOLEAN` | `false` | all, and `pcap_time_range` | `true` makes a capture that ends inside a record an error. By default the complete packets are returned and a warning is logged |
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

## Capture time

### `pcap_time_range(files, strict := false)`

One row per capture file: when it begins and ends, and how many frames it
has. `files` is the argument of the scan functions (a path, a pattern, or a
list of them; see "Parameters" and "Input files").

| Column | Type | Meaning |
|---|---|---|
| `filename` | `VARCHAR` | The path of the file, as `files` expanded to it |
| `start_time` | `TIMESTAMP_NS` | The smallest timestamp of a frame. NULL for a capture without frames |
| `end_time` | `TIMESTAMP_NS` | The largest timestamp of a frame. NULL for a capture without frames |
| `frames` | `UBIGINT` | The number of complete frames |
| `duration` | `DOUBLE` | Seconds from `start_time` to `end_time`. NULL for a capture without frames |
| `link_type` | `UINTEGER` | The link-layer type the capture's header declares; for pcapng, that of its first interface |
| `truncated` | `BOOLEAN` | Whether the capture ends inside a record |

- The timestamps have the type of `read_frames.timestamp`. They are the
  smallest and the largest of all frames, which are not the first and the
  last frame's when the frames are not in time order.
- A row costs one pass over the records of its file: every record is read
  (a compressed capture is decompressed), none is parsed. The extension keeps
  no index of a capture between statements, so no call is answered without
  that pass. Several files are read on several threads, and the rows come
  back in no particular order.
- A capture that ends inside a record gives the row of its complete frames,
  with `truncated` true; nothing is logged. With `strict := true` the
  statement fails instead, as a scan does. The pass reads to the end of the
  file, so it always finds a broken tail.
- Every file is opened and probed when the statement is bound, as for a scan.

```sql
SELECT * FROM pcap_time_range('capture.pcap');
SELECT min(start_time), max(end_time), sum(frames) FROM pcap_time_range('logs/*.pcap.gz');
```

### `start_time(files)`, `end_time(files)`, `relative_time(ts, files)`

The command-line tool's `start_time()`, `end_time()` and `relative_time(ts)`,
with the capture as an argument: that tool has one capture per session,
DuckDB has none. They are macros over `pcap_time_range` (see "Macros").

| Macro | Returns | Result |
|---|---|---|
| `start_time(files)` | `TIMESTAMP_NS` | The smallest timestamp of a frame of the files |
| `end_time(files)` | `TIMESTAMP_NS` | The largest timestamp of a frame of the files |
| `relative_time(ts, files)` | `DOUBLE` | Seconds from `start_time(files)` to `ts`; negative for a `ts` before it |

- With several files the start is the smallest of theirs and the end the
  largest. Without a frame in the files all three are NULL (the command-line
  tool answers the Unix epoch there). A NULL `ts` gives NULL.
- `ts` is a `TIMESTAMP_NS`, as the tables have it, or any other timestamp
  type `epoch_ns` takes (`TIMESTAMP`, `TIMESTAMPTZ`, ...).
- `relative_time` is the difference in nanoseconds divided by 1e9. The
  command-line tool divides a difference in microseconds by 1e6: the two are
  equal to the last bit on a capture with microsecond timestamps whose
  difference is below 2^53 ns (104 days), and this one keeps the nanoseconds
  of a capture that has them.
- `files` must be a constant (a literal, a prepared statement's parameter,
  `getvariable(...)`): a column is refused, as for a scan.
- The macro is a scalar subquery that does not depend on the row. DuckDB
  2.0.0 runs it once per statement, also when it is written several times
  with the same files, in the projection and in the filter (`EXPLAIN` shows
  one `PCAP_TIME_RANGE` under a common subplan), so the files are read once
  for the range, whatever the number of rows.
- A filter on `relative_time` is applied by DuckDB to the rows of the scan;
  it is not a filter on `timestamp` the scan takes over ("Pushdown").
- DuckDB 2.0.0 does not let another item of the same `SELECT` list refer to
  the alias of an expression that has a subquery, which these macros have:
  `SELECT relative_time(timestamp, 'x.pcap') AS rel, rel * 1000` is refused.
  Use a subquery or a common table expression.

```sql
SELECT frame_number, relative_time(timestamp, 'capture.pcap') AS seconds
FROM read_tcp('capture.pcap')
WHERE relative_time(timestamp, 'capture.pcap') < 10;
```

## Scalar functions

A NULL argument gives NULL, and so does an argument the function cannot use
(text that is not an address, a `BLOB` of the wrong length). No function
raises an error for its input. Integer arguments have exactly the type of the
column they are meant for: a literal that fits is accepted, a column of
another integer type needs a cast.

An address is what the tables store: an IPv4 address is a `UINTEGER`, and an
IPv6 or MAC address a `BLOB` of 16 or 6 bytes, so `is_private_ip(src_ip)`
takes a column of `read_ipv4` as it is, and `mac_is_broadcast(dst_mac)` one
of `read_ethernet`. Every function of an IPv6 or MAC address returns NULL for
a `BLOB` of another length, the tests of an address (`is_multicast_ip6`,
`mac_is_local`, ...) included.

A function that names a number has text for every number: the name, or text
made of the number, as the table says. The name columns of the tables
(`type_name` of `read_icmp`, `message_type_name` of `read_bgp`, ...) hold
the same text.

The eight functions that read a histogram (`hdr_count`, `hdr_percentile`,
...) are scalar functions too, and follow the first rule: NULL for NULL and
for a `BLOB` that is not a histogram. They are described under "Histograms".

| Function | Returns | Result |
|---|---|---|
| `ip4(address VARCHAR)` | `UINTEGER` | The value of a dotted-quad IPv4 address |
| `ip4_to_string(address UINTEGER)` | `VARCHAR` | Dotted-quad text of an IPv4 address |
| `ip6(address VARCHAR)` | `BLOB` | The 16 bytes of an IPv6 address |
| `ip6_to_string(address BLOB)` | `VARCHAR` | RFC 5952 text of a 16-byte IPv6 address |
| `mac(address VARCHAR)` | `BLOB` | The 6 bytes of a MAC address written `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff` or `aabbccddeeff` |
| `mac_to_string(address BLOB)` | `VARCHAR` | Colon-separated lowercase hex of a 6-byte MAC address |
| `is_private_ip(address UINTEGER)` | `BOOLEAN` | Whether an IPv4 address is in an RFC 1918 network: `10.0.0.0/8`, `172.16.0.0/12` or `192.168.0.0/16` |
| `is_loopback_ip(address UINTEGER)` | `BOOLEAN` | Whether an IPv4 address is in `127.0.0.0/8` |
| `is_multicast_ip(address UINTEGER)` | `BOOLEAN` | Whether an IPv4 address is in `224.0.0.0/4` |
| `is_multicast_ip6(address BLOB)` | `BOOLEAN` | Whether a 16-byte IPv6 address is in `ff00::/8` |
| `is_link_local_ip6(address BLOB)` | `BOOLEAN` | Whether a 16-byte IPv6 address is in `fe80::/10` |
| `mac_is_broadcast(address BLOB)` | `BOOLEAN` | Whether a 6-byte MAC address is `ff:ff:ff:ff:ff:ff` |
| `mac_is_multicast(address BLOB)` | `BOOLEAN` | Whether a 6-byte MAC address is a group address (the lowest bit of its first byte), the broadcast address included |
| `mac_is_local(address BLOB)` | `BOOLEAN` | Whether a 6-byte MAC address is locally administered (the second-lowest bit of its first byte) |
| `ip_in_cidr(address UINTEGER, cidr VARCHAR)` | `BOOLEAN` | Whether an IPv4 address is in a network such as `'192.168.0.0/16'`. NULL if `cidr` is not CIDR notation |
| `ip6_in_cidr(address BLOB, cidr VARCHAR)` | `BOOLEAN` | Whether an IPv6 address is in a network such as `'fe80::/10'`. NULL if `cidr` is not CIDR notation |
| `tcp_flags_str(flags USMALLINT)` | `VARCHAR` | The set flags, lowest bit first, comma-separated: `SYN,ACK`. The empty string when none is set |
| `has_tcp_flag(flags USMALLINT, flag VARCHAR)` | `BOOLEAN` | Whether the named flag (`'SYN'`, any case) is set. False for a name that is not a flag |
| `ethertype_name(ethertype USMALLINT)` | `VARCHAR` | `IPv4`, `ARP`, ...; the value as `0x88B5` for an unknown EtherType |
| `ip_proto_name(protocol UTINYINT)` | `VARCHAR` | `TCP`, `UDP`, ... from the IANA table; `Proto <n>` for an unassigned number |
| `dscp_name(dscp UTINYINT)` | `VARCHAR` | `CS0/BE`, `AF11`, `EF`, ... for the low six bits; `DSCP<n>` for a code point without a name |
| `ecn_name(ecn UTINYINT)` | `VARCHAR` | `Not-ECT`, `ECT(1)`, `ECT(0)` or `CE` for the low two bits |
| `icmp_type_name(type UTINYINT)` | `VARCHAR` | `Echo Request`, `Destination Unreachable`, ...; `Type <n>` for an unassigned type |
| `icmp_code_name(type UTINYINT, code UTINYINT)` | `VARCHAR` | The code of that type: `Port Unreachable`, `TTL Exceeded in Transit`, ...; `No Code` for code 0 of a type without codes; otherwise text of the number, `Destination Unreachable (code <n>)` or `Code <n>` |
| `icmpv6_type_name(type UTINYINT)` | `VARCHAR` | `Neighbor Solicitation`, `Echo Request`, ...; `Type <n>` for an unassigned type |
| `icmpv6_code_name(type UTINYINT, code UTINYINT)` | `VARCHAR` | The code of that type: `No Route to Destination`, `Hop Limit Exceeded in Transit`, ...; `No Code` and the text of the number as for `icmp_code_name` |
| `dns_type_name(qtype USMALLINT)` | `VARCHAR` | `A`, `AAAA`, ...; `TYPE<n>` for an unassigned type |
| `dns_class_name(class USMALLINT)` | `VARCHAR` | `IN`, `CH`, `HS`, `NONE`, `ANY`; `CLASS<n>` for another class |
| `dns_rcode_name(rcode USMALLINT)` | `VARCHAR` | `NOERROR`, `NXDOMAIN`, ...; `RCODE<n>` for an unassigned code |
| `bgp_message_type_name(message_type UTINYINT)` | `VARCHAR` | `OPEN`, `UPDATE`, `NOTIFICATION`, `KEEPALIVE`, `ROUTE-REFRESH`; `Unknown (<n>)` otherwise |
| `bgp_origin_name(origin UTINYINT)` | `VARCHAR` | `IGP`, `EGP`, `INCOMPLETE`; `Unknown (<n>)` otherwise |
| `ospf_packet_type_name(packet_type UTINYINT)` | `VARCHAR` | `Hello`, `Database Description`, `Link State Request`, `Link State Update`, `Link State Acknowledgment`; `Unknown (<n>)` otherwise |
| `ospf_lsa_type_name(lsa_type UTINYINT)` | `VARCHAR` | `Router-LSA`, `Network-LSA`, `AS-External-LSA`, ...; `Unknown (<n>)` otherwise |
| `gtp_message_type_name(message_type UTINYINT)` | `VARCHAR` | `Echo Request`, `Create PDP Context Request`, `G-PDU`, ...; `Unknown (<n>)` otherwise |
| `ntp_mode_name(mode UTINYINT)` | `VARCHAR` | `Client`, `Server`, `Symmetric Active`, `Broadcast`, ...; `Unknown (<n>)` above 7 |
| `ntp_stratum_name(stratum UTINYINT)` | `VARCHAR` | `Unspecified`, `Primary Reference`, `Secondary (stratum <n>)` for 2 to 15, `Unsynchronized` for 16, `Reserved (<n>)` above |
| `tls_record_type_name(record_type UTINYINT)` | `VARCHAR` | `ChangeCipherSpec`, `Alert`, `Handshake`, `ApplicationData`, `Heartbeat`; `Unknown (<n>)` otherwise |
| `tls_version_name(version USMALLINT)` | `VARCHAR` | `SSL 3.0`, `TLS 1.0` to `TLS 1.3`; `Unknown (0x<hex>)` otherwise |
| `pcap_hex(bytes BLOB)` | `VARCHAR` | Lowercase hexadecimal text |
| `pcap_unhex(hex VARCHAR)` | `BLOB` | The bytes hexadecimal text encodes. Any case; surrounding whitespace and a `0x` prefix are accepted |

```sql
SELECT ip4_to_string(src_ip), tcp_flags_str(flags)
FROM read_tcp('capture.pcap') JOIN read_ipv4('capture.pcap') USING (frame_number)
WHERE ip_in_cidr(src_ip, '10.0.0.0/8') AND has_tcp_flag(flags, 'SYN');
```

```sql
SELECT ip4_to_string(src_ip), icmp_type_name(type), icmp_code_name(type, code)
FROM read_icmp('capture.pcap') JOIN read_ipv4('capture.pcap') USING (frame_number)
WHERE NOT is_private_ip(src_ip);
```

## Histograms

A histogram of the values of a column, built by an aggregate function and
read by scalar functions. They are the `hdr_*` functions of the command-line
tool, on the same code (`pcapsql_core::format::histogram`, an
[HdrHistogram](https://hdrhistogram.org)): a histogram one of the two made
is one the other reads, and for the same values both give the same answers.

A histogram keeps its values to two significant decimal digits (within 1 %),
whatever their number, and grows with the largest of them: 2 KiB for values
up to 255, 1 KiB more for each doubling of the largest value after that,
about 60 KiB for the whole range of a `UBIGINT`. That is per group while the
aggregation runs; the result is a compact encoding of the counts.

### `hdr_histogram(value)`

An aggregate function. Returns the histogram of the values of its group as a
`BLOB`: HdrHistogram's V2 encoding, which other HdrHistogram implementations
read too.

- `value` is a number: any integer type (`TINYINT` to `HUGEINT`, `UTINYINT`
  to `UHUGEINT`), `FLOAT`, `DOUBLE` or `DECIMAL`. Any other type is refused
  when the statement is bound. A column is read as it is stored, without a
  cast in between.
- What is recorded is an unsigned 64-bit integer. NULL is not recorded, nor
  is a negative number, nor NaN. Of a number with a fraction the integer
  part is recorded, so scale a column of fractions first
  (`hdr_histogram(seconds * 1000)`). A number above 18446744073709551615
  (a `HUGEINT`, a large `DOUBLE`, infinity) is recorded as that.
- A group without a value to record, and an aggregate without `GROUP BY`
  over no rows, is an empty histogram, not NULL: its `hdr_count` is 0.
- `FILTER`, `DISTINCT` and `OVER` (a window) work as for DuckDB's own
  aggregate functions. An `ORDER BY` in the call changes nothing.
- DuckDB aggregates on several threads and combines their partial
  histograms. The answers do not depend on that. The bytes of the `BLOB`
  can: one field of the encoding's header (the highest value the histogram
  has room for) depends on how the values were split into partial
  histograms and in which order those were combined. Equal values give
  equal bytes when one worker recorded them all (a capture read as one
  partition, or `SET threads = 1`, without `GROUP BY`), and always when they
  are below 256; those are the bytes the command-line tool returns for
  them. Compare histograms by what the functions below say of them.
- DuckDB 2.0.0 frees the histogram of a group when it returns the group. The
  histograms of groups a statement never returns stay allocated until the
  process ends: a grouped `hdr_histogram` under a `LIMIT` without an
  `ORDER BY`, and a statement that fails while it returns its groups. An
  `ORDER BY` before the `LIMIT`, or reading the result to its end, frees
  them all. (This is DuckDB's handling of every aggregate function that
  owns memory, see `pcapsql-duckdb/README.md`.)

One argument: the second argument the command-line tool's function accepts
is ignored there, and is not accepted here.

### Reading a histogram

| Function | Returns | Result |
|---|---|---|
| `hdr_count(histogram BLOB)` | `UBIGINT` | The number of values recorded |
| `hdr_min(histogram BLOB)` | `UBIGINT` | The smallest value recorded, to two digits: the lowest value the histogram cannot tell from it. 0 for an empty histogram |
| `hdr_max(histogram BLOB)` | `UBIGINT` | The largest value recorded, to two digits: the highest value the histogram cannot tell from it, which is at least the value. 0 for an empty histogram |
| `hdr_mean(histogram BLOB)` | `DOUBLE` | The mean of the values, each to two digits. 0 for an empty histogram |
| `hdr_stdev(histogram BLOB)` | `DOUBLE` | Their standard deviation. 0 for an empty histogram |
| `hdr_percentile(histogram BLOB, percentile DOUBLE)` | `DOUBLE` | The value at a percentile, given as a fraction (`0.99`) or, above 1, as a percentage (`99`). 0 for an empty histogram |
| `hdr_buckets(histogram BLOB)` | `STRUCT(lo UBIGINT, hi UBIGINT, count UBIGINT)[]` | The recorded range in buckets on a logarithmic scale, each with its bounds (both included) and the number of values in it. Powers of two (`1-1`, `2-3`, `4-7`, ...) from the smallest value to the largest, empty buckets between them included; at most 64, and powers of ten when powers of two would be more. The counts add up to `hdr_count`. The empty list for an empty histogram |
| `hdr_ascii(histogram BLOB)` | `VARCHAR` | The histogram drawn as text: a line of statistics, a header, and a line per bucket with its count, its share, the cumulative share and a bar. `(empty histogram)` for an empty one |

NULL gives NULL, and so does a `BLOB` that is not a histogram: none of these
raises an error for its input.

```sql
SELECT hdr_count(h), hdr_percentile(h, 0.5), hdr_percentile(h, 0.99), hdr_max(h)
FROM (SELECT hdr_histogram(length) AS h FROM read_frames('capture.pcap'));

-- A histogram per group, and its buckets as rows
SELECT dst_port, unnest(hdr_buckets(hdr_histogram(length)), recursive := true)
FROM read_tcp('capture.pcap') GROUP BY dst_port;

-- The picture, in the DuckDB shell: .mode list
SELECT hdr_ascii(hdr_histogram(length)) FROM read_frames('capture.pcap');
```

## Functions of the command-line tool that DuckDB has

The command-line tool's SQL functions are all here, under the same names,
except those DuckDB provides itself. Of its capture time functions the three
take the capture as an argument here ("Capture time"). Its six date and time
helpers are not registered: DuckDB's own functions do the same, on the
`TIMESTAMP_NS` of the tables, with these spellings (`ts` is a timestamp
column):

| Command-line tool | In DuckDB | Result |
|---|---|---|
| `strftime`, called with the format first | `strftime(ts, '%Y-%m-%d %H:%M')` | Text in a format. The timestamp comes first. `%f` is microseconds and `%n` nanoseconds |
| `datetime` | `strftime(ts, '%Y-%m-%dT%H:%M:%S.%f')` | ISO 8601 text with microseconds |
| `date` | `strftime(ts, '%Y-%m-%d')`, or `ts::DATE` for a `DATE` | The date |
| `time` | `strftime(ts, '%H:%M:%S.%f')`, or `ts::TIME` for a `TIME` | The time of day |
| `epoch` | `epoch(ts)` | Seconds since 1970 as a `DOUBLE` |
| `epoch_ms` | `epoch_ms(ts)` | Milliseconds since 1970 as a `BIGINT` |

On a capture with microsecond timestamps each returns what the command-line
tool's function returns. The tool's window table functions (`tumble`, `hop`,
`session`) are table functions, not among these, and the extension does not
have them.

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
| `start_time(files)` | `(SELECT min(start_time) FROM pcap_time_range(files))` |
| `end_time(files)` | `(SELECT max(end_time) FROM pcap_time_range(files))` |
| `relative_time(ts, files)` | `(epoch_ns(ts) - epoch_ns((SELECT min(start_time) FROM pcap_time_range(files)))) / 1e9` |

The last three are described under "Capture time".

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

What a split costs, and when there is none. A capture has no index of its
records, so before a capture is scanned in partitions it is read once, on one
thread, for the places to split it at, and nothing of that is kept for the
next statement. The pass takes about as long as `SELECT count(*) FROM
read_frames(...)` on one thread (a quarter of a second per gigabyte where it
was measured; the roadmap, section 8.2, has the numbers). A query that parses
a protocol repays it two to three times over on four threads; a query that
needs little of the capture does not:

- A capture is split for its share of DuckDB's threads: its share of the
  bytes of all files of the call, rounded. Four captures of one size on four
  threads are read one per thread and none is split; a large capture beside
  small ones is split for nearly all the threads.
- With an upper bound on `frame_number` in the `WHERE` clause the pass ends
  at the last frame the bound admits (unless `strict := true`, which looks at
  the end of the capture).
- A `LIMIT` is not known to the scan. `SELECT * FROM read_tcp('big.pcap')
  LIMIT 10` on several threads waits for the pass over the whole capture
  first; `SET pcapsql_parallel_scan = false`, `SET threads = 1` or a bound on
  `frame_number` avoids that.
- A scan that parses nothing (`frames` columns only) gains little from a
  split and nothing for `count(*)`: reading the capture is most of its work,
  and the pass reads it once more.

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

## Copy format: `COPY ... TO 'x.pcap' (FORMAT pcap)`

Writes the rows of a query as a classic libpcap file: a row is a packet.

```sql
COPY (SELECT * FROM read_frames('in.pcapng') WHERE length > 1000 ORDER BY frame_number)
  TO 'out.pcap' (FORMAT pcap);
COPY (SELECT f.* FROM read_frames('in.pcap') f JOIN read_dns('in.pcap') d USING (frame_number)
      ORDER BY frame_number)
  TO 'dns.pcap' (FORMAT pcap, PRECISION 'us', SNAPLEN 65535);
```

Read back with `read_frames`, the file has the `timestamp`, `length`,
`original_length`, `link_type` and `raw_data` of the rows, in their order.
Only `COPY ... TO` exists: a capture is read with the table functions.

### Columns

The columns of a packet are found by name, in any letter case, not by
position. They are those of the `frames` table, so `SELECT *` of
`read_frames` is a valid input:

| Column | Type | | |
|---|---|---|---|
| `raw_data` | `BLOB` | required | The bytes of the packet |
| `timestamp` | `TIMESTAMP_NS`, `TIMESTAMP`, `TIMESTAMP_MS`, `TIMESTAMP_S` or `TIMESTAMPTZ` | required | When it was captured. A value is an instant in UTC |
| `original_length` | an integer of at most 64 bits | optional | The length on the wire. NULL or no such column: the length of `raw_data` |
| `link_type` | an integer of at most 64 bits | optional | The link-layer type. NULL or no such column: that of the file |

Every other column is ignored, `frame_number` and `length` among them: the
captured length of a record is the length of its `raw_data`. A query without
a required column, or with one of these columns in another type, is refused
when the statement is bound, with a message that says what is needed; nothing
is read or written.

A row that is not a packet fails the statement, and the message names the row
by its position in the output, counted from 1: NULL in `raw_data` or
`timestamp`, a `timestamp` before 1970-01-01 or after 2106-02-07 06:28:15 UTC
(a pcap record counts seconds in 32 unsigned bits), an `original_length` that
is negative or above 4294967295, a `link_type` that is not between 0 and 65535.
An `original_length` below the length of `raw_data` is written as it is.

### Options

| Option | Default | Meaning |
|---|---|---|
| `LINKTYPE` | the `link_type` of the first row; Ethernet (1) when it has none, or when there is no row | The link-layer type in the header of the file: a number (`LINKTYPE 113`) or one of the names `NULL`, `ETHERNET` (also `EN10MB`), `PPP`, `PPP_ETHER`, `RAW`, `C_HDLC`, `IEEE802_11`, `LOOP`, `LINUX_SLL`, `PFLOG`, `IEEE802_11_RADIOTAP`, `BLUETOOTH_HCI_H4`, `USB_LINUX`, `CAN_SOCKETCAN`, `IPV4`, `IPV6`, `NFLOG`, `USBPCAP`, `NETLINK`, `LINUX_SLL2`, in any letter case, with or without `LINKTYPE_` in front. Any other type by its number |
| `SNAPLEN` | `262144` | The snapshot length in the header, from 1 to 4294967295. A packet longer than this is cut to it; its record keeps the original length |
| `PRECISION` | the unit of the `timestamp` column: `'ns'` for `TIMESTAMP_NS`, `'us'` for the other types | The unit of the timestamps in the file: `'ns'` (magic number `0xa1b23c4d`) or `'us'` (`0xa1b2c3d4`). `'us'` for a `TIMESTAMP_NS` column drops what a timestamp has below the microsecond; it is the only way a timestamp loses precision |

Any other option that is not DuckDB's own is refused.

A pcap file has one link type. A row whose `link_type` is not that of the
file fails the statement: select the rows of one link type, or write a file
per link type with DuckDB's `PARTITION_BY`:

```sql
COPY (SELECT * FROM read_frames('mixed.pcapng'))
  TO 'by_link_type' (FORMAT pcap, PARTITION_BY (link_type), WRITE_PARTITION_COLUMNS);
-- by_link_type/link_type=1/data_0.pcap, by_link_type/link_type=113/data_0.pcap
```

`WRITE_PARTITION_COLUMNS` is needed: without it DuckDB takes the column away
before the format sees it, and every file says Ethernet. DuckDB 2.0.0 logs a
deprecation warning about identifiers for `PARTITION_BY` with a format of an
extension, however the column is written; the statement works.

### The file

- Classic pcap, version 2.4, little-endian, time zone offset and accuracy 0,
  one link type. pcapng is not written.
- Since `read_frames` returns `TIMESTAMP_NS`, a copy of its rows is a
  nanosecond pcap file unless `PRECISION 'us'` is given.
- The copy of a little-endian microsecond pcap file, whole and in order, with
  `PRECISION 'us'` and the `SNAPLEN` of its header, is that file byte for
  byte, provided the file is well-formed (a record whose microseconds field
  is a million or more is written with the seconds carried). A big-endian or
  pcapng input is not: the copy is little-endian classic pcap.
- A result without rows is a valid capture without packets: the 24 bytes of
  the header. `WRITE_EMPTY_FILE false` writes no file.
- The file is not compressed, and a file name that says it is (`.gz`, `.zst`,
  `.zstd`, `.bz2`, `.xz`, `.lz4`) is refused. DuckDB chooses this format by
  itself for a file named `x.pcap`, so `COPY ... TO 'x.pcap'` needs no
  `FORMAT`. A name ending in `.pcapng` or `.cap` does not select it: DuckDB
  writes CSV there unless the statement says `FORMAT pcap`.
- The file is written through DuckDB's file system, in buffers of 1 MiB (4 MiB
  for a remote path), so it can be anywhere DuckDB can write. No remote path
  has been written in a test.
- `RETURN_STATS` reports the rows and the size of each file.
  `PER_THREAD_OUTPUT` and `PARTITION_BY` write several files, each a capture
  of its own. DuckDB 2.0.0 refuses `FILE_SIZE_BYTES` for a format of an
  extension.

### Order

The file has the rows in the order the query produces them. With `ORDER BY`
that is the order asked for, on any number of threads. Without one SQL
promises no order. What DuckDB 2.0.0 does: it runs the copy function of an
extension on one thread and hands it the chunks of the query as they come,
and a scan that feeds a copy directly then runs on one thread too, so
`COPY (SELECT * FROM read_frames('x.pcap') WHERE ...) TO ...` writes the
frames in capture order. A join or an aggregation between the scan and the
copy has no such order. Say `ORDER BY frame_number` (or `timestamp`) when the
order matters: it costs a sort and does not depend on the plan. With
`PER_THREAD_OUTPUT` or `PARTITION_BY` the order within a file is DuckDB's.

### Failure

The statement fails on the first error and writes no more. DuckDB removes a
file the statement created; an existing local file is replaced only when the
statement succeeds, because DuckDB writes a temporary file beside it
(`tmp_<name>`) and moves it into place at the end. With `USE_TMP_FILE false`
an existing file is written over in place, and a failed statement leaves it
holding the packets written until then. DuckDB uses no temporary file on a
remote file system either; what a failed statement leaves there has not been
tried.

## DuckDB facilities the extension uses

- File system: every open goes through DuckDB's, so `enable_external_access`
  and `allowed_directories` apply.
- Logging: a truncated capture is reported as a warning in DuckDB's log. With
  `CALL enable_logging(level = 'debug')`, each scan writes records of type
  `pcapsql` to `duckdb_logs` that describe what it read and how.
