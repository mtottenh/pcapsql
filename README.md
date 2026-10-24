# pcapsql

[![CI](https://github.com/mtottenh/pcapsql/actions/workflows/ci.yml/badge.svg)](https://github.com/mtottenh/pcapsql/actions/workflows/ci.yml)
[![Release](https://github.com/mtottenh/pcapsql/actions/workflows/release.yml/badge.svg)](https://github.com/mtottenh/pcapsql/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Query PCAP files using SQL. Built on Apache Arrow and DataFusion.

## Installation

### Pre-built Packages

Download the latest release for your distribution from [GitHub Releases](https://github.com/mtottenh/pcapsql/releases).

| Distribution | Version | Package |
|:-------------|:--------|:--------|
| ![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?logo=ubuntu&logoColor=white) | 20.04, 22.04, 24.04, 24.10, 25.04, 25.10 | `.deb` |
| ![Debian](https://img.shields.io/badge/Debian-A81D33?logo=debian&logoColor=white) | 11, 12, 13 | `.deb` |
| ![Fedora](https://img.shields.io/badge/Fedora-51A2DA?logo=fedora&logoColor=white) | 39, 40, 41, 42, 43 | `.rpm` |
| ![Rocky Linux](https://img.shields.io/badge/Rocky_Linux-10B981?logo=rockylinux&logoColor=white) | 9, 10 | `.rpm` |
| ![Arch Linux](https://img.shields.io/badge/Arch_Linux-1793D1?logo=archlinux&logoColor=white) | Rolling | [AUR](https://aur.archlinux.org/packages/pcapsql) |

```bash
# Debian/Ubuntu
sudo dpkg -i pcapsql_*.deb

# Fedora/RHEL/Rocky
sudo rpm -i pcapsql-*.rpm

# Arch Linux (using yay)
yay -S pcapsql
```

### Build from Source

Requires Rust 1.70+:

```bash
cargo install --git https://github.com/mtottenh/pcapsql pcapsql-datafusion
```

Or clone and build:

```bash
git clone https://github.com/mtottenh/pcapsql
cd pcapsql
cargo build --release
./target/release/pcapsql --help
```

## Quick Start

```bash
# Interactive mode
pcapsql capture.pcap

# Single query
pcapsql capture.pcap -e "SELECT * FROM tcp LIMIT 10"

# With TLS decryption
pcapsql capture.pcap --keylog sslkeys.log -e "SELECT * FROM http2"

# Export to Parquet
pcapsql capture.pcap -e "SELECT * FROM dns" -o dns.parquet

# Query directly from S3 (requires cloud feature)
pcapsql s3://bucket/capture.pcap.gz -e "SELECT * FROM tcp LIMIT 10"

# Pipe a live capture in (one query; -U keeps tcpdump from buffering)
tcpdump -U -w - -i eth0 port 53 | pcapsql --stdin -e "SELECT * FROM dns_packets"
```

## Features

### Protocol Parsing
Parses 25+ protocols: Ethernet, VLAN, ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, DNS, DHCP, TLS, SSH, HTTP, NTP, QUIC, BGP, OSPF, GRE, MPLS, GTP, IPsec, VXLAN

### Encapsulation Support
Automatic parsing of tunneled traffic with inner protocol extraction:
- **VXLAN** - VNI extraction, inner Ethernet frames
- **GRE** - Optional checksum/key/sequence, inner IP
- **MPLS** - Label stack parsing, inner IP detection
- **GTP** - GTPv1/v2-C with extension headers
- **IP-in-IP** - 4in4, 6in4, 4in6, 6in6 tunnels

### TLS Decryption
Decrypt TLS traffic using SSLKEYLOGFILE (NSS format):
- TLS 1.2 (`CLIENT_RANDOM`) and TLS 1.3 (traffic secrets)
- AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
- SNI and ALPN extraction

### HTTP/2 Analysis
Full HTTP/2 frame parsing from decrypted TLS:
- All frame types (DATA, HEADERS, SETTINGS, GOAWAY, etc.)
- HPACK header decompression
- Stream state tracking
- Request/response correlation

### TCP Stream Reassembly
Reassemble TCP streams for application-layer parsing:
- Out-of-order segment handling
- Connection tracking
- Configurable memory limits and timeouts

### Cloud Storage
Query PCAP files directly from cloud storage without downloading:
- **AWS S3** (`s3://bucket/key`)
- **Google Cloud Storage** (`gs://bucket/key`)
- **Azure Blob Storage** (`az://container/blob`)
- **S3-compatible** services (MinIO, Cloudflare R2, LocalStack)
- Automatic compression detection (gzip, zstd, bzip2, xz, lz4)
- Efficient streaming with configurable chunk sizes

## Example Queries

```sql
-- Protocol distribution
SELECT protocol, COUNT(*) FROM packets GROUP BY protocol;

-- TCP SYN packets
SELECT src_ip, dst_ip, dst_port FROM tcp WHERE has_tcp_flag(tcp_flags, 'SYN');

-- Top talkers
SELECT src_ip, SUM(length) as bytes FROM ipv4 GROUP BY src_ip ORDER BY bytes DESC LIMIT 10;

-- DNS queries by type
SELECT query_name, dns_type_name(query_type) as qtype, COUNT(*) FROM dns GROUP BY 1, 2;

-- TLS Server Names (requires --keylog or just parses handshakes)
SELECT server_name, COUNT(*) FROM tls WHERE server_name IS NOT NULL GROUP BY 1;

-- HTTP/2 requests (requires --keylog)
SELECT method, path, status FROM http2 WHERE method IS NOT NULL;

-- Traffic inside VXLAN tunnels
SELECT * FROM ipv4 WHERE tunnel_type = 'vxlan';

-- Packets per 10-second window (see Window Functions)
SELECT window_start, count(*) FROM tumble(frames, INTERVAL '10' SECOND) GROUP BY 1 ORDER BY 1;
```

## Tables

| Table | Description |
|-------|-------------|
| `ethernet`, `ipv4`, `ipv6`, `tcp`, `udp` | Layer 2-4 protocols (`ipv6` includes the extension header chain: Hop-by-Hop/Routing/Fragment/Destination presence, fragment and routing header fields) |
| `dns`, `dhcp`, `ntp` | Application protocols |
| `http` | HTTP/1.x request/status line and headers, per packet (the segment that starts a message) |
| `tls` | TLS records and handshakes |
| `tcp_connections`, `tls_sessions`, `http_messages` | Reassembled TCP streams: one row per connection, TLS handshake, HTTP/1.x message |
| `http2` | HTTP/2 frames (requires TLS decryption) |
| `vxlan`, `gre`, `gtp`, `ipsec` | Tunnel headers (inner layers get `encap_depth` > 0 and a `tunnel_type`); `gtp` includes the GTPv1 N-PDU number and extension header chain and the GTPv2-C flags |
| `mpls` | Label stacks (label switching, not counted as a tunnel) |
| `bgp`, `ospf` | Routing protocols: BGP OPEN capabilities, UPDATE path attributes (AS path, next hop, MED, local pref, aggregator) and withdrawn/announced prefixes, NOTIFICATION codes, ROUTE-REFRESH address family; OSPFv2 Hello (neighbour count), Database Description and the first LSA header of DD/LSU/LSAck packets |
| `tcp_packets`, `udp_packets`, `dns_packets`, … | Views: one row per header of the named protocol with `frames.timestamp`, the layers under it **from the same encapsulation level** (a tunnelled segment shows its inner addresses; the outer header is in `tunneled_packets`) and that header's `encap_depth` / `tunnel_type` |
| `packets` | View: one row per encapsulation level of every frame, with the common columns of each layer at that level |

## SQL Functions (UDFs)

pcapsql provides specialized functions for network analysis. Run `pcapsql --list-udfs` for the complete list.

### Address Functions

| Function | Description |
|----------|-------------|
| `ip4('192.168.1.1')` | Parse IPv4 string to UInt32 |
| `ip4_to_string(ip)` | Convert UInt32 to IPv4 string |
| `ip_in_cidr(ip, '10.0.0.0/8')` | Check if IPv4 is in CIDR range |
| `ip6('fe80::1')` | Parse IPv6 string to Binary(16) |
| `ip6_to_string(ip)` | Convert Binary(16) to IPv6 string |
| `ip6_in_cidr(ip, '2001::/16')` | Check if IPv6 is in CIDR prefix |
| `mac('aa:bb:cc:dd:ee:ff')` | Parse MAC address to Binary(6) |
| `mac_to_string(mac)` | Convert Binary(6) to MAC string |

### Protocol Functions

| Function | Description |
|----------|-------------|
| `tcp_flags_str(flags)` | Convert TCP flags to string (e.g., "SYN,ACK") |
| `has_tcp_flag(flags, 'SYN')` | Check if TCP flag is set |
| `dns_type_name(type)` | DNS type number to name (A, AAAA, MX, etc.) |
| `dns_rcode_name(rcode)` | DNS response code to name (NXDOMAIN, etc.) |
| `icmp_type_name(type)` | ICMP type to name |
| `ip_proto_name(proto)` | IP protocol number to name (TCP, UDP, etc.) |
| `ethertype_name(type)` | EtherType to name (IPv4, ARP, etc.) |

Integer parameters take any integer column or literal (`dscp_name(46)`); a
value outside the parameter's range (`dscp_name(300)`) is a cast error, not a
wrapped lookup. String parameters take any string type.

### DateTime Functions

| Function | Description |
|----------|-------------|
| `strftime('%Y-%m-%d', ts)` | Format timestamp with strftime |
| `datetime(ts)` | ISO 8601 datetime string |
| `date(ts)`, `time(ts)` | Extract date or time portion |
| `epoch(ts)`, `epoch_ms(ts)` | Unix timestamp (seconds/milliseconds) |
| `start_time()`, `end_time()` | Capture start/end timestamps |
| `relative_time(ts)` | Seconds elapsed from capture start |

### Histogram Functions

| Function | Description |
|----------|-------------|
| `hdr_histogram(value)` | Build histogram (aggregate function) |
| `hdr_percentile(hist, 0.99)` | Extract percentile from histogram |
| `hdr_count/min/max/mean(hist)` | Extract statistics from histogram |
| `hdr_buckets(hist)` | Distribution as log-scale bucket rows (explode with `UNNEST`) |
| `hdr_ascii(hist)` | Render ASCII histogram with cumulative % (CDF) |

### Utility Functions

| Function | Description |
|----------|-------------|
| `hex(binary)` | Convert binary to hex string |
| `unhex('48656c6c6f')` | Parse hex string to binary |

### Window Functions

Table functions that add `window_start` / `window_end` (half-open, `Timestamp(Microsecond)`)
to a source's columns, for GROUP BY over time:

| Function | Windows |
|----------|---------|
| `tumble(source, size)` | Fixed, non-overlapping, aligned to the epoch |
| `hop(source, slide, size)` | Fixed size, a new window every `slide` (overlapping when `slide < size`) |
| `session(source, key_column, gap)` | Per key, closed after `gap` without a packet |

The source is `frames` or any `*_packets` view (they carry `frames.timestamp`); a protocol
table alone has no timestamp, so window `tcp_packets`, not `tcp`. Any other table or view
works when a `Timestamp(Microsecond)` column is named after the source:
`tumble(source, ts_column, size)`, `session(source, ts_column, key_column, gap)`. Sizes are
INTERVAL literals without months (`INTERVAL '10' SECOND`, `INTERVAL '1' HOUR`).

```sql
-- Packets and bytes per 10-second window
SELECT window_start, count(*) AS packets, sum(length) AS bytes
FROM tumble(frames, INTERVAL '10' SECOND) GROUP BY 1 ORDER BY 1;

-- 1-minute windows every 10 seconds, per destination port
SELECT window_start, dst_port, count(*)
FROM hop(tcp_packets, INTERVAL '10' SECOND, INTERVAL '1' MINUTE) GROUP BY 1, 2 ORDER BY 1, 2;

-- Sessions per client: a new session after 30 seconds of silence
SELECT src_ip_v4, window_start, window_end, count(*) AS packets
FROM session(tcp_packets, src_ip_v4, INTERVAL '30' SECOND) GROUP BY 1, 2, 3 ORDER BY 1, 2;
```

The functions expand into the query plan, so only the columns the query uses are parsed and
`WHERE` clauses on source columns reach the parser; `EXPLAIN` shows the expanded plan.
`session` buffers its (pruned) input in memory before it can emit anything, since a session's
bounds depend on every packet of its key; `hop` emits each row once per covering window, so
`size / slide` is capped at 10,000.

## Continuous Queries

`--continuous` runs a windowed aggregate over a **live** capture piped into standard input
and prints every window as soon as the stream's event time has passed its end:

```bash
# Packets and bytes per 10-second window, as they complete
tcpdump -U -w - -i eth0 | pcapsql --continuous --format csv \
  -e "SELECT window_start, count(*) AS packets, sum(length) AS bytes
      FROM tumble(frames, INTERVAL '10' SECOND) GROUP BY 1"

# Bytes per minute, every 10 seconds, per link type, for DNS traffic only
tcpdump -U -w - -i eth0 port 53 | pcapsql --continuous \
  -e "SELECT window_start, link_type, sum(length) AS bytes
      FROM hop(frames, INTERVAL '10' SECOND, INTERVAL '1' MINUTE) GROUP BY 1, 2"
```

The source of a continuous query is `frames` or a `*_packets` view (`tumble(dns_packets, …)`).
A view is a join of protocol tables, and a join over a stream would buffer one side for ever,
but these joins never reach DataFusion: the parser, which has every layer of a frame in hand,
emits the view's joined row itself (see "Fused joins" below), so the view streams exactly like
`frames`. What cannot be fused — the `FULL` joins of the unified `packets` view, a join written
above the window, a join on other conditions — is rejected.

A continuous query **aggregates over `tumble()` or `hop()` windows and nothing else**:
`SELECT window_start, …, <aggregates> FROM tumble(source, …) [WHERE …] GROUP BY window_start
[, window_end, <columns>]`. `WHERE` on source or window columns, several group columns, any
number of aggregates, `FILTER (WHERE …)` clauses, `HAVING`, `SELECT DISTINCT` and a `LIMIT`
(the first N windows) are fine; `ORDER BY`, `count(DISTINCT …)`, joins the parser cannot fuse,
`session()` windows and aggregates without `GROUP BY window_start` need the whole stream first
and are rejected at planning. Stream tables (`tcp_connections`, …) are not available. `EXPLAIN`
shows the `StreamingWindowAggregateExec` that will run, or the refusal.

Semantics and knobs:

- A window `[start, end)` is emitted once the **watermark** — the newest timestamp seen minus
  `--allowed-lateness` (default 1 s) — reaches `end`. A packet behind the newest timestamp is
  still counted while its window is open; one arriving after its window was emitted is dropped
  and counted (`--stats` prints `Late rows dropped`).
- Packets reach the query in batches of `--batch-size`, or after `--flush-interval` seconds
  (default 1) since the previous batch, whichever comes first. The wait for input is a
  `poll(2)` on the pipe with that timeout, so a quiet feed delivers its last packets within
  the interval even when nothing else arrives (a compressed stream cannot time out: its held
  packets wait for the next one).
- Windows close on **event time**. `--idle-timeout N` additionally closes every open window
  after N seconds without any input (off by default; use a value above `--flush-interval`); a
  packet for such a window arriving later is late.
- State is one accumulator set per open window and group. A `hop()` whose size is a multiple
  of its slide is aggregated per **slice** (one slide's worth) and the slices are merged when a
  window closes, so a 1-minute window sliding every 10 seconds costs one sixth of the state and
  work of one accumulator per window. (Aggregates whose result depends on input order, such as
  `array_agg` without `ORDER BY`, may list a sliced window's elements in slice order.)
- `--memory-limit SIZE` (e.g. `512MiB`) caps what DataFusion may hold for the run, the window
  state included; the aggregate accounts its state to the pool after every batch. When the state
  does not fit, `--on-memory-limit error` (the default) fails the query naming the open windows
  and groups, and `--on-memory-limit close-oldest` prints the oldest open windows before their
  time until it fits (`--stats` and `--progress` count them; a packet for such a window
  arriving later is late). Without a limit, state is bounded only by closed windows.
- Output is appended per window: CSV prints its header once, JSON is one object per line, the
  table format prints one table per window. `-o` is not available. `--progress` shows rows,
  windows, the current watermark and late rows.
- Ctrl-C stops the query, releases the parser (a reader waiting on a quiet pipe is woken
  through a cancel descriptor, so this is immediate for an uncompressed feed; a compressed one
  is released by its next byte or end of input), prints `--stats`, and exits with status 130.
  An execution error prints `--stats` the same way and exits with status 1.
- Everything that applies to `--stdin` applies: one statement, `RetentionPolicy::None`, no
  time-range functions, a single parse partition. Use `tcpdump -U` so packets are not held in
  tcpdump's stdio buffer.

Library callers use `EngineOptions { continuous: true, .. }` with `SourceSpec::Stdin` /
`SourceSpec::Sequential` and consume `QueryEngine::execute_stream(sql)`, a `Stream` of
`RecordBatch`es whose `finish()` returns the query's `ParseStats`.

### Fused joins

The parser has every layer of a frame in hand at once, and the `*_packets` views only join
those layers back together (`frames` ⋈ `tcp` ⋈ `ethernet` ⋈ `ipv4` ⋈ `ipv6`, on `frame_number`
and `encap_depth`). Under `RetentionPolicy::None` — every one-shot (`-e`/`-f`), `--stdin` and
`--continuous` run — a tree of inner and left joins of protocol tables on those keys is
**fused**: the parser emits the joined row itself, as one table of the parse pass, and no join
operator is left in the plan. The result is exactly what the joins would produce (inner and
left semantics, every match, nulls for a missing left side); the golden corpus checks it
against the REPL's join path on every view. `EXPLAIN` shows the fused table
(`TableScan: fused_frames_tcp_ethernet_ipv4_ipv6_…`) and `--stats` counts its rows.

What fuses: the `*_packets` views, hand-written joins of the same shape, a view joined with a
protocol table it does not already contain (when the view's selected columns are plain columns),
`WHERE` filters on inner sides, and the query's `LIMIT`. What does not, and runs as a DataFusion
join over the fused part instead: `FULL` joins (the unified `packets` view), join conditions
other than `frame_number` / `encap_depth` equality, the same table under two aliases (which
includes a view joined with one of its own members, `tcp_packets t JOIN tcp u`), a derived
table's own `LIMIT` on one side, and a join written above a window (`tumble(frames, …) t JOIN
udp …`). `--no-fuse-joins` turns fusion off for a run, to compare plans, results and timings.

## CLI Options

```
pcapsql <PCAP> [OPTIONS]
pcapsql --stdin -e <SQL> [OPTIONS]

Query:
  -e, --execute <SQL>       Execute query and exit
  -f, --file <FILE>         Execute the query in FILE and exit
  -o, --output <FILE>       Export results (.parquet, .csv, .json)
  --filter <EXPR>           BPF filter (tcpdump syntax)
  --stats                   Print parse statistics after the query

Input:
  --stdin                   Read the capture from standard input (`-` as <PCAP> means the same)

TLS Decryption:
  --keylog <FILE>           SSLKEYLOGFILE for TLS decryption

Performance:
  --no-mmap                 Disable memory-mapped file access
  --batch-size <N>          Packets per batch (default: 10000)

Cloud Storage:
  --cloud-endpoint <URL>    Custom S3-compatible endpoint
  --cloud-anonymous         Use unsigned requests (public buckets)
  --cloud-chunk-size <N>    Download chunk size (default: 8M)
```

### Reading from standard input

`--stdin` (or `-` in place of the capture path) reads a pcap or pcapng
capture, optionally gzip- or zstd-compressed, from standard input (a file
literally named `-` is `./-`):

```bash
# Live DNS from an interface; -U makes tcpdump flush per packet
tcpdump -U -w - -i eth0 port 53 | pcapsql --stdin -e "SELECT * FROM dns_packets"

# dumpcap writes pcapng; "any" is a Linux cooked (SLL) capture
dumpcap -w - -i any | pcapsql --stdin -e "SELECT packet_type_name, count(*) FROM linux_sll GROUP BY 1"

# A compressed file without a temporary copy
zcat capture.pcap.gz | pcapsql - -e "SELECT count(*) FROM frames" --stats
```

Stdin is read sequentially to end of input in a single parse pass, so:

- it takes a one-shot query, `-e` or `-f` with exactly one statement; the
  interactive REPL is not available (it would read its SQL from the same
  stdin). `-o`, `--export-format`, `--format`, `--filter`, `--stats` and
  `--progress` work as for a file;
- the one query may touch any tables, including the stream-analysis tables
  (`tcp_connections`, `tls_sessions`, …): they share the pass;
- `start_time()`, `end_time()` and `relative_time()` are not available: they
  need a pass over the whole capture before the query runs. Use
  `min(timestamp)` / `max(timestamp)` from `frames` in the query instead.

## REPL Commands

```
.tables                 List available tables
.schema [table]         Show table schema
.export <file> [query]  Export query results
.quit                   Exit
```

## Cloud Storage

Query PCAP files directly from AWS S3, Google Cloud Storage, or Azure Blob Storage without downloading.

### Building with Cloud Support

Cloud support is an optional feature. To enable it:

```bash
# S3 only
cargo build --release --features s3

# All cloud providers
cargo build --release --features cloud-all
```

Pre-built packages include S3 support by default.

### Usage Examples

```bash
# AWS S3
pcapsql s3://my-bucket/captures/traffic.pcap -e "SELECT * FROM tcp"

# Compressed files (auto-detected)
pcapsql s3://my-bucket/traffic.pcap.gz -e "SELECT COUNT(*) FROM packets"
pcapsql s3://my-bucket/traffic.pcap.zst -e "SELECT * FROM dns"

# Public buckets (no credentials required)
pcapsql s3://public-pcaps/sample.pcap --cloud-anonymous

# S3-compatible services (MinIO, Cloudflare R2, LocalStack)
pcapsql s3://bucket/file.pcap --cloud-endpoint http://localhost:9000

# Google Cloud Storage
pcapsql gs://my-bucket/capture.pcap -e "SELECT * FROM http"

# Azure Blob Storage
pcapsql az://container/capture.pcap -e "SELECT * FROM tls"
```

### Authentication

**AWS S3**: Uses standard AWS credential chain:
- Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
- AWS credentials file (`~/.aws/credentials`)
- IAM instance roles (EC2, ECS, Lambda)

**Google Cloud**: Uses Application Default Credentials:
- `GOOGLE_APPLICATION_CREDENTIALS` environment variable
- `gcloud auth application-default login`
- GCE metadata service

**Azure**: Uses Azure Identity credential chain:
- Environment variables (`AZURE_STORAGE_ACCOUNT`, `AZURE_STORAGE_KEY`)
- Azure CLI (`az login`)
- Managed Identity

### Performance Notes

- Large objects are parsed in parallel with independent byte-range reads; the boundary index that makes this possible is cached locally (`$PCAPSQL_INDEX_CACHE`, else `$XDG_CACHE_HOME/pcapsql/index`, else `~/.cache/pcapsql/index`) so later opens of the same object do not re-download it
- Default chunk size is 8MB; increase for high-latency connections
- Compression is recommended to reduce transfer time
- Both legacy PCAP and PCAPNG formats are supported

## License

MIT
