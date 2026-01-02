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
```

## Tables

| Table | Description |
|-------|-------------|
| `ethernet`, `ipv4`, `ipv6`, `tcp`, `udp` | Layer 2-4 protocols |
| `dns`, `dhcp`, `ntp`, `http` | Application protocols |
| `tls` | TLS records and handshakes |
| `http2` | HTTP/2 frames (requires TLS decryption) |
| `vxlan`, `gre`, `mpls`, `gtp` | Tunnel headers |
| `bgp`, `ospf` | Routing protocols |

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

### Utility Functions

| Function | Description |
|----------|-------------|
| `hex(binary)` | Convert binary to hex string |
| `unhex('48656c6c6f')` | Parse hex string to binary |

## CLI Options

```
pcapsql <PCAP> [OPTIONS]

Query:
  -e, --execute <SQL>       Execute query and exit
  -o, --output <FILE>       Export results (.parquet, .csv, .json)
  --filter <EXPR>           BPF filter (tcpdump syntax)

TLS Decryption:
  --keylog <FILE>           SSLKEYLOGFILE for TLS decryption

Performance:
  --streaming               Low-memory streaming mode
  --mmap                    Memory-mapped file access
  --batch-size <N>          Packets per batch (default: 10000)

Stream Reassembly:
  --track-streams           Enable TCP stream tracking
  --max-stream-memory <N>   Buffer limit (default: 1G)
  --stream-timeout <SECS>   Connection timeout (default: 300)

Cloud Storage:
  --cloud-endpoint <URL>    Custom S3-compatible endpoint
  --cloud-anonymous         Use unsigned requests (public buckets)
  --cloud-chunk-size <N>    Download chunk size (default: 8M)
```

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

- Cloud sources always use streaming mode for memory efficiency
- Default chunk size is 8MB; increase for high-latency connections
- Compression is recommended to reduce transfer time
- Both legacy PCAP and PCAPNG formats are supported

## License

MIT
