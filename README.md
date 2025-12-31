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

## CLI Options

```
pcapsql <PCAP> [OPTIONS]

Query:
  -e, --execute <SQL>       Execute query and exit
  -o, --output <FILE>       Export results (.parquet, .csv, .json)

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
```

## REPL Commands

```
.tables                 List available tables
.schema [table]         Show table schema
.export <file> [query]  Export query results
.quit                   Exit
```

## License

MIT
