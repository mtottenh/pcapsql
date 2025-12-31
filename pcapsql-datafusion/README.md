# pcapsql-datafusion

[![Crates.io](https://img.shields.io/crates/v/pcapsql-datafusion.svg)](https://crates.io/crates/pcapsql-datafusion)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)

SQL interface for PCAP analysis using Apache DataFusion.

This crate provides the `pcapsql` CLI tool for querying PCAP files using SQL.

## Installation

```bash
cargo install pcapsql-datafusion
```

Or download pre-built packages from [GitHub Releases](https://github.com/mtottenh/pcapsql/releases).

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

-- HTTP/2 requests (requires --keylog)
SELECT method, path, status FROM http2 WHERE method IS NOT NULL;
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

## Crate Features

| Feature | Default | Description |
|---------|---------|-------------|
| `compress-gzip` | Yes | Gzip-compressed PCAP support |
| `compress-zstd` | Yes | Zstd-compressed PCAP support |
| `compress-lz4` | No | LZ4-compressed PCAP support |
| `compress-bzip2` | No | Bzip2-compressed PCAP support |
| `compress-xz` | No | XZ-compressed PCAP support |
| `compress-all` | No | All compression formats |

## License

MIT
