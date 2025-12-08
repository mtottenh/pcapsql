# pcapsql

Query PCAP files using SQL. Built on Apache Arrow and DataFusion.

## Quick Start

```bash
cargo build --release

# Interactive mode
./target/release/pcapsql capture.pcap

# Single query
pcapsql capture.pcap -e "SELECT * FROM tcp LIMIT 10"

# Export to file
pcapsql capture.pcap -e "SELECT * FROM dns" -o dns.parquet
```

## Example Queries

```sql
-- Count by protocol
SELECT protocol, COUNT(*) FROM packets GROUP BY protocol;

-- TCP SYN packets
SELECT src_ip, dst_ip, src_port, dst_port FROM tcp WHERE tcp_flags & 2 = 2;

-- Top talkers
SELECT src_ip, SUM(length) as bytes FROM packets GROUP BY src_ip ORDER BY bytes DESC LIMIT 10;

-- DNS queries
SELECT * FROM dns WHERE dst_port = 53;
```

## Tables

- `packets` - All packets with unified schema
- `tcp`, `udp`, `icmp`, `arp`, `dns` - Protocol-specific views

## Supported Protocols

Ethernet, VLAN (802.1Q), ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, DNS, DHCP, TLS, SSH, HTTP, NTP, QUIC, BGP, OSPF, GRE, MPLS, GTP, IPsec, VXLAN

## REPL Commands

```
.tables     List tables
.schema     Show schemas
.export <file> [query]  Export results
.quit       Exit
```

## Export Formats

- `.parquet` - Apache Parquet
- `.csv` - CSV with header
- `.json` / `.jsonl` - JSON Lines

## License

MIT
