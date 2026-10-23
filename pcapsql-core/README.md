# pcapsql-core

[![Crates.io](https://img.shields.io/crates/v/pcapsql-core.svg)](https://crates.io/crates/pcapsql-core)
[![Documentation](https://docs.rs/pcapsql-core/badge.svg)](https://docs.rs/pcapsql-core)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)

Engine-agnostic PCAP protocol parsing library.

This crate provides the core parsing functionality for pcapsql, without any SQL engine dependencies. It can be used standalone for protocol analysis or as the foundation for SQL integrations (DataFusion, DuckDB).

## Features

- **Protocol Parsing**: 17+ built-in protocol parsers
- **PCAP Reading**: PCAP and PCAPNG formats with gzip/zstd compression
- **Memory-Mapped I/O**: Efficient reading of large capture files
- **Boundary Index**: Record-boundary checkpoints (persisted as a sidecar) so a capture can be read in parallel partitions, locally or over cloud byte ranges
- **Scoped Parsing**: `ParseScope` prunes the protocol walk and projects fields to what a query needs
- **TCP Stream Reassembly**: Connection tracking and application-layer parsing
- **TLS Decryption**: Support for TLS 1.2/1.3 with SSLKEYLOGFILE

## Quick Start

```rust
use pcapsql_core::io::{FilePacketSource, PacketReader, PacketSource};
use pcapsql_core::{default_registry, parse_packet, ParseScope};

// A registry with every built-in parser; a scope that parses everything.
let registry = default_registry();
let scope = ParseScope::full();

// Open a capture (pcap or pcapng, optionally gzip/zstd compressed).
let source = FilePacketSource::open("capture.pcap").unwrap();
let mut reader = source.sequential_reader().unwrap();

// Read packets zero-copy; `packet.data` borrows the reader's buffer.
loop {
    let processed = reader
        .process_packets(1000, |packet| {
            let layers = parse_packet(&registry, packet.link_type, packet.data, &scope);
            for (protocol, result) in &layers {
                println!("frame {} {}: {} fields", packet.frame_number, protocol, result.fields.len());
            }
            Ok(())
        })
        .unwrap();
    if processed == 0 {
        break;
    }
}
```

Timestamps are nanoseconds (`packet.timestamp_ns`). Scope a parse to the
tables a query touches with `ParseScope::for_tables(&["tcp", "dns"], &registry)`;
the dependency closure (link and network layers, tunnels) is parsed
automatically.

## Supported Protocols

| Layer | Protocols |
|-------|-----------|
| Link | Ethernet, VLAN (802.1Q), Linux SLL, Linux SLL2 |
| Network | IPv4, IPv6, ARP, ICMP, ICMPv6 |
| Transport | TCP, UDP |
| Application | DNS, DHCP, NTP, HTTP, TLS, SSH, QUIC |
| Tunneling | VXLAN, GRE, MPLS, GTP, IPsec |
| Routing | BGP, OSPF |

## Crate Features

| Feature | Default | Description |
|---------|---------|-------------|
| `mmap` | Yes | Memory-mapped file I/O |
| `compress-gzip` | Yes | Gzip decompression |
| `compress-zstd` | Yes | Zstd decompression |
| `compress-lz4` | No | LZ4 decompression |
| `compress-bzip2` | No | Bzip2 decompression |
| `compress-xz` | No | XZ decompression |
| `compress-all` | No | All compression formats |

## Architecture

```
pcapsql-core
├── schema/     - FieldDescriptor, DataKind (engine-agnostic types)
├── protocol/   - Protocol trait, parsers, FieldValue, ParseScope / pruning
├── io/         - PacketSource / SeekablePacketSource, readers (file, mmap,
│                 cloud), boundary index + sidecar, compression
├── stream/     - TCP reassembly, HTTP/TLS stream parsing
├── tls/        - TLS key derivation and decryption
└── format/     - Address formatting utilities
```

## License

MIT
