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
- **Parse Caching**: LRU cache to avoid redundant parsing during JOINs
- **TCP Stream Reassembly**: Connection tracking and application-layer parsing
- **TLS Decryption**: Support for TLS 1.2/1.3 with SSLKEYLOGFILE

## Quick Start

```rust
use pcapsql_core::prelude::*;
use pcapsql_core::io::FilePacketSource;

// Create a protocol registry with all built-in parsers
let registry = default_registry();

// Open a PCAP file
let source = FilePacketSource::open("capture.pcap").unwrap();
let mut reader = source.reader(None).unwrap();

// Read and parse packets
reader.process_packets(1000, |packet| {
    let results = pcapsql_core::parse_packet(
        &registry,
        packet.link_type as u16,
        &packet.data,
    );

    for (protocol_name, result) in results {
        println!("{}: {} fields", protocol_name, result.fields.len());
    }
    Ok(())
}).unwrap();
```

## Supported Protocols

| Layer | Protocols |
|-------|-----------|
| Link | Ethernet, VLAN (802.1Q), Linux SLL |
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
├── protocol/   - Protocol trait, parsers, FieldValue
├── io/         - PacketSource, PacketReader, mmap support
├── pcap/       - PCAP/PCAPNG reading, compression
├── cache/      - LRU parse cache
├── stream/     - TCP reassembly, HTTP/TLS stream parsing
├── tls/        - TLS key derivation and decryption
└── format/     - Address formatting utilities
```

## License

MIT
