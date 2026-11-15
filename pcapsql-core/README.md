# pcapsql-core

[![Crates.io](https://img.shields.io/crates/v/pcapsql-core.svg)](https://crates.io/crates/pcapsql-core)
[![Documentation](https://docs.rs/pcapsql-core/badge.svg)](https://docs.rs/pcapsql-core)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)

Engine-agnostic PCAP protocol parsing library.

This crate provides the core parsing functionality for pcapsql, without any SQL engine dependencies. It can be used standalone for protocol analysis or as the foundation for SQL integrations (DataFusion, DuckDB).

## Features

- **Protocol Parsing**: 26 built-in protocol parsers
- **PCAP Reading**: PCAP and PCAPNG formats with gzip/zstd compression
- **PCAP Writing**: `io::PcapWriter` writes a classic PCAP file (microsecond or nanosecond timestamps) to any `std::io::Write`
- **Memory-Mapped I/O**: Efficient reading of large capture files
- **Boundary Index**: Record-boundary checkpoints (persisted as a sidecar) so a capture can be read in parallel partitions, locally or over cloud byte ranges
- **Scoped Parsing**: `ParseScope` prunes the protocol walk and projects fields to what a query needs
- **TCP Stream Reassembly**: Connection tracking and application-layer parsing
- **TLS Decryption**: Support for TLS 1.2/1.3 with SSLKEYLOGFILE

## Quick Start

```rust
use pcapsql_core::io::{FilePacketSource, PacketReader, PacketSource};
use pcapsql_core::{default_registry, parse_packet, ParseBuf, ParseScope};

// A registry with every built-in parser; a scope that parses everything.
let registry = default_registry();
let scope = ParseScope::full();
// Where a packet's layers are kept: reused from packet to packet.
let mut buf = ParseBuf::new();

// Open a capture (pcap or pcapng, optionally gzip/zstd compressed).
let source = FilePacketSource::open("capture.pcap").unwrap();
let mut reader = source.sequential_reader().unwrap();

// Read packets zero-copy; `packet.data` borrows the reader's buffer.
loop {
    let processed = reader
        .process_packets(1000, |packet| {
            let layers =
                parse_packet(&registry, packet.link_type, packet.data, &scope, &mut buf);
            for layer in layers.iter() {
                let fields = layer.fields().len();
                println!("frame {} {}: {fields} fields", packet.frame_number, layer.name());
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
| Link | Ethernet, VLAN (802.1Q), Linux SLL, Linux SLL2, Netlink, rtnetlink |
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
└── format/     - Address formatting, and the kernels of the SQL scalar
                  functions (names, flags, cidr, mac, hex)
```

### Names of protocol numbers

`format::names` holds the one set of code-to-name tables. The `*_name()`
SQL functions and the name columns of the parsers (`icmp.type_name`,
`bgp.message_type_name`, `tls.version`, ...) both read it, so a column and
the function applied to the number beside it give the same text:

```rust
use pcapsql_core::format::{dns_type_name, icmp_type_name, ospf_lsa_type_name};

assert_eq!(icmp_type_name(8), "Echo Request");
assert_eq!(dns_type_name(28), "AAAA");
// A number without a name carries the number, in the table's own style.
assert_eq!(icmp_type_name(99), "Type 99");
assert_eq!(dns_type_name(999), "TYPE999");
assert_eq!(ospf_lsa_type_name(99), "Unknown (99)");
```

A lookup returns a `Name`, which is `Copy` and allocates nothing: write it
with `{}`, compare it with a `str`, or take `as_static()` / `into_cow()`. A
parser writes one with `FieldSink::name`. A parser must not keep a name
table of its own: add the table to `format::names` and list the column in
`protocol/name_columns_tests.rs`, which checks every name column against its
table over every number.

## License

MIT
