# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - Unreleased

### Added

- **Time UDFs**: New functions for capture time analysis ([#28](https://github.com/mtottenh/pcapsql/issues/28))
  - `start_time()` - Returns capture start timestamp
  - `end_time()` - Returns capture end timestamp
  - `relative_time(timestamp)` - Returns seconds from capture start
- **REPL**: `.timeinfo` command to display capture timing information ([#24](https://github.com/mtottenh/pcapsql/pull/24))
- **Protocols**: Netlink and Linux SLL support ([#23](https://github.com/mtottenh/pcapsql/pull/23))
  - Netlink protocol parser (LINKTYPE_NETLINK)
  - rtnetlink parser for NETLINK_ROUTE family
  - Linux SLL (cooked capture) link layer support
- **Packaging**: Published to crates.io (`pcapsql-core`, `pcapsql-datafusion`)

### Fixed

- Link type detection in streaming mode

### Changed

- Crate metadata updated for crates.io publishing

## [0.1.0] - 2024-12-29

### Added

- Initial release
- **Protocol Parsing**: 25+ protocols including Ethernet, VLAN, ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, DNS, DHCP, TLS, SSH, HTTP, NTP, QUIC, BGP, OSPF, GRE, MPLS, GTP, IPsec, VXLAN
- **Encapsulation Support**: VXLAN, GRE, MPLS, GTP, IP-in-IP tunnel parsing
- **TLS Decryption**: TLS 1.2/1.3 decryption using SSLKEYLOGFILE (NSS format)
- **HTTP/2 Analysis**: Full HTTP/2 frame parsing with HPACK header decompression
- **TCP Stream Reassembly**: Connection tracking with out-of-order segment handling
- **SQL Interface**: Query PCAP files using SQL via Apache DataFusion
- **Export Formats**: Parquet, CSV, JSON output
- **Performance Features**: Memory-mapped I/O, streaming mode, parse caching
- **CLI**: Interactive REPL with tab completion and history
- **Packaging**: .deb (Debian/Ubuntu), .rpm (Fedora/Rocky), AUR (Arch Linux)

[0.2.0]: https://github.com/mtottenh/pcapsql/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mtottenh/pcapsql/releases/tag/v0.1.0
