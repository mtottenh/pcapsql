//! # pcapsql-core
//!
//! Engine-agnostic PCAP protocol parsing library.
//!
//! This crate provides the core parsing functionality for pcapsql, without
//! any SQL engine dependencies. It can be used standalone for protocol
//! analysis or as the foundation for SQL integrations (DataFusion, DuckDB).
//!
//! ## Features
//!
//! - **Protocol Parsing**: 17 built-in protocol parsers (Ethernet, IP, TCP, UDP,
//!   DNS, HTTP, TLS, DHCP, NTP, and more)
//! - **PCAP Reading**: Support for PCAP and PCAPNG formats, including gzip/zstd
//!   compression
//! - **Memory-Mapped I/O**: Efficient reading of large capture files
//! - **Parse Caching**: LRU cache to avoid redundant parsing during JOINs
//! - **TCP Stream Reassembly**: Connection tracking and application-layer parsing
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use pcapsql_core::prelude::*;
//! use pcapsql_core::io::FilePacketSource;
//!
//! // Create a protocol registry with all built-in parsers
//! let registry = default_registry();
//!
//! // Open a PCAP file
//! let source = FilePacketSource::open("capture.pcap").unwrap();
//! let mut reader = source.reader(None).unwrap();
//!
//! // Read and parse packets using callback pattern
//! reader.process_packets(1000, |packet| {
//!     let results = pcapsql_core::parse_packet(
//!         &registry,
//!         packet.link_type as u16,
//!         &packet.data,
//!     );
//!
//!     for (protocol_name, result) in results {
//!         println!("{}: {} fields", protocol_name, result.fields.len());
//!     }
//!     Ok(())
//! }).unwrap();
//! ```
//!
//! ## Architecture
//!
//! ```text
//! +---------------------------------------------------------------------+
//! |                        pcapsql-core                                 |
//! +---------------------------------------------------------------------+
//! |  schema/     - FieldDescriptor, DataKind (engine-agnostic)          |
//! |  protocol/   - Protocol trait, 17 parsers, FieldValue               |
//! |  io/         - PacketSource, PacketReader, mmap support             |
//! |  pcap/       - PCAP/PCAPNG reading, compression                     |
//! |  cache/      - LRU parse cache                                      |
//! |  stream/     - TCP reassembly, HTTP/TLS stream parsing              |
//! |  format/     - Address formatting utilities                         |
//! |  error/      - Error types                                          |
//! +---------------------------------------------------------------------+
//! ```
//!
//! ## Crate Features
//!
//! - `default` - Gzip and Zstd compression enabled
//! - `compress-gzip` - Gzip decompression support
//! - `compress-zstd` - Zstd decompression support
//! - `compress-lz4` - LZ4 decompression support
//! - `compress-bzip2` - Bzip2 decompression support
//! - `compress-xz` - XZ decompression support
//! - `compress-all` - All compression formats
//!
//! ## Supported Protocols
//!
//! | Layer | Protocols |
//! |-------|-----------|
//! | Link | Ethernet, VLAN (802.1Q) |
//! | Network | IPv4, IPv6, ARP, ICMP, ICMPv6 |
//! | Transport | TCP, UDP |
//! | Application | DNS, DHCP, NTP, HTTP, TLS, SSH, QUIC |

pub mod cache;
pub mod error;
pub mod format;
pub mod io;
pub mod pcap;
pub mod prelude;
pub mod protocol;
pub mod schema;
pub mod stream;
pub mod tls;

// Re-export commonly used types at crate root for convenience
pub use cache::{CacheStats, CachedParse, LruParseCache, NoCache, OwnedParseResult, ParseCache};
pub use protocol::OwnedFieldValue;
pub use error::{Error, PcapError, ProtocolError, Result};
pub use format::{detect_address_column, format_ipv4, format_ipv6, format_mac, AddressKind};
pub use io::{FilePacketReader, FilePacketSource, PacketReader, PacketSource, RawPacket};
#[cfg(feature = "mmap")]
pub use io::{MmapPacketReader, MmapPacketSource};
pub use pcap::PcapReader;
pub use protocol::{
    chain_fields_for_protocol, compute_required_protocols, default_registry,
    merge_with_chain_fields, parse_packet, parse_packet_projected, parse_packet_pruned,
    parse_packet_pruned_projected, should_continue_parsing, should_run_parser, BuiltinProtocol,
    FieldValue, ParseContext, ParseResult, PayloadMode, ProjectionConfig, Protocol,
    ProtocolRegistry, TunnelLayer, TunnelType,
};
pub use schema::{DataKind, FieldDescriptor, ProtocolSchema};
pub use stream::{
    Connection, ConnectionState, ConnectionTracker, Direction, ParsedMessage, StreamConfig,
    StreamContext, StreamManager, StreamParser, StreamParseResult, StreamRegistry, TcpFlags,
};
pub use tls::{
    derive_tls12_keys, derive_tls13_keys, extract_tls13_inner_content_type, hash_for_cipher_suite,
    tls12_prf, AeadAlgorithm, DecryptionContext, DecryptionError, Direction as TlsDirection,
    HandshakeData, HashAlgorithm, KeyDerivationError, KeyLog, KeyLogEntries, KeyLogEntry,
    KeyLogError, SessionError, SessionState, Tls12KeyMaterial, Tls13KeyMaterial, TlsSession,
    TlsVersion,
};

/// Library version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
