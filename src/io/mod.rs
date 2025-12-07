//! Packet I/O abstractions.
//!
//! This module provides traits and implementations for reading packets from
//! various sources (files, memory-mapped files, network streams, etc.)
//!
//! ## Design
//!
//! The module uses generics with associated types for zero-vtable hot path:
//! - `PacketSource` trait with associated `Reader` type
//! - `PacketReader` trait for sequential reading
//! - Type erasure happens only at DataFusion boundaries
//!
//! ## Available Sources
//!
//! - `FilePacketSource` - Standard buffered file I/O (works with all file types)
//! - `MmapPacketSource` - Memory-mapped I/O for PCAP/PCAPNG files
//!
//! ## Compression Support
//!
//! Both sources support transparent decompression of compressed files.
//! Supported formats (via feature flags):
//! - Gzip (.gz) - always enabled
//! - Zstd (.zst) - `compress-zstd` feature
//! - LZ4 (.lz4) - `compress-lz4` feature
//! - Bzip2 (.bz2) - `compress-bzip2` feature
//! - XZ (.xz) - `compress-xz` feature

mod decompress;
mod mmap;
mod pcap_stream;
mod source;

pub use decompress::{AnyDecoder, Compression, DecompressReader, FileDecoder, MmapSlice};
pub use mmap::{MmapPacketReader, MmapPacketSource};
pub use pcap_stream::{GenericPcapReader, PcapFormat};
pub use source::{
    FilePacketReader, FilePacketSource, PacketPosition, PacketRange, PacketReader, PacketRef,
    PacketSource, PacketSourceMetadata, RawPacket,
};
