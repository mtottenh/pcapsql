//! Packet I/O abstractions.
//!
//! This module provides the trait hierarchy and implementations for reading
//! packets from various sources.
//!
//! ## Design
//!
//! - [`PacketSource`] is the sequential floor every backend meets.
//! - [`SeekablePacketSource`] is the opt-in random-access capability, with a
//!   [`SeekCost`] hint, backed by a persisted [`BoundaryIndex`].
//! - Type erasure happens only at DataFusion boundaries.
//!
//! ## Available Sources
//!
//! - [`FilePacketSource`] - Standard buffered file I/O (`SeekCost::Cheap`)
//! - [`MmapPacketSource`] - Memory-mapped I/O (`SeekCost::Free`; requires `mmap`)
//! - [`CloudPacketSource`] - Object-store I/O (`SeekCost::RangeRequest`; requires `cloud`)

#[cfg(feature = "cloud")]
mod cloud;
mod decompress;
mod index;
#[cfg(feature = "mmap")]
mod mmap;
mod pcap_stream;
mod source;

pub use decompress::{decompress_header, Compression, DecompressReader, FileDecoder};
#[cfg(feature = "mmap")]
pub use decompress::{AnyDecoder, MmapSlice};
pub use index::{
    build_boundary_index, header_hash, sidecar_path, BoundaryIndex, Checkpoint,
    DEFAULT_CHECKPOINT_STRIDE,
};
#[cfg(feature = "mmap")]
pub use mmap::{MmapPacketReader, MmapPacketSource};
pub use pcap_stream::{GenericPcapReader, InterfaceInfo, InterfaceState, PcapFormat};
pub use source::{
    FilePacketReader, FilePacketSource, PacketPosition, PacketRange, PacketReader, PacketRef,
    PacketSource, PacketSourceMetadata, SeekCost, SeekablePacketSource,
};

#[cfg(feature = "cloud")]
pub use cloud::{
    is_cloud_url, CloudLocation, CloudPacketReader, CloudPacketSource, ObjectStoreReader,
};
