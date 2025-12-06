//! Packet source abstractions and implementations.
//!
//! This module defines traits for abstracting over packet sources (files, memory-mapped
//! files, cloud storage, etc.) and provides implementations for common sources.
//!
//! ## Design Principles
//!
//! - Generic traits with associated types (no Box<dyn> in hot path)
//! - Matches existing enum-dispatch pattern used for protocols
//! - Supports future backends (mmap, S3) without trait changes
//! - Type erasure happens at DataFusion boundaries, not in hot path

use std::path::{Path, PathBuf};

use bytes::Bytes;

use crate::error::Error;
use crate::pcap::PcapReader;

/// Position within a packet source (for seeking/checkpointing).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PacketPosition {
    /// Byte offset in the underlying source
    pub byte_offset: u64,
    /// Frame number at this position (1-indexed, matching Wireshark)
    pub frame_number: u64,
}

impl PacketPosition {
    /// Position at the start of the source
    pub const START: Self = Self {
        byte_offset: 0,
        frame_number: 1,
    };
}

/// Range of packets for partitioning.
#[derive(Clone, Debug)]
pub struct PacketRange {
    /// Start position (inclusive)
    pub start: PacketPosition,
    /// End position (exclusive). None means read to EOF.
    pub end: Option<PacketPosition>,
}

impl PacketRange {
    /// Range covering the entire source
    pub fn whole() -> Self {
        Self {
            start: PacketPosition::START,
            end: None,
        }
    }

    /// Check if a frame number is within this range
    pub fn contains(&self, frame_number: u64) -> bool {
        frame_number >= self.start.frame_number
            && self.end.as_ref().map_or(true, |e| frame_number < e.frame_number)
    }
}

/// Metadata about a packet source.
#[derive(Clone, Debug)]
pub struct PacketSourceMetadata {
    /// Link-layer type (e.g., 1 = Ethernet)
    pub link_type: u32,
    /// Snapshot length
    pub snaplen: u32,
    /// Total size in bytes (if known)
    pub size_bytes: Option<u64>,
    /// Total packet count (if known, e.g., from index)
    pub packet_count: Option<u64>,
    /// Whether the source supports seeking
    pub seekable: bool,
}

/// Raw packet data from a reader.
#[derive(Clone, Debug)]
pub struct RawPacket {
    /// Frame number (1-indexed)
    pub frame_number: u64,
    /// Timestamp in microseconds since Unix epoch
    pub timestamp_us: i64,
    /// Captured length (may be less than original)
    pub captured_len: u32,
    /// Original packet length on the wire
    pub original_len: u32,
    /// Packet data (potentially zero-copy with Bytes)
    pub data: Bytes,
}

/// Source of packet data. Creates readers and computes partitions.
///
/// This trait uses an associated type for `Reader` to enable static dispatch
/// in the hot path, matching the enum-dispatch pattern used for protocols.
///
/// # Design Notes
///
/// We use generics rather than `Box<dyn PacketReader>` because:
/// 1. Each QueryEngine uses ONE source type (no heterogeneous mixing)
/// 2. The hot loop calls `reader.next_packet()` millions of times
/// 3. Static dispatch enables inlining and optimization
/// 4. Type erasure happens at DataFusion boundaries anyway
pub trait PacketSource: Send + Sync + Clone + 'static {
    /// The reader type this source produces
    type Reader: PacketReader;

    /// Get metadata about this source
    fn metadata(&self) -> &PacketSourceMetadata;

    /// Create a reader for the given range.
    /// If range is None, reads the entire source.
    fn reader(&self, range: Option<&PacketRange>) -> Result<Self::Reader, Error>;

    /// Compute partition boundaries for parallel reading.
    ///
    /// Returns at most `max_partitions` non-overlapping ranges that cover
    /// the entire source. The default implementation returns a single
    /// partition (the whole source).
    ///
    /// # Phase 2.5
    ///
    /// This default implementation is sufficient for Phase 2.
    /// Phase 2.5 will override this to scan the file and find
    /// packet boundaries at approximately equal byte offsets.
    fn partitions(&self, _max_partitions: usize) -> Result<Vec<PacketRange>, Error> {
        Ok(vec![PacketRange::whole()])
    }

    /// Get the link type for this source.
    fn link_type(&self) -> u32 {
        self.metadata().link_type
    }
}

/// Sequential reader of packets from a source.
///
/// This is the hot path - implementations should be optimized for
/// sequential reading with minimal overhead per packet.
pub trait PacketReader: Send + Unpin {
    /// Read the next packet.
    ///
    /// Returns `Ok(None)` at end of range/file.
    /// This is the primary hot-path method.
    fn next_packet(&mut self) -> Result<Option<RawPacket>, Error>;

    /// Current position in the source.
    fn position(&self) -> PacketPosition;

    /// Get the link type for packets from this reader.
    fn link_type(&self) -> u32;

    /// Read multiple packets at once for efficiency.
    ///
    /// This amortizes any per-call overhead and enables better
    /// cache utilization. The buffer is cleared before reading.
    ///
    /// Returns the number of packets read (0 means EOF).
    #[inline]
    fn read_batch(&mut self, buffer: &mut Vec<RawPacket>, max: usize) -> Result<usize, Error> {
        buffer.clear();
        buffer.reserve(max);
        while buffer.len() < max {
            match self.next_packet()? {
                Some(pkt) => buffer.push(pkt),
                None => break,
            }
        }
        Ok(buffer.len())
    }
}

/// Packet source backed by a PCAP/PCAPNG file.
#[derive(Clone)]
pub struct FilePacketSource {
    path: PathBuf,
    metadata: PacketSourceMetadata,
}

impl FilePacketSource {
    /// Open a PCAP file as a packet source.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();

        // Open once to get link type and other metadata
        let reader = PcapReader::open(&path)?;
        let link_type = reader.link_type() as u32;

        let size_bytes = std::fs::metadata(&path).ok().map(|m| m.len());

        let metadata = PacketSourceMetadata {
            link_type,
            snaplen: 65535, // Default, could read from header
            size_bytes,
            packet_count: None, // Would require scanning the file
            seekable: true,
        };

        Ok(Self { path, metadata })
    }

    /// Get the path to the file.
    pub fn file_path(&self) -> &Path {
        &self.path
    }
}

impl PacketSource for FilePacketSource {
    type Reader = FilePacketReader;

    fn metadata(&self) -> &PacketSourceMetadata {
        &self.metadata
    }

    fn reader(&self, range: Option<&PacketRange>) -> Result<Self::Reader, Error> {
        FilePacketReader::open(&self.path, self.metadata.link_type, range)
    }

    // partitions() uses default implementation (single partition)
    // Phase 2.5 will override this
}

/// Sequential packet reader for PCAP files.
pub struct FilePacketReader {
    inner: PcapReader,
    link_type: u32,
    position: PacketPosition,
    range: Option<PacketRange>,
}

impl FilePacketReader {
    /// Open a reader starting at the given position.
    fn open(path: &Path, link_type: u32, range: Option<&PacketRange>) -> Result<Self, Error> {
        let inner = PcapReader::open(path)?;

        // If starting position specified with frame > 1, we'd need to scan
        // For now, we always start from the beginning
        let position = if let Some(r) = range {
            if r.start.frame_number > 1 {
                tracing::warn!(
                    "FilePacketReader doesn't support seeking to frame {}, starting from beginning",
                    r.start.frame_number
                );
            }
            r.start.clone()
        } else {
            PacketPosition::START
        };

        Ok(Self {
            inner,
            link_type,
            position,
            range: range.cloned(),
        })
    }

    /// Check if we've reached the end of our range
    #[inline]
    fn past_range_end(&self) -> bool {
        if let Some(ref range) = self.range {
            if let Some(ref end) = range.end {
                return self.position.frame_number >= end.frame_number;
            }
        }
        false
    }
}

impl PacketReader for FilePacketReader {
    #[inline]
    fn next_packet(&mut self) -> Result<Option<RawPacket>, Error> {
        // Check range bounds
        if self.past_range_end() {
            return Ok(None);
        }

        // Skip packets before our range start
        while self.inner.frame_count() + 1 < self.position.frame_number {
            if self.inner.next_packet()?.is_none() {
                return Ok(None);
            }
        }

        // Read next packet from the underlying reader
        match self.inner.next_packet()? {
            Some(raw) => {
                let packet = RawPacket {
                    frame_number: raw.frame_number,
                    timestamp_us: raw.timestamp_us,
                    captured_len: raw.captured_length,
                    original_len: raw.original_length,
                    data: Bytes::from(raw.data),
                };

                // Update position
                self.position.frame_number = raw.frame_number + 1;

                Ok(Some(packet))
            }
            None => Ok(None),
        }
    }

    #[inline]
    fn position(&self) -> PacketPosition {
        self.position.clone()
    }

    fn link_type(&self) -> u32 {
        self.link_type
    }

    // read_batch() uses default implementation, which is efficient enough
    // for file I/O where the BufReader handles batching at the I/O level
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_range_whole() {
        let range = PacketRange::whole();
        assert_eq!(range.start, PacketPosition::START);
        assert!(range.end.is_none());
    }

    #[test]
    fn test_packet_position_start() {
        let pos = PacketPosition::START;
        assert_eq!(pos.frame_number, 1);
        assert_eq!(pos.byte_offset, 0);
    }

    #[test]
    fn test_packet_range_contains() {
        let range = PacketRange {
            start: PacketPosition {
                byte_offset: 0,
                frame_number: 5,
            },
            end: Some(PacketPosition {
                byte_offset: 0,
                frame_number: 10,
            }),
        };

        assert!(!range.contains(4));
        assert!(range.contains(5));
        assert!(range.contains(9));
        assert!(!range.contains(10));
    }

    #[test]
    fn test_packet_range_contains_no_end() {
        let range = PacketRange {
            start: PacketPosition {
                byte_offset: 0,
                frame_number: 5,
            },
            end: None,
        };

        assert!(!range.contains(4));
        assert!(range.contains(5));
        assert!(range.contains(1000));
    }
}
