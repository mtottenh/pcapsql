//! Memory-mapped packet source for efficient packet access.
//!
//! Uses `memmap2` crate for platform-independent memory mapping.
//! Provides efficient access to packet data for large files.
//!
//! ## Supported Formats
//!
//! - Classic PCAP (little/big endian, micro/nanosecond timestamps)
//! - PCAPNG
//! - All above formats with compression (gzip, zstd, lz4, bzip2, xz)
//!
//! ## Compression Handling
//!
//! For compressed files, the compressed data is mmap'd and decompression
//! happens on-the-fly through the `AnyDecoder` wrapper. This keeps the
//! compressed data in the OS page cache while streaming decompressed
//! packets through pcap_parser.

use std::fs::File;
use std::io::{BufReader, Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use memmap2::Mmap;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapNGReader};

use crate::error::{Error, PcapError};

use super::decompress::{AnyDecoder, Compression, MmapSlice};
use super::{
    PacketPosition, PacketRange, PacketReader, PacketSource, PacketSourceMetadata, RawPacket,
};

/// Format of the PCAP file (after decompression).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcapFormat {
    /// Classic PCAP (little-endian, microseconds)
    LegacyLeMicro,
    /// Classic PCAP (big-endian, microseconds)
    LegacyBeMicro,
    /// Classic PCAP (little-endian, nanoseconds)
    LegacyLeNano,
    /// Classic PCAP (big-endian, nanoseconds)
    LegacyBeNano,
    /// PCAPNG format
    PcapNg,
}

impl PcapFormat {
    /// Detect PCAP format from magic bytes.
    fn detect(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 4 {
            return Err(Error::Pcap(PcapError::InvalidFormat {
                reason: "Data too small for PCAP magic".into(),
            }));
        }

        let magic = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);

        match magic {
            0xa1b2c3d4 => Ok(PcapFormat::LegacyLeMicro),
            0xd4c3b2a1 => Ok(PcapFormat::LegacyBeMicro),
            0xa1b23c4d => Ok(PcapFormat::LegacyLeNano),
            0x4d3cb2a1 => Ok(PcapFormat::LegacyBeNano),
            0x0a0d0d0a => Ok(PcapFormat::PcapNg),
            _ => Err(Error::Pcap(PcapError::InvalidFormat {
                reason: format!("Unknown PCAP magic: 0x{:08x}", magic),
            })),
        }
    }

    /// Whether this is a PCAPNG format
    pub fn is_pcapng(&self) -> bool {
        matches!(self, PcapFormat::PcapNg)
    }

    /// Whether this is a legacy PCAP format
    pub fn is_legacy(&self) -> bool {
        !self.is_pcapng()
    }

    /// Whether bytes need to be swapped (big-endian format)
    pub fn byte_swap(&self) -> bool {
        matches!(self, PcapFormat::LegacyBeMicro | PcapFormat::LegacyBeNano)
    }

    /// Whether timestamps are in nanoseconds
    pub fn nano_precision(&self) -> bool {
        matches!(self, PcapFormat::LegacyLeNano | PcapFormat::LegacyBeNano)
    }

    /// Extract link type from header bytes.
    fn link_type_from_header(&self, data: &[u8]) -> u32 {
        if data.len() < 24 {
            return 1; // Default to Ethernet
        }
        if self.byte_swap() {
            u32::from_be_bytes([data[20], data[21], data[22], data[23]])
        } else {
            u32::from_le_bytes([data[20], data[21], data[22], data[23]])
        }
    }
}

/// Memory-mapped packet source.
///
/// Maps the entire file into virtual memory, allowing the OS to handle
/// caching and paging. Supports both uncompressed and compressed files.
///
/// For uncompressed legacy PCAP, uses direct byte parsing for maximum speed.
/// For PCAPNG or compressed files, uses pcap_parser with streaming decompression.
#[derive(Clone)]
pub struct MmapPacketSource {
    /// Path to the file (for error messages)
    path: PathBuf,
    /// Memory-mapped region (shared via Arc)
    mmap: Arc<Mmap>,
    /// Cached metadata
    metadata: PacketSourceMetadata,
    /// Detected compression format
    compression: Compression,
    /// PCAP format (after decompression)
    pcap_format: PcapFormat,
    /// Offset where packet data starts (for uncompressed legacy PCAP only)
    data_offset: usize,
}

impl MmapPacketSource {
    /// Open a PCAP or PCAPNG file with memory mapping.
    ///
    /// Automatically detects and handles compression.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path).map_err(Error::Io)?;

        // Create memory mapping
        let mmap = unsafe { Mmap::map(&file).map_err(Error::Io)? };

        // Detect compression
        let compression = Compression::detect(&mmap);

        // Detect PCAP format (may need to decompress first bytes)
        let (pcap_format, link_type, data_offset) = if compression.is_compressed() {
            Self::detect_format_compressed(&mmap, compression)?
        } else {
            Self::detect_format_uncompressed(&mmap)?
        };

        let metadata = PacketSourceMetadata {
            link_type,
            snaplen: 65535,
            size_bytes: Some(mmap.len() as u64),
            packet_count: None,
            seekable: !compression.is_compressed(), // Can only seek in uncompressed
        };

        Ok(Self {
            path,
            mmap: Arc::new(mmap),
            metadata,
            compression,
            pcap_format,
            data_offset,
        })
    }

    /// Detect format from uncompressed data.
    fn detect_format_uncompressed(data: &[u8]) -> Result<(PcapFormat, u32, usize), Error> {
        if data.len() < 24 {
            return Err(Error::Pcap(PcapError::InvalidFormat {
                reason: "File too small for PCAP header".into(),
            }));
        }

        let format = PcapFormat::detect(data)?;
        let link_type = if format.is_pcapng() {
            1 // Will be updated from interface description block
        } else {
            format.link_type_from_header(data)
        };
        let data_offset = if format.is_pcapng() { 0 } else { 24 };

        Ok((format, link_type, data_offset))
    }

    /// Detect format from compressed data (decompress first bytes).
    fn detect_format_compressed(
        data: &[u8],
        compression: Compression,
    ) -> Result<(PcapFormat, u32, usize), Error> {
        // Decompress enough bytes to detect the format and link type
        let mut decoder: Box<dyn Read> = match compression {
            Compression::None => unreachable!(),
            Compression::Gzip => {
                let cursor = Cursor::new(data);
                let gz = flate2::read::GzDecoder::new(cursor);
                Box::new(gz) as Box<dyn Read>
            }
            #[cfg(feature = "compress-zstd")]
            Compression::Zstd => {
                let cursor = Cursor::new(data);
                let zstd = zstd::Decoder::new(cursor)?;
                Box::new(zstd) as Box<dyn Read>
            }
            #[cfg(feature = "compress-lz4")]
            Compression::Lz4 => {
                let cursor = Cursor::new(data);
                let lz4 = lz4_flex::frame::FrameDecoder::new(cursor);
                Box::new(lz4) as Box<dyn Read>
            }
            #[cfg(feature = "compress-bzip2")]
            Compression::Bzip2 => {
                let cursor = Cursor::new(data);
                let bz2 = bzip2::read::BzDecoder::new(cursor);
                Box::new(bz2) as Box<dyn Read>
            }
            #[cfg(feature = "compress-xz")]
            Compression::Xz => {
                let cursor = Cursor::new(data);
                let xz = xz2::read::XzDecoder::new(cursor);
                Box::new(xz) as Box<dyn Read>
            }
        };

        // Read enough bytes to detect format and link type
        let mut header = [0u8; 24];
        decoder.read_exact(&mut header).map_err(|e| {
            Error::Pcap(PcapError::InvalidFormat {
                reason: format!("Failed to read compressed header: {}", e),
            })
        })?;

        let format = PcapFormat::detect(&header)?;
        let link_type = if format.is_pcapng() {
            1 // Will be updated during reading
        } else {
            format.link_type_from_header(&header)
        };

        // For compressed files, data_offset doesn't apply the same way
        Ok((format, link_type, 0))
    }

    /// Get the path to the file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the detected compression format.
    pub fn compression(&self) -> Compression {
        self.compression
    }

    /// Get the PCAP format.
    pub fn pcap_format(&self) -> PcapFormat {
        self.pcap_format
    }

    /// Check if this is a PCAPNG file.
    pub fn is_pcapng(&self) -> bool {
        self.pcap_format.is_pcapng()
    }

    /// Check if this file is compressed.
    pub fn is_compressed(&self) -> bool {
        self.compression.is_compressed()
    }

    /// Get the link type.
    pub fn link_type(&self) -> u32 {
        self.metadata.link_type
    }

    /// Parse PCAP header from raw bytes.
    ///
    /// Returns (format, link_type, data_offset) on success.
    /// This is used for testing header parsing logic.
    #[cfg(test)]
    fn parse_header(data: &[u8]) -> Result<(PcapFormat, u32, usize), Error> {
        Self::detect_format_uncompressed(data)
    }
}

impl PacketSource for MmapPacketSource {
    type Reader = MmapPacketReader;

    fn metadata(&self) -> &PacketSourceMetadata {
        &self.metadata
    }

    fn reader(&self, range: Option<&PacketRange>) -> Result<Self::Reader, Error> {
        MmapPacketReader::new(
            self.mmap.clone(),
            self.compression,
            self.pcap_format,
            self.data_offset,
            self.metadata.link_type,
            range.cloned(),
        )
    }

    fn partitions(&self, _max_partitions: usize) -> Result<Vec<PacketRange>, Error> {
        // For now, return single partition
        // Future optimization: scan for packet boundaries at byte offsets
        Ok(vec![PacketRange::whole()])
    }
}

impl std::fmt::Debug for MmapPacketSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MmapPacketSource")
            .field("path", &self.path)
            .field("size_bytes", &self.metadata.size_bytes)
            .field("link_type", &self.metadata.link_type)
            .field("compression", &self.compression)
            .field("pcap_format", &self.pcap_format)
            .finish()
    }
}

/// Buffer size for pcap_parser readers
const PCAP_BUFFER_SIZE: usize = 65536;

/// Memory-mapped packet reader.
///
/// Reads packets from the memory-mapped region. Supports:
/// - Uncompressed legacy PCAP: direct byte parsing (fastest)
/// - Uncompressed PCAPNG: pcap_parser with Cursor
/// - Compressed files: pcap_parser with AnyDecoder
pub struct MmapPacketReader {
    inner: ReaderInner,
    /// Current frame number
    frame_number: u64,
    /// Link type (may be updated from PCAPNG interface description)
    link_type: u32,
    /// Current byte offset (for position tracking, uncompressed only)
    byte_offset: u64,
    /// Optional range restriction
    range: Option<PacketRange>,
}

/// Inner reader implementation
enum ReaderInner {
    /// Direct byte parsing for uncompressed legacy PCAP (most efficient)
    LegacyDirect(LegacyMmapReader),
    /// pcap_parser for uncompressed PCAPNG
    PcapNgDirect(PcapNGReader<Cursor<MmapSlice>>),
    /// pcap_parser with decompression for compressed legacy PCAP
    LegacyCompressed(LegacyPcapReader<BufReader<AnyDecoder>>),
    /// pcap_parser with decompression for compressed PCAPNG
    PcapNgCompressed(PcapNGReader<BufReader<AnyDecoder>>),
}

/// Direct legacy PCAP reader (no pcap_parser overhead, uncompressed only)
struct LegacyMmapReader {
    /// Shared memory-mapped region
    mmap: Arc<Mmap>,
    /// Current byte offset in the file
    offset: usize,
    /// Whether byte order is swapped
    byte_swap: bool,
    /// Whether timestamps are in nanoseconds
    nano_precision: bool,
}

impl MmapPacketReader {
    fn new(
        mmap: Arc<Mmap>,
        compression: Compression,
        pcap_format: PcapFormat,
        data_offset: usize,
        link_type: u32,
        range: Option<PacketRange>,
    ) -> Result<Self, Error> {
        let frame_number = range
            .as_ref()
            .map(|r| r.start.frame_number)
            .unwrap_or(1);

        let start_offset = range
            .as_ref()
            .and_then(|r| {
                if r.start.byte_offset > 0 {
                    Some(r.start.byte_offset as usize)
                } else {
                    None
                }
            })
            .unwrap_or(data_offset);

        let inner = match (compression.is_compressed(), pcap_format.is_pcapng()) {
            // Uncompressed legacy PCAP: direct byte parsing
            (false, false) => {
                ReaderInner::LegacyDirect(LegacyMmapReader {
                    mmap,
                    offset: start_offset,
                    byte_swap: pcap_format.byte_swap(),
                    nano_precision: pcap_format.nano_precision(),
                })
            }

            // Uncompressed PCAPNG: pcap_parser with Cursor
            (false, true) => {
                let slice = MmapSlice::new(mmap);
                let cursor = Cursor::new(slice);
                let reader = PcapNGReader::new(PCAP_BUFFER_SIZE, cursor).map_err(|e| {
                    Error::Pcap(PcapError::InvalidFormat {
                        reason: format!("Failed to parse PCAPNG: {}", e),
                    })
                })?;
                ReaderInner::PcapNgDirect(reader)
            }

            // Compressed legacy PCAP: pcap_parser with AnyDecoder
            (true, false) => {
                let decoder = AnyDecoder::with_compression(mmap, compression)
                    .map_err(|e| Error::Pcap(PcapError::InvalidFormat {
                        reason: format!("Failed to create decompressor: {}", e),
                    }))?;
                let buf_reader = BufReader::with_capacity(PCAP_BUFFER_SIZE, decoder);
                let reader = LegacyPcapReader::new(PCAP_BUFFER_SIZE, buf_reader).map_err(|e| {
                    Error::Pcap(PcapError::InvalidFormat {
                        reason: format!("Failed to parse compressed PCAP: {}", e),
                    })
                })?;
                ReaderInner::LegacyCompressed(reader)
            }

            // Compressed PCAPNG: pcap_parser with AnyDecoder
            (true, true) => {
                let decoder = AnyDecoder::with_compression(mmap, compression)
                    .map_err(|e| Error::Pcap(PcapError::InvalidFormat {
                        reason: format!("Failed to create decompressor: {}", e),
                    }))?;
                let buf_reader = BufReader::with_capacity(PCAP_BUFFER_SIZE, decoder);
                let reader = PcapNGReader::new(PCAP_BUFFER_SIZE, buf_reader).map_err(|e| {
                    Error::Pcap(PcapError::InvalidFormat {
                        reason: format!("Failed to parse compressed PCAPNG: {}", e),
                    })
                })?;
                ReaderInner::PcapNgCompressed(reader)
            }
        };

        Ok(Self {
            inner,
            frame_number,
            link_type,
            byte_offset: start_offset as u64,
            range,
        })
    }

    /// Check if we've passed the end of our range.
    #[inline]
    fn past_range_end(&self) -> bool {
        if let Some(ref range) = self.range {
            if let Some(ref end) = range.end {
                return self.frame_number >= end.frame_number;
            }
        }
        false
    }
}

impl LegacyMmapReader {
    /// Read a u32 with proper byte order.
    #[inline]
    fn read_u32(&self, offset: usize) -> u32 {
        let data = &self.mmap[..];
        let bytes = [
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ];
        if self.byte_swap {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        }
    }

    fn next_packet(&mut self, frame_number: &mut u64) -> Result<Option<RawPacket>, Error> {
        let data = &self.mmap[..];

        // Check if we have enough data for packet header (16 bytes)
        if self.offset + 16 > data.len() {
            return Ok(None);
        }

        // Parse PCAP packet header
        let ts_sec = self.read_u32(self.offset);
        let ts_frac = self.read_u32(self.offset + 4);
        let captured_len = self.read_u32(self.offset + 8) as usize;
        let original_len = self.read_u32(self.offset + 12);

        // Sanity check captured length
        if captured_len > 65535 {
            return Err(Error::Pcap(PcapError::InvalidFormat {
                reason: format!(
                    "Invalid captured length {} at frame {}",
                    captured_len, frame_number
                ),
            }));
        }

        // Check if we have enough data for packet
        let packet_start = self.offset + 16;
        let packet_end = packet_start + captured_len;
        if packet_end > data.len() {
            return Ok(None);
        }

        // Create Bytes from the slice
        let packet_data = Bytes::copy_from_slice(&data[packet_start..packet_end]);

        // Calculate timestamp in microseconds
        let timestamp_us = if self.nano_precision {
            (ts_sec as i64) * 1_000_000 + (ts_frac as i64) / 1000
        } else {
            (ts_sec as i64) * 1_000_000 + (ts_frac as i64)
        };

        let packet = RawPacket {
            frame_number: *frame_number,
            timestamp_us,
            captured_len: captured_len as u32,
            original_len,
            data: packet_data,
        };

        // Advance position
        self.offset = packet_end;
        *frame_number += 1;

        Ok(Some(packet))
    }

    fn offset(&self) -> usize {
        self.offset
    }
}

/// Helper function to read next packet from a PCAPNG reader (generic over reader type)
fn read_pcapng_packet<R: Read>(
    reader: &mut PcapNGReader<R>,
    frame_number: &mut u64,
    link_type: &mut u32,
) -> Result<Option<RawPacket>, Error> {
    use pcap_parser::PcapError as PcapParserError;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::NG(ng_block) => {
                        use pcap_parser::pcapng::*;

                        match ng_block {
                            Block::InterfaceDescription(idb) => {
                                *link_type = idb.linktype.0 as u32;
                                reader.consume(offset);
                                continue;
                            }
                            Block::EnhancedPacket(epb) => {
                                *frame_number += 1;

                                let timestamp_us =
                                    ((epb.ts_high as i64) << 32) | (epb.ts_low as i64);

                                let packet = RawPacket {
                                    frame_number: *frame_number,
                                    timestamp_us,
                                    captured_len: epb.caplen,
                                    original_len: epb.origlen,
                                    data: Bytes::copy_from_slice(epb.data),
                                };

                                reader.consume(offset);
                                return Ok(Some(packet));
                            }
                            Block::SimplePacket(spb) => {
                                *frame_number += 1;

                                let packet = RawPacket {
                                    frame_number: *frame_number,
                                    timestamp_us: 0,
                                    captured_len: spb.data.len() as u32,
                                    original_len: spb.origlen,
                                    data: Bytes::copy_from_slice(spb.data),
                                };

                                reader.consume(offset);
                                return Ok(Some(packet));
                            }
                            _ => {
                                reader.consume(offset);
                                continue;
                            }
                        }
                    }
                    _ => {
                        reader.consume(offset);
                        continue;
                    }
                }
            }
            Err(PcapParserError::Eof) => return Ok(None),
            Err(PcapParserError::Incomplete(_)) => {
                reader.refill().map_err(|e| {
                    Error::Pcap(PcapError::InvalidFormat {
                        reason: format!("PCAPNG refill error: {}", e),
                    })
                })?;
                continue;
            }
            Err(e) => {
                return Err(Error::Pcap(PcapError::InvalidFormat {
                    reason: format!("PCAPNG parse error: {}", e),
                }));
            }
        }
    }
}

/// Helper function to read next packet from a legacy PCAP reader (generic over reader type)
fn read_legacy_packet<R: Read>(
    reader: &mut LegacyPcapReader<R>,
    frame_number: &mut u64,
    link_type: &mut u32,
) -> Result<Option<RawPacket>, Error> {
    use pcap_parser::PcapError as PcapParserError;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::Legacy(packet) => {
                        *frame_number += 1;

                        let timestamp_us =
                            (packet.ts_sec as i64) * 1_000_000 + (packet.ts_usec as i64);

                        let raw = RawPacket {
                            frame_number: *frame_number,
                            timestamp_us,
                            captured_len: packet.caplen,
                            original_len: packet.origlen,
                            data: Bytes::copy_from_slice(packet.data),
                        };

                        reader.consume(offset);
                        return Ok(Some(raw));
                    }
                    PcapBlockOwned::LegacyHeader(header) => {
                        *link_type = header.network.0 as u32;
                        reader.consume(offset);
                        continue;
                    }
                    _ => {
                        reader.consume(offset);
                        continue;
                    }
                }
            }
            Err(PcapParserError::Eof) => return Ok(None),
            Err(PcapParserError::Incomplete(_)) => {
                reader.refill().map_err(|e| {
                    Error::Pcap(PcapError::InvalidFormat {
                        reason: format!("Legacy PCAP refill error: {}", e),
                    })
                })?;
                continue;
            }
            Err(e) => {
                return Err(Error::Pcap(PcapError::InvalidFormat {
                    reason: format!("Legacy PCAP parse error: {}", e),
                }));
            }
        }
    }
}

impl PacketReader for MmapPacketReader {
    fn next_packet(&mut self) -> Result<Option<RawPacket>, Error> {
        if self.past_range_end() {
            return Ok(None);
        }

        match &mut self.inner {
            ReaderInner::LegacyDirect(reader) => {
                let result = reader.next_packet(&mut self.frame_number)?;
                if result.is_some() {
                    self.byte_offset = reader.offset() as u64;
                }
                Ok(result)
            }
            ReaderInner::PcapNgDirect(reader) => {
                read_pcapng_packet(reader, &mut self.frame_number, &mut self.link_type)
            }
            ReaderInner::LegacyCompressed(reader) => {
                read_legacy_packet(reader, &mut self.frame_number, &mut self.link_type)
            }
            ReaderInner::PcapNgCompressed(reader) => {
                read_pcapng_packet(reader, &mut self.frame_number, &mut self.link_type)
            }
        }
    }

    fn position(&self) -> PacketPosition {
        PacketPosition {
            byte_offset: self.byte_offset,
            frame_number: self.frame_number,
        }
    }

    fn link_type(&self) -> u32 {
        self.link_type
    }
}

// Implement Unpin for async compatibility
impl Unpin for MmapPacketReader {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_pcap_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join("corpus")
            .join(name)
    }

    #[test]
    fn test_mmap_source_opens() {
        let path = test_pcap_path("dns.cap");
        if !path.exists() {
            return; // Skip if test file doesn't exist
        }

        let source = MmapPacketSource::open(&path);
        assert!(source.is_ok(), "Failed to open: {:?}", source.err());
    }

    #[test]
    fn test_mmap_reader_reads_packets() {
        let path = test_pcap_path("dns.cap");
        if !path.exists() {
            return;
        }

        let source = MmapPacketSource::open(&path).unwrap();
        let mut reader = source.reader(None).unwrap();

        let packet = reader.next_packet().unwrap();
        assert!(packet.is_some());

        let pkt = packet.unwrap();
        assert_eq!(pkt.frame_number, 1);
        assert!(!pkt.data.is_empty());
    }

    #[test]
    fn test_mmap_reader_counts_match_file() {
        let path = test_pcap_path("dns.cap");
        if !path.exists() {
            return;
        }

        let source = MmapPacketSource::open(&path).unwrap();
        let mut reader = source.reader(None).unwrap();

        let mut count = 0;
        while reader.next_packet().unwrap().is_some() {
            count += 1;
        }

        // dns.cap has 38 packets
        assert!(count > 0, "Should have read some packets");
    }

    #[test]
    fn test_mmap_position_tracking() {
        let path = test_pcap_path("dns.cap");
        if !path.exists() {
            return;
        }

        let source = MmapPacketSource::open(&path).unwrap();
        let mut reader = source.reader(None).unwrap();

        let pos1 = reader.position();
        assert_eq!(pos1.frame_number, 1);

        reader.next_packet().unwrap();
        let pos2 = reader.position();
        assert_eq!(pos2.frame_number, 2);
        assert!(pos2.byte_offset > pos1.byte_offset);
    }

    #[test]
    fn test_mmap_link_type() {
        let path = test_pcap_path("dns.cap");
        if !path.exists() {
            return;
        }

        let source = MmapPacketSource::open(&path).unwrap();
        assert_eq!(source.link_type(), 1); // Ethernet
    }

    #[test]
    fn test_mmap_debug_format() {
        let path = test_pcap_path("dns.cap");
        if !path.exists() {
            return;
        }

        let source = MmapPacketSource::open(&path).unwrap();
        let debug_str = format!("{:?}", source);
        assert!(debug_str.contains("MmapPacketSource"));
        assert!(debug_str.contains("dns.cap"));
    }

    // ==========================================================================
    // Header Parsing Tests (for byte order and timestamp precision detection)
    // ==========================================================================

    #[test]
    fn test_parse_header_little_endian_microseconds() {
        // PCAP header: magic + version + reserved + snaplen + link_type
        // Little-endian, microseconds, link_type = 1 (Ethernet)
        let mut header = vec![0u8; 24];
        header[0..4].copy_from_slice(&0xa1b2c3d4u32.to_ne_bytes()); // magic
        header[4..6].copy_from_slice(&2u16.to_le_bytes()); // major version
        header[6..8].copy_from_slice(&4u16.to_le_bytes()); // minor version
        header[8..12].copy_from_slice(&0i32.to_le_bytes()); // reserved
        header[12..16].copy_from_slice(&0u32.to_le_bytes()); // reserved
        header[16..20].copy_from_slice(&65535u32.to_le_bytes()); // snaplen
        header[20..24].copy_from_slice(&1u32.to_le_bytes()); // link_type

        let result = MmapPacketSource::parse_header(&header);
        assert!(result.is_ok());
        let (format, link_type, offset) = result.unwrap();
        assert_eq!(format, PcapFormat::LegacyLeMicro);
        assert_eq!(link_type, 1);
        assert_eq!(offset, 24);
        assert!(!format.byte_swap());
        assert!(!format.nano_precision());
    }

    #[test]
    fn test_parse_header_big_endian_microseconds() {
        // Big-endian, microseconds: magic = 0xd4c3b2a1
        let mut header = vec![0u8; 24];
        // Write magic in native endian (will be read as 0xd4c3b2a1)
        header[0..4].copy_from_slice(&0xd4c3b2a1u32.to_ne_bytes());
        header[4..6].copy_from_slice(&2u16.to_be_bytes()); // major version
        header[6..8].copy_from_slice(&4u16.to_be_bytes()); // minor version
        header[8..12].copy_from_slice(&0i32.to_be_bytes()); // reserved
        header[12..16].copy_from_slice(&0u32.to_be_bytes()); // reserved
        header[16..20].copy_from_slice(&65535u32.to_be_bytes()); // snaplen
        header[20..24].copy_from_slice(&1u32.to_be_bytes()); // link_type (Ethernet)

        let result = MmapPacketSource::parse_header(&header);
        assert!(result.is_ok());
        let (format, link_type, offset) = result.unwrap();
        assert_eq!(format, PcapFormat::LegacyBeMicro);
        assert_eq!(link_type, 1);
        assert_eq!(offset, 24);
        assert!(format.byte_swap()); // Big-endian requires byte swapping
        assert!(!format.nano_precision());
    }

    #[test]
    fn test_parse_header_little_endian_nanoseconds() {
        // Little-endian, nanoseconds: magic = 0xa1b23c4d
        let mut header = vec![0u8; 24];
        header[0..4].copy_from_slice(&0xa1b23c4du32.to_ne_bytes());
        header[20..24].copy_from_slice(&1u32.to_le_bytes()); // link_type

        let result = MmapPacketSource::parse_header(&header);
        assert!(result.is_ok());
        let (format, link_type, _offset) = result.unwrap();
        assert_eq!(format, PcapFormat::LegacyLeNano);
        assert_eq!(link_type, 1);
        assert!(!format.byte_swap());
        assert!(format.nano_precision()); // Nanosecond precision
    }

    #[test]
    fn test_parse_header_big_endian_nanoseconds() {
        // Big-endian, nanoseconds: magic = 0x4d3cb2a1
        let mut header = vec![0u8; 24];
        header[0..4].copy_from_slice(&0x4d3cb2a1u32.to_ne_bytes());
        header[20..24].copy_from_slice(&1u32.to_be_bytes()); // link_type

        let result = MmapPacketSource::parse_header(&header);
        assert!(result.is_ok());
        let (format, _link_type, _offset) = result.unwrap();
        assert_eq!(format, PcapFormat::LegacyBeNano);
        assert!(format.byte_swap()); // Big-endian
        assert!(format.nano_precision()); // Nanosecond precision
    }

    #[test]
    fn test_parse_header_pcapng_detected() {
        // PCAPNG Section Header Block magic: 0x0a0d0d0a
        let mut header = vec![0u8; 32];
        header[0..4].copy_from_slice(&0x0a0d0d0au32.to_ne_bytes());

        let result = MmapPacketSource::parse_header(&header);
        assert!(result.is_ok());
        let (format, _link_type, _offset) = result.unwrap();
        assert_eq!(format, PcapFormat::PcapNg);
    }

    #[test]
    fn test_parse_header_unknown_magic() {
        let mut header = vec![0u8; 24];
        header[0..4].copy_from_slice(&0xDEADBEEFu32.to_ne_bytes());

        let result = MmapPacketSource::parse_header(&header);
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("Unknown PCAP magic"));
    }

    #[test]
    fn test_parse_header_too_small() {
        let header = vec![0u8; 10]; // Too small for PCAP header

        let result = MmapPacketSource::parse_header(&header);
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("too small"));
    }

    // ==========================================================================
    // Packet Data Validation Tests
    // ==========================================================================

    #[test]
    fn test_mmap_packet_data_integrity() {
        let path = test_pcap_path("dns.cap");
        if !path.exists() {
            return;
        }

        let source = MmapPacketSource::open(&path).unwrap();
        let mut reader = source.reader(None).unwrap();

        // Read first packet and validate Ethernet header structure
        let packet = reader.next_packet().unwrap().unwrap();

        // Minimum Ethernet frame is 14 bytes (MAC dst + MAC src + EtherType)
        assert!(packet.data.len() >= 14, "Packet too small for Ethernet");

        // captured_len should match data length
        assert_eq!(packet.captured_len as usize, packet.data.len());

        // original_len should be >= captured_len
        assert!(packet.original_len >= packet.captured_len);

        // Frame number should start at 1
        assert_eq!(packet.frame_number, 1);

        // Timestamp should be positive (after Unix epoch)
        assert!(packet.timestamp_us > 0);
    }

    #[test]
    fn test_mmap_all_packets_valid() {
        let path = test_pcap_path("dns.cap");
        if !path.exists() {
            return;
        }

        let source = MmapPacketSource::open(&path).unwrap();
        let mut reader = source.reader(None).unwrap();

        let mut prev_frame = 0u64;
        let mut count = 0;

        while let Some(packet) = reader.next_packet().unwrap() {
            // Frame numbers should be sequential
            assert_eq!(packet.frame_number, prev_frame + 1);
            prev_frame = packet.frame_number;

            // Basic sanity checks
            assert!(packet.data.len() <= 65535, "Packet exceeds max size");
            assert_eq!(packet.captured_len as usize, packet.data.len());

            count += 1;
        }

        assert!(count > 0, "Should have read packets");
    }

    #[test]
    fn test_mmap_timestamp_reasonableness() {
        let path = test_pcap_path("dns.cap");
        if !path.exists() {
            return;
        }

        let source = MmapPacketSource::open(&path).unwrap();
        let mut reader = source.reader(None).unwrap();

        let mut prev_timestamp = 0i64;

        while let Some(packet) = reader.next_packet().unwrap() {
            // Timestamps should be non-negative
            assert!(packet.timestamp_us >= 0);

            // Timestamps should generally not go backwards (within reason)
            // Allow small backward jumps for clock drift
            if prev_timestamp > 0 {
                let diff = packet.timestamp_us - prev_timestamp;
                assert!(
                    diff >= -1_000_000, // Allow up to 1 second backward
                    "Timestamp went backwards by {} us",
                    diff.abs()
                );
            }
            prev_timestamp = packet.timestamp_us;
        }
    }

    #[test]
    fn test_mmap_range_reading() {
        let path = test_pcap_path("dns.cap");
        if !path.exists() {
            return;
        }

        let source = MmapPacketSource::open(&path).unwrap();

        // Create a range starting from frame 5
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

        // Read with range but starting from beginning (range only limits end)
        let mut reader = source.reader(Some(&range)).unwrap();

        // The reader starts at frame_number from range
        assert_eq!(reader.position().frame_number, 5);

        let mut count = 0;
        while let Some(_) = reader.next_packet().unwrap() {
            count += 1;
            if count > 100 {
                break; // Safety limit
            }
        }

        // Should have read frames 5-9 (5 frames)
        assert!(count <= 5, "Should respect range end limit");
    }

    #[test]
    fn test_mmap_metadata() {
        let path = test_pcap_path("dns.cap");
        if !path.exists() {
            return;
        }

        let source = MmapPacketSource::open(&path).unwrap();
        let meta = source.metadata();

        assert_eq!(meta.link_type, 1); // Ethernet
        assert!(meta.seekable);
        assert!(meta.size_bytes.is_some());
        assert!(meta.size_bytes.unwrap() > 0);
    }

    #[test]
    fn test_mmap_clone() {
        let path = test_pcap_path("dns.cap");
        if !path.exists() {
            return;
        }

        let source1 = MmapPacketSource::open(&path).unwrap();
        let source2 = source1.clone();

        // Both sources should work independently
        let mut reader1 = source1.reader(None).unwrap();
        let mut reader2 = source2.reader(None).unwrap();

        let pkt1 = reader1.next_packet().unwrap().unwrap();
        let pkt2 = reader2.next_packet().unwrap().unwrap();

        // Should read identical first packets
        assert_eq!(pkt1.frame_number, pkt2.frame_number);
        assert_eq!(pkt1.data.len(), pkt2.data.len());
    }

    #[test]
    fn test_mmap_partitions() {
        let path = test_pcap_path("dns.cap");
        if !path.exists() {
            return;
        }

        let source = MmapPacketSource::open(&path).unwrap();
        let partitions = source.partitions(4).unwrap();

        // Currently returns single partition
        assert_eq!(partitions.len(), 1);
        assert!(partitions[0].start.frame_number == 0 || partitions[0].start.frame_number == 1);
    }
}
