//! Packet source trait hierarchy and the file-backed implementation.
//!
//! The source layer is split into two traits that reflect what backends can
//! *actually* do, rather than a single trait that over-promises:
//!
//! - [`PacketSource`] is the floor: every backend can be read sequentially from
//!   the first frame. Pipes, compressed streams, and seekable files all qualify.
//! - [`SeekablePacketSource`] is an opt-in capability for backends that genuinely
//!   support random access at a packet boundary. It carries a [`SeekCost`] hint so
//!   the query planner can decide whether parallel partitioning is worthwhile.
//!
//! A backend that cannot seek (a pipe, a standard-framed compressed stream)
//! simply does not implement [`SeekablePacketSource`], so asking it to seek is a
//! compile-time impossibility — there is no runtime `seekable` flag to lie.

use std::fs::File;
use std::io::{Chain, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::error::{Error, PcapError};
use crate::io::decompress::{decompress_header, Compression, DecompressReader};
use crate::io::index::{self, BoundaryIndex};
use crate::io::pcap_stream::{GenericPcapReader, PcapFormat};

/// Borrowed packet reference - zero-copy view into the parser buffer.
///
/// Passed to `process_packets()` callbacks; valid only for the callback's
/// duration. Timestamps are nanoseconds since the Unix epoch.
#[derive(Debug, Clone, Copy)]
pub struct PacketRef<'a> {
    /// Frame number (1-indexed, matching Wireshark)
    pub frame_number: u64,
    /// Timestamp in nanoseconds since Unix epoch
    pub timestamp_ns: i64,
    /// Captured length (may be less than original)
    pub captured_len: u32,
    /// Original packet length on the wire
    pub original_len: u32,
    /// Link layer type (e.g., 1 = Ethernet)
    pub link_type: u16,
    /// Packet data (borrowed from the parser buffer)
    pub data: &'a [u8],
}

impl<'a> PacketRef<'a> {
    /// Check if the packet was truncated during capture.
    #[inline]
    pub fn is_truncated(&self) -> bool {
        self.captured_len < self.original_len
    }
}

/// Position within a packet source (for seeking/checkpointing).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PacketPosition {
    /// Byte offset in the underlying (uncompressed) source
    pub byte_offset: u64,
    /// Frame number at this position (1-indexed, matching Wireshark)
    pub frame_number: u64,
}

impl PacketPosition {
    /// Position at the start of the source.
    pub const START: Self = Self {
        byte_offset: 0,
        frame_number: 1,
    };
}

/// Range of packets for partitioning.
#[derive(Clone, Debug)]
pub struct PacketRange {
    /// Start position (inclusive). `byte_offset` MUST land on a record boundary.
    pub start: PacketPosition,
    /// End position (exclusive). None means read to EOF.
    pub end: Option<PacketPosition>,
}

impl PacketRange {
    /// Range covering the entire source.
    pub fn whole() -> Self {
        Self {
            start: PacketPosition::START,
            end: None,
        }
    }

    /// Check if a frame number is within this range.
    pub fn contains(&self, frame_number: u64) -> bool {
        frame_number >= self.start.frame_number
            && self
                .end
                .as_ref()
                .is_none_or(|e| frame_number < e.frame_number)
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
    /// Total packet count (if known, e.g., from an index)
    pub packet_count: Option<u64>,
}

/// A source that can be read sequentially from the beginning.
///
/// This is the floor every backend meets. It deliberately exposes neither
/// `reader(range)` nor `partitions` — random access is the separate
/// [`SeekablePacketSource`] capability.
pub trait PacketSource: Send + Sync + Clone + 'static {
    /// The reader type this source produces.
    type Reader: PacketReader;

    /// Get metadata about this source.
    fn metadata(&self) -> &PacketSourceMetadata;

    /// Create a sequential reader over the whole source, from the first frame.
    /// Always available for every backend.
    fn sequential_reader(&self) -> Result<Self::Reader, Error>;

    /// Get the link type for this source.
    fn link_type(&self) -> u32 {
        self.metadata().link_type
    }
}

/// Cost of starting a reader at an arbitrary packet boundary.
///
/// Lets the planner decide whether parallelism is worth it for this source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeekCost {
    /// Free: slicing shared immutable memory (mmap). Parallelize aggressively.
    Free,
    /// Cheap: a local seek or extra file descriptor. Parallelize for large files.
    Cheap,
    /// Expensive: a network round trip per range (cloud range GET).
    /// Parallelize only when the object is large enough to amortize round trips.
    RangeRequest,
}

/// A source that can start a reader partway through, at a packet boundary.
///
/// Implemented only by backends that genuinely support random access. A source
/// whose bytes are compressed in a non-seekable framing must report a
/// single-partition plan from [`partitions`](SeekablePacketSource::partitions)
/// (it cannot split the compressed stream), even though the type is seekable for
/// its uncompressed form.
pub trait SeekablePacketSource: PacketSource {
    /// Cost hint used by the planner to gate parallelism.
    fn seek_cost(&self) -> SeekCost;

    /// Create a reader restricted to a packet range. `range.start.byte_offset`
    /// MUST land exactly on a record boundary (guaranteed by the boundary index).
    fn reader_at(&self, range: &PacketRange) -> Result<Self::Reader, Error>;

    /// Compute up to `max` non-overlapping ranges that cover the source.
    /// Builds (or loads) the boundary index as needed.
    fn partitions(&self, max: usize) -> Result<Vec<PacketRange>, Error>;
}

/// Sequential reader of packets from a source (the hot path).
///
/// ## Headerless / mid-file starts
///
/// A reader created via [`SeekablePacketSource::reader_at`] for a range whose
/// start is not frame 1 begins parsing at the given byte offset. It must NOT
/// attempt to read a global/section header from the stream at that offset: link
/// type and starting frame number come from the index, supplied to the reader by
/// the source (in practice via a synthesized header prepended to the byte
/// stream). The starting frame number is honored so frame numbers are globally
/// correct without cross-partition coordination.
pub trait PacketReader: Send + Unpin {
    /// Process up to `max` packets with borrowed data via callback.
    fn process_packets<F>(&mut self, max: usize, f: F) -> Result<usize, Error>
    where
        F: FnMut(PacketRef<'_>) -> Result<(), Error>;

    /// Current position in the source.
    fn position(&self) -> PacketPosition;

    /// Get the link type for packets from this reader.
    fn link_type(&self) -> u32;
}

/// The concrete `Read` stack used by file readers: an optional synthesized header
/// (empty for sequential reads) chained before the (possibly seeked) file,
/// wrapped in decompression.
type FileInner = GenericPcapReader<DecompressReader<Chain<Cursor<Vec<u8>>, File>>>;

/// Packet source backed by a PCAP/PCAPNG file on the local filesystem.
#[derive(Clone)]
pub struct FilePacketSource {
    path: PathBuf,
    metadata: PacketSourceMetadata,
    compression: Compression,
    pcap_format: PcapFormat,
    /// Lazily built / sidecar-loaded boundary index (uncompressed only).
    index: Arc<Mutex<Option<Arc<BoundaryIndex>>>>,
    index_stride: u64,
    source_mtime: Option<SystemTime>,
    header_hash: u64,
}

impl FilePacketSource {
    /// Open a PCAP file as a packet source.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();
        let detected = detect_file(&path)?;
        let metadata = PacketSourceMetadata {
            link_type: detected.link_type,
            snaplen: detected.snaplen,
            size_bytes: Some(detected.size),
            packet_count: None,
        };
        Ok(Self {
            path,
            metadata,
            compression: detected.compression,
            pcap_format: detected.format,
            index: Arc::new(Mutex::new(None)),
            index_stride: index::DEFAULT_CHECKPOINT_STRIDE,
            source_mtime: detected.mtime,
            header_hash: detected.header_hash,
        })
    }

    /// Get the path to the file.
    pub fn file_path(&self) -> &Path {
        &self.path
    }

    /// Set the checkpoint stride for index building (smaller = finer partitions).
    pub fn with_index_stride(mut self, stride: u64) -> Self {
        self.index_stride = stride.max(1);
        self
    }

    /// Whether the underlying bytes are compressed (and thus not splittable).
    pub fn is_compressed(&self) -> bool {
        self.compression.is_compressed()
    }

    /// Build or load the boundary index (uncompressed sources only).
    fn ensure_index(&self) -> Result<Arc<BoundaryIndex>, Error> {
        if self.compression.is_compressed() {
            return Err(Error::Pcap(PcapError::InvalidFormat {
                reason: "compressed sources are not seekable; cannot build boundary index".into(),
            }));
        }
        let mut guard = self.index.lock().expect("index mutex poisoned");
        if let Some(idx) = guard.as_ref() {
            return Ok(idx.clone());
        }

        let sidecar = index::sidecar_path(&self.path);
        // Try the sidecar cache first, validating it against the file.
        if let Ok(idx) = BoundaryIndex::read_sidecar(&sidecar) {
            if idx.stride == self.index_stride
                && idx.is_valid_for(
                    self.metadata.size_bytes.unwrap_or(0),
                    self.source_mtime,
                    self.header_hash,
                )
            {
                let idx = Arc::new(idx);
                *guard = Some(idx.clone());
                return Ok(idx);
            }
        }

        // Build by scanning the uncompressed file.
        let file = File::open(&self.path).map_err(Error::Io)?;
        let idx = index::build_boundary_index(
            file,
            self.pcap_format,
            self.index_stride,
            self.metadata.size_bytes.unwrap_or(0),
            self.source_mtime,
            self.header_hash,
        )?;
        // Best-effort sidecar persistence.
        let _ = idx.write_sidecar(&sidecar);
        let idx = Arc::new(idx);
        *guard = Some(idx.clone());
        Ok(idx)
    }
}

impl std::fmt::Debug for FilePacketSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilePacketSource")
            .field("path", &self.path)
            .field("compression", &self.compression)
            .field("pcap_format", &self.pcap_format)
            .field("link_type", &self.metadata.link_type)
            .finish()
    }
}

impl PacketSource for FilePacketSource {
    type Reader = FilePacketReader;

    fn metadata(&self) -> &PacketSourceMetadata {
        &self.metadata
    }

    fn sequential_reader(&self) -> Result<Self::Reader, Error> {
        FilePacketReader::sequential(&self.path, self.compression, self.pcap_format)
    }
}

impl SeekablePacketSource for FilePacketSource {
    fn seek_cost(&self) -> SeekCost {
        SeekCost::Cheap
    }

    fn reader_at(&self, range: &PacketRange) -> Result<Self::Reader, Error> {
        // Compressed sources are not splittable; only the whole-file range is
        // meaningful, which is exactly a sequential read.
        if self.compression.is_compressed() {
            return self.sequential_reader();
        }
        let idx = self.ensure_index()?;
        let header = synth_header_for(&idx, range.start.frame_number, self.pcap_format)?;
        let end_frame = range.end.as_ref().map(|e| e.frame_number);
        FilePacketReader::at(
            &self.path,
            self.pcap_format,
            header,
            range.start.byte_offset,
            range.start.frame_number,
            end_frame,
        )
    }

    fn partitions(&self, max: usize) -> Result<Vec<PacketRange>, Error> {
        if self.compression.is_compressed() {
            // Cannot split a non-seekable compressed stream.
            return Ok(vec![PacketRange::whole()]);
        }
        let idx = self.ensure_index()?;
        Ok(idx.partition_ranges(max))
    }
}

/// Sequential packet reader for PCAP files.
pub struct FilePacketReader {
    inner: FileInner,
    link_type: u32,
    end_frame: Option<u64>,
}

impl FilePacketReader {
    /// Open a sequential reader over the whole file (honors compression).
    fn sequential(
        path: &Path,
        compression: Compression,
        format: PcapFormat,
    ) -> Result<Self, Error> {
        let file = File::open(path).map_err(Error::Io)?;
        let chain = Cursor::new(Vec::new()).chain(file);
        let decode = DecompressReader::new(chain, compression).map_err(|e| {
            Error::Pcap(PcapError::InvalidFormat {
                reason: format!("decompressor: {e}"),
            })
        })?;
        let inner = GenericPcapReader::with_format(decode, format)?;
        let link_type = inner.link_type();
        Ok(Self {
            inner,
            link_type,
            end_frame: None,
        })
    }

    /// Open a reader at a byte offset, prepending a synthesized header so the
    /// parser establishes link type / interface state without a real header at
    /// the offset. Uncompressed sources only.
    fn at(
        path: &Path,
        format: PcapFormat,
        synth_header: Vec<u8>,
        byte_offset: u64,
        start_frame: u64,
        end_frame: Option<u64>,
    ) -> Result<Self, Error> {
        let mut file = File::open(path).map_err(Error::Io)?;
        file.seek(SeekFrom::Start(byte_offset)).map_err(Error::Io)?;
        let chain = Cursor::new(synth_header).chain(file);
        let decode = DecompressReader::new(chain, Compression::None).map_err(|e| {
            Error::Pcap(PcapError::InvalidFormat {
                reason: format!("decompressor: {e}"),
            })
        })?;
        let inner = GenericPcapReader::with_format_starting_at(decode, format, start_frame)?;
        let link_type = inner.link_type();
        Ok(Self {
            inner,
            link_type,
            end_frame,
        })
    }
}

impl PacketReader for FilePacketReader {
    fn process_packets<F>(&mut self, max: usize, f: F) -> Result<usize, Error>
    where
        F: FnMut(PacketRef<'_>) -> Result<(), Error>,
    {
        // `end_frame` is exclusive: emit frames with number < end_frame.
        let effective_max = match self.end_frame {
            Some(end) => {
                let current = self.inner.frame_count();
                let remaining = end.saturating_sub(current).saturating_sub(1);
                if remaining == 0 {
                    return Ok(0);
                }
                max.min(remaining as usize)
            }
            None => max,
        };
        let count = self.inner.process_packets(effective_max, f)?;
        self.link_type = self.inner.link_type();
        Ok(count)
    }

    #[inline]
    fn position(&self) -> PacketPosition {
        PacketPosition {
            byte_offset: self.inner.consumed_bytes(),
            frame_number: self.inner.frame_count(),
        }
    }

    fn link_type(&self) -> u32 {
        self.link_type
    }
}

/// Synthesize the header bytes a mid-file partition needs for `start_frame`.
pub(crate) fn synth_header_for(
    idx: &BoundaryIndex,
    start_frame: u64,
    format: PcapFormat,
) -> Result<Vec<u8>, Error> {
    let cp = idx.checkpoint_at(start_frame).ok_or_else(|| {
        Error::Pcap(PcapError::InvalidFormat {
            reason: format!("no index checkpoint at frame {start_frame}"),
        })
    })?;
    if format.is_pcapng() {
        let state = cp.interface_state.as_ref().ok_or_else(|| {
            Error::Pcap(PcapError::InvalidFormat {
                reason: "PCAPNG checkpoint missing interface state".into(),
            })
        })?;
        Ok(index::synth_pcapng_header(state))
    } else {
        Ok(index::synth_legacy_header(
            format,
            idx.link_type,
            idx.snaplen,
        ))
    }
}

/// Detected properties of a file source.
struct FileDetected {
    compression: Compression,
    format: PcapFormat,
    link_type: u32,
    snaplen: u32,
    size: u64,
    mtime: Option<SystemTime>,
    header_hash: u64,
}

/// Detect compression, format, link type and validity-guard fields of a file.
fn detect_file(path: &Path) -> Result<FileDetected, Error> {
    let meta = std::fs::metadata(path).map_err(|_| {
        Error::Pcap(PcapError::FileNotFound {
            path: path.display().to_string(),
        })
    })?;
    let size = meta.len();
    let mtime = meta.modified().ok();

    let mut file = File::open(path).map_err(|_| {
        Error::Pcap(PcapError::FileNotFound {
            path: path.display().to_string(),
        })
    })?;
    let mut head = vec![0u8; 4096.min(size as usize).max(4)];
    let n = file.read(&mut head).map_err(Error::Io)?;
    head.truncate(n);

    let compression = Compression::detect(&head);
    let header_hash = index::header_hash(&head);

    // Decompress enough to read the format + legacy header fields.
    let decompressed = decompress_header(&head, compression, 64).map_err(|e| {
        Error::Pcap(PcapError::InvalidFormat {
            reason: format!("failed to read header: {e}"),
        })
    })?;
    let format = PcapFormat::detect(&decompressed)?;
    let (link_type, snaplen) = if format.is_pcapng() {
        (1, 65535)
    } else if decompressed.len() >= 24 {
        let be = format.is_big_endian();
        let snaplen = read_u32(&decompressed[16..20], be);
        let link_type = read_u32(&decompressed[20..24], be);
        (link_type, snaplen)
    } else {
        (1, 65535)
    };

    Ok(FileDetected {
        compression,
        format,
        link_type,
        snaplen,
        size,
        mtime,
        header_hash,
    })
}

fn read_u32(b: &[u8], be: bool) -> u32 {
    let a = [b[0], b[1], b[2], b[3]];
    if be {
        u32::from_be_bytes(a)
    } else {
        u32::from_le_bytes(a)
    }
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
