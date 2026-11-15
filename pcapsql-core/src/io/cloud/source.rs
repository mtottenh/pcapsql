//! The packet source and reader over a cloud object, and the local cache of
//! its boundary index.

use std::io::{self, Chain, Cursor, Read};
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use object_store::{path::Path as ObjectPath, ObjectStore};
use tokio::runtime::Handle;

use super::location::CloudLocation;
use super::object_reader::{head_object, ObjectHead, ObjectStoreReader};
use super::runtime::{run_async, saveable_handle};
use crate::error::Error;
use crate::io::index::{self, BoundaryIndex};
use crate::io::pcap_stream::{Delivered, Pause};
use crate::io::read_source::process_bounded;
use crate::io::source::{starts_at_header, synth_header_for};
use crate::io::{
    decompress_header, Compression, DecompressReader, GenericPcapReader, PacketPosition,
    PacketRange, PacketReader, PacketRef, PacketSource, PacketSourceMetadata, PcapFormat, SeekCost,
    SeekablePacketSource,
};

/// Header size for initial read-ahead (64KB).
/// This should be large enough to contain:
/// - Compression magic bytes (up to 6 bytes)
/// - PCAP file header (24 bytes for legacy, ~32 bytes for pcapng)
/// - First few packet headers
///
/// We use 64KB to handle compressed files where the actual header
/// may expand from compressed data.
const HEADER_READ_SIZE: usize = 64 * 1024;

/// Directory for cached boundary indexes of remote objects, if one can be
/// determined. `None` disables caching (the index is rebuilt per open).
fn index_cache_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("PCAPSQL_INDEX_CACHE") {
        return (!dir.is_empty()).then(|| PathBuf::from(dir));
    }
    if let Some(dir) = std::env::var_os("XDG_CACHE_HOME") {
        if !dir.is_empty() {
            return Some(PathBuf::from(dir).join("pcapsql").join("index"));
        }
    }
    std::env::var_os("HOME").filter(|h| !h.is_empty()).map(|h| {
        PathBuf::from(h)
            .join(".cache")
            .join("pcapsql")
            .join("index")
    })
}

/// Cache file for a location's boundary index: `<cache-dir>/<fnv(url)>.idx`.
fn index_cache_path(location: &CloudLocation) -> Option<PathBuf> {
    let key = format!(
        "{}://{}/{}@{}",
        location.scheme(),
        location.bucket().unwrap_or(""),
        location.key(),
        location.endpoint().unwrap_or("")
    );
    index_cache_dir().map(|d| d.join(format!("{:016x}.idx", index::header_hash(key.as_bytes()))))
}
/// Cloud-backed packet source.
///
/// Implements [`PacketSource`] for cloud storage objects, enabling PCAP files
/// stored in S3/GCS/Azure to be queried directly.
#[derive(Clone)]
pub struct CloudPacketSource {
    location: CloudLocation,
    /// The store and object path, built once and shared by every reader
    /// (partition readers issue no HEAD and build no client of their own).
    store: Arc<dyn ObjectStore>,
    path: ObjectPath,
    object_size: u64,
    /// Object last-modified time from HEAD (validity guard for the cached index).
    last_modified: Option<SystemTime>,
    /// Object entity tag from HEAD (validity guard for the cached index).
    e_tag: Option<String>,
    metadata: PacketSourceMetadata,
    compression: Compression,
    pcap_format: PcapFormat,
    /// Lazily built boundary index (uncompressed objects only).
    index: Arc<Mutex<Option<Arc<BoundaryIndex>>>>,
    index_stride: u64,
    header_hash: u64,
    /// Runtime the source was opened under, for requests from plain threads.
    handle: Option<Handle>,
    /// Bytes fetched over the network by every reader of this source.
    fetched: Arc<AtomicU64>,
}

impl CloudPacketSource {
    /// Open a cloud object as a packet source.
    ///
    /// This method is optimized to minimize HTTP requests:
    /// - 1 HEAD request to get object size
    /// - 1 GET request for initial header (64KB)
    /// - In-memory decompression and parsing (no additional requests)
    ///
    /// Can be called from both sync and async contexts - handles runtime
    /// nesting correctly: blocking I/O runs in place on a multi-thread
    /// runtime and on a dedicated I/O runtime otherwise (see `run_async`).
    pub fn open(location: CloudLocation) -> Result<Self, Error> {
        // Build object store
        let store = location.build_store()?;
        let path = location.object_path();

        let handle = saveable_handle();
        let fetched = Arc::new(AtomicU64::new(0));

        // 1. HEAD request: object size, plus last-modified and e-tag for the
        //    index cache's validity guard.
        let ObjectHead {
            size: object_size,
            last_modified,
            e_tag,
        } = head_object(&store, &path, handle.as_ref())?;
        // The index cache stores e-tags up to a fixed length; an absurd one
        // is dropped here so the guard compares absent with absent.
        let e_tag = e_tag.filter(|t| t.len() <= index::MAX_ETAG_BYTES);

        if object_size < 24 {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "Cloud object too small to be a valid PCAP (< 24 bytes)",
            )));
        }

        // 2. Single GET request for header (64KB or file size, whichever is smaller)
        let header_size = HEADER_READ_SIZE.min(object_size as usize);
        let store_clone = Arc::clone(&store);
        let path_clone = path.clone();
        let header_bytes = run_async(handle.as_ref(), async move {
            let range = std::ops::Range {
                start: 0,
                end: header_size,
            };
            let bytes = store_clone
                .get_range(&path_clone, range)
                .await
                .map_err(|e| {
                    Error::Io(io::Error::other(format!(
                        "Failed to fetch cloud object header: {e}"
                    )))
                })?;
            Ok::<Vec<u8>, Error>(bytes.to_vec())
        })?;
        fetched.fetch_add(header_bytes.len() as u64, Ordering::Relaxed);

        if header_bytes.len() < 6 {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "Cloud object too small to be a valid PCAP",
            )));
        }

        // 3. Detect compression from header bytes (in-memory, no HTTP)
        let compression = Compression::detect(&header_bytes);

        // 4. Get decompressed header for PCAP parsing (in-memory, no HTTP).
        //    The whole fetched prefix is decompressed so the pcapng IDB walk
        //    below sees as far as the fetch did.
        let decompressed_header = decompress_header(&header_bytes, compression, HEADER_READ_SIZE)
            .map_err(|e| {
            Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to decompress header: {e}"),
            ))
        })?;

        if decompressed_header.len() < 4 {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "Decompressed header too small for PCAP magic",
            )));
        }

        // 5. Detect PCAP format from decompressed magic bytes
        let pcap_magic = [
            decompressed_header[0],
            decompressed_header[1],
            decompressed_header[2],
            decompressed_header[3],
        ];
        let pcap_format = PcapFormat::detect(&pcap_magic)?;

        // 6. Parse link type from decompressed header (in-memory, no HTTP)
        let link_type = Self::parse_link_type_from_header(&decompressed_header, pcap_format)?;

        let metadata = PacketSourceMetadata {
            link_type,
            snaplen: 65535,
            size_bytes: Some(object_size),
            packet_count: None, // Filled by the index if built
        };

        let header_hash = index::header_hash(&header_bytes);

        Ok(Self {
            location,
            store,
            path,
            object_size,
            last_modified,
            e_tag,
            metadata,
            compression,
            pcap_format,
            index: Arc::new(Mutex::new(None)),
            index_stride: index::DEFAULT_CHECKPOINT_STRIDE,
            header_hash,
            handle,
            fetched,
        })
    }

    /// Total bytes fetched over the network by this source and all its readers.
    pub fn bytes_fetched(&self) -> u64 {
        self.fetched.load(Ordering::Relaxed)
    }

    /// A reader over the raw object bytes, reusing the source's store, size and
    /// runtime handle (no HEAD request).
    fn raw_reader(&self, start: u64, end: Option<u64>) -> ObjectStoreReader {
        ObjectStoreReader::new(
            Arc::clone(&self.store),
            self.path.clone(),
            self.object_size,
            self.location.chunk_size(),
            self.handle.clone(),
            Arc::clone(&self.fetched),
        )
        .starting_at(start, end)
    }

    /// Set the checkpoint stride for index building (smaller = finer partitions).
    pub fn with_index_stride(mut self, stride: u64) -> Self {
        self.index_stride = stride.max(1);
        self
    }

    /// Build (and memoize) the boundary index of the uncompressed object.
    ///
    /// Building needs one full sequential read of the object, so the result is
    /// cached on local disk (see the module docs) and validated against the
    /// object's size, last-modified time, e-tag and header hash before reuse.
    /// Subsequent partition reads use exact offsets from the index.
    fn ensure_index(&self) -> Result<Arc<BoundaryIndex>, Error> {
        if self.compression.is_compressed() {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "compressed cloud objects are not seekable; cannot build boundary index",
            )));
        }
        let mut guard = self.index.lock().expect("index mutex poisoned");
        if let Some(idx) = guard.as_ref() {
            return Ok(idx.clone());
        }

        let cache_path = index_cache_path(&self.location);
        if let Some(cached) = cache_path
            .as_deref()
            .and_then(|p| BoundaryIndex::read_sidecar(p).ok())
        {
            if cached.stride == self.index_stride
                && cached.matches_source(
                    self.object_size,
                    self.last_modified,
                    self.header_hash,
                    self.e_tag.as_deref(),
                )
            {
                let idx = Arc::new(cached);
                *guard = Some(idx.clone());
                return Ok(idx);
            }
        }

        let reader = self.raw_reader(0, None);
        let mut idx = index::build_boundary_index(
            reader,
            self.pcap_format,
            self.index_stride,
            self.object_size,
            self.last_modified,
            self.header_hash,
        )?;
        idx.source_etag = self.e_tag.clone();
        // Always persisted (unlike local files): rebuilding means another
        // full read of the object over the network.
        if let Some(p) = cache_path.as_deref() {
            // Best effort: a missing or read-only cache dir just means no reuse.
            if let Some(dir) = p.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let _ = idx.write_sidecar(p);
        }
        let idx = Arc::new(idx);
        *guard = Some(idx.clone());
        Ok(idx)
    }

    /// Parse link type from decompressed PCAP header bytes.
    pub(super) fn parse_link_type_from_header(
        header: &[u8],
        format: PcapFormat,
    ) -> Result<u32, Error> {
        if format.is_pcapng() {
            // PCAPNG: Link type is in the Interface Description Block (IDB)
            // which comes after the Section Header Block (SHB).
            // Parse from the in-memory buffer using a cursor.
            Self::parse_pcapng_link_type(header)
        } else {
            // Legacy PCAP file header structure:
            // - Magic (4 bytes)
            // - Version major (2 bytes)
            // - Version minor (2 bytes)
            // - Timezone (4 bytes)
            // - Sigfigs (4 bytes)
            // - Snaplen (4 bytes)
            // - Link type (4 bytes)
            // Total: 24 bytes
            if header.len() < 24 {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Header too small for link type: {} bytes (need 24)",
                        header.len()
                    ),
                )));
            }

            // Link type is at offset 20, read as u32
            let link_type = if format.is_little_endian() {
                u32::from_le_bytes([header[20], header[21], header[22], header[23]])
            } else {
                u32::from_be_bytes([header[20], header[21], header[22], header[23]])
            };

            Ok(link_type)
        }
    }

    /// Parse the first interface's link type from the leading PCAPNG bytes.
    ///
    /// Walks the blocks after the Section Header Block until the first
    /// Interface Description Block, skipping anything else (comments, name
    /// resolution, custom blocks). When no IDB lies within the fetched prefix
    /// (`HEADER_READ_SIZE`), the link type defaults to Ethernet like a local
    /// pcapng source: the per-packet link type the readers report comes from
    /// the real IDBs anyway, this value is only the source-level hint.
    pub(super) fn parse_pcapng_link_type(header: &[u8]) -> Result<u32, Error> {
        // Minimum size: SHB (28 bytes) up to and including its byte-order magic.
        if header.len() < 12 {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "Header too small for PCAPNG section header",
            )));
        }

        // Detect endianness from the Byte-Order Magic at offset 8 by matching
        // the raw on-disk byte pattern (host byte order must not matter).
        let bom = [header[8], header[9], header[10], header[11]];
        let is_le = bom == [0x4D, 0x3C, 0x2B, 0x1A];
        let is_be = bom == [0x1A, 0x2B, 0x3C, 0x4D];
        if !is_le && !is_be {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid PCAPNG byte-order magic: {bom:02x?}"),
            )));
        }
        let u32_at = |off: usize| -> Option<u32> {
            let b = header.get(off..off + 4)?;
            let b = [b[0], b[1], b[2], b[3]];
            Some(if is_le {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            })
        };

        // Walk block by block: type (4), total length (4), body, length (4).
        let mut off = 0usize;
        while let (Some(block_type), Some(total_len)) = (u32_at(off), u32_at(off + 4)) {
            let total_len = total_len as usize;
            if total_len < 12 || !total_len.is_multiple_of(4) {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid PCAPNG block length {total_len} at offset {off}"),
                )));
            }
            if block_type == 1 {
                // IDB: link type is the u16 at offset 8 within the block.
                return match header.get(off + 8..off + 10) {
                    Some(b) => Ok(u32::from(if is_le {
                        u16::from_le_bytes([b[0], b[1]])
                    } else {
                        u16::from_be_bytes([b[0], b[1]])
                    })),
                    None => Ok(1),
                };
            }
            off += total_len;
        }
        Ok(1)
    }

    /// Get the cloud location.
    pub fn location(&self) -> &CloudLocation {
        &self.location
    }

    /// Get the detected compression format.
    pub fn compression(&self) -> Compression {
        self.compression
    }

    /// Get the detected PCAP format.
    pub fn pcap_format(&self) -> PcapFormat {
        self.pcap_format
    }
}

impl PacketSource for CloudPacketSource {
    type Reader = CloudPacketReader;

    fn metadata(&self) -> &PacketSourceMetadata {
        &self.metadata
    }

    fn sequential_reader(&self) -> Result<Self::Reader, Error> {
        CloudPacketReader::sequential(self.raw_reader(0, None), self.compression, self.pcap_format)
    }
}

impl SeekablePacketSource for CloudPacketSource {
    fn time_range_ns(&self) -> Option<(i64, i64)> {
        self.ensure_index().ok().and_then(|idx| idx.time_range_ns())
    }

    fn seek_cost(&self) -> SeekCost {
        SeekCost::RangeRequest
    }

    fn reader_at(&self, range: &PacketRange) -> Result<Self::Reader, Error> {
        let end_frame = range.end.as_ref().map(|e| e.frame_number);
        // Compressed input is not splittable, and a range from byte 0 starts
        // with the real header: both are a sequential read (see `source.rs`).
        if self.compression.is_compressed() || starts_at_header(range) {
            let mut reader = self.sequential_reader()?;
            reader.end_frame = end_frame;
            return Ok(reader);
        }
        let idx = self.ensure_index()?;
        let header = synth_header_for(&idx, range.start.frame_number, self.pcap_format)?;
        // Fetch only this partition's bytes: [start offset, next partition start).
        let end_offset = range.end.as_ref().map(|e| e.byte_offset);
        CloudPacketReader::at(
            self.raw_reader(range.start.byte_offset, end_offset),
            self.pcap_format,
            header,
            range.start.frame_number,
            end_frame,
        )
    }

    fn partitions(&self, max: usize) -> Result<Vec<PacketRange>, Error> {
        if self.compression.is_compressed() {
            return Ok(vec![PacketRange::whole()]);
        }
        let idx = self.ensure_index()?;
        Ok(idx.partition_ranges(max))
    }

    fn frame_count(&self) -> Option<u64> {
        if self.compression.is_compressed() {
            return None;
        }
        self.ensure_index().ok().map(|idx| idx.packet_count)
    }
}

/// The concrete `Read` stack for cloud readers: an optional synthesized header
/// (empty for sequential reads) chained before the object-store range reader,
/// wrapped in decompression.
type CloudInner = GenericPcapReader<DecompressReader<Chain<Cursor<Vec<u8>>, ObjectStoreReader>>>;

/// Cloud-backed packet reader.
pub struct CloudPacketReader {
    inner: CloudInner,
    link_type: u32,
    end_frame: Option<u64>,
}

impl CloudPacketReader {
    /// Sequential reader over the whole object (honors compression).
    fn sequential(
        cloud_reader: ObjectStoreReader,
        compression: Compression,
        format: PcapFormat,
    ) -> Result<Self, Error> {
        let chain = Cursor::new(Vec::new()).chain(cloud_reader);
        let decompress = DecompressReader::new(chain, compression)?;
        let inner = GenericPcapReader::with_format(decompress, format)?;
        let link_type = inner.link_type();
        Ok(Self {
            inner,
            link_type,
            end_frame: None,
        })
    }

    /// Reader at a byte offset, prepending a synthesized header. Uncompressed
    /// objects only (the only ones that are partitioned).
    fn at(
        cloud_reader: ObjectStoreReader,
        format: PcapFormat,
        synth_header: Vec<u8>,
        start_frame: u64,
        end_frame: Option<u64>,
    ) -> Result<Self, Error> {
        let chain = Cursor::new(synth_header).chain(cloud_reader);
        let decompress = DecompressReader::new(chain, Compression::None)?;
        let inner = GenericPcapReader::with_format_starting_at(decompress, format, start_frame)?;
        let link_type = inner.link_type();
        Ok(Self {
            inner,
            link_type,
            end_frame,
        })
    }
}

impl PacketReader for CloudPacketReader {
    #[inline]
    fn process_packets_flow<F>(&mut self, max: usize, f: F) -> Result<Delivered, Error>
    where
        F: FnMut(PacketRef<'_>) -> ControlFlow<Pause>,
    {
        let delivered = process_bounded(&mut self.inner, self.end_frame, max, f)?;
        self.link_type = self.inner.link_type();
        Ok(delivered)
    }

    fn position(&self) -> PacketPosition {
        PacketPosition {
            byte_offset: self.inner.consumed_bytes(),
            frame_number: self.inner.frame_count(),
        }
    }

    fn truncated(&self) -> bool {
        self.inner.truncated()
    }

    fn link_type(&self) -> u32 {
        self.link_type
    }
}

// A reader is moved to the thread that scans its partition; fail here, not there.
const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<CloudPacketReader>();
};

// Required for async compatibility
impl Unpin for CloudPacketReader {}
