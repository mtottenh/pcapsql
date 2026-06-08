//! Memory-mapped packet source — the reference lock-free seekable backend.
//!
//! An `Arc<Mmap>` is immutable shared memory that never moves. Each partition
//! takes a cheap [`MmapSlice::with_offset`] view into it and owns its own
//! `Cursor` / reader / Arrow builders, so nothing is `&mut`-shared and there is
//! nothing to lock. This is why mmap is [`SeekCost::Free`].
//!
//! ```text
//! Arc<Mmap>                              // immutable, shared read-only
//!    │  .clone() = refcount bump
//!    ▼
//! MmapSlice::with_offset(arc, start)     // cheap view: (Arc<Mmap>, offset)
//!    ▼
//! Cursor<MmapSlice>  ->  GenericPcapReader (headerless, per-partition)
//! ```

use std::fs::File;
use std::io::{Chain, Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use memmap2::Mmap;

use crate::error::{Error, PcapError};

use super::decompress::{Compression, DecompressReader, MmapSlice};
use super::index::{self, BoundaryIndex};
use super::pcap_stream::{GenericPcapReader, PcapFormat};
use super::source::synth_header_for;
use super::{
    PacketPosition, PacketRange, PacketReader, PacketRef, PacketSource, PacketSourceMetadata,
    SeekCost, SeekablePacketSource,
};

/// The concrete `Read` stack for mmap readers: an optional synthesized header
/// (empty for sequential reads) chained before an mmap slice, wrapped in
/// decompression.
type MmapInner = GenericPcapReader<DecompressReader<Chain<Cursor<Vec<u8>>, Cursor<MmapSlice>>>>;

/// Memory-mapped packet source.
#[derive(Clone)]
pub struct MmapPacketSource {
    path: PathBuf,
    mmap: Arc<Mmap>,
    metadata: PacketSourceMetadata,
    compression: Compression,
    pcap_format: PcapFormat,
    index: Arc<Mutex<Option<Arc<BoundaryIndex>>>>,
    index_stride: u64,
    source_mtime: Option<SystemTime>,
    header_hash: u64,
}

impl MmapPacketSource {
    /// Open a PCAP or PCAPNG file with memory mapping. Detects compression.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path).map_err(Error::Io)?;
        let mtime = file.metadata().ok().and_then(|m| m.modified().ok());
        let mmap = unsafe { Mmap::map(&file).map_err(Error::Io)? };

        let compression = Compression::detect(&mmap);
        let (pcap_format, link_type, snaplen) = if compression.is_compressed() {
            Self::detect_format_compressed(&mmap, compression)?
        } else {
            Self::detect_format_uncompressed(&mmap)?
        };

        let header_hash = index::header_hash(&mmap);
        let metadata = PacketSourceMetadata {
            link_type,
            snaplen,
            size_bytes: Some(mmap.len() as u64),
            packet_count: None,
        };

        Ok(Self {
            path,
            mmap: Arc::new(mmap),
            metadata,
            compression,
            pcap_format,
            index: Arc::new(Mutex::new(None)),
            index_stride: index::DEFAULT_CHECKPOINT_STRIDE,
            source_mtime: mtime,
            header_hash,
        })
    }

    /// Set the checkpoint stride for index building (smaller = finer partitions).
    pub fn with_index_stride(mut self, stride: u64) -> Self {
        self.index_stride = stride.max(1);
        self
    }

    fn detect_format_uncompressed(data: &[u8]) -> Result<(PcapFormat, u32, u32), Error> {
        if data.len() < 24 {
            return Err(Error::Pcap(PcapError::InvalidFormat {
                reason: "File too small for PCAP header".into(),
            }));
        }
        let format = PcapFormat::detect(data)?;
        let (link_type, snaplen) = if format.is_pcapng() {
            (1, 65535)
        } else {
            (
                Self::link_type_from_header(data, &format),
                Self::snaplen_from_header(data, &format),
            )
        };
        Ok((format, link_type, snaplen))
    }

    fn link_type_from_header(data: &[u8], format: &PcapFormat) -> u32 {
        if data.len() < 24 {
            return 1;
        }
        if format.is_big_endian() {
            u32::from_be_bytes([data[20], data[21], data[22], data[23]])
        } else {
            u32::from_le_bytes([data[20], data[21], data[22], data[23]])
        }
    }

    fn snaplen_from_header(data: &[u8], format: &PcapFormat) -> u32 {
        if data.len() < 20 {
            return 65535;
        }
        if format.is_big_endian() {
            u32::from_be_bytes([data[16], data[17], data[18], data[19]])
        } else {
            u32::from_le_bytes([data[16], data[17], data[18], data[19]])
        }
    }

    fn detect_format_compressed(
        data: &[u8],
        compression: Compression,
    ) -> Result<(PcapFormat, u32, u32), Error> {
        let header = super::decompress::decompress_header(data, compression, 64).map_err(|e| {
            Error::Pcap(PcapError::InvalidFormat {
                reason: format!("Failed to read compressed header: {e}"),
            })
        })?;
        if header.len() < 24 {
            return Err(Error::Pcap(PcapError::InvalidFormat {
                reason: "Compressed header too small".into(),
            }));
        }
        let format = PcapFormat::detect(&header)?;
        let (link_type, snaplen) = if format.is_pcapng() {
            (1, 65535)
        } else {
            (
                Self::link_type_from_header(&header, &format),
                Self::snaplen_from_header(&header, &format),
            )
        };
        Ok((format, link_type, snaplen))
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
        if let Ok(idx) = BoundaryIndex::read_sidecar(&sidecar) {
            if idx.stride == self.index_stride
                && idx.is_valid_for(self.mmap.len() as u64, self.source_mtime, self.header_hash)
            {
                let idx = Arc::new(idx);
                *guard = Some(idx.clone());
                return Ok(idx);
            }
        }

        // Build by scanning the uncompressed mmap bytes (offsets == file offsets).
        let cursor = Cursor::new(MmapSlice::new(self.mmap.clone()));
        let idx = index::build_boundary_index(
            cursor,
            self.pcap_format,
            self.index_stride,
            self.mmap.len() as u64,
            self.source_mtime,
            self.header_hash,
        )?;
        let _ = idx.write_sidecar(&sidecar);
        let idx = Arc::new(idx);
        *guard = Some(idx.clone());
        Ok(idx)
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

impl PacketSource for MmapPacketSource {
    type Reader = MmapPacketReader;

    fn metadata(&self) -> &PacketSourceMetadata {
        &self.metadata
    }

    fn sequential_reader(&self) -> Result<Self::Reader, Error> {
        MmapPacketReader::sequential(
            self.mmap.clone(),
            self.compression,
            self.pcap_format,
            self.metadata.link_type,
        )
    }
}

impl SeekablePacketSource for MmapPacketSource {
    fn seek_cost(&self) -> SeekCost {
        SeekCost::Free
    }

    fn reader_at(&self, range: &PacketRange) -> Result<Self::Reader, Error> {
        if self.compression.is_compressed() {
            return self.sequential_reader();
        }
        let idx = self.ensure_index()?;
        let header = synth_header_for(&idx, range.start.frame_number, self.pcap_format)?;
        let end_frame = range.end.as_ref().map(|e| e.frame_number);
        MmapPacketReader::at(
            self.mmap.clone(),
            self.pcap_format,
            header,
            range.start.byte_offset,
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
}

/// Memory-mapped packet reader.
pub struct MmapPacketReader {
    inner: MmapInner,
    link_type: u32,
    end_frame: Option<u64>,
}

impl MmapPacketReader {
    fn sequential(
        mmap: Arc<Mmap>,
        compression: Compression,
        format: PcapFormat,
        link_type: u32,
    ) -> Result<Self, Error> {
        let slice = MmapSlice::new(mmap);
        let chain = Cursor::new(Vec::new()).chain(Cursor::new(slice));
        let decode = DecompressReader::new(chain, compression).map_err(|e| {
            Error::Pcap(PcapError::InvalidFormat {
                reason: format!("decompressor: {e}"),
            })
        })?;
        let inner = GenericPcapReader::with_format(decode, format)?;
        Ok(Self {
            inner,
            link_type,
            end_frame: None,
        })
    }

    fn at(
        mmap: Arc<Mmap>,
        format: PcapFormat,
        synth_header: Vec<u8>,
        byte_offset: u64,
        start_frame: u64,
        end_frame: Option<u64>,
    ) -> Result<Self, Error> {
        let slice = MmapSlice::with_offset(mmap, byte_offset as usize);
        let chain = Cursor::new(synth_header).chain(Cursor::new(slice));
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

impl PacketReader for MmapPacketReader {
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
            return;
        }
        assert!(MmapPacketSource::open(&path).is_ok());
    }

    #[test]
    fn test_mmap_reader_reads_packets() {
        let path = test_pcap_path("dns.cap");
        if !path.exists() {
            return;
        }
        let source = MmapPacketSource::open(&path).unwrap();
        let mut reader = source.sequential_reader().unwrap();
        let mut found = false;
        reader
            .process_packets(1, |p| {
                assert_eq!(p.frame_number, 1);
                assert!(!p.data.is_empty());
                found = true;
                Ok(())
            })
            .unwrap();
        assert!(found);
    }

    #[test]
    fn test_mmap_link_type() {
        let path = test_pcap_path("dns.cap");
        if !path.exists() {
            return;
        }
        let source = MmapPacketSource::open(&path).unwrap();
        assert_eq!(source.metadata().link_type, 1);
    }

    #[test]
    fn test_mmap_partitions_split_and_cover() {
        let path = test_pcap_path("dns.cap");
        if !path.exists() {
            return;
        }
        // Fine stride so a small capture yields multiple partitions.
        let source = MmapPacketSource::open(&path).unwrap().with_index_stride(4);

        // Count all frames sequentially.
        let mut total = 0u64;
        let mut r = source.sequential_reader().unwrap();
        loop {
            let n = r.process_packets(64, |_| Ok(())).unwrap();
            if n == 0 {
                break;
            }
            total += n as u64;
        }
        assert!(total > 0);

        let parts = source.partitions(4).unwrap();
        assert!(!parts.is_empty());

        // Reading every partition reproduces exactly the same frames in order.
        let mut frames = Vec::new();
        for range in &parts {
            let mut pr = source.reader_at(range).unwrap();
            loop {
                let mut batch = Vec::new();
                let n = pr
                    .process_packets(64, |p| {
                        batch.push(p.frame_number);
                        Ok(())
                    })
                    .unwrap();
                frames.extend(batch);
                if n == 0 {
                    break;
                }
            }
        }
        let expected: Vec<u64> = (1..=total).collect();
        assert_eq!(frames, expected, "partitioned read must equal sequential");
    }

    #[test]
    fn test_mmap_clone_independent_readers() {
        let path = test_pcap_path("dns.cap");
        if !path.exists() {
            return;
        }
        let s1 = MmapPacketSource::open(&path).unwrap();
        let s2 = s1.clone();
        let mut r1 = s1.sequential_reader().unwrap();
        let mut r2 = s2.sequential_reader().unwrap();
        let mut f1 = 0u64;
        let mut f2 = 0u64;
        r1.process_packets(1, |p| {
            f1 = p.frame_number;
            Ok(())
        })
        .unwrap();
        r2.process_packets(1, |p| {
            f2 = p.frame_number;
            Ok(())
        })
        .unwrap();
        assert_eq!(f1, f2);
    }
}
