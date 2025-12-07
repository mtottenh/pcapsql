//! Compression detection and decompression support.
//!
//! Provides a unified `DecompressReader<R>` that wraps various decompression formats
//! and implements `Read`. Uses enum dispatch for zero-allocation decompression.
//!
//! The reader is generic over any `R: Read`, allowing it to work with:
//! - `File` for standard file I/O
//! - `Cursor<MmapSlice>` for memory-mapped files
//! - Any other `Read` source (e.g., network streams, S3)

use std::io::{self, Read};
#[cfg(feature = "compress-zstd")]
use std::io::BufReader;
#[cfg(feature = "mmap")]
use std::sync::Arc;

use flate2::read::GzDecoder;
#[cfg(feature = "mmap")]
use memmap2::Mmap;

/// Detected compression format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// No compression
    None,
    /// Gzip (.gz)
    Gzip,
    /// Zstandard (.zst)
    #[cfg(feature = "compress-zstd")]
    Zstd,
    /// LZ4 frame format (.lz4)
    #[cfg(feature = "compress-lz4")]
    Lz4,
    /// Bzip2 (.bz2)
    #[cfg(feature = "compress-bzip2")]
    Bzip2,
    /// XZ/LZMA (.xz)
    #[cfg(feature = "compress-xz")]
    Xz,
}

impl Compression {
    /// Detect compression format from magic bytes.
    pub fn detect(data: &[u8]) -> Self {
        if data.len() < 6 {
            return Compression::None;
        }

        // Check magic bytes for each format
        match data {
            // Gzip: 1f 8b
            [0x1f, 0x8b, ..] => Compression::Gzip,

            // Zstd: 28 b5 2f fd
            #[cfg(feature = "compress-zstd")]
            [0x28, 0xb5, 0x2f, 0xfd, ..] => Compression::Zstd,

            // LZ4 frame: 04 22 4d 18
            #[cfg(feature = "compress-lz4")]
            [0x04, 0x22, 0x4d, 0x18, ..] => Compression::Lz4,

            // Bzip2: 42 5a ("BZ")
            #[cfg(feature = "compress-bzip2")]
            [0x42, 0x5a, ..] => Compression::Bzip2,

            // XZ: fd 37 7a 58 5a 00
            #[cfg(feature = "compress-xz")]
            [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, ..] => Compression::Xz,

            _ => Compression::None,
        }
    }

    /// Get the typical file extension for this compression format.
    pub fn extension(&self) -> Option<&'static str> {
        match self {
            Compression::None => None,
            Compression::Gzip => Some("gz"),
            #[cfg(feature = "compress-zstd")]
            Compression::Zstd => Some("zst"),
            #[cfg(feature = "compress-lz4")]
            Compression::Lz4 => Some("lz4"),
            #[cfg(feature = "compress-bzip2")]
            Compression::Bzip2 => Some("bz2"),
            #[cfg(feature = "compress-xz")]
            Compression::Xz => Some("xz"),
        }
    }

    /// Check if this represents compressed data.
    pub fn is_compressed(&self) -> bool {
        !matches!(self, Compression::None)
    }
}

impl std::fmt::Display for Compression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Compression::None => write!(f, "none"),
            Compression::Gzip => write!(f, "gzip"),
            #[cfg(feature = "compress-zstd")]
            Compression::Zstd => write!(f, "zstd"),
            #[cfg(feature = "compress-lz4")]
            Compression::Lz4 => write!(f, "lz4"),
            #[cfg(feature = "compress-bzip2")]
            Compression::Bzip2 => write!(f, "bzip2"),
            #[cfg(feature = "compress-xz")]
            Compression::Xz => write!(f, "xz"),
        }
    }
}

/// A wrapper that allows sharing mmap data with Cursor.
/// Implements AsRef<[u8]> so it can be used as Cursor's inner type.
///
/// This type is only available when the `mmap` feature is enabled.
#[cfg(feature = "mmap")]
#[derive(Clone)]
pub struct MmapSlice {
    mmap: Arc<Mmap>,
    start: usize,
}

#[cfg(feature = "mmap")]
impl MmapSlice {
    /// Create a new MmapSlice from an `Arc<Mmap>`.
    pub fn new(mmap: Arc<Mmap>) -> Self {
        Self { mmap, start: 0 }
    }

    /// Create a new MmapSlice starting at a given offset.
    pub fn with_offset(mmap: Arc<Mmap>, start: usize) -> Self {
        Self { mmap, start }
    }
}

#[cfg(feature = "mmap")]
impl AsRef<[u8]> for MmapSlice {
    fn as_ref(&self) -> &[u8] {
        &self.mmap[self.start..]
    }
}

/// Unified decompression reader that wraps various decompression formats.
///
/// Generic over any `R: Read`, enabling composition with:
/// - `File` for standard file I/O
/// - `Cursor<MmapSlice>` for memory-mapped files
/// - Any other `Read` source
///
/// Uses enum dispatch rather than trait objects to avoid allocation
/// and enable potential inlining. The `Read` implementation simply
/// delegates to the inner decoder.
pub enum DecompressReader<R: Read> {
    /// No compression - pass-through
    None(R),

    /// Gzip decompression
    Gzip(GzDecoder<R>),

    /// Zstandard decompression
    #[cfg(feature = "compress-zstd")]
    Zstd(zstd::Decoder<'static, BufReader<R>>),

    /// LZ4 frame decompression
    #[cfg(feature = "compress-lz4")]
    Lz4(lz4_flex::frame::FrameDecoder<R>),

    /// Bzip2 decompression
    #[cfg(feature = "compress-bzip2")]
    Bzip2(bzip2::read::BzDecoder<R>),

    /// XZ/LZMA decompression
    #[cfg(feature = "compress-xz")]
    Xz(xz2::read::XzDecoder<R>),
}

impl<R: Read> DecompressReader<R> {
    /// Create a decompression reader with explicit compression format.
    pub fn new(source: R, compression: Compression) -> io::Result<Self> {
        match compression {
            Compression::None => Ok(DecompressReader::None(source)),

            Compression::Gzip => Ok(DecompressReader::Gzip(GzDecoder::new(source))),

            #[cfg(feature = "compress-zstd")]
            Compression::Zstd => {
                let decoder = zstd::Decoder::new(source)?;
                Ok(DecompressReader::Zstd(decoder))
            }

            #[cfg(feature = "compress-lz4")]
            Compression::Lz4 => {
                let decoder = lz4_flex::frame::FrameDecoder::new(source);
                Ok(DecompressReader::Lz4(decoder))
            }

            #[cfg(feature = "compress-bzip2")]
            Compression::Bzip2 => {
                let decoder = bzip2::read::BzDecoder::new(source);
                Ok(DecompressReader::Bzip2(decoder))
            }

            #[cfg(feature = "compress-xz")]
            Compression::Xz => {
                let decoder = xz2::read::XzDecoder::new(source);
                Ok(DecompressReader::Xz(decoder))
            }
        }
    }

    /// Get the compression format this reader handles.
    pub fn compression(&self) -> Compression {
        match self {
            DecompressReader::None(_) => Compression::None,
            DecompressReader::Gzip(_) => Compression::Gzip,
            #[cfg(feature = "compress-zstd")]
            DecompressReader::Zstd(_) => Compression::Zstd,
            #[cfg(feature = "compress-lz4")]
            DecompressReader::Lz4(_) => Compression::Lz4,
            #[cfg(feature = "compress-bzip2")]
            DecompressReader::Bzip2(_) => Compression::Bzip2,
            #[cfg(feature = "compress-xz")]
            DecompressReader::Xz(_) => Compression::Xz,
        }
    }
}

impl<R: Read> Read for DecompressReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            DecompressReader::None(r) => r.read(buf),
            DecompressReader::Gzip(r) => r.read(buf),
            #[cfg(feature = "compress-zstd")]
            DecompressReader::Zstd(r) => r.read(buf),
            #[cfg(feature = "compress-lz4")]
            DecompressReader::Lz4(r) => r.read(buf),
            #[cfg(feature = "compress-bzip2")]
            DecompressReader::Bzip2(r) => r.read(buf),
            #[cfg(feature = "compress-xz")]
            DecompressReader::Xz(r) => r.read(buf),
        }
    }
}

// DecompressReader is Send when R is Send
unsafe impl<R: Read + Send> Send for DecompressReader<R> {}

// Required for async compatibility
impl<R: Read + Unpin> Unpin for DecompressReader<R> {}

// =============================================================================
// Type aliases for convenience
// =============================================================================

use std::fs::File;
#[cfg(feature = "mmap")]
use std::io::Cursor;

/// Type alias for file-based decompression.
pub type FileDecoder = DecompressReader<File>;

/// Type alias for mmap-based decompression.
///
/// Only available when the `mmap` feature is enabled.
#[cfg(feature = "mmap")]
pub type AnyDecoder = DecompressReader<Cursor<MmapSlice>>;

#[cfg(feature = "mmap")]
impl AnyDecoder {
    /// Create a decoder for the given mmap'd data.
    ///
    /// Automatically detects compression format from magic bytes.
    pub fn from_mmap(mmap: Arc<Mmap>) -> io::Result<Self> {
        let compression = Compression::detect(&mmap);
        Self::with_compression_mmap(mmap, compression)
    }

    /// Create a decoder with explicit compression format.
    pub fn with_compression_mmap(mmap: Arc<Mmap>, compression: Compression) -> io::Result<Self> {
        let slice = MmapSlice::new(mmap);
        let cursor = Cursor::new(slice);
        DecompressReader::new(cursor, compression)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_no_compression() {
        // PCAP magic
        let data = [0xd4, 0xc3, 0xb2, 0xa1, 0x00, 0x00];
        assert_eq!(Compression::detect(&data), Compression::None);
    }

    #[test]
    fn test_detect_gzip() {
        let data = [0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00];
        assert_eq!(Compression::detect(&data), Compression::Gzip);
    }

    #[cfg(feature = "compress-zstd")]
    #[test]
    fn test_detect_zstd() {
        let data = [0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00];
        assert_eq!(Compression::detect(&data), Compression::Zstd);
    }

    #[cfg(feature = "compress-lz4")]
    #[test]
    fn test_detect_lz4() {
        let data = [0x04, 0x22, 0x4d, 0x18, 0x00, 0x00];
        assert_eq!(Compression::detect(&data), Compression::Lz4);
    }

    #[cfg(feature = "compress-bzip2")]
    #[test]
    fn test_detect_bzip2() {
        let data = [0x42, 0x5a, 0x68, 0x39, 0x00, 0x00];
        assert_eq!(Compression::detect(&data), Compression::Bzip2);
    }

    #[cfg(feature = "compress-xz")]
    #[test]
    fn test_detect_xz() {
        let data = [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];
        assert_eq!(Compression::detect(&data), Compression::Xz);
    }

    #[test]
    fn test_detect_short_data() {
        let data = [0x1f, 0x8b]; // Too short
        assert_eq!(Compression::detect(&data), Compression::None);
    }

    #[test]
    fn test_compression_display() {
        assert_eq!(format!("{}", Compression::None), "none");
        assert_eq!(format!("{}", Compression::Gzip), "gzip");
    }

    #[test]
    fn test_compression_extension() {
        assert_eq!(Compression::None.extension(), None);
        assert_eq!(Compression::Gzip.extension(), Some("gz"));
    }

    #[test]
    fn test_compression_is_compressed() {
        assert!(!Compression::None.is_compressed());
        assert!(Compression::Gzip.is_compressed());
    }
}
