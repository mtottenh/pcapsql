//! Compression detection and decompression support.
//!
//! Provides a unified `AnyDecoder` that wraps various decompression formats
//! and implements `Read`. Uses enum dispatch for zero-allocation decompression.

use std::fs::File;
use std::io::{self, Cursor, Read};
use std::sync::Arc;

use flate2::read::GzDecoder;
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
#[derive(Clone)]
pub struct MmapSlice {
    mmap: Arc<Mmap>,
    start: usize,
}

impl MmapSlice {
    /// Create a new MmapSlice from an Arc<Mmap>.
    pub fn new(mmap: Arc<Mmap>) -> Self {
        Self { mmap, start: 0 }
    }

    /// Create a new MmapSlice starting at a given offset.
    pub fn with_offset(mmap: Arc<Mmap>, start: usize) -> Self {
        Self { mmap, start }
    }
}

impl AsRef<[u8]> for MmapSlice {
    fn as_ref(&self) -> &[u8] {
        &self.mmap[self.start..]
    }
}

/// Unified decoder that wraps various decompression formats.
///
/// Uses enum dispatch rather than trait objects to avoid allocation
/// and enable potential inlining. The `Read` implementation simply
/// delegates to the inner decoder.
pub enum AnyDecoder {
    /// No compression - direct cursor over mmap'd data
    None(Cursor<MmapSlice>),

    /// Gzip decompression
    Gzip(GzDecoder<Cursor<MmapSlice>>),

    /// Zstandard decompression
    #[cfg(feature = "compress-zstd")]
    Zstd(zstd::Decoder<'static, std::io::BufReader<Cursor<MmapSlice>>>),

    /// LZ4 frame decompression
    #[cfg(feature = "compress-lz4")]
    Lz4(lz4_flex::frame::FrameDecoder<Cursor<MmapSlice>>),

    /// Bzip2 decompression
    #[cfg(feature = "compress-bzip2")]
    Bzip2(bzip2::read::BzDecoder<Cursor<MmapSlice>>),

    /// XZ/LZMA decompression
    #[cfg(feature = "compress-xz")]
    Xz(xz2::read::XzDecoder<Cursor<MmapSlice>>),
}

impl AnyDecoder {
    /// Create a decoder for the given mmap'd data.
    ///
    /// Automatically detects compression format from magic bytes.
    pub fn new(mmap: Arc<Mmap>) -> io::Result<Self> {
        let compression = Compression::detect(&mmap);
        Self::with_compression(mmap, compression)
    }

    /// Create a decoder with explicit compression format.
    pub fn with_compression(mmap: Arc<Mmap>, compression: Compression) -> io::Result<Self> {
        let slice = MmapSlice::new(mmap);
        let cursor = Cursor::new(slice);

        match compression {
            Compression::None => Ok(AnyDecoder::None(cursor)),

            Compression::Gzip => Ok(AnyDecoder::Gzip(GzDecoder::new(cursor))),

            #[cfg(feature = "compress-zstd")]
            Compression::Zstd => {
                let decoder = zstd::Decoder::new(cursor)?;
                Ok(AnyDecoder::Zstd(decoder))
            }

            #[cfg(feature = "compress-lz4")]
            Compression::Lz4 => {
                let decoder = lz4_flex::frame::FrameDecoder::new(cursor);
                Ok(AnyDecoder::Lz4(decoder))
            }

            #[cfg(feature = "compress-bzip2")]
            Compression::Bzip2 => {
                let decoder = bzip2::read::BzDecoder::new(cursor);
                Ok(AnyDecoder::Bzip2(decoder))
            }

            #[cfg(feature = "compress-xz")]
            Compression::Xz => {
                let decoder = xz2::read::XzDecoder::new(cursor);
                Ok(AnyDecoder::Xz(decoder))
            }
        }
    }

    /// Get the compression format this decoder handles.
    pub fn compression(&self) -> Compression {
        match self {
            AnyDecoder::None(_) => Compression::None,
            AnyDecoder::Gzip(_) => Compression::Gzip,
            #[cfg(feature = "compress-zstd")]
            AnyDecoder::Zstd(_) => Compression::Zstd,
            #[cfg(feature = "compress-lz4")]
            AnyDecoder::Lz4(_) => Compression::Lz4,
            #[cfg(feature = "compress-bzip2")]
            AnyDecoder::Bzip2(_) => Compression::Bzip2,
            #[cfg(feature = "compress-xz")]
            AnyDecoder::Xz(_) => Compression::Xz,
        }
    }
}

impl Read for AnyDecoder {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            AnyDecoder::None(r) => r.read(buf),
            AnyDecoder::Gzip(r) => r.read(buf),
            #[cfg(feature = "compress-zstd")]
            AnyDecoder::Zstd(r) => r.read(buf),
            #[cfg(feature = "compress-lz4")]
            AnyDecoder::Lz4(r) => r.read(buf),
            #[cfg(feature = "compress-bzip2")]
            AnyDecoder::Bzip2(r) => r.read(buf),
            #[cfg(feature = "compress-xz")]
            AnyDecoder::Xz(r) => r.read(buf),
        }
    }
}

// Required for async compatibility
impl Unpin for AnyDecoder {}

/// File-based decoder that wraps various decompression formats.
///
/// Similar to `AnyDecoder` but for `File` input instead of mmap'd data.
/// Uses enum dispatch for zero-allocation decompression.
pub enum FileDecoder {
    /// No compression - direct file access
    None(File),

    /// Gzip decompression
    Gzip(GzDecoder<File>),

    /// Zstandard decompression
    #[cfg(feature = "compress-zstd")]
    Zstd(zstd::Decoder<'static, std::io::BufReader<File>>),

    /// LZ4 frame decompression
    #[cfg(feature = "compress-lz4")]
    Lz4(lz4_flex::frame::FrameDecoder<File>),

    /// Bzip2 decompression
    #[cfg(feature = "compress-bzip2")]
    Bzip2(bzip2::read::BzDecoder<File>),

    /// XZ/LZMA decompression
    #[cfg(feature = "compress-xz")]
    Xz(xz2::read::XzDecoder<File>),
}

impl FileDecoder {
    /// Create a decoder for the given file with explicit compression format.
    pub fn new(file: File, compression: Compression) -> io::Result<Self> {
        match compression {
            Compression::None => Ok(FileDecoder::None(file)),

            Compression::Gzip => Ok(FileDecoder::Gzip(GzDecoder::new(file))),

            #[cfg(feature = "compress-zstd")]
            Compression::Zstd => {
                let decoder = zstd::Decoder::new(file)?;
                Ok(FileDecoder::Zstd(decoder))
            }

            #[cfg(feature = "compress-lz4")]
            Compression::Lz4 => {
                let decoder = lz4_flex::frame::FrameDecoder::new(file);
                Ok(FileDecoder::Lz4(decoder))
            }

            #[cfg(feature = "compress-bzip2")]
            Compression::Bzip2 => {
                let decoder = bzip2::read::BzDecoder::new(file);
                Ok(FileDecoder::Bzip2(decoder))
            }

            #[cfg(feature = "compress-xz")]
            Compression::Xz => {
                let decoder = xz2::read::XzDecoder::new(file);
                Ok(FileDecoder::Xz(decoder))
            }
        }
    }

    /// Get the compression format this decoder handles.
    pub fn compression(&self) -> Compression {
        match self {
            FileDecoder::None(_) => Compression::None,
            FileDecoder::Gzip(_) => Compression::Gzip,
            #[cfg(feature = "compress-zstd")]
            FileDecoder::Zstd(_) => Compression::Zstd,
            #[cfg(feature = "compress-lz4")]
            FileDecoder::Lz4(_) => Compression::Lz4,
            #[cfg(feature = "compress-bzip2")]
            FileDecoder::Bzip2(_) => Compression::Bzip2,
            #[cfg(feature = "compress-xz")]
            FileDecoder::Xz(_) => Compression::Xz,
        }
    }
}

impl Read for FileDecoder {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            FileDecoder::None(r) => r.read(buf),
            FileDecoder::Gzip(r) => r.read(buf),
            #[cfg(feature = "compress-zstd")]
            FileDecoder::Zstd(r) => r.read(buf),
            #[cfg(feature = "compress-lz4")]
            FileDecoder::Lz4(r) => r.read(buf),
            #[cfg(feature = "compress-bzip2")]
            FileDecoder::Bzip2(r) => r.read(buf),
            #[cfg(feature = "compress-xz")]
            FileDecoder::Xz(r) => r.read(buf),
        }
    }
}

// FileDecoder is Send since File and all decoders are Send
unsafe impl Send for FileDecoder {}

// Required for async compatibility
impl Unpin for FileDecoder {}

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
