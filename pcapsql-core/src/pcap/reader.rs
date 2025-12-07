//! PCAP file reader with automatic compression handling.
//!
//! This module provides [`PcapReader`], a convenience wrapper around
//! [`GenericPcapReader`](crate::io::GenericPcapReader) that handles:
//! - File I/O
//! - Automatic compression detection and decompression
//! - PCAP format detection (Legacy vs PCAPNG)

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{Error, PcapError as OurPcapError};
use crate::io::{Compression, FileDecoder, GenericPcapReader, PacketRef, PcapFormat, RawPacket};

/// Reader for PCAP and PCAPNG files, with optional decompression.
///
/// This is a thin wrapper around [`GenericPcapReader`] that adds:
/// - File opening with path-based API
/// - Automatic compression detection (gzip, zstd, etc.)
/// - Automatic PCAP format detection
///
/// # Supported Compression Formats
///
/// - Gzip (.gz) - always enabled
/// - Zstd (.zst) - `compress-zstd` feature
/// - LZ4 (.lz4) - `compress-lz4` feature
/// - Bzip2 (.bz2) - `compress-bzip2` feature
/// - XZ (.xz) - `compress-xz` feature
///
/// # Example
///
/// ```ignore
/// use pcapsql_core::pcap::PcapReader;
///
/// let mut reader = PcapReader::open("capture.pcap.gz")?;
/// while let Some(packet) = reader.next_packet()? {
///     println!("Frame {}: {} bytes", packet.frame_number, packet.data.len());
/// }
/// ```
pub struct PcapReader {
    inner: GenericPcapReader<FileDecoder>,
}

impl PcapReader {
    /// Open a PCAP file for reading.
    ///
    /// Automatically detects and handles compressed files.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let path = path.as_ref();

        // Read first bytes to detect compression
        let mut file = File::open(path).map_err(|_| {
            Error::Pcap(OurPcapError::FileNotFound {
                path: path.display().to_string(),
            })
        })?;

        let mut header = [0u8; 6];
        let bytes_read = file.read(&mut header).map_err(|_| {
            Error::Pcap(OurPcapError::InvalidFormat {
                reason: "File too short to read header".to_string(),
            })
        })?;

        if bytes_read < 4 {
            return Err(Error::Pcap(OurPcapError::InvalidFormat {
                reason: "File too short".to_string(),
            }));
        }

        // Detect compression format
        let compression = Compression::detect(&header);

        // Seek back to start
        file.seek(SeekFrom::Start(0)).map_err(Error::Io)?;

        // Create decoder
        let decoder = FileDecoder::new(file, compression).map_err(|e| {
            Error::Pcap(OurPcapError::InvalidFormat {
                reason: format!("Failed to create decoder: {}", e),
            })
        })?;

        // We need to read the magic bytes after decompression to detect PCAP format.
        // Unfortunately, this requires us to re-open the file since we consumed bytes.
        // First, let's read the magic from a temporary decoder.
        let mut temp_decoder = decoder;
        let mut magic = [0u8; 4];
        temp_decoder.read_exact(&mut magic).map_err(|_| {
            Error::Pcap(OurPcapError::InvalidFormat {
                reason: "File too short to read magic number".to_string(),
            })
        })?;

        // Detect PCAP format from magic bytes
        let format = PcapFormat::detect(&magic)?;

        // Re-open file and create fresh decoder
        drop(temp_decoder);
        let file = File::open(path)?;
        let decoder = FileDecoder::new(file, compression).map_err(|e| {
            Error::Pcap(OurPcapError::InvalidFormat {
                reason: format!("Failed to create decoder: {}", e),
            })
        })?;

        // Create the generic reader
        let inner = GenericPcapReader::with_format(decoder, format)?;

        Ok(Self { inner })
    }

    /// Get the link type of the capture (e.g., 1 = Ethernet).
    #[inline]
    pub fn link_type(&self) -> u16 {
        self.inner.link_type() as u16
    }

    /// Get the current frame count.
    #[inline]
    pub fn frame_count(&self) -> u64 {
        self.inner.frame_count()
    }

    /// Read the next packet.
    ///
    /// Returns `Ok(None)` at end of file.
    #[inline]
    pub fn next_packet(&mut self) -> Result<Option<RawPacket>, Error> {
        self.inner.next_packet()
    }

    /// Process packets with zero-copy borrowed data.
    ///
    /// The callback receives borrowed packet data. The borrow is valid
    /// only during the callback - data must be processed before returning.
    /// This eliminates the copy overhead of `next_packet()`.
    ///
    /// Returns the number of packets processed.
    #[inline]
    pub fn process_packets<F>(&mut self, max: usize, f: F) -> Result<usize, Error>
    where
        F: FnMut(PacketRef<'_>) -> Result<(), Error>,
    {
        self.inner.process_packets(max, f)
    }
}

/// Iterator adapter for PcapReader.
impl Iterator for PcapReader {
    type Item = Result<RawPacket, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_packet() {
            Ok(Some(packet)) => Some(Ok(packet)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression as GzCompression;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_compression_detection() {
        // Gzip magic
        let gzip_data = [0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00];
        assert_eq!(Compression::detect(&gzip_data), Compression::Gzip);

        // PCAP magic (no compression)
        let pcap_data = [0xd4, 0xc3, 0xb2, 0xa1, 0x00, 0x00];
        assert_eq!(Compression::detect(&pcap_data), Compression::None);
    }

    #[test]
    fn test_create_and_read_gzip_pcap() {
        // Create a minimal valid PCAP file
        let pcap_data = create_minimal_pcap();

        // Compress it with gzip
        let temp = NamedTempFile::with_suffix(".pcap.gz").unwrap();
        {
            let file = File::create(temp.path()).unwrap();
            let mut encoder = GzEncoder::new(file, GzCompression::default());
            encoder.write_all(&pcap_data).unwrap();
            encoder.finish().unwrap();
        }

        // Try to open it
        let reader = PcapReader::open(temp.path());
        assert!(
            reader.is_ok(),
            "Failed to open gzipped PCAP: {:?}",
            reader.err()
        );
    }

    #[cfg(feature = "compress-zstd")]
    #[test]
    fn test_create_and_read_zstd_pcap() {
        // Create a minimal valid PCAP file
        let pcap_data = create_minimal_pcap();

        // Compress it with zstd
        let temp = NamedTempFile::with_suffix(".pcap.zst").unwrap();
        {
            let file = File::create(temp.path()).unwrap();
            let mut encoder = zstd::Encoder::new(file, 3).unwrap();
            encoder.write_all(&pcap_data).unwrap();
            encoder.finish().unwrap();
        }

        // Try to open it
        let reader = PcapReader::open(temp.path());
        assert!(
            reader.is_ok(),
            "Failed to open zstd PCAP: {:?}",
            reader.err()
        );
    }

    /// Create a minimal valid PCAP file with one packet.
    fn create_minimal_pcap() -> Vec<u8> {
        let mut data = Vec::new();

        // PCAP global header
        data.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]); // Magic (little endian)
        data.extend_from_slice(&[0x02, 0x00]); // Version major (2)
        data.extend_from_slice(&[0x04, 0x00]); // Version minor (4)
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Thiszone
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Sigfigs
        data.extend_from_slice(&[0xff, 0xff, 0x00, 0x00]); // Snaplen (65535)
        data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Network (Ethernet)

        // One packet header + minimal Ethernet frame
        let packet_data = [
            // Ethernet header (14 bytes)
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Dst MAC
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Src MAC
            0x08, 0x00, // EtherType (IPv4)
        ];

        let ts_sec: u32 = 1000000000;
        let ts_usec: u32 = 0;
        let caplen: u32 = packet_data.len() as u32;
        let origlen: u32 = packet_data.len() as u32;

        data.extend_from_slice(&ts_sec.to_le_bytes());
        data.extend_from_slice(&ts_usec.to_le_bytes());
        data.extend_from_slice(&caplen.to_le_bytes());
        data.extend_from_slice(&origlen.to_le_bytes());
        data.extend_from_slice(&packet_data);

        data
    }
}
