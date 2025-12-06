//! PCAP file reader.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use flate2::read::GzDecoder;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError, PcapNGReader};

use super::RawPacket;
use crate::error::{Error, PcapError as OurPcapError};

/// Buffer size for reading PCAP files (64KB).
const BUFFER_SIZE: usize = 65536;

/// Gzip magic bytes.
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// Reader for PCAP and PCAPNG files, with optional gzip decompression.
pub struct PcapReader {
    inner: ReaderInner,
    frame_number: u64,
    link_type: u16,
}

enum ReaderInner {
    Legacy(LegacyPcapReader<BufReader<Box<dyn Read + Send>>>),
    Ng(PcapNGReader<BufReader<Box<dyn Read + Send>>>),
}

impl PcapReader {
    /// Open a PCAP file for reading.
    ///
    /// Automatically detects and decompresses gzipped files.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let path = path.as_ref();

        // Check if file is gzipped (by extension or magic bytes)
        let is_gzipped = is_gzip_file(path)?;

        // Open file and optionally wrap with gzip decoder
        let file = File::open(path).map_err(|_| {
            Error::Pcap(OurPcapError::FileNotFound {
                path: path.display().to_string(),
            })
        })?;

        let reader: Box<dyn Read + Send> = if is_gzipped {
            Box::new(GzDecoder::new(file))
        } else {
            Box::new(file)
        };

        let mut buf_reader = BufReader::with_capacity(BUFFER_SIZE, reader);

        // Peek at magic number to determine PCAP format
        let mut magic = [0u8; 4];
        buf_reader.read_exact(&mut magic).map_err(|_| {
            Error::Pcap(OurPcapError::InvalidFormat {
                reason: "File too short to read magic number".to_string(),
            })
        })?;

        // Re-open file since we consumed the magic bytes
        drop(buf_reader);
        let file = File::open(path)?;
        let reader: Box<dyn Read + Send> = if is_gzipped {
            Box::new(GzDecoder::new(file))
        } else {
            Box::new(file)
        };
        let buf_reader = BufReader::with_capacity(BUFFER_SIZE, reader);

        // Check magic number for PCAP format
        match &magic {
            // PCAP magic (little endian)
            [0xd4, 0xc3, 0xb2, 0xa1] => Self::open_legacy(buf_reader),
            // PCAP magic (big endian)
            [0xa1, 0xb2, 0xc3, 0xd4] => Self::open_legacy(buf_reader),
            // PCAP nanosecond (little endian)
            [0x4d, 0x3c, 0xb2, 0xa1] => Self::open_legacy(buf_reader),
            // PCAP nanosecond (big endian)
            [0xa1, 0xb2, 0x3c, 0x4d] => Self::open_legacy(buf_reader),
            // PCAPNG
            [0x0a, 0x0d, 0x0d, 0x0a] => Self::open_ng(buf_reader),
            _ => Err(Error::Pcap(OurPcapError::InvalidFormat {
                reason: format!("Unknown magic number: {magic:02x?}"),
            })),
        }
    }

    fn open_legacy(reader: BufReader<Box<dyn Read + Send>>) -> Result<Self, Error> {
        let pcap_reader = LegacyPcapReader::new(BUFFER_SIZE, reader).map_err(|e| {
            Error::Pcap(OurPcapError::InvalidFormat {
                reason: format!("Failed to parse PCAP header: {e}"),
            })
        })?;

        Ok(Self {
            inner: ReaderInner::Legacy(pcap_reader),
            frame_number: 0,
            link_type: 1, // Default to Ethernet, will be updated
        })
    }

    fn open_ng(reader: BufReader<Box<dyn Read + Send>>) -> Result<Self, Error> {
        let pcap_reader = PcapNGReader::new(BUFFER_SIZE, reader).map_err(|e| {
            Error::Pcap(OurPcapError::InvalidFormat {
                reason: format!("Failed to parse PCAPNG header: {e}"),
            })
        })?;

        Ok(Self {
            inner: ReaderInner::Ng(pcap_reader),
            frame_number: 0,
            link_type: 1, // Will be updated from interface description block
        })
    }

    /// Get the link type of the capture.
    pub fn link_type(&self) -> u16 {
        self.link_type
    }

    /// Get the current frame count.
    pub fn frame_count(&self) -> u64 {
        self.frame_number
    }

    /// Read the next packet.
    pub fn next_packet(&mut self) -> Result<Option<RawPacket>, Error> {
        // Determine the reader type to avoid borrow issues
        let is_legacy = matches!(self.inner, ReaderInner::Legacy(_));

        if is_legacy {
            self.next_legacy_impl()
        } else {
            self.next_ng_impl()
        }
    }

    fn next_legacy_impl(&mut self) -> Result<Option<RawPacket>, Error> {
        let reader = match &mut self.inner {
            ReaderInner::Legacy(r) => r,
            _ => unreachable!(),
        };
        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::Legacy(packet) => {
                            self.frame_number += 1;

                            // Convert timestamp
                            let timestamp_us = (packet.ts_sec as i64) * 1_000_000
                                + (packet.ts_usec as i64);

                            let raw = RawPacket::new(
                                self.frame_number,
                                timestamp_us,
                                packet.caplen,
                                packet.origlen,
                                self.link_type,
                                packet.data.to_vec(),
                            );

                            reader.consume(offset);
                            return Ok(Some(raw));
                        }
                        PcapBlockOwned::LegacyHeader(header) => {
                            self.link_type = header.network.0 as u16;
                            reader.consume(offset);
                            continue;
                        }
                        _ => {
                            reader.consume(offset);
                            continue;
                        }
                    }
                }
                Err(PcapError::Eof) => return Ok(None),
                Err(PcapError::Incomplete(_)) => {
                    reader.refill().map_err(|e| {
                        Error::Pcap(OurPcapError::InvalidFormat {
                            reason: format!("Refill error: {e}"),
                        })
                    })?;
                    continue;
                }
                Err(e) => {
                    return Err(Error::Pcap(OurPcapError::InvalidFormat {
                        reason: format!("Parse error: {e}"),
                    }))
                }
            }
        }
    }

    fn next_ng_impl(&mut self) -> Result<Option<RawPacket>, Error> {
        let reader = match &mut self.inner {
            ReaderInner::Ng(r) => r,
            _ => unreachable!(),
        };
        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::NG(ng_block) => {
                            use pcap_parser::pcapng::*;

                            match ng_block {
                                Block::InterfaceDescription(idb) => {
                                    self.link_type = idb.linktype.0 as u16;
                                    reader.consume(offset);
                                    continue;
                                }
                                Block::EnhancedPacket(epb) => {
                                    self.frame_number += 1;

                                    // Timestamp is in interface time units (usually microseconds)
                                    let timestamp_us = ((epb.ts_high as i64) << 32)
                                        | (epb.ts_low as i64);

                                    let raw = RawPacket::new(
                                        self.frame_number,
                                        timestamp_us,
                                        epb.caplen,
                                        epb.origlen,
                                        self.link_type,
                                        epb.data.to_vec(),
                                    );

                                    reader.consume(offset);
                                    return Ok(Some(raw));
                                }
                                Block::SimplePacket(spb) => {
                                    self.frame_number += 1;

                                    let raw = RawPacket::new(
                                        self.frame_number,
                                        0, // No timestamp in simple packets
                                        spb.data.len() as u32,
                                        spb.origlen,
                                        self.link_type,
                                        spb.data.to_vec(),
                                    );

                                    reader.consume(offset);
                                    return Ok(Some(raw));
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
                Err(PcapError::Eof) => return Ok(None),
                Err(PcapError::Incomplete(_)) => {
                    reader.refill().map_err(|e| {
                        Error::Pcap(OurPcapError::InvalidFormat {
                            reason: format!("Refill error: {e}"),
                        })
                    })?;
                    continue;
                }
                Err(e) => {
                    return Err(Error::Pcap(OurPcapError::InvalidFormat {
                        reason: format!("Parse error: {e}"),
                    }))
                }
            }
        }
    }
}

/// Check if a file is gzipped by extension or magic bytes.
fn is_gzip_file<P: AsRef<Path>>(path: P) -> Result<bool, Error> {
    let path = path.as_ref();

    // Check by extension first
    if let Some(filename) = path.file_name().and_then(|f| f.to_str()) {
        let lower = filename.to_lowercase();
        if lower.ends_with(".gz") {
            return Ok(true);
        }
    }

    // Check by magic bytes
    let mut file = File::open(path).map_err(|_| {
        Error::Pcap(OurPcapError::FileNotFound {
            path: path.display().to_string(),
        })
    })?;

    let mut magic = [0u8; 2];
    match file.read_exact(&mut magic) {
        Ok(()) => Ok(magic == GZIP_MAGIC),
        Err(_) => Ok(false), // File too short to be gzipped
    }
}

/// Check if a path appears to be a gzip file by extension only.
/// Useful for quick checks without opening the file.
pub fn is_gzip_extension<P: AsRef<Path>>(path: P) -> bool {
    let path = path.as_ref();
    if let Some(filename) = path.file_name().and_then(|f| f.to_str()) {
        let lower = filename.to_lowercase();
        lower.ends_with(".gz")
    } else {
        false
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
    use std::io::Write;
    use tempfile::NamedTempFile;
    use flate2::write::GzEncoder;
    use flate2::Compression;

    #[test]
    fn test_detect_gzip_by_extension() {
        assert!(is_gzip_extension("test.pcap.gz"));
        assert!(is_gzip_extension("test.pcapng.gz"));
        assert!(is_gzip_extension("TEST.PCAP.GZ"));
        assert!(!is_gzip_extension("test.pcap"));
        assert!(!is_gzip_extension("test.pcapng"));
    }

    #[test]
    fn test_detect_gzip_by_magic_bytes() {
        // Create a temp file with gzip magic bytes
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(&GZIP_MAGIC).unwrap();
        temp.write_all(&[0x00, 0x00]).unwrap();
        temp.flush().unwrap();

        assert!(is_gzip_file(temp.path()).unwrap());
    }

    #[test]
    fn test_non_gzip_file() {
        // Create a temp file without gzip magic
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(&[0xd4, 0xc3, 0xb2, 0xa1]).unwrap(); // PCAP magic
        temp.flush().unwrap();

        assert!(!is_gzip_file(temp.path()).unwrap());
    }

    #[test]
    fn test_create_and_read_gzip_pcap() {
        // Create a minimal valid PCAP file
        let pcap_data = create_minimal_pcap();

        // Compress it with gzip
        let temp = NamedTempFile::with_suffix(".pcap.gz").unwrap();
        {
            let file = File::create(temp.path()).unwrap();
            let mut encoder = GzEncoder::new(file, Compression::default());
            encoder.write_all(&pcap_data).unwrap();
            encoder.finish().unwrap();
        }

        // Try to open it
        let reader = PcapReader::open(temp.path());
        assert!(reader.is_ok(), "Failed to open gzipped PCAP: {:?}", reader.err());
    }

    /// Create a minimal valid PCAP file with one empty packet.
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
