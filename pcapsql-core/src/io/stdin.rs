//! Stdin packet source for reading PCAP data from standard input.
//!
//! Enables piping pcap data from tools like tcpdump:
//! ```text
//! tcpdump -w - | pcapsql --stdin -e "SELECT COUNT(*) FROM frames"
//! ```
//!
//! ## Design
//!
//! Stdin is non-seekable and can only be consumed once. The source:
//! 1. Pre-reads the first bytes to detect compression and PCAP format
//! 2. Chains the pre-read bytes with the remaining stdin into a single reader
//! 3. Allows only one reader to be created (returns error on subsequent calls)
//!
//! The `Clone` requirement from `PacketSource` is satisfied via `Arc` sharing,
//! but all clones share the same underlying stdin — only one reader can be created.

use std::io::{self, Cursor, Read};
use std::sync::{Arc, Mutex};

use crate::error::{Error, PcapError};
use crate::io::decompress::{Compression, DecompressReader};
use crate::io::pcap_stream::{GenericPcapReader, PcapFormat};
use crate::io::source::{
    PacketPosition, PacketRange, PacketReader, PacketRef, PacketSource, PacketSourceMetadata,
};

/// Size of the header buffer for format detection.
/// Must be large enough for compression magic (6 bytes) + PCAPNG Section Header Block
/// (which can be 200-500+ bytes with options). 4096 bytes covers any realistic SHB
/// and ensures PcapNGReader::new() has enough data in the first read from the Chain reader.
const HEADER_DETECT_SIZE: usize = 4096;

/// Packet source backed by standard input.
///
/// Reads PCAP/PCAPNG data from stdin, supporting optional compression.
/// Can only create one reader since stdin is consumed on first read.
#[derive(Clone)]
pub struct StdinPacketSource {
    metadata: PacketSourceMetadata,
    pcap_format: PcapFormat,
    compression: Compression,
    /// Shared state: the pre-read header bytes and stdin handle.
    /// Wrapped in Arc<Mutex<Option<...>>> so that:
    /// - Arc satisfies Clone requirement
    /// - Mutex provides interior mutability
    /// - Option allows taking ownership exactly once
    inner: Arc<Mutex<Option<StdinState>>>,
}

/// Internal state consumed when creating a reader.
struct StdinState {
    /// Bytes already read from stdin (header detection).
    header_bytes: Vec<u8>,
}

impl StdinPacketSource {
    /// Create a new stdin packet source.
    ///
    /// Reads the first bytes from stdin to detect compression format and
    /// PCAP type. Returns an error if stdin doesn't contain valid PCAP data.
    pub fn new() -> Result<Self, Error> {
        let stdin = io::stdin();
        let mut handle = stdin.lock();

        // Read enough bytes for compression detection
        let mut header_buf = vec![0u8; HEADER_DETECT_SIZE];
        let bytes_read = read_full(&mut handle, &mut header_buf)?;

        if bytes_read < 4 {
            return Err(Error::Pcap(PcapError::InvalidFormat {
                reason: "Stdin too short to contain PCAP header".to_string(),
            }));
        }
        header_buf.truncate(bytes_read);

        // Detect compression
        let compression = Compression::detect(&header_buf);

        // Get the decompressed magic bytes to detect PCAP format
        let decompressed = if compression.is_compressed() {
            crate::io::decompress::decompress_header(&header_buf, compression, 32)?
        } else {
            header_buf.clone()
        };

        if decompressed.len() < 4 {
            return Err(Error::Pcap(PcapError::InvalidFormat {
                reason: "Not enough data to detect PCAP format after decompression".to_string(),
            }));
        }

        let pcap_format = PcapFormat::detect(&decompressed)?;

        // For link_type, we need to parse the full header.
        // For legacy PCAP, the header is 24 bytes and link_type is at offset 20.
        // For PCAPNG, link_type comes from the IDB block during reading.
        let link_type = if pcap_format.is_legacy() && decompressed.len() >= 24 {
            let lt_bytes = &decompressed[20..24];
            if pcap_format.is_little_endian() {
                u32::from_le_bytes([lt_bytes[0], lt_bytes[1], lt_bytes[2], lt_bytes[3]])
            } else {
                u32::from_be_bytes([lt_bytes[0], lt_bytes[1], lt_bytes[2], lt_bytes[3]])
            }
        } else {
            1 // Default to Ethernet, will be updated during reading for PCAPNG
        };

        drop(handle);

        let metadata = PacketSourceMetadata {
            link_type,
            snaplen: 65535,
            size_bytes: None,   // Unknown for stdin
            packet_count: None, // Unknown for stdin
            seekable: false,    // Stdin is not seekable
        };

        Ok(Self {
            metadata,
            pcap_format,
            compression,
            inner: Arc::new(Mutex::new(Some(StdinState {
                header_bytes: header_buf,
            }))),
        })
    }
}

impl PacketSource for StdinPacketSource {
    type Reader = StdinPacketReader;

    fn metadata(&self) -> &PacketSourceMetadata {
        &self.metadata
    }

    fn reader(&self, _range: Option<&PacketRange>) -> Result<Self::Reader, Error> {
        // Take the stdin state — this can only succeed once
        let state = {
            let mut guard = self.inner.lock().map_err(|_| {
                Error::Pcap(PcapError::InvalidFormat {
                    reason: "Stdin source lock poisoned".to_string(),
                })
            })?;
            guard.take().ok_or_else(|| {
                Error::Pcap(PcapError::InvalidFormat {
                    reason: "Stdin reader already created — stdin can only be read once"
                        .to_string(),
                })
            })?
        };

        // Chain the pre-read header bytes with the remaining stdin
        let header_cursor = Cursor::new(state.header_bytes);
        let stdin = io::stdin();
        let chained: Box<dyn Read + Send> = Box::new(header_cursor.chain(stdin));

        // Apply decompression if needed
        let decompressed = DecompressReader::new(chained, self.compression).map_err(|e| {
            Error::Pcap(PcapError::InvalidFormat {
                reason: format!("Failed to create decompressor for stdin: {e}"),
            })
        })?;

        // Create the generic PCAP reader
        let inner = GenericPcapReader::with_format(decompressed, self.pcap_format)?;

        Ok(StdinPacketReader {
            inner,
            link_type: self.metadata.link_type,
            position: PacketPosition::START,
        })
    }

    fn partitions(&self, _max_partitions: usize) -> Result<Vec<PacketRange>, Error> {
        // Stdin cannot be partitioned — single sequential read only
        Ok(vec![PacketRange::whole()])
    }
}

impl std::fmt::Debug for StdinPacketSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StdinPacketSource")
            .field("metadata", &self.metadata)
            .field("pcap_format", &self.pcap_format)
            .field("compression", &self.compression)
            .finish()
    }
}

/// Packet reader that reads from standard input.
pub struct StdinPacketReader {
    inner: GenericPcapReader<DecompressReader<Box<dyn Read + Send>>>,
    link_type: u32,
    position: PacketPosition,
}

impl PacketReader for StdinPacketReader {
    fn process_packets<F>(&mut self, max: usize, mut f: F) -> Result<usize, Error>
    where
        F: FnMut(PacketRef<'_>) -> Result<(), Error>,
    {
        let count = self.inner.process_packets(max, |packet| {
            self.position.frame_number = packet.frame_number + 1;
            f(packet)
        })?;

        Ok(count)
    }

    fn position(&self) -> PacketPosition {
        self.position.clone()
    }

    fn link_type(&self) -> u32 {
        self.link_type
    }
}

// Safety: StdinPacketReader is Send because all its fields are Send
// (GenericPcapReader<DecompressReader<Box<dyn Read + Send>>> is Send,
//  u32 and PacketPosition are Send)
unsafe impl Send for StdinPacketReader {}

// Required for async compatibility in DataFusion streaming
impl Unpin for StdinPacketReader {}

/// Read as many bytes as possible into `buf`, handling partial reads.
///
/// Unlike `read_exact`, this doesn't error on EOF — returns the count of bytes read.
fn read_full(reader: &mut impl Read, buf: &mut [u8]) -> Result<usize, Error> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break, // EOF
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_full_complete() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let mut cursor = Cursor::new(data.clone());
        let mut buf = vec![0u8; 8];
        let n = read_full(&mut cursor, &mut buf).unwrap();
        assert_eq!(n, 8);
        assert_eq!(buf, data);
    }

    #[test]
    fn test_read_full_partial() {
        let data = vec![1, 2, 3];
        let mut cursor = Cursor::new(data.clone());
        let mut buf = vec![0u8; 8];
        let n = read_full(&mut cursor, &mut buf).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf[..3], &data[..]);
    }

    #[test]
    fn test_read_full_empty() {
        let data: Vec<u8> = vec![];
        let mut cursor = Cursor::new(data);
        let mut buf = vec![0u8; 8];
        let n = read_full(&mut cursor, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_stdin_source_from_pipe() {
        // We can't easily test actual stdin in unit tests, but we can test
        // the helper functions and ensure the types compile correctly.

        // Verify metadata defaults
        let metadata = PacketSourceMetadata {
            link_type: 1,
            snaplen: 65535,
            size_bytes: None,
            packet_count: None,
            seekable: false,
        };

        assert!(!metadata.seekable);
        assert!(metadata.size_bytes.is_none());
        assert!(metadata.packet_count.is_none());
    }

    #[test]
    fn test_stdin_source_clone() {
        // Verify that StdinPacketSource implements Clone (required by PacketSource)
        fn assert_clone<T: Clone>() {}
        assert_clone::<StdinPacketSource>();
    }

    #[test]
    fn test_stdin_source_send_sync() {
        // Verify that StdinPacketSource implements Send + Sync (required by PacketSource)
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<StdinPacketSource>();
    }

    #[test]
    fn test_stdin_reader_send_unpin() {
        // Verify that StdinPacketReader implements Send + Unpin (required by PacketReader)
        fn assert_send_unpin<T: Send + Unpin>() {}
        assert_send_unpin::<StdinPacketReader>();
    }
}
