//! PCAP file reader.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError, PcapNGReader};

use super::RawPacket;
use crate::error::{Error, PcapError as OurPcapError};

/// Buffer size for reading PCAP files (64KB).
const BUFFER_SIZE: usize = 65536;

/// Reader for PCAP and PCAPNG files.
pub struct PcapReader {
    inner: ReaderInner,
    frame_number: u64,
    link_type: u16,
}

enum ReaderInner {
    Legacy(LegacyPcapReader<BufReader<File>>),
    Ng(PcapNGReader<BufReader<File>>),
}

impl PcapReader {
    /// Open a PCAP file for reading.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let path = path.as_ref();
        let file = File::open(path).map_err(|_| {
            Error::Pcap(OurPcapError::FileNotFound {
                path: path.display().to_string(),
            })
        })?;

        let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);

        // Peek at magic number to determine format
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic).map_err(|_| {
            Error::Pcap(OurPcapError::InvalidFormat {
                reason: "File too short to read magic number".to_string(),
            })
        })?;

        // Reset reader position
        drop(reader);
        let file = File::open(path)?;
        let reader = BufReader::with_capacity(BUFFER_SIZE, file);

        // Check magic number
        match &magic {
            // PCAP magic (little endian)
            [0xd4, 0xc3, 0xb2, 0xa1] => Self::open_legacy(reader),
            // PCAP magic (big endian)
            [0xa1, 0xb2, 0xc3, 0xd4] => Self::open_legacy(reader),
            // PCAP nanosecond (little endian)
            [0x4d, 0x3c, 0xb2, 0xa1] => Self::open_legacy(reader),
            // PCAP nanosecond (big endian)
            [0xa1, 0xb2, 0x3c, 0x4d] => Self::open_legacy(reader),
            // PCAPNG
            [0x0a, 0x0d, 0x0d, 0x0a] => Self::open_ng(reader),
            _ => Err(Error::Pcap(OurPcapError::InvalidFormat {
                reason: format!("Unknown magic number: {magic:02x?}"),
            })),
        }
    }

    fn open_legacy(reader: BufReader<File>) -> Result<Self, Error> {
        let pcap_reader = LegacyPcapReader::new(BUFFER_SIZE, reader).map_err(|e| {
            Error::Pcap(OurPcapError::InvalidFormat {
                reason: format!("Failed to parse PCAP header: {e}"),
            })
        })?;

        // Get link type from header
        // Note: pcap-parser doesn't expose this directly in the iterator,
        // we'll get it from the first packet's context
        Ok(Self {
            inner: ReaderInner::Legacy(pcap_reader),
            frame_number: 0,
            link_type: 1, // Default to Ethernet, will be updated
        })
    }

    fn open_ng(reader: BufReader<File>) -> Result<Self, Error> {
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
