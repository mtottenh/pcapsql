//! Generic PCAP/PCAPNG reader over any Read source.
//!
//! This module provides a unified PCAP parser that works with any `R: Read` source,
//! using the `pcap_parser` crate.
//!
//! ## Timestamps
//!
//! Packet timestamps are decoded to **nanoseconds since the Unix epoch** (`i64`).
//! For legacy PCAP the sub-second field is interpreted per the magic (microseconds
//! or nanoseconds). For PCAPNG the per-interface `if_tsresol` is honored, so a
//! capture mixing microsecond- and nanosecond-resolution interfaces decodes
//! correctly. This per-interface state is exactly what a mid-file partition needs,
//! and is what the boundary index persists in each checkpoint.
//!
//! ## Mid-file / headerless starts
//!
//! [`GenericPcapReader::with_format_starting_at`] constructs a reader whose first
//! frame is numbered `start_frame` instead of 1. The caller is responsible for
//! supplying a byte stream that begins with a (real or synthesized) header
//! followed by record data at a record boundary — see [`crate::io::index`] for the
//! header synthesis used by seekable sources.

use std::io::{BufReader, Read};

use pcap_parser::pcapng::Block;
use pcap_parser::traits::{PcapNGPacketBlock, PcapReaderIterator};
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError as PcapParserError, PcapNGReader};

use crate::error::{Error, PcapError};
use crate::io::PacketRef;

/// Initial buffer size for pcap_parser readers (256 KiB).
///
/// Frames larger than this are handled by growing the buffer on demand (see the
/// `BufferTooSmall` handling in the read loops).
const BUFFER_SIZE: usize = 262144;

/// Hard ceiling for the read buffer (64 MiB).
///
/// `BufferTooSmall` is raised from the *declared* record length, so without a
/// ceiling a single corrupt caplen would keep doubling the buffer until the
/// allocation failed. No real link layer produces frames this large.
pub(crate) const MAX_BUFFER_SIZE: usize = 64 * 1024 * 1024;

/// Default timestamp resolution (units per second) when none is known: microseconds.
const DEFAULT_RESOLUTION: u64 = 1_000_000;

/// Decode a PCAPNG `if_tsresol` byte into units per second.
///
/// Bit 7 clear: the low 7 bits are a power of ten (`6` ⇒ 10⁶ = microseconds).
/// Bit 7 set: the low 7 bits are a power of two (`0x8A` ⇒ 2¹⁰ units per second).
/// Returns `None` for exponents that do not fit in a `u64` (decimal > 19,
/// binary > 63). Decoded locally rather than via `pcap_parser` because its
/// `build_ts_resolution` rejects every binary resolution (it range-checks the
/// raw byte, which always has bit 7 set in that branch).
#[inline]
pub fn tsresol_units(if_tsresol: u8) -> Option<u64> {
    let exp = u32::from(if_tsresol & 0x7F);
    if if_tsresol & 0x80 == 0 {
        (exp <= 19).then(|| 10u64.pow(exp))
    } else {
        (exp <= 63).then(|| 1u64 << exp)
    }
}

/// Per-interface state required to interpret packets (PCAPNG).
///
/// For legacy PCAP there is a single implicit interface; this type is used for
/// PCAPNG where each Interface Description Block introduces one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceInfo {
    /// Link-layer type for packets on this interface.
    pub link_type: u32,
    /// `if_tsresol` raw byte (decimal exponent, or binary if high bit set).
    pub if_tsresol: u8,
    /// Snapshot length declared for this interface.
    pub snaplen: u32,
}

impl InterfaceInfo {
    /// Timestamp resolution in units per second (e.g. 1_000_000 for microseconds).
    #[inline]
    pub fn resolution(&self) -> u64 {
        tsresol_units(self.if_tsresol).unwrap_or(DEFAULT_RESOLUTION)
    }
}

/// The full interface table in effect at a point in a PCAPNG stream.
///
/// Persisted in boundary-index checkpoints so a partition starting mid-file can
/// reconstruct the interfaces (link type + `if_tsresol`) it needs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InterfaceState {
    /// Interfaces in declaration order; index == PCAPNG interface id within the section.
    pub interfaces: Vec<InterfaceInfo>,
    /// Byte order of the current section (from the SHB byte-order magic).
    ///
    /// A synthesized header for a mid-file partition must use the same byte
    /// order as the blocks that follow it, or every block length is misread.
    pub big_endian: bool,
}

/// Convert a legacy timestamp (seconds + sub-second field) to nanoseconds.
#[inline]
pub(crate) fn ns_from_legacy(ts_sec: u32, ts_frac: u32, nano: bool) -> i64 {
    let sub_ns = if nano {
        ts_frac as i64
    } else {
        (ts_frac as i64) * 1_000
    };
    (ts_sec as i64) * 1_000_000_000 + sub_ns
}

/// Convert PCAPNG timestamp ticks to nanoseconds given the interface resolution.
#[inline]
pub(crate) fn ns_from_ticks(ts_high: u32, ts_low: u32, resolution: u64) -> i64 {
    let ticks = ((ts_high as u128) << 32) | (ts_low as u128);
    let res = if resolution == 0 {
        DEFAULT_RESOLUTION
    } else {
        resolution
    } as u128;
    (ticks * 1_000_000_000u128 / res) as i64
}

/// Format of the PCAP file.
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
    /// Detect PCAP format from the file's leading magic bytes.
    ///
    /// Matches the on-disk byte sequence directly, so detection is independent
    /// of the host's endianness. (Decoding the magic as a host-order integer
    /// would swap the LE/BE variants when running on a big-endian host.)
    pub fn detect(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 4 {
            return Err(Error::Pcap(PcapError::InvalidFormat {
                reason: "Data too small for PCAP magic".into(),
            }));
        }

        match [data[0], data[1], data[2], data[3]] {
            // Legacy magic 0xA1B2C3D4 (microseconds) written by LE / BE hosts.
            [0xd4, 0xc3, 0xb2, 0xa1] => Ok(PcapFormat::LegacyLeMicro),
            [0xa1, 0xb2, 0xc3, 0xd4] => Ok(PcapFormat::LegacyBeMicro),
            // Legacy magic 0xA1B23C4D (nanoseconds) written by LE / BE hosts.
            [0x4d, 0x3c, 0xb2, 0xa1] => Ok(PcapFormat::LegacyLeNano),
            [0xa1, 0xb2, 0x3c, 0x4d] => Ok(PcapFormat::LegacyBeNano),
            // PCAPNG Section Header Block type (palindromic across endianness).
            [0x0a, 0x0d, 0x0d, 0x0a] => Ok(PcapFormat::PcapNg),
            other => Err(Error::Pcap(PcapError::InvalidFormat {
                reason: format!("Unknown PCAP magic: {other:02x?}"),
            })),
        }
    }

    /// Whether this is a PCAPNG format.
    pub fn is_pcapng(&self) -> bool {
        matches!(self, PcapFormat::PcapNg)
    }

    /// Whether this is a legacy PCAP format.
    pub fn is_legacy(&self) -> bool {
        !self.is_pcapng()
    }

    /// Whether the legacy sub-second field is nanoseconds (vs microseconds).
    pub fn legacy_is_nano(&self) -> bool {
        matches!(self, PcapFormat::LegacyLeNano | PcapFormat::LegacyBeNano)
    }

    /// Whether this format uses big-endian byte order on disk.
    pub fn is_big_endian(&self) -> bool {
        matches!(self, PcapFormat::LegacyBeMicro | PcapFormat::LegacyBeNano)
    }

    /// Whether this format uses little-endian byte order.
    pub fn is_little_endian(&self) -> bool {
        !self.is_big_endian()
    }

    /// The 32-bit magic value for a legacy format (host-order u32).
    pub fn legacy_magic_u32(&self) -> u32 {
        match self {
            PcapFormat::LegacyLeMicro | PcapFormat::LegacyBeMicro => 0xa1b2_c3d4,
            PcapFormat::LegacyLeNano | PcapFormat::LegacyBeNano => 0xa1b2_3c4d,
            PcapFormat::PcapNg => 0x0a0d_0d0a,
        }
    }
}

/// Generic PCAP/PCAPNG reader over any Read source.
pub struct GenericPcapReader<R: Read> {
    inner: ReaderInner<R>,
    format: PcapFormat,
    frame_number: u64,
    link_type: u32,
    /// PCAPNG interface table for the current section (empty for legacy).
    interfaces: Vec<InterfaceInfo>,
    /// Byte order of the current PCAPNG section (false for legacy).
    big_endian: bool,
    /// Current buffer capacity, grown on demand for oversized frames.
    capacity: usize,
}

/// Inner reader using enum dispatch for format-specific handling.
enum ReaderInner<R: Read> {
    Legacy(LegacyPcapReader<BufReader<R>>),
    Ng(PcapNGReader<BufReader<R>>),
}

impl<R: Read> GenericPcapReader<R> {
    /// Create a reader with known format, starting at frame 1.
    ///
    /// The byte stream must begin with the appropriate header (legacy global
    /// header, or PCAPNG section header block).
    pub fn with_format(source: R, format: PcapFormat) -> Result<Self, Error> {
        Self::build(source, format, 0)
    }

    /// Create a reader whose first emitted frame is numbered `start_frame`.
    ///
    /// Used for mid-file partitions: the supplied byte stream must begin with a
    /// real or synthesized header (so link type / interface state are
    /// established) followed by record data at a record boundary.
    pub fn with_format_starting_at(
        source: R,
        format: PcapFormat,
        start_frame: u64,
    ) -> Result<Self, Error> {
        let prev = start_frame.saturating_sub(1);
        Self::build(source, format, prev)
    }

    fn build(source: R, format: PcapFormat, initial_frame: u64) -> Result<Self, Error> {
        let buf_reader = BufReader::with_capacity(BUFFER_SIZE, source);

        let (inner, link_type) = if format.is_pcapng() {
            let reader = PcapNGReader::new(BUFFER_SIZE, buf_reader).map_err(|e| {
                Error::Pcap(PcapError::InvalidFormat {
                    reason: format!("Failed to parse PCAPNG: {e:?}"),
                })
            })?;
            (ReaderInner::Ng(reader), 1u32)
        } else {
            let mut reader = LegacyPcapReader::new(BUFFER_SIZE, buf_reader).map_err(|e| {
                Error::Pcap(PcapError::InvalidFormat {
                    reason: format!("Failed to parse legacy PCAP: {e:?}"),
                })
            })?;
            let link_type = Self::read_legacy_header_link_type(&mut reader)?;
            (ReaderInner::Legacy(reader), link_type)
        };

        Ok(GenericPcapReader {
            inner,
            format,
            frame_number: initial_frame,
            link_type,
            interfaces: Vec::new(),
            big_endian: false,
            capacity: BUFFER_SIZE,
        })
    }

    /// Read the legacy PCAP header to extract link_type, leaving the reader
    /// positioned at the first packet record.
    fn read_legacy_header_link_type<S: Read>(
        reader: &mut LegacyPcapReader<S>,
    ) -> Result<u32, Error> {
        loop {
            match reader.next() {
                Ok((offset, block)) => match block {
                    PcapBlockOwned::LegacyHeader(header) => {
                        let link_type = header.network.0 as u32;
                        reader.consume(offset);
                        return Ok(link_type);
                    }
                    PcapBlockOwned::Legacy(_) => {
                        // Header already consumed elsewhere; default to Ethernet.
                        return Ok(1);
                    }
                    _ => {
                        reader.consume(offset);
                        continue;
                    }
                },
                Err(PcapParserError::Eof) | Err(PcapParserError::UnexpectedEof) => return Ok(1),
                Err(PcapParserError::Incomplete(_)) => {
                    reader.refill().map_err(|e| {
                        Error::Pcap(PcapError::InvalidFormat {
                            reason: format!("Failed to read PCAP header: {e:?}"),
                        })
                    })?;
                    continue;
                }
                Err(e) => {
                    return Err(Error::Pcap(PcapError::InvalidFormat {
                        reason: format!("Failed to parse PCAP header: {e:?}"),
                    }));
                }
            }
        }
    }

    /// Get the link type (e.g., 1 = Ethernet). For PCAPNG this reflects the most
    /// recently seen interface.
    pub fn link_type(&self) -> u32 {
        self.link_type
    }

    /// Get the current frame count (number of packets emitted so far, offset by
    /// the starting frame for mid-file readers).
    pub fn frame_count(&self) -> u64 {
        self.frame_number
    }

    /// Number of bytes consumed from the underlying stream so far.
    pub fn consumed_bytes(&self) -> u64 {
        match &self.inner {
            ReaderInner::Legacy(r) => r.consumed() as u64,
            ReaderInner::Ng(r) => r.consumed() as u64,
        }
    }

    /// Snapshot of the current PCAPNG interface table.
    pub fn interface_state(&self) -> InterfaceState {
        InterfaceState {
            interfaces: self.interfaces.clone(),
            big_endian: self.big_endian,
        }
    }

    /// Process up to `max` packets, invoking `f` with borrowed packet data.
    ///
    /// Returns the number of packets delivered. An error returned by `f`
    /// stops the loop and is propagated, but the packet it was called with
    /// counts as processed (it is consumed and its frame number is spent), so
    /// a caller that uses an error to pause resumes at the next record with
    /// no re-delivery.
    #[inline]
    pub fn process_packets<F>(&mut self, max: usize, f: F) -> Result<usize, Error>
    where
        F: FnMut(PacketRef<'_>) -> Result<(), Error>,
    {
        let nano = self.format.legacy_is_nano();
        match &mut self.inner {
            ReaderInner::Legacy(reader) => process_legacy_packets(
                reader,
                max,
                &mut self.frame_number,
                &mut self.link_type,
                nano,
                &mut self.capacity,
                f,
            ),
            ReaderInner::Ng(reader) => process_pcapng_packets(
                reader,
                max,
                &mut self.frame_number,
                &mut self.link_type,
                &mut self.interfaces,
                &mut self.big_endian,
                &mut self.capacity,
                f,
            ),
        }
    }
}

/// Log that a capture ended inside a record (truncated file or stalled stream).
fn warn_truncated(what: &str, consumed: usize, frames: u64) {
    tracing::warn!(
        byte_offset = consumed,
        frames_read = frames,
        "{what}: capture is truncated (record header declares more bytes than remain); \
         returning the complete prefix"
    );
}

/// Grow the buffer to fit a frame larger than the current capacity.
fn grow_buffer<I: PcapReaderIterator>(
    reader: &mut I,
    capacity: &mut usize,
    what: &str,
) -> Result<(), Error> {
    let new_cap = capacity.saturating_mul(2);
    if new_cap == *capacity || new_cap > MAX_BUFFER_SIZE || !reader.grow(new_cap) {
        return Err(Error::Pcap(PcapError::InvalidFormat {
            reason: format!(
                "{what}: frame exceeds maximum buffer size ({} MiB); the record length is probably corrupt",
                MAX_BUFFER_SIZE / (1024 * 1024)
            ),
        }));
    }
    *capacity = new_cap;
    reader.refill().map_err(|e| {
        Error::Pcap(PcapError::InvalidFormat {
            reason: format!("{what} refill error: {e:?}"),
        })
    })
}

/// Process packets from a legacy PCAP reader with zero-copy.
#[allow(clippy::too_many_arguments)]
fn process_legacy_packets<S: Read, F>(
    reader: &mut LegacyPcapReader<S>,
    max: usize,
    frame_number: &mut u64,
    link_type: &mut u32,
    nano: bool,
    capacity: &mut usize,
    mut f: F,
) -> Result<usize, Error>
where
    F: FnMut(PacketRef<'_>) -> Result<(), Error>,
{
    let mut count = 0;
    while count < max {
        match reader.next() {
            Ok((offset, block)) => match block {
                PcapBlockOwned::Legacy(packet) => {
                    *frame_number += 1;
                    let timestamp_ns = ns_from_legacy(packet.ts_sec, packet.ts_usec, nano);
                    let packet_ref = PacketRef {
                        frame_number: *frame_number,
                        timestamp_ns,
                        captured_len: packet.caplen,
                        original_len: packet.origlen,
                        link_type: *link_type as u16,
                        data: packet.data,
                    };
                    // The packet has been delivered: consume it before
                    // propagating a callback error, so a caller that stops
                    // early resumes at the next record (no re-delivery).
                    let r = f(packet_ref);
                    reader.consume(offset);
                    count += 1;
                    r?;
                }
                PcapBlockOwned::LegacyHeader(header) => {
                    *link_type = header.network.0 as u32;
                    reader.consume(offset);
                }
                _ => {
                    reader.consume(offset);
                }
            },
            Err(PcapParserError::Eof) => break,
            // Truncated capture: the last record declares more bytes than are
            // present. Stop cleanly with the complete prefix, but say so.
            Err(PcapParserError::UnexpectedEof) => {
                warn_truncated("Legacy PCAP", reader.consumed(), *frame_number);
                break;
            }
            Err(PcapParserError::Incomplete(_)) => {
                reader.refill().map_err(|e| {
                    Error::Pcap(PcapError::InvalidFormat {
                        reason: format!("Legacy PCAP refill error: {e:?}"),
                    })
                })?;
            }
            Err(PcapParserError::BufferTooSmall) => {
                grow_buffer(reader, capacity, "Legacy PCAP")?;
            }
            Err(e) => {
                return Err(Error::Pcap(PcapError::InvalidFormat {
                    reason: format!("Legacy PCAP parse error: {e:?}"),
                }));
            }
        }
    }
    Ok(count)
}

/// Process packets from a PCAPNG reader with zero-copy, honoring per-interface
/// link type and timestamp resolution.
#[allow(clippy::too_many_arguments)]
fn process_pcapng_packets<S: Read, F>(
    reader: &mut PcapNGReader<S>,
    max: usize,
    frame_number: &mut u64,
    link_type: &mut u32,
    interfaces: &mut Vec<InterfaceInfo>,
    big_endian: &mut bool,
    capacity: &mut usize,
    mut f: F,
) -> Result<usize, Error>
where
    F: FnMut(PacketRef<'_>) -> Result<(), Error>,
{
    let mut count = 0;
    while count < max {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::NG(ng_block) => match ng_block {
                        Block::SectionHeader(shb) => {
                            // New section: interface namespace resets; byte
                            // order may change.
                            interfaces.clear();
                            *big_endian = shb.big_endian();
                            reader.consume(offset);
                        }
                        Block::InterfaceDescription(idb) => {
                            let info = InterfaceInfo {
                                link_type: idb.linktype.0 as u32,
                                if_tsresol: idb.if_tsresol,
                                snaplen: idb.snaplen,
                            };
                            if tsresol_units(info.if_tsresol).is_none() {
                                tracing::warn!(
                                    if_tsresol = info.if_tsresol,
                                    interface = interfaces.len(),
                                    "PCAPNG: invalid if_tsresol; assuming microseconds"
                                );
                            }
                            *link_type = info.link_type;
                            interfaces.push(info);
                            reader.consume(offset);
                        }
                        Block::EnhancedPacket(epb) => {
                            *frame_number += 1;
                            let (lt, resolution) = interfaces
                                .get(epb.if_id as usize)
                                .map(|i| (i.link_type, i.resolution()))
                                .unwrap_or((*link_type, DEFAULT_RESOLUTION));
                            let timestamp_ns = ns_from_ticks(epb.ts_high, epb.ts_low, resolution);
                            // `packet_data()` strips the on-disk 32-bit padding.
                            let data = epb.packet_data();
                            let packet_ref = PacketRef {
                                frame_number: *frame_number,
                                timestamp_ns,
                                captured_len: epb.caplen,
                                original_len: epb.origlen,
                                link_type: lt as u16,
                                data,
                            };
                            let r = f(packet_ref);
                            reader.consume(offset);
                            count += 1;
                            r?;
                        }
                        Block::SimplePacket(spb) => {
                            *frame_number += 1;
                            let lt = interfaces
                                .first()
                                .map(|i| i.link_type)
                                .unwrap_or(*link_type);
                            let data = spb.packet_data();
                            let packet_ref = PacketRef {
                                frame_number: *frame_number,
                                timestamp_ns: 0,
                                captured_len: data.len() as u32,
                                original_len: spb.origlen,
                                link_type: lt as u16,
                                data,
                            };
                            let r = f(packet_ref);
                            reader.consume(offset);
                            count += 1;
                            r?;
                        }
                        _ => {
                            reader.consume(offset);
                        }
                    },
                    _ => {
                        reader.consume(offset);
                    }
                }
            }
            Err(PcapParserError::Eof) => break,
            Err(PcapParserError::UnexpectedEof) => {
                warn_truncated("PCAPNG", reader.consumed(), *frame_number);
                break;
            }
            Err(PcapParserError::Incomplete(_)) => {
                reader.refill().map_err(|e| {
                    Error::Pcap(PcapError::InvalidFormat {
                        reason: format!("PCAPNG refill error: {e:?}"),
                    })
                })?;
            }
            Err(PcapParserError::BufferTooSmall) => {
                grow_buffer(reader, capacity, "PCAPNG")?;
            }
            Err(e) => {
                return Err(Error::Pcap(PcapError::InvalidFormat {
                    reason: format!("PCAPNG parse error: {e:?}"),
                }));
            }
        }
    }
    Ok(count)
}

// GenericPcapReader is Send when R is Send
unsafe impl<R: Read + Send> Send for GenericPcapReader<R> {}

// Required for async compatibility
impl<R: Read> Unpin for GenericPcapReader<R> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A callback error stops the loop *after* the packet it was called
    /// with: that packet is consumed and its frame number spent, so a caller
    /// that pauses with an error resumes at the next record (no duplicate).
    #[test]
    fn callback_error_consumes_the_delivered_packet() {
        use pcapsql_testgen::{legacy_pcap, GenPacket, LegacyVariant};
        let packets: Vec<GenPacket> = (0..5u32)
            .map(|i| GenPacket {
                ts_sec: 1_700_000_000 + i,
                ts_frac: 0,
                data: vec![i as u8; 20],
                origlen: 20,
            })
            .collect();
        let bytes = legacy_pcap(LegacyVariant::LeMicro, 1, 65535, &packets).bytes;
        let mut reader =
            GenericPcapReader::with_format(Cursor::new(bytes), PcapFormat::LegacyLeMicro).unwrap();

        // Stop after the second packet by returning an error from the callback.
        let mut seen = Vec::new();
        let err = reader.process_packets(10, |p| {
            seen.push(p.frame_number);
            if p.frame_number == 2 {
                Err(Error::Io(std::io::Error::other("pause")))
            } else {
                Ok(())
            }
        });
        assert!(err.is_err());
        assert_eq!(seen, vec![1, 2]);

        // Resume: frames 3, 4, 5 follow with no re-delivery of frame 2.
        let mut rest = Vec::new();
        let n = reader
            .process_packets(10, |p| {
                rest.push(p.frame_number);
                Ok(())
            })
            .unwrap();
        assert_eq!(n, 3);
        assert_eq!(rest, vec![3, 4, 5]);
        assert_eq!(reader.process_packets(10, |_| Ok(())).unwrap(), 0);
    }

    #[test]
    fn test_pcap_format_detect() {
        let le_micro = [0xd4, 0xc3, 0xb2, 0xa1];
        assert_eq!(
            PcapFormat::detect(&le_micro).unwrap(),
            PcapFormat::LegacyLeMicro
        );

        let be_micro = [0xa1, 0xb2, 0xc3, 0xd4];
        assert_eq!(
            PcapFormat::detect(&be_micro).unwrap(),
            PcapFormat::LegacyBeMicro
        );

        let le_nano = [0x4d, 0x3c, 0xb2, 0xa1];
        assert_eq!(
            PcapFormat::detect(&le_nano).unwrap(),
            PcapFormat::LegacyLeNano
        );

        let be_nano = [0xa1, 0xb2, 0x3c, 0x4d];
        assert_eq!(
            PcapFormat::detect(&be_nano).unwrap(),
            PcapFormat::LegacyBeNano
        );

        let pcapng = [0x0a, 0x0d, 0x0d, 0x0a];
        assert_eq!(PcapFormat::detect(&pcapng).unwrap(), PcapFormat::PcapNg);

        let unknown = [0xDE, 0xAD, 0xBE, 0xEF];
        assert!(PcapFormat::detect(&unknown).is_err());
    }

    #[test]
    fn test_tsresol_units_decimal_and_binary() {
        assert_eq!(tsresol_units(6), Some(1_000_000));
        assert_eq!(tsresol_units(9), Some(1_000_000_000));
        assert_eq!(tsresol_units(0), Some(1));
        assert_eq!(tsresol_units(19), Some(10u64.pow(19)));
        assert_eq!(tsresol_units(20), None);
        // Binary exponents: bit 7 set, low 7 bits = power of two.
        assert_eq!(tsresol_units(0x80), Some(1));
        assert_eq!(tsresol_units(0x8A), Some(1024));
        assert_eq!(tsresol_units(0x80 | 63), Some(1u64 << 63));
        assert_eq!(tsresol_units(0x80 | 64), None);
        // The reader falls back to microseconds for invalid bytes.
        let info = InterfaceInfo {
            link_type: 1,
            if_tsresol: 0x80 | 64,
            snaplen: 0,
        };
        assert_eq!(info.resolution(), DEFAULT_RESOLUTION);
    }

    #[test]
    fn test_pcap_format_properties() {
        assert!(PcapFormat::LegacyLeMicro.is_legacy());
        assert!(!PcapFormat::LegacyLeMicro.is_pcapng());
        assert!(PcapFormat::PcapNg.is_pcapng());
        assert!(PcapFormat::LegacyLeNano.legacy_is_nano());
        assert!(!PcapFormat::LegacyLeMicro.legacy_is_nano());
        assert!(PcapFormat::LegacyBeMicro.is_big_endian());
    }

    #[test]
    fn test_ns_conversions() {
        // micro: 1.5s -> 1_500_000 us -> 1_500_000_000 ns
        assert_eq!(ns_from_legacy(1, 500_000, false), 1_500_000_000);
        // nano: 1.5s -> 500_000_000 ns
        assert_eq!(ns_from_legacy(1, 500_000_000, true), 1_500_000_000);
        // ticks at microsecond resolution
        assert_eq!(ns_from_ticks(0, 1_500_000, 1_000_000), 1_500_000_000);
        // ticks at nanosecond resolution
        assert_eq!(
            ns_from_ticks(0, 1_500_000_000, 1_000_000_000),
            1_500_000_000
        );
    }

    /// Create a minimal valid legacy PCAP (LE micro) with one packet.
    fn create_minimal_pcap() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]); // Magic (LE micro)
        data.extend_from_slice(&[0x02, 0x00]); // Version major
        data.extend_from_slice(&[0x04, 0x00]); // Version minor
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Thiszone
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Sigfigs
        data.extend_from_slice(&[0xff, 0xff, 0x00, 0x00]); // Snaplen
        data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Network (Ethernet)

        let packet_data = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
        ];
        let ts_sec: u32 = 1_000_000_000;
        let ts_usec: u32 = 500_000;
        data.extend_from_slice(&ts_sec.to_le_bytes());
        data.extend_from_slice(&ts_usec.to_le_bytes());
        data.extend_from_slice(&(packet_data.len() as u32).to_le_bytes());
        data.extend_from_slice(&(packet_data.len() as u32).to_le_bytes());
        data.extend_from_slice(&packet_data);
        data
    }

    #[test]
    fn test_generic_reader_from_memory() {
        let pcap_data = create_minimal_pcap();
        let format = PcapFormat::detect(&pcap_data).expect("detect");
        let cursor = Cursor::new(pcap_data);
        let mut reader = GenericPcapReader::with_format(cursor, format).expect("reader");

        let mut seen = Vec::new();
        loop {
            let n = reader
                .process_packets(16, |p| {
                    seen.push((p.frame_number, p.captured_len, p.link_type, p.timestamp_ns));
                    Ok(())
                })
                .expect("read");
            if n == 0 {
                break;
            }
        }
        assert_eq!(seen.len(), 1);
        let (frame, caplen, link, ts) = seen[0];
        assert_eq!(frame, 1);
        assert_eq!(caplen, 14);
        assert_eq!(link, 1);
        // 1_000_000_000 s + 500_000 us = 1e18 + 5e11 ns
        assert_eq!(ts, 1_000_000_000i64 * 1_000_000_000 + 500_000_000);
    }

    #[test]
    fn test_starting_at_offsets_frame_numbers() {
        let pcap_data = create_minimal_pcap();
        let format = PcapFormat::detect(&pcap_data).expect("detect");
        let cursor = Cursor::new(pcap_data);
        let mut reader =
            GenericPcapReader::with_format_starting_at(cursor, format, 100).expect("reader");
        let mut first_frame = None;
        reader
            .process_packets(1, |p| {
                first_frame = Some(p.frame_number);
                Ok(())
            })
            .expect("read");
        assert_eq!(first_frame, Some(100));
    }
}
