//! Building a [`BoundaryIndex`]: one header-only sequential scan of the
//! capture.

use std::io::Read;
use std::time::SystemTime;

use pcap_parser::pcapng::Block;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError as PcapParserError, PcapNGReader};

use super::{invalid, BoundaryIndex, Checkpoint};
use crate::error::Error;
use crate::io::pcap_stream::{
    ns_from_legacy, ns_from_ticks, InterfaceInfo, InterfaceState, MAX_BUFFER_SIZE,
};
use crate::io::PcapFormat;

/// Build a boundary index by a single sequential scan over the (uncompressed)
/// capture bytes. Records a checkpoint every `stride` frames (and always at
/// frame 1), capturing PCAPNG interface state at each.
pub fn build_boundary_index<R: Read>(
    source: R,
    format: PcapFormat,
    stride: u64,
    source_len: u64,
    source_mtime: Option<SystemTime>,
    header_hash: u64,
) -> Result<BoundaryIndex, Error> {
    build_boundary_index_to(
        source,
        format,
        stride,
        source_len,
        source_mtime,
        header_hash,
        None,
    )
}

/// [`build_boundary_index`] that reads no further than frame `last_frame`
/// when one is given: for a caller that will not read past that frame, so
/// that a scan of a capture's first frames does not start with a pass over
/// all of it.
///
/// The result is the index the capture had when frame `last_frame` was its
/// last ([`BoundaryIndex::packet_count`] is at most `last_frame`), with
/// `source_len` as given. A range to the end of the capture cut from it
/// delivers the later frames as it delivers frames appended to a capture
/// after its index was built, so nothing but
/// [`packet_count`](BoundaryIndex::packet_count) tells the two apart.
pub fn build_boundary_index_to<R: Read>(
    source: R,
    format: PcapFormat,
    stride: u64,
    source_len: u64,
    source_mtime: Option<SystemTime>,
    header_hash: u64,
    last_frame: Option<u64>,
) -> Result<BoundaryIndex, Error> {
    let stride = stride.max(1);
    let mut builder = IndexBuilder::new(stride);
    builder.last_frame = last_frame.unwrap_or(u64::MAX);
    if format.is_pcapng() {
        let mut reader = PcapNGReader::new(262144, source)
            .map_err(|e| invalid(&format!("PCAPNG index init: {e:?}")))?;
        scan_pcapng(&mut reader, &mut builder)?;
    } else {
        let mut reader = LegacyPcapReader::new(262144, source)
            .map_err(|e| invalid(&format!("legacy index init: {e:?}")))?;
        scan_legacy(&mut reader, &mut builder, format.legacy_is_nano())?;
    }
    Ok(BoundaryIndex {
        source_len,
        source_mtime,
        header_hash,
        source_etag: None,
        format,
        link_type: builder.link_type,
        snaplen: builder.snaplen,
        packet_count: builder.frame_number,
        stride,
        checkpoints: builder.checkpoints,
    })
}

/// Accumulates checkpoints during a scan.
struct IndexBuilder {
    stride: u64,
    frame_number: u64,
    link_type: u32,
    snaplen: u32,
    interfaces: Vec<InterfaceInfo>,
    /// Byte order of the current PCAPNG section.
    big_endian: bool,
    checkpoints: Vec<Checkpoint>,
    cur: Option<usize>,
    /// The frame the scan ends with, if the capture has that many.
    last_frame: u64,
}

impl IndexBuilder {
    fn new(stride: u64) -> Self {
        Self {
            stride,
            frame_number: 0,
            link_type: 1,
            snaplen: 0,
            interfaces: Vec::new(),
            big_endian: false,
            checkpoints: Vec::new(),
            cur: None,
            last_frame: u64::MAX,
        }
    }

    /// Whether the frame the scan is to end with has been seen.
    fn done(&self) -> bool {
        self.frame_number >= self.last_frame
    }

    /// Record a packet at `byte_offset` with timestamp `ts_ns`, deciding whether
    /// it begins a new checkpoint window.
    fn observe_packet(&mut self, byte_offset: u64, ts_ns: i64, pcapng: bool) {
        self.frame_number += 1;
        let frame = self.frame_number;
        let starts_window = frame == 1 || (frame - 1).is_multiple_of(self.stride);
        if starts_window {
            let interface_state = if pcapng {
                Some(InterfaceState {
                    interfaces: self.interfaces.clone(),
                    big_endian: self.big_endian,
                })
            } else {
                None
            };
            self.checkpoints.push(Checkpoint {
                frame_number: frame,
                byte_offset,
                interface_state,
                min_ts: Some(ts_ns),
                max_ts: Some(ts_ns),
            });
            self.cur = Some(self.checkpoints.len() - 1);
        } else if let Some(i) = self.cur {
            let cp = &mut self.checkpoints[i];
            cp.min_ts = Some(cp.min_ts.map_or(ts_ns, |m| m.min(ts_ns)));
            cp.max_ts = Some(cp.max_ts.map_or(ts_ns, |m| m.max(ts_ns)));
        }
    }
}

fn scan_legacy<S: Read>(
    reader: &mut LegacyPcapReader<S>,
    builder: &mut IndexBuilder,
    nano: bool,
) -> Result<(), Error> {
    let mut capacity = 262144usize;
    loop {
        // `consumed()` before `next()` is the byte offset of the block `next()`
        // is about to return (the start of its record).
        let block_start = reader.consumed() as u64;
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(hdr) => {
                        builder.link_type = hdr.network.0 as u32;
                        builder.snaplen = hdr.snaplen;
                    }
                    PcapBlockOwned::Legacy(pkt) => {
                        let ts = ns_from_legacy(pkt.ts_sec, pkt.ts_usec, nano);
                        builder.observe_packet(block_start, ts, false);
                    }
                    _ => {}
                }
                reader.consume(offset);
                if builder.done() {
                    break;
                }
            }
            Err(PcapParserError::Eof) | Err(PcapParserError::UnexpectedEof) => break,
            Err(PcapParserError::Incomplete(_)) => {
                reader
                    .refill()
                    .map_err(|e| invalid(&format!("legacy index refill: {e:?}")))?;
            }
            Err(PcapParserError::BufferTooSmall) => {
                capacity = grow(reader, capacity)?;
            }
            Err(e) => return Err(invalid(&format!("legacy index parse: {e:?}"))),
        }
    }
    Ok(())
}

fn scan_pcapng<S: Read>(
    reader: &mut PcapNGReader<S>,
    builder: &mut IndexBuilder,
) -> Result<(), Error> {
    let mut capacity = 262144usize;
    loop {
        // `consumed()` before `next()` is the byte offset of the block `next()`
        // is about to return (the start of its record).
        let block_start = reader.consumed() as u64;
        match reader.next() {
            Ok((offset, block)) => {
                if let PcapBlockOwned::NG(ng) = block {
                    match ng {
                        Block::SectionHeader(shb) => {
                            builder.interfaces.clear();
                            builder.big_endian = shb.big_endian();
                        }
                        Block::InterfaceDescription(idb) => {
                            // Same normalization as the packet reader, so the
                            // persisted interface state always validates.
                            let (info, _) = InterfaceInfo::from_idb(&idb, builder.big_endian);
                            if builder.interfaces.is_empty() {
                                builder.link_type = info.link_type;
                                builder.snaplen = info.snaplen;
                            }
                            builder.interfaces.push(info);
                        }
                        Block::EnhancedPacket(epb) => {
                            let ts = builder
                                .interfaces
                                .get(epb.if_id as usize)
                                .map(|i| i.timestamp_ns(epb.ts_high, epb.ts_low))
                                .unwrap_or_else(|| {
                                    ns_from_ticks(epb.ts_high, epb.ts_low, 1_000_000, 0)
                                });
                            builder.observe_packet(block_start, ts, true);
                        }
                        Block::SimplePacket(_) => {
                            builder.observe_packet(block_start, 0, true);
                        }
                        _ => {}
                    }
                }
                reader.consume(offset);
                if builder.done() {
                    break;
                }
            }
            Err(PcapParserError::Eof) | Err(PcapParserError::UnexpectedEof) => break,
            Err(PcapParserError::Incomplete(_)) => {
                reader
                    .refill()
                    .map_err(|e| invalid(&format!("pcapng index refill: {e:?}")))?;
            }
            Err(PcapParserError::BufferTooSmall) => {
                capacity = grow(reader, capacity)?;
            }
            Err(e) => return Err(invalid(&format!("pcapng index parse: {e:?}"))),
        }
    }
    Ok(())
}

fn grow<I: PcapReaderIterator>(reader: &mut I, capacity: usize) -> Result<usize, Error> {
    // Same ceiling as the packet reader: a corrupt record length must turn
    // into an error, not a multi-GiB zero-filled allocation.
    let new_cap = capacity.saturating_mul(2);
    if new_cap == capacity || new_cap > MAX_BUFFER_SIZE || !reader.grow(new_cap) {
        return Err(invalid(&format!(
            "index scan: frame exceeds maximum buffer size ({} MiB)",
            MAX_BUFFER_SIZE / (1024 * 1024)
        )));
    }
    reader
        .refill()
        .map_err(|e| invalid(&format!("index grow refill: {e:?}")))?;
    Ok(new_cap)
}
