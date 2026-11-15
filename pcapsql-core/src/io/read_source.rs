//! A [`PacketReader`] over any [`Read`].
//!
//! [`ReadPacketReader`] is the reader behind the file source, and the way a
//! host that owns its own file handles (a database engine's file system, an
//! in-memory buffer) reads a capture without going through a
//! [`PacketSource`](crate::io::PacketSource): the host opens the bytes, this
//! type parses them.

use std::io::{self, Chain, Cursor, Read};
use std::ops::ControlFlow;

use crate::error::{Error, PcapError};
use crate::io::decompress::{Compression, DecompressReader};
use crate::io::index::BoundaryIndex;
use crate::io::pcap_stream::{Delivered, GenericPcapReader, Pause, PcapFormat};
use crate::io::source::{
    starts_at_header, synth_header_for, PacketPosition, PacketRange, PacketReader, PacketRef,
};
use crate::io::stdin::StreamHeader;

/// The `Read` stack under a [`ReadPacketReader`]: bytes that come before the
/// stream (a probed head or a synthesized header, possibly empty), then the
/// stream itself, decompressed, with the first read made long enough for the
/// parser to see the whole capture header.
type Stack<R> = HeadFill<DecompressReader<Chain<Cursor<Vec<u8>>, R>>>;

/// Packet reader over any byte stream.
///
/// Two ways in: [`sequential`](Self::sequential) reads a whole capture from
/// its first frame (compressed or not), [`at`](Self::at) reads one
/// [`PacketRange`] of an uncompressed capture from a stream positioned at the
/// range's start.
pub struct ReadPacketReader<R: Read> {
    inner: GenericPcapReader<Stack<R>>,
    link_type: u32,
    end_frame: Option<u64>,
}

impl<R: Read> ReadPacketReader<R> {
    /// Reader over a whole capture, from its first frame.
    ///
    /// `header` is what [`StreamHeader::probe`] reported for the stream.
    /// `head` holds the bytes the probe took from `read` (what it returned),
    /// or is empty when `read` is positioned at the start of the capture
    /// again.
    pub fn sequential(read: R, header: &StreamHeader, head: Vec<u8>) -> Result<Self, Error> {
        Self::open(
            head,
            read,
            header.compression,
            header.format,
            header.header_len,
            None,
        )
    }

    /// Reader restricted to `range` of an uncompressed capture.
    ///
    /// `read` must be positioned at `range.start.byte_offset`, and `range`
    /// must come from `index` (its start is then a record boundary whose
    /// interface state the index knows). A range that starts at byte 0 is read
    /// from the capture's own header.
    pub fn at(
        read: R,
        format: PcapFormat,
        index: &BoundaryIndex,
        range: &PacketRange,
    ) -> Result<Self, Error> {
        let end_frame = range.end.as_ref().map(|e| e.frame_number);
        if starts_at_header(range) {
            // The capture's own header is of unknown length here: have the
            // first read fill the parser's buffer, as a regular file does.
            let reader = Self::open(
                Vec::new(),
                read,
                Compression::None,
                format,
                usize::MAX,
                None,
            )?;
            return Ok(reader.with_end_frame(end_frame));
        }
        let header = synth_header_for(index, range.start.frame_number, format)?;
        let first_read = header.len();
        let reader = Self::open(
            header,
            read,
            Compression::None,
            format,
            first_read,
            Some(range.start.frame_number),
        )?;
        Ok(reader.with_end_frame(end_frame))
    }

    /// Stop before frame `end_frame` (exclusive); `None` reads to the end.
    pub fn with_end_frame(mut self, end_frame: Option<u64>) -> Self {
        self.end_frame = end_frame;
        self
    }

    /// `prefix` then `read`, decompressed, parsed as `format`. `first_read`
    /// is the least the parser must see in its first read (0: whatever one
    /// read of the stream yields, as for a regular file). `start_frame` is
    /// the number of the first frame when the stream does not begin at
    /// frame 1.
    pub(crate) fn open(
        prefix: Vec<u8>,
        read: R,
        compression: Compression,
        format: PcapFormat,
        first_read: usize,
        start_frame: Option<u64>,
    ) -> Result<Self, Error> {
        let chain = Cursor::new(prefix).chain(read);
        let decode = DecompressReader::new(chain, compression).map_err(|e| {
            Error::Pcap(PcapError::InvalidFormat {
                reason: format!("decompressor: {e}"),
            })
        })?;
        let stack = HeadFill::new(decode, first_read);
        let inner = match start_frame {
            Some(frame) => GenericPcapReader::with_format_starting_at(stack, format, frame)?,
            None => GenericPcapReader::with_format(stack, format)?,
        };
        let link_type = inner.link_type();
        Ok(Self {
            inner,
            link_type,
            end_frame: None,
        })
    }
}

impl<R: Read + Send> PacketReader for ReadPacketReader<R> {
    #[inline]
    fn process_packets_flow<F>(&mut self, max: usize, f: F) -> Result<Delivered, Error>
    where
        F: FnMut(PacketRef<'_>) -> ControlFlow<Pause>,
    {
        let delivered = process_bounded(&mut self.inner, self.end_frame, max, f)?;
        self.link_type = self.inner.link_type();
        Ok(delivered)
    }

    #[inline]
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

/// [`GenericPcapReader::process_packets_flow`] limited to frames numbered
/// below `end_frame` (exclusive).
#[inline]
pub(crate) fn process_bounded<R: Read, F>(
    inner: &mut GenericPcapReader<R>,
    end_frame: Option<u64>,
    max: usize,
    f: F,
) -> Result<Delivered, Error>
where
    F: FnMut(PacketRef<'_>) -> ControlFlow<Pause>,
{
    let max = match end_frame {
        Some(end) => {
            let remaining = end.saturating_sub(inner.frame_count()).saturating_sub(1);
            if remaining == 0 {
                return Ok(Delivered {
                    consumed: 0,
                    paused: None,
                });
            }
            max.min(usize::try_from(remaining).unwrap_or(usize::MAX))
        }
        None => max,
    };
    inner.process_packets_flow(max, f)
}

/// A reader whose *first* `read` returns at least `min` bytes (or everything
/// up to end of input), by looping over the inner reader. Later reads pass
/// through, and so does the first when `min` is 0.
///
/// `pcap_parser` parses the capture header from the bytes of its first read
/// alone; a decompressor, a pipe or a network file system is free to return
/// fewer.
pub(crate) struct HeadFill<R> {
    inner: R,
    min: usize,
    first: bool,
}

impl<R: Read> HeadFill<R> {
    pub(crate) fn new(inner: R, min: usize) -> Self {
        Self {
            inner,
            min,
            first: min > 0,
        }
    }
}

impl<R: Read> Read for HeadFill<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.first {
            return self.inner.read(buf);
        }
        self.first = false;
        let want = self.min.min(buf.len());
        let mut filled = 0;
        while filled < want {
            match self.inner.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(filled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::index::build_boundary_index;
    use pcapsql_testgen::{
        legacy_pcap, pcapng, GenPacket, LegacyVariant, PcapngInterface, PcapngPacket, PcapngSection,
    };

    const FRAMES: u32 = 95;
    /// Frames between two checkpoints of the test index.
    const STRIDE: u64 = 10;

    fn legacy() -> Vec<u8> {
        let packets: Vec<GenPacket> = (0..FRAMES)
            .map(|i| GenPacket {
                ts_sec: 1_700_000_000 + i,
                ts_frac: i,
                data: vec![i as u8; 40 + (i % 7) as usize],
                origlen: 60,
            })
            .collect();
        legacy_pcap(LegacyVariant::LeMicro, 1, 65535, &packets).bytes
    }

    fn ng() -> Vec<u8> {
        let section = PcapngSection {
            interfaces: vec![PcapngInterface {
                link_type: 1,
                tsresol: 6,
                snaplen: 65535,
                if_tsoffset: 0,
            }],
            packets: (0..FRAMES)
                .map(|i| PcapngPacket {
                    interface_id: 0,
                    ts_sec: 1_700_000_000 + u64::from(i),
                    ts_frac_units: u64::from(i),
                    data: vec![i as u8; 40 + (i % 7) as usize],
                    origlen: 60,
                })
                .collect(),
        };
        pcapng(&[section]).bytes
    }

    /// Read `reader` to its end; the frame numbers it delivered.
    fn drain<R: PacketReader>(reader: &mut R) -> Vec<u64> {
        let mut frames = Vec::new();
        loop {
            let read = reader
                .process_packets(7, |packet| {
                    frames.push(packet.frame_number);
                    Ok(())
                })
                .unwrap();
            if read == 0 {
                return frames;
            }
        }
    }

    fn sequential(bytes: &[u8]) -> ReadPacketReader<Cursor<&[u8]>> {
        let mut read = Cursor::new(bytes);
        let (header, head) = StreamHeader::probe(&mut read).unwrap();
        ReadPacketReader::sequential(read, &header, head).unwrap()
    }

    fn index(bytes: &[u8]) -> BoundaryIndex {
        let format = PcapFormat::detect(bytes).unwrap();
        let len = bytes.len() as u64;
        build_boundary_index(Cursor::new(bytes), format, STRIDE, len, None, 0).unwrap()
    }

    /// One reader per range of an index over `bytes` with a checkpoint every
    /// [`STRIDE`] frames, `partitions` ranges asked for.
    fn ranged(
        bytes: &[u8],
        partitions: usize,
    ) -> Vec<(PacketRange, ReadPacketReader<Cursor<&[u8]>>)> {
        let index = index(bytes);
        let ranges = index.partition_ranges(partitions);
        assert!(ranges.len() > 1, "{ranges:?}");
        ranges
            .into_iter()
            .map(|range| {
                let read = Cursor::new(&bytes[range.start.byte_offset as usize..]);
                let reader = ReadPacketReader::at(read, index.format, &index, &range).unwrap();
                (range, reader)
            })
            .collect()
    }

    #[test]
    fn a_complete_capture_is_not_truncated() {
        let all: Vec<u64> = (1..=u64::from(FRAMES)).collect();
        for bytes in [legacy(), ng()] {
            let mut reader = sequential(&bytes);
            assert!(!reader.truncated());
            assert_eq!(drain(&mut reader), all);
            assert!(!reader.truncated());
            // Asked again at the end, the answer is the same.
            assert!(drain(&mut reader).is_empty());
            assert!(!reader.truncated());

            let mut frames = Vec::new();
            for (range, mut reader) in ranged(&bytes, 4) {
                frames.extend(drain(&mut reader));
                assert!(!reader.truncated(), "{range:?}");
            }
            assert_eq!(frames, all);
        }
    }

    /// A capture cut inside its last record: in the packet data, in the
    /// record header, and one byte into the record.
    #[test]
    fn a_sequential_reader_reports_a_record_cut_short() {
        for bytes in [legacy(), ng()] {
            // The last record: 16 (legacy) or 32 (pcapng) bytes of framing
            // around 43 bytes of data (padded to 44 in pcapng).
            let record = if bytes[0] == 0x0a { 32 + 44 } else { 16 + 43 };
            for cut in [5, record - 7, record - 1] {
                let bytes = &bytes[..bytes.len() - cut];
                let mut reader = sequential(bytes);
                // Not before the reader has got to the end.
                let read = reader.process_packets(50, |_| Ok(())).unwrap();
                assert_eq!(read, 50);
                assert!(!reader.truncated(), "cut {cut}");
                let complete = u64::from(FRAMES) - 1;
                assert_eq!(drain(&mut reader), (51..=complete).collect::<Vec<_>>());
                assert!(reader.truncated(), "cut {cut}");
                assert_eq!(reader.position().frame_number, complete);
                // It stays so however often the end is asked for.
                assert!(drain(&mut reader).is_empty());
                assert!(reader.truncated(), "cut {cut}");
                // A call that reads nothing does not change the answer.
                assert_eq!(reader.process_packets(0, |_| Ok(())).unwrap(), 0);
                assert!(reader.truncated(), "cut {cut}");
            }
        }
    }

    /// Of the readers of a partitioned capture only the one that reads to
    /// the end of the input sees the truncation.
    #[test]
    fn only_the_last_range_reader_reports_a_record_cut_short() {
        for bytes in [legacy(), ng()] {
            let bytes = &bytes[..bytes.len() - 5];
            let complete = u64::from(FRAMES) - 1;
            let readers = ranged(bytes, 4);
            let last = readers.len() - 1;
            let mut frames = Vec::new();
            for (ordinal, (range, mut reader)) in readers.into_iter().enumerate() {
                assert_eq!(range.end.is_none(), ordinal == last);
                frames.extend(drain(&mut reader));
                assert_eq!(reader.truncated(), ordinal == last, "{range:?}");
            }
            assert_eq!(frames, (1..=complete).collect::<Vec<_>>());
        }
    }

    /// A capture cut inside a range that is not the last of the index it is
    /// read with (the index is older than the cut): the reader of that range
    /// runs into the end of the input and says so.
    #[test]
    fn a_range_reader_that_runs_into_the_end_of_the_input_reports_it() {
        for whole in [legacy(), ng()] {
            let index = index(&whole);
            let ranges = index.partition_ranges(4);
            let range = &ranges[1];
            let end = range.end.as_ref().unwrap();
            let cut = &whole[..end.byte_offset as usize - 30];
            let read = Cursor::new(&cut[range.start.byte_offset as usize..]);
            let mut reader = ReadPacketReader::at(read, index.format, &index, range).unwrap();
            let frames = drain(&mut reader);
            assert_eq!(frames.first(), Some(&range.start.frame_number));
            assert_eq!(frames.last(), Some(&(end.frame_number - 2)));
            assert!(reader.truncated());
        }
    }

    /// The default of the trait: a reader that cannot tell says no.
    #[test]
    fn a_reader_without_the_signal_is_never_truncated() {
        struct Nothing;
        impl PacketReader for Nothing {
            fn process_packets_flow<F>(&mut self, _max: usize, _f: F) -> Result<Delivered, Error>
            where
                F: FnMut(PacketRef<'_>) -> ControlFlow<Pause>,
            {
                Ok(Delivered {
                    consumed: 0,
                    paused: None,
                })
            }
            fn position(&self) -> PacketPosition {
                PacketPosition::START
            }
            fn link_type(&self) -> u32 {
                1
            }
        }
        assert!(!Nothing.truncated());
    }
}
