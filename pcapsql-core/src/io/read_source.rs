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
