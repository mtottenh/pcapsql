//! Non-seekable packet source: standard input, or any other byte stream.
//!
//! Lets a capture be piped straight into a query instead of written to a
//! file first:
//!
//! ```text
//! tcpdump -U -w - -i eth0 port 53 | pcapsql --stdin -e "SELECT ... FROM dns_packets"
//! dumpcap -w - -i any            | pcapsql --stdin -e "SELECT ... FROM linux_sll"
//! zcat capture.pcap.gz           | pcapsql --stdin -e "SELECT count(*) FROM frames"
//! ```
//!
//! `tcpdump -U` (packet-buffered output) matters for a live feed: without it
//! tcpdump's stdio buffering holds packets back for seconds. `dumpcap`
//! writes pcapng and flushes per packet by default.
//!
//! ## Design
//!
//! - A stream can be read once, so [`StdinPacketSource`] implements
//!   [`PacketSource`] only, never [`crate::io::SeekablePacketSource`]: the
//!   type is the "not seekable" flag. [`PacketSource::sequential_reader`]
//!   hands out the stream exactly once and fails clearly after that.
//! - Opening the source **probes** the head of the stream: the compression
//!   magic, the capture format (legacy pcap in either byte order and
//!   timestamp unit, or pcapng) and the link type (the legacy global header,
//!   or the pcapng section header plus the first interface description
//!   block). The probe reads exactly the bytes those headers occupy and no
//!   more, so on a live feed the first packet is never held back by a
//!   fixed-size pre-read. The probed bytes are chained back in front of the
//!   rest of the stream for the reader.
//! - Per-packet link types still come from the stream (the pcapng interface
//!   table), exactly as for file sources; the probed link type is the
//!   source-level metadata a planner sees before the first packet.
//! - The source is **bounded**: the reader runs to end of input, like a file.
//!   A continuous (unbounded) mode is a property of the engine that consumes
//!   the stream, not of this type. What this type offers it is a **read
//!   timeout** ([`PacketReader::set_read_timeout`]) on a source opened from
//!   a file descriptor ([`StdinPacketSource::stdin`],
//!   [`StdinPacketSource::from_fd_reader`]): the reader waits for input with
//!   `poll(2)` and reports when none arrived in time, so the consumer can
//!   flush what it holds while the feed is quiet. The same `poll` watches a
//!   **cancel descriptor** (an `eventfd`, or a pipe where there is none):
//!   [`PacketSource::cancel_reads`] writes to it from any thread and the
//!   reader's wait ends at once, whether or not a timeout is set, so a
//!   consumer that is done can release a producer blocked on a quiet feed
//!   instead of waiting for the next byte. A source opened from an arbitrary
//!   `Read` ([`StdinPacketSource::from_reader`]) or a compressed stream can do
//!   neither (a blocked `read` cannot be interrupted, and a decompressor's
//!   buffering hides the descriptor's readiness).
//!
//! Everything here is `Send` by construction (a boxed `Read + Send` behind a
//! mutex). The only `unsafe` is the `poll(2)`, `eventfd(2)` and `pipe(2)`
//! calls behind the read timeout.

use std::io::{self, Cursor, Read};
use std::ops::ControlFlow;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::error::{Error, PcapError};
use crate::io::decompress::{Compression, DecompressReader};
use crate::io::pcap_stream::{Delivered, GenericPcapReader, Pause, PcapFormat};
use crate::io::probe::{probe_stream, StreamHeader};
use crate::io::read_source::HeadFill;
use crate::io::source::{
    PacketPosition, PacketReader, PacketRef, PacketSource, PacketSourceMetadata,
};

mod timed_read;

use timed_read::ReadTimeout;
#[cfg(unix)]
use timed_read::TimedRead;

/// Packet source over standard input or any other `Read + Send` stream.
///
/// Construct with [`StdinPacketSource::stdin`] for the process's stdin, or
/// [`StdinPacketSource::from_reader`] for any reader (a pipe, a socket, an
/// in-memory buffer in tests). Opening probes the stream head (see the
/// module documentation); nothing else is read until the reader runs.
///
/// Clones share the one underlying stream: whichever clone calls
/// [`PacketSource::sequential_reader`] first gets it.
#[derive(Clone)]
pub struct StdinPacketSource {
    metadata: PacketSourceMetadata,
    header: StreamHeader,
    /// The stream (probed prefix chained before the rest), taken exactly
    /// once by `sequential_reader`.
    stream: Arc<Mutex<Option<Box<dyn Read + Send>>>>,
    /// The read-timeout control of the stream's descriptor, when the source
    /// was opened from one and is not compressed.
    timeout: Option<Arc<ReadTimeout>>,
}

impl StdinPacketSource {
    /// Open the process's standard input as a packet source.
    ///
    /// Reads the capture header from stdin immediately (blocking until the
    /// producer has written it); the packets are read by the sequential
    /// reader.
    ///
    /// On Unix the descriptor is read directly, not through `io::stdin()`:
    /// that is an 8 KiB `BufReader`, and bytes it had pulled into its buffer
    /// would be invisible to the `poll(2)` behind the read timeout and the
    /// cancel descriptor, so a short feed would sit there until the next
    /// packet arrived on the pipe.
    pub fn stdin() -> Result<Self, Error> {
        #[cfg(unix)]
        {
            use std::os::fd::AsFd;
            let fd = io::stdin()
                .as_fd()
                .try_clone_to_owned()
                .map_err(|e| io::Error::other(format!("cannot dup standard input: {e}")))?;
            Self::from_fd_reader(std::fs::File::from(fd))
        }
        #[cfg(not(unix))]
        {
            Self::from_reader(io::stdin())
        }
    }

    /// Open a byte stream that is backed by a file descriptor (a pipe, a
    /// socket): like [`Self::from_reader`], plus a read timeout for a
    /// continuous consumer, implemented with `poll(2)` on the descriptor.
    /// A compressed stream gets no timeout (the decompressor's buffering
    /// hides the descriptor's readiness).
    #[cfg(unix)]
    pub fn from_fd_reader<R: Read + std::os::fd::AsRawFd + Send + 'static>(
        mut reader: R,
    ) -> Result<Self, Error> {
        let fd = reader.as_raw_fd();
        let (header, prefix) = probe_stream(&mut reader, "stdin")?;
        let control = Arc::new(ReadTimeout::new());
        let timed = TimedRead {
            inner: reader,
            fd,
            control: Arc::clone(&control),
        };
        let timeout = (header.compression == Compression::None).then_some(control);
        Ok(Self::assemble(header, prefix, Box::new(timed), timeout))
    }

    /// Open any byte stream as a packet source.
    ///
    /// Probes the stream head for compression, format and link type, reading
    /// exactly the header bytes. Fails if the stream is empty, ends inside
    /// the header, or does not start with a capture (or compression) magic.
    ///
    /// Such a source cannot time out a read (see [`Self::from_fd_reader`]):
    /// a continuous engine over it flushes held packets only when the next
    /// packet arrives.
    pub fn from_reader<R: Read + Send + 'static>(mut reader: R) -> Result<Self, Error> {
        let (header, prefix) = probe_stream(&mut reader, "stdin")?;
        Ok(Self::assemble(header, prefix, Box::new(reader), None))
    }

    fn assemble(
        header: StreamHeader,
        prefix: Vec<u8>,
        rest: Box<dyn Read + Send>,
        timeout: Option<Arc<ReadTimeout>>,
    ) -> Self {
        let metadata = PacketSourceMetadata {
            link_type: header.link_type,
            snaplen: header.snaplen,
            size_bytes: None,   // unknown for a stream
            packet_count: None, // unknown for a stream
        };
        let stream: Box<dyn Read + Send> = Box::new(Cursor::new(prefix).chain(rest));
        Self {
            metadata,
            header,
            stream: Arc::new(Mutex::new(Some(stream))),
            timeout,
        }
    }

    /// Whether a reader over this source can time out waiting for input and
    /// be cancelled (opened from a descriptor, uncompressed).
    pub fn supports_read_timeout(&self) -> bool {
        self.timeout.is_some()
    }

    /// What the probe found at the head of the stream.
    pub fn header(&self) -> &StreamHeader {
        &self.header
    }

    /// Capture format of the stream.
    pub fn format(&self) -> PcapFormat {
        self.header.format
    }

    /// Compression framing of the stream.
    pub fn compression(&self) -> Compression {
        self.header.compression
    }

    /// Whether the stream is still available to a reader (false once
    /// [`PacketSource::sequential_reader`] has been called).
    pub fn is_available(&self) -> bool {
        self.stream.lock().map(|g| g.is_some()).unwrap_or(false)
    }
}

impl std::fmt::Debug for StdinPacketSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StdinPacketSource")
            .field("format", &self.header.format)
            .field("compression", &self.header.compression)
            .field("link_type", &self.metadata.link_type)
            .field("available", &self.is_available())
            .finish()
    }
}

impl PacketSource for StdinPacketSource {
    type Reader = StdinPacketReader;

    fn metadata(&self) -> &PacketSourceMetadata {
        &self.metadata
    }

    /// The one reader over the stream. A second call fails: the bytes are
    /// gone with the first reader.
    fn sequential_reader(&self) -> Result<Self::Reader, Error> {
        let stream = self
            .stream
            .lock()
            .map_err(|_| io::Error::other("stdin source lock poisoned"))?
            .take()
            .ok_or_else(|| {
                io::Error::other(
                    "stdin was already consumed: a non-seekable source can be read exactly once",
                )
            })?;
        StdinPacketReader::new(stream, self.header, self.timeout.clone())
    }

    /// End the reader's current and every later wait for input (see the
    /// module documentation). No effect on a source without a descriptor.
    fn cancel_reads(&self) {
        if let Some(control) = &self.timeout {
            control.cancel();
        }
    }
}

/// The reader over a non-seekable stream: decompression, then the generic
/// pcap/pcapng parser, with the probed header length guaranteed to arrive in
/// the parser's first read.
///
/// `process_packets` returns 0 at end of input, after the parser has reported
/// a truncated trailing record if the stream ended inside one. On a source
/// opened from a descriptor, [`PacketReader::set_read_timeout`] bounds how
/// long a call waits for input: the wait is a `poll(2)` on the descriptor,
/// a timeout surfaces as an error that [`PacketReader::take_read_timeout`]
/// identifies, and the parser's buffer is untouched, so the next call
/// resumes exactly where it was. [`PacketSource::cancel_reads`] on the source
/// ends the wait for good: the call fails and [`PacketReader::cancelled`] is
/// true from then on. A reader over a source without a descriptor can only
/// be released by input, the writer closing, or the process exiting.
pub struct StdinPacketReader {
    inner: GenericPcapReader<HeadFill<DecompressReader<Box<dyn Read + Send>>>>,
    link_type: u32,
    timeout: Option<Arc<ReadTimeout>>,
}

impl StdinPacketReader {
    fn new(
        stream: Box<dyn Read + Send>,
        header: StreamHeader,
        timeout: Option<Arc<ReadTimeout>>,
    ) -> Result<Self, Error> {
        let decode = DecompressReader::new(stream, header.compression).map_err(|e| {
            Error::Pcap(PcapError::InvalidFormat {
                reason: format!("decompressor: {e}"),
            })
        })?;
        // pcap_parser reads the capture header from its very first `read`,
        // which otherwise returns whatever one call to the decompressor
        // yields.
        let filled = HeadFill::new(decode, header.header_len);
        let inner = GenericPcapReader::with_format(filled, header.format)?;
        let link_type = if header.format.is_pcapng() {
            // The parser only learns the interface table from the IDBs it
            // reads; until then report what the probe saw.
            header.link_type
        } else {
            inner.link_type()
        };
        Ok(Self {
            inner,
            link_type,
            timeout,
        })
    }
}

impl PacketReader for StdinPacketReader {
    #[inline]
    fn process_packets_flow<F>(&mut self, max: usize, f: F) -> Result<Delivered, Error>
    where
        F: FnMut(PacketRef<'_>) -> ControlFlow<Pause>,
    {
        let delivered = self.inner.process_packets_flow(max, f)?;
        if delivered.consumed > 0 || self.inner.frame_count() > 0 {
            self.link_type = self.inner.link_type();
        }
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

    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> bool {
        match &self.timeout {
            Some(control) => {
                control.set(timeout);
                true
            }
            None => false,
        }
    }

    fn take_read_timeout(&mut self) -> bool {
        self.timeout
            .as_ref()
            .is_some_and(|control| control.take_timed_out())
    }

    fn cancelled(&self) -> bool {
        self.timeout
            .as_ref()
            .is_some_and(|control| control.is_cancelled())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::probe::LEGACY_HEADER_LEN;
    use pcapsql_testgen::{
        legacy_pcap, pcapng, GenPacket, GeneratedCapture, LegacyVariant, PcapngInterface,
        PcapngPacket, PcapngSection,
    };
    use std::io::Write;

    fn frames(n: usize) -> Vec<GenPacket> {
        (0..n)
            .map(|i| GenPacket {
                ts_sec: 1_700_000_000 + i as u32,
                ts_frac: (i as u32 * 7) % 1_000_000,
                data: vec![i as u8; 40 + i],
                origlen: (40 + i) as u32,
            })
            .collect()
    }

    fn legacy(variant: LegacyVariant, link_type: u16, n: usize) -> GeneratedCapture {
        legacy_pcap(variant, link_type, 65535, &frames(n))
    }

    fn ng(link_type: u16, n: usize) -> GeneratedCapture {
        let packets = (0..n)
            .map(|i| PcapngPacket {
                interface_id: 0,
                ts_sec: 1_700_000_000 + i as u64,
                ts_frac_units: (i as u64 * 11) % 1_000_000,
                data: vec![i as u8; 30 + i],
                origlen: (30 + i) as u32,
            })
            .collect();
        pcapng(&[PcapngSection {
            interfaces: vec![PcapngInterface {
                link_type,
                tsresol: 6,
                snaplen: 262_144,
                if_tsoffset: 0,
            }],
            packets,
        }])
    }

    /// Drain a source and return (frame_number, link_type, timestamp_ns, len)
    /// per packet.
    fn drain(source: &StdinPacketSource) -> Vec<(u64, u16, i64, usize)> {
        let mut reader = source.sequential_reader().expect("reader");
        let mut out = Vec::new();
        loop {
            let n = reader
                .process_packets(3, |p| {
                    out.push((p.frame_number, p.link_type, p.timestamp_ns, p.data.len()));
                    Ok(())
                })
                .expect("process");
            if n == 0 {
                break;
            }
        }
        out
    }

    fn check_against(source: &StdinPacketSource, cap: &GeneratedCapture) {
        let got = drain(source);
        assert_eq!(got.len(), cap.expected.len());
        for (g, e) in got.iter().zip(&cap.expected) {
            assert_eq!(g.0, e.frame_number);
            assert_eq!(g.1 as u32, e.link_type);
            assert_eq!(g.2, e.timestamp_ns);
            assert_eq!(g.3, e.caplen as usize);
        }
    }

    /// A reader that hands out one byte per `read` and counts what was taken.
    struct Trickle {
        data: Vec<u8>,
        pos: usize,
    }

    impl Read for Trickle {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.data.len() || buf.is_empty() {
                return Ok(0);
            }
            buf[0] = self.data[self.pos];
            self.pos += 1;
            Ok(1)
        }
    }

    /// A reader that counts the bytes taken from it, so a test can check
    /// how much the probe consumed.
    struct Counting<R> {
        inner: R,
        taken: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl<R: Read> Read for Counting<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.taken
                .fetch_add(n, std::sync::atomic::Ordering::Relaxed);
            Ok(n)
        }
    }

    fn counting(
        bytes: Vec<u8>,
    ) -> (
        Counting<Cursor<Vec<u8>>>,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let taken = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        (
            Counting {
                inner: Cursor::new(bytes),
                taken: taken.clone(),
            },
            taken,
        )
    }

    #[test]
    fn legacy_variants_are_detected_and_parsed() {
        for (variant, format) in [
            (LegacyVariant::LeMicro, PcapFormat::LegacyLeMicro),
            (LegacyVariant::BeMicro, PcapFormat::LegacyBeMicro),
            (LegacyVariant::LeNano, PcapFormat::LegacyLeNano),
            (LegacyVariant::BeNano, PcapFormat::LegacyBeNano),
        ] {
            let cap = legacy(variant, 101, 5); // 101 = LINKTYPE_RAW
            let source = StdinPacketSource::from_reader(Cursor::new(cap.bytes.clone())).unwrap();
            assert_eq!(source.format(), format, "{variant:?}");
            assert_eq!(source.compression(), Compression::None);
            assert_eq!(source.metadata().link_type, 101);
            assert_eq!(source.metadata().snaplen, 65535);
            assert!(source.metadata().size_bytes.is_none());
            assert!(source.metadata().packet_count.is_none());
            check_against(&source, &cap);
        }
    }

    #[test]
    fn pcapng_link_type_comes_from_the_first_idb() {
        let cap = ng(113, 4); // LINKTYPE_LINUX_SLL
        let source = StdinPacketSource::from_reader(Cursor::new(cap.bytes.clone())).unwrap();
        assert_eq!(source.format(), PcapFormat::PcapNg);
        assert_eq!(
            source.metadata().link_type,
            113,
            "A9: metadata lies about pcapng link type"
        );
        assert_eq!(source.metadata().snaplen, 262_144);
        let reader = source.sequential_reader().unwrap();
        assert_eq!(reader.link_type(), 113);
        drop(reader);
        let source = StdinPacketSource::from_reader(Cursor::new(cap.bytes.clone())).unwrap();
        check_against(&source, &cap);
    }

    #[test]
    fn probe_reads_exactly_the_header_bytes() {
        use std::sync::atomic::Ordering::Relaxed;
        // Legacy: the 24-byte global header and nothing else (A16: no fixed
        // pre-read that would hold back the first packet of a live feed).
        let cap = legacy(LegacyVariant::LeMicro, 1, 3);
        let (reader, taken) = counting(cap.bytes.clone());
        let source = StdinPacketSource::from_reader(reader).unwrap();
        assert_eq!(taken.load(Relaxed), LEGACY_HEADER_LEN);
        assert_eq!(source.header().header_len, LEGACY_HEADER_LEN);
        check_against(&source, &cap);

        // pcapng: SHB + first IDB, both complete blocks, nothing of the first EPB.
        let cap = ng(1, 3);
        let shb_len = u32::from_le_bytes(cap.bytes[4..8].try_into().unwrap()) as usize;
        let idb_len =
            u32::from_le_bytes(cap.bytes[shb_len + 4..shb_len + 8].try_into().unwrap()) as usize;
        let (reader, taken) = counting(cap.bytes.clone());
        let source = StdinPacketSource::from_reader(reader).unwrap();
        assert_eq!(taken.load(Relaxed), shb_len + idb_len);
        assert_eq!(source.header().header_len, shb_len);
        check_against(&source, &cap);
    }

    #[test]
    fn short_reads_do_not_confuse_the_probe_or_the_reader() {
        let cap = legacy(LegacyVariant::BeNano, 1, 6);
        let source = StdinPacketSource::from_reader(Trickle {
            data: cap.bytes.clone(),
            pos: 0,
        })
        .unwrap();
        check_against(&source, &cap);

        let cap = ng(1, 6);
        let source = StdinPacketSource::from_reader(Trickle {
            data: cap.bytes.clone(),
            pos: 0,
        })
        .unwrap();
        assert_eq!(source.metadata().link_type, 1);
        check_against(&source, &cap);
    }

    #[test]
    fn gzip_compressed_stream_is_detected_and_parsed() {
        for cap in [legacy(LegacyVariant::LeMicro, 1, 8), ng(113, 8)] {
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            enc.write_all(&cap.bytes).unwrap();
            let gz = enc.finish().unwrap();
            let source = StdinPacketSource::from_reader(Trickle { data: gz, pos: 0 }).unwrap();
            assert_eq!(source.compression(), Compression::Gzip);
            assert_eq!(source.format(), cap_format(&cap));
            assert_eq!(source.metadata().link_type, cap.expected[0].link_type);
            check_against(&source, &cap);
        }
    }

    fn cap_format(cap: &GeneratedCapture) -> PcapFormat {
        PcapFormat::detect(&cap.bytes).unwrap()
    }

    /// A reader that returns at most `chunk` bytes per `read`.
    struct Chunked {
        data: Vec<u8>,
        pos: usize,
        chunk: usize,
    }

    impl Read for Chunked {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.chunk.min(buf.len()).min(self.data.len() - self.pos);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    #[test]
    fn compressed_header_split_across_small_reads_still_probes() {
        // The gzip header alone is 10 bytes and the deflate stream needs
        // dozens more before the pcapng SHB + IDB decode: with 7-byte reads
        // the probe must keep asking until the headers decode, and must not
        // demand more than one read's worth at a time.
        let cap = ng(113, 6);
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&cap.bytes).unwrap();
        let gz = enc.finish().unwrap();
        for chunk in [1usize, 7, 64] {
            let source = StdinPacketSource::from_reader(Chunked {
                data: gz.clone(),
                pos: 0,
                chunk,
            })
            .unwrap();
            assert_eq!(source.compression(), Compression::Gzip, "chunk {chunk}");
            assert_eq!(source.format(), PcapFormat::PcapNg, "chunk {chunk}");
            assert_eq!(source.metadata().link_type, 113, "chunk {chunk}");
            check_against(&source, &cap);
        }
    }

    #[cfg(feature = "compress-zstd")]
    #[test]
    fn zstd_compressed_stream_is_detected_and_parsed() {
        let cap = ng(113, 8);
        let zst = zstd::stream::encode_all(Cursor::new(&cap.bytes), 3).unwrap();
        let source = StdinPacketSource::from_reader(Trickle { data: zst, pos: 0 }).unwrap();
        assert_eq!(source.compression(), Compression::Zstd);
        assert_eq!(source.metadata().link_type, 113);
        check_against(&source, &cap);
    }

    #[test]
    fn header_only_streams_are_valid_empty_captures() {
        // A legacy global header with no records.
        let cap = legacy(LegacyVariant::LeMicro, 1, 0);
        assert_eq!(cap.bytes.len(), LEGACY_HEADER_LEN);
        let source = StdinPacketSource::from_reader(Cursor::new(cap.bytes)).unwrap();
        assert!(drain(&source).is_empty());

        // SHB + IDB, no packets.
        let cap = ng(276, 0);
        let source = StdinPacketSource::from_reader(Cursor::new(cap.bytes)).unwrap();
        assert_eq!(source.metadata().link_type, 276);
        assert!(drain(&source).is_empty());

        // SHB alone: shorter than the probe's optional IDB read.
        let cap = ng(276, 0);
        let shb_len = u32::from_le_bytes(cap.bytes[4..8].try_into().unwrap()) as usize;
        let source =
            StdinPacketSource::from_reader(Cursor::new(cap.bytes[..shb_len].to_vec())).unwrap();
        assert_eq!(source.format(), PcapFormat::PcapNg);
        assert_eq!(source.metadata().link_type, 1);
        assert!(drain(&source).is_empty());
    }

    #[test]
    fn empty_input_is_a_clear_error() {
        let err = StdinPacketSource::from_reader(Cursor::new(Vec::new()))
            .expect_err("empty input must fail");
        assert!(err.to_string().contains("stdin is empty"), "{err}");
    }

    #[test]
    fn garbage_input_is_a_clear_error() {
        let err = StdinPacketSource::from_reader(Cursor::new(b"this is not a capture".to_vec()))
            .expect_err("garbage must fail");
        assert!(err.to_string().contains("Unknown PCAP magic"), "{err}");

        // A valid magic but a header cut short.
        let cap = legacy(LegacyVariant::LeMicro, 1, 2);
        let err = StdinPacketSource::from_reader(Cursor::new(cap.bytes[..10].to_vec()))
            .expect_err("truncated header must fail");
        assert!(
            err.to_string().contains("too short for a capture header"),
            "{err}"
        );

        // Compressed garbage.
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"not a capture either, sorry").unwrap();
        let err = StdinPacketSource::from_reader(Cursor::new(enc.finish().unwrap()))
            .expect_err("compressed garbage must fail");
        assert!(err.to_string().contains("Unknown PCAP magic"), "{err}");
    }

    #[test]
    fn truncated_trailing_record_yields_the_complete_prefix() {
        let cap = legacy(LegacyVariant::LeMicro, 1, 5);
        // Cut inside the last record's data.
        let cut = cap.bytes.len() - 7;
        let source =
            StdinPacketSource::from_reader(Cursor::new(cap.bytes[..cut].to_vec())).unwrap();
        let got = drain(&source);
        assert_eq!(got.len(), 4, "the four complete records, then a clean end");

        let cap = ng(1, 5);
        let cut = cap.bytes.len() - 7;
        let source =
            StdinPacketSource::from_reader(Cursor::new(cap.bytes[..cut].to_vec())).unwrap();
        assert_eq!(drain(&source).len(), 4);
    }

    #[test]
    fn sequential_reader_is_take_once_across_clones() {
        let cap = legacy(LegacyVariant::LeMicro, 1, 2);
        let source = StdinPacketSource::from_reader(Cursor::new(cap.bytes)).unwrap();
        let clone = source.clone();
        assert!(source.is_available());
        let _reader = clone.sequential_reader().expect("first reader");
        assert!(!source.is_available());
        let err = source
            .sequential_reader()
            .err()
            .expect("second reader must fail");
        assert!(err.to_string().contains("already consumed"), "{err}");
    }

    #[test]
    fn types_are_send_without_unsafe() {
        fn assert_send_sync<T: Send + Sync>() {}
        fn assert_send_unpin<T: Send + Unpin>() {}
        assert_send_sync::<StdinPacketSource>();
        assert_send_unpin::<StdinPacketReader>();
    }
}
