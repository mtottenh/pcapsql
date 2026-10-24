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
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::error::{Error, PcapError};
use crate::io::decompress::{decompress_header, Compression, DecompressReader};
use crate::io::pcap_stream::{GenericPcapReader, PcapFormat, BUFFER_SIZE};
use crate::io::source::{
    PacketPosition, PacketReader, PacketRef, PacketSource, PacketSourceMetadata,
};

/// Length of the legacy pcap global header.
const LEGACY_HEADER_LEN: usize = 24;
/// Smallest valid pcapng Section Header Block (no options).
const SHB_MIN_LEN: usize = 28;
/// Smallest valid pcapng Interface Description Block (no options).
const IDB_MIN_LEN: usize = 20;
/// pcapng block type of an Interface Description Block.
const IDB_BLOCK_TYPE: u32 = 1;
/// Sanity cap on the header blocks the probe is willing to pre-read: what
/// the reader itself accepts in one buffer. Real SHBs and IDBs are a few
/// hundred bytes; a larger length is a corrupt stream, which the reader
/// proper would report too.
const MAX_HEADER_BLOCK_LEN: usize = BUFFER_SIZE;
/// First request size when growing a *compressed* prefix whose decompressed
/// output does not yet hold the headers; doubles on each step up to
/// [`COMPRESSED_PROBE_MAX_STEP`]. One `read` per step, taking whatever it
/// returns, so a live feed is never waited on for more than it has sent.
const COMPRESSED_PROBE_STEP: usize = 512;
const COMPRESSED_PROBE_MAX_STEP: usize = 64 * 1024;

/// What the probe learned from the head of the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamHeader {
    /// Compression framing around the capture (`Compression::None` for raw).
    pub compression: Compression,
    /// Capture format.
    pub format: PcapFormat,
    /// Link type from the legacy header or the first pcapng IDB (1 when a
    /// pcapng stream declares no interface before its first other block).
    pub link_type: u32,
    /// Snapshot length from the same header (65535 when unknown).
    pub snaplen: u32,
    /// Bytes of (decompressed) stream the format's own header occupies: the
    /// legacy global header, or the pcapng SHB. The reader must see at least
    /// this much in its first read.
    pub header_len: usize,
}

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

/// Shared control of a [`TimedRead`]: the current timeout, whether the last
/// read gave up because of it, and the cancel descriptor that ends a wait
/// for good.
#[derive(Debug)]
struct ReadTimeout {
    /// Timeout in milliseconds; negative means none.
    millis: AtomicI64,
    timed_out: AtomicBool,
    cancelled: AtomicBool,
    /// Becomes readable once [`ReadTimeout::cancel`] has been called (`None`
    /// when the descriptor could not be created: cancellation then takes
    /// effect at the next read).
    #[cfg(unix)]
    cancel: Option<CancelFd>,
}

impl ReadTimeout {
    fn new() -> Self {
        Self {
            millis: AtomicI64::new(-1),
            timed_out: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
            #[cfg(unix)]
            cancel: CancelFd::new(),
        }
    }

    fn set(&self, timeout: Option<Duration>) {
        let millis = match timeout {
            Some(t) => i64::try_from(t.as_millis())
                .unwrap_or(i64::MAX)
                .min(i32::MAX as i64),
            None => -1,
        };
        self.millis.store(millis, Ordering::Relaxed);
    }

    fn take_timed_out(&self) -> bool {
        self.timed_out.swap(false, Ordering::Relaxed)
    }

    /// End the current and every later wait for input: the reader fails
    /// with a cancellation it reports through [`PacketReader::cancelled`].
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        #[cfg(unix)]
        if let Some(fd) = &self.cancel {
            fd.signal();
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// A descriptor that `poll(2)` reports readable once signalled: an `eventfd`
/// on Linux, the read end of a pipe elsewhere. It is never drained, so once
/// signalled every later poll returns at once too.
#[cfg(unix)]
#[derive(Debug)]
struct CancelFd {
    read: std::os::fd::OwnedFd,
    /// The pipe's write end; an eventfd is written through `read`.
    write: Option<std::os::fd::OwnedFd>,
}

#[cfg(unix)]
impl CancelFd {
    fn new() -> Option<Self> {
        use std::os::fd::{FromRawFd, OwnedFd};
        #[cfg(target_os = "linux")]
        {
            // SAFETY: a plain syscall with constant flags; the descriptor it
            // returns is owned here and nowhere else.
            let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
            if fd < 0 {
                return None;
            }
            // SAFETY: `fd` is a fresh, valid descriptor we own.
            let read = unsafe { OwnedFd::from_raw_fd(fd) };
            Some(Self { read, write: None })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let mut fds = [0 as libc::c_int; 2];
            // SAFETY: `fds` is a valid two-element array for the syscall to
            // fill; the descriptors it returns are owned here and nowhere
            // else.
            let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
            if rc < 0 {
                return None;
            }
            for fd in fds {
                // SAFETY: `fd` is a descriptor we own; the flags are the
                // documented ones for F_SETFD / F_SETFL.
                unsafe {
                    libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                    libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
                }
            }
            // SAFETY: fresh, valid descriptors we own.
            let (read, write) =
                unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
            Some(Self {
                read,
                write: Some(write),
            })
        }
    }

    fn poll_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.read.as_raw_fd()
    }

    /// Make the descriptor readable. Idempotent; a failed write (the pipe is
    /// full, so it is already readable) is fine.
    fn signal(&self) {
        use std::os::fd::AsRawFd;
        let one: u64 = 1;
        let (fd, bytes): (std::os::fd::RawFd, &[u8]) = match &self.write {
            Some(write) => (write.as_raw_fd(), &one.to_ne_bytes()[..1]),
            None => (self.read.as_raw_fd(), &one.to_ne_bytes()[..]),
        };
        // SAFETY: `fd` is a descriptor we own and `bytes` is a valid buffer
        // of the given length.
        let _ = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
    }
}

/// A reader over a file descriptor whose `read` first waits with `poll(2)`
/// for the descriptor to become readable, bounded by the timeout when one is
/// set, and watching the cancel descriptor. It fails with
/// `io::ErrorKind::TimedOut` (recording it) when nothing arrives in time, and
/// with `io::ErrorKind::Other` once cancelled (not `Interrupted`, which the
/// readers above retry), from then on without touching the inner reader.
/// Without a timeout and without a cancel descriptor it is a plain
/// pass-through.
#[cfg(unix)]
struct TimedRead<R> {
    inner: R,
    fd: std::os::fd::RawFd,
    control: Arc<ReadTimeout>,
}

#[cfg(unix)]
impl<R: Read> Read for TimedRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let cancelled = || io::Error::other("the read was cancelled by the consumer");
        if self.control.is_cancelled() {
            return Err(cancelled());
        }
        let millis = self.control.millis.load(Ordering::Relaxed);
        let cancel = self.control.cancel.as_ref().map(CancelFd::poll_fd);
        if millis >= 0 || cancel.is_some() {
            let mut pfds = [
                libc::pollfd {
                    fd: self.fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: cancel.unwrap_or(-1), // a negative fd is ignored by poll
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let timeout = if millis >= 0 {
                millis as libc::c_int
            } else {
                -1
            };
            loop {
                // SAFETY: `pfds` is a valid, initialised array of two pollfds
                // that outlives the call; `nfds` is 2.
                let ready = unsafe { libc::poll(pfds.as_mut_ptr(), 2, timeout) };
                if ready > 0 {
                    if pfds[1].revents != 0 {
                        self.control.cancelled.store(true, Ordering::SeqCst);
                        return Err(cancelled());
                    }
                    break; // readable, hung up or in error: `read` reports which
                }
                if ready == 0 {
                    self.control.timed_out.store(true, Ordering::Relaxed);
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "no input within the read timeout",
                    ));
                }
                let err = io::Error::last_os_error();
                if err.kind() != io::ErrorKind::Interrupted {
                    return Err(err);
                }
            }
        }
        self.inner.read(buf)
    }
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
        let (header, prefix) = probe_stream(&mut reader)?;
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
        let (header, prefix) = probe_stream(&mut reader)?;
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
    fn process_packets<F>(&mut self, max: usize, f: F) -> Result<usize, Error>
    where
        F: FnMut(PacketRef<'_>) -> Result<(), Error>,
    {
        let count = self.inner.process_packets(max, f)?;
        if count > 0 || self.inner.frame_count() > 0 {
            self.link_type = self.inner.link_type();
        }
        Ok(count)
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

/// A reader whose *first* `read` returns at least `min` bytes (or everything
/// up to end of input), by looping over the inner reader. Later reads pass
/// through.
///
/// `pcap_parser` parses the capture header from the bytes of its first read
/// alone; a decompressor (or a pipe) is free to return fewer.
struct HeadFill<R> {
    inner: R,
    min: usize,
    first: bool,
}

impl<R: Read> HeadFill<R> {
    fn new(inner: R, min: usize) -> Self {
        Self {
            inner,
            min,
            first: true,
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

// ---------------------------------------------------------------------------
// Header probe
// ---------------------------------------------------------------------------

/// What [`analyze_header`] still needs, in bytes of (decompressed) stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Need {
    /// Part of the capture's own header: end of input before this is an
    /// error.
    Required(usize),
    /// The first pcapng block after the SHB, hoped to be an IDB: end of
    /// input before this is a valid (empty) capture with the default link
    /// type.
    Optional(usize),
}

impl Need {
    fn target(self) -> usize {
        match self {
            Need::Required(n) | Need::Optional(n) => n,
        }
    }
}

/// Outcome of analyzing a (decompressed) stream prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Probe {
    Done {
        format: PcapFormat,
        link_type: u32,
        snaplen: u32,
        header_len: usize,
    },
    Need(Need),
}

/// Pure analysis of a decompressed stream prefix: the format and, when the
/// prefix holds them, the link type and snaplen from the legacy global
/// header or the pcapng SHB + first IDB. Reports exactly how many bytes it
/// needs to go further, so the caller reads no more than that.
fn analyze_header(bytes: &[u8]) -> Result<Probe, Error> {
    if bytes.len() < 4 {
        return Ok(Probe::Need(Need::Required(4)));
    }
    let format = PcapFormat::detect(bytes)?;
    if format.is_legacy() {
        if bytes.len() < LEGACY_HEADER_LEN {
            return Ok(Probe::Need(Need::Required(LEGACY_HEADER_LEN)));
        }
        let be = format.is_big_endian();
        return Ok(Probe::Done {
            format,
            snaplen: read_u32(&bytes[16..20], be),
            link_type: read_u32(&bytes[20..24], be),
            header_len: LEGACY_HEADER_LEN,
        });
    }

    // pcapng: block type (4), block total length (4), byte-order magic (4).
    if bytes.len() < 12 {
        return Ok(Probe::Need(Need::Required(12)));
    }
    let be = match &bytes[8..12] {
        [0x4d, 0x3c, 0x2b, 0x1a] => false,
        [0x1a, 0x2b, 0x3c, 0x4d] => true,
        other => {
            return Err(Error::Pcap(PcapError::InvalidFormat {
                reason: format!(
                    "PCAPNG section header has an invalid byte-order magic {other:02x?}"
                ),
            }))
        }
    };
    let shb_len = read_u32(&bytes[4..8], be) as usize;
    if shb_len < SHB_MIN_LEN || !shb_len.is_multiple_of(4) || shb_len > MAX_HEADER_BLOCK_LEN {
        return Err(Error::Pcap(PcapError::InvalidFormat {
            reason: format!(
                "PCAPNG section header block declares an invalid length ({shb_len} bytes)"
            ),
        }));
    }
    if bytes.len() < shb_len {
        return Ok(Probe::Need(Need::Required(shb_len)));
    }
    let done_without_idb = Probe::Done {
        format,
        link_type: 1,
        snaplen: 65535,
        header_len: shb_len,
    };

    // The first block after the SHB is normally the IDB that gives the link
    // type. Anything else is left to the reader.
    let idb = shb_len;
    if bytes.len() < idb + 8 {
        return Ok(Probe::Need(Need::Optional(idb + 8)));
    }
    let block_type = read_u32(&bytes[idb..idb + 4], be);
    let block_len = read_u32(&bytes[idb + 4..idb + 8], be) as usize;
    if block_type != IDB_BLOCK_TYPE
        || block_len < IDB_MIN_LEN
        || !block_len.is_multiple_of(4)
        || block_len > MAX_HEADER_BLOCK_LEN
    {
        return Ok(done_without_idb);
    }
    if bytes.len() < idb + block_len {
        return Ok(Probe::Need(Need::Optional(idb + block_len)));
    }
    Ok(Probe::Done {
        format,
        link_type: read_u16(&bytes[idb + 8..idb + 10], be) as u32,
        snaplen: read_u32(&bytes[idb + 12..idb + 16], be),
        header_len: shb_len,
    })
}

/// Read the head of the stream: compression, format, link type. Returns the
/// header and the raw bytes consumed from the stream, which the caller
/// chains back in front of it.
fn probe_stream<R: Read>(reader: &mut R) -> Result<(StreamHeader, Vec<u8>), Error> {
    let mut raw = Vec::with_capacity(64);
    // The compression magics need 6 bytes; every capture header is longer.
    read_up_to(reader, &mut raw, 6)?;
    if raw.is_empty() {
        return Err(Error::Pcap(PcapError::InvalidFormat {
            reason: "stdin is empty: no capture header was read".into(),
        }));
    }
    let compression = Compression::detect(&raw);
    let finish = |probe: Probe, raw: Vec<u8>| -> Result<(StreamHeader, Vec<u8>), Error> {
        match probe {
            Probe::Done {
                format,
                link_type,
                snaplen,
                header_len,
            } => Ok((
                StreamHeader {
                    compression,
                    format,
                    link_type,
                    snaplen,
                    header_len,
                },
                raw,
            )),
            Probe::Need(_) => unreachable!("finish is only called on a complete probe"),
        }
    };

    if !compression.is_compressed() {
        loop {
            match analyze_header(&raw)? {
                done @ Probe::Done { .. } => return finish(done, raw),
                Probe::Need(need) => {
                    read_up_to(reader, &mut raw, need.target())?;
                    if raw.len() < need.target() {
                        return match need {
                            Need::Required(n) => Err(truncated_header(raw.len(), n)),
                            // SHB alone (or ending inside the block after
                            // it): a capture with no interface declared yet.
                            Need::Optional(_) => finish(analyze_shb_only(&raw)?, raw),
                        };
                    }
                }
            }
        }
    }

    // Compressed: grow the compressed prefix until it decompresses to what
    // the header analysis needs. A prefix cut inside the compressed stream
    // decompresses to an error once the decoder runs out of input ("read
    // more"); a prefix that decompresses to fewer bytes than asked for was a
    // complete stream, and what it holds is final. Each step is one `read`
    // of a doubling size, so a decoder that emits nothing until a whole
    // block is present costs O(log n) re-decodes, not O(n / step).
    let mut want = LEGACY_HEADER_LEN;
    let mut step = COMPRESSED_PROBE_STEP;
    let mut eof = false;
    loop {
        match decompress_header(&raw, compression, want) {
            Ok(decompressed) => match analyze_header(&decompressed)? {
                done @ Probe::Done { .. } => return finish(done, raw),
                Probe::Need(need) if decompressed.len() >= want => {
                    // The prefix may decompress further: ask for more output
                    // before reading more input.
                    want = need.target();
                    continue;
                }
                Probe::Need(Need::Required(n)) => {
                    return Err(truncated_header(decompressed.len(), n));
                }
                Probe::Need(Need::Optional(_)) => {
                    return finish(analyze_shb_only(&decompressed)?, raw);
                }
            },
            Err(e) if eof => {
                return Err(Error::Pcap(PcapError::InvalidFormat {
                    reason: format!(
                        "failed to decompress the capture header from stdin ({compression}): {e}"
                    ),
                }));
            }
            Err(_) => {}
        }
        let before = raw.len();
        read_once(reader, &mut raw, step)?;
        eof = raw.len() == before;
        step = (step * 2).min(COMPRESSED_PROBE_MAX_STEP);
    }
}

/// A pcapng prefix that holds a complete SHB but ended before a complete
/// IDB: a capture with the default link type.
fn analyze_shb_only(bytes: &[u8]) -> Result<Probe, Error> {
    let format = PcapFormat::detect(bytes)?;
    let be = bytes[8] == 0x1a;
    Ok(Probe::Done {
        format,
        link_type: 1,
        snaplen: 65535,
        header_len: read_u32(&bytes[4..8], be) as usize,
    })
}

fn truncated_header(have: usize, need: usize) -> Error {
    Error::Pcap(PcapError::InvalidFormat {
        reason: format!(
            "stdin ended after {have} bytes: too short for a capture header ({need} bytes needed)"
        ),
    })
}

/// Read from `reader` into `buf` until `buf.len() == target` or end of
/// input; never asks for more than `target` bytes.
fn read_up_to<R: Read>(reader: &mut R, buf: &mut Vec<u8>, target: usize) -> Result<(), Error> {
    while buf.len() < target {
        let start = buf.len();
        buf.resize(target, 0);
        match reader.read(&mut buf[start..]) {
            Ok(0) => {
                buf.truncate(start);
                break;
            }
            Ok(n) => buf.truncate(start + n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => buf.truncate(start),
            Err(e) => {
                buf.truncate(start);
                return Err(Error::Io(e));
            }
        }
    }
    Ok(())
}

/// One `read` of up to `max` bytes appended to `buf`: whatever the stream
/// has (0 at end of input). Retries only on `Interrupted`.
fn read_once<R: Read>(reader: &mut R, buf: &mut Vec<u8>, max: usize) -> Result<(), Error> {
    let start = buf.len();
    buf.resize(start + max, 0);
    loop {
        match reader.read(&mut buf[start..]) {
            Ok(n) => {
                buf.truncate(start + n);
                return Ok(());
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                buf.truncate(start);
                return Err(Error::Io(e));
            }
        }
    }
}

fn read_u32(b: &[u8], be: bool) -> u32 {
    let a = [b[0], b[1], b[2], b[3]];
    if be {
        u32::from_be_bytes(a)
    } else {
        u32::from_le_bytes(a)
    }
}

fn read_u16(b: &[u8], be: bool) -> u16 {
    let a = [b[0], b[1]];
    if be {
        u16::from_be_bytes(a)
    } else {
        u16::from_le_bytes(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
