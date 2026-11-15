//! The read timeout and the cancellation of a descriptor-backed stream.
//!
//! [`TimedRead`] waits for its descriptor with `poll(2)` before each `read`,
//! bounded by the timeout a [`ReadTimeout`] holds and watching its cancel
//! descriptor ([`CancelFd`]: an `eventfd`, or a pipe where there is none).
//! The only `unsafe` of the stdin source is here: the `poll(2)`,
//! `eventfd(2)` and `pipe(2)` calls. Off Unix only the [`ReadTimeout`]
//! remains, and no source has one.

#[cfg(unix)]
use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
#[cfg(unix)]
use std::sync::Arc;
use std::time::Duration;

/// Shared control of a [`TimedRead`]: the current timeout, whether the last
/// read gave up because of it, and the cancel descriptor that ends a wait
/// for good.
#[derive(Debug)]
pub(super) struct ReadTimeout {
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
    // Only a descriptor-backed source has one (`StdinPacketSource::from_fd_reader`).
    #[cfg(unix)]
    pub(super) fn new() -> Self {
        Self {
            millis: AtomicI64::new(-1),
            timed_out: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
            #[cfg(unix)]
            cancel: CancelFd::new(),
        }
    }

    pub(super) fn set(&self, timeout: Option<Duration>) {
        let millis = match timeout {
            Some(t) => i64::try_from(t.as_millis())
                .unwrap_or(i64::MAX)
                .min(i32::MAX as i64),
            None => -1,
        };
        self.millis.store(millis, Ordering::Relaxed);
    }

    pub(super) fn take_timed_out(&self) -> bool {
        self.timed_out.swap(false, Ordering::Relaxed)
    }

    /// End the current and every later wait for input: the reader fails
    /// with a cancellation it reports through [`PacketReader::cancelled`].
    pub(super) fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        #[cfg(unix)]
        if let Some(fd) = &self.cancel {
            fd.signal();
        }
    }

    pub(super) fn is_cancelled(&self) -> bool {
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
pub(super) struct TimedRead<R> {
    pub(super) inner: R,
    pub(super) fd: std::os::fd::RawFd,
    pub(super) control: Arc<ReadTimeout>,
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
