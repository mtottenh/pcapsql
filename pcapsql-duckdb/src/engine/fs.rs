//! File access through DuckDB's file system.
//!
//! The extension never opens a file itself: every open goes through the `FileSystem` of the
//! callback's [`Context`], so a capture can be anywhere DuckDB can read (a local path, `s3://`,
//! `https://`, any registered file system) and DuckDB's own access rules apply
//! (`enable_external_access`, `allowed_directories`). `std::fs` is not used anywhere in this
//! crate; `clippy.toml` and `scripts/check-no-std-fs.sh` enforce that.
//!
//! [`DuckFile`] is the [`Read`] the packet readers of `pcapsql-core` take
//! (`ReadPacketReader<DuckFile>`): [`DuckFile::open`] for a whole capture,
//! [`DuckFile::open_at`] for a partition that starts at a byte offset.
//!
//! A `Context` and its `FileSystem` only live for one callback. A [`DuckFile`] outlives both, so
//! a worker opens its file in one callback and keeps reading it in later ones.

use std::io::{self, Read};

use duckdb_neo::{
    connection::Context,
    file::{File, FileBuilder, FileSystem},
    Result,
};

/// Bytes [`DuckFile`] asks a local file for at a time.
///
/// The capture parser underneath reads in 64 KiB to 1 MiB steps; one call into DuckDB per MiB
/// keeps the call overhead out of the profile without holding much memory per worker.
pub const LOCAL_BUFFER: usize = 1 << 20;

/// Bytes [`DuckFile`] asks a remote file (as `FileSystem::is_remote` reports it) for at a time.
///
/// A read of a remote file is a request to a server, so fewer and larger reads win.
pub const REMOTE_BUFFER: usize = 4 << 20;

/// The least buffer a [`DuckFile`] is given.
const MIN_BUFFER: usize = 4096;

/// A file opened for reading through DuckDB's file system, as a buffered [`Read`].
///
/// It reads forward from its position; [`seek`](Self::seek) moves the position. It is `Send`
/// (it can be kept in a table function's local state) and, like the `File` it wraps, not `Sync`.
#[derive(Debug)]
pub struct DuckFile {
    file: File,
    /// Bytes read from the file and not yet handed out: `buffer[start..end]`.
    buffer: Box<[u8]>,
    start: usize,
    end: usize,
    /// The file offset of the next byte [`Read::read`] returns.
    position: u64,
}

// Local state must be `Send`; fail here, not at the first table function that stores one.
const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<DuckFile>();
};

impl DuckFile {
    /// Open `path` for reading, positioned at its first byte.
    ///
    /// DuckDB refuses the open when the path is outside what the session may access.
    pub fn open(context: &Context, path: &str) -> Result<Self> {
        let file_system = FileSystem::new(context)?;
        let remote = file_system.is_remote(path)?;
        let file = FileBuilder::new(&file_system, path)?.read().open()?;
        let wanted = if remote { REMOTE_BUFFER } else { LOCAL_BUFFER };
        // No point in a buffer larger than the file. A size that cannot be told is no reason
        // to fail the open: the reads will say what is wrong, if anything.
        let capacity = match file.size() {
            Ok(size) => usize::try_from(size).map_or(wanted, |size| wanted.min(size)),
            Err(_) => wanted,
        };
        Ok(Self::with_buffer(file, capacity))
    }

    /// Open `path` for reading, positioned at byte `offset`: the start of a partition.
    pub fn open_at(context: &Context, path: &str, offset: u64) -> Result<Self> {
        let mut file = Self::open(context, path)?;
        file.seek(offset)?;
        Ok(file)
    }

    /// Wrap an open file that is positioned at its first byte, reading `capacity` bytes at a
    /// time (at least 4 KiB).
    pub fn with_buffer(file: File, capacity: usize) -> Self {
        Self {
            file,
            buffer: vec![0; capacity.max(MIN_BUFFER)].into_boxed_slice(),
            start: 0,
            end: 0,
            position: 0,
        }
    }

    /// The size of the file in bytes.
    pub fn size(&self) -> Result<u64> {
        self.file.size()
    }

    /// The file offset of the next byte a read returns.
    pub fn position(&self) -> u64 {
        self.position
    }

    /// Continue reading at byte `offset` of the file.
    pub fn seek(&mut self, offset: u64) -> Result<()> {
        let buffered = (self.end - self.start) as u64;
        // Within what is buffered: nothing to ask DuckDB for.
        if offset >= self.position && offset - self.position <= buffered {
            self.start += (offset - self.position) as usize;
        } else {
            let target = usize::try_from(offset).map_err(|_| {
                duckdb_neo::Error::invalid_parameter(format!(
                    "file offset {offset} is beyond what this platform can address"
                ))
            })?;
            self.file.seek(target)?;
            self.start = 0;
            self.end = 0;
        }
        self.position = offset;
        Ok(())
    }

    /// How many bytes one call into DuckDB asks for.
    pub fn buffer_capacity(&self) -> usize {
        self.buffer.len()
    }
}

impl Read for DuckFile {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.start == self.end {
            // A read at least as large as the buffer gains nothing from going through it.
            if out.len() >= self.buffer.len() {
                let read = self.file.read_into(out).map_err(io::Error::other)?;
                self.position += read as u64;
                return Ok(read);
            }
            self.start = 0;
            self.end = self
                .file
                .read_into(&mut self.buffer)
                .map_err(io::Error::other)?;
        }
        let count = out.len().min(self.end - self.start);
        out[..count].copy_from_slice(&self.buffer[self.start..self.start + count]);
        self.start += count;
        self.position += count as u64;
        Ok(count)
    }
}
