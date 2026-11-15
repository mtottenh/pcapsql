//! `std::io::Read` over an object, by byte-range requests.

use std::io::{self, Read};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use object_store::{path::Path as ObjectPath, ObjectStore};
use tokio::runtime::Handle;

use super::location::CloudLocation;
use super::runtime::{run_async, saveable_handle};
use crate::error::Error;

/// Cloud storage reader implementing `std::io::Read`.
///
/// Uses byte-range requests for efficient streaming. Data is fetched in chunks
/// and buffered locally. This allows processing large cloud objects without
/// downloading them entirely to memory.
pub struct ObjectStoreReader {
    store: Arc<dyn ObjectStore>,
    path: ObjectPath,
    object_size: u64,
    /// Exclusive upper bound for reads (`object_size` for a whole-object read;
    /// the next partition's start offset for a partition reader, so a worker
    /// never fetches bytes that belong to its neighbour).
    limit: u64,
    position: u64,
    buffer: Vec<u8>,
    buffer_start: u64,
    chunk_size: usize,
    /// Runtime to run requests on from plain threads (see `run_async`).
    handle: Option<Handle>,
    /// Bytes fetched over the network, shared with the owning source.
    fetched: Arc<AtomicU64>,
}

impl ObjectStoreReader {
    /// Open a cloud object for reading (one HEAD request for the size).
    pub fn open(location: &CloudLocation) -> Result<Self, Error> {
        let store = location.build_store()?;
        let path = location.object_path();
        let handle = saveable_handle();
        let object_size = head_object(&store, &path, handle.as_ref())?.size;
        Ok(Self::new(
            store,
            path,
            object_size,
            location.chunk_size(),
            handle,
            Arc::new(AtomicU64::new(0)),
        ))
    }

    /// Reader over an already-described object (no HEAD request).
    pub(super) fn new(
        store: Arc<dyn ObjectStore>,
        path: ObjectPath,
        object_size: u64,
        chunk_size: usize,
        handle: Option<Handle>,
        fetched: Arc<AtomicU64>,
    ) -> Self {
        Self {
            store,
            path,
            object_size,
            limit: object_size,
            position: 0,
            buffer: Vec::new(),
            buffer_start: 0,
            chunk_size,
            handle,
            fetched,
        }
    }

    /// Open a reader positioned at a byte offset (for mid-file partitions).
    pub fn open_at(location: &CloudLocation, start: u64) -> Result<Self, Error> {
        Ok(Self::open(location)?.starting_at(start, None))
    }

    /// Position the reader at `start` and cap reads at `end` (exclusive;
    /// `None` = end of object).
    pub(super) fn starting_at(mut self, start: u64, end: Option<u64>) -> Self {
        self.position = start;
        self.buffer_start = start;
        self.buffer.clear();
        self.limit = end.unwrap_or(self.object_size).min(self.object_size);
        self
    }

    /// Create a reader with pre-fetched header bytes.
    ///
    /// This is an optimization to avoid re-fetching the header when the
    /// caller has already fetched it for format detection.
    pub fn with_prefetched_header(
        store: Arc<dyn ObjectStore>,
        path: ObjectPath,
        object_size: u64,
        chunk_size: usize,
        header_bytes: Vec<u8>,
    ) -> Self {
        let mut reader = Self::new(
            store,
            path,
            object_size,
            chunk_size,
            saveable_handle(),
            Arc::new(AtomicU64::new(0)),
        );
        reader.buffer = header_bytes;
        reader
    }

    /// Set the chunk size for fetching data.
    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    /// Get the total size of the cloud object.
    pub fn size(&self) -> u64 {
        self.object_size
    }

    /// Fetch a range of bytes from the cloud object.
    fn fetch_range(&self, start: u64, end: u64) -> io::Result<Vec<u8>> {
        let store = Arc::clone(&self.store);
        let path = self.path.clone();
        let bytes = run_async(self.handle.as_ref(), async move {
            let range = std::ops::Range {
                start: start as usize,
                end: end as usize,
            };

            let bytes = store
                .get_range(&path, range)
                .await
                .map_err(|e| io::Error::other(format!("Cloud GetRange failed: {e}")))?;

            Ok::<Vec<u8>, io::Error>(bytes.to_vec())
        })?;
        self.fetched
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        Ok(bytes)
    }

    /// Ensure buffer contains data at current position.
    fn ensure_buffer(&mut self) -> io::Result<()> {
        // Check if current position is within buffer
        if self.position >= self.buffer_start
            && self.position < self.buffer_start + self.buffer.len() as u64
        {
            return Ok(());
        }

        // Need to fetch new chunk
        if self.position >= self.limit {
            // At EOF, clear buffer
            self.buffer.clear();
            return Ok(());
        }

        let start = self.position;
        // Never fetch past this reader's limit: a partition reader stops at the
        // next partition's first record, so the neighbour's bytes are its own.
        let end = (start + self.chunk_size as u64).min(self.limit);

        self.buffer = self.fetch_range(start, end)?;
        self.buffer_start = start;

        Ok(())
    }
}

/// What a HEAD request tells us about an object.
pub(super) struct ObjectHead {
    pub(super) size: u64,
    pub(super) last_modified: Option<SystemTime>,
    /// Entity tag, when the store reports one. Together with `last_modified`
    /// (one-second granularity) it guards the cached boundary index.
    pub(super) e_tag: Option<String>,
}

/// HEAD an object.
pub(super) fn head_object(
    store: &Arc<dyn ObjectStore>,
    path: &ObjectPath,
    handle: Option<&Handle>,
) -> Result<ObjectHead, Error> {
    let store = Arc::clone(store);
    let path = path.clone();
    run_async(handle, async move {
        let meta = store.head(&path).await.map_err(|e| {
            Error::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Failed to HEAD cloud object: {e}"),
            ))
        })?;
        Ok::<ObjectHead, Error>(ObjectHead {
            size: meta.size as u64,
            last_modified: Some(SystemTime::from(meta.last_modified)),
            e_tag: meta.e_tag,
        })
    })
}

impl Read for ObjectStoreReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.limit {
            return Ok(0); // EOF
        }

        self.ensure_buffer()?;

        if self.buffer.is_empty() {
            return Ok(0); // EOF
        }

        // Calculate how much we can read from buffer
        let buffer_offset = (self.position - self.buffer_start) as usize;
        let in_buffer = self.buffer.len() - buffer_offset;
        // Also respect `limit` when the buffer was filled before `limit` applied.
        let to_limit = (self.limit - self.position) as usize;
        let to_read = buf.len().min(in_buffer).min(to_limit);

        buf[..to_read].copy_from_slice(&self.buffer[buffer_offset..buffer_offset + to_read]);
        self.position += to_read as u64;

        Ok(to_read)
    }
}

// A reader is moved to the thread that scans its partition; fail here, not there.
const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<ObjectStoreReader>();
};

// Required for async compatibility
impl Unpin for ObjectStoreReader {}
