//! Cloud storage reader implementation.
//!
//! Provides [`ObjectStoreReader`] which implements `std::io::Read` for cloud storage,
//! enabling integration with the existing `GenericPcapReader<R: Read>` and
//! `DecompressReader<R: Read>` abstractions.
//!
//! ## Supported Providers
//!
//! - AWS S3 (`s3://bucket/key`) - requires `s3` feature
//! - Google Cloud Storage (`gs://bucket/key`) - requires `gcs` feature
//! - Azure Blob Storage (`az://container/blob`) - requires `azure` feature
//! - S3-compatible (MinIO, R2, LocalStack) - requires `s3` feature + custom endpoint
//!
//! ## Usage
//!
//! ```ignore
//! use pcapsql_core::io::{CloudPacketSource, CloudLocation};
//!
//! let location = CloudLocation::parse("s3://bucket/capture.pcap")?;
//! // `open` is synchronous; it drives its own HTTP requests (see `run_async`).
//! let source = CloudPacketSource::open(location)?;
//! ```
//!
//! ## Partitioned reads and the boundary index
//!
//! Partitioning a remote object needs a [`BoundaryIndex`], which is built by one
//! sequential read of the whole object. That index is cached on local disk
//! (keyed by the object URL, validated by size, last-modified time and header
//! hash) under `$PCAPSQL_INDEX_CACHE`, else `$XDG_CACHE_HOME/pcapsql/index`,
//! else `$HOME/.cache/pcapsql/index`, so later opens of the same object — in
//! this process or another — partition immediately with no full download.

use std::io::{self, Chain, Cursor, Read};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

use tokio::runtime::{Handle, RuntimeFlavor};

use object_store::{path::Path as ObjectPath, ObjectStore};
use url::Url;

use crate::error::Error;

/// Execute an async operation, handling runtime nesting correctly.
///
/// - Inside a tokio runtime: `block_in_place` + `block_on` on the current handle.
/// - On a plain thread with a `saved` handle (captured when the source was
///   opened inside a runtime, then handed to parse worker threads): run the
///   future on that runtime. This is the partitioned-parse case; without it
///   every byte-range GET from a worker thread would build and tear down a
///   fresh runtime, re-establishing the HTTP connection pool each time.
/// - Otherwise: a temporary single-threaded runtime.
/// - On a `current_thread` runtime (`#[tokio::test]`, `#[tokio::main(flavor =
///   "current_thread")]`) neither `block_in_place` nor `Handle::block_on` from
///   another thread can work: the former panics, the latter never drives the
///   runtime's I/O driver while the runtime thread is blocked. Such callers,
///   and plain threads without a saved handle, use a dedicated multi-thread
///   I/O runtime owned by this module, driven from a helper thread.
fn run_async<F, T>(saved: Option<&Handle>, future: F) -> T
where
    F: std::future::Future<Output = T> + Send,
    T: Send,
{
    match Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| handle.block_on(future))
        }
        // Inside a current_thread runtime: cannot block here.
        Ok(_) => io_runtime_block_on(future),
        Err(_) => match saved {
            Some(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
                handle.block_on(future)
            }
            _ => io_runtime_block_on(future),
        },
    }
}

/// A runtime handle worth saving for worker threads: only a multi-thread
/// runtime can be driven from a thread that is not its own.
fn saveable_handle() -> Option<Handle> {
    Handle::try_current()
        .ok()
        .filter(|h| h.runtime_flavor() == RuntimeFlavor::MultiThread)
}

/// Run `future` to completion on the module's dedicated I/O runtime from a
/// helper thread, so it is safe to call from inside any tokio context.
fn io_runtime_block_on<F, T>(future: F) -> T
where
    F: std::future::Future<Output = T> + Send,
    T: Send,
{
    static IO_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    let rt = IO_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("pcapsql-cloud-io")
            .enable_all()
            .build()
            .expect("Failed to create cloud I/O runtime")
    });
    std::thread::scope(|s| {
        s.spawn(|| rt.handle().block_on(future))
            .join()
            .expect("cloud I/O future panicked")
    })
}

/// Directory for cached boundary indexes of remote objects, if one can be
/// determined. `None` disables caching (the index is rebuilt per open).
fn index_cache_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("PCAPSQL_INDEX_CACHE") {
        return (!dir.is_empty()).then(|| PathBuf::from(dir));
    }
    if let Some(dir) = std::env::var_os("XDG_CACHE_HOME") {
        if !dir.is_empty() {
            return Some(PathBuf::from(dir).join("pcapsql").join("index"));
        }
    }
    std::env::var_os("HOME").filter(|h| !h.is_empty()).map(|h| {
        PathBuf::from(h)
            .join(".cache")
            .join("pcapsql")
            .join("index")
    })
}

/// Cache file for a location's boundary index: `<cache-dir>/<fnv(url)>.idx`.
fn index_cache_path(location: &CloudLocation) -> Option<PathBuf> {
    let key = format!(
        "{}://{}/{}@{}",
        location.scheme(),
        location.bucket().unwrap_or(""),
        location.key(),
        location.endpoint().unwrap_or("")
    );
    index_cache_dir().map(|d| d.join(format!("{:016x}.idx", index::header_hash(key.as_bytes()))))
}
use super::index::{self, BoundaryIndex};
use super::source::synth_header_for;
use crate::io::{
    decompress_header, Compression, DecompressReader, GenericPcapReader, PacketPosition,
    PacketRange, PacketReader, PacketRef, PacketSource, PacketSourceMetadata, PcapFormat, SeekCost,
    SeekablePacketSource,
};

/// Default chunk size for cloud reads (8MB).
const DEFAULT_CHUNK_SIZE: usize = 8 * 1024 * 1024;

/// Header size for initial read-ahead (64KB).
/// This should be large enough to contain:
/// - Compression magic bytes (up to 6 bytes)
/// - PCAP file header (24 bytes for legacy, ~32 bytes for pcapng)
/// - First few packet headers
///
/// We use 64KB to handle compressed files where the actual header
/// may expand from compressed data.
const HEADER_READ_SIZE: usize = 64 * 1024;

/// Parsed cloud storage location.
#[derive(Debug, Clone)]
pub struct CloudLocation {
    /// The parsed URL
    url: Url,
    /// Custom endpoint override (for S3-compatible services)
    endpoint: Option<String>,
    /// Whether to use anonymous (unsigned) requests
    anonymous: bool,
    /// Chunk size for byte-range requests
    chunk_size: usize,
}

impl CloudLocation {
    /// Parse a cloud storage URL.
    ///
    /// Supported formats:
    /// - `s3://bucket/key` - AWS S3
    /// - `gs://bucket/key` - Google Cloud Storage
    /// - `az://container/blob` - Azure Blob Storage
    /// - `s3://endpoint:port/bucket/key` - S3 with custom endpoint
    pub fn parse(url_str: &str) -> Result<Self, Error> {
        let url = Url::parse(url_str).map_err(|e| {
            Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid URL: {e}"),
            ))
        })?;

        let scheme = url.scheme();
        if !["s3", "gs", "az", "azure"].contains(&scheme) {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unsupported URL scheme: {scheme}. Expected s3://, gs://, or az://"),
            )));
        }

        Ok(Self {
            url,
            endpoint: None,
            anonymous: false,
            chunk_size: DEFAULT_CHUNK_SIZE,
        })
    }

    /// Set a custom endpoint URL (for MinIO, R2, LocalStack, etc.).
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Use anonymous (unsigned) requests for public buckets.
    pub fn with_anonymous(mut self, anonymous: bool) -> Self {
        self.anonymous = anonymous;
        self
    }

    /// Set the chunk size for byte-range requests.
    ///
    /// Larger values reduce HTTP request overhead but increase memory usage.
    /// Default is 8MB.
    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    /// Get the configured chunk size.
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Get the URL scheme (s3, gs, az).
    pub fn scheme(&self) -> &str {
        self.url.scheme()
    }

    /// Get the bucket/container name.
    pub fn bucket(&self) -> Option<&str> {
        self.url.host_str()
    }

    /// Get the object key/path.
    pub fn key(&self) -> &str {
        self.url.path().trim_start_matches('/')
    }

    /// Get the custom endpoint if set.
    pub fn endpoint(&self) -> Option<&str> {
        self.endpoint.as_deref()
    }

    /// Check if anonymous access is enabled.
    pub fn is_anonymous(&self) -> bool {
        self.anonymous
    }

    /// Build an ObjectStore for this location.
    pub fn build_store(&self) -> Result<Arc<dyn ObjectStore>, Error> {
        match self.scheme() {
            #[cfg(feature = "s3")]
            "s3" => self.build_s3_store(),
            #[cfg(feature = "gcs")]
            "gs" => self.build_gcs_store(),
            #[cfg(feature = "azure")]
            "az" | "azure" => self.build_azure_store(),
            scheme => Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unsupported or disabled scheme: {scheme}"),
            ))),
        }
    }

    #[cfg(feature = "s3")]
    fn build_s3_store(&self) -> Result<Arc<dyn ObjectStore>, Error> {
        use object_store::aws::AmazonS3Builder;

        let bucket = self.bucket().ok_or_else(|| {
            Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "S3 URL must include bucket name",
            ))
        })?;

        let mut builder = AmazonS3Builder::from_env().with_bucket_name(bucket);

        if let Some(endpoint) = &self.endpoint {
            builder = builder.with_endpoint(endpoint).with_allow_http(true);
        }

        if self.anonymous {
            builder = builder.with_skip_signature(true);
        }

        let store = builder
            .build()
            .map_err(|e| Error::Io(io::Error::other(format!("Failed to build S3 store: {e}"))))?;

        Ok(Arc::new(store))
    }

    #[cfg(feature = "gcs")]
    fn build_gcs_store(&self) -> Result<Arc<dyn ObjectStore>, Error> {
        use object_store::gcp::GoogleCloudStorageBuilder;

        let bucket = self.bucket().ok_or_else(|| {
            Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "GCS URL must include bucket name",
            ))
        })?;

        let builder = GoogleCloudStorageBuilder::from_env().with_bucket_name(bucket);

        // Note: object_store 0.11 doesn't support anonymous access for GCS.
        // GCS public buckets typically work via Application Default Credentials.
        if self.anonymous {
            tracing::warn!(
                "Anonymous access not supported for GCS in this version; \
                 using default credentials"
            );
        }

        let store = builder.build().map_err(|e| {
            Error::Io(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to build GCS store: {e}"),
            ))
        })?;

        Ok(Arc::new(store))
    }

    #[cfg(feature = "azure")]
    fn build_azure_store(&self) -> Result<Arc<dyn ObjectStore>, Error> {
        use object_store::azure::MicrosoftAzureBuilder;

        let container = self.bucket().ok_or_else(|| {
            Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Azure URL must include container name",
            ))
        })?;

        let mut builder = MicrosoftAzureBuilder::from_env().with_container_name(container);

        if self.anonymous {
            builder = builder.with_skip_signature(true);
        }

        let store = builder.build().map_err(|e| {
            Error::Io(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to build Azure store: {e}"),
            ))
        })?;

        Ok(Arc::new(store))
    }

    /// Get the object path for this location.
    pub fn object_path(&self) -> ObjectPath {
        ObjectPath::from(self.key())
    }
}

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
        let (object_size, _) = head_object(&store, &path, handle.as_ref())?;
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
    fn new(
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
    fn starting_at(mut self, start: u64, end: Option<u64>) -> Self {
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

/// HEAD an object: `(size, last_modified)`.
fn head_object(
    store: &Arc<dyn ObjectStore>,
    path: &ObjectPath,
    handle: Option<&Handle>,
) -> Result<(u64, Option<SystemTime>), Error> {
    let store = Arc::clone(store);
    let path = path.clone();
    run_async(handle, async move {
        let meta = store.head(&path).await.map_err(|e| {
            Error::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Failed to HEAD cloud object: {e}"),
            ))
        })?;
        Ok::<(u64, Option<SystemTime>), Error>((
            meta.size as u64,
            Some(SystemTime::from(meta.last_modified)),
        ))
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

// ObjectStoreReader is Send because all its fields are Send
unsafe impl Send for ObjectStoreReader {}

// Required for async compatibility
impl Unpin for ObjectStoreReader {}

/// Cloud-backed packet source.
///
/// Implements [`PacketSource`] for cloud storage objects, enabling PCAP files
/// stored in S3/GCS/Azure to be queried directly.
#[derive(Clone)]
pub struct CloudPacketSource {
    location: CloudLocation,
    /// The store and object path, built once and shared by every reader
    /// (partition readers issue no HEAD and build no client of their own).
    store: Arc<dyn ObjectStore>,
    path: ObjectPath,
    object_size: u64,
    /// Object last-modified time from HEAD (validity guard for the cached index).
    last_modified: Option<SystemTime>,
    metadata: PacketSourceMetadata,
    compression: Compression,
    pcap_format: PcapFormat,
    /// Lazily built boundary index (uncompressed objects only).
    index: Arc<Mutex<Option<Arc<BoundaryIndex>>>>,
    index_stride: u64,
    header_hash: u64,
    /// Runtime the source was opened under, for requests from plain threads.
    handle: Option<Handle>,
    /// Bytes fetched over the network by every reader of this source.
    fetched: Arc<AtomicU64>,
}

impl CloudPacketSource {
    /// Open a cloud object as a packet source.
    ///
    /// This method is optimized to minimize HTTP requests:
    /// - 1 HEAD request to get object size
    /// - 1 GET request for initial header (64KB)
    /// - In-memory decompression and parsing (no additional requests)
    ///
    /// Can be called from both sync and async contexts - handles runtime
    /// nesting correctly using `block_in_place` when called from async.
    pub fn open(location: CloudLocation) -> Result<Self, Error> {
        // Build object store
        let store = location.build_store()?;
        let path = location.object_path();

        let handle = saveable_handle();
        let fetched = Arc::new(AtomicU64::new(0));

        // 1. HEAD request to get object size (and last-modified for the index cache)
        let (object_size, last_modified) = head_object(&store, &path, handle.as_ref())?;

        if object_size < 24 {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "Cloud object too small to be a valid PCAP (< 24 bytes)",
            )));
        }

        // 2. Single GET request for header (64KB or file size, whichever is smaller)
        let header_size = HEADER_READ_SIZE.min(object_size as usize);
        let store_clone = Arc::clone(&store);
        let path_clone = path.clone();
        let header_bytes = run_async(handle.as_ref(), async move {
            let range = std::ops::Range {
                start: 0,
                end: header_size,
            };
            let bytes = store_clone
                .get_range(&path_clone, range)
                .await
                .map_err(|e| {
                    Error::Io(io::Error::other(format!(
                        "Failed to fetch cloud object header: {e}"
                    )))
                })?;
            Ok::<Vec<u8>, Error>(bytes.to_vec())
        })?;
        fetched.fetch_add(header_bytes.len() as u64, Ordering::Relaxed);

        if header_bytes.len() < 6 {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "Cloud object too small to be a valid PCAP",
            )));
        }

        // 3. Detect compression from header bytes (in-memory, no HTTP)
        let compression = Compression::detect(&header_bytes);

        // 4. Get decompressed header for PCAP parsing (in-memory, no HTTP)
        // Need at least 24 bytes for PCAP header, add margin for safety
        const PCAP_HEADER_SIZE: usize = 256;
        let decompressed_header = decompress_header(&header_bytes, compression, PCAP_HEADER_SIZE)
            .map_err(|e| {
            Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to decompress header: {e}"),
            ))
        })?;

        if decompressed_header.len() < 4 {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "Decompressed header too small for PCAP magic",
            )));
        }

        // 5. Detect PCAP format from decompressed magic bytes
        let pcap_magic = [
            decompressed_header[0],
            decompressed_header[1],
            decompressed_header[2],
            decompressed_header[3],
        ];
        let pcap_format = PcapFormat::detect(&pcap_magic)?;

        // 6. Parse link type from decompressed header (in-memory, no HTTP)
        let link_type = Self::parse_link_type_from_header(&decompressed_header, pcap_format)?;

        let metadata = PacketSourceMetadata {
            link_type,
            snaplen: 65535,
            size_bytes: Some(object_size),
            packet_count: None, // Filled by the index if built
        };

        let header_hash = index::header_hash(&header_bytes);

        Ok(Self {
            location,
            store,
            path,
            object_size,
            last_modified,
            metadata,
            compression,
            pcap_format,
            index: Arc::new(Mutex::new(None)),
            index_stride: index::DEFAULT_CHECKPOINT_STRIDE,
            header_hash,
            handle,
            fetched,
        })
    }

    /// Total bytes fetched over the network by this source and all its readers.
    pub fn bytes_fetched(&self) -> u64 {
        self.fetched.load(Ordering::Relaxed)
    }

    /// A reader over the raw object bytes, reusing the source's store, size and
    /// runtime handle (no HEAD request).
    fn raw_reader(&self, start: u64, end: Option<u64>) -> ObjectStoreReader {
        ObjectStoreReader::new(
            Arc::clone(&self.store),
            self.path.clone(),
            self.object_size,
            self.location.chunk_size(),
            self.handle.clone(),
            Arc::clone(&self.fetched),
        )
        .starting_at(start, end)
    }

    /// Set the checkpoint stride for index building (smaller = finer partitions).
    pub fn with_index_stride(mut self, stride: u64) -> Self {
        self.index_stride = stride.max(1);
        self
    }

    /// Build (and memoize) the boundary index of the uncompressed object.
    ///
    /// Building needs one full sequential read of the object, so the result is
    /// cached on local disk (see the module docs) and validated against the
    /// object's size, last-modified time and header hash before reuse.
    /// Subsequent partition reads use exact offsets from the index.
    fn ensure_index(&self) -> Result<Arc<BoundaryIndex>, Error> {
        if self.compression.is_compressed() {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "compressed cloud objects are not seekable; cannot build boundary index",
            )));
        }
        let mut guard = self.index.lock().expect("index mutex poisoned");
        if let Some(idx) = guard.as_ref() {
            return Ok(idx.clone());
        }

        let cache_path = index_cache_path(&self.location);
        if let Some(cached) = cache_path
            .as_deref()
            .and_then(|p| BoundaryIndex::read_sidecar(p).ok())
        {
            if cached.stride == self.index_stride
                && cached.is_valid_for(self.object_size, self.last_modified, self.header_hash)
            {
                let idx = Arc::new(cached);
                *guard = Some(idx.clone());
                return Ok(idx);
            }
        }

        let reader = self.raw_reader(0, None);
        let idx = index::build_boundary_index(
            reader,
            self.pcap_format,
            self.index_stride,
            self.object_size,
            self.last_modified,
            self.header_hash,
        )?;
        if let Some(p) = cache_path.as_deref() {
            // Best effort: a missing or read-only cache dir just means no reuse.
            if let Some(dir) = p.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let _ = idx.write_sidecar(p);
        }
        let idx = Arc::new(idx);
        *guard = Some(idx.clone());
        Ok(idx)
    }

    /// Parse link type from decompressed PCAP header bytes.
    fn parse_link_type_from_header(header: &[u8], format: PcapFormat) -> Result<u32, Error> {
        if format.is_pcapng() {
            // PCAPNG: Link type is in the Interface Description Block (IDB)
            // which comes after the Section Header Block (SHB).
            // Parse from the in-memory buffer using a cursor.
            Self::parse_pcapng_link_type(header)
        } else {
            // Legacy PCAP file header structure:
            // - Magic (4 bytes)
            // - Version major (2 bytes)
            // - Version minor (2 bytes)
            // - Timezone (4 bytes)
            // - Sigfigs (4 bytes)
            // - Snaplen (4 bytes)
            // - Link type (4 bytes)
            // Total: 24 bytes
            if header.len() < 24 {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Header too small for link type: {} bytes (need 24)",
                        header.len()
                    ),
                )));
            }

            // Link type is at offset 20, read as u32
            let link_type = if format.is_little_endian() {
                u32::from_le_bytes([header[20], header[21], header[22], header[23]])
            } else {
                u32::from_be_bytes([header[20], header[21], header[22], header[23]])
            };

            Ok(link_type)
        }
    }

    /// Parse link type from PCAPNG header bytes.
    ///
    /// PCAPNG structure:
    /// - Section Header Block (SHB): 28+ bytes
    /// - Interface Description Block (IDB): contains link type at offset 8
    fn parse_pcapng_link_type(header: &[u8]) -> Result<u32, Error> {
        // Minimum size: SHB (28 bytes) + IDB header (12 bytes) = 40 bytes
        if header.len() < 40 {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "Header too small for PCAPNG link type",
            )));
        }

        // SHB structure:
        // - Block Type (4): 0x0A0D0D0A
        // - Block Total Length (4)
        // - Byte-Order Magic (4): 0x1A2B3C4D
        // - Major Version (2)
        // - Minor Version (2)
        // - Section Length (8)
        // - Options (variable)
        // - Block Total Length (4)

        // Detect endianness from the Byte-Order Magic at offset 8 by matching
        // the raw on-disk byte pattern (host byte order must not matter).
        let bom = [header[8], header[9], header[10], header[11]];
        let is_le = bom == [0x4D, 0x3C, 0x2B, 0x1A];
        let is_be = bom == [0x1A, 0x2B, 0x3C, 0x4D];

        if !is_le && !is_be {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid PCAPNG byte-order magic: {bom:02x?}"),
            )));
        }

        // Read SHB block total length to find where IDB starts
        let shb_len = if is_le {
            u32::from_le_bytes([header[4], header[5], header[6], header[7]])
        } else {
            u32::from_be_bytes([header[4], header[5], header[6], header[7]])
        } as usize;

        // IDB starts after SHB
        let idb_start = shb_len;
        if header.len() < idb_start + 12 {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Header too small for IDB: {} bytes (need {})",
                    header.len(),
                    idb_start + 12
                ),
            )));
        }

        // Verify IDB block type (0x00000001)
        let idb_type = if is_le {
            u32::from_le_bytes([
                header[idb_start],
                header[idb_start + 1],
                header[idb_start + 2],
                header[idb_start + 3],
            ])
        } else {
            u32::from_be_bytes([
                header[idb_start],
                header[idb_start + 1],
                header[idb_start + 2],
                header[idb_start + 3],
            ])
        };

        if idb_type != 1 {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Expected IDB block type 1, got {idb_type} at offset {idb_start}"),
            )));
        }

        // IDB structure:
        // - Block Type (4): 0x00000001
        // - Block Total Length (4)
        // - Link Type (2) <-- what we need
        // - Reserved (2)
        // - SnapLen (4)
        // - Options (variable)
        // - Block Total Length (4)

        // Link type is at offset 8 within IDB (2 bytes)
        let link_type = if is_le {
            u16::from_le_bytes([header[idb_start + 8], header[idb_start + 9]]) as u32
        } else {
            u16::from_be_bytes([header[idb_start + 8], header[idb_start + 9]]) as u32
        };

        Ok(link_type)
    }

    /// Get the cloud location.
    pub fn location(&self) -> &CloudLocation {
        &self.location
    }

    /// Get the detected compression format.
    pub fn compression(&self) -> Compression {
        self.compression
    }

    /// Get the detected PCAP format.
    pub fn pcap_format(&self) -> PcapFormat {
        self.pcap_format
    }
}

impl PacketSource for CloudPacketSource {
    type Reader = CloudPacketReader;

    fn metadata(&self) -> &PacketSourceMetadata {
        &self.metadata
    }

    fn sequential_reader(&self) -> Result<Self::Reader, Error> {
        CloudPacketReader::sequential(self.raw_reader(0, None), self.compression, self.pcap_format)
    }
}

impl SeekablePacketSource for CloudPacketSource {
    fn time_range_ns(&self) -> Option<(i64, i64)> {
        self.ensure_index().ok().and_then(|idx| idx.time_range_ns())
    }

    fn seek_cost(&self) -> SeekCost {
        SeekCost::RangeRequest
    }

    fn reader_at(&self, range: &PacketRange) -> Result<Self::Reader, Error> {
        if self.compression.is_compressed() {
            return self.sequential_reader();
        }
        let idx = self.ensure_index()?;
        let header = synth_header_for(&idx, range.start.frame_number, self.pcap_format)?;
        let end_frame = range.end.as_ref().map(|e| e.frame_number);
        // Fetch only this partition's bytes: [start offset, next partition start).
        let end_offset = range.end.as_ref().map(|e| e.byte_offset);
        CloudPacketReader::at(
            self.raw_reader(range.start.byte_offset, end_offset),
            self.pcap_format,
            header,
            range.start.frame_number,
            end_frame,
        )
    }

    fn partitions(&self, max: usize) -> Result<Vec<PacketRange>, Error> {
        if self.compression.is_compressed() {
            return Ok(vec![PacketRange::whole()]);
        }
        let idx = self.ensure_index()?;
        Ok(idx.partition_ranges(max))
    }

    fn frame_count(&self) -> Option<u64> {
        if self.compression.is_compressed() {
            return None;
        }
        self.ensure_index().ok().map(|idx| idx.packet_count)
    }
}

/// The concrete `Read` stack for cloud readers: an optional synthesized header
/// (empty for sequential reads) chained before the object-store range reader,
/// wrapped in decompression.
type CloudInner = GenericPcapReader<DecompressReader<Chain<Cursor<Vec<u8>>, ObjectStoreReader>>>;

/// Cloud-backed packet reader.
pub struct CloudPacketReader {
    inner: CloudInner,
    link_type: u32,
    end_frame: Option<u64>,
}

impl CloudPacketReader {
    /// Sequential reader over the whole object (honors compression).
    fn sequential(
        cloud_reader: ObjectStoreReader,
        compression: Compression,
        format: PcapFormat,
    ) -> Result<Self, Error> {
        let chain = Cursor::new(Vec::new()).chain(cloud_reader);
        let decompress = DecompressReader::new(chain, compression)?;
        let inner = GenericPcapReader::with_format(decompress, format)?;
        let link_type = inner.link_type();
        Ok(Self {
            inner,
            link_type,
            end_frame: None,
        })
    }

    /// Reader at a byte offset, prepending a synthesized header. Uncompressed
    /// objects only (the only ones that are partitioned).
    fn at(
        cloud_reader: ObjectStoreReader,
        format: PcapFormat,
        synth_header: Vec<u8>,
        start_frame: u64,
        end_frame: Option<u64>,
    ) -> Result<Self, Error> {
        let chain = Cursor::new(synth_header).chain(cloud_reader);
        let decompress = DecompressReader::new(chain, Compression::None)?;
        let inner = GenericPcapReader::with_format_starting_at(decompress, format, start_frame)?;
        let link_type = inner.link_type();
        Ok(Self {
            inner,
            link_type,
            end_frame,
        })
    }
}

impl PacketReader for CloudPacketReader {
    fn process_packets<F>(&mut self, max: usize, f: F) -> Result<usize, Error>
    where
        F: FnMut(PacketRef<'_>) -> Result<(), Error>,
    {
        // `end_frame` is exclusive: emit frames with number < end_frame.
        let effective_max = match self.end_frame {
            Some(end) => {
                let current = self.inner.frame_count();
                let remaining = end.saturating_sub(current).saturating_sub(1);
                if remaining == 0 {
                    return Ok(0);
                }
                max.min(remaining as usize)
            }
            None => max,
        };
        let count = self.inner.process_packets(effective_max, f)?;
        self.link_type = self.inner.link_type();
        Ok(count)
    }

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

// CloudPacketReader is Send
unsafe impl Send for CloudPacketReader {}

// Required for async compatibility
impl Unpin for CloudPacketReader {}

/// Check if a URL string is a cloud storage URL.
pub fn is_cloud_url(url: &str) -> bool {
    url.starts_with("s3://") || url.starts_with("gs://") || url.starts_with("az://")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `run_async` must not panic or hang when the caller is inside a
    /// current_thread runtime (`#[tokio::test]`, current_thread mains).
    #[test]
    fn run_async_works_inside_a_current_thread_runtime() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let v = rt.block_on(async {
            run_async(None, async {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                41 + 1
            })
        });
        assert_eq!(v, 42);
        // A current_thread handle is never saved for worker threads.
        rt.block_on(async { assert!(saveable_handle().is_none()) });
    }

    /// From a plain thread with no runtime at all, and from inside a
    /// multi-thread runtime.
    #[test]
    fn run_async_works_without_a_runtime_and_on_multi_thread() {
        assert_eq!(run_async(None, async { 7 }), 7);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let v = rt.block_on(async {
            let saved = saveable_handle();
            assert!(saved.is_some());
            run_async(saved.as_ref(), async { 8 })
        });
        assert_eq!(v, 8);
    }

    #[test]
    fn test_parse_s3_url() {
        let loc = CloudLocation::parse("s3://my-bucket/path/to/file.pcap").unwrap();
        assert_eq!(loc.scheme(), "s3");
        assert_eq!(loc.bucket(), Some("my-bucket"));
        assert_eq!(loc.key(), "path/to/file.pcap");
        assert!(loc.endpoint().is_none());
    }

    #[test]
    fn test_parse_s3_root_key() {
        let loc = CloudLocation::parse("s3://bucket/file.pcap").unwrap();
        assert_eq!(loc.bucket(), Some("bucket"));
        assert_eq!(loc.key(), "file.pcap");
    }

    #[test]
    fn test_parse_gcs_url() {
        let loc = CloudLocation::parse("gs://my-bucket/capture.pcap.gz").unwrap();
        assert_eq!(loc.scheme(), "gs");
        assert_eq!(loc.bucket(), Some("my-bucket"));
        assert_eq!(loc.key(), "capture.pcap.gz");
    }

    #[test]
    fn test_parse_azure_url() {
        let loc = CloudLocation::parse("az://container/blob/path.pcap").unwrap();
        assert_eq!(loc.scheme(), "az");
        assert_eq!(loc.bucket(), Some("container"));
        assert_eq!(loc.key(), "blob/path.pcap");
    }

    #[test]
    fn test_parse_invalid_scheme() {
        assert!(CloudLocation::parse("http://example.com/file").is_err());
        assert!(CloudLocation::parse("ftp://bucket/key").is_err());
    }

    #[test]
    fn test_with_endpoint() {
        let loc = CloudLocation::parse("s3://bucket/key")
            .unwrap()
            .with_endpoint("http://localhost:9000");
        assert_eq!(loc.endpoint(), Some("http://localhost:9000"));
    }

    #[test]
    fn test_with_anonymous() {
        let loc = CloudLocation::parse("s3://bucket/key")
            .unwrap()
            .with_anonymous(true);
        assert!(loc.is_anonymous());
    }

    #[test]
    fn test_is_cloud_url() {
        assert!(is_cloud_url("s3://bucket/key"));
        assert!(is_cloud_url("gs://bucket/key"));
        assert!(is_cloud_url("az://container/blob"));
        assert!(!is_cloud_url("/path/to/file.pcap"));
        assert!(!is_cloud_url("./relative/path.pcap"));
        assert!(!is_cloud_url("http://example.com"));
    }

    #[test]
    fn test_object_path() {
        let loc = CloudLocation::parse("s3://bucket/path/to/file.pcap").unwrap();
        let path = loc.object_path();
        assert_eq!(path.as_ref(), "path/to/file.pcap");
    }

    #[test]
    fn test_with_chunk_size() {
        let loc = CloudLocation::parse("s3://bucket/key")
            .unwrap()
            .with_chunk_size(16 * 1024 * 1024);
        assert_eq!(loc.chunk_size(), 16 * 1024 * 1024);
    }

    #[test]
    fn test_default_chunk_size() {
        let loc = CloudLocation::parse("s3://bucket/key").unwrap();
        assert_eq!(loc.chunk_size(), DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn test_parse_legacy_link_type_le() {
        // Legacy PCAP header with link type = 1 (Ethernet) at offset 20
        // Little-endian format
        let mut header = [0u8; 24];
        // Magic (LE microseconds)
        header[0..4].copy_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
        // Version major
        header[4..6].copy_from_slice(&[0x02, 0x00]);
        // Version minor
        header[6..8].copy_from_slice(&[0x04, 0x00]);
        // Timezone (0)
        // Sigfigs (0)
        // Snaplen (65535)
        header[16..20].copy_from_slice(&[0xff, 0xff, 0x00, 0x00]);
        // Link type (1 = Ethernet, LE)
        header[20..24].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]);

        let format = PcapFormat::LegacyLeMicro;
        let link_type = CloudPacketSource::parse_link_type_from_header(&header, format).unwrap();
        assert_eq!(link_type, 1);
    }

    #[test]
    fn test_parse_legacy_link_type_be() {
        // Legacy PCAP header with link type = 1 (Ethernet) at offset 20
        // Big-endian format
        let mut header = [0u8; 24];
        // Magic (BE microseconds)
        header[0..4].copy_from_slice(&[0xa1, 0xb2, 0xc3, 0xd4]);
        // Version major
        header[4..6].copy_from_slice(&[0x00, 0x02]);
        // Version minor
        header[6..8].copy_from_slice(&[0x00, 0x04]);
        // Timezone (0)
        // Sigfigs (0)
        // Snaplen (65535)
        header[16..20].copy_from_slice(&[0x00, 0x00, 0xff, 0xff]);
        // Link type (1 = Ethernet, BE)
        header[20..24].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]);

        let format = PcapFormat::LegacyBeMicro;
        let link_type = CloudPacketSource::parse_link_type_from_header(&header, format).unwrap();
        assert_eq!(link_type, 1);
    }

    #[test]
    fn test_parse_pcapng_link_type() {
        // Minimal PCAPNG with SHB (28 bytes) + IDB (20 bytes) = 48 bytes
        let mut header = vec![0u8; 48];

        // Section Header Block (SHB)
        // Block Type (0x0A0D0D0A)
        header[0..4].copy_from_slice(&[0x0a, 0x0d, 0x0d, 0x0a]);
        // Block Total Length (28 bytes) - LE
        header[4..8].copy_from_slice(&[0x1c, 0x00, 0x00, 0x00]);
        // Byte-Order Magic (0x1A2B3C4D) - LE
        header[8..12].copy_from_slice(&[0x4d, 0x3c, 0x2b, 0x1a]);
        // Major Version (1)
        header[12..14].copy_from_slice(&[0x01, 0x00]);
        // Minor Version (0)
        header[14..16].copy_from_slice(&[0x00, 0x00]);
        // Section Length (-1 = unspecified)
        header[16..24].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        // Block Total Length (again)
        header[24..28].copy_from_slice(&[0x1c, 0x00, 0x00, 0x00]);

        // Interface Description Block (IDB) at offset 28
        // Block Type (1)
        header[28..32].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        // Block Total Length (20 bytes)
        header[32..36].copy_from_slice(&[0x14, 0x00, 0x00, 0x00]);
        // Link Type (1 = Ethernet)
        header[36..38].copy_from_slice(&[0x01, 0x00]);
        // Reserved
        header[38..40].copy_from_slice(&[0x00, 0x00]);
        // SnapLen (65535)
        header[40..44].copy_from_slice(&[0xff, 0xff, 0x00, 0x00]);
        // Block Total Length (again)
        header[44..48].copy_from_slice(&[0x14, 0x00, 0x00, 0x00]);

        let link_type = CloudPacketSource::parse_pcapng_link_type(&header).unwrap();
        assert_eq!(link_type, 1);
    }

    #[test]
    fn test_parse_link_type_header_too_small() {
        let header = [0u8; 20]; // Too small for legacy PCAP
        let format = PcapFormat::LegacyLeMicro;
        assert!(CloudPacketSource::parse_link_type_from_header(&header, format).is_err());
    }

    #[test]
    fn test_parse_pcapng_header_too_small() {
        let header = [0u8; 30]; // Too small for PCAPNG
        assert!(CloudPacketSource::parse_pcapng_link_type(&header).is_err());
    }
}
