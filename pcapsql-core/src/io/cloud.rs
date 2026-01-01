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
//! let source = CloudPacketSource::open(location).await?;
//!
//! // Now use with QueryEngine
//! let engine = QueryEngine::with_streaming_source(source).await?;
//! ```

use std::io::{self, Read};
use std::sync::Arc;

use object_store::{path::Path as ObjectPath, ObjectStore};
use url::Url;

use crate::error::Error;

/// Execute an async operation, handling runtime nesting correctly.
///
/// If called from within a tokio runtime, uses `block_in_place` to allow
/// blocking while running the future on the current runtime's handle.
/// If called outside a runtime, creates a temporary single-threaded runtime.
fn run_async<F, T>(future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    // Try to get the current runtime handle
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            // We're in a runtime, need to block in place and run on current handle
            tokio::task::block_in_place(|| handle.block_on(future))
        }
        Err(_) => {
            // Not in a runtime, create a temporary one
            // Use current_thread to minimize overhead for blocking operations
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create temporary runtime")
                .block_on(future)
        }
    }
}
use crate::io::{
    decompress_header, Compression, DecompressReader, GenericPcapReader, PacketPosition,
    PacketRange, PacketReader, PacketRef, PacketSource, PacketSourceMetadata, PcapFormat,
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

        let mut builder = GoogleCloudStorageBuilder::from_env().with_bucket_name(bucket);

        if self.anonymous {
            builder = builder.with_anonymous(true);
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
    position: u64,
    buffer: Vec<u8>,
    buffer_start: u64,
    chunk_size: usize,
}

impl ObjectStoreReader {
    /// Open a cloud object for reading.
    pub fn open(location: &CloudLocation) -> Result<Self, Error> {
        let store = location.build_store()?;
        let path = location.object_path();

        // Get object size via HEAD request
        let object_size = run_async(async {
            let meta = store.head(&path).await.map_err(|e| {
                Error::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Failed to HEAD cloud object: {e}"),
                ))
            })?;
            Ok::<u64, Error>(meta.size as u64)
        })?;

        Ok(Self {
            store,
            path,
            object_size,
            position: 0,
            buffer: Vec::new(),
            buffer_start: 0,
            chunk_size: location.chunk_size(),
        })
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
        Self {
            store,
            path,
            object_size,
            position: 0,
            buffer: header_bytes,
            buffer_start: 0,
            chunk_size,
        }
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
        run_async(async move {
            let range = std::ops::Range {
                start: start as usize,
                end: end as usize,
            };

            let bytes = store
                .get_range(&path, range)
                .await
                .map_err(|e| io::Error::other(format!("Cloud GetRange failed: {e}")))?;

            Ok(bytes.to_vec())
        })
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
        if self.position >= self.object_size {
            // At EOF, clear buffer
            self.buffer.clear();
            return Ok(());
        }

        let start = self.position;
        let end = (start + self.chunk_size as u64).min(self.object_size);

        self.buffer = self.fetch_range(start, end)?;
        self.buffer_start = start;

        Ok(())
    }
}

impl Read for ObjectStoreReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.object_size {
            return Ok(0); // EOF
        }

        self.ensure_buffer()?;

        if self.buffer.is_empty() {
            return Ok(0); // EOF
        }

        // Calculate how much we can read from buffer
        let buffer_offset = (self.position - self.buffer_start) as usize;
        let available = self.buffer.len() - buffer_offset;
        let to_read = buf.len().min(available);

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
    metadata: PacketSourceMetadata,
    compression: Compression,
    pcap_format: PcapFormat,
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

        // 1. HEAD request to get object size
        let store_clone = Arc::clone(&store);
        let path_clone = path.clone();
        let object_size = run_async(async move {
            let meta = store_clone.head(&path_clone).await.map_err(|e| {
                Error::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Failed to HEAD cloud object: {e}"),
                ))
            })?;
            Ok::<u64, Error>(meta.size as u64)
        })?;

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
        let header_bytes = run_async(async move {
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
            packet_count: None, // Would require scanning
            seekable: false,    // Cloud doesn't support efficient seeking
        };

        Ok(Self {
            location,
            metadata,
            compression,
            pcap_format,
        })
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

        // Detect endianness from Byte-Order Magic at offset 8
        let bom = u32::from_ne_bytes([header[8], header[9], header[10], header[11]]);
        let is_le = bom == 0x1A2B3C4D;
        let is_be = bom == 0x4D3C2B1A;

        if !is_le && !is_be {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid PCAPNG byte-order magic: 0x{bom:08x}"),
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

    fn reader(&self, _range: Option<&PacketRange>) -> Result<Self::Reader, Error> {
        // Note: Range support would require index or sequential scan
        // For now, we always read from the beginning
        CloudPacketReader::new(
            &self.location,
            self.compression,
            self.pcap_format,
            self.metadata.link_type,
        )
    }

    fn partitions(&self, _max_partitions: usize) -> Result<Vec<PacketRange>, Error> {
        // Cloud doesn't support efficient partitioning without an index
        // Return single partition covering entire object
        Ok(vec![PacketRange::whole()])
    }
}

/// Cloud-backed packet reader.
///
/// Wraps the ObjectStoreReader → DecompressReader → GenericPcapReader stack
/// and implements [`PacketReader`] for the query engine.
pub struct CloudPacketReader {
    inner: GenericPcapReader<DecompressReader<ObjectStoreReader>>,
    link_type: u32,
    position: PacketPosition,
}

impl CloudPacketReader {
    /// Create a new cloud packet reader.
    fn new(
        location: &CloudLocation,
        compression: Compression,
        format: PcapFormat,
        link_type: u32,
    ) -> Result<Self, Error> {
        let cloud_reader = ObjectStoreReader::open(location)?;
        let decompress = DecompressReader::new(cloud_reader, compression)?;
        let inner = GenericPcapReader::with_format(decompress, format)?;

        Ok(Self {
            inner,
            link_type,
            position: PacketPosition::START,
        })
    }
}

impl PacketReader for CloudPacketReader {
    fn process_packets<F>(&mut self, max: usize, mut f: F) -> Result<usize, Error>
    where
        F: FnMut(PacketRef<'_>) -> Result<(), Error>,
    {
        let count = self.inner.process_packets(max, |packet| {
            self.position.frame_number = packet.frame_number + 1;
            f(packet)
        })?;

        Ok(count)
    }

    fn position(&self) -> PacketPosition {
        self.position.clone()
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
