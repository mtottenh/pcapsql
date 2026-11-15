//! Where a cloud object is, and the store client for it.

use std::io;
use std::sync::Arc;

use object_store::{path::Path as ObjectPath, ObjectStore};
use url::Url;

use crate::error::Error;

/// Default chunk size for cloud reads (8MB).
pub(super) const DEFAULT_CHUNK_SIZE: usize = 8 * 1024 * 1024;

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

        let store = builder
            .build()
            .map_err(|e| Error::Io(io::Error::other(format!("Failed to build GCS store: {e}"))))?;

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
            Error::Io(io::Error::other(format!(
                "Failed to build Azure store: {e}"
            )))
        })?;

        Ok(Arc::new(store))
    }

    /// Get the object path for this location.
    pub fn object_path(&self) -> ObjectPath {
        ObjectPath::from(self.key())
    }
}
