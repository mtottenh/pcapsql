//! URI handling and cloud storage detection.
//!
//! This module provides utilities for:
//! - Detecting cloud storage URLs (s3://, gs://, az://)
//! - Creating appropriate packet sources based on URI scheme

use std::path::PathBuf;

/// Represents a parsed input source - either a local file or cloud URL.
#[derive(Debug, Clone)]
pub enum InputSource {
    /// Local file path.
    LocalFile(PathBuf),

    /// Cloud storage URL (requires `cloud` feature).
    #[cfg(feature = "cloud")]
    CloudUrl(String),
}

impl InputSource {
    /// Parse an input path or URL into an InputSource.
    ///
    /// Detects cloud URLs by scheme (s3://, gs://, az://) and falls back
    /// to treating the input as a local file path.
    pub fn parse(input: &str) -> Self {
        #[cfg(feature = "cloud")]
        {
            if pcapsql_core::io::is_cloud_url(input) {
                return InputSource::CloudUrl(input.to_string());
            }
        }

        InputSource::LocalFile(PathBuf::from(input))
    }

    /// Check if this is a cloud URL.
    #[allow(dead_code)]
    pub fn is_cloud(&self) -> bool {
        #[cfg(feature = "cloud")]
        {
            matches!(self, InputSource::CloudUrl(_))
        }
        #[cfg(not(feature = "cloud"))]
        {
            false
        }
    }

    /// Get the display name for this source.
    pub fn display_name(&self) -> String {
        match self {
            InputSource::LocalFile(path) => path.display().to_string(),
            #[cfg(feature = "cloud")]
            InputSource::CloudUrl(url) => url.clone(),
        }
    }
}

/// Cloud storage options parsed from CLI arguments.
#[cfg(feature = "cloud")]
#[derive(Debug, Clone, Default)]
pub struct CloudOptions {
    /// Custom endpoint URL (for S3-compatible services).
    pub endpoint: Option<String>,

    /// Use anonymous (unsigned) requests.
    pub anonymous: bool,

    /// Chunk size for byte-range requests.
    pub chunk_size: usize,
}

#[cfg(feature = "cloud")]
impl CloudOptions {
    /// Create CloudOptions with defaults.
    pub fn new() -> Self {
        Self {
            endpoint: None,
            anonymous: false,
            chunk_size: 8 * 1024 * 1024, // 8MB default
        }
    }

    /// Set custom endpoint.
    pub fn with_endpoint(mut self, endpoint: Option<String>) -> Self {
        self.endpoint = endpoint;
        self
    }

    /// Set anonymous mode.
    pub fn with_anonymous(mut self, anonymous: bool) -> Self {
        self.anonymous = anonymous;
        self
    }

    /// Set chunk size.
    pub fn with_chunk_size(mut self, chunk_size: usize) -> Self {
        self.chunk_size = chunk_size;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_file_parsing() {
        let source = InputSource::parse("/path/to/file.pcap");
        match source {
            InputSource::LocalFile(path) => {
                assert_eq!(path, PathBuf::from("/path/to/file.pcap"));
            }
            #[cfg(feature = "cloud")]
            InputSource::CloudUrl(_) => panic!("Expected LocalFile"),
        }
    }

    #[test]
    fn test_relative_path_parsing() {
        let source = InputSource::parse("./data/test.pcap");
        match source {
            InputSource::LocalFile(path) => {
                assert_eq!(path, PathBuf::from("./data/test.pcap"));
            }
            #[cfg(feature = "cloud")]
            InputSource::CloudUrl(_) => panic!("Expected LocalFile"),
        }
    }

    #[cfg(feature = "cloud")]
    #[test]
    fn test_s3_url_parsing() {
        let source = InputSource::parse("s3://bucket/key.pcap");
        match source {
            InputSource::CloudUrl(url) => {
                assert_eq!(url, "s3://bucket/key.pcap");
            }
            InputSource::LocalFile(_) => panic!("Expected CloudUrl"),
        }
    }

    #[cfg(feature = "cloud")]
    #[test]
    fn test_gs_url_parsing() {
        let source = InputSource::parse("gs://bucket/path/to/file.pcap");
        match source {
            InputSource::CloudUrl(url) => {
                assert_eq!(url, "gs://bucket/path/to/file.pcap");
            }
            InputSource::LocalFile(_) => panic!("Expected CloudUrl"),
        }
    }

    #[cfg(feature = "cloud")]
    #[test]
    fn test_azure_url_parsing() {
        let source = InputSource::parse("az://container/blob.pcap");
        match source {
            InputSource::CloudUrl(url) => {
                assert_eq!(url, "az://container/blob.pcap");
            }
            InputSource::LocalFile(_) => panic!("Expected CloudUrl"),
        }
    }

    #[test]
    fn test_display_name_local() {
        let source = InputSource::parse("test.pcap");
        assert_eq!(source.display_name(), "test.pcap");
    }

    #[cfg(feature = "cloud")]
    #[test]
    fn test_display_name_cloud() {
        let source = InputSource::parse("s3://bucket/file.pcap");
        assert_eq!(source.display_name(), "s3://bucket/file.pcap");
    }

    #[cfg(feature = "cloud")]
    #[test]
    fn test_cloud_options_builder() {
        let opts = CloudOptions::new()
            .with_endpoint(Some("http://localhost:9000".to_string()))
            .with_anonymous(true)
            .with_chunk_size(16 * 1024 * 1024);

        assert_eq!(opts.endpoint, Some("http://localhost:9000".to_string()));
        assert!(opts.anonymous);
        assert_eq!(opts.chunk_size, 16 * 1024 * 1024);
    }
}
