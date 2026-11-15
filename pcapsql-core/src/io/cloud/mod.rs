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

mod location;
mod object_reader;
mod runtime;
mod source;

pub use location::CloudLocation;
pub use object_reader::ObjectStoreReader;
pub use source::{CloudPacketReader, CloudPacketSource};

/// Check if a URL string is a cloud storage URL.
pub fn is_cloud_url(url: &str) -> bool {
    url.starts_with("s3://") || url.starts_with("gs://") || url.starts_with("az://")
}

#[cfg(test)]
mod tests {
    use super::location::DEFAULT_CHUNK_SIZE;
    use super::runtime::{run_async, saveable_handle};
    use super::*;
    use crate::io::PcapFormat;

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

    /// The IDB need not follow the SHB directly: other blocks in between are
    /// skipped, and a prefix without any IDB yields the Ethernet default.
    #[test]
    fn test_parse_pcapng_link_type_skips_other_blocks() {
        fn block(block_type: u32, body: &[u8]) -> Vec<u8> {
            let total = (12 + body.len()) as u32;
            let mut v = block_type.to_le_bytes().to_vec();
            v.extend_from_slice(&total.to_le_bytes());
            v.extend_from_slice(body);
            v.extend_from_slice(&total.to_le_bytes());
            v
        }
        let mut shb_body = vec![0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0];
        shb_body.extend_from_slice(&[0xff; 8]);
        let mut header = block(0x0A0D_0D0A, &shb_body);
        header.extend(block(0x0BAD, &[0; 16])); // a custom block
        header.extend(block(4, &[0; 8])); // a name resolution block
        let mut idb_body = 113u16.to_le_bytes().to_vec(); // LINKTYPE_LINUX_SLL
        idb_body.extend_from_slice(&[0, 0]);
        idb_body.extend_from_slice(&65535u32.to_le_bytes());
        header.extend(block(1, &idb_body));
        assert_eq!(
            CloudPacketSource::parse_pcapng_link_type(&header).unwrap(),
            113
        );

        // SHB only (IDB beyond the fetched prefix): default, not an error.
        let shb_only = block(0x0A0D_0D0A, &shb_body);
        assert_eq!(
            CloudPacketSource::parse_pcapng_link_type(&shb_only).unwrap(),
            1
        );
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
