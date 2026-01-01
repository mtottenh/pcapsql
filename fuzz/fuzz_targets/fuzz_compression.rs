//! Fuzz target for compression detection and decompression.
//!
//! Tests format confusion and decompression bombs for supported formats:
//! - Gzip (0x1f, 0x8b)
//! - Zstd (0x28, 0xb5, 0x2f, 0xfd)
//! - LZ4 (0x04, 0x22, 0x4d, 0x18)
//! - Bzip2 (0x42, 0x5a)
//! - XZ (0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00)

#![no_main]

use libfuzzer_sys::fuzz_target;
use pcapsql_core::io::{Compression, DecompressReader};
use std::io::{Cursor, Read};

/// Maximum bytes to read during decompression to prevent bombs.
const MAX_DECOMPRESS_SIZE: usize = 1024 * 1024; // 1MB

fuzz_target!(|data: &[u8]| {
    // Test format detection - should never panic
    let compression = Compression::detect(data);

    // Test decompression with size limit to prevent bombs
    let cursor = Cursor::new(data);
    if let Ok(mut reader) = DecompressReader::new(cursor, compression) {
        let mut buf = vec![0u8; MAX_DECOMPRESS_SIZE];
        // Read with limit - should handle all malformed input gracefully
        let _ = reader.read(&mut buf);
    }
});
