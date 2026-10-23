//! Fuzz target for PCAP file format parsing.
//!
//! Tests handling of malformed PCAP/PCAPNG files including:
//! - Magic byte detection
//! - Global header parsing
//! - Packet record headers (caplen, origlen, timestamps)
//! - Endianness handling

#![no_main]

use libfuzzer_sys::fuzz_target;
use pcapsql_core::io::{GenericPcapReader, PcapFormat};
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Test format detection - should never panic
    if let Ok(format) = PcapFormat::detect(data) {
        // Test full PCAP parsing with detected format
        let cursor = Cursor::new(data);
        if let Ok(mut reader) = GenericPcapReader::with_format(cursor, format) {
            // Read all packets through the zero-copy callback API - should
            // never panic; errors (truncated/corrupt records) are expected.
            loop {
                match reader.process_packets(64, |_packet| Ok(())) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
    }
});
