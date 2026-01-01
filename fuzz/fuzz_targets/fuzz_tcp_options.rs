//! Fuzz target for TCP options parsing.
//!
//! TCP parser (~1306 lines) handles various options:
//! - NOP (kind=1): Padding
//! - MSS (kind=2): Maximum Segment Size
//! - Window Scale (kind=3): Scale factor
//! - SACK Permitted (kind=4): Selective ACK allowed
//! - SACK (kind=5): Selective ACK blocks
//! - Timestamp (kind=8): TSval and TSecr
//!
//! This target differs from others: fuzz data becomes TCP OPTIONS,
//! not the payload after the TCP header.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pcapsql_core::{default_registry, parse_packet};

// Include generated frame wrappers
include!("../src/frames.rs");

/// Build a TCP header with the given data offset and options.
/// Returns a complete TCP header (20 bytes base + options + padding).
fn build_tcp_header(data_offset: u8, options: &[u8]) -> Vec<u8> {
    let mut header = Vec::with_capacity(60); // Max TCP header is 60 bytes

    // Source port (12345 = 0x3039)
    header.push(0x30);
    header.push(0x39);

    // Destination port (80 = 0x0050 for HTTP, triggers TCP parsing)
    header.push(0x00);
    header.push(0x50);

    // Sequence number (1)
    header.push(0x00);
    header.push(0x00);
    header.push(0x00);
    header.push(0x01);

    // Acknowledgment number (0)
    header.push(0x00);
    header.push(0x00);
    header.push(0x00);
    header.push(0x00);

    // Data offset (4 bits) + Reserved (4 bits)
    // Data offset is in 32-bit words (5 = 20 bytes minimum)
    header.push((data_offset << 4) | 0x00);

    // Flags: SYN (0x02) - common for options
    header.push(0x02);

    // Window size (65535)
    header.push(0xff);
    header.push(0xff);

    // Checksum (0 - not validated by parser)
    header.push(0x00);
    header.push(0x00);

    // Urgent pointer (0)
    header.push(0x00);
    header.push(0x00);

    // Options (variable length)
    header.extend_from_slice(options);

    // Padding to 4-byte boundary
    let options_len = options.len();
    let padding = (4 - (options_len % 4)) % 4;
    for _ in 0..padding {
        header.push(0x00); // NOP or END padding
    }

    header
}

fuzz_target!(|data: &[u8]| {
    // TCP options can be 0-40 bytes (header is 20-60 bytes total)
    // Empty input or too large means we skip
    if data.is_empty() || data.len() > 40 {
        return;
    }

    let registry = default_registry();

    // Start with Ethernet + IPv4 frame (no TCP yet)
    let mut frame = TCP_OPTIONS_FRAME.to_vec();

    // Calculate TCP header length with options
    let options_len = data.len();
    let padding = (4 - (options_len % 4)) % 4;
    let tcp_header_len = 20 + options_len + padding;

    // Data offset is TCP header length in 32-bit words
    let data_offset = (tcp_header_len / 4) as u8;

    // Build TCP header with fuzz data as options
    let tcp_header = build_tcp_header(data_offset, data);

    // Patch IPv4 total length (offset 16-17): IP(20) + TCP header
    let ip_total_len = (20 + tcp_header_len) as u16;
    frame[16] = (ip_total_len >> 8) as u8;
    frame[17] = (ip_total_len & 0xff) as u8;

    // Append TCP header with options
    frame.extend_from_slice(&tcp_header);

    // Parse the packet - TCP parser extracts and parses options
    let _ = parse_packet(&registry, 1, &frame);
});
