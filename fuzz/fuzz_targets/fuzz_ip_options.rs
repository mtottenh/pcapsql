//! Fuzz target for IPv4 options and IPv6 extension headers.
//!
//! This target tests the complex variable-length structures in IP headers:
//!
//! **IPv4 Options:**
//! - IHL (Internet Header Length) validation (5-15 32-bit words)
//! - Option kind/length parsing
//! - Padding handling
//!
//! **IPv6 Extension Headers:**
//! - Extension header chain traversal
//! - Next header field validation
//! - Hop-by-Hop, Routing, Fragment, Destination headers

#![no_main]

use libfuzzer_sys::fuzz_target;
use pcapsql_core::{default_registry, parse_packet};

// Include generated frame wrappers
include!("../src/frames.rs");

/// Build an IPv4 header with the given IHL and options.
/// Returns a complete IPv4 header (20 bytes minimum + options).
fn build_ipv4_header(ihl: u8, options: &[u8]) -> Vec<u8> {
    let mut header = Vec::with_capacity(60); // Max IPv4 header is 60 bytes

    // Version (4) + IHL (4-15)
    // IHL must be at least 5 (20 bytes), max 15 (60 bytes)
    let ihl_clamped = ihl.clamp(5, 15);
    header.push((4 << 4) | ihl_clamped);

    // DSCP + ECN
    header.push(0x00);

    // Total length (placeholder - will be set by caller)
    header.push(0x00);
    header.push(0x28); // 40 bytes minimum

    // Identification
    header.push(0x00);
    header.push(0x01);

    // Flags + Fragment offset
    header.push(0x00);
    header.push(0x00);

    // TTL
    header.push(0x40); // 64

    // Protocol (6 = TCP, so we get a next-layer parser)
    header.push(0x06);

    // Header checksum (0 - not validated by parser)
    header.push(0x00);
    header.push(0x00);

    // Source IP: 10.0.0.1
    header.push(0x0a);
    header.push(0x00);
    header.push(0x00);
    header.push(0x01);

    // Destination IP: 10.0.0.2
    header.push(0x0a);
    header.push(0x00);
    header.push(0x00);
    header.push(0x02);

    // Options (variable length, up to 40 bytes)
    let options_space = ((ihl_clamped as usize) - 5) * 4;
    let options_to_copy = options.len().min(options_space);
    header.extend_from_slice(&options[..options_to_copy]);

    // Padding to match IHL
    while header.len() < (ihl_clamped as usize) * 4 {
        header.push(0x00); // NOP padding
    }

    header
}

/// Build an IPv6 header with extension header chain.
/// Returns a complete IPv6 header (40 bytes) + extension headers.
fn build_ipv6_header(ext_headers: &[u8]) -> Vec<u8> {
    let mut header = Vec::with_capacity(40 + ext_headers.len());

    // Version (6) + Traffic Class (upper 4 bits)
    header.push(0x60);

    // Traffic Class (lower 4 bits) + Flow Label (upper 4 bits)
    header.push(0x00);

    // Flow Label (remaining 16 bits)
    header.push(0x00);
    header.push(0x00);

    // Payload length (extension headers + any payload)
    let payload_len = ext_headers.len() as u16;
    header.push((payload_len >> 8) as u8);
    header.push((payload_len & 0xff) as u8);

    // Next header - if we have ext headers, first byte of fuzz data is next header
    // Otherwise use 59 (No Next Header)
    if !ext_headers.is_empty() {
        header.push(ext_headers[0]); // First byte as next header type
    } else {
        header.push(59); // No Next Header
    }

    // Hop Limit
    header.push(64);

    // Source address (::1)
    for _ in 0..15 {
        header.push(0x00);
    }
    header.push(0x01);

    // Destination address (::1)
    for _ in 0..15 {
        header.push(0x00);
    }
    header.push(0x01);

    // Extension headers (fuzz data, skip first byte which was used as next header type)
    if ext_headers.len() > 1 {
        header.extend_from_slice(&ext_headers[1..]);
    }

    header
}

fuzz_target!(|data: &[u8]| {
    // Need at least a few bytes to work with
    if data.is_empty() {
        return;
    }

    let registry = default_registry();

    // Use first byte to determine which protocol variant to test
    let selector = data[0] % 3;
    let payload = if data.len() > 1 { &data[1..] } else { &[] };

    match selector {
        0 => {
            // Test IPv4 with options
            // First byte of payload is IHL, rest is options
            if payload.is_empty() {
                return;
            }

            let ihl = (payload[0] % 11) + 5; // IHL from 5-15
            let options = if payload.len() > 1 { &payload[1..] } else { &[] };

            // Build frame: Ethernet + IPv4 with options
            let mut frame = IPV4_OPTIONS_FRAME.to_vec();
            let ipv4_header = build_ipv4_header(ihl, options);

            // Patch total length in IPv4 header
            let total_len = ipv4_header.len() as u16;
            let mut patched_header = ipv4_header;
            patched_header[2] = (total_len >> 8) as u8;
            patched_header[3] = (total_len & 0xff) as u8;

            frame.extend_from_slice(&patched_header);

            let _ = parse_packet(&registry, 1, &frame);
        }
        1 => {
            // Test IPv6 with extension headers
            let mut frame = IPV6_EXT_FRAME.to_vec();
            let ipv6_header = build_ipv6_header(payload);
            frame.extend_from_slice(&ipv6_header);

            let _ = parse_packet(&registry, 1, &frame);
        }
        _ => {
            // Test both IPv4 and IPv6 with same fuzz data
            // This helps find differences in handling

            // IPv4 path
            if !payload.is_empty() {
                let ihl = (payload[0] % 11) + 5;
                let options = if payload.len() > 1 { &payload[1..] } else { &[] };

                let mut frame = IPV4_OPTIONS_FRAME.to_vec();
                let ipv4_header = build_ipv4_header(ihl, options);
                let total_len = ipv4_header.len() as u16;
                let mut patched_header = ipv4_header;
                patched_header[2] = (total_len >> 8) as u8;
                patched_header[3] = (total_len & 0xff) as u8;
                frame.extend_from_slice(&patched_header);

                let _ = parse_packet(&registry, 1, &frame);
            }

            // IPv6 path
            let mut frame = IPV6_EXT_FRAME.to_vec();
            let ipv6_header = build_ipv6_header(payload);
            frame.extend_from_slice(&ipv6_header);

            let _ = parse_packet(&registry, 1, &frame);
        }
    }
});
