//! Fuzz target for HTTP/1.x and HTTP/2 stream parsers.
//!
//! This target tests the application-layer parsing of HTTP messages:
//!
//! **HTTP/1.x:**
//! - Request line parsing (method, path, version)
//! - Response status line parsing
//! - Header field parsing (name: value)
//! - Chunked transfer encoding
//! - Content-Length handling
//!
//! **HTTP/2:**
//! - Frame header (9 bytes)
//! - Frame type validation
//! - Stream ID handling
//! - HPACK header compression
//! - Flow control (WINDOW_UPDATE)

#![no_main]

use libfuzzer_sys::fuzz_target;
use pcapsql_core::stream::{
    Direction, Http2StreamParser, HttpStreamParser, StreamContext, StreamParser,
};
use std::net::{IpAddr, Ipv4Addr};

/// Create a mock StreamContext for HTTP parsing.
fn http_context() -> StreamContext {
    StreamContext {
        connection_id: 1,
        direction: Direction::ToServer,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        src_port: 12345,
        dst_port: 80,
        bytes_parsed: 0,
        messages_parsed: 0,
        alpn: None,
    }
}

/// Create a mock StreamContext for HTTP/2 parsing.
fn http2_context() -> StreamContext {
    StreamContext {
        connection_id: 2,
        direction: Direction::ToServer,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        src_port: 12345,
        dst_port: 443,
        bytes_parsed: 0,
        messages_parsed: 0,
        alpn: Some("h2".to_string()),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Use first byte to select which parser variant to test
    let selector = data[0] % 4;
    let payload = if data.len() > 1 { &data[1..] } else { &[] };

    if payload.is_empty() {
        return;
    }

    match selector {
        0 => {
            // Test HTTP/1.x request parsing (client -> server)
            let parser = HttpStreamParser::new();
            let ctx = http_context();
            let _ = parser.parse_stream(payload, &ctx);
        }
        1 => {
            // Test HTTP/1.x response parsing (server -> client)
            let parser = HttpStreamParser::new();
            let mut ctx = http_context();
            ctx.direction = Direction::ToClient;
            let _ = parser.parse_stream(payload, &ctx);
        }
        2 => {
            // Test HTTP/2 frame parsing (client -> server)
            let parser = Http2StreamParser::new();
            let ctx = http2_context();
            let _ = parser.parse_stream(payload, &ctx);
        }
        _ => {
            // Test HTTP/2 frame parsing (server -> client)
            let parser = Http2StreamParser::new();
            let mut ctx = http2_context();
            ctx.direction = Direction::ToClient;
            let _ = parser.parse_stream(payload, &ctx);
        }
    }
});
