//! HTTP/2 frame parser for decrypted TLS streams.
//!
//! Implements RFC 7540 frame parsing with HPACK header decompression.
//! This parser processes decrypted TLS application data containing HTTP/2 frames.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::{Buf, BytesMut};
use compact_str::CompactString;
use hpack::Decoder as HpackDecoder;

use crate::protocol::{FieldValue, OwnedFieldValue};
use crate::schema::{DataKind, FieldDescriptor};
use crate::stream::{Direction, ParsedMessage, StreamContext, StreamParseResult, StreamParser};

/// HTTP/2 connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
pub const CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// HTTP/2 frame types (RFC 7540 Section 6)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Data,
    Headers,
    Priority,
    RstStream,
    Settings,
    PushPromise,
    Ping,
    GoAway,
    WindowUpdate,
    Continuation,
    Unknown(u8),
}

impl From<u8> for FrameType {
    fn from(v: u8) -> Self {
        match v {
            0x0 => FrameType::Data,
            0x1 => FrameType::Headers,
            0x2 => FrameType::Priority,
            0x3 => FrameType::RstStream,
            0x4 => FrameType::Settings,
            0x5 => FrameType::PushPromise,
            0x6 => FrameType::Ping,
            0x7 => FrameType::GoAway,
            0x8 => FrameType::WindowUpdate,
            0x9 => FrameType::Continuation,
            other => FrameType::Unknown(other),
        }
    }
}

impl FrameType {
    /// Get string name for the frame type
    pub fn as_str(&self) -> &'static str {
        match self {
            FrameType::Data => "DATA",
            FrameType::Headers => "HEADERS",
            FrameType::Priority => "PRIORITY",
            FrameType::RstStream => "RST_STREAM",
            FrameType::Settings => "SETTINGS",
            FrameType::PushPromise => "PUSH_PROMISE",
            FrameType::Ping => "PING",
            FrameType::GoAway => "GOAWAY",
            FrameType::WindowUpdate => "WINDOW_UPDATE",
            FrameType::Continuation => "CONTINUATION",
            FrameType::Unknown(_) => "UNKNOWN",
        }
    }
}

/// HTTP/2 frame flags
pub mod flags {
    pub const END_STREAM: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const PADDED: u8 = 0x8;
    pub const PRIORITY: u8 = 0x20;
    pub const ACK: u8 = 0x1;
}

/// HTTP/2 error codes (RFC 7540 Section 7)
pub mod error_codes {
    pub const NO_ERROR: u32 = 0x0;
    pub const PROTOCOL_ERROR: u32 = 0x1;
    pub const INTERNAL_ERROR: u32 = 0x2;
    pub const FLOW_CONTROL_ERROR: u32 = 0x3;
    pub const SETTINGS_TIMEOUT: u32 = 0x4;
    pub const STREAM_CLOSED: u32 = 0x5;
    pub const FRAME_SIZE_ERROR: u32 = 0x6;
    pub const REFUSED_STREAM: u32 = 0x7;
    pub const CANCEL: u32 = 0x8;
    pub const COMPRESSION_ERROR: u32 = 0x9;
    pub const CONNECT_ERROR: u32 = 0xa;
    pub const ENHANCE_YOUR_CALM: u32 = 0xb;
    pub const INADEQUATE_SECURITY: u32 = 0xc;
    pub const HTTP_1_1_REQUIRED: u32 = 0xd;

    pub fn name(code: u32) -> &'static str {
        match code {
            NO_ERROR => "NO_ERROR",
            PROTOCOL_ERROR => "PROTOCOL_ERROR",
            INTERNAL_ERROR => "INTERNAL_ERROR",
            FLOW_CONTROL_ERROR => "FLOW_CONTROL_ERROR",
            SETTINGS_TIMEOUT => "SETTINGS_TIMEOUT",
            STREAM_CLOSED => "STREAM_CLOSED",
            FRAME_SIZE_ERROR => "FRAME_SIZE_ERROR",
            REFUSED_STREAM => "REFUSED_STREAM",
            CANCEL => "CANCEL",
            COMPRESSION_ERROR => "COMPRESSION_ERROR",
            CONNECT_ERROR => "CONNECT_ERROR",
            ENHANCE_YOUR_CALM => "ENHANCE_YOUR_CALM",
            INADEQUATE_SECURITY => "INADEQUATE_SECURITY",
            HTTP_1_1_REQUIRED => "HTTP_1_1_REQUIRED",
            _ => "UNKNOWN",
        }
    }
}

/// HTTP/2 settings identifiers (RFC 7540 Section 6.5.2)
pub mod settings {
    pub const HEADER_TABLE_SIZE: u16 = 0x1;
    pub const ENABLE_PUSH: u16 = 0x2;
    pub const MAX_CONCURRENT_STREAMS: u16 = 0x3;
    pub const INITIAL_WINDOW_SIZE: u16 = 0x4;
    pub const MAX_FRAME_SIZE: u16 = 0x5;
    pub const MAX_HEADER_LIST_SIZE: u16 = 0x6;

    pub fn name(id: u16) -> &'static str {
        match id {
            HEADER_TABLE_SIZE => "HEADER_TABLE_SIZE",
            ENABLE_PUSH => "ENABLE_PUSH",
            MAX_CONCURRENT_STREAMS => "MAX_CONCURRENT_STREAMS",
            INITIAL_WINDOW_SIZE => "INITIAL_WINDOW_SIZE",
            MAX_FRAME_SIZE => "MAX_FRAME_SIZE",
            MAX_HEADER_LIST_SIZE => "MAX_HEADER_LIST_SIZE",
            _ => "UNKNOWN",
        }
    }
}

/// HTTP/2 frame header (9 bytes)
#[derive(Debug, Clone)]
pub struct FrameHeader {
    pub length: u32,
    pub frame_type: FrameType,
    pub flags: u8,
    pub stream_id: u32,
}

impl FrameHeader {
    pub const SIZE: usize = 9;

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }

        let length =
            ((data[0] as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32);
        let frame_type = FrameType::from(data[3]);
        let flags = data[4];
        let stream_id = ((data[5] as u32 & 0x7F) << 24)
            | ((data[6] as u32) << 16)
            | ((data[7] as u32) << 8)
            | (data[8] as u32);

        Some(FrameHeader {
            length,
            frame_type,
            flags,
            stream_id,
        })
    }

    /// Check if END_STREAM flag is set
    pub fn is_end_stream(&self) -> bool {
        self.flags & flags::END_STREAM != 0
    }

    /// Check if END_HEADERS flag is set
    pub fn is_end_headers(&self) -> bool {
        self.flags & flags::END_HEADERS != 0
    }

    /// Check if PADDED flag is set
    pub fn is_padded(&self) -> bool {
        self.flags & flags::PADDED != 0
    }

    /// Check if PRIORITY flag is set
    pub fn is_priority(&self) -> bool {
        self.flags & flags::PRIORITY != 0
    }

    /// Check if ACK flag is set
    pub fn is_ack(&self) -> bool {
        self.flags & flags::ACK != 0
    }
}

/// Priority data for HEADERS and PRIORITY frames
#[derive(Debug, Clone)]
pub struct PriorityData {
    pub exclusive: bool,
    pub stream_dependency: u32,
    pub weight: u8,
}

/// HTTP/2 stream state (RFC 7540 Section 5.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

impl StreamState {
    pub fn as_str(&self) -> &'static str {
        match self {
            StreamState::Idle => "idle",
            StreamState::Open => "open",
            StreamState::HalfClosedLocal => "half-closed (local)",
            StreamState::HalfClosedRemote => "half-closed (remote)",
            StreamState::Closed => "closed",
        }
    }
}

/// HTTP/2 stream tracking
#[derive(Debug, Clone)]
pub struct Http2Stream {
    pub stream_id: u32,
    pub state: StreamState,

    // Request info
    pub method: Option<String>,
    pub path: Option<String>,
    pub authority: Option<String>,
    pub scheme: Option<String>,
    pub request_headers: Vec<(String, String)>,
    pub request_body_len: usize,

    // Response info
    pub status: Option<u16>,
    pub response_headers: Vec<(String, String)>,
    pub response_body_len: usize,

    // Frame tracking
    pub request_frame: Option<u64>,
    pub response_frame: Option<u64>,
}

impl Http2Stream {
    pub fn new(stream_id: u32) -> Self {
        Self {
            stream_id,
            state: StreamState::Idle,
            method: None,
            path: None,
            authority: None,
            scheme: None,
            request_headers: Vec::new(),
            request_body_len: 0,
            status: None,
            response_headers: Vec::new(),
            response_body_len: 0,
            request_frame: None,
            response_frame: None,
        }
    }

    /// Extract common header value
    pub fn get_header(&self, name: &str) -> Option<&str> {
        // Check request headers first, then response
        for (n, v) in &self.request_headers {
            if n.eq_ignore_ascii_case(name) {
                return Some(v);
            }
        }
        for (n, v) in &self.response_headers {
            if n.eq_ignore_ascii_case(name) {
                return Some(v);
            }
        }
        None
    }
}

/// Per-connection HTTP/2 state
struct Http2ConnectionState {
    /// HPACK decoder (direction-aware)
    client_decoder: HpackDecoder<'static>,
    server_decoder: HpackDecoder<'static>,

    /// Streams indexed by stream_id
    streams: HashMap<u32, Http2Stream>,

    /// Continuation state: (stream_id, accumulated header block, direction)
    continuation: Option<(u32, Vec<u8>, Direction)>,

    /// Buffer for incomplete frames
    buffer: BytesMut,

    /// Whether we've seen the client preface
    client_preface_seen: bool,

    /// Whether we've seen the server preface (SETTINGS frame)
    server_preface_seen: bool,
}

impl Http2ConnectionState {
    fn new() -> Self {
        Self {
            client_decoder: HpackDecoder::new(),
            server_decoder: HpackDecoder::new(),
            streams: HashMap::new(),
            continuation: None,
            buffer: BytesMut::new(),
            client_preface_seen: false,
            server_preface_seen: false,
        }
    }

    fn get_decoder(&mut self, direction: Direction) -> &mut HpackDecoder<'static> {
        match direction {
            Direction::ToServer => &mut self.client_decoder,
            Direction::ToClient => &mut self.server_decoder,
        }
    }
}

/// HTTP/2 stream parser
pub struct Http2StreamParser {
    /// Per-connection state
    connections: Arc<Mutex<HashMap<u64, Http2ConnectionState>>>,
}

impl Http2StreamParser {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Remove state for a closed connection
    pub fn remove_connection(&self, connection_id: u64) {
        let mut connections = self.connections.lock().unwrap();
        connections.remove(&connection_id);
    }

    /// Parse a single frame and return fields
    fn parse_frame(
        state: &mut Http2ConnectionState,
        header: &FrameHeader,
        payload: &[u8],
        direction: Direction,
        frame_number: u64,
    ) -> HashMap<String, OwnedFieldValue> {
        let mut fields = HashMap::new();

        fields.insert(
            "frame_type".to_string(),
            FieldValue::Str(header.frame_type.as_str()),
        );
        fields.insert(
            "stream_id".to_string(),
            FieldValue::UInt32(header.stream_id),
        );
        fields.insert("flags".to_string(), FieldValue::UInt8(header.flags));
        fields.insert(
            "length".to_string(),
            FieldValue::UInt32(header.length),
        );

        match header.frame_type {
            FrameType::Data => {
                Self::parse_data_frame(state, header, payload, direction, frame_number, &mut fields);
            }
            FrameType::Headers => {
                Self::parse_headers_frame(state, header, payload, direction, frame_number, &mut fields);
            }
            FrameType::Priority => {
                Self::parse_priority_frame(payload, &mut fields);
            }
            FrameType::RstStream => {
                Self::parse_rst_stream_frame(state, header, payload, &mut fields);
            }
            FrameType::Settings => {
                Self::parse_settings_frame(header, payload, &mut fields);
            }
            FrameType::PushPromise => {
                Self::parse_push_promise_frame(state, header, payload, direction, &mut fields);
            }
            FrameType::Ping => {
                Self::parse_ping_frame(header, payload, &mut fields);
            }
            FrameType::GoAway => {
                Self::parse_goaway_frame(payload, &mut fields);
            }
            FrameType::WindowUpdate => {
                Self::parse_window_update_frame(payload, &mut fields);
            }
            FrameType::Continuation => {
                Self::parse_continuation_frame(state, header, payload, direction, &mut fields);
            }
            FrameType::Unknown(t) => {
                fields.insert(
                    "unknown_type".to_string(),
                    FieldValue::UInt8(t),
                );
            }
        }

        // Add stream state if available
        if header.stream_id != 0 {
            if let Some(stream) = state.streams.get(&header.stream_id) {
                fields.insert(
                    "stream_state".to_string(),
                    FieldValue::Str(stream.state.as_str()),
                );
            }
        }

        fields
    }

    fn parse_data_frame(
        state: &mut Http2ConnectionState,
        header: &FrameHeader,
        payload: &[u8],
        direction: Direction,
        frame_number: u64,
        fields: &mut HashMap<String, OwnedFieldValue>,
    ) {
        let (data, pad_len) = if header.is_padded() && !payload.is_empty() {
            let pad_len = payload[0] as usize;
            if pad_len < payload.len() {
                (&payload[1..payload.len() - pad_len], pad_len)
            } else {
                (&payload[1..], 0)
            }
        } else {
            (payload, 0)
        };

        fields.insert(
            "data_length".to_string(),
            FieldValue::UInt64(data.len() as u64),
        );
        if pad_len > 0 {
            fields.insert(
                "padding_length".to_string(),
                FieldValue::UInt8(pad_len as u8),
            );
        }
        fields.insert(
            "end_stream".to_string(),
            FieldValue::Bool(header.is_end_stream()),
        );

        // Update stream state
        let stream = state
            .streams
            .entry(header.stream_id)
            .or_insert_with(|| Http2Stream::new(header.stream_id));

        match direction {
            Direction::ToServer => {
                stream.request_body_len += data.len();
            }
            Direction::ToClient => {
                stream.response_body_len += data.len();
            }
        }

        if header.is_end_stream() {
            stream.state = match stream.state {
                StreamState::Open => StreamState::HalfClosedRemote,
                StreamState::HalfClosedLocal => StreamState::Closed,
                _ => StreamState::Closed,
            };
        }
    }

    fn parse_headers_frame(
        state: &mut Http2ConnectionState,
        header: &FrameHeader,
        payload: &[u8],
        direction: Direction,
        frame_number: u64,
        fields: &mut HashMap<String, OwnedFieldValue>,
    ) {
        let mut offset = 0;
        let mut pad_len = 0;

        if header.is_padded() && !payload.is_empty() {
            pad_len = payload[0] as usize;
            offset += 1;
        }

        // Parse priority if present
        if header.is_priority() && payload.len() >= offset + 5 {
            let dep_bytes = &payload[offset..offset + 4];
            let dep = u32::from_be_bytes([
                dep_bytes[0] & 0x7F,
                dep_bytes[1],
                dep_bytes[2],
                dep_bytes[3],
            ]);
            let exclusive = dep_bytes[0] & 0x80 != 0;
            let weight = payload[offset + 4];
            offset += 5;

            fields.insert(
                "priority_exclusive".to_string(),
                FieldValue::Bool(exclusive),
            );
            fields.insert(
                "priority_dependency".to_string(),
                FieldValue::UInt32(dep),
            );
            fields.insert(
                "priority_weight".to_string(),
                FieldValue::UInt8(weight),
            );
        }

        let header_block_end = payload.len().saturating_sub(pad_len);
        let header_block = &payload[offset.min(header_block_end)..header_block_end];

        fields.insert(
            "end_stream".to_string(),
            FieldValue::Bool(header.is_end_stream()),
        );
        fields.insert(
            "end_headers".to_string(),
            FieldValue::Bool(header.is_end_headers()),
        );

        // Decode headers first if complete
        let decoded_headers = if header.is_end_headers() {
            let decoder = state.get_decoder(direction);
            decoder.decode(header_block).ok()
        } else {
            // Start continuation
            state.continuation = Some((header.stream_id, header_block.to_vec(), direction));
            None
        };

        // Now get or create stream
        let stream = state
            .streams
            .entry(header.stream_id)
            .or_insert_with(|| Http2Stream::new(header.stream_id));

        if stream.state == StreamState::Idle {
            stream.state = StreamState::Open;
            stream.request_frame = Some(frame_number);
        }

        // Process decoded headers if available
        if let Some(headers) = decoded_headers {
            Self::process_headers(stream, &headers, direction, frame_number, fields);
        }

        if header.is_end_stream() {
            stream.state = match stream.state {
                StreamState::Open => StreamState::HalfClosedRemote,
                StreamState::HalfClosedLocal => StreamState::Closed,
                _ => StreamState::Closed,
            };
        }
    }

    fn process_headers(
        stream: &mut Http2Stream,
        headers: &[(Vec<u8>, Vec<u8>)],
        direction: Direction,
        frame_number: u64,
        fields: &mut HashMap<String, OwnedFieldValue>,
    ) {
        let mut header_strs = Vec::new();

        for (name, value) in headers {
            let name_str = String::from_utf8_lossy(name).to_string();
            let value_str = String::from_utf8_lossy(value).to_string();

            // Extract pseudo-headers
            match name_str.as_str() {
                ":method" => {
                    stream.method = Some(value_str.clone());
                    fields.insert(
                        "method".to_string(),
                        FieldValue::OwnedString(CompactString::new(&value_str)),
                    );
                }
                ":path" => {
                    stream.path = Some(value_str.clone());
                    fields.insert(
                        "path".to_string(),
                        FieldValue::OwnedString(CompactString::new(&value_str)),
                    );
                }
                ":authority" => {
                    stream.authority = Some(value_str.clone());
                    fields.insert(
                        "authority".to_string(),
                        FieldValue::OwnedString(CompactString::new(&value_str)),
                    );
                }
                ":scheme" => {
                    stream.scheme = Some(value_str.clone());
                    fields.insert(
                        "scheme".to_string(),
                        FieldValue::OwnedString(CompactString::new(&value_str)),
                    );
                }
                ":status" => {
                    if let Ok(status) = value_str.parse::<u16>() {
                        stream.status = Some(status);
                        stream.response_frame = Some(frame_number);
                        fields.insert("status".to_string(), FieldValue::UInt16(status));
                    }
                }
                "content-type" => {
                    fields.insert(
                        "content_type".to_string(),
                        FieldValue::OwnedString(CompactString::new(&value_str)),
                    );
                }
                "content-length" => {
                    if let Ok(len) = value_str.parse::<u64>() {
                        fields.insert("content_length".to_string(), FieldValue::UInt64(len));
                    }
                }
                "user-agent" => {
                    fields.insert(
                        "user_agent".to_string(),
                        FieldValue::OwnedString(CompactString::new(&value_str)),
                    );
                }
                _ => {}
            }

            // Store in appropriate list
            if direction == Direction::ToServer || stream.status.is_none() {
                stream.request_headers.push((name_str.clone(), value_str.clone()));
            } else {
                stream.response_headers.push((name_str.clone(), value_str.clone()));
            }

            header_strs.push(format!("{}: {}", name_str, value_str));
        }

        // Store all headers as a semicolon-separated string
        if !header_strs.is_empty() {
            let headers_str = header_strs.join("; ");
            if direction == Direction::ToServer || stream.status.is_none() {
                fields.insert(
                    "request_headers".to_string(),
                    FieldValue::OwnedString(CompactString::new(&headers_str)),
                );
            } else {
                fields.insert(
                    "response_headers".to_string(),
                    FieldValue::OwnedString(CompactString::new(&headers_str)),
                );
            }
        }
    }

    fn parse_priority_frame(payload: &[u8], fields: &mut HashMap<String, OwnedFieldValue>) {
        if payload.len() >= 5 {
            let dep = u32::from_be_bytes([
                payload[0] & 0x7F,
                payload[1],
                payload[2],
                payload[3],
            ]);
            let exclusive = payload[0] & 0x80 != 0;
            let weight = payload[4];

            fields.insert(
                "priority_exclusive".to_string(),
                FieldValue::Bool(exclusive),
            );
            fields.insert(
                "priority_dependency".to_string(),
                FieldValue::UInt32(dep),
            );
            fields.insert(
                "priority_weight".to_string(),
                FieldValue::UInt8(weight),
            );
        }
    }

    fn parse_rst_stream_frame(
        state: &mut Http2ConnectionState,
        header: &FrameHeader,
        payload: &[u8],
        fields: &mut HashMap<String, OwnedFieldValue>,
    ) {
        if payload.len() >= 4 {
            let error_code = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
            fields.insert("error_code".to_string(), FieldValue::UInt32(error_code));
            fields.insert(
                "error_name".to_string(),
                FieldValue::Str(error_codes::name(error_code)),
            );
        }

        // Update stream state
        if let Some(stream) = state.streams.get_mut(&header.stream_id) {
            stream.state = StreamState::Closed;
        }
    }

    fn parse_settings_frame(
        header: &FrameHeader,
        payload: &[u8],
        fields: &mut HashMap<String, OwnedFieldValue>,
    ) {
        fields.insert("ack".to_string(), FieldValue::Bool(header.is_ack()));

        if !header.is_ack() {
            let mut settings_strs = Vec::new();
            let mut pos = 0;
            while pos + 6 <= payload.len() {
                let id = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
                let value = u32::from_be_bytes([
                    payload[pos + 2],
                    payload[pos + 3],
                    payload[pos + 4],
                    payload[pos + 5],
                ]);
                pos += 6;

                settings_strs.push(format!("{}={}", settings::name(id), value));

                // Store specific settings as individual fields
                match id {
                    settings::HEADER_TABLE_SIZE => {
                        fields.insert(
                            "header_table_size".to_string(),
                            FieldValue::UInt32(value),
                        );
                    }
                    settings::MAX_CONCURRENT_STREAMS => {
                        fields.insert(
                            "max_concurrent_streams".to_string(),
                            FieldValue::UInt32(value),
                        );
                    }
                    settings::INITIAL_WINDOW_SIZE => {
                        fields.insert(
                            "initial_window_size".to_string(),
                            FieldValue::UInt32(value),
                        );
                    }
                    settings::MAX_FRAME_SIZE => {
                        fields.insert("max_frame_size".to_string(), FieldValue::UInt32(value));
                    }
                    _ => {}
                }
            }

            if !settings_strs.is_empty() {
                fields.insert(
                    "settings".to_string(),
                    FieldValue::OwnedString(CompactString::new(&settings_strs.join(", "))),
                );
            }
        }
    }

    fn parse_push_promise_frame(
        state: &mut Http2ConnectionState,
        header: &FrameHeader,
        payload: &[u8],
        direction: Direction,
        fields: &mut HashMap<String, OwnedFieldValue>,
    ) {
        let mut offset = 0;
        let mut pad_len = 0;

        if header.is_padded() && !payload.is_empty() {
            pad_len = payload[0] as usize;
            offset += 1;
        }

        if payload.len() >= offset + 4 {
            let promised_stream_id = u32::from_be_bytes([
                payload[offset] & 0x7F,
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3],
            ]);
            offset += 4;

            fields.insert(
                "promised_stream_id".to_string(),
                FieldValue::UInt32(promised_stream_id),
            );

            let header_block_end = payload.len().saturating_sub(pad_len);
            let header_block = &payload[offset.min(header_block_end)..header_block_end];

            if header.is_end_headers() {
                let decoder = state.get_decoder(direction);
                if let Ok(headers) = decoder.decode(header_block) {
                    let stream = state
                        .streams
                        .entry(promised_stream_id)
                        .or_insert_with(|| Http2Stream::new(promised_stream_id));
                    Self::process_headers(stream, &headers, direction, 0, fields);
                }
            }
        }
    }

    fn parse_ping_frame(
        header: &FrameHeader,
        payload: &[u8],
        fields: &mut HashMap<String, OwnedFieldValue>,
    ) {
        fields.insert("ack".to_string(), FieldValue::Bool(header.is_ack()));

        if payload.len() >= 8 {
            let mut data = [0u8; 8];
            data.copy_from_slice(&payload[..8]);
            fields.insert("ping_data".to_string(), FieldValue::OwnedBytes(data.to_vec()));
        }
    }

    fn parse_goaway_frame(payload: &[u8], fields: &mut HashMap<String, OwnedFieldValue>) {
        if payload.len() >= 8 {
            let last_stream_id = u32::from_be_bytes([
                payload[0] & 0x7F,
                payload[1],
                payload[2],
                payload[3],
            ]);
            let error_code =
                u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);

            fields.insert(
                "last_stream_id".to_string(),
                FieldValue::UInt32(last_stream_id),
            );
            fields.insert("error_code".to_string(), FieldValue::UInt32(error_code));
            fields.insert(
                "error_name".to_string(),
                FieldValue::Str(error_codes::name(error_code)),
            );

            if payload.len() > 8 {
                let debug_data = String::from_utf8_lossy(&payload[8..]).to_string();
                fields.insert(
                    "debug_data".to_string(),
                    FieldValue::OwnedString(CompactString::new(&debug_data)),
                );
            }
        }
    }

    fn parse_window_update_frame(payload: &[u8], fields: &mut HashMap<String, OwnedFieldValue>) {
        if payload.len() >= 4 {
            let increment =
                u32::from_be_bytes([payload[0] & 0x7F, payload[1], payload[2], payload[3]]);
            fields.insert(
                "window_increment".to_string(),
                FieldValue::UInt32(increment),
            );
        }
    }

    fn parse_continuation_frame(
        state: &mut Http2ConnectionState,
        header: &FrameHeader,
        payload: &[u8],
        direction: Direction,
        fields: &mut HashMap<String, OwnedFieldValue>,
    ) {
        fields.insert(
            "end_headers".to_string(),
            FieldValue::Bool(header.is_end_headers()),
        );

        // Accumulate header block
        if let Some((stream_id, ref mut block, saved_dir)) = state.continuation.take() {
            if stream_id == header.stream_id && saved_dir == direction {
                block.extend_from_slice(payload);

                if header.is_end_headers() {
                    // Decode complete header block
                    let decoder = state.get_decoder(direction);
                    if let Ok(headers) = decoder.decode(block) {
                        let stream = state
                            .streams
                            .entry(header.stream_id)
                            .or_insert_with(|| Http2Stream::new(header.stream_id));
                        Self::process_headers(stream, &headers, direction, 0, fields);
                    }
                } else {
                    // More continuation frames expected
                    state.continuation = Some((stream_id, block.clone(), saved_dir));
                }
            }
        }
    }
}

impl Default for Http2StreamParser {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamParser for Http2StreamParser {
    fn name(&self) -> &'static str {
        "http2"
    }

    fn display_name(&self) -> &'static str {
        "HTTP/2"
    }

    fn can_parse_stream(&self, context: &StreamContext) -> bool {
        // HTTP/2 is typically used with ALPN "h2" or on decrypted TLS streams
        if let Some(ref alpn) = context.alpn {
            return alpn == "h2" || alpn == "h2c";
        }
        false
    }

    fn parse_stream(&self, data: &[u8], context: &StreamContext) -> StreamParseResult {
        let mut connections = self.connections.lock().unwrap();
        let state = connections
            .entry(context.connection_id)
            .or_insert_with(Http2ConnectionState::new);

        // Track buffer size before adding new data
        let buffer_len_before = state.buffer.len();

        // Append new data to buffer
        state.buffer.extend_from_slice(data);

        // Check for connection preface (client side)
        if context.direction == Direction::ToServer && !state.client_preface_seen {
            if state.buffer.len() >= CONNECTION_PREFACE.len() {
                if &state.buffer[..CONNECTION_PREFACE.len()] == CONNECTION_PREFACE {
                    state.buffer.advance(CONNECTION_PREFACE.len());
                    state.client_preface_seen = true;
                } else {
                    // Not HTTP/2
                    return StreamParseResult::NotThisProtocol;
                }
            } else {
                // Need more data
                return StreamParseResult::NeedMore {
                    minimum_bytes: Some(CONNECTION_PREFACE.len()),
                };
            }
        }

        let mut messages = Vec::new();
        // Calculate bytes consumed: (old buffer + new data) - remaining buffer
        // This is computed at the end after processing frames
        let total_input = buffer_len_before + data.len();

        // Parse complete frames
        loop {
            if state.buffer.len() < FrameHeader::SIZE {
                break; // Need more data for header
            }

            let header = FrameHeader::parse(&state.buffer).unwrap();
            let total_frame_len = FrameHeader::SIZE + header.length as usize;

            if state.buffer.len() < total_frame_len {
                break; // Need more data for payload
            }

            let payload = state.buffer[FrameHeader::SIZE..total_frame_len].to_vec();
            state.buffer.advance(total_frame_len);

            // Track server preface (first SETTINGS frame from server)
            if context.direction == Direction::ToClient
                && !state.server_preface_seen
                && header.frame_type == FrameType::Settings
            {
                state.server_preface_seen = true;
            }

            // Parse the frame
            let fields = Self::parse_frame(state, &header, &payload, context.direction, 0);

            let message = ParsedMessage {
                protocol: "http2",
                connection_id: context.connection_id,
                message_id: context.messages_parsed as u32 + messages.len() as u32,
                direction: context.direction,
                frame_number: 0, // Will be set by manager
                fields,
            };
            messages.push(message);
        }

        // Calculate total bytes consumed: (old buffer + new data) - remaining buffer
        let total_consumed = total_input - state.buffer.len();

        if !messages.is_empty() {
            StreamParseResult::Complete {
                messages,
                bytes_consumed: total_consumed,
            }
        } else if total_consumed == 0 {
            StreamParseResult::NeedMore {
                minimum_bytes: Some(FrameHeader::SIZE),
            }
        } else {
            StreamParseResult::Complete {
                messages: vec![],
                bytes_consumed: total_consumed,
            }
        }
    }

    fn message_schema(&self) -> Vec<FieldDescriptor> {
        vec![
            // Frame info
            FieldDescriptor::new("connection_id", DataKind::UInt64),
            FieldDescriptor::new("frame_type", DataKind::String),
            FieldDescriptor::new("stream_id", DataKind::UInt32),
            FieldDescriptor::new("flags", DataKind::UInt8),
            FieldDescriptor::new("length", DataKind::UInt32),
            // Request
            FieldDescriptor::new("method", DataKind::String).set_nullable(true),
            FieldDescriptor::new("path", DataKind::String).set_nullable(true),
            FieldDescriptor::new("authority", DataKind::String).set_nullable(true),
            FieldDescriptor::new("scheme", DataKind::String).set_nullable(true),
            // Response
            FieldDescriptor::new("status", DataKind::UInt16).set_nullable(true),
            // Headers
            FieldDescriptor::new("request_headers", DataKind::String).set_nullable(true),
            FieldDescriptor::new("response_headers", DataKind::String).set_nullable(true),
            // Common headers
            FieldDescriptor::new("content_type", DataKind::String).set_nullable(true),
            FieldDescriptor::new("content_length", DataKind::UInt64).set_nullable(true),
            FieldDescriptor::new("user_agent", DataKind::String).set_nullable(true),
            // Data frame
            FieldDescriptor::new("data_length", DataKind::UInt64).set_nullable(true),
            FieldDescriptor::new("end_stream", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("end_headers", DataKind::Bool).set_nullable(true),
            // Settings
            FieldDescriptor::new("settings", DataKind::String).set_nullable(true),
            FieldDescriptor::new("ack", DataKind::Bool).set_nullable(true),
            // Error handling
            FieldDescriptor::new("error_code", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("error_name", DataKind::String).set_nullable(true),
            // GoAway
            FieldDescriptor::new("last_stream_id", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("debug_data", DataKind::String).set_nullable(true),
            // Window update
            FieldDescriptor::new("window_increment", DataKind::UInt32).set_nullable(true),
            // Priority
            FieldDescriptor::new("priority_exclusive", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("priority_dependency", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("priority_weight", DataKind::UInt8).set_nullable(true),
            // Push promise
            FieldDescriptor::new("promised_stream_id", DataKind::UInt32).set_nullable(true),
            // Stream state
            FieldDescriptor::new("stream_state", DataKind::String).set_nullable(true),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_context() -> StreamContext {
        StreamContext {
            connection_id: 1,
            direction: Direction::ToServer,
            src_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            src_port: 54321,
            dst_port: 443,
            bytes_parsed: 0,
            messages_parsed: 0,
            alpn: Some("h2".to_string()),
        }
    }

    #[test]
    fn test_frame_type_from_u8() {
        assert_eq!(FrameType::from(0x0), FrameType::Data);
        assert_eq!(FrameType::from(0x1), FrameType::Headers);
        assert_eq!(FrameType::from(0x4), FrameType::Settings);
        assert_eq!(FrameType::from(0x7), FrameType::GoAway);
        assert!(matches!(FrameType::from(0xFF), FrameType::Unknown(0xFF)));
    }

    #[test]
    fn test_frame_type_as_str() {
        assert_eq!(FrameType::Data.as_str(), "DATA");
        assert_eq!(FrameType::Headers.as_str(), "HEADERS");
        assert_eq!(FrameType::Settings.as_str(), "SETTINGS");
        assert_eq!(FrameType::Unknown(99).as_str(), "UNKNOWN");
    }

    #[test]
    fn test_frame_header_parse() {
        // SETTINGS frame, length=6, no flags, stream 0
        let data = [0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
        let header = FrameHeader::parse(&data).unwrap();
        assert_eq!(header.length, 6);
        assert_eq!(header.frame_type, FrameType::Settings);
        assert_eq!(header.flags, 0);
        assert_eq!(header.stream_id, 0);
    }

    #[test]
    fn test_frame_header_parse_with_stream_id() {
        // DATA frame on stream 1
        let data = [0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01];
        let header = FrameHeader::parse(&data).unwrap();
        assert_eq!(header.length, 16);
        assert_eq!(header.frame_type, FrameType::Data);
        assert!(header.is_end_stream());
        assert_eq!(header.stream_id, 1);
    }

    #[test]
    fn test_frame_header_flags() {
        let mut data = [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01];

        // Test END_STREAM
        data[4] = flags::END_STREAM;
        let header = FrameHeader::parse(&data).unwrap();
        assert!(header.is_end_stream());
        assert!(!header.is_end_headers());

        // Test END_HEADERS
        data[4] = flags::END_HEADERS;
        let header = FrameHeader::parse(&data).unwrap();
        assert!(header.is_end_headers());
        assert!(!header.is_end_stream());

        // Test PADDED
        data[4] = flags::PADDED;
        let header = FrameHeader::parse(&data).unwrap();
        assert!(header.is_padded());

        // Test PRIORITY
        data[4] = flags::PRIORITY;
        let header = FrameHeader::parse(&data).unwrap();
        assert!(header.is_priority());
    }

    #[test]
    fn test_error_code_names() {
        assert_eq!(error_codes::name(error_codes::NO_ERROR), "NO_ERROR");
        assert_eq!(error_codes::name(error_codes::PROTOCOL_ERROR), "PROTOCOL_ERROR");
        assert_eq!(error_codes::name(error_codes::CANCEL), "CANCEL");
        assert_eq!(error_codes::name(0xFFFF), "UNKNOWN");
    }

    #[test]
    fn test_settings_names() {
        assert_eq!(settings::name(settings::HEADER_TABLE_SIZE), "HEADER_TABLE_SIZE");
        assert_eq!(settings::name(settings::MAX_FRAME_SIZE), "MAX_FRAME_SIZE");
        assert_eq!(settings::name(0xFFFF), "UNKNOWN");
    }

    #[test]
    fn test_http2_stream_state() {
        assert_eq!(StreamState::Idle.as_str(), "idle");
        assert_eq!(StreamState::Open.as_str(), "open");
        assert_eq!(StreamState::Closed.as_str(), "closed");
    }

    #[test]
    fn test_http2_stream_new() {
        let stream = Http2Stream::new(1);
        assert_eq!(stream.stream_id, 1);
        assert_eq!(stream.state, StreamState::Idle);
        assert!(stream.method.is_none());
        assert!(stream.status.is_none());
    }

    #[test]
    fn test_parser_can_parse_stream() {
        let parser = Http2StreamParser::new();

        // Should parse with h2 ALPN
        let mut ctx = test_context();
        ctx.alpn = Some("h2".to_string());
        assert!(parser.can_parse_stream(&ctx));

        // Should not parse without ALPN
        ctx.alpn = None;
        assert!(!parser.can_parse_stream(&ctx));

        // Should not parse with different ALPN
        ctx.alpn = Some("http/1.1".to_string());
        assert!(!parser.can_parse_stream(&ctx));
    }

    #[test]
    fn test_parse_connection_preface() {
        let ctx = test_context();

        // Test 1: Partial preface should need more data
        let parser1 = Http2StreamParser::new();
        let partial = &CONNECTION_PREFACE[..10];
        let result = parser1.parse_stream(partial, &ctx);
        assert!(matches!(result, StreamParseResult::NeedMore { .. }));

        // Test 2: Full preface followed by SETTINGS should parse (fresh parser)
        let parser2 = Http2StreamParser::new();
        let mut data = CONNECTION_PREFACE.to_vec();
        // SETTINGS frame, length=0, ACK flag
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00]);

        let result = parser2.parse_stream(&data, &ctx);
        match result {
            StreamParseResult::Complete { messages, .. } => {
                assert_eq!(messages.len(), 1);
                assert_eq!(
                    messages[0].fields.get("frame_type"),
                    Some(&FieldValue::Str("SETTINGS"))
                );
            }
            _ => panic!("Expected Complete, got {:?}", result),
        }
    }

    #[test]
    fn test_parse_settings_frame() {
        let parser = Http2StreamParser::new();
        let mut ctx = test_context();
        ctx.direction = Direction::ToClient; // Server sends first SETTINGS

        // SETTINGS frame with HEADER_TABLE_SIZE=4096, MAX_CONCURRENT_STREAMS=100
        let frame = [
            0x00, 0x00, 0x0c, // length = 12
            0x04, // type = SETTINGS
            0x00, // flags = 0
            0x00, 0x00, 0x00, 0x00, // stream_id = 0
            // HEADER_TABLE_SIZE = 4096
            0x00, 0x01, 0x00, 0x00, 0x10, 0x00,
            // MAX_CONCURRENT_STREAMS = 100
            0x00, 0x03, 0x00, 0x00, 0x00, 0x64,
        ];

        let result = parser.parse_stream(&frame, &ctx);
        match result {
            StreamParseResult::Complete { messages, .. } => {
                assert_eq!(messages.len(), 1);
                assert_eq!(
                    messages[0].fields.get("header_table_size"),
                    Some(&FieldValue::UInt32(4096))
                );
                assert_eq!(
                    messages[0].fields.get("max_concurrent_streams"),
                    Some(&FieldValue::UInt32(100))
                );
            }
            _ => panic!("Expected Complete"),
        }
    }

    #[test]
    fn test_parse_ping_frame() {
        let parser = Http2StreamParser::new();
        let mut ctx = test_context();
        ctx.direction = Direction::ToClient;

        // PING frame
        let frame = [
            0x00, 0x00, 0x08, // length = 8
            0x06, // type = PING
            0x00, // flags = 0
            0x00, 0x00, 0x00, 0x00, // stream_id = 0
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // opaque data
        ];

        let result = parser.parse_stream(&frame, &ctx);
        match result {
            StreamParseResult::Complete { messages, .. } => {
                assert_eq!(messages.len(), 1);
                assert_eq!(
                    messages[0].fields.get("frame_type"),
                    Some(&FieldValue::Str("PING"))
                );
                assert_eq!(messages[0].fields.get("ack"), Some(&FieldValue::Bool(false)));
            }
            _ => panic!("Expected Complete"),
        }
    }

    #[test]
    fn test_parse_window_update_frame() {
        let parser = Http2StreamParser::new();
        let mut ctx = test_context();
        ctx.direction = Direction::ToClient;

        // WINDOW_UPDATE frame, increment = 65535
        let frame = [
            0x00, 0x00, 0x04, // length = 4
            0x08, // type = WINDOW_UPDATE
            0x00, // flags = 0
            0x00, 0x00, 0x00, 0x00, // stream_id = 0
            0x00, 0x00, 0xff, 0xff, // increment = 65535
        ];

        let result = parser.parse_stream(&frame, &ctx);
        match result {
            StreamParseResult::Complete { messages, .. } => {
                assert_eq!(messages.len(), 1);
                assert_eq!(
                    messages[0].fields.get("window_increment"),
                    Some(&FieldValue::UInt32(65535))
                );
            }
            _ => panic!("Expected Complete"),
        }
    }

    #[test]
    fn test_parse_goaway_frame() {
        let parser = Http2StreamParser::new();
        let mut ctx = test_context();
        ctx.direction = Direction::ToClient;

        // GOAWAY frame, last_stream_id=1, error=NO_ERROR, debug="bye"
        let frame = [
            0x00, 0x00, 0x0b, // length = 11
            0x07, // type = GOAWAY
            0x00, // flags = 0
            0x00, 0x00, 0x00, 0x00, // stream_id = 0
            0x00, 0x00, 0x00, 0x01, // last_stream_id = 1
            0x00, 0x00, 0x00, 0x00, // error_code = NO_ERROR
            b'b', b'y', b'e', // debug data
        ];

        let result = parser.parse_stream(&frame, &ctx);
        match result {
            StreamParseResult::Complete { messages, .. } => {
                assert_eq!(messages.len(), 1);
                assert_eq!(
                    messages[0].fields.get("last_stream_id"),
                    Some(&FieldValue::UInt32(1))
                );
                assert_eq!(
                    messages[0].fields.get("error_name"),
                    Some(&FieldValue::Str("NO_ERROR"))
                );
            }
            _ => panic!("Expected Complete"),
        }
    }

    #[test]
    fn test_parse_data_frame() {
        let parser = Http2StreamParser::new();
        let mut ctx = test_context();
        ctx.direction = Direction::ToClient;

        // DATA frame on stream 1, END_STREAM
        let mut frame = vec![
            0x00, 0x00, 0x05, // length = 5
            0x00, // type = DATA
            0x01, // flags = END_STREAM
            0x00, 0x00, 0x00, 0x01, // stream_id = 1
        ];
        frame.extend_from_slice(b"hello");

        let result = parser.parse_stream(&frame, &ctx);
        match result {
            StreamParseResult::Complete { messages, .. } => {
                assert_eq!(messages.len(), 1);
                assert_eq!(
                    messages[0].fields.get("data_length"),
                    Some(&FieldValue::UInt64(5))
                );
                assert_eq!(
                    messages[0].fields.get("end_stream"),
                    Some(&FieldValue::Bool(true))
                );
            }
            _ => panic!("Expected Complete"),
        }
    }

    #[test]
    fn test_parse_rst_stream_frame() {
        let parser = Http2StreamParser::new();
        let mut ctx = test_context();
        ctx.direction = Direction::ToClient;

        // RST_STREAM frame, stream 1, CANCEL error
        let frame = [
            0x00, 0x00, 0x04, // length = 4
            0x03, // type = RST_STREAM
            0x00, // flags = 0
            0x00, 0x00, 0x00, 0x01, // stream_id = 1
            0x00, 0x00, 0x00, 0x08, // error_code = CANCEL (8)
        ];

        let result = parser.parse_stream(&frame, &ctx);
        match result {
            StreamParseResult::Complete { messages, .. } => {
                assert_eq!(messages.len(), 1);
                assert_eq!(
                    messages[0].fields.get("error_code"),
                    Some(&FieldValue::UInt32(8))
                );
                assert_eq!(
                    messages[0].fields.get("error_name"),
                    Some(&FieldValue::Str("CANCEL"))
                );
            }
            _ => panic!("Expected Complete"),
        }
    }

    #[test]
    fn test_incomplete_frame_needs_more() {
        let parser = Http2StreamParser::new();
        let mut ctx = test_context();
        ctx.direction = Direction::ToClient;

        // Only partial frame header
        let partial = [0x00, 0x00, 0x10, 0x00];
        let result = parser.parse_stream(&partial, &ctx);
        assert!(matches!(result, StreamParseResult::NeedMore { .. }));
    }

    #[test]
    fn test_multiple_frames() {
        let parser = Http2StreamParser::new();
        let mut ctx = test_context();
        ctx.direction = Direction::ToClient;

        // Two frames: SETTINGS ACK + PING
        let mut data = vec![
            // SETTINGS ACK
            0x00, 0x00, 0x00, // length = 0
            0x04, // type = SETTINGS
            0x01, // flags = ACK
            0x00, 0x00, 0x00, 0x00, // stream_id = 0
            // PING
            0x00, 0x00, 0x08, // length = 8
            0x06, // type = PING
            0x00, // flags = 0
            0x00, 0x00, 0x00, 0x00, // stream_id = 0
        ];
        data.extend_from_slice(&[0u8; 8]); // PING data

        let result = parser.parse_stream(&data, &ctx);
        match result {
            StreamParseResult::Complete { messages, .. } => {
                assert_eq!(messages.len(), 2);
                assert_eq!(
                    messages[0].fields.get("frame_type"),
                    Some(&FieldValue::Str("SETTINGS"))
                );
                assert_eq!(
                    messages[1].fields.get("frame_type"),
                    Some(&FieldValue::Str("PING"))
                );
            }
            _ => panic!("Expected Complete"),
        }
    }
}
