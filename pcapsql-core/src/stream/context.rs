use std::collections::HashMap;
use std::net::IpAddr;

use crate::protocol::OwnedFieldValue;

/// Direction of data flow in a TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    ToServer,
    ToClient,
}

impl Direction {
    /// Return a string representation of the direction.
    pub fn as_str(&self) -> &'static str {
        match self {
            Direction::ToServer => "to_server",
            Direction::ToClient => "to_client",
        }
    }
}

/// Context for stream parsing.
#[derive(Debug, Clone)]
pub struct StreamContext {
    pub connection_id: u64,
    pub direction: Direction,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    /// Bytes already parsed from this stream
    pub bytes_parsed: usize,
    /// Messages already parsed from this stream
    pub messages_parsed: usize,
    /// ALPN protocol hint (from TLS handshake)
    pub alpn: Option<String>,
}

/// Result of stream parsing.
#[derive(Debug, Clone)]
pub enum StreamParseResult {
    /// Successfully parsed one or more messages.
    Complete {
        messages: Vec<ParsedMessage>,
        bytes_consumed: usize,
    },

    /// Parser produced a transformed stream for child parsing (e.g., TLS decryption).
    Transform {
        child_protocol: &'static str,
        child_data: Vec<u8>,
        bytes_consumed: usize,
        metadata: Option<ParsedMessage>,
    },

    /// Need more data before parsing can proceed.
    NeedMore { minimum_bytes: Option<usize> },

    /// This stream doesn't match our protocol.
    NotThisProtocol,

    /// Parse error - stream is malformed.
    Error {
        message: String,
        skip_bytes: Option<usize>,
    },
}

/// A parsed application-layer message.
///
/// All field values are owned since stream parsing may outlive the original packet data.
/// Field names are always static strings from protocol definitions.
#[derive(Debug, Clone)]
pub struct ParsedMessage {
    pub protocol: &'static str,
    pub connection_id: u64,
    pub message_id: u32,
    pub direction: Direction,
    pub frame_number: u64,
    pub fields: HashMap<&'static str, OwnedFieldValue>,
}
