//! Parse context and result types.

use std::collections::HashMap;

use super::FieldValue;

/// Context passed through the parsing chain.
#[derive(Debug, Clone)]
pub struct ParseContext {
    /// Link type from PCAP header (e.g., 1 = Ethernet).
    pub link_type: u16,

    /// Parent protocol that identified this protocol.
    pub parent_protocol: Option<&'static str>,

    /// Protocol-specific hints (e.g., ethertype, IP protocol number).
    pub hints: HashMap<&'static str, u64>,

    /// Offset into the original packet where this protocol's data starts.
    pub offset: usize,
}

impl ParseContext {
    /// Create a new parse context for a packet with the given link type.
    pub fn new(link_type: u16) -> Self {
        Self {
            link_type,
            parent_protocol: None,
            hints: HashMap::new(),
            offset: 0,
        }
    }

    /// Get a hint value by key.
    pub fn hint(&self, key: &str) -> Option<u64> {
        self.hints.get(key).copied()
    }

    /// Check if we're at the start of the packet (no parent protocol).
    pub fn is_root(&self) -> bool {
        self.parent_protocol.is_none()
    }
}

/// Result of parsing a protocol layer.
#[derive(Debug, Clone)]
pub struct ParseResult<'a> {
    /// Extracted field values, keyed by field name.
    pub fields: HashMap<&'static str, FieldValue>,

    /// Remaining unparsed bytes (payload for next layer).
    pub remaining: &'a [u8],

    /// Hints for child protocol identification.
    pub child_hints: HashMap<&'static str, u64>,

    /// Parse error if partial parsing occurred.
    pub error: Option<String>,
}

impl<'a> ParseResult<'a> {
    /// Create a successful parse result.
    pub fn success(
        fields: HashMap<&'static str, FieldValue>,
        remaining: &'a [u8],
        child_hints: HashMap<&'static str, u64>,
    ) -> Self {
        Self {
            fields,
            remaining,
            child_hints,
            error: None,
        }
    }

    /// Create an error parse result.
    pub fn error(error: String, remaining: &'a [u8]) -> Self {
        Self {
            fields: HashMap::new(),
            remaining,
            child_hints: HashMap::new(),
            error: Some(error),
        }
    }

    /// Create a result with partial fields and an error.
    pub fn partial(
        fields: HashMap<&'static str, FieldValue>,
        remaining: &'a [u8],
        error: String,
    ) -> Self {
        Self {
            fields,
            remaining,
            child_hints: HashMap::new(),
            error: Some(error),
        }
    }

    /// Get a field value by name.
    pub fn get(&self, name: &str) -> Option<&FieldValue> {
        self.fields.get(name)
    }

    /// Check if parsing was successful.
    pub fn is_ok(&self) -> bool {
        self.error.is_none()
    }
}
