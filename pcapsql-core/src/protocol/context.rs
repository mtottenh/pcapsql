//! Parse context and result types.

use smallvec::SmallVec;

use super::FieldValue;

/// Field entry for parse results: (field_name, value).
/// Field names are always static strings (protocol-defined).
/// The lifetime parameter ties the value to the packet/buffer data.
pub type FieldEntry<'data> = (&'static str, FieldValue<'data>);

/// Hint entry for child protocol detection: (hint_name, value).
pub type HintEntry = (&'static str, u64);

/// Context passed through the parsing chain.
#[derive(Debug, Clone)]
pub struct ParseContext {
    /// Link type from PCAP header (e.g., 1 = Ethernet).
    pub link_type: u16,

    /// Parent protocol that identified this protocol.
    pub parent_protocol: Option<&'static str>,

    /// Protocol-specific hints (e.g., ethertype, IP protocol number).
    /// Uses SmallVec for consistency with ParseResult. Typically 2-4 entries.
    pub hints: SmallVec<[HintEntry; 4]>,

    /// Offset into the original packet where this protocol's data starts.
    pub offset: usize,
}

impl ParseContext {
    /// Create a new parse context for a packet with the given link type.
    pub fn new(link_type: u16) -> Self {
        Self {
            link_type,
            parent_protocol: None,
            hints: SmallVec::new(),
            offset: 0,
        }
    }

    /// Get a hint value by key (linear search, but N is small).
    #[inline]
    pub fn hint(&self, key: &str) -> Option<u64> {
        self.hints.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
    }

    /// Insert a hint value (appends, may create duplicates).
    /// Use `set_hint()` if you need to update an existing hint.
    #[inline]
    pub fn insert_hint(&mut self, key: &'static str, value: u64) {
        self.hints.push((key, value));
    }

    /// Set a hint value (updates existing or appends).
    #[inline]
    pub fn set_hint(&mut self, key: &'static str, value: u64) {
        if let Some(entry) = self.hints.iter_mut().find(|(k, _)| *k == key) {
            entry.1 = value;
        } else {
            self.hints.push((key, value));
        }
    }

    /// Clear all hints (for context reuse).
    #[inline]
    pub fn clear_hints(&mut self) {
        self.hints.clear();
    }

    /// Check if we're at the start of the packet (no parent protocol).
    pub fn is_root(&self) -> bool {
        self.parent_protocol.is_none()
    }
}

/// Result of parsing a protocol layer.
///
/// Uses SmallVec for inline storage to avoid HashMap allocation overhead.
/// Most protocols have <16 fields and <4 child hints, so these fit inline.
///
/// The lifetime parameter `'data` ties the result to the packet/buffer data,
/// allowing zero-copy parsing where field values reference the packet directly.
#[derive(Debug, Clone)]
pub struct ParseResult<'data> {
    /// Extracted field values. Most protocols have <16 fields.
    /// Field values may reference the packet data (zero-copy).
    pub fields: SmallVec<[FieldEntry<'data>; 16]>,

    /// Remaining unparsed bytes (payload for next layer).
    pub remaining: &'data [u8],

    /// Hints for child protocol identification. Typically 2-4 entries.
    pub child_hints: SmallVec<[HintEntry; 4]>,

    /// Parse error if partial parsing occurred.
    pub error: Option<String>,
}

impl<'data> ParseResult<'data> {
    /// Create a successful parse result.
    pub fn success(
        fields: SmallVec<[FieldEntry<'data>; 16]>,
        remaining: &'data [u8],
        child_hints: SmallVec<[HintEntry; 4]>,
    ) -> Self {
        Self {
            fields,
            remaining,
            child_hints,
            error: None,
        }
    }

    /// Create an error parse result.
    pub fn error(error: String, remaining: &'data [u8]) -> Self {
        Self {
            fields: SmallVec::new(),
            remaining,
            child_hints: SmallVec::new(),
            error: Some(error),
        }
    }

    /// Create a result with partial fields and an error.
    pub fn partial(
        fields: SmallVec<[FieldEntry<'data>; 16]>,
        remaining: &'data [u8],
        error: String,
    ) -> Self {
        Self {
            fields,
            remaining,
            child_hints: SmallVec::new(),
            error: Some(error),
        }
    }

    /// Get a field value by name (linear search, but N is small).
    pub fn get(&self, name: &str) -> Option<&FieldValue<'data>> {
        self.fields.iter().find(|(k, _)| *k == name).map(|(_, v)| v)
    }

    /// Get a child hint value by name.
    pub fn hint(&self, name: &str) -> Option<u64> {
        self.child_hints
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| *v)
    }

    /// Check if parsing was successful.
    pub fn is_ok(&self) -> bool {
        self.error.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_hint_access() {
        let mut ctx = ParseContext::new(1);
        ctx.insert_hint("ip_protocol", 6);
        ctx.insert_hint("dst_port", 80);

        assert_eq!(ctx.hint("ip_protocol"), Some(6));
        assert_eq!(ctx.hint("dst_port"), Some(80));
        assert_eq!(ctx.hint("nonexistent"), None);
    }

    #[test]
    fn test_context_set_hint_update() {
        let mut ctx = ParseContext::new(1);
        ctx.set_hint("ip_protocol", 6);
        ctx.set_hint("ip_protocol", 17); // Update existing

        assert_eq!(ctx.hint("ip_protocol"), Some(17));
        assert_eq!(ctx.hints.len(), 1); // No duplicates
    }

    #[test]
    fn test_context_set_hint_insert() {
        let mut ctx = ParseContext::new(1);
        ctx.set_hint("ip_protocol", 6);
        ctx.set_hint("dst_port", 80); // Insert new

        assert_eq!(ctx.hint("ip_protocol"), Some(6));
        assert_eq!(ctx.hint("dst_port"), Some(80));
        assert_eq!(ctx.hints.len(), 2);
    }

    #[test]
    fn test_context_clear_hints() {
        let mut ctx = ParseContext::new(1);
        ctx.insert_hint("ip_protocol", 6);
        ctx.insert_hint("dst_port", 80);

        ctx.clear_hints();

        assert_eq!(ctx.hints.len(), 0);
        assert_eq!(ctx.hint("ip_protocol"), None);
    }

    #[test]
    fn test_hint_count_stays_inline() {
        let mut ctx = ParseContext::new(1);
        ctx.insert_hint("ethertype", 0x0800);
        ctx.insert_hint("ip_protocol", 6);
        ctx.insert_hint("src_port", 12345);
        ctx.insert_hint("dst_port", 80);

        // Should stay inline (no heap allocation) with 4 entries
        assert!(!ctx.hints.spilled());
    }

    #[test]
    fn test_parse_result_success() {
        let mut fields = SmallVec::new();
        fields.push(("src_port", FieldValue::UInt16(80)));

        let mut hints = SmallVec::new();
        hints.push(("transport", 6u64));

        let result = ParseResult::success(fields, &[], hints);

        assert!(result.is_ok());
        assert_eq!(result.get("src_port"), Some(&FieldValue::UInt16(80)));
        assert_eq!(result.hint("transport"), Some(6));
    }

    #[test]
    fn test_parse_result_error() {
        let result = ParseResult::error("test error".to_string(), &[1, 2, 3]);

        assert!(!result.is_ok());
        assert_eq!(result.error, Some("test error".to_string()));
        assert_eq!(result.remaining, &[1, 2, 3]);
    }
}
