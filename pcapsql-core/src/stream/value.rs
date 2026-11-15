//! The value of a field of a reassembled message.
//!
//! A packet's field values ([`FieldValue`](crate::protocol::FieldValue))
//! borrow the packet and the arena it was parsed into, and are gone with the
//! next packet. A message of a stream is assembled from many packets and
//! kept until its table is built, so its values own what they hold.

use compact_str::CompactString;

/// A field value that outlives the packets it was parsed from: what
/// [`ParsedMessage::fields`](super::ParsedMessage::fields) holds.
#[derive(Debug, Clone)]
pub enum OwnedFieldValue {
    /// Unsigned 8-bit integer
    UInt8(u8),
    /// Unsigned 16-bit integer
    UInt16(u16),
    /// Unsigned 32-bit integer
    UInt32(u32),
    /// Unsigned 64-bit integer
    UInt64(u64),
    /// Boolean value
    Bool(bool),
    /// A static string (a method's or a version's name).
    Str(&'static str),
    /// A string taken from the stream. Inline up to 24 bytes.
    OwnedString(CompactString),
    /// Bytes taken from the stream.
    OwnedBytes(Vec<u8>),
}

impl OwnedFieldValue {
    /// The value as a string, when it is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            OwnedFieldValue::Str(s) => Some(s),
            OwnedFieldValue::OwnedString(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

// Not derived: a static string and a copied one with the same text are the
// same value.
impl PartialEq for OwnedFieldValue {
    fn eq(&self, other: &Self) -> bool {
        use OwnedFieldValue as V;
        match (self, other) {
            (V::UInt8(a), V::UInt8(b)) => a == b,
            (V::UInt16(a), V::UInt16(b)) => a == b,
            (V::UInt32(a), V::UInt32(b)) => a == b,
            (V::UInt64(a), V::UInt64(b)) => a == b,
            (V::Bool(a), V::Bool(b)) => a == b,
            (V::Str(_) | V::OwnedString(_), V::Str(_) | V::OwnedString(_)) => {
                self.as_str() == other.as_str()
            }
            (V::OwnedBytes(a), V::OwnedBytes(b)) => a == b,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_and_copied_strings_compare_by_text() {
        let copied = OwnedFieldValue::OwnedString(CompactString::new("GET"));
        assert_eq!(OwnedFieldValue::Str("GET"), copied);
        assert_eq!(copied, OwnedFieldValue::Str("GET"));
        assert_ne!(copied, OwnedFieldValue::Str("PUT"));
        assert_eq!(copied.as_str(), Some("GET"));
        assert_eq!(OwnedFieldValue::UInt16(80).as_str(), None);
        assert_ne!(OwnedFieldValue::UInt16(80), OwnedFieldValue::UInt32(80));
        assert_eq!(
            OwnedFieldValue::OwnedBytes(vec![1, 2]),
            OwnedFieldValue::OwnedBytes(vec![1, 2])
        );
    }
}
