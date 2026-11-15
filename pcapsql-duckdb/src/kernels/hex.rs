//! Hex conversion, for `pcap_hex` and `pcap_unhex` (named so as not to shadow DuckDB's own
//! `hex` and `unhex`).

/// Lower-case hex digits of `bytes`.
pub fn encode(bytes: &[u8]) -> String {
    ::hex::encode(bytes)
}

/// Bytes of a hex string in either case; `None` for an odd length or a non-hex character.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    ::hex::decode(text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_encode() {
        assert_eq!(encode(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
        assert_eq!(encode(&[0x00, 0xFF]), "00ff");
        assert_eq!(encode(&[]), "");
    }

    #[test]
    fn test_hex_decode() {
        assert_eq!(decode("deadbeef").unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(decode("00FF").unwrap(), vec![0x00, 0xFF]);
        assert!(decode("invalid!").is_none());
        assert!(decode("abc").is_none());
    }
}
