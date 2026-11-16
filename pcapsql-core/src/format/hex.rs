//! Hexadecimal encoding and decoding of byte strings.

use std::fmt;

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Write bytes as lowercase hexadecimal, two digits per byte and no
/// separator. Writes nothing for an empty slice.
///
/// # Example
///
/// ```
/// use pcapsql_core::format::write_hex;
///
/// let mut s = String::new();
/// write_hex(&[0xde, 0xad, 0xbe, 0xef], &mut s).unwrap();
/// assert_eq!(s, "deadbeef");
/// ```
pub fn write_hex(bytes: &[u8], out: &mut impl fmt::Write) -> fmt::Result {
    // In blocks, so the sink sees a few `write_str` calls and not one per byte.
    let mut buf = [0u8; 128];
    for chunk in bytes.chunks(buf.len() / 2) {
        for (pair, &b) in buf.chunks_exact_mut(2).zip(chunk) {
            pair[0] = HEX_DIGITS[usize::from(b >> 4)];
            pair[1] = HEX_DIGITS[usize::from(b & 0x0f)];
        }
        let text = &buf[..chunk.len() * 2];
        // Every byte written is an ASCII hex digit.
        out.write_str(std::str::from_utf8(text).map_err(|_| fmt::Error)?)?;
    }
    Ok(())
}

/// Parse hexadecimal string to bytes (case-insensitive).
///
/// Surrounding whitespace is ignored, as is one `0x` or `0X` prefix. The
/// empty string decodes to no bytes. Returns `None` for an odd number of
/// digits or any other character (including separators such as `:`).
pub fn parse_hex(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim();

    // Handle optional "0x" prefix
    let hex = hex
        .strip_prefix("0x")
        .or_else(|| hex.strip_prefix("0X"))
        .unwrap_or(hex);

    let digits = hex.as_bytes();

    // Must have even number of characters
    if !digits.len().is_multiple_of(2) {
        return None;
    }

    // Must only contain valid hex characters: `nibble` rejects every other
    // byte, which covers non-ASCII text too (no UTF-8 byte of a multi-byte
    // character is a hex digit).
    digits
        .chunks_exact(2)
        .map(|pair| Some(nibble(pair[0])? << 4 | nibble(pair[1])?))
        .collect()
}

fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes_to_hex(bytes: &[u8]) -> String {
        let mut s = String::new();
        write_hex(bytes, &mut s).unwrap();
        s
    }

    #[test]
    fn test_bytes_to_hex() {
        assert_eq!(
            bytes_to_hex(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            "ffffffffffff"
        );
        assert_eq!(
            bytes_to_hex(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            "001122334455"
        );
        assert_eq!(bytes_to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(bytes_to_hex(&[]), "");
    }

    /// Lengths around the internal block size, against the obvious
    /// per-byte formatting.
    #[test]
    fn test_bytes_to_hex_long() {
        for len in [1, 63, 64, 65, 127, 128, 129, 1000] {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let expected: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(bytes_to_hex(&bytes), expected, "len {len}");
        }
    }

    #[test]
    fn test_hex_to_bytes() {
        assert_eq!(
            parse_hex("ffffffffffff"),
            Some(vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
        );
        assert_eq!(
            parse_hex("001122334455"),
            Some(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
        assert_eq!(parse_hex("deadbeef"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(parse_hex("DEADBEEF"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(parse_hex("DeAdBeEf"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(parse_hex(""), Some(vec![]));
    }

    #[test]
    fn test_hex_to_bytes_with_prefix() {
        assert_eq!(parse_hex("0xdeadbeef"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(parse_hex("0XDEADBEEF"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        // Prefix alone is the empty byte string; only one prefix is removed.
        assert_eq!(parse_hex("0x"), Some(vec![]));
        assert_eq!(parse_hex("0x0xff"), None);
    }

    #[test]
    fn test_hex_to_bytes_invalid() {
        // Odd length
        assert_eq!(parse_hex("deadbee"), None);
        // Invalid characters
        assert_eq!(parse_hex("deadbeeg"), None);
        assert_eq!(parse_hex("hello"), None);
        assert_eq!(parse_hex("de:ad"), None);
        assert_eq!(parse_hex("de ad"), None);
        assert_eq!(parse_hex("+f"), None);
        // Non-ASCII, even byte length
        assert_eq!(parse_hex("\u{e9}"), None);
        assert_eq!(parse_hex("ab\u{e9}"), None);
    }

    #[test]
    fn test_hex_to_bytes_whitespace() {
        assert_eq!(
            parse_hex("  deadbeef  "),
            Some(vec![0xde, 0xad, 0xbe, 0xef])
        );
    }

    #[test]
    fn test_roundtrip() {
        let original = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let hex = bytes_to_hex(&original);
        let result = parse_hex(&hex).unwrap();
        assert_eq!(original, result);
    }
}
