//! Hexadecimal encoding and decoding of byte strings.

use std::fmt;

pub(crate) const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

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
    let mut bytes = Vec::new();
    parse_hex_into(hex, &mut bytes)?;
    Some(bytes)
}

/// [`parse_hex`] into a buffer the caller keeps: `out` is cleared, and the
/// bytes that `hex` encodes are returned as a slice of it. A loop that
/// decodes many strings into one buffer allocates only when a string is
/// longer than every one before it.
///
/// Accepts and rejects exactly what [`parse_hex`] does. After `None`, `out`
/// holds the bytes of the digit pairs before the one that is not hex, or
/// nothing.
///
/// # Example
///
/// ```
/// use pcapsql_core::format::parse_hex_into;
///
/// let mut buf = Vec::new();
/// assert_eq!(parse_hex_into("0xDEAD", &mut buf), Some(&[0xde, 0xad][..]));
/// assert_eq!(parse_hex_into("beef", &mut buf), Some(&[0xbe, 0xef][..]));
/// assert_eq!(parse_hex_into("be:ef", &mut buf), None);
/// ```
pub fn parse_hex_into<'b>(hex: &str, out: &'b mut Vec<u8>) -> Option<&'b [u8]> {
    out.clear();
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

    // Must only contain valid hex characters: `NIBBLE` rejects every other
    // byte, which covers non-ASCII text too (no UTF-8 byte of a multi-byte
    // character is a hex digit).
    out.reserve(digits.len() / 2);
    for pair in digits.chunks_exact(2) {
        let high = NIBBLE[usize::from(pair[0])];
        let low = NIBBLE[usize::from(pair[1])];
        if (high | low) & NOT_HEX != 0 {
            return None;
        }
        out.push(high << 4 | low);
    }
    Some(out)
}

/// What [`NIBBLE`] holds for a byte that is not a hex digit: a bit no digit's
/// value has.
const NOT_HEX: u8 = 0x80;

/// The value of each byte as a hex digit of either case, or [`NOT_HEX`].
const NIBBLE: [u8; 256] = {
    let mut table = [NOT_HEX; 256];
    let mut value = 0;
    while value < 16 {
        let digit = HEX_DIGITS[value as usize];
        table[digit as usize] = value;
        table[digit.to_ascii_uppercase() as usize] = value;
        value += 1;
    }
    table
};

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

    /// `parse_hex` as it was before `parse_hex_into`: the reference for what
    /// is accepted and what is decoded.
    fn parse_hex_reference(hex: &str) -> Option<Vec<u8>> {
        fn nibble(digit: u8) -> Option<u8> {
            match digit {
                b'0'..=b'9' => Some(digit - b'0'),
                b'a'..=b'f' => Some(digit - b'a' + 10),
                b'A'..=b'F' => Some(digit - b'A' + 10),
                _ => None,
            }
        }
        let hex = hex.trim();
        let hex = hex
            .strip_prefix("0x")
            .or_else(|| hex.strip_prefix("0X"))
            .unwrap_or(hex);
        let digits = hex.as_bytes();
        if !digits.len().is_multiple_of(2) {
            return None;
        }
        digits
            .chunks_exact(2)
            .map(|pair| Some(nibble(pair[0])? << 4 | nibble(pair[1])?))
            .collect()
    }

    /// Both forms against the reference, the buffer reused with whatever
    /// the call before left in it.
    fn check_parse(hex: &str, buf: &mut Vec<u8>) {
        let expected = parse_hex_reference(hex);
        assert_eq!(parse_hex(hex), expected, "{hex:?}");
        assert_eq!(parse_hex_into(hex, buf), expected.as_deref(), "{hex:?}");
    }

    #[test]
    fn nibble_table_is_the_hex_digits_of_both_cases() {
        for byte in 0..=u8::MAX {
            let expected = char::from(byte)
                .to_digit(16)
                .filter(|_| byte.is_ascii())
                .map_or(NOT_HEX, |value| value as u8);
            assert_eq!(NIBBLE[usize::from(byte)], expected, "byte {byte:#04x}");
        }
    }

    #[test]
    fn parse_hex_into_reuses_the_buffer() {
        let mut buf = vec![1, 2, 3];
        assert_eq!(parse_hex_into("", &mut buf), Some(&[][..]));
        assert_eq!(parse_hex_into("00ff", &mut buf), Some(&[0x00, 0xff][..]));
        // A rejected string does not answer with the bytes of the one before.
        assert_eq!(parse_hex_into("abc", &mut buf), None);
        assert_eq!(parse_hex_into("abzz", &mut buf), None);
        assert_eq!(parse_hex_into(" 0Xab ", &mut buf), Some(&[0xab][..]));
        let capacity = buf.capacity();
        assert_eq!(parse_hex_into("cd", &mut buf), Some(&[0xcd][..]));
        assert_eq!(buf.capacity(), capacity);
    }

    #[test]
    fn parse_hex_is_the_reference_for_every_short_string() {
        // Every string of up to three characters over an alphabet with
        // digits of both cases, the prefix letters, a separator, whitespace
        // and the characters next to the digit ranges.
        let alphabet = [
            "0", "9", "a", "f", "A", "F", "g", "G", "x", "X", ":", " ", "\t", "/", "@", "`", "-",
            "\u{e9}",
        ];
        let mut buf = Vec::new();
        for a in alphabet {
            check_parse(a, &mut buf);
            for b in alphabet {
                check_parse(&format!("{a}{b}"), &mut buf);
                for c in alphabet {
                    check_parse(&format!("{a}{b}{c}"), &mut buf);
                    check_parse(&format!("0x{a}{b}{c}"), &mut buf);
                    check_parse(&format!("{a}{b}{c}0"), &mut buf);
                }
            }
        }
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(20_000))]

            /// Text that is mostly hex: digits of both cases with now and
            /// then a prefix, a separator, whitespace or another character,
            /// of odd and even length.
            #[test]
            fn parse_hex_is_the_reference_for_hex_like_text(
                hex in "[ \t]{0,2}(0[xX]){0,2}([0-9a-fA-F]{0,40}|[0-9a-fA-F:xXgG -]{0,12}|[0-9a-f]{0,6}\\PC{0,2})[ \n]{0,2}",
            ) {
                check_parse(&hex, &mut vec![0xaa; 3]);
            }

            /// Any text at all.
            #[test]
            fn parse_hex_is_the_reference_for_any_text(hex in "\\PC{0,24}") {
                check_parse(&hex, &mut Vec::new());
            }

            /// Every byte string survives `write_hex` and back, in either
            /// case, into a buffer that held something else.
            #[test]
            fn parse_hex_into_inverts_write_hex(
                bytes in proptest::collection::vec(any::<u8>(), 0..200),
                before in proptest::collection::vec(any::<u8>(), 0..8),
            ) {
                let hex = bytes_to_hex(&bytes);
                let mut buf = before;
                prop_assert_eq!(parse_hex_into(&hex, &mut buf), Some(&bytes[..]));
                prop_assert_eq!(parse_hex_into(&hex.to_uppercase(), &mut buf), Some(&bytes[..]));
                check_parse(&hex, &mut buf);
            }
        }
    }
}
