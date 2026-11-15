//! TCP flag formatting and tests.
//!
//! The flags are the 9-bit bitmap of the `tcp.flags` column (NS in bit 8).

use std::fmt;

/// TCP flag bits and names, lowest bit first (the order they are printed in).
pub const TCP_FLAGS: &[(u16, &str)] = &[
    (0x001, "FIN"),
    (0x002, "SYN"),
    (0x004, "RST"),
    (0x008, "PSH"),
    (0x010, "ACK"),
    (0x020, "URG"),
    (0x040, "ECE"),
    (0x080, "CWR"),
    (0x100, "NS"),
];

/// Write the names of the set flags, comma-separated and lowest bit first
/// (`SYN,ACK`). Writes nothing when no known flag is set; bits above NS are
/// ignored.
///
/// # Example
///
/// ```
/// use pcapsql_core::format::write_tcp_flags;
///
/// let mut s = String::new();
/// write_tcp_flags(0x012, &mut s).unwrap();
/// assert_eq!(s, "SYN,ACK");
/// ```
pub fn write_tcp_flags(flags: u16, out: &mut impl fmt::Write) -> fmt::Result {
    let mut first = true;
    for &(bit, name) in TCP_FLAGS {
        if flags & bit != 0 {
            if !first {
                out.write_char(',')?;
            }
            out.write_str(name)?;
            first = false;
        }
    }
    Ok(())
}

/// The bit for a flag name, matched case-insensitively. `None` for a name
/// that is not a TCP flag.
///
/// Resolve the name once with this when it is constant across a batch, then
/// test `flags & mask != 0` per row.
pub fn tcp_flag_mask(name: &str) -> Option<u16> {
    // The comparison has always been against `name.to_uppercase()`, which is
    // full Unicode upper-casing: U+017F LONG S upper-cases to `S`, so
    // "\u{17f}yn" names SYN. For an ASCII name that is ASCII case folding,
    // so only a non-ASCII name pays for the allocation.
    let upper;
    let name = if name.is_ascii() {
        name
    } else {
        upper = name.to_uppercase();
        &upper
    };
    TCP_FLAGS
        .iter()
        .find(|&&(_, flag_name)| flag_name.eq_ignore_ascii_case(name))
        .map(|&(bit, _)| bit)
}

/// Whether the named flag is set. The name is matched case-insensitively; a
/// name that is not a TCP flag is never set.
///
/// # Example
///
/// ```
/// use pcapsql_core::format::has_tcp_flag;
///
/// assert!(has_tcp_flag(0x012, "syn"));
/// assert!(!has_tcp_flag(0x012, "RST"));
/// assert!(!has_tcp_flag(0x012, "nonsense"));
/// ```
pub fn has_tcp_flag(flags: u16, name: &str) -> bool {
    tcp_flag_mask(name).is_some_and(|mask| flags & mask != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn format_tcp_flags(flags: u16) -> String {
        let mut s = String::new();
        write_tcp_flags(flags, &mut s).unwrap();
        s
    }

    #[test]
    fn test_tcp_flags_str() {
        // SYN only
        assert_eq!(format_tcp_flags(0x002), "SYN");
        // SYN+ACK
        assert_eq!(format_tcp_flags(0x012), "SYN,ACK");
        // FIN+ACK
        assert_eq!(format_tcp_flags(0x011), "FIN,ACK");
        // RST
        assert_eq!(format_tcp_flags(0x004), "RST");
        // All flags
        assert_eq!(
            format_tcp_flags(0x1FF),
            "FIN,SYN,RST,PSH,ACK,URG,ECE,CWR,NS"
        );
        // Empty
        assert_eq!(format_tcp_flags(0x000), "");
        // Bits above NS have no name
        assert_eq!(format_tcp_flags(0xFE00), "");
        assert_eq!(
            format_tcp_flags(0xFFFF),
            "FIN,SYN,RST,PSH,ACK,URG,ECE,CWR,NS"
        );
    }

    #[test]
    fn test_has_tcp_flag() {
        assert!(has_tcp_flag(0x002, "SYN"));
        assert!(has_tcp_flag(0x002, "syn")); // Case insensitive
        assert!(has_tcp_flag(0x002, "Syn")); // Mixed case
        assert!(!has_tcp_flag(0x002, "ACK"));
        assert!(has_tcp_flag(0x012, "SYN"));
        assert!(has_tcp_flag(0x012, "ACK"));
        assert!(!has_tcp_flag(0x012, "RST"));
    }

    #[test]
    fn test_has_tcp_flag_unknown_name() {
        assert!(!has_tcp_flag(0x1FF, ""));
        assert!(!has_tcp_flag(0x1FF, "SYNACK"));
        assert!(!has_tcp_flag(0x1FF, " SYN")); // not trimmed
        assert_eq!(tcp_flag_mask("bogus"), None);
    }

    #[test]
    fn test_tcp_flag_mask() {
        for &(bit, name) in TCP_FLAGS {
            assert_eq!(tcp_flag_mask(name), Some(bit));
            assert_eq!(tcp_flag_mask(&name.to_lowercase()), Some(bit));
        }
    }

    /// The name comparison is `to_uppercase()`, not ASCII case folding, for
    /// every input: the ASCII fast path must agree with it.
    #[test]
    fn test_flag_name_unicode_uppercase() {
        // U+017F LONG S and U+0131 DOTLESS I upper-case to ASCII letters.
        assert!(has_tcp_flag(0x002, "\u{17f}yn"));
        assert!(has_tcp_flag(0x001, "f\u{131}n"));
        // U+FB01 LATIN SMALL LIGATURE FI upper-cases to "FI".
        assert!(has_tcp_flag(0x001, "\u{fb01}n"));
        assert!(!has_tcp_flag(0x002, "s\u{fc}n"));
    }

    #[test]
    fn test_common_flag_combinations() {
        // SYN (connection initiation)
        assert_eq!(format_tcp_flags(0x002), "SYN");

        // SYN-ACK (connection response)
        assert_eq!(format_tcp_flags(0x012), "SYN,ACK");

        // ACK (acknowledgment)
        assert_eq!(format_tcp_flags(0x010), "ACK");

        // FIN-ACK (graceful close)
        assert_eq!(format_tcp_flags(0x011), "FIN,ACK");

        // RST (reset)
        assert_eq!(format_tcp_flags(0x004), "RST");

        // RST-ACK
        assert_eq!(format_tcp_flags(0x014), "RST,ACK");

        // PSH-ACK (push data)
        assert_eq!(format_tcp_flags(0x018), "PSH,ACK");
    }
}
