//! QUIC version names.

use super::Name;

use crate::protocol::quic_version as version;

/// Convert a QUIC version to its name: `Draft-n` for an IETF draft version
/// (`0xff0000nn`), the number as `0x` and eight hex digits otherwise.
pub fn quic_version_name(ver: u32) -> Name {
    match ver {
        version::VERSION_NEGOTIATION => Name::fixed("Version Negotiation"),
        version::QUIC_V1 => Name::fixed("QUIC v1"),
        version::QUIC_V2 => Name::fixed("QUIC v2"),
        version::DRAFT_29 => Name::fixed("Draft-29"),
        version::DRAFT_32 => Name::fixed("Draft-32"),
        version::DRAFT_34 => Name::fixed("Draft-34"),
        v if (v & 0xff00_0000) == 0xff00_0000 => Name::numbered("Draft-", v & 0xff, ""),
        _ => Name::hex("0x", ver, 8, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_version_name() {
        assert_eq!(quic_version_name(0), "Version Negotiation");
        assert_eq!(quic_version_name(1), "QUIC v1");
        assert_eq!(quic_version_name(0x6b33_43cf), "QUIC v2");
        assert_eq!(quic_version_name(0xff00_001d), "Draft-29");
        assert_eq!(quic_version_name(0xff00_001b), "Draft-27");
        assert_eq!(quic_version_name(0x1234_5678), "0x12345678");
        assert_eq!(quic_version_name(2), "0x00000002");
    }
}
