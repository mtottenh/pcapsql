//! GRE version names.

use super::Name;

use crate::protocol::gre_version;

/// Convert a GRE version (the three version bits) to its name;
/// `Unknown (n)` otherwise.
pub fn gre_version_name(version: u8) -> Name {
    match version {
        gre_version::STANDARD => Name::fixed("Standard"),
        gre_version::PPTP_ENHANCED => Name::fixed("PPTP-Enhanced"),
        _ => Name::unknown(version),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gre_version_name() {
        assert_eq!(gre_version_name(0), "Standard");
        assert_eq!(gre_version_name(1), "PPTP-Enhanced");
        assert_eq!(gre_version_name(2), "Unknown (2)");
        assert_eq!(gre_version_name(7), "Unknown (7)");
    }
}
