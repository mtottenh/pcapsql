//! NTP mode and stratum names.

use super::Name;

use crate::protocol::{ntp_mode as mode, ntp_stratum as stratum};

/// Convert an NTP mode (0-7) to its name; `Unknown (n)` otherwise.
pub fn ntp_mode_name(m: u8) -> Name {
    match m {
        mode::RESERVED => Name::fixed("Reserved"),
        mode::SYMMETRIC_ACTIVE => Name::fixed("Symmetric Active"),
        mode::SYMMETRIC_PASSIVE => Name::fixed("Symmetric Passive"),
        mode::CLIENT => Name::fixed("Client"),
        mode::SERVER => Name::fixed("Server"),
        mode::BROADCAST => Name::fixed("Broadcast"),
        mode::CONTROL => Name::fixed("NTP Control"),
        mode::PRIVATE => Name::fixed("Private"),
        _ => Name::unknown(m),
    }
}

/// Convert an NTP stratum to its description.
pub fn ntp_stratum_name(s: u8) -> Name {
    match s {
        stratum::UNSPECIFIED => Name::fixed("Unspecified"),
        stratum::PRIMARY => Name::fixed("Primary Reference"),
        2..=15 => Name::numbered("Secondary (stratum ", s, ")"),
        stratum::UNSYNCHRONIZED => Name::fixed("Unsynchronized"),
        _ => Name::numbered("Reserved (", s, ")"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntp_mode_name() {
        assert_eq!(ntp_mode_name(mode::RESERVED), "Reserved");
        assert_eq!(ntp_mode_name(mode::SYMMETRIC_ACTIVE), "Symmetric Active");
        assert_eq!(ntp_mode_name(mode::SYMMETRIC_PASSIVE), "Symmetric Passive");
        assert_eq!(ntp_mode_name(mode::CLIENT), "Client");
        assert_eq!(ntp_mode_name(mode::SERVER), "Server");
        assert_eq!(ntp_mode_name(mode::BROADCAST), "Broadcast");
        assert_eq!(ntp_mode_name(mode::CONTROL), "NTP Control");
        assert_eq!(ntp_mode_name(mode::PRIVATE), "Private");
        assert_eq!(ntp_mode_name(8), "Unknown (8)");
    }

    #[test]
    fn test_ntp_stratum_name() {
        assert_eq!(ntp_stratum_name(stratum::UNSPECIFIED), "Unspecified");
        assert_eq!(ntp_stratum_name(stratum::PRIMARY), "Primary Reference");
        assert_eq!(ntp_stratum_name(2), "Secondary (stratum 2)");
        assert_eq!(ntp_stratum_name(15), "Secondary (stratum 15)");
        assert_eq!(ntp_stratum_name(stratum::UNSYNCHRONIZED), "Unsynchronized");
        assert_eq!(ntp_stratum_name(17), "Reserved (17)");
    }
}
