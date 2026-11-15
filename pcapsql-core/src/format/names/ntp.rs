//! NTP mode and stratum names.

use std::borrow::Cow;

use crate::protocol::{ntp_mode as mode, ntp_stratum as stratum};

/// Convert an NTP mode (0-7) to its name; `Unknown (n)` otherwise.
pub fn ntp_mode_name(m: u8) -> Cow<'static, str> {
    match m {
        mode::RESERVED => Cow::Borrowed("Reserved"),
        mode::SYMMETRIC_ACTIVE => Cow::Borrowed("Symmetric Active"),
        mode::SYMMETRIC_PASSIVE => Cow::Borrowed("Symmetric Passive"),
        mode::CLIENT => Cow::Borrowed("Client"),
        mode::SERVER => Cow::Borrowed("Server"),
        mode::BROADCAST => Cow::Borrowed("Broadcast"),
        mode::CONTROL => Cow::Borrowed("NTP Control"),
        mode::PRIVATE => Cow::Borrowed("Private"),
        _ => Cow::Owned(format!("Unknown ({m})")),
    }
}

/// Convert an NTP stratum to its description.
pub fn ntp_stratum_name(s: u8) -> Cow<'static, str> {
    match s {
        stratum::UNSPECIFIED => Cow::Borrowed("Unspecified"),
        stratum::PRIMARY => Cow::Borrowed("Primary Reference"),
        2..=15 => Cow::Owned(format!("Secondary (stratum {s})")),
        stratum::UNSYNCHRONIZED => Cow::Borrowed("Unsynchronized"),
        _ => Cow::Owned(format!("Reserved ({s})")),
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
