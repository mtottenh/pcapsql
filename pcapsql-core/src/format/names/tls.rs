//! TLS version and record type names.

use std::borrow::Cow;

use crate::protocol::{tls_record_type as record_type, tls_version as version};

/// Convert a TLS protocol version to its name (`GREASE` for RFC 8701 values);
/// `Unknown (0xNNNN)` otherwise.
pub fn tls_version_name(ver: u16) -> Cow<'static, str> {
    match ver {
        version::SSL_2_0 => Cow::Borrowed("SSL 2.0"),
        version::SSL_3_0 => Cow::Borrowed("SSL 3.0"),
        version::TLS_1_0 => Cow::Borrowed("TLS 1.0"),
        version::TLS_1_1 => Cow::Borrowed("TLS 1.1"),
        version::TLS_1_2 => Cow::Borrowed("TLS 1.2"),
        version::TLS_1_3 => Cow::Borrowed("TLS 1.3"),
        // GREASE values (RFC 8701) - pattern 0x?a?a
        v if (v & 0x0f0f) == 0x0a0a => Cow::Borrowed("GREASE"),
        _ => Cow::Owned(format!("Unknown (0x{ver:04x})")),
    }
}

/// Convert a TLS record content type to its name; `Unknown (n)` otherwise.
pub fn tls_record_type_name(rt: u8) -> Cow<'static, str> {
    match rt {
        record_type::CHANGE_CIPHER_SPEC => Cow::Borrowed("ChangeCipherSpec"),
        record_type::ALERT => Cow::Borrowed("Alert"),
        record_type::HANDSHAKE => Cow::Borrowed("Handshake"),
        record_type::APPLICATION_DATA => Cow::Borrowed("ApplicationData"),
        record_type::HEARTBEAT => Cow::Borrowed("Heartbeat"),
        _ => Cow::Owned(format!("Unknown ({rt})")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_version_name() {
        assert_eq!(tls_version_name(version::SSL_2_0), "SSL 2.0");
        assert_eq!(tls_version_name(version::SSL_3_0), "SSL 3.0");
        assert_eq!(tls_version_name(version::TLS_1_0), "TLS 1.0");
        assert_eq!(tls_version_name(version::TLS_1_1), "TLS 1.1");
        assert_eq!(tls_version_name(version::TLS_1_2), "TLS 1.2");
        assert_eq!(tls_version_name(version::TLS_1_3), "TLS 1.3");
        // GREASE values
        assert_eq!(tls_version_name(0x0a0a), "GREASE");
        assert_eq!(tls_version_name(0x1a1a), "GREASE");
        assert_eq!(tls_version_name(0xfafa), "GREASE");
        // Unknown
        assert_eq!(tls_version_name(0x0305), "Unknown (0x0305)");
    }

    #[test]
    fn test_tls_record_type_name() {
        assert_eq!(
            tls_record_type_name(record_type::CHANGE_CIPHER_SPEC),
            "ChangeCipherSpec"
        );
        assert_eq!(tls_record_type_name(record_type::ALERT), "Alert");
        assert_eq!(tls_record_type_name(record_type::HANDSHAKE), "Handshake");
        assert_eq!(
            tls_record_type_name(record_type::APPLICATION_DATA),
            "ApplicationData"
        );
        assert_eq!(tls_record_type_name(record_type::HEARTBEAT), "Heartbeat");
        assert_eq!(tls_record_type_name(99), "Unknown (99)");
    }
}
