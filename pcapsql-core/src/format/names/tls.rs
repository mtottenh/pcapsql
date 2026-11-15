//! TLS version, record type, alert, compression method, signature scheme,
//! named group and EC point format names.

use super::Name;

use crate::protocol::{tls_alert as alert, tls_record_type as record_type, tls_version as version};

/// Whether a 16-bit TLS code point is a GREASE value (RFC 8701): `0x0a0a`,
/// `0x1a1a`, ... `0xfafa`.
fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a
}

/// Convert a TLS protocol version to its name (`GREASE` for RFC 8701 values);
/// `Unknown (0xNNNN)` otherwise.
pub fn tls_version_name(ver: u16) -> Name {
    match ver {
        version::SSL_2_0 => Name::fixed("SSL 2.0"),
        version::SSL_3_0 => Name::fixed("SSL 3.0"),
        version::TLS_1_0 => Name::fixed("TLS 1.0"),
        version::TLS_1_1 => Name::fixed("TLS 1.1"),
        version::TLS_1_2 => Name::fixed("TLS 1.2"),
        version::TLS_1_3 => Name::fixed("TLS 1.3"),
        v if is_grease(v) => Name::fixed("GREASE"),
        _ => Name::hex("Unknown (0x", ver, 4, ")"),
    }
}

/// Convert a TLS record content type to its name; `Unknown (n)` otherwise.
pub fn tls_record_type_name(rt: u8) -> Name {
    match rt {
        record_type::CHANGE_CIPHER_SPEC => Name::fixed("ChangeCipherSpec"),
        record_type::ALERT => Name::fixed("Alert"),
        record_type::HANDSHAKE => Name::fixed("Handshake"),
        record_type::APPLICATION_DATA => Name::fixed("ApplicationData"),
        record_type::HEARTBEAT => Name::fixed("Heartbeat"),
        _ => Name::unknown(rt),
    }
}

/// Convert a TLS alert description to its name as the RFCs spell it
/// (`handshake_failure`); `Unknown (n)` otherwise.
pub fn tls_alert_description_name(code: u8) -> Name {
    Name::fixed(match code {
        alert::CLOSE_NOTIFY => "close_notify",
        alert::UNEXPECTED_MESSAGE => "unexpected_message",
        alert::BAD_RECORD_MAC => "bad_record_mac",
        alert::DECRYPTION_FAILED => "decryption_failed",
        alert::RECORD_OVERFLOW => "record_overflow",
        alert::DECOMPRESSION_FAILURE => "decompression_failure",
        alert::HANDSHAKE_FAILURE => "handshake_failure",
        alert::NO_CERTIFICATE => "no_certificate",
        alert::BAD_CERTIFICATE => "bad_certificate",
        alert::UNSUPPORTED_CERTIFICATE => "unsupported_certificate",
        alert::CERTIFICATE_REVOKED => "certificate_revoked",
        alert::CERTIFICATE_EXPIRED => "certificate_expired",
        alert::CERTIFICATE_UNKNOWN => "certificate_unknown",
        alert::ILLEGAL_PARAMETER => "illegal_parameter",
        alert::UNKNOWN_CA => "unknown_ca",
        alert::ACCESS_DENIED => "access_denied",
        alert::DECODE_ERROR => "decode_error",
        alert::DECRYPT_ERROR => "decrypt_error",
        alert::EXPORT_RESTRICTION => "export_restriction",
        alert::PROTOCOL_VERSION => "protocol_version",
        alert::INSUFFICIENT_SECURITY => "insufficient_security",
        alert::INTERNAL_ERROR => "internal_error",
        alert::INAPPROPRIATE_FALLBACK => "inappropriate_fallback",
        alert::USER_CANCELED => "user_canceled",
        alert::NO_RENEGOTIATION => "no_renegotiation",
        alert::MISSING_EXTENSION => "missing_extension",
        alert::UNSUPPORTED_EXTENSION => "unsupported_extension",
        alert::CERTIFICATE_UNOBTAINABLE => "certificate_unobtainable",
        alert::UNRECOGNIZED_NAME => "unrecognized_name",
        alert::BAD_CERTIFICATE_STATUS_RESPONSE => "bad_certificate_status_response",
        alert::BAD_CERTIFICATE_HASH_VALUE => "bad_certificate_hash_value",
        alert::UNKNOWN_PSK_IDENTITY => "unknown_psk_identity",
        alert::CERTIFICATE_REQUIRED => "certificate_required",
        alert::NO_APPLICATION_PROTOCOL => "no_application_protocol",
        _ => return Name::unknown(code),
    })
}

/// Convert a TLS compression method to its name; the number as `0x` and two
/// hex digits otherwise.
pub fn tls_compression_method_name(method: u8) -> Name {
    match method {
        0 => Name::fixed("null"),
        1 => Name::fixed("DEFLATE"),
        64 => Name::fixed("LZS"),
        _ => Name::hex("0x", method, 2, ""),
    }
}

/// Convert a TLS signature scheme (the `signature_algorithms` extension) to
/// its name (`GREASE` for RFC 8701 values); the number as `0x` and four hex
/// digits otherwise.
pub fn tls_signature_scheme_name(scheme: u16) -> Name {
    Name::fixed(match scheme {
        0x0201 => "rsa_pkcs1_sha1",
        0x0203 => "ecdsa_sha1",
        0x0401 => "rsa_pkcs1_sha256",
        0x0403 => "ecdsa_secp256r1_sha256",
        0x0501 => "rsa_pkcs1_sha384",
        0x0503 => "ecdsa_secp384r1_sha384",
        0x0601 => "rsa_pkcs1_sha512",
        0x0603 => "ecdsa_secp521r1_sha512",
        0x0804 => "rsa_pss_rsae_sha256",
        0x0805 => "rsa_pss_rsae_sha384",
        0x0806 => "rsa_pss_rsae_sha512",
        0x0807 => "ed25519",
        0x0808 => "ed448",
        0x0809 => "rsa_pss_pss_sha256",
        0x080a => "rsa_pss_pss_sha384",
        0x080b => "rsa_pss_pss_sha512",
        v if is_grease(v) => "GREASE",
        _ => return Name::hex("0x", scheme, 4, ""),
    })
}

/// Convert a TLS named group (the `supported_groups` extension) to its name
/// (`GREASE` for RFC 8701 values); the number as `0x` and four hex digits
/// otherwise.
pub fn tls_named_group_name(group: u16) -> Name {
    Name::fixed(match group {
        1 => "sect163k1",
        2 => "sect163r1",
        3 => "sect163r2",
        4 => "sect193r1",
        5 => "sect193r2",
        6 => "sect233k1",
        7 => "sect233r1",
        8 => "sect239k1",
        9 => "sect283k1",
        10 => "sect283r1",
        11 => "sect409k1",
        12 => "sect409r1",
        13 => "sect571k1",
        14 => "sect571r1",
        15 => "secp160k1",
        16 => "secp160r1",
        17 => "secp160r2",
        18 => "secp192k1",
        19 => "secp192r1",
        20 => "secp224k1",
        21 => "secp224r1",
        22 => "secp256k1",
        23 => "secp256r1",
        24 => "secp384r1",
        25 => "secp521r1",
        26 => "brainpoolP256r1",
        27 => "brainpoolP384r1",
        28 => "brainpoolP512r1",
        29 => "x25519",
        30 => "x448",
        256 => "ffdhe2048",
        257 => "ffdhe3072",
        258 => "ffdhe4096",
        259 => "ffdhe6144",
        260 => "ffdhe8192",
        v if is_grease(v) => "GREASE",
        _ => return Name::hex("0x", group, 4, ""),
    })
}

/// Convert a TLS EC point format to its name; the number as `0x` and two
/// hex digits otherwise.
pub fn tls_ec_point_format_name(format: u8) -> Name {
    match format {
        0 => Name::fixed("uncompressed"),
        1 => Name::fixed("ansiX962_compressed_prime"),
        2 => Name::fixed("ansiX962_compressed_char2"),
        _ => Name::hex("0x", format, 2, ""),
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

    #[test]
    fn test_tls_alert_description_name() {
        assert_eq!(tls_alert_description_name(0), "close_notify");
        assert_eq!(tls_alert_description_name(40), "handshake_failure");
        assert_eq!(tls_alert_description_name(120), "no_application_protocol");
        assert_eq!(tls_alert_description_name(255), "Unknown (255)");
    }

    #[test]
    fn test_tls_extension_value_names() {
        assert_eq!(tls_compression_method_name(0), "null");
        assert_eq!(tls_compression_method_name(1), "DEFLATE");
        assert_eq!(tls_compression_method_name(2), "0x02");

        assert_eq!(tls_signature_scheme_name(0x0403), "ecdsa_secp256r1_sha256");
        assert_eq!(tls_signature_scheme_name(0x0807), "ed25519");
        assert_eq!(tls_signature_scheme_name(0x3a3a), "GREASE");
        assert_eq!(tls_signature_scheme_name(0x0101), "0x0101");

        assert_eq!(tls_named_group_name(23), "secp256r1");
        assert_eq!(tls_named_group_name(29), "x25519");
        assert_eq!(tls_named_group_name(256), "ffdhe2048");
        assert_eq!(tls_named_group_name(0x0a0a), "GREASE");
        assert_eq!(tls_named_group_name(0x6399), "0x6399");

        assert_eq!(tls_ec_point_format_name(0), "uncompressed");
        assert_eq!(tls_ec_point_format_name(3), "0x03");
    }
}
