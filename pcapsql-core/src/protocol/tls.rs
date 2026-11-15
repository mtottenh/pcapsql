//! TLS protocol parser.
//!
//! Parses TLS (Transport Layer Security) records using the `tls-parser` crate
//! from the Rusticata project, which is designed for passive network analysis.
//!
//! ## Features
//!
//! - Full TLS 1.0-1.3 handshake parsing
//! - Complete IANA cipher suite coverage
//! - Extension parsing (SNI, ALPN, supported_versions, signature_algorithms, etc.)
//! - JA3/JA3S fingerprinting for threat hunting
//! - Alert message decoding
//! - Foundation fields for future TLS decryption support
//!
//! ## Decryption Foundation
//!
//! This parser extracts `client_random`, `server_random`, and `session_id` fields
//! which are essential for TLS decryption when used with SSLKEYLOGFILE.

use std::fmt::Write as _;

use tls_parser::{
    parse_tls_extensions, parse_tls_plaintext, TlsCipherSuite, TlsExtension, TlsMessage,
    TlsMessageHandshake, TlsVersion,
};

use super::{
    Cond, Dispatch, DispatchRule, FieldSink, FieldValue, HintKey, Hints, ParseContext, Parsed,
    Protocol,
};
use crate::format::names::{
    tls_alert_description_name, tls_compression_method_name, tls_ec_point_format_name,
    tls_named_group_name, tls_signature_scheme_name, tls_version_name, Name,
};
use crate::schema::{DataKind, FieldDescriptor};

/// TLS/HTTPS port.
#[allow(dead_code)]
pub const TLS_PORT: u16 = 443;

/// TLS version constants.
pub mod version {
    /// SSL 2.0 (obsolete, insecure).
    pub const SSL_2_0: u16 = 0x0200;
    /// SSL 3.0 (obsolete, insecure).
    pub const SSL_3_0: u16 = 0x0300;
    /// TLS 1.0 (RFC 2246).
    pub const TLS_1_0: u16 = 0x0301;
    /// TLS 1.1 (RFC 4346).
    pub const TLS_1_1: u16 = 0x0302;
    /// TLS 1.2 (RFC 5246).
    pub const TLS_1_2: u16 = 0x0303;
    /// TLS 1.3 (RFC 8446).
    pub const TLS_1_3: u16 = 0x0304;
}

/// TLS record type constants.
pub mod record_type {
    /// Change Cipher Spec message.
    pub const CHANGE_CIPHER_SPEC: u8 = 20;
    /// Alert message.
    pub const ALERT: u8 = 21;
    /// Handshake message.
    pub const HANDSHAKE: u8 = 22;
    /// Application data (encrypted).
    pub const APPLICATION_DATA: u8 = 23;
    /// Heartbeat (RFC 6520).
    pub const HEARTBEAT: u8 = 24;
}

/// TLS alert description constants.
pub mod alert {
    pub const CLOSE_NOTIFY: u8 = 0;
    pub const UNEXPECTED_MESSAGE: u8 = 10;
    pub const BAD_RECORD_MAC: u8 = 20;
    pub const DECRYPTION_FAILED: u8 = 21;
    pub const RECORD_OVERFLOW: u8 = 22;
    pub const DECOMPRESSION_FAILURE: u8 = 30;
    pub const HANDSHAKE_FAILURE: u8 = 40;
    pub const NO_CERTIFICATE: u8 = 41;
    pub const BAD_CERTIFICATE: u8 = 42;
    pub const UNSUPPORTED_CERTIFICATE: u8 = 43;
    pub const CERTIFICATE_REVOKED: u8 = 44;
    pub const CERTIFICATE_EXPIRED: u8 = 45;
    pub const CERTIFICATE_UNKNOWN: u8 = 46;
    pub const ILLEGAL_PARAMETER: u8 = 47;
    pub const UNKNOWN_CA: u8 = 48;
    pub const ACCESS_DENIED: u8 = 49;
    pub const DECODE_ERROR: u8 = 50;
    pub const DECRYPT_ERROR: u8 = 51;
    pub const EXPORT_RESTRICTION: u8 = 60;
    pub const PROTOCOL_VERSION: u8 = 70;
    pub const INSUFFICIENT_SECURITY: u8 = 71;
    pub const INTERNAL_ERROR: u8 = 80;
    pub const INAPPROPRIATE_FALLBACK: u8 = 86;
    pub const USER_CANCELED: u8 = 90;
    pub const NO_RENEGOTIATION: u8 = 100;
    pub const MISSING_EXTENSION: u8 = 109;
    pub const UNSUPPORTED_EXTENSION: u8 = 110;
    pub const CERTIFICATE_UNOBTAINABLE: u8 = 111;
    pub const UNRECOGNIZED_NAME: u8 = 112;
    pub const BAD_CERTIFICATE_STATUS_RESPONSE: u8 = 113;
    pub const BAD_CERTIFICATE_HASH_VALUE: u8 = 114;
    pub const UNKNOWN_PSK_IDENTITY: u8 = 115;
    pub const CERTIFICATE_REQUIRED: u8 = 116;
    pub const NO_APPLICATION_PROTOCOL: u8 = 120;
}

/// Common TLS ports for priority matching.
const TLS_PORTS: &[u64] = &[
    443,   // HTTPS
    8443,  // HTTPS alternate
    993,   // IMAPS
    995,   // POP3S
    465,   // SMTPS (submission)
    636,   // LDAPS
    853,   // DNS over TLS
    5061,  // SIPS
    14433, // Test port (used by testdata/tls/)
];

/// TLS protocol parser using tls-parser crate.
#[derive(Debug, Clone, Copy)]
pub struct TlsProtocol;

impl Protocol for TlsProtocol {
    fn name(&self) -> &'static str {
        "tls"
    }

    fn display_name(&self) -> &'static str {
        "TLS"
    }

    fn dispatch(&self) -> Dispatch {
        const RULES: &[DispatchRule] = &[DispatchRule::hints(
            &[Cond::Port(TLS_PORTS), Cond::OVER_TCP],
            50,
        )];
        Dispatch::Exact(RULES)
    }

    fn child_hint_keys(&self) -> Option<&'static [HintKey]> {
        Some(&[])
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        // TLS records run over TCP. UDP 443 is QUIC (its own parser); DTLS
        // has a different record header and is not parsed here.
        if !context.over_tcp() {
            return None;
        }
        let src_port = context.hint(HintKey::SrcPort);
        let dst_port = context.hint(HintKey::DstPort);

        // Check for known TLS ports
        for &port in TLS_PORTS {
            if src_port == Some(port) || dst_port == Some(port) {
                return Some(50);
            }
        }

        None
    }

    fn parse<'a>(
        &self,
        data: &'a [u8],
        _context: &ParseContext,
        fields: &mut FieldSink<'_, 'a>,
    ) -> Parsed<'a> {
        // TLS record header is 5 bytes minimum
        if data.len() < 5 {
            return Parsed::error("TLS record too short", data);
        }

        // Use tls-parser for zero-copy parsing
        match parse_tls_plaintext(data) {
            Ok((remaining, record)) => {
                // Record header fields
                fields.push(("record_type", FieldValue::UInt8(record.hdr.record_type.0)));
                fields.push(("record_version", FieldValue::UInt16(record.hdr.version.0)));
                fields.push((
                    "version",
                    fields.name(tls_version_name(record.hdr.version.0)),
                ));

                // Process messages in the record
                for msg in &record.msg {
                    match msg {
                        TlsMessage::Handshake(handshake) => {
                            parse_handshake(handshake, fields);
                        }
                        TlsMessage::Alert(alert) => {
                            fields.push(("alert_level", FieldValue::UInt8(alert.severity.0)));
                            fields.push(("alert_description", FieldValue::UInt8(alert.code.0)));
                            fields.push((
                                "alert_description_str",
                                fields.name(tls_alert_description_name(alert.code.0)),
                            ));
                        }
                        TlsMessage::Heartbeat(hb) => {
                            fields.push(("is_heartbeat", FieldValue::Bool(true)));
                            fields.push(("heartbeat_type", FieldValue::UInt8(hb.heartbeat_type.0)));
                        }
                        TlsMessage::ChangeCipherSpec => {
                            fields.push(("is_change_cipher_spec", FieldValue::Bool(true)));
                        }
                        TlsMessage::ApplicationData(app_data) => {
                            // Application data is encrypted, just note its presence and size
                            fields.push(("has_app_data", FieldValue::Bool(true)));
                            fields.push((
                                "app_data_length",
                                FieldValue::UInt32(app_data.blob.len() as u32),
                            ));
                        }
                    }
                }

                Parsed::ok(remaining, Hints::new())
            }
            Err(nom::Err::Incomplete(_)) => {
                // Partial record - extract what we can from the header
                let record_type = data[0];
                fields.push(("record_type", FieldValue::UInt8(record_type)));

                let version = TlsVersion(u16::from_be_bytes([data[1], data[2]]));
                fields.push(("record_version", FieldValue::UInt16(version.0)));
                fields.push(("version", fields.name(tls_version_name(version.0))));

                Parsed::partial(&data[5..], "TLS record incomplete")
            }
            Err(e) => Parsed::error(
                fields.text_fmt(format_args!("TLS parse error: {e:?}")),
                data,
            ),
        }
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            // Record layer
            FieldDescriptor::new("tls.record_type", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("tls.record_version", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("tls.version", DataKind::String).set_nullable(true),
            // Handshake
            FieldDescriptor::new("tls.handshake_type", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("tls.handshake_version", DataKind::UInt16).set_nullable(true),
            // Decryption foundation fields
            FieldDescriptor::new("tls.client_random", DataKind::FixedBinary(32)).set_nullable(true),
            FieldDescriptor::new("tls.server_random", DataKind::FixedBinary(32)).set_nullable(true),
            FieldDescriptor::new("tls.session_id", DataKind::Binary).set_nullable(true),
            FieldDescriptor::new("tls.session_id_length", DataKind::UInt8).set_nullable(true),
            // Cipher suites
            FieldDescriptor::new("tls.cipher_suites", DataKind::String).set_nullable(true),
            FieldDescriptor::new("tls.cipher_suite_count", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("tls.selected_cipher", DataKind::String).set_nullable(true),
            FieldDescriptor::new("tls.selected_cipher_id", DataKind::UInt16).set_nullable(true),
            // Compression
            FieldDescriptor::new("tls.compression_methods", DataKind::String).set_nullable(true),
            FieldDescriptor::new("tls.selected_compression", DataKind::UInt8).set_nullable(true),
            // Extensions
            FieldDescriptor::new("tls.sni", DataKind::String).set_nullable(true),
            FieldDescriptor::new("tls.alpn", DataKind::String).set_nullable(true),
            FieldDescriptor::new("tls.supported_versions", DataKind::String).set_nullable(true),
            FieldDescriptor::new("tls.signature_algorithms", DataKind::String).set_nullable(true),
            FieldDescriptor::new("tls.supported_groups", DataKind::String).set_nullable(true),
            FieldDescriptor::new("tls.ec_point_formats", DataKind::String).set_nullable(true),
            FieldDescriptor::new("tls.extensions_length", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("tls.extension_types", DataKind::String).set_nullable(true),
            // Alerts
            FieldDescriptor::new("tls.alert_level", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("tls.alert_description", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("tls.alert_description_str", DataKind::String).set_nullable(true),
            // Heartbeat
            FieldDescriptor::new("tls.is_heartbeat", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("tls.heartbeat_type", DataKind::UInt8).set_nullable(true),
            // Change cipher spec
            FieldDescriptor::new("tls.is_change_cipher_spec", DataKind::Bool).set_nullable(true),
            // Application data
            FieldDescriptor::new("tls.has_app_data", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("tls.app_data_length", DataKind::UInt32).set_nullable(true),
            // JA3 fingerprinting
            FieldDescriptor::new("tls.ja3", DataKind::String).set_nullable(true),
            FieldDescriptor::new("tls.ja3_hash", DataKind::String).set_nullable(true),
            FieldDescriptor::new("tls.ja3s", DataKind::String).set_nullable(true),
            FieldDescriptor::new("tls.ja3s_hash", DataKind::String).set_nullable(true),
            // Certificate info (basic)
            FieldDescriptor::new("tls.certificate_count", DataKind::UInt16).set_nullable(true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        &[]
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &["tcp"]
    }
}

/// Parse a TLS handshake message.
fn parse_handshake<'a>(handshake: &TlsMessageHandshake<'a>, fields: &mut FieldSink<'_, 'a>) {
    match handshake {
        TlsMessageHandshake::ClientHello(ch) => {
            fields.push(("handshake_type", FieldValue::UInt8(1)));
            fields.push(("handshake_version", FieldValue::UInt16(ch.version.0)));

            // Decryption foundation: client_random (32 bytes)
            fields.push(("client_random", FieldValue::Bytes(ch.random)));

            // Session ID (for session resumption tracking)
            if let Some(session_id) = ch.session_id {
                fields.push((
                    "session_id_length",
                    FieldValue::UInt8(session_id.len() as u8),
                ));
                if !session_id.is_empty() {
                    fields.push(("session_id", FieldValue::Bytes(session_id)));
                }
            } else {
                fields.push(("session_id_length", FieldValue::UInt8(0)));
            }

            // Cipher suites - full IANA coverage via tls-parser
            let cipher_count = ch.ciphers.len();
            fields.push((
                "cipher_suite_count",
                FieldValue::UInt16(cipher_count as u16),
            ));

            // Build cipher suite list (limit to first 50 for reasonable output)
            let cipher_names: Vec<String> = ch
                .ciphers
                .iter()
                .take(50)
                .map(|c| cipher_suite_name(c.0))
                .collect();
            if !cipher_names.is_empty() {
                fields.push(("cipher_suites", fields.str(&cipher_names.join(";"))));
            }

            // Compression methods
            let methods = ch.comp.iter().map(|c| tls_compression_method_name(c.0));
            if let Some(methods) = name_list(fields, methods) {
                fields.push(("compression_methods", methods));
            }

            // Parse extensions
            if let Some(ext_data) = ch.ext {
                fields.push((
                    "extensions_length",
                    FieldValue::UInt16(ext_data.len() as u16),
                ));
                parse_extensions(ext_data, fields, true);

                // Compute JA3 fingerprint
                let ja3_string = compute_ja3(ch);
                let ja3_hash = format!("{:x}", md5::compute(&ja3_string));
                fields.push(("ja3", fields.str(&ja3_string)));
                fields.push(("ja3_hash", fields.str(&ja3_hash)));
            }
        }
        TlsMessageHandshake::ServerHello(sh) => {
            fields.push(("handshake_type", FieldValue::UInt8(2)));
            fields.push(("handshake_version", FieldValue::UInt16(sh.version.0)));

            // Decryption foundation: server_random (32 bytes)
            fields.push(("server_random", FieldValue::Bytes(sh.random)));

            // Session ID
            if let Some(session_id) = sh.session_id {
                fields.push((
                    "session_id_length",
                    FieldValue::UInt8(session_id.len() as u8),
                ));
                if !session_id.is_empty() {
                    fields.push(("session_id", FieldValue::Bytes(session_id)));
                }
            } else {
                fields.push(("session_id_length", FieldValue::UInt8(0)));
            }

            // Selected cipher suite - essential for decryption
            let cipher_name = cipher_suite_name(sh.cipher.0);
            fields.push(("selected_cipher", fields.str(&cipher_name)));
            fields.push(("selected_cipher_id", FieldValue::UInt16(sh.cipher.0)));

            // Selected compression
            fields.push(("selected_compression", FieldValue::UInt8(sh.compression.0)));

            // Parse extensions
            if let Some(ext_data) = sh.ext {
                fields.push((
                    "extensions_length",
                    FieldValue::UInt16(ext_data.len() as u16),
                ));
                parse_extensions(ext_data, fields, false);

                // Compute JA3S fingerprint
                let ja3s_string = compute_ja3s(sh);
                let ja3s_hash = format!("{:x}", md5::compute(&ja3s_string));
                fields.push(("ja3s", fields.str(&ja3s_string)));
                fields.push(("ja3s_hash", fields.str(&ja3s_hash)));
            }
        }
        TlsMessageHandshake::Certificate(cert) => {
            fields.push(("handshake_type", FieldValue::UInt8(11)));
            fields.push((
                "certificate_count",
                FieldValue::UInt16(cert.cert_chain.len() as u16),
            ));
        }
        TlsMessageHandshake::ServerKeyExchange(_) => {
            fields.push(("handshake_type", FieldValue::UInt8(12)));
        }
        TlsMessageHandshake::CertificateRequest(_) => {
            fields.push(("handshake_type", FieldValue::UInt8(13)));
        }
        TlsMessageHandshake::ServerDone(_) => {
            fields.push(("handshake_type", FieldValue::UInt8(14)));
        }
        TlsMessageHandshake::CertificateVerify(_) => {
            fields.push(("handshake_type", FieldValue::UInt8(15)));
        }
        TlsMessageHandshake::ClientKeyExchange(_) => {
            fields.push(("handshake_type", FieldValue::UInt8(16)));
        }
        TlsMessageHandshake::Finished(_) => {
            fields.push(("handshake_type", FieldValue::UInt8(20)));
        }
        TlsMessageHandshake::CertificateStatus(_) => {
            fields.push(("handshake_type", FieldValue::UInt8(22)));
        }
        TlsMessageHandshake::NextProtocol(_) => {
            fields.push(("handshake_type", FieldValue::UInt8(67)));
        }
        TlsMessageHandshake::KeyUpdate(_) => {
            fields.push(("handshake_type", FieldValue::UInt8(24)));
        }
        TlsMessageHandshake::HelloRetryRequest(_) => {
            fields.push(("handshake_type", FieldValue::UInt8(6)));
        }
        TlsMessageHandshake::EndOfEarlyData => {
            fields.push(("handshake_type", FieldValue::UInt8(5)));
        }
        TlsMessageHandshake::NewSessionTicket(_) => {
            fields.push(("handshake_type", FieldValue::UInt8(4)));
        }
        TlsMessageHandshake::HelloRequest => {
            fields.push(("handshake_type", FieldValue::UInt8(0)));
        }
        TlsMessageHandshake::ServerHelloV13Draft18(_) => {
            // Draft TLS 1.3 server hello
            fields.push(("handshake_type", FieldValue::UInt8(2)));
        }
    }
}

/// Parse TLS extensions and extract relevant fields.
fn parse_extensions(ext_data: &[u8], fields: &mut FieldSink<'_, '_>, _is_client: bool) {
    if let Ok((_, extensions)) = parse_tls_extensions(ext_data) {
        // Collect extension types for analysis
        let mut ext_types: Vec<u16> = Vec::new();

        for ext in &extensions {
            let ext_type = get_extension_type(ext);
            ext_types.push(ext_type);

            match ext {
                TlsExtension::SNI(sni_list) => {
                    // Extract first hostname from SNI list
                    for (name_type, name_data) in sni_list {
                        if name_type.0 == 0 {
                            // Hostname type
                            if let Ok(hostname) = std::str::from_utf8(name_data) {
                                fields.push(("sni", fields.str(hostname)));
                                break;
                            }
                        }
                    }
                }
                TlsExtension::ALPN(alpn_list) => {
                    let protocols: Vec<&str> = alpn_list
                        .iter()
                        .filter_map(|p| std::str::from_utf8(p).ok())
                        .collect();
                    if !protocols.is_empty() {
                        fields.push(("alpn", fields.str(&protocols.join(";"))));
                    }
                }
                TlsExtension::SupportedVersions(versions) => {
                    let versions = versions.iter().map(|v| tls_version_name(v.0));
                    if let Some(versions) = name_list(fields, versions) {
                        fields.push(("supported_versions", versions));
                    }
                }
                TlsExtension::SignatureAlgorithms(algs) => {
                    let schemes = algs.iter().map(|a| tls_signature_scheme_name(*a));
                    if let Some(schemes) = name_list(fields, schemes) {
                        fields.push(("signature_algorithms", schemes));
                    }
                }
                TlsExtension::EllipticCurves(curves) => {
                    let groups = curves.iter().map(|c| tls_named_group_name(c.0));
                    if let Some(groups) = name_list(fields, groups) {
                        fields.push(("supported_groups", groups));
                    }
                }
                TlsExtension::EcPointFormats(formats) => {
                    let formats = formats.iter().map(|f| tls_ec_point_format_name(*f));
                    if let Some(formats) = name_list(fields, formats) {
                        fields.push(("ec_point_formats", formats));
                    }
                }
                _ => {}
            }
        }

        // Store extension types list
        if !ext_types.is_empty() {
            let types_str: Vec<String> = ext_types.iter().map(|t| t.to_string()).collect();
            fields.push(("extension_types", fields.str(&types_str.join(","))));
        }
    }
}

/// Get the numeric extension type.
fn get_extension_type(ext: &TlsExtension) -> u16 {
    match ext {
        TlsExtension::SNI(_) => 0,
        TlsExtension::MaxFragmentLength(_) => 1,
        TlsExtension::StatusRequest(_) => 5,
        TlsExtension::EllipticCurves(_) => 10,
        TlsExtension::EcPointFormats(_) => 11,
        TlsExtension::SignatureAlgorithms(_) => 13,
        TlsExtension::Heartbeat(_) => 15,
        TlsExtension::ALPN(_) => 16,
        TlsExtension::SignedCertificateTimestamp(_) => 18,
        TlsExtension::Padding(_) => 21,
        TlsExtension::EncryptThenMac => 22,
        TlsExtension::ExtendedMasterSecret => 23,
        TlsExtension::SessionTicket(_) => 35,
        TlsExtension::PreSharedKey(_) => 41,
        TlsExtension::EarlyData(_) => 42,
        TlsExtension::SupportedVersions(_) => 43,
        TlsExtension::Cookie(_) => 44,
        TlsExtension::PskExchangeModes(_) => 45,
        TlsExtension::OidFilters(_) => 48,
        TlsExtension::PostHandshakeAuth => 49,
        TlsExtension::KeyShare(_) | TlsExtension::KeyShareOld(_) => 51,
        TlsExtension::RenegotiationInfo(_) => 65281,
        TlsExtension::EncryptedServerName { .. } => 65486,
        TlsExtension::Grease(grease, _) => *grease,
        TlsExtension::Unknown(t, _) => t.0,
        _ => 65535,
    }
}

/// Compute JA3 fingerprint string for Client Hello.
///
/// JA3 format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
fn compute_ja3(ch: &tls_parser::TlsClientHelloContents) -> String {
    // SSL/TLS Version
    let version = ch.version.0;

    // Cipher suites (excluding GREASE values)
    let ciphers: Vec<String> = ch
        .ciphers
        .iter()
        .filter(|c| !is_grease_value(c.0))
        .map(|c| c.0.to_string())
        .collect();

    // Parse extensions to get types, curves, and point formats
    let mut ext_types: Vec<u16> = Vec::new();
    let mut curves: Vec<u16> = Vec::new();
    let mut point_formats: Vec<u8> = Vec::new();

    if let Some(ext_data) = ch.ext {
        if let Ok((_, extensions)) = parse_tls_extensions(ext_data) {
            for ext in &extensions {
                let ext_type = get_extension_type(ext);
                if !is_grease_value(ext_type) {
                    ext_types.push(ext_type);
                }

                match ext {
                    TlsExtension::EllipticCurves(c) => {
                        curves.extend(c.iter().filter(|v| !is_grease_value(v.0)).map(|v| v.0));
                    }
                    TlsExtension::EcPointFormats(f) => {
                        point_formats.extend(f.iter());
                    }
                    _ => {}
                }
            }
        }
    }

    format!(
        "{},{},{},{},{}",
        version,
        ciphers.join("-"),
        ext_types
            .iter()
            .map(|t| t.to_string())
            .collect::<Vec<_>>()
            .join("-"),
        curves
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-"),
        point_formats
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join("-"),
    )
}

/// Compute JA3S fingerprint string for Server Hello.
///
/// JA3S format: SSLVersion,Cipher,Extensions
fn compute_ja3s(sh: &tls_parser::TlsServerHelloContents) -> String {
    // SSL/TLS Version
    let version = sh.version.0;

    // Selected cipher
    let cipher = sh.cipher.0;

    // Extension types (excluding GREASE)
    let mut ext_types: Vec<u16> = Vec::new();

    if let Some(ext_data) = sh.ext {
        if let Ok((_, extensions)) = parse_tls_extensions(ext_data) {
            for ext in &extensions {
                let ext_type = get_extension_type(ext);
                if !is_grease_value(ext_type) {
                    ext_types.push(ext_type);
                }
            }
        }
    }

    format!(
        "{},{},{}",
        version,
        cipher,
        ext_types
            .iter()
            .map(|t| t.to_string())
            .collect::<Vec<_>>()
            .join("-"),
    )
}

/// Check if a value is a GREASE value (used to prevent ossification).
fn is_grease_value(val: u16) -> bool {
    // GREASE values are: 0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa
    val & 0x0f0f == 0x0a0a
}

/// The names joined by `;`, written into the arena; `None` when there are
/// none.
fn name_list<'a>(
    fields: &FieldSink<'_, 'a>,
    names: impl Iterator<Item = Name>,
) -> Option<FieldValue<'a>> {
    let mut list = fields.text_builder();
    for name in names {
        if !list.is_empty() {
            list.push_str(";");
        }
        // Writing to an arena string does not fail.
        let _ = write!(list, "{name}");
    }
    (!list.is_empty()).then(|| list.finish())
}

/// Get cipher suite name from ID using tls-parser's IANA database.
fn cipher_suite_name(id: u16) -> String {
    if is_grease_value(id) {
        return format!("GREASE (0x{id:04x})");
    }

    TlsCipherSuite::from_id(id)
        .map(|cs| cs.name.to_string())
        .unwrap_or_else(|| format!("0x{id:04X}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::test_utils::ParseLayer as _;

    /// Create a minimal TLS Client Hello with SNI.
    fn create_tls_client_hello() -> Vec<u8> {
        let mut packet = Vec::new();

        // TLS Record Header
        packet.push(22); // Content type: Handshake
        packet.push(0x03); // Version major (TLS 1.2)
        packet.push(0x03); // Version minor

        // We'll calculate length later
        let length_pos = packet.len();
        packet.push(0x00); // Length high byte (placeholder)
        packet.push(0x00); // Length low byte (placeholder)

        let handshake_start = packet.len();

        // Handshake Header
        packet.push(1); // Type: Client Hello
        packet.push(0x00); // Length (3 bytes, placeholder)
        packet.push(0x00);
        packet.push(0x00);

        let hello_start = packet.len();

        // Client Hello body
        packet.push(0x03); // Version major
        packet.push(0x03); // Version minor

        // Random (32 bytes)
        packet.extend_from_slice(&[0x01; 32]);

        // Session ID (0 length)
        packet.push(0x00);

        // Cipher Suites (6 bytes = 3 suites)
        packet.push(0x00);
        packet.push(0x06);
        packet.extend_from_slice(&0xC02Fu16.to_be_bytes()); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        packet.extend_from_slice(&0xC030u16.to_be_bytes()); // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        packet.extend_from_slice(&0x1301u16.to_be_bytes()); // TLS_AES_128_GCM_SHA256

        // Compression methods (1 = null)
        packet.push(0x01);
        packet.push(0x00);

        // Extensions
        let extensions_len_pos = packet.len();
        packet.push(0x00); // Extensions length (placeholder)
        packet.push(0x00);

        let extensions_start = packet.len();

        // SNI Extension (type 0)
        packet.extend_from_slice(&0u16.to_be_bytes()); // Extension type

        let hostname = b"www.example.com";
        let sni_ext_len = 2 + 1 + 2 + hostname.len(); // list_len + type + name_len + name
        packet.extend_from_slice(&(sni_ext_len as u16).to_be_bytes()); // Extension length

        // SNI List
        let sni_list_len = 1 + 2 + hostname.len(); // type + name_len + name
        packet.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        packet.push(0x00); // Name type = hostname
        packet.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        packet.extend_from_slice(hostname);

        // Fix up lengths
        let extensions_len = packet.len() - extensions_start;
        packet[extensions_len_pos] = (extensions_len >> 8) as u8;
        packet[extensions_len_pos + 1] = (extensions_len & 0xFF) as u8;

        let hello_len = packet.len() - hello_start;
        packet[handshake_start + 1] = ((hello_len >> 16) & 0xFF) as u8;
        packet[handshake_start + 2] = ((hello_len >> 8) & 0xFF) as u8;
        packet[handshake_start + 3] = (hello_len & 0xFF) as u8;

        let record_len = packet.len() - handshake_start;
        packet[length_pos] = (record_len >> 8) as u8;
        packet[length_pos + 1] = (record_len & 0xFF) as u8;

        packet
    }

    /// Create a minimal TLS Server Hello.
    fn create_tls_server_hello() -> Vec<u8> {
        let mut packet = Vec::new();

        // TLS Record Header
        packet.push(22); // Handshake
        packet.push(0x03); // Version major
        packet.push(0x03); // Version minor

        let length_pos = packet.len();
        packet.push(0x00);
        packet.push(0x00);

        let handshake_start = packet.len();

        // Handshake Header
        packet.push(2); // Server Hello
        packet.push(0x00);
        packet.push(0x00);
        packet.push(0x00);

        let hello_start = packet.len();

        // Server Hello body
        packet.push(0x03); // Version major
        packet.push(0x03); // Version minor

        // Random (32 bytes)
        packet.extend_from_slice(&[0x02; 32]);

        // Session ID (0 length)
        packet.push(0x00);

        // Selected cipher suite
        packet.extend_from_slice(&0xC02Fu16.to_be_bytes()); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

        // Compression method
        packet.push(0x00);

        // Fix up lengths
        let hello_len = packet.len() - hello_start;
        packet[handshake_start + 1] = ((hello_len >> 16) & 0xFF) as u8;
        packet[handshake_start + 2] = ((hello_len >> 8) & 0xFF) as u8;
        packet[handshake_start + 3] = (hello_len & 0xFF) as u8;

        let record_len = packet.len() - handshake_start;
        packet[length_pos] = (record_len >> 8) as u8;
        packet[length_pos + 1] = (record_len & 0xFF) as u8;

        packet
    }

    /// Create a TLS Alert record.
    fn create_tls_alert() -> Vec<u8> {
        vec![
            21, // Record type: Alert
            0x03, 0x03, // Version: TLS 1.2
            0x00, 0x02, // Length: 2
            0x02, // Level: Fatal
            0x28, // Description: Handshake Failure (40)
        ]
    }

    #[test]
    fn test_can_parse_tls_by_port() {
        let parser = TlsProtocol;

        // Without hint
        let ctx1 = ParseContext::new(1);
        assert!(parser.can_parse(&ctx1).is_none());

        // With dst_port 443 over TCP
        let mut ctx2 = ParseContext::new(1);
        ctx2.insert_hint(HintKey::DstPort, 443);
        ctx2.insert_hint(HintKey::Transport, 6);
        assert!(parser.can_parse(&ctx2).is_some());

        // With src_port 443 over TCP
        let mut ctx3 = ParseContext::new(1);
        ctx3.insert_hint(HintKey::SrcPort, 443);
        ctx3.insert_hint(HintKey::Transport, 6);
        assert!(parser.can_parse(&ctx3).is_some());

        // With other TLS ports
        let mut ctx4 = ParseContext::new(1);
        ctx4.insert_hint(HintKey::DstPort, 8443);
        ctx4.insert_hint(HintKey::Transport, 6);
        assert!(parser.can_parse(&ctx4).is_some());

        // UDP 443 is QUIC's, not TLS's
        let mut ctx5 = ParseContext::new(1);
        ctx5.insert_hint(HintKey::DstPort, 443);
        ctx5.insert_hint(HintKey::Transport, 17);
        assert!(parser.can_parse(&ctx5).is_none());
    }

    #[test]
    fn test_parse_tls_client_hello() {
        let packet = create_tls_client_hello();

        let parser = TlsProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint(HintKey::DstPort, 443);

        let result = parser.parse_layer(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("record_type"), Some(&FieldValue::UInt8(22)));
        assert_eq!(result.get("version"), Some(&FieldValue::Str("TLS 1.2")));
        assert_eq!(result.get("handshake_type"), Some(&FieldValue::UInt8(1)));

        // Verify client_random is extracted (decryption foundation)
        if let Some(FieldValue::Bytes(random)) = result.get("client_random") {
            assert_eq!(random.len(), 32);
            assert_eq!(random[0], 0x01);
        } else {
            panic!("client_random not found or wrong type");
        }
    }

    #[test]
    fn test_parse_tls_server_hello() {
        let packet = create_tls_server_hello();

        let parser = TlsProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint(HintKey::SrcPort, 443);

        let result = parser.parse_layer(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("handshake_type"), Some(&FieldValue::UInt8(2)));
        assert_eq!(
            result.get("selected_cipher"),
            Some(&FieldValue::Str("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"))
        );
        assert_eq!(
            result.get("selected_cipher_id"),
            Some(&FieldValue::UInt16(0xC02F))
        );

        // Verify server_random is extracted (decryption foundation)
        if let Some(FieldValue::Bytes(random)) = result.get("server_random") {
            assert_eq!(random.len(), 32);
            assert_eq!(random[0], 0x02);
        } else {
            panic!("server_random not found or wrong type");
        }
    }

    #[test]
    fn test_extract_sni() {
        let packet = create_tls_client_hello();

        let parser = TlsProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint(HintKey::DstPort, 443);

        let result = parser.parse_layer(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("sni"), Some(&FieldValue::Str("www.example.com")));
    }

    #[test]
    fn test_parse_tls_alert() {
        let packet = create_tls_alert();

        let parser = TlsProtocol;
        let context = ParseContext::new(1);

        let result = parser.parse_layer(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("record_type"), Some(&FieldValue::UInt8(21)));
        assert_eq!(result.get("alert_level"), Some(&FieldValue::UInt8(2)));
        assert_eq!(
            result.get("alert_description"),
            Some(&FieldValue::UInt8(40))
        );
        assert_eq!(
            result.get("alert_description_str"),
            Some(&FieldValue::Str("handshake_failure"))
        );
    }

    #[test]
    fn test_cipher_suite_names() {
        // Test that common cipher suites are properly named via tls-parser
        assert_eq!(cipher_suite_name(0x1301), "TLS_AES_128_GCM_SHA256");
        assert_eq!(cipher_suite_name(0x1302), "TLS_AES_256_GCM_SHA384");
        assert_eq!(
            cipher_suite_name(0xC02F),
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        );
        assert_eq!(
            cipher_suite_name(0xC030),
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        );
    }

    #[test]
    fn test_grease_detection() {
        assert!(is_grease_value(0x0a0a));
        assert!(is_grease_value(0x1a1a));
        assert!(is_grease_value(0x2a2a));
        assert!(is_grease_value(0xfafa));
        assert!(!is_grease_value(0x0001));
        assert!(!is_grease_value(0xC02F));
    }

    #[test]
    fn test_ja3_computation() {
        let packet = create_tls_client_hello();

        let parser = TlsProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint(HintKey::DstPort, 443);

        let result = parser.parse_layer(&packet, &context);

        assert!(result.is_ok());
        // Verify JA3 fields are present
        assert!(result.get("ja3").is_some());
        assert!(result.get("ja3_hash").is_some());

        // JA3 hash should be 32 hex characters (MD5)
        if let Some(FieldValue::Str(hash)) = result.get("ja3_hash") {
            assert_eq!(hash.len(), 32);
        }
    }

    #[test]
    fn test_tls_schema_fields() {
        let parser = TlsProtocol;
        let fields = parser.schema_fields();

        assert!(!fields.is_empty());

        let field_names: Vec<&str> = fields.iter().map(|f| f.name).collect();

        // Original fields
        assert!(field_names.contains(&"tls.record_type"));
        assert!(field_names.contains(&"tls.version"));
        assert!(field_names.contains(&"tls.sni"));
        assert!(field_names.contains(&"tls.cipher_suites"));

        // New fields
        assert!(field_names.contains(&"tls.client_random"));
        assert!(field_names.contains(&"tls.server_random"));
        assert!(field_names.contains(&"tls.session_id"));
        assert!(field_names.contains(&"tls.ja3"));
        assert!(field_names.contains(&"tls.ja3_hash"));
        assert!(field_names.contains(&"tls.alpn"));
        assert!(field_names.contains(&"tls.supported_versions"));
        assert!(field_names.contains(&"tls.alert_level"));
    }

    #[test]
    fn test_tls_too_short() {
        let short_packet = vec![0x16, 0x03, 0x03]; // Only 3 bytes

        let parser = TlsProtocol;
        let context = ParseContext::new(1);

        let result = parser.parse_layer(&short_packet, &context);

        assert!(!result.is_ok());
    }
}
