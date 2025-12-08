//! SSH protocol parser.
//!
//! Parses SSH (Secure Shell) protocol identification strings and binary packets,
//! particularly KEXINIT messages for algorithm negotiation analysis.

use smallvec::SmallVec;

use super::{FieldValue, ParseContext, ParseResult, Protocol};
use crate::schema::{DataKind, FieldDescriptor};

/// SSH default port.
pub const SSH_PORT: u16 = 22;

/// SSH message types.
mod msg_type {
    pub const SSH_MSG_DISCONNECT: u8 = 1;
    pub const SSH_MSG_IGNORE: u8 = 2;
    pub const SSH_MSG_UNIMPLEMENTED: u8 = 3;
    pub const SSH_MSG_DEBUG: u8 = 4;
    pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;
    pub const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
    pub const SSH_MSG_KEXINIT: u8 = 20;
    pub const SSH_MSG_NEWKEYS: u8 = 21;
    pub const SSH_MSG_KEX_DH_INIT: u8 = 30;
    pub const SSH_MSG_KEX_DH_REPLY: u8 = 31;
    pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
    pub const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
    pub const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
    pub const SSH_MSG_USERAUTH_BANNER: u8 = 53;
    pub const SSH_MSG_CHANNEL_OPEN: u8 = 90;
    pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
    pub const SSH_MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
    pub const SSH_MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
    pub const SSH_MSG_CHANNEL_DATA: u8 = 94;
    pub const SSH_MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
    pub const SSH_MSG_CHANNEL_EOF: u8 = 96;
    pub const SSH_MSG_CHANNEL_CLOSE: u8 = 97;
    pub const SSH_MSG_CHANNEL_REQUEST: u8 = 98;
    pub const SSH_MSG_CHANNEL_SUCCESS: u8 = 99;
    pub const SSH_MSG_CHANNEL_FAILURE: u8 = 100;
}

/// SSH protocol parser.
#[derive(Debug, Clone, Copy)]
pub struct SshProtocol;

impl Protocol for SshProtocol {
    fn name(&self) -> &'static str {
        "ssh"
    }

    fn display_name(&self) -> &'static str {
        "SSH"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        let src_port = context.hint("src_port");
        let dst_port = context.hint("dst_port");

        // Check for SSH port 22
        match (src_port, dst_port) {
            (Some(22), _) | (_, Some(22)) => Some(50),
            _ => None,
        }
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        let mut fields = SmallVec::new();

        // Check if this is an SSH protocol identification string
        if data.starts_with(b"SSH-") {
            return parse_protocol_identification(data, &mut fields);
        }

        // Try to parse as SSH binary packet
        if data.len() < 5 {
            return ParseResult::error("SSH packet too short".to_string(), data);
        }

        let packet_length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;

        // Sanity check on packet length - SSH packets shouldn't exceed 35000 bytes typically
        if packet_length > 35000 || packet_length < 2 {
            // This might be encrypted traffic or not an SSH packet
            fields.push(("encrypted", FieldValue::Bool(true)));
            let remaining_start = data.len().min(4 + packet_length);
            return ParseResult::success(fields, &data[remaining_start..], SmallVec::new());
        }

        let padding_length = data[4] as usize;
        fields.push(("packet_length", FieldValue::UInt32(packet_length as u32)));
        fields.push(("padding_length", FieldValue::UInt8(padding_length as u8)));

        // Check if we have the full packet
        if data.len() < 4 + packet_length {
            return ParseResult::partial(fields, &data[4..], "SSH packet truncated".to_string());
        }

        // Payload starts at offset 5
        let payload_length = packet_length.saturating_sub(padding_length + 1);
        if payload_length == 0 || data.len() < 6 {
            return ParseResult::success(fields, &data[4 + packet_length..], SmallVec::new());
        }

        let msg_type = data[5];
        fields.push(("msg_type", FieldValue::UInt8(msg_type)));
        fields.push((
            "msg_type_name",
            FieldValue::String(format_msg_type(msg_type)),
        ));

        // Parse specific message types
        let payload = &data[5..5 + payload_length];
        match msg_type {
            msg_type::SSH_MSG_KEXINIT => {
                parse_kexinit_message(payload, &mut fields);
            }
            msg_type::SSH_MSG_USERAUTH_REQUEST => {
                parse_userauth_request(payload, &mut fields);
            }
            msg_type::SSH_MSG_CHANNEL_OPEN => {
                parse_channel_open(payload, &mut fields);
            }
            _ => {}
        }

        let remaining = &data[4 + packet_length..];
        ParseResult::success(fields, remaining, SmallVec::new())
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            // Protocol identification
            FieldDescriptor::new("ssh.protocol_version", DataKind::String).set_nullable(true),
            FieldDescriptor::new("ssh.software_version", DataKind::String).set_nullable(true),
            FieldDescriptor::new("ssh.comments", DataKind::String).set_nullable(true),
            // Binary packet
            FieldDescriptor::new("ssh.packet_length", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("ssh.padding_length", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("ssh.msg_type", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("ssh.msg_type_name", DataKind::String).set_nullable(true),
            FieldDescriptor::new("ssh.encrypted", DataKind::Bool).set_nullable(true),
            // KEXINIT
            FieldDescriptor::new("ssh.kex_algorithms", DataKind::String).set_nullable(true),
            FieldDescriptor::new("ssh.host_key_algorithms", DataKind::String).set_nullable(true),
            FieldDescriptor::new("ssh.encryption_algorithms", DataKind::String).set_nullable(true),
            FieldDescriptor::new("ssh.mac_algorithms", DataKind::String).set_nullable(true),
            FieldDescriptor::new("ssh.compression_algorithms", DataKind::String).set_nullable(true),
            // USERAUTH
            FieldDescriptor::new("ssh.auth_username", DataKind::String).set_nullable(true),
            FieldDescriptor::new("ssh.auth_service", DataKind::String).set_nullable(true),
            FieldDescriptor::new("ssh.auth_method", DataKind::String).set_nullable(true),
            // CHANNEL
            FieldDescriptor::new("ssh.channel_type", DataKind::String).set_nullable(true),
            FieldDescriptor::new("ssh.channel_id", DataKind::UInt32).set_nullable(true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        &[]
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &["tcp"]
    }
}

/// Parse SSH protocol identification string.
fn parse_protocol_identification<'a>(
    data: &'a [u8],
    fields: &mut SmallVec<[(&'static str, FieldValue); 16]>,
) -> ParseResult<'a> {
    // Find the end of the identification string (CR LF or just LF)
    let line_end = data.iter().position(|&b| b == b'\n').unwrap_or(data.len());
    let line = &data[..line_end];

    // Remove trailing CR if present
    let line = if line.ends_with(b"\r") {
        &line[..line.len() - 1]
    } else {
        line
    };

    // Parse "SSH-protoversion-softwareversion SP comments"
    if let Ok(line_str) = std::str::from_utf8(line) {
        if line_str.starts_with("SSH-") {
            let content = &line_str[4..]; // Skip "SSH-"

            if let Some(dash_pos) = content.find('-') {
                let proto_version = &content[..dash_pos];
                fields.push((
                    "protocol_version",
                    FieldValue::String(proto_version.to_string()),
                ));

                let rest = &content[dash_pos + 1..];

                // Software version ends at space (if comments follow) or end of line
                if let Some(space_pos) = rest.find(' ') {
                    let software_version = &rest[..space_pos];
                    let comments = rest[space_pos + 1..].trim();

                    fields.push((
                        "software_version",
                        FieldValue::String(software_version.to_string()),
                    ));
                    if !comments.is_empty() {
                        fields.push(("comments", FieldValue::String(comments.to_string())));
                    }
                } else {
                    fields.push(("software_version", FieldValue::String(rest.to_string())));
                }
            }
        }
    }

    // Remaining data after the identification string
    let remaining_start = (line_end + 1).min(data.len());
    ParseResult::success(fields.clone(), &data[remaining_start..], SmallVec::new())
}

/// Parse KEXINIT message to extract algorithm lists.
fn parse_kexinit_message(payload: &[u8], fields: &mut SmallVec<[(&'static str, FieldValue); 16]>) {
    // KEXINIT format:
    // byte      SSH_MSG_KEXINIT (20) - included in payload
    // byte[16]  cookie
    // name-list kex_algorithms
    // name-list server_host_key_algorithms
    // ...
    if payload.len() < 17 {
        return;
    }

    let mut offset = 17; // Skip msg_type (1) + cookie (16)

    // Helper to read a name-list
    let read_name_list = |data: &[u8], off: &mut usize| -> Option<String> {
        if *off + 4 > data.len() {
            return None;
        }
        let len =
            u32::from_be_bytes([data[*off], data[*off + 1], data[*off + 2], data[*off + 3]])
                as usize;
        *off += 4;
        if *off + len > data.len() {
            return None;
        }
        let value = std::str::from_utf8(&data[*off..*off + len])
            .ok()?
            .to_string();
        *off += len;
        Some(value)
    };

    if let Some(kex_algs) = read_name_list(payload, &mut offset) {
        if !kex_algs.is_empty() {
            fields.push(("kex_algorithms", FieldValue::String(kex_algs)));
        }
    }

    if let Some(host_key_algs) = read_name_list(payload, &mut offset) {
        if !host_key_algs.is_empty() {
            fields.push(("host_key_algorithms", FieldValue::String(host_key_algs)));
        }
    }

    if let Some(enc_c2s) = read_name_list(payload, &mut offset) {
        if !enc_c2s.is_empty() {
            fields.push(("encryption_algorithms", FieldValue::String(enc_c2s)));
        }
    }

    // Skip encryption_algorithms_server_to_client
    let _ = read_name_list(payload, &mut offset);

    if let Some(mac_c2s) = read_name_list(payload, &mut offset) {
        if !mac_c2s.is_empty() {
            fields.push(("mac_algorithms", FieldValue::String(mac_c2s)));
        }
    }

    // Skip mac_algorithms_server_to_client
    let _ = read_name_list(payload, &mut offset);

    if let Some(comp_c2s) = read_name_list(payload, &mut offset) {
        if !comp_c2s.is_empty() {
            fields.push(("compression_algorithms", FieldValue::String(comp_c2s)));
        }
    }
}

/// Parse USERAUTH_REQUEST message.
fn parse_userauth_request(payload: &[u8], fields: &mut SmallVec<[(&'static str, FieldValue); 16]>) {
    if payload.len() < 5 {
        return;
    }

    let mut offset = 1; // Skip msg_type

    let read_string = |data: &[u8], off: &mut usize| -> Option<String> {
        if *off + 4 > data.len() {
            return None;
        }
        let len =
            u32::from_be_bytes([data[*off], data[*off + 1], data[*off + 2], data[*off + 3]])
                as usize;
        *off += 4;
        if *off + len > data.len() {
            return None;
        }
        let value = std::str::from_utf8(&data[*off..*off + len])
            .ok()?
            .to_string();
        *off += len;
        Some(value)
    };

    if let Some(username) = read_string(payload, &mut offset) {
        if !username.is_empty() {
            fields.push(("auth_username", FieldValue::String(username)));
        }
    }

    if let Some(service) = read_string(payload, &mut offset) {
        if !service.is_empty() {
            fields.push(("auth_service", FieldValue::String(service)));
        }
    }

    if let Some(method) = read_string(payload, &mut offset) {
        if !method.is_empty() {
            fields.push(("auth_method", FieldValue::String(method)));
        }
    }
}

/// Parse CHANNEL_OPEN message.
fn parse_channel_open(payload: &[u8], fields: &mut SmallVec<[(&'static str, FieldValue); 16]>) {
    if payload.len() < 5 {
        return;
    }

    let mut offset = 1; // Skip msg_type

    // Read channel type string
    if offset + 4 > payload.len() {
        return;
    }
    let len =
        u32::from_be_bytes([payload[offset], payload[offset + 1], payload[offset + 2], payload[offset + 3]])
            as usize;
    offset += 4;

    if offset + len > payload.len() {
        return;
    }

    if let Ok(channel_type) = std::str::from_utf8(&payload[offset..offset + len]) {
        if !channel_type.is_empty() {
            fields.push(("channel_type", FieldValue::String(channel_type.to_string())));
        }
    }
    offset += len;

    // Read sender channel ID
    if offset + 4 <= payload.len() {
        let channel_id = u32::from_be_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
        ]);
        fields.push(("channel_id", FieldValue::UInt32(channel_id)));
    }
}

/// Format SSH message type as a readable name.
fn format_msg_type(msg_type: u8) -> String {
    match msg_type {
        msg_type::SSH_MSG_DISCONNECT => "DISCONNECT".to_string(),
        msg_type::SSH_MSG_IGNORE => "IGNORE".to_string(),
        msg_type::SSH_MSG_UNIMPLEMENTED => "UNIMPLEMENTED".to_string(),
        msg_type::SSH_MSG_DEBUG => "DEBUG".to_string(),
        msg_type::SSH_MSG_SERVICE_REQUEST => "SERVICE_REQUEST".to_string(),
        msg_type::SSH_MSG_SERVICE_ACCEPT => "SERVICE_ACCEPT".to_string(),
        msg_type::SSH_MSG_KEXINIT => "KEXINIT".to_string(),
        msg_type::SSH_MSG_NEWKEYS => "NEWKEYS".to_string(),
        msg_type::SSH_MSG_KEX_DH_INIT => "KEX_DH_INIT".to_string(),
        msg_type::SSH_MSG_KEX_DH_REPLY => "KEX_DH_REPLY".to_string(),
        msg_type::SSH_MSG_USERAUTH_REQUEST => "USERAUTH_REQUEST".to_string(),
        msg_type::SSH_MSG_USERAUTH_FAILURE => "USERAUTH_FAILURE".to_string(),
        msg_type::SSH_MSG_USERAUTH_SUCCESS => "USERAUTH_SUCCESS".to_string(),
        msg_type::SSH_MSG_USERAUTH_BANNER => "USERAUTH_BANNER".to_string(),
        msg_type::SSH_MSG_CHANNEL_OPEN => "CHANNEL_OPEN".to_string(),
        msg_type::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => "CHANNEL_OPEN_CONFIRMATION".to_string(),
        msg_type::SSH_MSG_CHANNEL_OPEN_FAILURE => "CHANNEL_OPEN_FAILURE".to_string(),
        msg_type::SSH_MSG_CHANNEL_WINDOW_ADJUST => "CHANNEL_WINDOW_ADJUST".to_string(),
        msg_type::SSH_MSG_CHANNEL_DATA => "CHANNEL_DATA".to_string(),
        msg_type::SSH_MSG_CHANNEL_EXTENDED_DATA => "CHANNEL_EXTENDED_DATA".to_string(),
        msg_type::SSH_MSG_CHANNEL_EOF => "CHANNEL_EOF".to_string(),
        msg_type::SSH_MSG_CHANNEL_CLOSE => "CHANNEL_CLOSE".to_string(),
        msg_type::SSH_MSG_CHANNEL_REQUEST => "CHANNEL_REQUEST".to_string(),
        msg_type::SSH_MSG_CHANNEL_SUCCESS => "CHANNEL_SUCCESS".to_string(),
        msg_type::SSH_MSG_CHANNEL_FAILURE => "CHANNEL_FAILURE".to_string(),
        _ => format!("UNKNOWN({})", msg_type),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_ssh_identification(proto: &str, software: &str, comments: Option<&str>) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(b"SSH-");
        packet.extend_from_slice(proto.as_bytes());
        packet.push(b'-');
        packet.extend_from_slice(software.as_bytes());
        if let Some(c) = comments {
            packet.push(b' ');
            packet.extend_from_slice(c.as_bytes());
        }
        packet.extend_from_slice(b"\r\n");
        packet
    }

    fn create_ssh_packet(msg_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();

        let payload_size = 1 + payload.len();
        let padding_needed = {
            let base = 4 + 1 + payload_size;
            let remainder = base % 8;
            if remainder == 0 {
                8
            } else {
                8 - remainder
            }
        };
        let padding_length = padding_needed.max(4);
        let packet_length = 1 + 1 + payload.len() + padding_length;

        packet.extend_from_slice(&(packet_length as u32).to_be_bytes());
        packet.push(padding_length as u8);
        packet.push(msg_type);
        packet.extend_from_slice(payload);
        packet.extend(std::iter::repeat(0u8).take(padding_length));

        packet
    }

    fn create_kexinit_payload() -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0u8; 16]); // Cookie

        let write_name_list = |buf: &mut Vec<u8>, list: &str| {
            buf.extend_from_slice(&(list.len() as u32).to_be_bytes());
            buf.extend_from_slice(list.as_bytes());
        };

        write_name_list(&mut payload, "curve25519-sha256,diffie-hellman-group14-sha256");
        write_name_list(&mut payload, "ssh-ed25519,rsa-sha2-512");
        write_name_list(
            &mut payload,
            "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com",
        );
        write_name_list(
            &mut payload,
            "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com",
        );
        write_name_list(
            &mut payload,
            "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com",
        );
        write_name_list(
            &mut payload,
            "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com",
        );
        write_name_list(&mut payload, "none,zlib@openssh.com");
        write_name_list(&mut payload, "none,zlib@openssh.com");
        write_name_list(&mut payload, "");
        write_name_list(&mut payload, "");
        payload.push(0); // first_kex_packet_follows
        payload.extend_from_slice(&[0u8; 4]); // reserved

        payload
    }

    #[test]
    fn test_can_parse_ssh_by_port() {
        let parser = SshProtocol;

        let ctx1 = ParseContext::new(1);
        assert!(parser.can_parse(&ctx1).is_none());

        let mut ctx2 = ParseContext::new(1);
        ctx2.insert_hint("dst_port", 22);
        assert!(parser.can_parse(&ctx2).is_some());

        let mut ctx3 = ParseContext::new(1);
        ctx3.insert_hint("src_port", 22);
        assert!(parser.can_parse(&ctx3).is_some());
    }

    #[test]
    fn test_parse_ssh_identification_string() {
        let packet = create_ssh_identification("2.0", "OpenSSH_8.9p1", Some("Ubuntu-3ubuntu0.1"));

        let parser = SshProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 22);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("protocol_version"),
            Some(&FieldValue::String("2.0".to_string()))
        );
        assert_eq!(
            result.get("software_version"),
            Some(&FieldValue::String("OpenSSH_8.9p1".to_string()))
        );
        assert_eq!(
            result.get("comments"),
            Some(&FieldValue::String("Ubuntu-3ubuntu0.1".to_string()))
        );
    }

    #[test]
    fn test_parse_client_identification() {
        let packet = create_ssh_identification("2.0", "libssh2_1.10.0", None);

        let parser = SshProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 22);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("protocol_version"),
            Some(&FieldValue::String("2.0".to_string()))
        );
        assert_eq!(
            result.get("software_version"),
            Some(&FieldValue::String("libssh2_1.10.0".to_string()))
        );
        assert!(result.get("comments").is_none());
    }

    #[test]
    fn test_parse_server_identification() {
        let packet = create_ssh_identification("2.0", "dropbear_2022.83", None);

        let parser = SshProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("src_port", 22);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("protocol_version"),
            Some(&FieldValue::String("2.0".to_string()))
        );
        assert_eq!(
            result.get("software_version"),
            Some(&FieldValue::String("dropbear_2022.83".to_string()))
        );
    }

    #[test]
    fn test_protocol_version_extraction() {
        let packet = create_ssh_identification("1.99", "OpenSSH_7.9", None);

        let parser = SshProtocol;
        let context = ParseContext::new(1);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("protocol_version"),
            Some(&FieldValue::String("1.99".to_string()))
        );
    }

    #[test]
    fn test_software_version_extraction() {
        let packet = create_ssh_identification("2.0", "PuTTY_Release_0.78", None);

        let parser = SshProtocol;
        let context = ParseContext::new(1);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("software_version"),
            Some(&FieldValue::String("PuTTY_Release_0.78".to_string()))
        );
    }

    #[test]
    fn test_parse_kexinit_message() {
        let kexinit_payload = create_kexinit_payload();
        let packet = create_ssh_packet(msg_type::SSH_MSG_KEXINIT, &kexinit_payload);

        let parser = SshProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 22);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("msg_type"),
            Some(&FieldValue::UInt8(msg_type::SSH_MSG_KEXINIT))
        );
        assert_eq!(
            result.get("msg_type_name"),
            Some(&FieldValue::String("KEXINIT".to_string()))
        );
    }

    #[test]
    fn test_kex_algorithms_extraction() {
        let kexinit_payload = create_kexinit_payload();
        let packet = create_ssh_packet(msg_type::SSH_MSG_KEXINIT, &kexinit_payload);

        let parser = SshProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 22);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("kex_algorithms"),
            Some(&FieldValue::String(
                "curve25519-sha256,diffie-hellman-group14-sha256".to_string()
            ))
        );
    }

    #[test]
    fn test_encryption_algorithms_extraction() {
        let kexinit_payload = create_kexinit_payload();
        let packet = create_ssh_packet(msg_type::SSH_MSG_KEXINIT, &kexinit_payload);

        let parser = SshProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 22);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("encryption_algorithms"),
            Some(&FieldValue::String(
                "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com".to_string()
            ))
        );
    }

    #[test]
    fn test_newkeys_detection() {
        let packet = create_ssh_packet(msg_type::SSH_MSG_NEWKEYS, &[]);

        let parser = SshProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 22);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("msg_type"),
            Some(&FieldValue::UInt8(msg_type::SSH_MSG_NEWKEYS))
        );
        assert_eq!(
            result.get("msg_type_name"),
            Some(&FieldValue::String("NEWKEYS".to_string()))
        );
    }

    #[test]
    fn test_post_encryption_packet_size() {
        let mut packet = Vec::new();
        let encrypted_length: u32 = 128;
        packet.extend_from_slice(&encrypted_length.to_be_bytes());
        packet.push(16);
        packet.extend(std::iter::repeat(0xFFu8).take(127));

        let parser = SshProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 22);

        let result = parser.parse(&packet, &context);

        assert_eq!(result.get("packet_length"), Some(&FieldValue::UInt32(128)));
    }

    #[test]
    fn test_ssh_schema_fields() {
        let parser = SshProtocol;
        let fields = parser.schema_fields();

        assert!(!fields.is_empty());

        let field_names: Vec<&str> = fields.iter().map(|f| f.name).collect();
        assert!(field_names.contains(&"ssh.protocol_version"));
        assert!(field_names.contains(&"ssh.software_version"));
        assert!(field_names.contains(&"ssh.msg_type"));
        assert!(field_names.contains(&"ssh.kex_algorithms"));
        assert!(field_names.contains(&"ssh.encryption_algorithms"));
    }

    #[test]
    fn test_ssh_too_short() {
        let short_packet = vec![0x00, 0x00, 0x00];

        let parser = SshProtocol;
        let context = ParseContext::new(1);

        let result = parser.parse(&short_packet, &context);

        assert!(!result.is_ok());
    }

    #[test]
    fn test_userauth_request_parsing() {
        let mut payload = Vec::new();
        let username = b"testuser";
        payload.extend_from_slice(&(username.len() as u32).to_be_bytes());
        payload.extend_from_slice(username);
        let service = b"ssh-connection";
        payload.extend_from_slice(&(service.len() as u32).to_be_bytes());
        payload.extend_from_slice(service);
        let method = b"publickey";
        payload.extend_from_slice(&(method.len() as u32).to_be_bytes());
        payload.extend_from_slice(method);

        let packet = create_ssh_packet(msg_type::SSH_MSG_USERAUTH_REQUEST, &payload);

        let parser = SshProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 22);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("msg_type"),
            Some(&FieldValue::UInt8(msg_type::SSH_MSG_USERAUTH_REQUEST))
        );
        assert_eq!(
            result.get("auth_username"),
            Some(&FieldValue::String("testuser".to_string()))
        );
        assert_eq!(
            result.get("auth_service"),
            Some(&FieldValue::String("ssh-connection".to_string()))
        );
        assert_eq!(
            result.get("auth_method"),
            Some(&FieldValue::String("publickey".to_string()))
        );
    }

    #[test]
    fn test_channel_open_parsing() {
        let mut payload = Vec::new();
        let channel_type = b"session";
        payload.extend_from_slice(&(channel_type.len() as u32).to_be_bytes());
        payload.extend_from_slice(channel_type);
        let channel_id: u32 = 0;
        payload.extend_from_slice(&channel_id.to_be_bytes());
        payload.extend_from_slice(&0x00200000u32.to_be_bytes());
        payload.extend_from_slice(&0x00008000u32.to_be_bytes());

        let packet = create_ssh_packet(msg_type::SSH_MSG_CHANNEL_OPEN, &payload);

        let parser = SshProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 22);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("channel_type"),
            Some(&FieldValue::String("session".to_string()))
        );
        assert_eq!(result.get("channel_id"), Some(&FieldValue::UInt32(0)));
    }
}
