//! SSH table schema definition.
//!
//! The `ssh` table contains SSH protocol fields including version identification,
//! binary packet headers, key exchange, authentication, and channel information.

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `ssh` table.
///
/// Fields:
/// - `frame_number`: Reference to frames table
/// - `protocol_version`: SSH protocol version (e.g., "2.0")
/// - `software_version`: Software version string (e.g., "OpenSSH_8.9p1")
/// - `comments`: Optional comments from identification string
/// - `packet_length`: Binary packet length
/// - `padding_length`: Padding length in binary packet
/// - `msg_type`: SSH message type number
/// - `msg_type_name`: Human-readable message type name
/// - `encrypted`: True if packet appears to be encrypted
/// - `kex_algorithms`: Key exchange algorithms (from KEXINIT)
/// - `host_key_algorithms`: Host key algorithms (from KEXINIT)
/// - `encryption_algorithms`: Encryption algorithms (from KEXINIT)
/// - `mac_algorithms`: MAC algorithms (from KEXINIT)
/// - `compression_algorithms`: Compression algorithms (from KEXINIT)
/// - `auth_username`: Username from USERAUTH_REQUEST
/// - `auth_service`: Service name from USERAUTH_REQUEST
/// - `auth_method`: Authentication method from USERAUTH_REQUEST
/// - `channel_type`: Channel type from CHANNEL_OPEN
/// - `channel_id`: Channel ID from CHANNEL_OPEN
pub fn ssh_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        // Protocol identification
        Field::new("protocol_version", DataType::Utf8, true),
        Field::new("software_version", DataType::Utf8, true),
        Field::new("comments", DataType::Utf8, true),
        // Binary packet
        Field::new("packet_length", DataType::UInt32, true),
        Field::new("padding_length", DataType::UInt8, true),
        Field::new("msg_type", DataType::UInt8, true),
        Field::new("msg_type_name", DataType::Utf8, true),
        Field::new("encrypted", DataType::Boolean, true),
        // KEXINIT
        Field::new("kex_algorithms", DataType::Utf8, true),
        Field::new("host_key_algorithms", DataType::Utf8, true),
        Field::new("encryption_algorithms", DataType::Utf8, true),
        Field::new("mac_algorithms", DataType::Utf8, true),
        Field::new("compression_algorithms", DataType::Utf8, true),
        // USERAUTH
        Field::new("auth_username", DataType::Utf8, true),
        Field::new("auth_service", DataType::Utf8, true),
        Field::new("auth_method", DataType::Utf8, true),
        // CHANNEL
        Field::new("channel_type", DataType::Utf8, true),
        Field::new("channel_id", DataType::UInt32, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_schema() {
        let schema = ssh_table_schema();

        assert_eq!(schema.fields().len(), 19);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("protocol_version").is_ok());
        assert!(schema.field_with_name("software_version").is_ok());
        assert!(schema.field_with_name("msg_type").is_ok());
        assert!(schema.field_with_name("kex_algorithms").is_ok());
        assert!(schema.field_with_name("encryption_algorithms").is_ok());
        assert!(schema.field_with_name("auth_username").is_ok());
        assert!(schema.field_with_name("channel_type").is_ok());
    }

    #[test]
    fn test_no_protocol_prefix() {
        let schema = ssh_table_schema();
        for field in schema.fields() {
            assert!(
                !field.name().starts_with("ssh."),
                "Field '{}' should not have protocol prefix",
                field.name()
            );
        }
    }
}
