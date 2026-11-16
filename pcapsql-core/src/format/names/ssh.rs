//! SSH message type names.

use super::Name;

use crate::protocol::ssh_msg_type as msg_type;

/// Convert an SSH message number (RFC 4250) to its name without the
/// `SSH_MSG_` prefix; `Unknown (n)` otherwise.
pub fn ssh_msg_type_name(msg: u8) -> Name {
    Name::fixed(match msg {
        msg_type::SSH_MSG_DISCONNECT => "DISCONNECT",
        msg_type::SSH_MSG_IGNORE => "IGNORE",
        msg_type::SSH_MSG_UNIMPLEMENTED => "UNIMPLEMENTED",
        msg_type::SSH_MSG_DEBUG => "DEBUG",
        msg_type::SSH_MSG_SERVICE_REQUEST => "SERVICE_REQUEST",
        msg_type::SSH_MSG_SERVICE_ACCEPT => "SERVICE_ACCEPT",
        msg_type::SSH_MSG_KEXINIT => "KEXINIT",
        msg_type::SSH_MSG_NEWKEYS => "NEWKEYS",
        msg_type::SSH_MSG_KEX_DH_INIT => "KEX_DH_INIT",
        msg_type::SSH_MSG_KEX_DH_REPLY => "KEX_DH_REPLY",
        msg_type::SSH_MSG_USERAUTH_REQUEST => "USERAUTH_REQUEST",
        msg_type::SSH_MSG_USERAUTH_FAILURE => "USERAUTH_FAILURE",
        msg_type::SSH_MSG_USERAUTH_SUCCESS => "USERAUTH_SUCCESS",
        msg_type::SSH_MSG_USERAUTH_BANNER => "USERAUTH_BANNER",
        msg_type::SSH_MSG_CHANNEL_OPEN => "CHANNEL_OPEN",
        msg_type::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => "CHANNEL_OPEN_CONFIRMATION",
        msg_type::SSH_MSG_CHANNEL_OPEN_FAILURE => "CHANNEL_OPEN_FAILURE",
        msg_type::SSH_MSG_CHANNEL_WINDOW_ADJUST => "CHANNEL_WINDOW_ADJUST",
        msg_type::SSH_MSG_CHANNEL_DATA => "CHANNEL_DATA",
        msg_type::SSH_MSG_CHANNEL_EXTENDED_DATA => "CHANNEL_EXTENDED_DATA",
        msg_type::SSH_MSG_CHANNEL_EOF => "CHANNEL_EOF",
        msg_type::SSH_MSG_CHANNEL_CLOSE => "CHANNEL_CLOSE",
        msg_type::SSH_MSG_CHANNEL_REQUEST => "CHANNEL_REQUEST",
        msg_type::SSH_MSG_CHANNEL_SUCCESS => "CHANNEL_SUCCESS",
        msg_type::SSH_MSG_CHANNEL_FAILURE => "CHANNEL_FAILURE",
        _ => return Name::unknown(msg),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_msg_type_name() {
        assert_eq!(ssh_msg_type_name(1), "DISCONNECT");
        assert_eq!(ssh_msg_type_name(20), "KEXINIT");
        assert_eq!(ssh_msg_type_name(21), "NEWKEYS");
        assert_eq!(ssh_msg_type_name(100), "CHANNEL_FAILURE");
        assert_eq!(ssh_msg_type_name(0), "Unknown (0)");
        assert_eq!(ssh_msg_type_name(200), "Unknown (200)");
    }
}
