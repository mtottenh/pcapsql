//! Value formatting and the scalar kernels behind the SQL functions.
//!
//! Network address formatting, for displaying addresses in human-readable form:
//! - IPv4 addresses (UInt32 -> dotted-decimal string)
//! - IPv6 addresses (16 bytes -> RFC 5952 string)
//! - MAC addresses (6 bytes -> colon-separated hex)
//!
//! These functions are used by the CLI output formatter to automatically format
//! address columns for display while keeping the underlying binary storage for
//! efficient filtering and range queries.
//!
//! # Scalar kernels
//!
//! The rest of the module is the engine-independent logic of the SQL scalar
//! functions (`ip_proto_name()`, `tcp_flags_str()`, `ip_in_cidr()`, ...), so
//! that every query engine built on this crate gives the same answer:
//!
//! - [`names`]: protocol numbers to names, for the functions and for the
//!   parsers' name columns alike
//! - [`flags`]: TCP flag formatting and tests
//! - [`cidr`]: IP address parsing, CIDR membership, address classes
//! - [`mac`]: MAC address parsing and classes
//! - [`hex`]: hex encoding and decoding
//!
//! A kernel takes one value (a scalar or a byte slice) and returns a scalar,
//! a [`Name`] (a name of a table or text made of the number, without
//! allocating either), or writes to a [`fmt::Write`](std::fmt::Write) sink. None
//! takes or returns a column, and none knows about NULL: the engine's wrapper
//! owns null handling, constant arguments and registration. Where a function
//! has an invalid-input case (`parse_*`), it returns `None` and the wrapper
//! decides what that means in SQL (NULL in both engines today).

pub(crate) mod address;
pub mod cidr;
pub mod flags;
pub mod hex;
pub mod mac;
pub mod names;

pub use address::{
    detect_address_column, format_ipv4, format_ipv6, format_mac, ipv4_text, ipv6_text, mac_text,
    write_ipv4, write_ipv6, write_mac, AddressKind, IPV4_TEXT_LEN, IPV6_TEXT_LEN, MAC_TEXT_LEN,
};
pub use cidr::{
    ipv4_in_cidr, ipv4_prefix_mask, ipv6_in_prefix, is_link_local_ipv6, is_loopback_ipv4,
    is_multicast_ipv4, is_multicast_ipv6, is_private_ipv4, parse_cidr_v4, parse_cidr_v6,
    parse_ipv4, parse_ipv6,
};
pub use flags::{has_tcp_flag, tcp_flag_mask, write_tcp_flags, TCP_FLAGS};
pub use hex::{parse_hex, parse_hex_into, write_hex};
pub use mac::{is_broadcast_mac, is_local_mac, is_multicast_mac, parse_mac};
pub use names::*;
