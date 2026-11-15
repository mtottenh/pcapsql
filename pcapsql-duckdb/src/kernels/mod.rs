//! Scalar-function kernels: pure functions over Rust values, with no DuckDB types.
//!
//! This module is temporary. Step S6 of the shared scan layer moves these functions to
//! `pcapsql_core::format`, where the DataFusion UDFs call them too. They are kept here until then
//! because they hold the logic of the sixteen scalar functions of the V1 extension, and
//! `engine::scalar` wraps them as each function is ported.
//!
//! A kernel returns `None` where the SQL function returns NULL.
//!
//! | SQL function | Kernel |
//! |---|---|
//! | `ip4(VARCHAR) -> UINTEGER` | [`address::parse_ip4`] |
//! | `ip4_to_string(UINTEGER) -> VARCHAR` | `pcapsql_core::format::format_ipv4` |
//! | `ip6(VARCHAR) -> BLOB` | [`address::parse_ip6`] |
//! | `ip6_to_string(BLOB) -> VARCHAR` | `pcapsql_core::format::format_ipv6` |
//! | `mac(VARCHAR) -> BLOB` | [`address::parse_mac`] |
//! | `mac_to_string(BLOB) -> VARCHAR` | `pcapsql_core::format::format_mac` |
//! | `ip_in_cidr(UINTEGER, VARCHAR) -> BOOLEAN` | [`cidr::ip4_in_cidr`] |
//! | `ip6_in_cidr(BLOB, VARCHAR) -> BOOLEAN` | [`cidr::ip6_in_cidr`] |
//! | `tcp_flags_str(USMALLINT) -> VARCHAR` | [`protocol::format_tcp_flags`] |
//! | `has_tcp_flag(USMALLINT, VARCHAR) -> BOOLEAN` | [`protocol::check_tcp_flag`] |
//! | `dns_type_name(USMALLINT) -> VARCHAR` | [`protocol::dns_type_to_string`] |
//! | `dns_rcode_name(USMALLINT) -> VARCHAR` | [`protocol::dns_rcode_to_string`] |
//! | `ip_proto_name(UTINYINT) -> VARCHAR` | [`protocol::ip_proto_to_string`] |
//! | `ethertype_name(USMALLINT) -> VARCHAR` | [`protocol::ethertype_to_string`] |
//! | `pcap_hex(BLOB) -> VARCHAR` | [`hex::encode`] |
//! | `pcap_unhex(VARCHAR) -> BLOB` | [`hex::decode`] |

pub mod address;
pub mod cidr;
pub mod hex;
pub mod protocol;
