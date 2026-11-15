//! Names for protocol numbers: the tables behind the `*_name()` SQL functions.
//!
//! Every function takes the number as stored in its column and returns
//! [`Cow<'static, str>`](std::borrow::Cow): borrowed for a value with a
//! name, owned only for the fallback text that carries the number (for
//! example `TYPE999`). A caller that copies the text into its own buffer
//! therefore allocates nothing for the common case.

mod bgp;
mod dns;
mod gtp;
mod icmp;
mod ip;
mod ntp;
mod ospf;
mod tls;

pub use bgp::{bgp_message_type_name, bgp_origin_name};
pub use dns::{dns_class_name, dns_opcode_name, dns_rcode_name, dns_type_name};
pub use gtp::gtp_message_type_name;
pub use icmp::{icmp_code_name, icmp_type_name, icmpv6_code_name, icmpv6_type_name};
pub use ip::{dscp_name, ecn_name, ethertype_name, ip_proto_name};
pub use ntp::{ntp_mode_name, ntp_stratum_name};
pub use ospf::{ospf_lsa_type_name, ospf_packet_type_name};
pub use tls::{tls_record_type_name, tls_version_name};
