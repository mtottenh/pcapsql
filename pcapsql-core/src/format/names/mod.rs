//! Names for protocol numbers: the one set of code-to-name tables.
//!
//! The `*_name()` SQL functions and the name columns the protocol parsers
//! write both read these tables, so a parser's column and the function
//! applied to the number beside it give the same text. A parser holds no
//! name table of its own (`protocol/name_columns_tests.rs` checks every name
//! column against its table here).
//!
//! Every function takes the number as stored in its column and returns a
//! [`Name`]: a name of the table, or the table's text for a number without
//! one, which carries the number (`TYPE999`, `Unknown (7)`). Each table
//! keeps the text its registry is usually written in, so the text for a
//! number without a name differs from table to table; where there is no such
//! convention it is `Unknown (n)`. Looking a name up allocates nothing:
//! a [`Name`] is `Copy`, and writes itself to a [`fmt::Write`] sink (it is
//! [`Display`](fmt::Display)) or into a parser's arena
//! ([`FieldSink::name`](crate::protocol::FieldSink::name)).

use std::borrow::Cow;
use std::fmt;

mod arp;
mod bgp;
mod dns;
mod gre;
mod gtp;
mod icmp;
mod ip;
mod linux;
mod mpls;
mod ntp;
mod ospf;
mod quic;
mod ssh;
mod tls;

pub use arp::arp_operation_name;
pub use bgp::{bgp_capability_name, bgp_error_code_name, bgp_message_type_name, bgp_origin_name};
pub use dns::{dns_class_name, dns_opcode_name, dns_rcode_name, dns_type_name};
pub use gre::gre_version_name;
pub use gtp::gtp_message_type_name;
pub use icmp::{icmp_code_name, icmp_type_name, icmpv6_code_name, icmpv6_type_name};
pub use ip::{dscp_name, ecn_name, ethertype_name, ip_proto_name};
pub use linux::{
    address_family_name, arphrd_name, netlink_family_name, netlink_msg_type_name,
    rtnetlink_msg_type_name, sll_packet_type_name,
};
pub use mpls::mpls_special_label_name;
pub use ntp::{ntp_mode_name, ntp_stratum_name};
pub use ospf::{ospf_lsa_type_name, ospf_packet_type_name};
pub use quic::quic_version_name;
pub use ssh::ssh_msg_type_name;
pub use tls::{
    tls_alert_description_name, tls_compression_method_name, tls_ec_point_format_name,
    tls_named_group_name, tls_record_type_name, tls_signature_scheme_name, tls_version_name,
};

/// The text a name table gives for a number.
///
/// It is either a name of the table or text made of the number, and in both
/// cases it is `Copy` and owns nothing. Compare it with a `str`, write it
/// with `{}`, or take a [`Cow`] with [`into_cow`](Self::into_cow), which
/// allocates only for text made of the number.
///
/// # Example
///
/// ```
/// use pcapsql_core::format::dns_type_name;
///
/// assert_eq!(dns_type_name(28), "AAAA");
/// assert_eq!(dns_type_name(28).as_static(), Some("AAAA"));
/// assert_eq!(dns_type_name(999).to_string(), "TYPE999");
/// assert_eq!(dns_type_name(999).as_static(), None);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Name(Text);

#[derive(Debug, Clone, Copy)]
enum Text {
    Fixed(&'static str),
    Numbered {
        prefix: &'static str,
        number: u32,
        digits: Digits,
        suffix: &'static str,
    },
}

/// How the number of a [`Name`] is written.
#[derive(Debug, Clone, Copy)]
enum Digits {
    Decimal,
    /// Lower-case hexadecimal, zero-padded to a width.
    Hex(usize),
    /// Upper-case hexadecimal, zero-padded to a width.
    UpperHex(usize),
}

impl Name {
    /// A name of the table.
    const fn fixed(name: &'static str) -> Self {
        Self(Text::Fixed(name))
    }

    /// `prefix`, the number in decimal, `suffix`.
    fn numbered(prefix: &'static str, number: impl Into<u32>, suffix: &'static str) -> Self {
        Self(Text::Numbered {
            prefix,
            number: number.into(),
            digits: Digits::Decimal,
            suffix,
        })
    }

    /// `Unknown (n)`: the text for a number without a name, in a table with
    /// no convention of its own.
    fn unknown(number: impl Into<u32>) -> Self {
        Self::numbered("Unknown (", number, ")")
    }

    /// `prefix`, the number in lower-case hexadecimal of `width` digits,
    /// `suffix`.
    fn hex(
        prefix: &'static str,
        number: impl Into<u32>,
        width: usize,
        suffix: &'static str,
    ) -> Self {
        Self(Text::Numbered {
            prefix,
            number: number.into(),
            digits: Digits::Hex(width),
            suffix,
        })
    }

    /// `prefix`, then the number in upper-case hexadecimal of `width` digits.
    fn upper_hex(prefix: &'static str, number: impl Into<u32>, width: usize) -> Self {
        Self(Text::Numbered {
            prefix,
            number: number.into(),
            digits: Digits::UpperHex(width),
            suffix: "",
        })
    }

    /// The text when it is a name of the table; `None` when it is made of
    /// the number.
    pub const fn as_static(&self) -> Option<&'static str> {
        match self.0 {
            Text::Fixed(name) => Some(name),
            Text::Numbered { .. } => None,
        }
    }

    /// The text, borrowed when it is a name of the table.
    pub fn into_cow(self) -> Cow<'static, str> {
        match self.as_static() {
            Some(name) => Cow::Borrowed(name),
            None => Cow::Owned(self.to_string()),
        }
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Text::Fixed(name) => f.write_str(name),
            Text::Numbered {
                prefix,
                number,
                digits,
                suffix,
            } => {
                f.write_str(prefix)?;
                match digits {
                    Digits::Decimal => write!(f, "{number}")?,
                    Digits::Hex(width) => write!(f, "{number:0width$x}")?,
                    Digits::UpperHex(width) => write!(f, "{number:0width$X}")?,
                }
                f.write_str(suffix)
            }
        }
    }
}

impl From<Name> for Cow<'static, str> {
    fn from(name: Name) -> Self {
        name.into_cow()
    }
}

/// A sink that checks what is written to it against a text, so that a
/// [`Name`] is compared without being built.
struct Expect<'a>(Option<&'a str>);

impl fmt::Write for Expect<'_> {
    fn write_str(&mut self, written: &str) -> fmt::Result {
        self.0 = self.0.and_then(|rest| rest.strip_prefix(written));
        Ok(())
    }
}

impl PartialEq<str> for Name {
    fn eq(&self, other: &str) -> bool {
        let mut expect = Expect(Some(other));
        // `Expect` does not fail.
        let _ = fmt::write(&mut expect, format_args!("{self}"));
        expect.0 == Some("")
    }
}

impl PartialEq<&str> for Name {
    fn eq(&self, other: &&str) -> bool {
        *self == **other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_of_the_table_is_borrowed() {
        let name = Name::fixed("TCP");
        assert_eq!(name.as_static(), Some("TCP"));
        assert!(matches!(name.into_cow(), Cow::Borrowed("TCP")));
        assert_eq!(name, "TCP");
        assert!(name != "TC");
        assert!(name != "TCPX");
    }

    #[test]
    fn text_made_of_the_number() {
        let cases = [
            (Name::unknown(7u8), "Unknown (7)"),
            (Name::numbered("TYPE", 65535u16, ""), "TYPE65535"),
            (
                Name::hex("Unknown (0x", 0x0305u16, 4, ")"),
                "Unknown (0x0305)",
            ),
            (Name::hex("0x", 0xabu8, 2, ""), "0xab"),
            (Name::hex("0x", 0xff00_0000u32, 8, ""), "0xff000000"),
            (Name::upper_hex("0x", 0x88b5u16, 4), "0x88B5"),
        ];
        for (name, text) in cases {
            assert_eq!(name.as_static(), None);
            assert_eq!(name.to_string(), text);
            assert!(matches!(name.into_cow(), Cow::Owned(owned) if owned == text));
            assert_eq!(name, text);
            assert!(name != text[1..]);
            assert!(name != text[..text.len() - 1]);
        }
    }
}
