//! Scalar functions: vector loops over the kernels of `pcapsql_core::format`.
//!
//! No function has logic of its own here. Each is one of eight loops, instantiated with a kernel:
//!
//! - [`Map`]: one argument, the kernel returns the value (`ip4`, `mac`, `mac_is_local`, ...);
//! - [`MapInto`]: one argument, the kernel puts the value in a buffer the loop lends it and
//!   returns the part it filled (`pcap_unhex`, `ip4_to_string`, `ip6_to_string`,
//!   `mac_to_string`), or returns a static string (`ecn_name`, and through [`name`] the
//!   functions that name a protocol number: `dns_type_name`, `icmp_type_name`, ...);
//! - [`ZipInto`]: the same for two arguments (through [`name_of_pair`], `icmp_code_name` and
//!   `icmpv6_code_name`; and `hdr_percentile`, whose buffer is the number it returns);
//! - [`Format`]: one argument, the kernel writes text of any length (`tcp_flags_str`,
//!   `pcap_hex`, `hdr_ascii`);
//! - [`StructList`]: one argument, the kernel gives a list of rows (`hdr_buckets`), which
//!   `engine::nested` stores as a `LIST(STRUCT)`;
//! - [`Match`]: a value and a text pattern, tested for each row (`ip6_in_cidr`);
//! - [`MatchPlain`]: the same for a fixed-width value whose test always has an answer
//!   (`ip_in_cidr`, `has_tcp_flag`), with the answers of a chunk computed over slices of its
//!   values and stored as one slice when the pattern is constant;
//! - [`TestPlain`]: a fixed-width value alone, tested the same way (`is_private_ip`, ...).
//!
//! The kernel is a type parameter of the loop (a function item or a closure that captures
//! nothing), not a function pointer in it: each function gets its own copy of the loop, with the
//! kernel inlined into it.
//!
//! Inputs are read through `duckdb-neo`'s vector reader, which maps rows through the vector's
//! selection, so flat, constant and dictionary inputs all work. NULL in gives NULL out, and so
//! does a value the kernel rejects: no function raises an error for its input.
//!
//! An address is what the tables store: an IPv4 address is a `UINTEGER`, and an IPv6 or MAC
//! address a `BLOB` of 16 or 6 bytes. A function of an IPv6 or MAC address returns NULL for a
//! `BLOB` of another length, which is not an address.
//!
//! A histogram is the `BLOB` the aggregate function `hdr_histogram` returns
//! (`engine::aggregate`), in either engine. The `hdr_*` functions here read it with the kernel
//! that wrote it and return NULL for a `BLOB` that is not one, as the DataFusion engine's do.
//!
//! One module here has `unsafe` code, the second of the two places in the crate that do
//! (`scripts/check-unsafe.sh`): `valid`, in [`plain`], borrows the values of rows of a flat
//! vector as a slice when none of those rows is NULL, and says why it may.

mod list;
mod map;
mod pattern;
mod plain;

use duckdb_neo::{
    data_chunk::VectorCollection,
    extension::Extension,
    logical_type::LogicalType,
    scalar::ScalarCallbacks,
    signature::{FunctionDocumentationBuilder, FunctionParameter, SignatureBuilder},
    types::BlobValue,
    vector::{NativeElement, StorageKind, Vector},
    DuckDBType, Result,
};
use pcapsql_core::format;
use pcapsql_core::format::histogram::HdrHistogram;

use self::list::StructList;
use self::map::{name, name_of_pair, Format, Ipv6Text, Map, MapInto, ZipInto};
use self::pattern::Match;
use self::plain::{MatchPlain, TestPlain};
use super::guard;

pub(super) fn register(extension: &Extension) -> Result<()> {
    register_addresses(extension)?;
    register_address_classes(extension)?;
    register_cidr(extension)?;
    register_tcp_flags(extension)?;
    register_names(extension)?;
    register_hex(extension)?;
    register_histograms(extension)
}

/// Addresses to and from text.
fn register_addresses(extension: &Extension) -> Result<()> {
    Function::new("ip4", "The UINTEGER value of a dotted-quad IPv4 address.")
        .parameter::<String>("address")
        .example("ip4('192.168.1.1')")
        .register::<u32, _>(extension, Map::<String, u32, _, _>::new(format::parse_ipv4))?;
    Function::new(
        "ip4_to_string",
        "Dotted-quad text of a UINTEGER IPv4 address.",
    )
    .parameter::<u32>("address")
    .example("ip4_to_string(3232235777)")
    .register::<String, _>(
        extension,
        // The text goes from the kernel's buffer, on the stack, into the vector.
        MapInto::<u32, String, [u8; format::IPV4_TEXT_LEN], _>::new(|address, text| {
            Some(format::ipv4_text(*address, text))
        }),
    )?;
    Function::new("ip6", "The 16 bytes of an IPv6 address.")
        .parameter::<String>("address")
        .example("ip6('2001:db8::1')")
        .register::<BlobValue, _>(
            extension,
            Map::<String, BlobValue, _, _>::new(format::parse_ipv6),
        )?;
    Function::new("ip6_to_string", "RFC 5952 text of a 16-byte IPv6 address.")
        .parameter::<BlobValue>("address")
        .example("ip6_to_string(ip6('2001:db8::1'))")
        .register::<String, _>(
            extension,
            MapInto::<BlobValue, String, Ipv6Text, _>::new(|address, text| {
                Some(format::ipv6_text(address.try_into().ok()?, &mut text.0))
            }),
        )?;
    Function::new("mac", "The 6 bytes of a MAC address.")
        .parameter::<String>("address")
        .example("mac('aa:bb:cc:dd:ee:ff')")
        .register::<BlobValue, _>(
            extension,
            Map::<String, BlobValue, _, _>::new(format::parse_mac),
        )?;
    Function::new(
        "mac_to_string",
        "Colon-separated hex text of a 6-byte MAC address.",
    )
    .parameter::<BlobValue>("address")
    .example("mac_to_string(mac('aa-bb-cc-dd-ee-ff'))")
    .register::<String, _>(
        extension,
        MapInto::<BlobValue, String, [u8; format::MAC_TEXT_LEN], _>::new(|address, text| {
            Some(format::mac_text(address.try_into().ok()?, text))
        }),
    )
}

/// `f(BLOB) -> BOOLEAN`: a kernel that classifies an address of `LEN` bytes. The kernels look at
/// the first bytes of whatever they are given; in SQL a blob of another length is NULL.
fn of_address<const LEN: usize>(
    kernel: impl Fn(&[u8]) -> bool + Send + Sync + 'static,
) -> impl ScalarCallbacks {
    Map::<BlobValue, bool, bool, _>::new(move |address: &[u8]| {
        (address.len() == LEN).then(|| kernel(address))
    })
}

/// What kind of address an address is.
fn register_address_classes(extension: &Extension) -> Result<()> {
    Function::new(
        "is_private_ip",
        "Whether a UINTEGER IPv4 address is in an RFC 1918 private network.",
    )
    .parameter::<u32>("address")
    .example("is_private_ip(ip4('192.168.1.1'))")
    .register::<bool, _>(extension, TestPlain::<u32, _>::new(format::is_private_ipv4))?;
    Function::new(
        "is_loopback_ip",
        "Whether a UINTEGER IPv4 address is in 127.0.0.0/8.",
    )
    .parameter::<u32>("address")
    .example("is_loopback_ip(ip4('127.0.0.1'))")
    .register::<bool, _>(
        extension,
        TestPlain::<u32, _>::new(format::is_loopback_ipv4),
    )?;
    Function::new(
        "is_multicast_ip",
        "Whether a UINTEGER IPv4 address is in 224.0.0.0/4.",
    )
    .parameter::<u32>("address")
    .example("is_multicast_ip(ip4('224.0.0.251'))")
    .register::<bool, _>(
        extension,
        TestPlain::<u32, _>::new(format::is_multicast_ipv4),
    )?;
    Function::new(
        "is_multicast_ip6",
        "Whether a 16-byte IPv6 address is in ff00::/8.",
    )
    .parameter::<BlobValue>("address")
    .example("is_multicast_ip6(ip6('ff02::1'))")
    .register::<bool, _>(extension, of_address::<16>(format::is_multicast_ipv6))?;
    Function::new(
        "is_link_local_ip6",
        "Whether a 16-byte IPv6 address is in fe80::/10.",
    )
    .parameter::<BlobValue>("address")
    .example("is_link_local_ip6(ip6('fe80::1'))")
    .register::<bool, _>(extension, of_address::<16>(format::is_link_local_ipv6))?;
    Function::new(
        "mac_is_broadcast",
        "Whether a 6-byte MAC address is ff:ff:ff:ff:ff:ff.",
    )
    .parameter::<BlobValue>("address")
    .example("mac_is_broadcast(mac('ff:ff:ff:ff:ff:ff'))")
    .register::<bool, _>(extension, of_address::<6>(format::is_broadcast_mac))?;
    Function::new(
        "mac_is_multicast",
        "Whether a 6-byte MAC address is a group address.",
    )
    .parameter::<BlobValue>("address")
    .example("mac_is_multicast(mac('01:00:5e:00:00:fb'))")
    .register::<bool, _>(extension, of_address::<6>(format::is_multicast_mac))?;
    Function::new(
        "mac_is_local",
        "Whether a 6-byte MAC address is locally administered.",
    )
    .parameter::<BlobValue>("address")
    .example("mac_is_local(mac('02:00:00:00:00:01'))")
    .register::<bool, _>(extension, of_address::<6>(format::is_local_mac))
}

/// CIDR membership.
fn register_cidr(extension: &Extension) -> Result<()> {
    Function::new(
        "ip_in_cidr",
        "Whether a UINTEGER IPv4 address is in a network given in CIDR notation.",
    )
    .parameter::<u32>("address")
    .parameter::<String>("cidr")
    .example("ip_in_cidr(ip4('192.168.1.100'), '192.168.0.0/16')")
    .register::<bool, _>(
        extension,
        MatchPlain::<u32, _, _, _>::new(format::parse_cidr_v4, |address, &(network, mask)| {
            format::ipv4_in_cidr(address, network, mask)
        }),
    )?;
    Function::new(
        "ip6_in_cidr",
        "Whether a 16-byte IPv6 address is in a network given in CIDR notation.",
    )
    .parameter::<BlobValue>("address")
    .parameter::<String>("cidr")
    .example("ip6_in_cidr(ip6('fe80::1'), 'fe80::/10')")
    .register::<bool, _>(
        extension,
        Match::<BlobValue, _, _, _>::new(
            format::parse_cidr_v6,
            |address, (network, prefix_len)| {
                // The kernel answers false for a blob that is not an address; in SQL that is NULL.
                (address.len() == 16).then(|| format::ipv6_in_prefix(address, network, *prefix_len))
            },
        ),
    )
}

/// TCP flags.
fn register_tcp_flags(extension: &Extension) -> Result<()> {
    Function::new(
        "tcp_flags_str",
        "The names of the set TCP flags, comma-separated.",
    )
    .parameter::<u16>("flags")
    .example("tcp_flags_str(18)")
    .register::<String, _>(
        extension,
        Format::<u16, _>::new(|flags, out| format::write_tcp_flags(*flags, out).ok()),
    )?;
    Function::new("has_tcp_flag", "Whether the named TCP flag is set.")
        .parameter::<u16>("flags")
        .parameter::<String>("flag")
        .example("has_tcp_flag(18, 'SYN')")
        .register::<bool, _>(
            extension,
            // A name that is not a flag is a valid pattern that no row matches: no bit.
            MatchPlain::<u16, _, _, _>::new(
                |flag| Some(format::tcp_flag_mask(flag).unwrap_or(0)),
                |flags, mask| flags & mask != 0,
            ),
        )
}

/// Protocol numbers to names. Every number has text: one without a name gets text made of the
/// number, as the kernel spells it (`TYPE999`, `Unknown (9)`, ...).
fn register_names(extension: &Extension) -> Result<()> {
    Function::new("ethertype_name", "The name of an EtherType.")
        .parameter::<u16>("ethertype")
        .example("ethertype_name(2048)")
        .register::<String, _>(extension, name(format::ethertype_name))?;
    Function::new("ip_proto_name", "The name of an IP protocol number.")
        .parameter::<u8>("protocol")
        .example("ip_proto_name(6)")
        .register::<String, _>(extension, name(format::ip_proto_name))?;
    Function::new(
        "dscp_name",
        "The name of a differentiated services code point.",
    )
    .parameter::<u8>("dscp")
    .example("dscp_name(46)")
    .register::<String, _>(extension, name(format::dscp_name))?;
    Function::new(
        "ecn_name",
        "The name of an explicit congestion notification codepoint.",
    )
    .parameter::<u8>("ecn")
    .example("ecn_name(3)")
    .register::<String, _>(
        extension,
        // Every codepoint has a name: there is no text to make, and nothing to make it in.
        MapInto::<u8, String, (), _>::new(|ecn, _| Some(format::ecn_name(*ecn))),
    )?;
    Function::new("icmp_type_name", "The name of an ICMP message type.")
        .parameter::<u8>("type")
        .example("icmp_type_name(8)")
        .register::<String, _>(extension, name(format::icmp_type_name))?;
    Function::new(
        "icmp_code_name",
        "The name of an ICMP code, which depends on the message type.",
    )
    .parameter::<u8>("type")
    .parameter::<u8>("code")
    .example("icmp_code_name(3, 3)")
    .register::<String, _>(extension, name_of_pair(format::icmp_code_name))?;
    Function::new("icmpv6_type_name", "The name of an ICMPv6 message type.")
        .parameter::<u8>("type")
        .example("icmpv6_type_name(135)")
        .register::<String, _>(extension, name(format::icmpv6_type_name))?;
    Function::new(
        "icmpv6_code_name",
        "The name of an ICMPv6 code, which depends on the message type.",
    )
    .parameter::<u8>("type")
    .parameter::<u8>("code")
    .example("icmpv6_code_name(1, 4)")
    .register::<String, _>(extension, name_of_pair(format::icmpv6_code_name))?;
    Function::new("dns_type_name", "The name of a DNS record type.")
        .parameter::<u16>("qtype")
        .example("dns_type_name(28)")
        .register::<String, _>(extension, name(format::dns_type_name))?;
    Function::new("dns_class_name", "The name of a DNS class.")
        .parameter::<u16>("class")
        .example("dns_class_name(1)")
        .register::<String, _>(extension, name(format::dns_class_name))?;
    Function::new("dns_rcode_name", "The name of a DNS response code.")
        .parameter::<u16>("rcode")
        .example("dns_rcode_name(3)")
        .register::<String, _>(extension, name(format::dns_rcode_name))?;
    Function::new("bgp_message_type_name", "The name of a BGP message type.")
        .parameter::<u8>("message_type")
        .example("bgp_message_type_name(2)")
        .register::<String, _>(extension, name(format::bgp_message_type_name))?;
    Function::new(
        "bgp_origin_name",
        "The name of a value of the BGP ORIGIN path attribute.",
    )
    .parameter::<u8>("origin")
    .example("bgp_origin_name(0)")
    .register::<String, _>(extension, name(format::bgp_origin_name))?;
    Function::new("ospf_packet_type_name", "The name of an OSPF packet type.")
        .parameter::<u8>("packet_type")
        .example("ospf_packet_type_name(1)")
        .register::<String, _>(extension, name(format::ospf_packet_type_name))?;
    Function::new("ospf_lsa_type_name", "The name of an OSPF LSA type.")
        .parameter::<u8>("lsa_type")
        .example("ospf_lsa_type_name(1)")
        .register::<String, _>(extension, name(format::ospf_lsa_type_name))?;
    Function::new("gtp_message_type_name", "The name of a GTP message type.")
        .parameter::<u8>("message_type")
        .example("gtp_message_type_name(255)")
        .register::<String, _>(extension, name(format::gtp_message_type_name))?;
    Function::new("ntp_mode_name", "The name of an NTP mode.")
        .parameter::<u8>("mode")
        .example("ntp_mode_name(3)")
        .register::<String, _>(extension, name(format::ntp_mode_name))?;
    Function::new("ntp_stratum_name", "What an NTP stratum says of a clock.")
        .parameter::<u8>("stratum")
        .example("ntp_stratum_name(1)")
        .register::<String, _>(extension, name(format::ntp_stratum_name))?;
    Function::new(
        "tls_record_type_name",
        "The name of a TLS record content type.",
    )
    .parameter::<u8>("record_type")
    .example("tls_record_type_name(22)")
    .register::<String, _>(extension, name(format::tls_record_type_name))?;
    Function::new("tls_version_name", "The name of a TLS protocol version.")
        .parameter::<u16>("version")
        .example("tls_version_name(771)")
        .register::<String, _>(extension, name(format::tls_version_name))
}

/// Hex.
fn register_hex(extension: &Extension) -> Result<()> {
    Function::new("pcap_hex", "Lowercase hexadecimal text of a BLOB.")
        .parameter::<BlobValue>("bytes")
        .example("pcap_hex('\\xDE\\xAD'::BLOB)")
        .register::<String, _>(
            extension,
            Format::<BlobValue, _>::new(|bytes, out| format::write_hex(bytes, out).ok()),
        )?;
    Function::new("pcap_unhex", "The bytes that hexadecimal text encodes.")
        .parameter::<String>("hex")
        .example("pcap_unhex('dead')")
        .register::<BlobValue, _>(
            extension,
            MapInto::<String, BlobValue, Vec<u8>, _>::new(format::parse_hex_into),
        )
}

/// The type `hdr_buckets` returns: the DataFusion engine's list of `lo`, `hi`, `count`.
const BUCKETS_TYPE: &str = "STRUCT(lo UBIGINT, hi UBIGINT, count UBIGINT)[]";

/// `f(BLOB) -> O`: a statistic of the histogram a BLOB encodes. NULL for a BLOB that is not a
/// histogram.
fn of_histogram<O, R>(
    statistic: impl Fn(&HdrHistogram) -> R + Send + Sync + 'static,
) -> impl ScalarCallbacks
where
    O: duckdb_neo::vector::WritableNativeElement + 'static,
    R: std::borrow::Borrow<O::Write> + 'static,
{
    Map::<BlobValue, O, R, _>::new(move |bytes: &[u8]| {
        HdrHistogram::deserialize(bytes)
            .ok()
            .map(|histogram| statistic(&histogram))
    })
}

/// What a histogram (the BLOB of `hdr_histogram`) says.
fn register_histograms(extension: &Extension) -> Result<()> {
    Function::new("hdr_count", "The number of values a histogram recorded.")
        .parameter::<BlobValue>("histogram")
        .example("hdr_count(hdr_histogram(length))")
        .register::<u64, _>(extension, of_histogram::<u64, u64>(HdrHistogram::len))?;
    Function::new(
        "hdr_min",
        "The smallest value a histogram recorded, at its precision.",
    )
    .parameter::<BlobValue>("histogram")
    .example("hdr_min(hdr_histogram(length))")
    .register::<u64, _>(extension, of_histogram::<u64, u64>(HdrHistogram::min))?;
    Function::new(
        "hdr_max",
        "The largest value a histogram recorded, at its precision.",
    )
    .parameter::<BlobValue>("histogram")
    .example("hdr_max(hdr_histogram(length))")
    .register::<u64, _>(extension, of_histogram::<u64, u64>(HdrHistogram::max))?;
    Function::new("hdr_mean", "The mean of the values a histogram recorded.")
        .parameter::<BlobValue>("histogram")
        .example("hdr_mean(hdr_histogram(length))")
        .register::<f64, _>(extension, of_histogram::<f64, f64>(HdrHistogram::mean))?;
    Function::new(
        "hdr_stdev",
        "The standard deviation of the values a histogram recorded.",
    )
    .parameter::<BlobValue>("histogram")
    .example("hdr_stdev(hdr_histogram(length))")
    .register::<f64, _>(extension, of_histogram::<f64, f64>(HdrHistogram::stdev))?;
    Function::new(
        "hdr_percentile",
        "The value at a percentile of a histogram, given as a fraction (0.99) or, above 1, \
         as a percentage (99).",
    )
    .parameter::<BlobValue>("histogram")
    .parameter::<f64>("percentile")
    .example("hdr_percentile(hdr_histogram(length), 0.99)")
    .register::<f64, _>(
        extension,
        // The value goes through the buffer of the loop, which is a number here.
        ZipInto::<BlobValue, f64, f64, f64, _>::new(|bytes, percentile, value| {
            *value = HdrHistogram::deserialize(bytes)
                .ok()?
                .percentile(*percentile);
            Some(&*value)
        }),
    )?;
    Function::new(
        "hdr_ascii",
        "A histogram drawn as text: its statistics, and a line per bucket with a bar.",
    )
    .parameter::<BlobValue>("histogram")
    .example("hdr_ascii(hdr_histogram(length))")
    .register::<String, _>(
        extension,
        Format::<BlobValue, _>::new(|bytes, out| {
            HdrHistogram::deserialize(bytes).ok()?.write_ascii(out).ok()
        }),
    )?;
    Function::new(
        "hdr_buckets",
        "The values of a histogram in buckets on a logarithmic scale: a list of lo, hi, count.",
    )
    .parameter::<BlobValue>("histogram")
    .example("unnest(hdr_buckets(hdr_histogram(length)), recursive := true)")
    .register_returning(
        extension,
        LogicalType::from_text(extension, BUCKETS_TYPE)?,
        StructList::<BlobValue, u64, 3, _>::new(|bytes, buckets| {
            let histogram = HdrHistogram::deserialize(bytes).ok()?;
            buckets.extend(
                histogram
                    .buckets()
                    .map(|bucket| [bucket.lo, bucket.hi, bucket.count]),
            );
            Some(())
        }),
    )
}

/// What a scalar function is registered with, apart from its implementation.
struct Function {
    name: &'static str,
    parameters: Vec<FunctionParameter>,
    documentation: FunctionDocumentationBuilder,
}

impl Function {
    fn new(name: &'static str, description: &str) -> Self {
        Self {
            name,
            parameters: Vec::new(),
            documentation: FunctionDocumentationBuilder::new().description(description),
        }
    }

    fn parameter<T: DuckDBType>(mut self, name: &str) -> Self {
        self.parameters.push(FunctionParameter::new::<T>(name));
        self
    }

    fn example(mut self, example: &str) -> Self {
        self.documentation = self.documentation.add_example("", example);
        self
    }

    /// Register the function with return type `O`, with its callback under the panic guard.
    fn register<O: DuckDBType, T: ScalarCallbacks>(
        self,
        extension: &Extension,
        implementation: T,
    ) -> Result<()> {
        self.register_returning(extension, O::logical_type(extension)?, implementation)
    }

    /// [`register`](Self::register) for a return type no Rust type stands for.
    fn register_returning<T: ScalarCallbacks>(
        self,
        extension: &Extension,
        return_type: LogicalType,
        implementation: T,
    ) -> Result<()> {
        let signature = self
            .parameters
            .into_iter()
            .fold(SignatureBuilder::new(), SignatureBuilder::param)
            .return_type(return_type)
            .documentation(self.documentation);
        guard::scalar_function(self.name, signature, implementation).register(extension)
    }
}

/// A vector in a storage kind the vector reader accepts.
pub(super) fn readable<T: NativeElement>(mut vector: Vector<'_, T>) -> Result<Vector<'_, T>> {
    // Sequence and FSST vectors have no selection-based view; DuckDB materialises them on request.
    if vector.storage_kind() == StorageKind::Other {
        vector.flatten()?;
    }
    Ok(vector)
}

/// The only argument of a function, ready to read.
fn argument<T: NativeElement>(vectors: &mut VectorCollection) -> Result<Vector<'_, T>> {
    readable(vectors.get_vector_at_mut::<T>(0)?)
}
