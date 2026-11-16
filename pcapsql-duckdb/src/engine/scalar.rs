//! Scalar functions: vector loops over the kernels of `pcapsql_core::format`.
//!
//! No function has logic of its own here. Each is one of three loops, instantiated with a kernel:
//!
//! - [`Map`]: one argument, the kernel returns the value (`ip4`, `mac`, `dns_type_name`, ...);
//! - [`Format`]: one argument, the kernel writes text (`ip4_to_string`, `pcap_hex`, ...);
//! - [`Match`]: a value and a text pattern, tested for each row (`ip_in_cidr`, `has_tcp_flag`).
//!
//! Inputs are read through `duckdb-neo`'s vector reader, which maps rows through the vector's
//! selection, so flat, constant and dictionary inputs all work. NULL in gives NULL out, and so
//! does a value the kernel rejects: no function raises an error for its input.

use std::borrow::{Borrow, Cow};
use std::marker::PhantomData;

use duckdb_neo::{
    connection::Context,
    data_chunk::VectorCollection,
    extension::Extension,
    scalar::ScalarCallbacks,
    signature::{FunctionDocumentationBuilder, FunctionParameter, SignatureBuilder},
    types::BlobValue,
    vector::{
        NativeElement, ReadableNativeElement, StorageKind, Unknown, Vector, WritableNativeElement,
    },
    DuckDBType, Result,
};
use pcapsql_core::format;

use super::guard;

pub(super) fn register(extension: &Extension) -> Result<()> {
    // Addresses.
    Function::new("ip4", "The UINTEGER value of a dotted-quad IPv4 address.")
        .parameter::<String>("address")
        .example("ip4('192.168.1.1')")
        .register::<u32, _>(extension, Map::<String, u32, _>::new(format::parse_ipv4))?;
    Function::new(
        "ip4_to_string",
        "Dotted-quad text of a UINTEGER IPv4 address.",
    )
    .parameter::<u32>("address")
    .example("ip4_to_string(3232235777)")
    .register::<String, _>(
        extension,
        Format::<u32>::new(|address, out| format::write_ipv4(*address, out).ok()),
    )?;
    Function::new("ip6", "The 16 bytes of an IPv6 address.")
        .parameter::<String>("address")
        .example("ip6('2001:db8::1')")
        .register::<BlobValue, _>(
            extension,
            Map::<String, BlobValue, _>::new(format::parse_ipv6),
        )?;
    Function::new("ip6_to_string", "RFC 5952 text of a 16-byte IPv6 address.")
        .parameter::<BlobValue>("address")
        .example("ip6_to_string(ip6('2001:db8::1'))")
        .register::<String, _>(
            extension,
            Format::<BlobValue>::new(|address, out| {
                format::write_ipv6(address.try_into().ok()?, out).ok()
            }),
        )?;
    Function::new("mac", "The 6 bytes of a MAC address.")
        .parameter::<String>("address")
        .example("mac('aa:bb:cc:dd:ee:ff')")
        .register::<BlobValue, _>(
            extension,
            Map::<String, BlobValue, _>::new(format::parse_mac),
        )?;
    Function::new(
        "mac_to_string",
        "Colon-separated hex text of a 6-byte MAC address.",
    )
    .parameter::<BlobValue>("address")
    .example("mac_to_string(mac('aa-bb-cc-dd-ee-ff'))")
    .register::<String, _>(
        extension,
        Format::<BlobValue>::new(|address, out| {
            format::write_mac(address.try_into().ok()?, out).ok()
        }),
    )?;

    // CIDR membership.
    Function::new(
        "ip_in_cidr",
        "Whether a UINTEGER IPv4 address is in a network given in CIDR notation.",
    )
    .parameter::<u32>("address")
    .parameter::<String>("cidr")
    .example("ip_in_cidr(ip4('192.168.1.100'), '192.168.0.0/16')")
    .register::<bool, _>(
        extension,
        Match::<u32, _>::new(format::parse_cidr_v4, |address, &(network, mask)| {
            Some(format::ipv4_in_cidr(*address, network, mask))
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
        Match::<BlobValue, _>::new(format::parse_cidr_v6, |address, (network, prefix_len)| {
            // The kernel answers false for a blob that is not an address; in SQL that is NULL.
            (address.len() == 16).then(|| format::ipv6_in_prefix(address, network, *prefix_len))
        }),
    )?;

    // TCP flags.
    Function::new(
        "tcp_flags_str",
        "The names of the set TCP flags, comma-separated.",
    )
    .parameter::<u16>("flags")
    .example("tcp_flags_str(18)")
    .register::<String, _>(
        extension,
        Format::<u16>::new(|flags, out| format::write_tcp_flags(*flags, out).ok()),
    )?;
    Function::new("has_tcp_flag", "Whether the named TCP flag is set.")
        .parameter::<u16>("flags")
        .parameter::<String>("flag")
        .example("has_tcp_flag(18, 'SYN')")
        .register::<bool, _>(
            extension,
            // A name that is not a flag is a valid pattern that no row matches.
            Match::<u16, Option<u16>>::new(
                |flag| Some(format::tcp_flag_mask(flag)),
                |flags, mask| Some(mask.is_some_and(|mask| flags & mask != 0)),
            ),
        )?;

    // Protocol numbers to names.
    Function::new("dns_type_name", "The name of a DNS record type.")
        .parameter::<u16>("qtype")
        .example("dns_type_name(28)")
        .register::<String, _>(
            extension,
            Name::<u16>::new(|qtype| Some(format::dns_type_name(*qtype))),
        )?;
    Function::new("dns_rcode_name", "The name of a DNS response code.")
        .parameter::<u16>("rcode")
        .example("dns_rcode_name(3)")
        .register::<String, _>(
            extension,
            Name::<u16>::new(|rcode| Some(format::dns_rcode_name(*rcode))),
        )?;
    Function::new("ip_proto_name", "The name of an IP protocol number.")
        .parameter::<u8>("protocol")
        .example("ip_proto_name(6)")
        .register::<String, _>(
            extension,
            Name::<u8>::new(|protocol| Some(format::ip_proto_name(*protocol))),
        )?;
    Function::new("ethertype_name", "The name of an EtherType.")
        .parameter::<u16>("ethertype")
        .example("ethertype_name(2048)")
        .register::<String, _>(
            extension,
            Name::<u16>::new(|ethertype| Some(format::ethertype_name(*ethertype))),
        )?;

    // Hex.
    Function::new("pcap_hex", "Lowercase hexadecimal text of a BLOB.")
        .parameter::<BlobValue>("bytes")
        .example("pcap_hex('\\xDE\\xAD'::BLOB)")
        .register::<String, _>(
            extension,
            Format::<BlobValue>::new(|bytes, out| format::write_hex(bytes, out).ok()),
        )?;
    Function::new("pcap_unhex", "The bytes that hexadecimal text encodes.")
        .parameter::<String>("hex")
        .example("pcap_unhex('dead')")
        .register::<BlobValue, _>(
            extension,
            Map::<String, BlobValue, _>::new(format::parse_hex),
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
        let signature = self
            .parameters
            .into_iter()
            .fold(SignatureBuilder::new(), SignatureBuilder::param)
            .return_type(O::logical_type(extension)?)
            .documentation(self.documentation);
        guard::scalar_function(self.name, signature, implementation).register(extension)
    }
}

/// A vector in a storage kind the vector reader accepts.
fn readable<T: NativeElement>(mut vector: Vector<'_, T>) -> Result<Vector<'_, T>> {
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

/// `f(I) -> O`, where the kernel returns the value, or `None` for NULL.
///
/// `R` is what the kernel returns: something that borrows as what the output vector stores, such
/// as `[u8; 6]` or `Vec<u8>` for a BLOB.
struct Map<I: ReadableNativeElement + 'static, O, R> {
    kernel: for<'a> fn(I::Ref<'a>) -> Option<R>,
    output: PhantomData<fn() -> O>,
}

impl<I: ReadableNativeElement + 'static, O, R> Map<I, O, R> {
    fn new(kernel: for<'a> fn(I::Ref<'a>) -> Option<R>) -> Self {
        Self {
            kernel,
            output: PhantomData,
        }
    }
}

/// `f(I) -> VARCHAR`, where the kernel returns a name. A fixed name is copied from the static
/// string straight into the vector; only the `Unknown (n)` fallbacks allocate.
type Name<I> = Map<I, String, Cow<'static, str>>;

impl<I, O, R> ScalarCallbacks for Map<I, O, R>
where
    I: ReadableNativeElement + 'static,
    O: WritableNativeElement + 'static,
    R: Borrow<O::Write> + 'static,
{
    type BindData = ();
    type InitData = ();

    fn exec(
        &self,
        _context: &Context,
        _bind_data: Option<&()>,
        _init_data: Option<&mut ()>,
        vectors: &mut VectorCollection,
        output: Vector<'_, Unknown>,
    ) -> Result<()> {
        let rows = vectors.row_count()?;
        let input = argument::<I>(vectors)?;
        let mut output = output.cast::<O>()?;
        output.set_size(rows)?;
        let mut writer = output.writer()?;
        for (row, value) in input.reader()?.iter().enumerate() {
            let result = value.and_then(self.kernel);
            writer.set_option(row, result.as_ref().map(Borrow::borrow))?;
        }
        Ok(())
    }
}

/// `f(I) -> VARCHAR`, where the kernel writes the text, or returns `None` for NULL.
struct Format<I: ReadableNativeElement + 'static> {
    kernel: for<'a> fn(I::Ref<'a>, &mut String) -> Option<()>,
}

impl<I: ReadableNativeElement + 'static> Format<I> {
    fn new(kernel: for<'a> fn(I::Ref<'a>, &mut String) -> Option<()>) -> Self {
        Self { kernel }
    }
}

impl<I: ReadableNativeElement + 'static> ScalarCallbacks for Format<I> {
    type BindData = ();
    type InitData = ();

    fn exec(
        &self,
        _context: &Context,
        _bind_data: Option<&()>,
        _init_data: Option<&mut ()>,
        vectors: &mut VectorCollection,
        output: Vector<'_, Unknown>,
    ) -> Result<()> {
        let rows = vectors.row_count()?;
        let input = argument::<I>(vectors)?;
        let mut output = output.cast::<String>()?;
        output.set_size(rows)?;
        let mut writer = output.writer()?;
        // The vector writer takes finished text, not a `fmt::Write` sink, so the kernels write
        // into one buffer that is reused for every row of the chunk.
        let mut text = String::new();
        for (row, value) in input.reader()?.iter().enumerate() {
            text.clear();
            let written = value.and_then(|value| (self.kernel)(value, &mut text));
            writer.set_option(row, written.map(|()| text.as_str()))?;
        }
        Ok(())
    }
}

/// `f(I, VARCHAR) -> BOOLEAN`: a value tested against a pattern that is parsed from text, such as
/// a CIDR network. NULL when the text is not a pattern, or when `test` returns `None`.
///
/// The pattern is nearly always a literal, which arrives as a constant vector and is parsed once
/// for the chunk. Otherwise it is parsed again whenever the text differs from the row before.
struct Match<I: ReadableNativeElement + 'static, P> {
    parse: fn(&str) -> Option<P>,
    test: for<'a> fn(I::Ref<'a>, &P) -> Option<bool>,
}

impl<I: ReadableNativeElement + 'static, P> Match<I, P> {
    fn new(parse: fn(&str) -> Option<P>, test: for<'a> fn(I::Ref<'a>, &P) -> Option<bool>) -> Self {
        Self { parse, test }
    }
}

impl<I: ReadableNativeElement + 'static, P: 'static> ScalarCallbacks for Match<I, P> {
    type BindData = ();
    type InitData = ();

    fn exec(
        &self,
        _context: &Context,
        _bind_data: Option<&()>,
        _init_data: Option<&mut ()>,
        vectors: &mut VectorCollection,
        output: Vector<'_, Unknown>,
    ) -> Result<()> {
        let rows = vectors.row_count()?;
        let [values, patterns] = vectors.get_vector_array_mut([0, 1])?;
        let values = readable(values.cast::<I>()?)?;
        let patterns = readable(patterns.cast::<String>()?)?;
        let mut output = output.cast::<bool>()?;
        output.set_size(rows)?;
        let mut writer = output.writer()?;
        if rows == 0 {
            return Ok(());
        }

        let values = values.reader()?;
        let texts = patterns.reader()?;
        if patterns.storage_kind() == StorageKind::Constant {
            let Some(pattern) = texts.get(0)?.and_then(self.parse) else {
                return writer.fill_null();
            };
            for (row, value) in values.iter().enumerate() {
                let result = value.and_then(|value| (self.test)(value, &pattern));
                writer.set_option(row, result.as_ref())?;
            }
        } else {
            let mut parsed: Option<(&str, Option<P>)> = None;
            for (row, (value, text)) in values.iter().zip(texts.iter()).enumerate() {
                let result = match (value, text) {
                    (Some(value), Some(text)) => {
                        if parsed.as_ref().is_none_or(|(last, _)| *last != text) {
                            parsed = Some((text, (self.parse)(text)));
                        }
                        let pattern = parsed.as_ref().and_then(|(_, pattern)| pattern.as_ref());
                        pattern.and_then(|pattern| (self.test)(value, pattern))
                    }
                    _ => None,
                };
                writer.set_option(row, result.as_ref())?;
            }
        }
        Ok(())
    }
}
