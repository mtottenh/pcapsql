//! Scalar functions: vector loops over the kernels of `pcapsql_core::format`.
//!
//! No function has logic of its own here. Each is one of five loops, instantiated with a kernel:
//!
//! - [`Map`]: one argument, the kernel returns the value (`ip4`, `mac`, `dns_type_name`, ...);
//! - [`MapInto`]: one argument, the kernel puts the value in a buffer the loop lends it and
//!   returns the part it filled (`pcap_unhex`, `ip4_to_string`, `ip6_to_string`,
//!   `mac_to_string`);
//! - [`Format`]: one argument, the kernel writes text of any length (`tcp_flags_str`,
//!   `pcap_hex`);
//! - [`Match`]: a value and a text pattern, tested for each row (`ip6_in_cidr`);
//! - [`MatchPlain`]: the same for a fixed-width value whose test always has an answer
//!   (`ip_in_cidr`, `has_tcp_flag`), with the answers of a chunk stored as one slice when the
//!   pattern is constant.
//!
//! The kernel is a type parameter of the loop (a function item or a closure that captures
//! nothing), not a function pointer in it: each function gets its own copy of the loop, with the
//! kernel inlined into it.
//!
//! Inputs are read through `duckdb-neo`'s vector reader, which maps rows through the vector's
//! selection, so flat, constant and dictionary inputs all work. NULL in gives NULL out, and so
//! does a value the kernel rejects: no function raises an error for its input.
//!
//! One function here has an `unsafe` call, the second of the two places in the crate that do
//! (`scripts/check-unsafe.sh`): [`values_without_nulls`] borrows the values of a flat vector
//! without NULLs as a slice, and says why it may.

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
        NativeElement, PlainNative, ReadableNativeElement, Selection, StorageKind, Unknown, Vector,
        VectorReader, VectorWriter, WritableNativeElement,
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
        )?;

    // Protocol numbers to names.
    Function::new("dns_type_name", "The name of a DNS record type.")
        .parameter::<u16>("qtype")
        .example("dns_type_name(28)")
        .register::<String, _>(
            extension,
            Name::<u16, _>::new(|qtype| Some(format::dns_type_name(*qtype))),
        )?;
    Function::new("dns_rcode_name", "The name of a DNS response code.")
        .parameter::<u16>("rcode")
        .example("dns_rcode_name(3)")
        .register::<String, _>(
            extension,
            Name::<u16, _>::new(|rcode| Some(format::dns_rcode_name(*rcode))),
        )?;
    Function::new("ip_proto_name", "The name of an IP protocol number.")
        .parameter::<u8>("protocol")
        .example("ip_proto_name(6)")
        .register::<String, _>(
            extension,
            Name::<u8, _>::new(|protocol| Some(format::ip_proto_name(*protocol))),
        )?;
    Function::new("ethertype_name", "The name of an EtherType.")
        .parameter::<u16>("ethertype")
        .example("ethertype_name(2048)")
        .register::<String, _>(
            extension,
            Name::<u16, _>::new(|ethertype| Some(format::ethertype_name(*ethertype))),
        )?;

    // Hex.
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

/// `f(I) -> O`, where the kernel `K` returns the value, or `None` for NULL.
///
/// `R` is what the kernel returns: something that borrows as what the output vector stores, such
/// as `[u8; 6]` or `Vec<u8>` for a BLOB.
struct Map<I, O, R, K> {
    kernel: K,
    types: PhantomData<fn(I) -> (O, R)>,
}

impl<I, O, R, K> Map<I, O, R, K>
where
    I: ReadableNativeElement + 'static,
    K: for<'a> Fn(I::Ref<'a>) -> Option<R>,
{
    fn new(kernel: K) -> Self {
        Self {
            kernel,
            types: PhantomData,
        }
    }
}

/// `f(I) -> VARCHAR`, where the kernel returns a name. A fixed name is copied from the static
/// string straight into the vector; only the `Unknown (n)` fallbacks allocate.
type Name<I, K> = Map<I, String, Cow<'static, str>, K>;

impl<I, O, R, K> ScalarCallbacks for Map<I, O, R, K>
where
    I: ReadableNativeElement + 'static,
    O: WritableNativeElement + 'static,
    R: Borrow<O::Write> + 'static,
    K: for<'a> Fn(I::Ref<'a>) -> Option<R> + Send + Sync + 'static,
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
            let result = value.and_then(&self.kernel);
            writer.set_option(row, result.as_ref().map(Borrow::borrow))?;
        }
        Ok(())
    }
}

/// `f(I) -> O`, where the kernel `K` puts the value in the buffer it is lent and returns the
/// part of the buffer that holds it, or `None` for NULL.
///
/// The buffer, an `S`, is one for the chunk: a kernel whose value is a `Vec` (`parse_hex_into`)
/// allocates when a value is longer than every one before it in the chunk, not for every row,
/// and a kernel whose value has a longest form writes it on the stack.
struct MapInto<I, O, S, K> {
    kernel: K,
    types: PhantomData<fn(I, S) -> O>,
}

impl<I, O, S, K> MapInto<I, O, S, K>
where
    I: ReadableNativeElement + 'static,
    O: WritableNativeElement + 'static,
    K: for<'a, 'b> Fn(I::Ref<'a>, &'b mut S) -> Option<&'b O::Write>,
{
    fn new(kernel: K) -> Self {
        Self {
            kernel,
            types: PhantomData,
        }
    }
}

impl<I, O, S, K> ScalarCallbacks for MapInto<I, O, S, K>
where
    I: ReadableNativeElement + 'static,
    O: WritableNativeElement + 'static,
    S: Default + 'static,
    K: for<'a, 'b> Fn(I::Ref<'a>, &'b mut S) -> Option<&'b O::Write> + Send + Sync + 'static,
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
        let mut buffer = S::default();
        for (row, value) in input.reader()?.iter().enumerate() {
            let result = value.and_then(|value| (self.kernel)(value, &mut buffer));
            writer.set_option(row, result)?;
        }
        Ok(())
    }
}

/// The buffer [`MapInto`] lends the kernel of `ip6_to_string`: an array this long has no
/// `Default` of its own.
struct Ipv6Text([u8; format::IPV6_TEXT_LEN]);

impl Default for Ipv6Text {
    fn default() -> Self {
        Self([0; format::IPV6_TEXT_LEN])
    }
}

/// `f(I) -> VARCHAR`, where the kernel `K` writes the text, or returns `None` for NULL.
struct Format<I, K> {
    kernel: K,
    input: PhantomData<fn(I)>,
}

impl<I, K> Format<I, K>
where
    I: ReadableNativeElement + 'static,
    K: for<'a> Fn(I::Ref<'a>, &mut String) -> Option<()>,
{
    fn new(kernel: K) -> Self {
        Self {
            kernel,
            input: PhantomData,
        }
    }
}

impl<I, K> ScalarCallbacks for Format<I, K>
where
    I: ReadableNativeElement + 'static,
    K: for<'a> Fn(I::Ref<'a>, &mut String) -> Option<()> + Send + Sync + 'static,
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
        let mut output = output.cast::<String>()?;
        output.set_size(rows)?;
        let mut writer = output.writer()?;
        // The vector writer takes finished text, not a `fmt::Write` sink, so the kernels write
        // into one buffer that is reused for every row of the chunk. (A kernel whose text has a
        // longest form is a `MapInto` over a buffer of that length, with no copy in between.)
        let mut text = String::new();
        for (row, value) in input.reader()?.iter().enumerate() {
            text.clear();
            let written = value.and_then(|value| (self.kernel)(value, &mut text));
            writer.set_option(row, written.map(|()| text.as_str()))?;
        }
        Ok(())
    }
}

/// The vectors of one call of a match function, `f(I, VARCHAR) -> BOOLEAN`.
struct MatchVectors<'a, I: NativeElement> {
    /// The rows of the chunk, which `output` is sized to.
    rows: usize,
    values: Vector<'a, I>,
    patterns: Vector<'a, String>,
    output: Vector<'a, bool>,
}

impl<'a, I: NativeElement> MatchVectors<'a, I> {
    fn new(vectors: &'a mut VectorCollection, output: Vector<'a, Unknown>) -> Result<Self> {
        let rows = vectors.row_count()?;
        let [values, patterns] = vectors.get_vector_array_mut([0, 1])?;
        let values = readable(values.cast::<I>()?)?;
        let patterns = readable(patterns.cast::<String>()?)?;
        let mut output = output.cast::<bool>()?;
        output.set_size(rows)?;
        Ok(Self {
            rows,
            values,
            patterns,
            output,
        })
    }
}

/// The rows of a match function, each value tested against the pattern of its own row. The
/// pattern is parsed again whenever the text differs from the row before.
fn match_rows<I, P>(
    values: &VectorReader<'_, I>,
    texts: &VectorReader<'_, String>,
    writer: &mut VectorWriter<'_, bool>,
    parse: impl Fn(&str) -> Option<P>,
    test: impl for<'a> Fn(I::Ref<'a>, &P) -> Option<bool>,
) -> Result<()>
where
    I: ReadableNativeElement,
{
    let mut parsed: Option<(&str, Option<P>)> = None;
    for (row, (value, text)) in values.iter().zip(texts.iter()).enumerate() {
        let result = match (value, text) {
            (Some(value), Some(text)) => {
                if parsed.as_ref().is_none_or(|(last, _)| *last != text) {
                    parsed = Some((text, parse(text)));
                }
                let pattern = parsed.as_ref().and_then(|(_, pattern)| pattern.as_ref());
                pattern.and_then(|pattern| test(value, pattern))
            }
            _ => None,
        };
        writer.set_option(row, result.as_ref())?;
    }
    Ok(())
}

/// `f(I, VARCHAR) -> BOOLEAN`: a value tested against a pattern that is parsed from text, such as
/// a CIDR network. NULL when the text is not a pattern, or when `test` returns `None`.
///
/// The pattern is nearly always a literal, which arrives as a constant vector and is parsed once
/// for the chunk. Otherwise it is parsed again whenever the text differs from the row before.
struct Match<I, P, Parse, Test> {
    parse: Parse,
    test: Test,
    types: PhantomData<fn(I) -> P>,
}

impl<I, P, Parse, Test> Match<I, P, Parse, Test>
where
    I: ReadableNativeElement + 'static,
    Parse: Fn(&str) -> Option<P>,
    Test: for<'a> Fn(I::Ref<'a>, &P) -> Option<bool>,
{
    fn new(parse: Parse, test: Test) -> Self {
        Self {
            parse,
            test,
            types: PhantomData,
        }
    }
}

impl<I, P, Parse, Test> ScalarCallbacks for Match<I, P, Parse, Test>
where
    I: ReadableNativeElement + 'static,
    P: 'static,
    Parse: Fn(&str) -> Option<P> + Send + Sync + 'static,
    Test: for<'a> Fn(I::Ref<'a>, &P) -> Option<bool> + Send + Sync + 'static,
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
        let MatchVectors {
            rows,
            values,
            patterns,
            mut output,
        } = MatchVectors::<I>::new(vectors, output)?;
        let mut writer = output.writer()?;
        if rows == 0 {
            return Ok(());
        }

        let values = values.reader()?;
        let texts = patterns.reader()?;
        if patterns.storage_kind() == StorageKind::Constant {
            let Some(pattern) = texts.get(0)?.and_then(&self.parse) else {
                return writer.fill_null();
            };
            for (row, value) in values.iter().enumerate() {
                let result = value.and_then(|value| (self.test)(value, &pattern));
                writer.set_option(row, result.as_ref())?;
            }
            Ok(())
        } else {
            match_rows(&values, &texts, &mut writer, &self.parse, &self.test)
        }
    }
}

/// The values of a flat vector that has no NULL row, as a slice: row `r` is `values[r]`. `None`
/// for a vector with a NULL row and for one that is not flat (its rows are behind the selection
/// of a dictionary or constant vector), whose values the caller reads through the reader.
///
/// This is the one `unsafe` call of the crate outside `engine::writer`. Nothing is required of
/// the caller: the function checks what the call needs.
fn values_without_nulls<'vector, I>(reader: &VectorReader<'vector, I>) -> Option<&'vector [I]>
where
    I: PlainNative + NativeElement<Native<'vector> = I>,
{
    let rows = reader.len();
    // Flat: the slots of the vector are its rows, in order, and there are `rows` of them.
    if !matches!(reader.selection(), Selection::Identity) {
        return None;
    }
    // No NULL: bit `r % 64` of word `r / 64` of the mask is set for every row `r`. The bits after
    // the last row say nothing. A vector without a mask has no NULL.
    if let Some(validity) = reader.validity() {
        let (words, tail) = (rows / 64, rows % 64);
        if validity.get(..words)?.iter().any(|word| *word != u64::MAX) {
            return None;
        }
        if tail != 0 && !validity.get(words)? & ((1u64 << tail) - 1) != 0 {
            return None;
        }
    }
    // SAFETY: `VectorReader::as_slice` returns the vector's physical slots as `&[I::Native]`,
    // for the lifetime of the borrow of the vector the reader holds, and requires one thing:
    // that every slot it exposes, including that of a NULL row and one no row selects, is
    // initialised as `I::Native`. DuckDB does not promise that for the slot of a NULL row (an
    // operator need not write it, and the buffer is not zeroed), so:
    //
    // - the vector is flat (checked above), so the slots exposed are exactly rows `0..rows`:
    //   there is no slot that a selection leaves out;
    // - no row is NULL (checked above), and DuckDB reads the slot of a non-NULL row as a value
    //   of the vector's type wherever it evaluates one, so every operator writes it: all of
    //   `0..rows` are initialised;
    // - the vector's logical type was checked to be the one stored as `I` when `duckdb-neo`
    //   attached the type to it (`Vector::cast`), `I::Native` is `I` (the bound above), and
    //   every bit pattern of a slot is a value of a `PlainNative` type.
    //
    // The reader borrows the vector, so nothing resizes or writes it while the slice lives.
    #[allow(unsafe_code)]
    let values = unsafe { reader.as_slice() }?;
    // Flat storage has one slot per row.
    (values.len() == rows).then_some(values)
}

/// The rows of a chunk a [`MatchPlain`] has room to answer at once: DuckDB's vector size
/// (`STANDARD_VECTOR_SIZE`), which no chunk exceeds.
const BLOCK: usize = 2048;

/// [`Match`] for a value that is stored as itself (an integer) and a test that has an answer
/// for every value: `f(I, VARCHAR) -> BOOLEAN`, NULL only for a NULL argument or text that is
/// not a pattern.
///
/// With a constant pattern (a literal) the answers of a chunk are computed into an array of
/// `bool`s in a loop that does nothing else, and copied into the output as one slice, which
/// also marks the rows valid; the rows of NULL values are then made NULL from the input's
/// validity mask, which costs nothing for an input without NULLs. A NULL value is not tested:
/// its answer is `false` until then.
///
/// The loop that computes the answers reads the values as a slice ([`values_without_nulls`]) and
/// does nothing but test them, so the compiler turns it into a SIMD compare. `duckdb-neo` lends
/// that slice only on the promise that every slot of the vector holds a value, which is not so
/// for the slot of a NULL row: a chunk with a NULL value, and one whose values are behind a
/// selection (a dictionary or constant vector), is read through the vector reader instead, a row
/// at a time.
struct MatchPlain<I, P, Parse, Test> {
    parse: Parse,
    test: Test,
    types: PhantomData<fn(I) -> P>,
}

impl<I, P, Parse, Test> MatchPlain<I, P, Parse, Test>
where
    I: PlainNative + 'static,
    Parse: Fn(&str) -> Option<P>,
    Test: Fn(I, &P) -> bool,
{
    fn new(parse: Parse, test: Test) -> Self {
        Self {
            parse,
            test,
            types: PhantomData,
        }
    }
}

impl<I, P, Parse, Test> ScalarCallbacks for MatchPlain<I, P, Parse, Test>
where
    I: PlainNative
        + for<'a> ReadableNativeElement<Ref<'a> = &'a I>
        + for<'a> NativeElement<Native<'a> = I>
        + 'static,
    P: 'static,
    Parse: Fn(&str) -> Option<P> + Send + Sync + 'static,
    Test: Fn(I, &P) -> bool + Send + Sync + 'static,
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
        let MatchVectors {
            rows,
            values,
            patterns,
            mut output,
        } = MatchVectors::<I>::new(vectors, output)?;
        let mut writer = output.writer()?;
        if rows == 0 {
            return Ok(());
        }

        let values = values.reader()?;
        let texts = patterns.reader()?;
        if patterns.storage_kind() != StorageKind::Constant {
            return match_rows(
                &values,
                &texts,
                &mut writer,
                &self.parse,
                |value, pattern| Some((self.test)(*value, pattern)),
            );
        }
        let Some(pattern) = texts.get(0)?.and_then(&self.parse) else {
            return writer.fill_null();
        };

        let mut block = [false; BLOCK];
        let Some(answers) = block.get_mut(..values.len()) else {
            // More rows than DuckDB puts in a chunk: answer them one by one.
            for (row, value) in values.iter().enumerate() {
                let answer = value.map(|value| (self.test)(*value, &pattern));
                writer.set_option(row, answer.as_ref())?;
            }
            return Ok(());
        };
        if let Some(values) = values_without_nulls(&values) {
            // Nothing but the test, over two slices: a SIMD compare. No row is NULL.
            for (answer, value) in answers.iter_mut().zip(values) {
                *answer = (self.test)(*value, &pattern);
            }
            return writer.write_slice(0, answers);
        }
        for (answer, value) in answers.iter_mut().zip(values.iter()) {
            *answer = value.is_some_and(|value| (self.test)(*value, &pattern));
        }
        // Marks the rows valid.
        writer.write_slice(0, answers)?;

        // The NULLs. A vector without a validity mask has none.
        let Some(validity) = values.validity() else {
            return Ok(());
        };
        if matches!(values.selection(), Selection::Identity) {
            // A flat vector: row `r` is bit `r % 64` of word `r / 64`, set when not NULL. Whole
            // words without a NULL are skipped.
            for (index, word) in validity.iter().enumerate() {
                let mut nulls = !word;
                while nulls != 0 {
                    let row = index * 64 + nulls.trailing_zeros() as usize;
                    if row >= rows {
                        // Bits after the last row.
                        break;
                    }
                    writer.set_null(row)?;
                    nulls &= nulls - 1;
                }
            }
        } else {
            // The mask is of the physical slots a selection maps the rows to.
            for row in 0..rows {
                if values.is_null(row)? {
                    writer.set_null(row)?;
                }
            }
        }
        Ok(())
    }
}
