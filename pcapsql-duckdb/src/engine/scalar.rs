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
//!   (`ip_in_cidr`, `has_tcp_flag`), with the answers of a chunk computed over slices of its
//!   values and stored as one slice when the pattern is constant.
//!
//! The kernel is a type parameter of the loop (a function item or a closure that captures
//! nothing), not a function pointer in it: each function gets its own copy of the loop, with the
//! kernel inlined into it.
//!
//! Inputs are read through `duckdb-neo`'s vector reader, which maps rows through the vector's
//! selection, so flat, constant and dictionary inputs all work. NULL in gives NULL out, and so
//! does a value the kernel rejects: no function raises an error for its input.
//!
//! One module here has `unsafe` code, the second of the two places in the crate that do
//! (`scripts/check-unsafe.sh`): [`valid`] borrows the values of rows of a flat vector as a
//! slice when none of those rows is NULL, and says why it may.

use std::borrow::{Borrow, Cow};
use std::marker::PhantomData;
use std::ops::Range;

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

/// The values of rows of a flat vector as slices, for the rows that are not NULL.
///
/// This module is the one place of the crate outside `engine::writer` with `unsafe` code
/// (`scripts/check-unsafe.sh`). It has two functions. [`values`](valid::values) is what the rest
/// of the file calls, and requires nothing of its caller: it checks what the borrow needs.
/// `slots` forms the slice, from a pointer and a validity mask instead of a vector, so that its
/// tests can give it a buffer whose NULL slots are not initialised, under Miri.
///
/// What is and is not read: a slot is covered by a slice only if its row is in the range asked
/// for and the range has no NULL row. The slot of a NULL row is never part of a slice and is
/// never read, as an integer or as anything else: DuckDB does not promise to initialise it (an
/// operator need not write it, and the buffer is not zeroed), and reading uninitialised memory as
/// an integer is undefined behaviour. So `VectorReader::as_slice`, which exposes every slot of
/// the vector, is not what is called here.
#[allow(unsafe_code)]
mod valid {
    use std::ops::Range;
    use std::slice;

    use duckdb_neo::vector::{NativeElement, PlainNative, Selection, VectorReader};

    /// The values of rows `rows` of a flat vector as a slice: `values[i]` is row
    /// `rows.start + i`. `None` if one of the rows is NULL, if the range is not of rows of the
    /// vector, and for a vector that is not flat (its rows are behind the selection of a
    /// dictionary or constant vector): the caller reads those rows through the reader.
    pub(super) fn values<'vector, I>(
        reader: &VectorReader<'vector, I>,
        rows: Range<usize>,
    ) -> Option<&'vector [I]>
    where
        I: PlainNative + NativeElement<Native<'vector> = I>,
    {
        // Flat: slot `r` of the vector is row `r`, and the mask is of the rows.
        if !matches!(reader.selection(), Selection::Identity) {
            return None;
        }
        // SAFETY: what `slots` requires, in its order.
        //
        // - The pointer is the `data` of the view DuckDB gave `duckdb-neo` for this vector
        //   (`duckdb_v2_vector_get_view`), which is where DuckDB itself reads the rows from. The
        //   vector is flat (checked above), so that buffer has a slot for each of its
        //   `reader.len()` rows, in row order. The vector's logical type was checked to be the
        //   one stored as `I` when `duckdb-neo` attached the type to it (`Vector::cast`),
        //   `I::Native` is `I` (the bound above), and a `PlainNative` type has the size and
        //   alignment of the slot.
        // - `'vector` is the reader's borrow of the vector. It is a shared borrow, so for as
        //   long as it lasts there is no writer of the vector, nothing resizes it, and DuckDB,
        //   which is waiting for this function call to return, does not free it.
        // - The mask is the `validity` of the same view, of the same rows: bit `r % 64` of word
        //   `r / 64` is set when row `r` is not NULL, and a vector without a mask has no NULL.
        //   DuckDB reads the slot of a row that is not NULL as a value of the vector's type
        //   wherever it evaluates one, so whichever operator produced the vector wrote it; and
        //   every bit pattern of the slot is a value of a `PlainNative` type.
        //
        // Nothing is assumed of the slot of a NULL row.
        unsafe { slots(reader.as_ptr(), reader.len(), reader.validity(), rows) }
    }

    /// Slots `rows` of the `len` slots at `data` as a slice, if the bit of each of them is set
    /// in `validity`, or there is no mask. `None` otherwise, also for a range that is not within
    /// `0..len`, for a mask that is too short for it, and for a pointer that is null or not
    /// aligned for `T`.
    ///
    /// No slot outside `rows` is covered by the slice, and no slot at all is read here.
    ///
    /// # Safety
    ///
    /// - `data` is null, or points to the first of `len` slots of the size of `T` in one
    ///   allocation;
    /// - nothing writes or frees those slots for `'a`;
    /// - slot `r` holds an initialised value of `T` if bit `r % 64` of `validity[r / 64]` is
    ///   set, and, when `validity` is `None`, for every `r < len`. Other slots need not be
    ///   initialised.
    unsafe fn slots<'a, T>(
        data: *const T,
        len: usize,
        validity: Option<&[u64]>,
        rows: Range<usize>,
    ) -> Option<&'a [T]> {
        if data.is_null() || !data.is_aligned() || rows.start > rows.end || rows.end > len {
            return None;
        }
        if !validity.is_none_or(|validity| all_set(validity, rows.clone())) {
            return None;
        }
        // SAFETY: `data` is not null and is aligned for `T` (checked above), and
        // `rows.start <= rows.end <= len` (checked above), so `data.add(rows.start)` is within
        // the allocation of the `len` slots, or one past its end for an empty range at `len`,
        // and the `rows.end - rows.start` slots from there are slots `rows` of it: of one
        // allocation, and no more than `isize::MAX` bytes, as an allocation is. Each of them
        // holds an initialised `T`: its bit is set in the mask (checked above) or there is no
        // mask, which is when the caller promises that. Nothing writes or frees them for `'a`
        // (the caller's promise), and a shared slice does not either.
        Some(unsafe { slice::from_raw_parts(data.add(rows.start), rows.end - rows.start) })
    }

    /// Whether every one of bits `bits` is set, where bit `b` is bit `b % 64` of `words[b / 64]`.
    /// False for a bit of a word that is not there.
    fn all_set(words: &[u64], bits: Range<usize>) -> bool {
        if bits.is_empty() {
            return true;
        }
        let (first, last) = (bits.start / 64, (bits.end - 1) / 64);
        (first..=last).all(|index| {
            // The bits of this word that are in the range: `low..high`, at least one.
            let low = if index == first { bits.start % 64 } else { 0 };
            let high = if index == last {
                (bits.end - 1) % 64 + 1
            } else {
                64
            };
            let mask = (u64::MAX >> (64 - (high - low))) << low;
            words.get(index).is_some_and(|word| word & mask == mask)
        })
    }

    /// These run under Miri (`cargo +nightly miri test -p pcapsql-duckdb --lib valid`), which
    /// reports a read of a slot that was never written. Miri runs them a thousand times slower,
    /// so under it they take fewer sizes, and fewer ranges of each.
    #[cfg(test)]
    mod tests {
        use std::mem::MaybeUninit;

        use super::super::{Nulls, Spans};
        use super::*;

        /// A buffer of `len` slots where slot `r` holds `r` if `valid(r)` and is not
        /// initialised otherwise, and its validity mask. The bits after the last slot are set,
        /// as DuckDB may leave them.
        fn column(len: usize, valid: impl Fn(usize) -> bool) -> (Vec<MaybeUninit<u32>>, Vec<u64>) {
            let mut slots = Vec::with_capacity(len);
            let mut validity = vec![0u64; len.div_ceil(64)];
            for row in 0..len {
                if valid(row) {
                    slots.push(MaybeUninit::new(row as u32));
                    validity[row / 64] |= 1 << (row % 64);
                } else {
                    slots.push(MaybeUninit::uninit());
                }
            }
            if let Some(last) = validity.last_mut().filter(|_| !len.is_multiple_of(64)) {
                *last |= u64::MAX << (len % 64);
            }
            (slots, validity)
        }

        /// `slots` over a buffer of [`column`].
        fn slice<'a>(
            slots: &'a [MaybeUninit<u32>],
            validity: Option<&[u64]>,
            rows: Range<usize>,
        ) -> Option<&'a [u32]> {
            // SAFETY: the pointer is of the `slots.len()` slots of the buffer, which is borrowed
            // for `'a`; `column` initialised each slot whose bit it set, and the tests that pass
            // no mask initialised every slot.
            unsafe { super::slots(slots.as_ptr().cast::<u32>(), slots.len(), validity, rows) }
        }

        /// Whether a row is valid.
        type Valid = Box<dyn Fn(usize) -> bool>;

        /// The NULL patterns of the tests: which rows of `len` are valid.
        fn patterns(len: usize) -> Vec<(&'static str, Valid)> {
            // A fixed pseudo-random sequence: the same NULLs in every run.
            let random = |percent: u64| {
                Box::new(move |row: usize| {
                    let hash =
                        (row as u64 ^ 0x9e37_79b9_7f4a_7c15).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                    (hash >> 32) % 100 >= percent
                }) as Valid
            };
            vec![
                ("no NULL", Box::new(|_| true)),
                ("all NULL", Box::new(|_| false)),
                ("first", Box::new(|row| row != 0)),
                ("last", Box::new(move |row| row + 1 != len)),
                ("bit 0 of each word", Box::new(|row| row % 64 != 0)),
                ("bit 63 of each word", Box::new(|row| row % 64 != 63)),
                ("only bit 0 of each word", Box::new(|row| row % 64 == 0)),
                ("only bit 63 of each word", Box::new(|row| row % 64 == 63)),
                ("alternate rows", Box::new(|row| row % 2 == 0)),
                ("alternate words", Box::new(|row| row / 64 % 2 == 0)),
                (
                    "alternate words, NULL first",
                    Box::new(|row| row / 64 % 2 == 1),
                ),
                ("runs", Box::new(|row| row % 100 < 37)),
                ("runs across words", Box::new(|row| (row + 50) % 200 < 130)),
                ("1% NULL", random(1)),
                ("50% NULL", random(50)),
                ("99% NULL", random(99)),
            ]
        }

        /// The numbers of rows of the tests: around a word of the mask and, without Miri,
        /// around a chunk.
        fn sizes() -> &'static [usize] {
            if cfg!(miri) {
                &[0, 1, 63, 64, 65, 127, 128, 129, 200]
            } else {
                &[0, 1, 63, 64, 65, 127, 128, 129, 2047, 2048, 2049, 4097]
            }
        }

        #[test]
        fn a_range_is_a_slice_exactly_when_it_has_no_null() {
            for len in [0, 1, 63, 64, 65, 130] {
                // From every row, or under Miri from the rows around the words.
                let starts: Vec<usize> = if cfg!(miri) {
                    [0, 1, 31, 62, 63, 64, 65, 66, 127, 128, 129, 130]
                        .into_iter()
                        .filter(|start| *start <= len)
                        .collect()
                } else {
                    (0..=len).collect()
                };
                for (name, valid) in patterns(len) {
                    let (slots, validity) = column(len, &valid);
                    for &start in &starts {
                        // Ranges of up to a word and a row, or under Miri those around a word.
                        let ends: Vec<usize> = if cfg!(miri) {
                            vec![start, start + 1, start + 63, start + 64, start + 65, len]
                        } else {
                            (start..=start + 65).collect()
                        };
                        for end in ends.into_iter().filter(|end| *end <= len) {
                            let values = slice(&slots, Some(&validity), start..end);
                            let context = format_args!("{len} {name} {start}..{end}");
                            if (start..end).all(&valid) {
                                let values = values.unwrap_or_else(|| panic!("{context}"));
                                let rows = (start..end).map(|row| row as u32);
                                assert!(values.iter().copied().eq(rows), "{context}");
                            } else {
                                assert_eq!(values, None, "{context}");
                            }
                        }
                    }
                }
            }
        }

        /// What `MatchPlain` does with a chunk: the sum of the values of its rows that are not
        /// NULL, read as slices where the mask has no NULL and by row where it has some.
        fn sum(slots: &[MaybeUninit<u32>], validity: Option<&[u64]>, context: &str) -> u64 {
            let mut covered = 0;
            let mut sum = 0;
            for (span, nulls) in Spans::new(validity, slots.len()) {
                assert_eq!(span.start, covered, "{context}");
                assert!(!span.is_empty(), "{context}");
                covered = span.end;
                let is_valid = |row: usize| {
                    validity.is_none_or(|words| words[row / 64] & (1 << (row % 64)) != 0)
                };
                let values = slice(slots, validity, span.clone());
                match nulls {
                    Nulls::None => {
                        // Reads every slot of the slice: Miri would report one not written.
                        let values = values.unwrap_or_else(|| panic!("{context} {span:?}"));
                        assert!(values.iter().copied().eq(span.map(|row| row as u32)));
                        sum += values.iter().map(|value| u64::from(*value)).sum::<u64>();
                    }
                    Nulls::All => assert!(!span.clone().any(is_valid), "{context} {span:?}"),
                    Nulls::Some => {
                        assert_eq!(values, None, "{context} {span:?}");
                        assert!(span.clone().any(&is_valid), "{context} {span:?}");
                        // A row that is not NULL is a slice of one.
                        for row in span.filter(|row| is_valid(*row)) {
                            let value = slice(slots, validity, row..row + 1).unwrap();
                            sum += u64::from(value[0]);
                        }
                    }
                }
            }
            assert_eq!(covered, slots.len(), "{context}");
            sum
        }

        #[test]
        fn the_spans_of_a_mask_read_every_valid_row_and_no_other() {
            for &len in sizes() {
                for (name, valid) in patterns(len) {
                    let (slots, validity) = column(len, &valid);
                    let expected: u64 = (0..len)
                        .filter(|row| valid(*row))
                        .map(|row| row as u64)
                        .sum();
                    assert_eq!(sum(&slots, Some(&validity), name), expected, "{len} {name}");
                }
            }
        }

        #[test]
        fn runs_of_nulls_of_every_length_leave_the_rows_around_them() {
            let len = 700;
            let lengths: Vec<usize> = if cfg!(miri) {
                vec![1, 2, 63, 64, 65, 127, 128, 129, 200]
            } else {
                (1..=200).collect()
            };
            for nulls in lengths {
                // A different place in the word for each length.
                let offset = nulls * 7 % 300;
                let valid = |row: usize| !(offset..offset + nulls).contains(&row);
                let (slots, validity) = column(len, valid);
                let expected: u64 = (0..len)
                    .filter(|row| valid(*row))
                    .map(|row| row as u64)
                    .sum();
                let context = format!("{nulls} NULLs at {offset}");
                assert_eq!(
                    sum(&slots, Some(&validity), &context),
                    expected,
                    "{context}"
                );
                // The rows before the NULLs and after them are slices; a range that reaches
                // into the NULLs from either side is not.
                for (rows, lent) in [
                    (0..offset, true),
                    (offset + nulls..len, true),
                    (0..offset + 1, false),
                    (offset + nulls - 1..len, false),
                    (offset..offset + nulls, false),
                ] {
                    let values = slice(&slots, Some(&validity), rows.clone());
                    assert_eq!(values.is_some(), lent, "{context} {rows:?}");
                    if let Some(values) = values {
                        assert!(values.iter().copied().eq(rows.map(|row| row as u32)));
                    }
                }
            }
        }

        #[test]
        fn a_vector_without_a_mask_is_one_slice() {
            for &len in sizes() {
                let (slots, _) = column(len, |_| true);
                let spans: Vec<_> = Spans::new(None, len).collect();
                assert_eq!(
                    spans,
                    Vec::from_iter((len != 0).then_some((0..len, Nulls::None)))
                );
                let expected: u64 = (0..len).map(|row| row as u64).sum();
                assert_eq!(sum(&slots, None, "no mask"), expected, "{len}");
            }
        }

        #[test]
        fn words_that_are_alike_are_one_span() {
            let words = [
                u64::MAX,
                u64::MAX,
                0,
                0,
                0,
                0b101,
                u64::MAX,
                1 << 63,
                0,
                u64::MAX,
            ];
            let spans: Vec<_> = Spans::new(Some(&words), 640 - 3).collect();
            assert_eq!(
                spans,
                [
                    (0..128, Nulls::None),
                    (128..320, Nulls::All),
                    (320..384, Nulls::Some),
                    (384..448, Nulls::None),
                    (448..512, Nulls::Some),
                    (512..576, Nulls::All),
                    (576..637, Nulls::None),
                ]
            );
            // A mask without a NULL is one span, as no mask is.
            let spans: Vec<_> = Spans::new(Some(&[u64::MAX; 33]), 2049).collect();
            assert_eq!(spans, [(0..2049, Nulls::None)]);
            let spans: Vec<_> = Spans::new(Some(&[0; 33]), 2049).collect();
            assert_eq!(spans, [(0..2049, Nulls::All)]);
        }

        #[test]
        fn the_bits_after_the_last_row_are_not_rows() {
            let spans: Vec<_> = Spans::new(Some(&[u64::MAX, !0b111]), 67).collect();
            assert_eq!(spans, [(0..64, Nulls::None), (64..67, Nulls::All)]);
            let spans: Vec<_> = Spans::new(Some(&[u64::MAX, 0b111]), 67).collect();
            assert_eq!(spans, [(0..67, Nulls::None)]);
            let spans: Vec<_> = Spans::new(Some(&[0, 0b111 << 3]), 67).collect();
            assert_eq!(spans, [(0..67, Nulls::All)]);
            let spans: Vec<_> = Spans::new(Some(&[u64::MAX, 0b101]), 67).collect();
            assert_eq!(spans, [(0..64, Nulls::None), (64..67, Nulls::Some)]);
            // Nor is a row whose word the mask does not have one to read.
            let spans: Vec<_> = Spans::new(Some(&[1 << 63]), 100).collect();
            assert_eq!(spans, [(0..64, Nulls::Some), (64..100, Nulls::All)]);
        }

        #[test]
        fn what_is_not_a_range_of_the_slots_is_not_a_slice() {
            let (slots, validity) = column(130, |_| true);
            assert_eq!(slice(&slots, Some(&validity), 0..131), None);
            assert_eq!(slice(&slots, None, 131..131), None);
            #[allow(clippy::reversed_empty_ranges)]
            let reversed = 5..4;
            assert_eq!(slice(&slots, None, reversed), None);
            // A mask without the word of a row: nothing says the row is valid.
            assert_eq!(slice(&slots, Some(&validity[..2]), 100..129), None);
            assert_eq!(
                slice(&slots, Some(&validity[..2]), 100..128).map(<[u32]>::len),
                Some(28)
            );
            assert_eq!(slice(&slots, Some(&[]), 0..1), None);
            assert_eq!(slice(&slots, Some(&[]), 7..7), Some(&[][..]));
            // SAFETY: a null pointer, and one that is not aligned for `u32`, are refused before
            // anything is made of them.
            unsafe {
                assert_eq!(super::slots::<u32>(std::ptr::null(), 4, None, 0..4), None);
                let unaligned = slots.as_ptr().cast::<u8>().wrapping_add(1).cast::<u32>();
                assert_eq!(super::slots(unaligned, 4, None, 0..4), None);
            }
        }
    }
}

/// What the validity mask says of a span of rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Nulls {
    /// No row of the span is NULL.
    None,
    /// Some rows are NULL and some are not.
    Some,
    /// Every row is NULL.
    All,
}

/// The bits of the rows of the word of a validity mask whose first row is `first`, one of
/// `rows` rows: all 64, or in the last word the low ones of as many rows as are left.
fn row_bits(first: usize, rows: usize) -> u64 {
    u64::MAX >> (64 - rows.saturating_sub(first).clamp(1, 64))
}

/// Rows `0..rows` in spans of whole words of a validity mask, in order, where row `r` is bit
/// `r % 64` of word `r / 64`, set when the row is not NULL. A span is the rows of one word that
/// has both NULLs and rows that are not, or of as many words in a row as have no NULL, or of as
/// many as have nothing else; the last word has the rows there are, and its other bits say
/// nothing. Without a mask no row is NULL, and the rows are one span.
///
/// The mask has a word for every row ([`MatchPlain`] gives it no other); the rows of a word
/// that is not there are [`Nulls::All`], which nothing reads.
struct Spans<'a> {
    validity: Option<&'a [u64]>,
    /// The first row no span has covered yet: the first of a word.
    next: usize,
    rows: usize,
}

impl<'a> Spans<'a> {
    fn new(validity: Option<&'a [u64]>, rows: usize) -> Self {
        Self {
            validity,
            next: 0,
            rows,
        }
    }

    /// The rows of the word that `start` is the first row of: where they end, and their NULLs.
    fn word(&self, words: &[u64], start: usize) -> (usize, Nulls) {
        let end = self.rows.min(start + 64);
        let all = row_bits(start, self.rows);
        let nulls = match words.get(start / 64).map_or(all, |word| !word & all) {
            0 => Nulls::None,
            nulls if nulls == all => Nulls::All,
            _ => Nulls::Some,
        };
        (end, nulls)
    }
}

impl Iterator for Spans<'_> {
    type Item = (Range<usize>, Nulls);

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.next;
        if start >= self.rows {
            return None;
        }
        let Some(words) = self.validity else {
            self.next = self.rows;
            return Some((start..self.rows, Nulls::None));
        };
        let (mut end, nulls) = self.word(words, start);
        if nulls != Nulls::Some {
            // The words after it that are alike.
            while end < self.rows {
                let (after, next) = self.word(words, end);
                if next != nulls {
                    break;
                }
                end = after;
            }
        }
        self.next = end;
        Some((start..end, nulls))
    }
}

/// Make the rows among `0..rows` that are NULL in a validity mask NULL in the output: row `r`
/// is bit `r % 64` of word `r / 64`, set when the row is not NULL. With `stored`, only the rows
/// of the words that have a row that is not NULL, which are the ones [`MatchPlain`] stores
/// answers in.
#[inline(always)]
fn null_rows(
    writer: &mut VectorWriter<'_, bool>,
    words: &[u64],
    rows: usize,
    stored: bool,
) -> Result<()> {
    for (index, word) in words.iter().enumerate().take(rows.div_ceil(64)) {
        let first = index * 64;
        let all = row_bits(first, rows);
        let mut nulls = !word & all;
        if stored && nulls == all {
            continue;
        }
        // Words without a NULL are skipped.
        while nulls != 0 {
            writer.set_null(first + nulls.trailing_zeros() as usize)?;
            nulls &= nulls - 1;
        }
    }
    Ok(())
}

/// The rows of a chunk a [`MatchPlain`] has room to answer at once: DuckDB's vector size
/// (`STANDARD_VECTOR_SIZE`), which no chunk exceeds.
const BLOCK: usize = 2048;

/// [`Match`] for a value that is stored as itself (an integer) and a test that has an answer
/// for every value: `f(I, VARCHAR) -> BOOLEAN`, NULL only for a NULL argument or text that is
/// not a pattern.
///
/// With a constant pattern (a literal) the answers of a chunk are computed into an array of
/// `bool`s in a loop that does nothing else, and copied into the output as slices, which also
/// marks the rows valid. The loop reads the values of a flat vector as a slice
/// ([`valid::values`]) and does nothing but test them, so the compiler turns it into a SIMD
/// compare.
///
/// A slice of values is of rows that are not NULL, because the slot of a NULL row holds nothing
/// that may be read: the whole chunk when it has no validity mask, and otherwise the rows of
/// the 64-row words of the mask that have no NULL ([`Spans`]). The rows of a word that are all
/// NULL are not read and not written (the output is made NULL first, once, if there is such a
/// word). Those of a word with some NULLs are read through the vector reader, a row at a time,
/// which reads the rows that are not NULL; the answer of a NULL row is `false` until its row
/// is made NULL from the mask, after the answers are stored. So NULLs that come in runs, as the
/// `tcp_flags` of packets that are not TCP do, cost the SIMD compare only the words at the ends
/// of each run.
///
/// Where NULLs are here and there in more than three words of four, nothing is gained by
/// telling the words apart, and the whole chunk is read through the reader; so is a chunk
/// whose values are behind a selection (a dictionary or constant vector).
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
        let Some(answers) = block.get_mut(..rows) else {
            // More rows than DuckDB puts in a chunk: answer them one by one.
            for (row, value) in values.iter().enumerate() {
                let answer = value.map(|value| (self.test)(*value, &pattern));
                writer.set_option(row, answer.as_ref())?;
            }
            return Ok(());
        };
        let validity = values.validity();
        // A flat vector: row `r` is slot `r`, and bit `r % 64` of word `r / 64` of the mask.
        let flat = matches!(values.selection(), Selection::Identity)
            && validity.is_none_or(|words| words.len() >= rows.div_ceil(64));
        // The whole words of the mask that have NULLs and rows that are not NULL.
        let mixed = validity.filter(|_| flat).map_or(0, |words| {
            let whole = words.iter().take(rows / 64);
            whole
                .filter(|word| **word != 0 && **word != u64::MAX)
                .count()
        });
        if !flat || mixed * 64 > rows / 4 * 3 {
            // The rows are behind a selection, or NULL here and there.
            let validity = validity.map(|words| (words, flat));
            self.answer_rows(&values, validity, answers, &mut writer, &pattern)
        } else {
            self.answer_spans(&values, validity, answers, &mut writer, &pattern)
        }
    }
}

impl<I, P, Parse, Test> MatchPlain<I, P, Parse, Test>
where
    I: PlainNative
        + for<'a> ReadableNativeElement<Ref<'a> = &'a I>
        + for<'a> NativeElement<Native<'a> = I>
        + 'static,
    Test: Fn(I, &P) -> bool,
{
    /// The answers of a chunk, all of its rows read through the reader, which reads the ones
    /// that are not NULL: computed in `answers` and stored in the output; then its NULLs, from
    /// the mask of the rows if `validity` says it is that (the mask of a flat vector), and
    /// through the reader if it is of the slots a selection maps the rows to.
    ///
    /// Not inlined, and nor is [`Self::answer_spans`]: each loop is compiled as it is without
    /// the other beside it.
    #[inline(never)]
    fn answer_rows(
        &self,
        values: &VectorReader<'_, I>,
        validity: Option<(&[u64], bool)>,
        answers: &mut [bool],
        writer: &mut VectorWriter<'_, bool>,
        pattern: &P,
    ) -> Result<()> {
        // (`for_each`, not `for`: the reader then tells a flat, a constant and a dictionary
        // vector apart once, not for every row.)
        let mut slots = answers.iter_mut();
        values.iter().for_each(|value| {
            if let Some(answer) = slots.next() {
                *answer = value.is_some_and(|value| (self.test)(*value, pattern));
            }
        });
        // Marks the rows valid.
        writer.write_slice(0, answers)?;
        // The NULLs. A vector without a validity mask has none.
        match validity {
            Some((words, true)) => null_rows(writer, words, answers.len(), false),
            Some((_, false)) => (0..answers.len()).try_for_each(|row| {
                if values.is_null(row)? {
                    writer.set_null(row)?;
                }
                Ok(())
            }),
            None => Ok(()),
        }
    }

    /// The answers of a flat chunk, whose `validity` has a word for each of its rows, computed
    /// in `answers` a span of the mask at a time and stored in the output; then its NULLs.
    #[inline(never)]
    fn answer_spans(
        &self,
        values: &VectorReader<'_, I>,
        validity: Option<&[u64]>,
        answers: &mut [bool],
        writer: &mut VectorWriter<'_, bool>,
        pattern: &P,
    ) -> Result<()> {
        let rows = answers.len();
        // The answers of rows `stored..span.start` are computed and not stored yet.
        let mut stored = 0;
        for (span, nulls) in Spans::new(validity, rows) {
            let slice = match nulls {
                Nulls::None => valid::values(values, span.clone()),
                Nulls::Some => None,
                Nulls::All => {
                    // Nothing to read. The first such span makes every row of the output NULL,
                    // none of which has an answer stored yet; these rows stay so, and storing
                    // the answers of the rows before them marks those valid.
                    if stored == 0 {
                        writer.fill_null()?;
                    }
                    let answers = answers.get(stored..span.start).unwrap_or_default();
                    writer.write_slice(stored, answers)?;
                    stored = span.end;
                    continue;
                }
            };
            let answers = answers.get_mut(span.clone()).unwrap_or_default();
            if let Some(values) = slice {
                // Nothing but the test, over two slices: a SIMD compare. No row is NULL.
                for (answer, value) in answers.iter_mut().zip(values) {
                    *answer = (self.test)(*value, pattern);
                }
            } else {
                // Rows with NULLs among them, one by one: the reader reads the others.
                for (answer, row) in answers.iter_mut().zip(span) {
                    let value = values.get(row)?;
                    *answer = value.is_some_and(|value| (self.test)(*value, pattern));
                }
            }
        }
        writer.write_slice(stored, answers.get(stored..).unwrap_or_default())?;
        // The NULLs among the rows that were stored.
        if let Some(words) = validity {
            null_rows(writer, words, rows, true)?;
        }
        Ok(())
    }
}
