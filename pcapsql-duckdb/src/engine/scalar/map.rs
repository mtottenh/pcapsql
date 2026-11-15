//! The loops whose kernel gives the value of a row: [`Map`], [`MapInto`], [`ZipInto`] and
//! [`Format`], and the two instances of them that name a number, [`name`] and [`name_of_pair`].

use std::borrow::Borrow;
use std::fmt::Write;
use std::marker::PhantomData;

use duckdb_neo::{
    connection::Context,
    data_chunk::VectorCollection,
    scalar::ScalarCallbacks,
    vector::{ReadableNativeElement, Unknown, Vector, WritableNativeElement},
    Result,
};
use pcapsql_core::format;

use super::plain::Plain;
use super::{argument, readable};

/// `f(I) -> O`, where the kernel `K` returns the value, or `None` for NULL.
///
/// `R` is what the kernel returns: something that borrows as what the output vector stores, such
/// as `[u8; 6]` or `Vec<u8>` for a BLOB.
pub(super) struct Map<I, O, R, K> {
    kernel: K,
    types: PhantomData<fn(I) -> (O, R)>,
}

impl<I, O, R, K> Map<I, O, R, K>
where
    I: ReadableNativeElement + 'static,
    K: for<'a> Fn(I::Ref<'a>) -> Option<R>,
{
    pub(super) fn new(kernel: K) -> Self {
        Self {
            kernel,
            types: PhantomData,
        }
    }
}

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
pub(super) struct MapInto<I, O, S, K> {
    kernel: K,
    types: PhantomData<fn(I, S) -> O>,
}

impl<I, O, S, K> MapInto<I, O, S, K>
where
    I: ReadableNativeElement + 'static,
    O: WritableNativeElement + 'static,
    K: for<'a, 'b> Fn(I::Ref<'a>, &'b mut S) -> Option<&'b O::Write>,
{
    pub(super) fn new(kernel: K) -> Self {
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

/// `f(A, B) -> O`: [`MapInto`] for a kernel of two arguments. NULL when either is.
pub(super) struct ZipInto<A, B, O, S, K> {
    kernel: K,
    types: PhantomData<fn(A, B, S) -> O>,
}

impl<A, B, O, S, K> ZipInto<A, B, O, S, K>
where
    A: ReadableNativeElement + 'static,
    B: ReadableNativeElement + 'static,
    O: WritableNativeElement + 'static,
    K: for<'a, 'b> Fn(A::Ref<'a>, B::Ref<'a>, &'b mut S) -> Option<&'b O::Write>,
{
    pub(super) fn new(kernel: K) -> Self {
        Self {
            kernel,
            types: PhantomData,
        }
    }
}

impl<A, B, O, S, K> ScalarCallbacks for ZipInto<A, B, O, S, K>
where
    A: ReadableNativeElement + 'static,
    B: ReadableNativeElement + 'static,
    O: WritableNativeElement + 'static,
    S: Default + 'static,
    K: for<'a, 'b> Fn(A::Ref<'a>, B::Ref<'a>, &'b mut S) -> Option<&'b O::Write>
        + Send
        + Sync
        + 'static,
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
        let [first, second] = vectors.get_vector_array_mut([0, 1])?;
        let first = readable(first.cast::<A>()?)?;
        let second = readable(second.cast::<B>()?)?;
        let mut output = output.cast::<O>()?;
        output.set_size(rows)?;
        let mut writer = output.writer()?;
        let mut buffer = S::default();
        let (first, second) = (first.reader()?, second.reader()?);
        for (row, pair) in first.iter().zip(second.iter()).enumerate() {
            let result = match pair {
                (Some(first), Some(second)) => (self.kernel)(first, second, &mut buffer),
                _ => None,
            };
            writer.set_option(row, result)?;
        }
        Ok(())
    }
}

/// The text of a name, for a kernel of [`MapInto`]: a name of the table is the static string
/// itself, which the loop copies straight into the vector; text made of the number
/// (`Unknown (n)`) is written into the buffer of the chunk, which allocates the first time.
fn name_text(name: format::Name, text: &mut String) -> Option<&str> {
    match name.as_static() {
        Some(name) => Some(name),
        None => {
            text.clear();
            write!(text, "{name}").ok()?;
            Some(text.as_str())
        }
    }
}

/// `f(I) -> VARCHAR`, where the kernel names a number.
pub(super) fn name<I, K>(kernel: K) -> impl ScalarCallbacks
where
    I: Plain,
    K: Fn(I) -> format::Name + Send + Sync + 'static,
{
    MapInto::<I, String, String, _>::new(move |number, text| name_text(kernel(*number), text))
}

/// `f(A, B) -> VARCHAR`, where the kernel names a pair of numbers.
pub(super) fn name_of_pair<A, B, K>(kernel: K) -> impl ScalarCallbacks
where
    A: Plain,
    B: Plain,
    K: Fn(A, B) -> format::Name + Send + Sync + 'static,
{
    ZipInto::<A, B, String, String, _>::new(move |first, second, text| {
        name_text(kernel(*first, *second), text)
    })
}

/// The buffer [`MapInto`] lends the kernel of `ip6_to_string`: an array this long has no
/// `Default` of its own.
pub(super) struct Ipv6Text(pub(super) [u8; format::IPV6_TEXT_LEN]);

impl Default for Ipv6Text {
    fn default() -> Self {
        Self([0; format::IPV6_TEXT_LEN])
    }
}

/// `f(I) -> VARCHAR`, where the kernel `K` writes the text, or returns `None` for NULL.
pub(super) struct Format<I, K> {
    kernel: K,
    input: PhantomData<fn(I)>,
}

impl<I, K> Format<I, K>
where
    I: ReadableNativeElement + 'static,
    K: for<'a> Fn(I::Ref<'a>, &mut String) -> Option<()>,
{
    pub(super) fn new(kernel: K) -> Self {
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
