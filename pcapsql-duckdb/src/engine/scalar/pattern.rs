//! The loop that tests a value against a pattern parsed from text, [`Match`], and what
//! [`MatchPlain`](super::plain::MatchPlain) shares with it.

use std::marker::PhantomData;

use duckdb_neo::{
    connection::Context,
    data_chunk::VectorCollection,
    scalar::ScalarCallbacks,
    vector::{
        NativeElement, ReadableNativeElement, StorageKind, Unknown, Vector, VectorReader,
        VectorWriter,
    },
    Result,
};

use super::readable;

/// The vectors of one call of a match function, `f(I, VARCHAR) -> BOOLEAN`.
pub(super) struct MatchVectors<'a, I: NativeElement> {
    /// The rows of the chunk, which `output` is sized to.
    pub(super) rows: usize,
    pub(super) values: Vector<'a, I>,
    pub(super) patterns: Vector<'a, String>,
    pub(super) output: Vector<'a, bool>,
}

impl<'a, I: NativeElement> MatchVectors<'a, I> {
    pub(super) fn new(
        vectors: &'a mut VectorCollection,
        output: Vector<'a, Unknown>,
    ) -> Result<Self> {
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
pub(super) fn match_rows<I, P>(
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
pub(super) struct Match<I, P, Parse, Test> {
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
    pub(super) fn new(parse: Parse, test: Test) -> Self {
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
