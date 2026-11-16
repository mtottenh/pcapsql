//! The loop whose kernel gives a list of rows: [`StructList`].

use std::marker::PhantomData;

use duckdb_neo::{
    connection::Context,
    data_chunk::VectorCollection,
    scalar::ScalarCallbacks,
    vector::{ReadableNativeElement, Unknown, Vector, WritableNativeElement},
    Result,
};

use super::argument;
use crate::engine::nested::write_struct_lists;

/// `f(I) -> STRUCT(... N fields of T ...)[]`, where the kernel `K` appends the structs of a
/// row's list to the vector it is lent, each as the values of its fields in their order, or
/// returns `None` for NULL.
pub(super) struct StructList<I, T, const N: usize, K> {
    kernel: K,
    types: PhantomData<fn(I) -> T>,
}

impl<I, T, const N: usize, K> StructList<I, T, N, K>
where
    I: ReadableNativeElement + 'static,
    K: for<'a> Fn(I::Ref<'a>, &mut Vec<[T; N]>) -> Option<()>,
{
    pub(super) fn new(kernel: K) -> Self {
        Self {
            kernel,
            types: PhantomData,
        }
    }
}

impl<I, T, const N: usize, K> ScalarCallbacks for StructList<I, T, N, K>
where
    I: ReadableNativeElement + 'static,
    T: WritableNativeElement<Write = T> + 'static,
    K: for<'a> Fn(I::Ref<'a>, &mut Vec<[T; N]>) -> Option<()> + Send + Sync + 'static,
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
        // The structs of the whole chunk, and which of them are each row's: the vector is
        // written once all of it is known.
        let mut items = Vec::new();
        let mut lists = Vec::with_capacity(rows);
        for value in input.reader()?.iter() {
            let start = items.len();
            match value.and_then(|value| (self.kernel)(value, &mut items)) {
                Some(()) => lists.push(Some(start..items.len())),
                None => {
                    // What a kernel appended before it gave up is not a row's.
                    items.truncate(start);
                    lists.push(None);
                }
            }
        }
        write_struct_lists(output, &lists, &items)
    }
}
