//! Writing a `LIST(STRUCT(...))` vector: the result of a scalar function whose value is a
//! list of rows (`hdr_buckets`).
//!
//! [`ChunkWriter`](super::writer::ChunkWriter) stores the lists the scan layer has, whose items
//! are numbers, text or bytes. A list of structs is three levels of vectors: the list vector,
//! whose rows are ranges of its child; the child, a struct vector, which holds no data of its
//! own; and one vector per field of the struct, as long as the child. [`write_struct_lists`]
//! fills all three through `duckdb-neo`'s checked writers, so there is no `unsafe` here: the
//! rows are known before the first is written (a scalar function has its whole chunk), which is
//! what those writers need and a row sink cannot give them.
//!
//! The fields of the struct all have one type, a fixed-width one (`T`): what is general here
//! is the number of fields and that type. Fields of several types would need a writer per
//! field type, which nothing asks for yet.

use std::ops::Range;

use duckdb_neo::{
    types::{List, ListIndex, Struct},
    vector::{Unknown, Vector, WritableNativeElement},
    Error, Result,
};

/// Store one list of structs per row in `output`, a writable vector of the type
/// `STRUCT(... N fields of T ...)[]`.
///
/// `items` are the structs of all rows, each the values of its `N` fields in the order of the
/// type. Row `i` is the structs `lists[i]` of them, or NULL for `None`. The ranges may share
/// or skip items; each must lie within `items`.
///
/// Fails, with the vector in an unspecified but valid state, when `output` is not such a
/// vector or a range is out of bounds.
pub fn write_struct_lists<T, const N: usize>(
    output: Vector<'_, Unknown>,
    lists: &[Option<Range<usize>>],
    items: &[[T; N]],
) -> Result<()>
where
    T: WritableNativeElement<Write = T>,
{
    let mut output = output.cast::<List<Struct>>()?;
    output.set_size(lists.len())?;
    // Sized before the rows are written: a row is checked against it.
    output.set_child_size(items.len())?;
    {
        let mut rows = output.list_writer()?;
        for (row, list) in lists.iter().enumerate() {
            match list {
                // An inverted range is an empty one that starts where it says.
                Some(range) => {
                    rows.set_entry(row, ListIndex::new(range.start as u64, range.len() as u64))?
                }
                None => rows.set_null(row)?,
            }
        }
    }

    let no_children = || Error::invalid_input("a LIST(STRUCT) vector has no child vectors");
    let mut children = output.children_mut().ok_or_else(no_children)?;
    let mut structs = children.get_vector_at_mut::<Struct>(0)?;
    let mut fields = structs.children_mut().ok_or_else(no_children)?;
    if fields.col_count() != N {
        return Err(Error::invalid_input(format!(
            "the struct of the vector has {} fields, and the items have {N}",
            fields.col_count()
        )));
    }
    for field in 0..N {
        // Fails for a field that is not a `T`.
        let mut vector = fields.get_vector_at_mut::<T>(field)?;
        let mut values = vector.writer()?;
        for (index, item) in items.iter().enumerate() {
            values.set(index, &item[field])?;
        }
    }
    Ok(())
}
