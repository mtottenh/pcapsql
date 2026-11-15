//! Scalar functions: vector loops over the kernels.
//!
//! Inputs are read through `duckdb-neo`'s vector reader, which maps rows through the vector's
//! selection, so flat, constant and dictionary inputs all work. NULL in gives NULL out, and so
//! does a value the kernel rejects.

use duckdb_neo::{
    connection::Context,
    data_chunk::VectorCollection,
    extension::Extension,
    scalar::ScalarCallbacks,
    signature::{FunctionParameter, SignatureBuilder},
    vector::{NativeElement, StorageKind, Unknown, Vector},
    DuckDBType, Result,
};
use pcapsql_core::format::format_ipv4;

use super::guard;
use crate::kernels::address::parse_ip4;

pub(super) fn register(extension: &Extension) -> Result<()> {
    guard::scalar_function(
        "ip4",
        SignatureBuilder::new()
            .param(FunctionParameter::new::<String>("address"))
            .return_type(u32::logical_type(extension)?),
        Ip4,
    )
    .register(extension)?;

    guard::scalar_function(
        "ip4_to_string",
        SignatureBuilder::new()
            .param(FunctionParameter::new::<u32>("address"))
            .return_type(String::logical_type(extension)?),
        Ip4ToString,
    )
    .register(extension)
}

/// The argument at `index`, in a storage kind the vector reader accepts.
fn argument<T: NativeElement>(
    vectors: &mut VectorCollection,
    index: usize,
) -> Result<Vector<'_, T>> {
    let mut vector = vectors.get_vector_at_mut::<T>(index)?;
    // Sequence and FSST vectors have no selection-based view; DuckDB materialises them on request.
    if vector.storage_kind() == StorageKind::Other {
        vector.flatten()?;
    }
    Ok(vector)
}

/// `ip4(VARCHAR) -> UINTEGER`: the numeric value of a dotted-quad address.
struct Ip4;

impl ScalarCallbacks for Ip4 {
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
        let input = argument::<String>(vectors, 0)?;
        let mut output = output.cast::<u32>()?;
        output.set_size(rows)?;
        let mut writer = output.writer()?;
        for (row, text) in input.reader()?.iter().enumerate() {
            writer.set_option(row, text.and_then(parse_ip4).as_ref())?;
        }
        Ok(())
    }
}

/// `ip4_to_string(UINTEGER) -> VARCHAR`: dotted-quad text of a numeric address.
struct Ip4ToString;

impl ScalarCallbacks for Ip4ToString {
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
        let input = argument::<u32>(vectors, 0)?;
        let mut output = output.cast::<String>()?;
        output.set_size(rows)?;
        let mut writer = output.writer()?;
        for (row, address) in input.reader()?.iter().enumerate() {
            writer.set_option(row, address.map(|address| format_ipv4(*address)).as_deref())?;
        }
        Ok(())
    }
}
