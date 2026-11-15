//! Panic containment for DuckDB callbacks.
//!
//! `duckdb-neo` catches a panic that unwinds out of a callback and reports it as an INTERNAL
//! error. DuckDB treats INTERNAL as fatal: it invalidates the database, and every later query on
//! it fails. A bug in one packet parser must not cost the user their session, so every callback
//! body runs under [`run`], which reports the panic as an ordinary query error.
//!
//! Functions are registered through [`table_function`], [`scalar_function`] and
//! [`copy_function`], which wrap the implementation in [`Guarded`] so that no callback can be
//! left out.
//!
//! This relies on unwinding: the extension must not be built with `panic = "abort"`.

use std::any::Any;
use std::fmt::Display;
use std::num::NonZeroUsize;
use std::panic::{catch_unwind, AssertUnwindSafe};

use duckdb_neo::{
    bind_arguments::BindArgument,
    column_data_collection::ColumnDataCollection,
    connection::Context,
    copy_function::{
        CopyFunctionBuilder, CopyToBindInfo, CopyToFunctionCallbacks, CopyToStatistics,
        CopyToStatisticsCallbacks,
    },
    data_chunk::{DataChunkRef, VectorCollection},
    error::DuckDBError,
    scalar::{ScalarCallbacks, ScalarFunctionBuilder},
    signature::SignatureBuilder,
    table_function::{
        BindFunctionHandle, BindInfoApi, ExecColumnInfo, InitColumnData, PartitionData,
        PartitioningData, PushdownData, TableClaimBatchCallbacks, TableFilterPushdownCallbacks,
        TableFunctionBuilder, TableFunctionCallbacks, TableGetBindInfoCallbacks,
        TablePartitionInfo, TablePartitioningCallbacks,
    },
    vector::{Unknown, Vector},
    Error, Result,
};

/// Run a callback body, converting a panic into an error that names `callback`.
pub fn run<T>(callback: impl Display, body: impl FnOnce() -> Result<T>) -> Result<T> {
    // The error fails the query, after which DuckDB drops the function's states, so whatever a
    // panic left half-updated is not used to produce results.
    catch_unwind(AssertUnwindSafe(body)).unwrap_or_else(|panic| {
        Err(Error {
            code: DuckDBError::QueryExecutor,
            message: format!(
                "pcapsql: panic in {callback}: {}",
                panic_message(panic.as_ref())
            ),
        })
    })
}

fn panic_message(panic: &(dyn Any + Send)) -> &str {
    if let Some(text) = panic.downcast_ref::<String>() {
        text
    } else if let Some(text) = panic.downcast_ref::<&str>() {
        text
    } else {
        "no message"
    }
}

/// A builder for the table function `name` whose callbacks all run under [`run`].
pub fn table_function<T: TableFunctionCallbacks>(
    name: &str,
    signature: SignatureBuilder,
    implementation: T,
) -> TableFunctionBuilder<Guarded<T>> {
    let guarded = Guarded {
        name: name.to_owned(),
        inner: implementation,
    };
    TableFunctionBuilder::new(name, signature, guarded)
}

/// A builder for the scalar function `name` whose callback runs under [`run`].
pub fn scalar_function<T: ScalarCallbacks>(
    name: &str,
    signature: SignatureBuilder,
    implementation: T,
) -> ScalarFunctionBuilder<Guarded<T>> {
    let guarded = Guarded {
        name: name.to_owned(),
        inner: implementation,
    };
    ScalarFunctionBuilder::new(name, signature, guarded)
}

/// A builder for the `COPY ... TO` format `name` whose callbacks all run under [`run`].
pub fn copy_function<T: CopyToFunctionCallbacks>(
    name: &str,
    implementation: T,
) -> CopyFunctionBuilder<Guarded<T>> {
    let guarded = Guarded {
        name: format!("COPY TO (FORMAT {name})"),
        inner: implementation,
    };
    CopyFunctionBuilder::new(name, guarded)
}

/// A function implementation whose callbacks each run under [`run`].
#[derive(Debug)]
pub struct Guarded<T> {
    /// The SQL name of the function, for the error message.
    name: String,
    inner: T,
}

impl<T> Guarded<T> {
    fn run<R>(&self, callback: &str, body: impl FnOnce(&T) -> Result<R>) -> Result<R> {
        run(format_args!("{} ({callback})", self.name), || {
            body(&self.inner)
        })
    }
}

impl<T: TableFunctionCallbacks> TableFunctionCallbacks for Guarded<T> {
    type BindData = T::BindData;
    type LocalState = T::LocalState;
    type GlobalState = T::GlobalState;

    fn bind(
        &self,
        context: &Context,
        arguments: Vec<BindArgument>,
        bind_handle: BindFunctionHandle<'_>,
    ) -> Result<Self::BindData> {
        self.run("bind", |inner| inner.bind(context, arguments, bind_handle))
    }

    fn init_global_state(
        &self,
        context: &Context,
        bind_data: &Self::BindData,
        column_data: InitColumnData<'_>,
    ) -> Result<Option<Self::GlobalState>> {
        self.run("init_global_state", |inner| {
            inner.init_global_state(context, bind_data, column_data)
        })
    }

    fn max_threads(
        &self,
        context: &Context,
        bind_data: &Self::BindData,
        global_state: Option<&Self::GlobalState>,
        column_data: InitColumnData<'_>,
    ) -> Result<Option<NonZeroUsize>> {
        self.run("max_threads", |inner| {
            inner.max_threads(context, bind_data, global_state, column_data)
        })
    }

    fn init_local_state(
        &self,
        context: &Context,
        bind_data: &Self::BindData,
        global_state: Option<&Self::GlobalState>,
        column_data: InitColumnData<'_>,
    ) -> Result<Option<Self::LocalState>> {
        self.run("init_local_state", |inner| {
            inner.init_local_state(context, bind_data, global_state, column_data)
        })
    }

    fn exec(
        &self,
        context: &Context,
        bind_data: &Self::BindData,
        local_state: Option<&mut Self::LocalState>,
        global_state: Option<&Self::GlobalState>,
        output: DataChunkRef<'_>,
        column_info: ExecColumnInfo<'_>,
    ) -> Result<()> {
        self.run("exec", |inner| {
            inner.exec(
                context,
                bind_data,
                local_state,
                global_state,
                output,
                column_info,
            )
        })
    }

    fn progress(
        &self,
        context: &Context,
        bind_data: &Self::BindData,
        global_state: Option<&Self::GlobalState>,
    ) -> Result<Option<f64>> {
        self.run("progress", |inner| {
            inner.progress(context, bind_data, global_state)
        })
    }
}

impl<T: TableFilterPushdownCallbacks> TableFilterPushdownCallbacks for Guarded<T> {
    fn pushdown_filter(
        &self,
        context: &Context,
        bind_data: &Self::BindData,
        pushdown_data: PushdownData<'_>,
    ) -> Result<()> {
        self.run("pushdown_filter", |inner| {
            inner.pushdown_filter(context, bind_data, pushdown_data)
        })
    }
}

impl<T: TablePartitioningCallbacks> TablePartitioningCallbacks for Guarded<T> {
    fn partition_data(
        &self,
        context: &Context,
        bind_data: &Self::BindData,
        local_state: Option<&mut Self::LocalState>,
        global_state: Option<&Self::GlobalState>,
        partition_data: PartitionData<'_>,
    ) -> Result<usize> {
        self.run("partition_data", |inner| {
            inner.partition_data(
                context,
                bind_data,
                local_state,
                global_state,
                partition_data,
            )
        })
    }

    fn partitioning(
        &self,
        context: &Context,
        bind_data: &Self::BindData,
        partitioning_data: PartitioningData<'_>,
    ) -> Result<TablePartitionInfo> {
        self.run("partitioning", |inner| {
            inner.partitioning(context, bind_data, partitioning_data)
        })
    }
}

impl<T: TableGetBindInfoCallbacks> TableGetBindInfoCallbacks for Guarded<T> {
    fn bind_info(
        &self,
        context: &Context,
        bind_data: &Self::BindData,
        api: BindInfoApi<'_>,
    ) -> Result<()> {
        self.run("bind_info", |inner| {
            inner.bind_info(context, bind_data, api)
        })
    }
}

impl<T: TableClaimBatchCallbacks> TableClaimBatchCallbacks for Guarded<T> {
    fn claim_batch(
        &self,
        context: &Context,
        bind_data: &Self::BindData,
        local_state: Option<&mut Self::LocalState>,
        global_state: Option<&Self::GlobalState>,
    ) -> Result<bool> {
        self.run("claim_batch", |inner| {
            inner.claim_batch(context, bind_data, local_state, global_state)
        })
    }
}

impl<T: ScalarCallbacks> ScalarCallbacks for Guarded<T> {
    type BindData = T::BindData;
    type InitData = T::InitData;

    fn exec(
        &self,
        context: &Context,
        bind_data: Option<&Self::BindData>,
        init_data: Option<&mut Self::InitData>,
        vectors: &mut VectorCollection,
        output: Vector<'_, Unknown>,
    ) -> Result<()> {
        self.run("exec", |inner| {
            inner.exec(context, bind_data, init_data, vectors, output)
        })
    }
}

impl<T: CopyToFunctionCallbacks> CopyToFunctionCallbacks for Guarded<T> {
    type InitData = T::InitData;
    type BindData = T::BindData;
    type BatchData = T::BatchData;

    fn bind(&self, context: &Context, bind_info: &CopyToBindInfo) -> Result<Self::BindData> {
        self.run("bind", |inner| inner.bind(context, bind_info))
    }

    fn init(
        &self,
        context: &Context,
        bind_data: &Self::BindData,
        file_path: &str,
    ) -> Result<Self::InitData> {
        self.run("init", |inner| inner.init(context, bind_data, file_path))
    }

    fn batch(
        &self,
        context: &Context,
        bind_data: &Self::BindData,
        init_data: &Self::InitData,
        input: &ColumnDataCollection<'_>,
    ) -> Result<Self::BatchData> {
        self.run("batch", |inner| {
            inner.batch(context, bind_data, init_data, input)
        })
    }

    fn batch_size(
        &self,
        context: &Context,
        bind_data: &Self::BindData,
    ) -> Result<Option<NonZeroUsize>> {
        self.run("batch_size", |inner| inner.batch_size(context, bind_data))
    }

    fn flush(
        &self,
        context: &Context,
        bind_data: &Self::BindData,
        init_data: &Self::InitData,
        input: &ColumnDataCollection<'_>,
        batch_data: &mut Self::BatchData,
    ) -> Result<()> {
        self.run("flush", |inner| {
            inner.flush(context, bind_data, init_data, input, batch_data)
        })
    }

    fn finalize(
        &self,
        context: &Context,
        bind_data: &Self::BindData,
        init_data: &Self::InitData,
    ) -> Result<()> {
        self.run("finalize", |inner| {
            inner.finalize(context, bind_data, init_data)
        })
    }
}

impl<T: CopyToStatisticsCallbacks> CopyToStatisticsCallbacks for Guarded<T> {
    fn statistics(
        &self,
        context: &Context,
        bind_data: &Self::BindData,
        init_data: &Self::InitData,
    ) -> Result<CopyToStatistics> {
        self.run("statistics", |inner| {
            inner.statistics(context, bind_data, init_data)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_results_through() {
        assert_eq!(run("f", || Ok(7)).unwrap(), 7);
        let error = run("f", || Err::<(), _>(Error::invalid_input("bad"))).unwrap_err();
        assert_eq!(error.code, DuckDBError::InputInvalid);
        assert_eq!(error.message, "bad");
    }

    #[test]
    fn converts_a_panic_to_an_ordinary_error() {
        let error = run("read_x (exec)", || -> Result<()> {
            panic!("index {} out of range", 9)
        })
        .unwrap_err();
        assert_eq!(error.code, DuckDBError::QueryExecutor);
        assert_eq!(
            error.message,
            "pcapsql: panic in read_x (exec): index 9 out of range"
        );

        let error = run("f", || -> Result<()> { panic!("static text") }).unwrap_err();
        assert_eq!(error.message, "pcapsql: panic in f: static text");

        let error = run("f", || -> Result<()> { std::panic::panic_any(42_u8) }).unwrap_err();
        assert_eq!(error.message, "pcapsql: panic in f: no message");
    }
}
