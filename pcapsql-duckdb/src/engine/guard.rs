//! Panic containment for DuckDB callbacks.
//!
//! `duckdb-neo` catches a panic that unwinds out of a callback and reports it as an INTERNAL
//! error. DuckDB treats INTERNAL as fatal: it invalidates the database, and every later query on
//! it fails. A bug in one packet parser must not cost the user their session, so every callback
//! body runs under [`run`], which reports the panic as an ordinary query error.
//!
//! Functions are registered through [`table_function`], [`scalar_function`],
//! [`copy_function`] and [`aggregate_function`], which wrap the implementation in [`Guarded`]
//! so that no callback can be left out.
//!
//! This relies on unwinding: the extension must not be built with `panic = "abort"`.
//!
//! # Aggregate functions
//!
//! One callback of an aggregate function cannot fail: `init`, which makes the state of a
//! group. `duckdb-neo` aborts the process when it panics, because DuckDB destroys every state
//! afterwards, initialised or not. So an aggregate function is written against [`Aggregate`],
//! not against `duckdb-neo`'s trait, and the guard keeps each state in a [`Slot`]: the state,
//! or the message of the panic that kept it from being made. `init` then always returns a
//! value DuckDB can destroy, and the first callback that is given the slot (through [`Slots`],
//! which is the only way to a state) fails the query with that message.

use std::any::Any;
use std::fmt::Display;
use std::num::NonZeroUsize;
use std::panic::{catch_unwind, AssertUnwindSafe};

use duckdb_neo::{
    aggregate::{AggregateCallbacks, AggregateFunctionBuilder, ReturnTypeHandle, States},
    bind_arguments::{BindArgument, BindArguments},
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
    catch_unwind(AssertUnwindSafe(body))
        .unwrap_or_else(|panic| Err(failed(panic_text(callback, panic.as_ref()))))
}

/// What the error of a panic in `callback` says.
fn panic_text(callback: impl Display, panic: &(dyn Any + Send)) -> String {
    format!("pcapsql: panic in {callback}: {}", panic_message(panic))
}

/// The ordinary error a panic becomes.
fn failed(message: String) -> Error {
    Error {
        code: DuckDBError::QueryExecutor,
        message,
    }
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

/// A builder for the aggregate function `name` whose callbacks all run under [`run`], `init`
/// included (see the module documentation).
pub fn aggregate_function<T: Aggregate>(
    name: &str,
    signature: SignatureBuilder,
    implementation: T,
) -> AggregateFunctionBuilder<Guarded<T>> {
    let guarded = Guarded {
        name: name.to_owned(),
        inner: implementation,
    };
    AggregateFunctionBuilder::new(name, signature, guarded)
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

/// An aggregate function: `duckdb-neo`'s `AggregateCallbacks`, with the states behind
/// [`Slots`] so that `init` may panic like any other callback (see the module documentation).
pub trait Aggregate: Send + Sync + 'static {
    /// Data shared from binding through execution.
    type BindData: Any + Send + Sync + PartialEq;
    /// The state of one group.
    type State: Any + Send + Sync;

    /// Validate a call site and create the data its later callbacks share.
    fn bind(
        &self,
        context: &Context,
        arguments: BindArguments<'_>,
        result_type: ReturnTypeHandle<'_>,
    ) -> Result<Self::BindData>;

    /// The state of a group no row was added to.
    fn init(&self, bind_data: Option<&Self::BindData>) -> Self::State;

    /// Add the rows of `data` to their groups: row `i` belongs to `states.get_mut(i)`, and
    /// rows of one group share a state.
    fn update(
        &self,
        bind_data: Option<&Self::BindData>,
        data: &mut VectorCollection,
        states: Slots<'_, '_, Self::State>,
    ) -> Result<()>;

    /// Add the state `source.get(i)` to the state `target.get_mut(i)`, for every `i`.
    fn combine(
        &self,
        bind_data: Option<&Self::BindData>,
        source: &SourceSlots<'_, '_, Self::State>,
        target: Slots<'_, '_, Self::State>,
    ) -> Result<()>;

    /// Store the result of state `i` in row `result_offset + i` of `result`.
    fn finalize(
        &self,
        bind_data: Option<&Self::BindData>,
        states: &[&Self::State],
        result: Vector<'_, Unknown>,
        result_offset: usize,
    ) -> Result<()>;
}

/// What DuckDB stores for a group of a guarded aggregate function: the state [`Aggregate::init`]
/// returned, or what the panic that it ended in said.
#[derive(Debug)]
pub struct Slot<S>(std::result::Result<S, String>);

impl<S> Slot<S> {
    fn state(&self) -> Result<&S> {
        self.0.as_ref().map_err(|message| failed(message.clone()))
    }

    fn state_mut(&mut self) -> Result<&mut S> {
        self.0.as_mut().map_err(|message| failed(message.clone()))
    }
}

/// The states a callback of an [`Aggregate`] may change. A state whose `init` panicked is
/// the error of that panic.
#[derive(Debug)]
pub struct Slots<'s, 'a, S>(&'s mut States<'a, Slot<S>>);

impl<S> Slots<'_, '_, S> {
    /// The number of states: that of the rows or groups DuckDB handed the callback.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there is no state.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// State `index`. Several indices can be the same state (the rows of one group), which
    /// is why only one is lent at a time.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut S> {
        self.0[index].state_mut()
    }
}

/// The states a callback of an [`Aggregate`] reads: the sources of `combine`.
#[derive(Debug)]
pub struct SourceSlots<'s, 'a, S>(&'s States<'a, Slot<S>>);

impl<S> SourceSlots<'_, '_, S> {
    /// The number of states.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there is no state.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// State `index`.
    pub fn get(&self, index: usize) -> Result<&S> {
        self.0[index].state()
    }
}

impl<T: Aggregate> AggregateCallbacks for Guarded<T> {
    type BindData = T::BindData;
    type StateItem = Slot<T::State>;

    fn bind(
        &self,
        context: &Context,
        arguments: BindArguments<'_>,
        result_type: ReturnTypeHandle<'_>,
    ) -> Result<Self::BindData> {
        self.run("bind", |inner| inner.bind(context, arguments, result_type))
    }

    /// Never panics and never fails: a panic of the implementation's `init` is kept in the
    /// slot. (The text of the message is the one allocation here, as in every guard.)
    fn init(&self, bind_data: Option<&Self::BindData>) -> Self::StateItem {
        Slot(
            catch_unwind(AssertUnwindSafe(|| self.inner.init(bind_data)))
                .map_err(|panic| panic_text(format_args!("{} (init)", self.name), panic.as_ref())),
        )
    }

    fn update(
        &self,
        bind_data: Option<&Self::BindData>,
        data: &mut VectorCollection,
        mut states: States<'_, Self::StateItem>,
    ) -> Result<()> {
        self.run("update", |inner| {
            inner.update(bind_data, data, Slots(&mut states))
        })
    }

    fn combine(
        &self,
        bind_data: Option<&Self::BindData>,
        source: &States<'_, Self::StateItem>,
        mut target: States<'_, Self::StateItem>,
    ) -> Result<()> {
        self.run("combine", |inner| {
            inner.combine(bind_data, &SourceSlots(source), Slots(&mut target))
        })
    }

    fn finalize(
        &self,
        bind_data: Option<&Self::BindData>,
        states: &[&Self::StateItem],
        result: Vector<'_, Unknown>,
        result_offset: usize,
    ) -> Result<()> {
        self.run("finalize", |inner| {
            let states = states
                .iter()
                .map(|slot| slot.state())
                .collect::<Result<Vec<&T::State>>>()?;
            inner.finalize(bind_data, &states, result, result_offset)
        })
    }

    // `size` and `destroy` are `duckdb-neo`'s: the size of a slot, and its drop. Neither runs
    // code of the implementation but the drop of a state.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slot_is_its_state_or_the_error_of_the_panic_that_kept_it_from_being_made() {
        let mut made: Slot<Vec<u8>> = Slot(Ok(vec![1]));
        made.state_mut().unwrap().push(2);
        assert_eq!(made.state().unwrap(), &[1, 2]);

        let mut lost: Slot<Vec<u8>> = Slot(Err("pcapsql: panic in f (init): no".to_owned()));
        for error in [lost.state().unwrap_err(), lost.state_mut().unwrap_err()] {
            assert_eq!(error.code, DuckDBError::QueryExecutor);
            assert_eq!(error.message, "pcapsql: panic in f (init): no");
        }
    }

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
