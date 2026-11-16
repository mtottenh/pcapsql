//! `engine::nested::write_struct_lists`: lists of structs stored in a DuckDB vector, read back
//! through SQL.
//!
//! The extension's own user of it is `hdr_buckets` (three `UBIGINT` fields; `histogram.rs`).
//! Here it is driven by test-only scalar functions with other field types and counts, and with
//! what `hdr_buckets` never produces: ranges that share items, and input that must be refused.

use std::ops::Range;

use duckdb_neo::{
    connection::{Connection, Context},
    data_chunk::VectorCollection,
    logical_type::LogicalType,
    scalar::{ScalarCallbacks, ScalarFunctionBuilder},
    signature::{FunctionParameter, SignatureBuilder},
    vector::{Unknown, Vector, WritableNativeElement},
    Parameters, Result,
};
use pcapsql_duckdb::engine::nested::write_struct_lists;
use pcapsql_duckdb_itest::{column, connect, rows, value};

/// The items of a chunk, and which of them are each row's.
type Chunk<T, const N: usize> = (Vec<[T; N]>, Vec<Option<Range<usize>>>);

/// `f(BIGINT) -> STRUCT(... N fields of T ...)[]`: the lists `lists` makes of the arguments of
/// a chunk, stored by `write_struct_lists`.
struct Lists<T, const N: usize> {
    lists: fn(&[Option<i64>]) -> Chunk<T, N>,
}

impl<T, const N: usize> ScalarCallbacks for Lists<T, N>
where
    T: WritableNativeElement<Write = T> + Send + Sync + 'static,
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
        let mut input = vectors.get_vector_at_mut::<i64>(0)?;
        input.flatten()?;
        let arguments: Vec<Option<i64>> = input.reader()?.iter().map(|n| n.copied()).collect();
        let (items, lists) = (self.lists)(&arguments);
        write_struct_lists(output, &lists, &items)
    }
}

/// Register `name(BIGINT)` returning `return_type`, which `lists` fills.
fn register<T, const N: usize>(
    connection: &Connection,
    name: &str,
    return_type: &str,
    lists: fn(&[Option<i64>]) -> Chunk<T, N>,
) -> Result<()>
where
    T: WritableNativeElement<Write = T> + Send + Sync + 'static,
{
    let signature = SignatureBuilder::new()
        .param(FunctionParameter::new::<i64>("n"))
        .return_type(LogicalType::from_text(connection, return_type)?);
    ScalarFunctionBuilder::new(name, signature, Lists { lists }).register(connection)
}

/// Row `n` is NULL for NULL and for a multiple of 11; otherwise the `n % 5` pairs
/// `(k, n + k)` for `k` from 0.
fn pairs(arguments: &[Option<i64>]) -> Chunk<u16, 2> {
    let mut items = Vec::new();
    let lists = arguments
        .iter()
        .map(|argument| {
            let n = argument.filter(|n| n % 11 != 0)?;
            let start = items.len();
            items.extend((0..n % 5).map(|k| [k as u16, (n + k) as u16]));
            Some(start..items.len())
        })
        .collect();
    (items, lists)
}

/// What `pairs(n)` is, as DuckDB prints it.
fn pairs_text(n: Option<i64>) -> String {
    match n.filter(|n| n % 11 != 0) {
        None => "NULL".to_owned(),
        Some(n) => {
            let items: Vec<String> = (0..n % 5)
                .map(|k| format!("{{'a': {k}, 'b': {}}}", (n + k) as u16))
                .collect();
            format!("[{}]", items.join(", "))
        }
    }
}

#[test]
fn lists_of_structs_are_read_back_as_they_were_given() -> Result<()> {
    let connection = connect()?;
    register(
        &connection,
        "pairs",
        "STRUCT(a USMALLINT, b USMALLINT)[]",
        pairs,
    )?;
    assert_eq!(
        value(&connection, "SELECT typeof(pairs(1))")?,
        "STRUCT(a USMALLINT, b USMALLINT)[]"
    );
    // A constant, a NULL, an empty list, and a list.
    assert_eq!(
        rows(
            &connection,
            "SELECT pairs(3)::VARCHAR, pairs(NULL)::VARCHAR, pairs(5)::VARCHAR, pairs(22)::VARCHAR"
        )?,
        [[
            "[{'a': 0, 'b': 3}, {'a': 1, 'b': 4}, {'a': 2, 'b': 5}]",
            "NULL",
            "[]",
            "NULL"
        ]
        .map(String::from)
        .to_vec()]
    );
    // Several chunks, each with more items than rows of a chunk, NULLs and empty lists among
    // them.
    let actual = column(
        &connection,
        "SELECT pairs(CASE WHEN i % 13 = 0 THEN NULL ELSE i END)::VARCHAR
         FROM range(20000) t(i) ORDER BY i",
    )?;
    assert_eq!(actual.len(), 20000);
    for (i, text) in actual.iter().enumerate() {
        let n = (i % 13 != 0).then_some(i as i64);
        assert_eq!(text, &pairs_text(n), "row {i}");
    }
    // The fields are columns once unnested, and the lists survive DuckDB's own operators.
    let arguments: Vec<Option<i64>> = (1..1000).map(Some).collect();
    let (items, lists) = pairs(&arguments);
    let sum = |field: usize| -> u64 { items.iter().map(|item| u64::from(item[field])).sum() };
    let longest = lists.iter().flatten().map(Range::len).max().unwrap();
    assert!(
        items.len() > 1500 && longest == 4,
        "{} {longest}",
        items.len()
    );
    assert_eq!(
        rows(
            &connection,
            "SELECT count(*), sum(a), sum(b), max(len(p)) FROM (
                 SELECT p, unnest(p, recursive := true) FROM (SELECT pairs(i) AS p FROM range(1, 1000) t(i)))",
        )?,
        [vec![
            items.len().to_string(),
            sum(0).to_string(),
            sum(1).to_string(),
            longest.to_string(),
        ]]
    );
    Ok(())
}

/// One `DOUBLE` field, and rows that share items: row `n` is the first `n % 4` items of the
/// chunk's three, whatever the other rows are.
fn shared(arguments: &[Option<i64>]) -> Chunk<f64, 1> {
    let items = vec![[0.5], [1.5], [-2.25]];
    let lists = arguments
        .iter()
        .map(|argument| argument.map(|n| 0..(n % 4) as usize))
        .collect();
    (items, lists)
}

#[test]
fn rows_may_share_items_and_a_struct_may_have_one_field() -> Result<()> {
    let connection = connect()?;
    register(&connection, "shared", "STRUCT(x DOUBLE)[]", shared)?;
    assert_eq!(
        rows(
            &connection,
            "SELECT i, shared(i)::VARCHAR FROM range(5) t(i) ORDER BY i"
        )?,
        [
            ["0", "[]"],
            ["1", "[{'x': 0.5}]"],
            ["2", "[{'x': 0.5}, {'x': 1.5}]"],
            ["3", "[{'x': 0.5}, {'x': 1.5}, {'x': -2.25}]"],
            ["4", "[]"],
        ]
        .map(|cells| cells.map(String::from).to_vec())
    );
    assert_eq!(
        value(
            &connection,
            "SELECT sum(list_sum(list_transform(shared(i), lambda s: s.x))) FROM range(4000) t(i)"
        )?,
        "2250.0"
    );
    Ok(())
}

/// One list that ends past the items.
fn out_of_bounds(arguments: &[Option<i64>]) -> Chunk<u16, 2> {
    (vec![[1, 2]], arguments.iter().map(|_| Some(0..2)).collect())
}

#[test]
fn what_does_not_fit_the_vector_is_an_error_not_a_write() -> Result<()> {
    let connection = connect()?;
    // Two fields written to a struct of one, and of three.
    register(&connection, "one_field", "STRUCT(a USMALLINT)[]", pairs)?;
    register(
        &connection,
        "three_fields",
        "STRUCT(a USMALLINT, b USMALLINT, c USMALLINT)[]",
        pairs,
    )?;
    // Fields of another type, a list of something else, and no list at all.
    register(
        &connection,
        "wide_fields",
        "STRUCT(a UINTEGER, b UINTEGER)[]",
        pairs,
    )?;
    register(&connection, "plain_list", "USMALLINT[]", pairs)?;
    register(
        &connection,
        "no_list",
        "STRUCT(a USMALLINT, b USMALLINT)",
        pairs,
    )?;
    register(
        &connection,
        "past_the_items",
        "STRUCT(a USMALLINT, b USMALLINT)[]",
        out_of_bounds,
    )?;
    for (function, expected) in [
        (
            "one_field",
            "the struct of the vector has 1 fields, and the items have 2",
        ),
        (
            "three_fields",
            "the struct of the vector has 3 fields, and the items have 2",
        ),
        ("wide_fields", ""),
        ("plain_list", ""),
        ("no_list", ""),
        ("past_the_items", "is past the 1 child elements"),
    ] {
        let error = rows(
            &connection,
            &format!("SELECT {function}(i) FROM range(1, 4) t(i)"),
        )
        .unwrap_err();
        assert!(error.message.contains(expected), "{function}: {error}");
        // An ordinary error: the connection goes on.
        assert_eq!(value(&connection, "SELECT 42")?, "42", "{function}");
    }
    connection.execute("SELECT 1", Parameters::None)?;
    Ok(())
}
