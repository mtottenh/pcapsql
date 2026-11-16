//! The `hdr_*` functions against the kernels they wrap: the aggregate `hdr_histogram` and the
//! scalars that read what it returns.
//!
//! For synthetic values and for columns of real captures, what DuckDB answers must be what
//! `pcapsql_core::format::histogram` answers for the same values. The DataFusion engine's
//! functions are wrappers of the same kernels and are tested against them the same way
//! (`pcapsql-datafusion`, `udf/histogram.rs`), so this ties the two engines together;
//! `golden_differential.rs` compares the two directly over a capture, the serialized
//! histogram byte for byte.

use std::path::Path;

use duckdb_neo::{connection::Connection, Parameters, Result};
use pcapsql_core::format::histogram::{
    HdrHistogram, DEFAULT_SIGFIGS, MAX_BUCKETS, MAX_SIGFIGS, MIN_SIGFIGS,
};
use pcapsql_core::scan::testing::Cell;
use pcapsql_duckdb_itest::{column, connect, reference_rows, rows, value};

/// The percentiles every comparison asks for: fractions and, above 1, percentages.
const PERCENTILES: [f64; 7] = [0.0, 0.25, 0.5, 0.9, 99.0, 99.9, 1.0];

/// Everything the scalar functions say of a histogram.
#[derive(Debug, PartialEq)]
struct Answers {
    count: u64,
    min: u64,
    max: u64,
    mean: f64,
    stdev: f64,
    percentiles: Vec<f64>,
    buckets: String,
    ascii: String,
}

/// What the kernel says of `histogram`, the buckets as DuckDB prints a list of structs.
fn kernel_answers(histogram: &HdrHistogram) -> Answers {
    let buckets: Vec<String> = histogram
        .buckets()
        .map(|bucket| {
            format!(
                "{{'lo': {}, 'hi': {}, 'count': {}}}",
                bucket.lo, bucket.hi, bucket.count
            )
        })
        .collect();
    let mut ascii = String::new();
    histogram.write_ascii(&mut ascii).unwrap();
    Answers {
        count: histogram.len(),
        min: histogram.min(),
        max: histogram.max(),
        mean: histogram.mean(),
        stdev: histogram.stdev(),
        percentiles: PERCENTILES
            .iter()
            .map(|&p| histogram.percentile(p))
            .collect(),
        buckets: format!("[{}]", buckets.join(", ")),
        ascii,
    }
}

/// The histogram a function reads when it is given the one that recorded `values`: the
/// kernel's, through its serialized form.
fn histogram_of(values: impl IntoIterator<Item = u64>) -> HdrHistogram {
    histogram_at(DEFAULT_SIGFIGS, values)
}

/// [`histogram_of`] for a histogram that keeps `sigfigs` digits.
fn histogram_at(sigfigs: u8, values: impl IntoIterator<Item = u64>) -> HdrHistogram {
    let mut histogram = HdrHistogram::with_sigfigs(sigfigs).unwrap();
    for value in values {
        histogram.record(value);
    }
    HdrHistogram::deserialize(&histogram.serialize().unwrap()).unwrap()
}

/// The select list that asks every scalar function about the histogram `h`.
fn every_answer(h: &str) -> String {
    let percentiles: Vec<String> = PERCENTILES
        .iter()
        .map(|p| format!("hdr_percentile({h}, {p:?})"))
        .collect();
    format!(
        "hdr_count({h}), hdr_min({h}), hdr_max({h}), hdr_mean({h}), hdr_stdev({h}), {}, \
         hdr_buckets({h})::VARCHAR, hdr_ascii({h})",
        percentiles.join(", ")
    )
}

/// The answers in a row of [`every_answer`].
fn answers(row: &[String]) -> Answers {
    let number = |index: usize| -> f64 {
        row[index]
            .parse()
            .unwrap_or_else(|_| panic!("{:?}", row[index]))
    };
    Answers {
        count: row[0].parse().unwrap(),
        min: row[1].parse().unwrap(),
        max: row[2].parse().unwrap(),
        mean: number(3),
        stdev: number(4),
        percentiles: (0..PERCENTILES.len()).map(|i| number(5 + i)).collect(),
        buckets: row[5 + PERCENTILES.len()].clone(),
        ascii: row[6 + PERCENTILES.len()].clone(),
    }
}

/// The answers about the one histogram `sql` returns as `h`.
fn answers_of(connection: &Connection, sql: &str) -> Answers {
    let query = format!("SELECT {} FROM ({sql}) q", every_answer("h"));
    let result = rows(connection, &query).unwrap_or_else(|error| panic!("{query}: {error}"));
    assert_eq!(result.len(), 1, "{query}");
    answers(&result[0])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn row(cells: &[&str]) -> Vec<String> {
    cells.iter().map(|cell| cell.to_string()).collect()
}

#[test]
fn the_functions_and_their_types() -> Result<()> {
    let connection = connect()?;
    assert_eq!(
        rows(
            &connection,
            "SELECT function_name, function_type, parameters::VARCHAR, parameter_types::VARCHAR,
                    return_type
             FROM duckdb_functions() WHERE function_name LIKE 'hdr\\_%' ESCAPE '\\'
             ORDER BY function_name",
        )?,
        [
            row(&["hdr_ascii", "scalar", "[histogram]", "[BLOB]", "VARCHAR"]),
            row(&[
                "hdr_buckets",
                "scalar",
                "[histogram]",
                "[BLOB]",
                "STRUCT(lo UBIGINT, hi UBIGINT, count UBIGINT)[]"
            ]),
            row(&["hdr_count", "scalar", "[histogram]", "[BLOB]", "UBIGINT"]),
            row(&[
                "hdr_histogram",
                "aggregate",
                "[value, sigfigs]",
                "[ANY, ANY]",
                "BLOB"
            ]),
            row(&["hdr_max", "scalar", "[histogram]", "[BLOB]", "UBIGINT"]),
            row(&["hdr_mean", "scalar", "[histogram]", "[BLOB]", "DOUBLE"]),
            row(&["hdr_min", "scalar", "[histogram]", "[BLOB]", "UBIGINT"]),
            row(&[
                "hdr_percentile",
                "scalar",
                "[histogram, percentile]",
                "[BLOB, DOUBLE]",
                "DOUBLE"
            ]),
            row(&["hdr_stdev", "scalar", "[histogram]", "[BLOB]", "DOUBLE"]),
        ]
    );
    assert_eq!(
        value(
            &connection,
            "SELECT typeof(hdr_histogram(i)) FROM range(3) t(i)"
        )?,
        "BLOB"
    );
    Ok(())
}

/// A column of values of a type, and what a histogram records of it.
struct Case {
    what: &'static str,
    /// The rows of a `VALUES` list.
    values: &'static str,
    /// The type the column `v` is cast to.
    sql_type: &'static str,
    recorded: &'static [u64],
}

const CASES: &[Case] = &[
    Case {
        what: "integers, some NULL",
        values: "(1), (NULL), (5), (5), (1000), (NULL)",
        sql_type: "INTEGER",
        recorded: &[1, 5, 5, 1000],
    },
    Case {
        what: "one row",
        values: "(42)",
        sql_type: "INTEGER",
        recorded: &[42],
    },
    Case {
        what: "every row NULL",
        values: "(NULL), (NULL)",
        sql_type: "BIGINT",
        recorded: &[],
    },
    Case {
        what: "zero",
        values: "(0), (0), (0)",
        sql_type: "UTINYINT",
        recorded: &[0, 0, 0],
    },
    Case {
        what: "the largest values",
        values: "(18446744073709551615), (9223372036854775808), (1)",
        sql_type: "UBIGINT",
        recorded: &[u64::MAX, 1 << 63, 1],
    },
    Case {
        what: "negative values are not recorded",
        values: "(-1), (-9223372036854775808), (0), (7), (9223372036854775807)",
        sql_type: "BIGINT",
        recorded: &[0, 7, i64::MAX as u64],
    },
    Case {
        what: "small signed integers",
        values: "(-128), (127), (-1), (3)",
        sql_type: "TINYINT",
        recorded: &[127, 3],
    },
    Case {
        what: "SMALLINT",
        values: "(-32768), (32767), (300)",
        sql_type: "SMALLINT",
        recorded: &[32767, 300],
    },
    Case {
        what: "USMALLINT",
        values: "(65535), (0), (1500)",
        sql_type: "USMALLINT",
        recorded: &[65535, 0, 1500],
    },
    Case {
        what: "UINTEGER",
        values: "(4294967295), (136), (583), (65080)",
        sql_type: "UINTEGER",
        recorded: &[4294967295, 136, 583, 65080],
    },
    Case {
        what: "fractions are cut off, NaN and negative numbers left out, infinity is the largest",
        values: "(1.5), (2.99), (-3.0), (1e30), ('nan'), ('inf'), ('-inf'), (0.0), (-0.0), (0.99)",
        sql_type: "DOUBLE",
        recorded: &[1, 2, u64::MAX, u64::MAX, 0, 0, 0],
    },
    Case {
        what: "FLOAT",
        values: "(1.5::FLOAT), (16777216.0), (-0.25), ('nan'), (3.75)",
        sql_type: "FLOAT",
        recorded: &[1, 16777216, 3],
    },
    Case {
        what: "DECIMAL in 16 bits",
        values: "(12.99), (0.50), (-7.50), (99.99), (NULL)",
        sql_type: "DECIMAL(4, 2)",
        recorded: &[12, 0, 99],
    },
    Case {
        what: "DECIMAL in 32 bits",
        values: "(123456.789), (-0.001), (0.999)",
        sql_type: "DECIMAL(9, 3)",
        recorded: &[123456, 0],
    },
    Case {
        what: "DECIMAL in 64 bits",
        values: "(123456789012.999999), (5), (-5)",
        sql_type: "DECIMAL(18, 6)",
        recorded: &[123456789012, 5],
    },
    Case {
        what: "DECIMAL in 128 bits",
        values: "(12345678901234567890.5), (99999999999999999999999999.9999999999), (-1), (2.5)",
        sql_type: "DECIMAL(38, 10)",
        recorded: &[12345678901234567890, u64::MAX, 2],
    },
    Case {
        what: "DECIMAL without a fraction",
        values: "(7), (123456789012345678), (-3)",
        sql_type: "DECIMAL(18, 0)",
        recorded: &[7, 123456789012345678],
    },
    Case {
        what: "HUGEINT: what a u64 cannot hold is its largest value",
        values: "(170141183460469231731687303715884105727), (-1), (18446744073709551616), (3), \
                 (18446744073709551615)",
        sql_type: "HUGEINT",
        recorded: &[u64::MAX, u64::MAX, 3, u64::MAX],
    },
    Case {
        what: "UHUGEINT",
        values: "(340282366920938463463374607431768211455), (17), (0)",
        sql_type: "UHUGEINT",
        recorded: &[u64::MAX, 17, 0],
    },
];

#[test]
fn synthetic_values_answer_as_the_kernel_does() -> Result<()> {
    let connection = connect()?;
    for case in CASES {
        let expected = kernel_answers(&histogram_of(case.recorded.iter().copied()));
        let column = format!(
            "SELECT v::{} AS v FROM (VALUES {}) t(v)",
            case.sql_type, case.values
        );
        assert_eq!(
            value(
                &connection,
                &format!("SELECT DISTINCT typeof(v) FROM ({column})")
            )?,
            case.sql_type.replace(", ", ","),
            "{}",
            case.what
        );
        for threads in [1, 4] {
            connection.execute(format!("SET threads = {threads}"), Parameters::None)?;
            let actual = answers_of(
                &connection,
                &format!("SELECT hdr_histogram(v) AS h FROM ({column})"),
            );
            assert_eq!(actual, expected, "{}, {threads} threads", case.what);
        }
    }
    Ok(())
}

#[test]
fn no_rows_and_no_values_are_an_empty_histogram_not_null() -> Result<()> {
    let connection = connect()?;
    let empty = kernel_answers(&histogram_of([]));
    assert_eq!(empty.count, 0);
    assert_eq!(empty.buckets, "[]");
    assert_eq!(empty.ascii, "(empty histogram)");
    for sql in [
        "SELECT hdr_histogram(i) AS h FROM range(10) t(i) WHERE false",
        "SELECT hdr_histogram(NULL::DOUBLE) AS h FROM range(10)",
        "SELECT hdr_histogram(NULL) AS h",
        "SELECT hdr_histogram(i) FILTER (i > 100) AS h FROM range(10) t(i)",
    ] {
        assert_eq!(answers_of(&connection, sql), empty, "{sql}");
        assert_eq!(
            value(&connection, &format!("SELECT h IS NULL FROM ({sql}) q"))?,
            "false",
            "{sql}"
        );
    }
    // With GROUP BY, a group has rows: one whose values are all NULL is empty too, and no
    // rows are no groups.
    assert_eq!(
        rows(
            &connection,
            "SELECT g, hdr_count(hdr_histogram(v)) FROM (VALUES (1, NULL), (1, NULL), (2, 5)) t(g, v)
             GROUP BY g ORDER BY g",
        )?,
        [row(&["1", "0"]), row(&["2", "1"])]
    );
    assert!(rows(
        &connection,
        "SELECT g, hdr_histogram(v) FROM (SELECT 1 AS g, 2 AS v WHERE false) GROUP BY g",
    )?
    .is_empty());
    Ok(())
}

#[test]
fn what_is_not_a_number_is_refused_when_the_statement_is_bound() -> Result<()> {
    let connection = connect()?;
    for (argument, name) in [
        ("'text'", "VARCHAR"),
        ("true", "BOOLEAN"),
        ("TIMESTAMP '2024-01-01'", "TIMESTAMP"),
        ("INTERVAL 1 SECOND", "INTERVAL"),
        ("'\\x00'::BLOB", "BLOB"),
        ("[1, 2]", "INTEGER[]"),
        ("DATE '2024-01-01'", "DATE"),
    ] {
        let error = rows(&connection, &format!("SELECT hdr_histogram({argument})")).unwrap_err();
        assert!(
            error.message.contains(&format!(
                "hdr_histogram: the values must be numbers (an integer type, FLOAT, DOUBLE or \
                 DECIMAL), not {name}"
            )),
            "{argument}: {error}"
        );
        // Nothing ran: EXPLAIN binds the statement and fails the same way.
        assert!(rows(
            &connection,
            &format!("EXPLAIN SELECT hdr_histogram({argument})")
        )
        .is_err());
    }
    // One or two arguments.
    for sql in [
        "SELECT hdr_histogram()",
        "SELECT hdr_histogram(i, 3, 4) FROM range(3) t(i)",
    ] {
        let error = rows(&connection, sql).unwrap_err();
        assert!(error.message.contains("hdr_histogram"), "{sql}: {error}");
    }
    assert_eq!(value(&connection, "SELECT 42")?, "42");
    Ok(())
}

#[test]
fn a_histogram_of_either_side_is_read_by_the_other() -> Result<()> {
    let connection = connect()?;
    connection.execute("SET threads = 1", Parameters::None)?;
    let values: Vec<u64> = (0..500).map(|i| (i * i + 7) % 9001).collect();
    let list: Vec<String> = values.iter().map(|value| format!("({value})")).collect();
    let column = format!("SELECT v FROM (VALUES {}) t(v)", list.join(", "));

    let mut recorded = HdrHistogram::default();
    for &value in &values {
        recorded.record(value);
    }
    let mut merged = HdrHistogram::default();
    merged.merge(&recorded).unwrap();
    let expected = kernel_answers(&histogram_of(values.iter().copied()));

    // The kernel's bytes, in both forms they have, read by DuckDB.
    for histogram in [&recorded, &merged] {
        let literal = format!(
            "SELECT from_hex('{}') AS h",
            hex(&histogram.serialize().unwrap())
        );
        assert_eq!(answers_of(&connection, &literal), expected);
    }

    // DuckDB's bytes, read by the kernel.
    let bytes = value(
        &connection,
        &format!("SELECT lower(hex(hdr_histogram(v))) FROM ({column})"),
    )?;
    let from_duckdb: Vec<u8> = (0..bytes.len() / 2)
        .map(|i| u8::from_str_radix(&bytes[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    let read = HdrHistogram::deserialize(&from_duckdb).unwrap();
    assert_eq!(kernel_answers(&read), expected);

    // And they are the kernel's own: on one thread DuckDB merges the one state that saw the
    // rows into the state of the result, which is the kernel's `merge` into an empty
    // histogram. (The DataFusion engine does the same with its partial state.)
    assert_eq!(bytes, hex(&merged.serialize().unwrap()));
    Ok(())
}

/// The captures of the fuzzing corpus: real ones, classic pcap of either byte order and pcapng.
fn corpus() -> Vec<(String, String)> {
    let directory =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/fuzz_pcap_reader");
    let mut captures: Vec<(String, String)> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .map(|path| {
            (
                path.file_name().unwrap().to_str().unwrap().to_owned(),
                path.to_str().unwrap().to_owned(),
            )
        })
        .collect();
    captures.sort();
    assert!(captures.len() >= 25, "{}", captures.len());
    captures
}

/// The values of the column `name` of `table` in a capture, as the shared scan layer reads
/// them without DuckDB, with the value of `key` beside each.
fn column_of(bytes: &[u8], table: &str, name: &str, key: &str) -> Vec<(u64, u64)> {
    let (columns, cells) = reference_rows(bytes, table);
    let index = |wanted: &str| {
        columns
            .iter()
            .position(|column| column.name == wanted)
            .unwrap_or_else(|| panic!("{table}.{wanted}"))
    };
    let number = |cell: &Cell| -> Option<u64> {
        match cell {
            Cell::Null => None,
            Cell::U8(value) => Some(u64::from(*value)),
            Cell::U16(value) => Some(u64::from(*value)),
            Cell::U32(value) => Some(u64::from(*value)),
            Cell::U64(value) => Some(*value),
            other => panic!("{table}.{name}: {other:?}"),
        }
    };
    let (value, key) = (index(name), index(key));
    cells
        .iter()
        .filter_map(|row| Some((number(&row[key])?, number(&row[value])?)))
        .collect()
}

#[test]
fn columns_of_real_captures_answer_as_the_kernel_does() -> Result<()> {
    let connection = connect()?;
    let (mut captures, mut groups, mut values) = (0, 0, 0);
    for (name, path) in corpus() {
        let bytes = std::fs::read(&path).unwrap();

        // The length of every frame.
        let lengths = column_of(&bytes, "frames", "length", "frame_number");
        let expected = kernel_answers(&histogram_of(lengths.iter().map(|(_, length)| *length)));
        for threads in [1, 4] {
            connection.execute(format!("SET threads = {threads}"), Parameters::None)?;
            let actual = answers_of(
                &connection,
                &format!("SELECT hdr_histogram(length) AS h FROM read_frames('{path}')"),
            );
            assert_eq!(actual, expected, "{name}: frames.length, {threads} threads");
        }
        values += lengths.len();

        // The total length of the IPv4 packets of each protocol: a histogram per group.
        let lengths = column_of(&bytes, "ipv4", "total_length", "protocol");
        let mut protocols: Vec<u64> = lengths.iter().map(|(protocol, _)| *protocol).collect();
        protocols.sort_unstable();
        protocols.dedup();
        let grouped = rows(
            &connection,
            &format!(
                "SELECT protocol, {} FROM (
                     SELECT protocol, hdr_histogram(total_length) AS h FROM read_ipv4('{path}')
                     WHERE total_length IS NOT NULL GROUP BY protocol) q
                 ORDER BY protocol",
                every_answer("h")
            ),
        )?;
        assert_eq!(grouped.len(), protocols.len(), "{name}: {grouped:?}");
        for (cells, protocol) in grouped.iter().zip(&protocols) {
            assert_eq!(cells[0], protocol.to_string(), "{name}");
            let of_protocol = lengths
                .iter()
                .filter(|(key, _)| key == protocol)
                .map(|(_, length)| *length);
            assert_eq!(
                answers(&cells[1..]),
                kernel_answers(&histogram_of(of_protocol)),
                "{name}: ipv4.total_length of protocol {protocol}"
            );
            groups += 1;
        }
        captures += 1;
    }
    // The comparison was of something.
    assert!(
        captures >= 25 && groups >= 10 && values > 1000,
        "{captures} {groups} {values}"
    );
    Ok(())
}

#[test]
fn a_latency_column_is_cut_to_whole_units() -> Result<()> {
    // Milliseconds since the start of the capture: a DOUBLE computed from the timestamps.
    let connection = connect()?;
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/fuzz_pcap_reader/dns.cap");
    let path = path.to_str().unwrap();
    let offsets = column(
        &connection,
        &format!(
            "SELECT epoch_ns(timestamp) - (SELECT epoch_ns(min(timestamp)) FROM read_frames('{path}'))
             FROM read_frames('{path}') ORDER BY frame_number"
        ),
    )?;
    let milliseconds = offsets
        .iter()
        .map(|nanoseconds| (nanoseconds.parse::<i64>().unwrap() as f64 / 1e9 * 1000.0) as u64);
    let expected = kernel_answers(&histogram_of(milliseconds));
    assert!(
        expected.count == 38 && expected.max > 270_000,
        "{expected:?}"
    );
    let actual = answers_of(
        &connection,
        &format!(
            "SELECT hdr_histogram(relative_time(timestamp, '{path}') * 1000) AS h
             FROM read_frames('{path}')"
        ),
    );
    assert_eq!(actual, expected);
    Ok(())
}

/// The histogram of group `group` of [`GROUPED`]: the `i` of `0..ROWS` with `i % GROUPS` equal
/// to it, each recorded as `i`.
fn group_histogram(group: u64) -> HdrHistogram {
    histogram_of((0..ROWS).filter(|i| i % GROUPS == group))
}

const ROWS: u64 = 1_200_000;
const GROUPS: u64 = 3_000;
/// Over a table, which DuckDB scans on several threads (a row group at a time), where it
/// reads `range` on one.
const NUMBERS: &str = "CREATE TABLE numbers AS SELECT i FROM range(1200000) t(i)";
const GROUPED: &str = "SELECT i % 3000 AS g, hdr_histogram(i) AS h FROM numbers GROUP BY g";

#[test]
fn parallel_aggregation_combines_the_states_of_many_groups() -> Result<()> {
    let connection = connect()?;
    connection.execute(NUMBERS, Parameters::None)?;
    let select = format!(
        "SELECT g, lower(hex(h)), {} FROM ({GROUPED}) q ORDER BY g",
        every_answer("h")
    );
    let mut combined = 0;
    for threads in [1, 4] {
        connection.execute(format!("SET threads = {threads}"), Parameters::None)?;
        let result = rows(&connection, &select)?;
        assert_eq!(result.len() as u64, GROUPS);
        for (group, cells) in result.iter().enumerate() {
            let group = group as u64;
            assert_eq!(cells[0], group.to_string());
            // Checked against the kernel for some groups, cell by cell; the count, the
            // smallest and the largest value for all.
            if group.is_multiple_of(97) {
                let expected = kernel_answers(&group_histogram(group));
                assert_eq!(
                    answers(&cells[2..]),
                    expected,
                    "group {group}, {threads} threads"
                );
            }
            assert_eq!(cells[2], (ROWS / GROUPS).to_string(), "group {group}");
            // The smallest value is the group's number, as two digits keep it.
            assert_eq!(
                cells[3],
                histogram_of([group]).min().to_string(),
                "group {group}"
            );

            // A histogram that was only recorded into has the top of a power of two as its
            // highest trackable value; one that DuckDB combined from partial states has the
            // largest value of a state. So the bytes tell whether `combine` ran.
            let mut recorded = HdrHistogram::default();
            (0..ROWS)
                .filter(|i| i % GROUPS == group)
                .for_each(|i| recorded.record(i));
            if cells[1] != hex(&recorded.serialize().unwrap()) && threads == 4 {
                combined += 1;
            }
        }
    }
    // On four threads DuckDB aggregates into a table per thread and combines them: the test
    // was of `combine`, for (nearly) every group.
    assert!(
        combined as u64 > GROUPS / 2,
        "{combined} of {GROUPS} groups were combined"
    );
    Ok(())
}

#[test]
fn filter_distinct_order_by_and_windows_work() -> Result<()> {
    let connection = connect()?;
    // FILTER, DISTINCT, and an ORDER BY inside the call, which changes nothing.
    assert_eq!(
        rows(
            &connection,
            "SELECT hdr_count(hdr_histogram(v)), hdr_count(hdr_histogram(v) FILTER (v > 2)),
                    hdr_count(hdr_histogram(DISTINCT v)), hdr_max(hdr_histogram(v ORDER BY v DESC)),
                    hdr_min(hdr_histogram(DISTINCT v) FILTER (v <> 1))
             FROM (VALUES (1), (2), (3), (3), (NULL), (40)) t(v)",
        )?,
        [row(&["5", "3", "4", "40", "2"])]
    );

    // As a window function: a running histogram, a sliding one, and one per partition.
    let result = rows(
        &connection,
        "SELECT i,
                hdr_count(hdr_histogram(i) OVER (ORDER BY i)),
                hdr_max(hdr_histogram(i) OVER (ORDER BY i)),
                hdr_min(hdr_histogram(i) OVER (ORDER BY i ROWS BETWEEN 2 PRECEDING AND CURRENT ROW)),
                hdr_count(hdr_histogram(i) OVER (ORDER BY i ROWS BETWEEN 2 PRECEDING AND CURRENT ROW)),
                hdr_count(hdr_histogram(i) OVER (PARTITION BY i % 3)),
                hdr_min(hdr_histogram(i) OVER (PARTITION BY i % 3))
         FROM range(1, 5001) t(i) ORDER BY i",
    )?;
    assert_eq!(result.len(), 5000);
    for (index, cells) in result.iter().enumerate() {
        let i = index as u64 + 1;
        let expected = [
            i,
            i,
            // The largest and the smallest value, as a histogram of two digits has them.
            histogram_of([i]).max(),
            histogram_of([i.saturating_sub(2).max(1)]).min(),
            i.min(3),
            // 1..=5000 has 1667 numbers with remainder 1 and 2, and 1666 with 0.
            if i.is_multiple_of(3) { 1666 } else { 1667 },
            if i.is_multiple_of(3) { 3 } else { i % 3 },
        ];
        let actual: Vec<u64> = cells.iter().map(|cell| cell.parse().unwrap()).collect();
        assert_eq!(actual, expected, "row {i}");
    }
    Ok(())
}

#[test]
fn a_blob_that_is_no_histogram_is_null_for_every_function() -> Result<()> {
    let connection = connect()?;
    let valid = histogram_of([5, 50, 500, 5000]).serialize().unwrap();
    let mut blobs = vec![
        String::new(),
        "00".to_owned(),
        hex(b"not a histogram"),
        "ff".repeat(64),
        // Cut short, and without its first byte.
        hex(&valid[..valid.len() - 1]),
        hex(&valid[..8]),
        hex(&valid[1..]),
        // Another serialized thing: the header of a capture file.
        "d4c3b2a1020004000000000000000000ffff000001000000".to_owned(),
    ];
    // The cookie of the encoding alone, and with nothing but zeros after it.
    blobs.push(hex(&valid[..4]));
    blobs.push(format!("{}{}", hex(&valid[..4]), "00".repeat(36)));
    for blob in &blobs {
        let result = rows(
            &connection,
            &format!(
                "SELECT {} FROM (SELECT from_hex('{blob}') AS h) q",
                every_answer("h")
            ),
        )?;
        assert!(
            result[0].iter().all(|cell| cell == "NULL"),
            "{blob}: {result:?}"
        );
    }
    // NULL in, NULL out, and a NULL percentile too.
    let result = rows(
        &connection,
        &format!(
            "SELECT {}, hdr_percentile(from_hex('{}'), NULL) FROM (SELECT NULL::BLOB AS h) q",
            every_answer("h"),
            hex(&valid)
        ),
    )?;
    assert!(result[0].iter().all(|cell| cell == "NULL"), "{result:?}");

    // Every single-bit change of a histogram is read or is NULL: never an error, and the
    // connection goes on. Good and bad rows in one chunk keep their places.
    let mut damaged = Vec::new();
    for index in 0..valid.len() {
        for bit in 0..8 {
            let mut bytes = valid.clone();
            bytes[index] ^= 1 << bit;
            damaged.push(format!("('{}')", hex(&bytes)));
        }
    }
    let result = rows(
        &connection,
        &format!(
            "SELECT hdr_count(h) IS NULL, hdr_buckets(h) IS NULL, hdr_percentile(h, 0.5) IS NULL
             FROM (SELECT from_hex(x) AS h FROM (VALUES {}) t(x)) q",
            damaged.join(", ")
        ),
    )?;
    assert_eq!(result.len(), valid.len() * 8);
    let refused = result.iter().filter(|cells| cells[0] == "true").count();
    assert!(refused > 0 && refused < result.len(), "{refused}");
    for cells in &result {
        // All functions agree on whether a BLOB is a histogram.
        assert!(cells.iter().all(|cell| cell == &cells[0]), "{cells:?}");
    }
    assert_eq!(value(&connection, "SELECT 42")?, "42");
    Ok(())
}

#[test]
fn buckets_are_rows_of_lo_hi_and_count() -> Result<()> {
    let connection = connect()?;
    // Unnested: a row per bucket, with the fields as columns.
    assert_eq!(
        rows(
            &connection,
            "SELECT lo, hi, count, typeof(lo), typeof(hi), typeof(count)
             FROM (SELECT unnest(hdr_buckets(hdr_histogram(v)), recursive := true)
                   FROM (VALUES (1), (2), (100), (1024)) t(v))
             WHERE count > 0 ORDER BY lo",
        )?,
        [
            row(&["1", "1", "1", "UBIGINT", "UBIGINT", "UBIGINT"]),
            row(&["2", "3", "1", "UBIGINT", "UBIGINT", "UBIGINT"]),
            row(&["64", "127", "1", "UBIGINT", "UBIGINT", "UBIGINT"]),
            row(&["1024", "2047", "1", "UBIGINT", "UBIGINT", "UBIGINT"]),
        ]
    );
    // The buckets of a histogram hold every value once, and there are at most 64 of them
    // whatever the range.
    assert_eq!(
        rows(
            &connection,
            "SELECT len(b), list_sum(list_transform(b, lambda x: x.count)), b[1].lo, b[-1].hi >= 9223372036854775808
             FROM (SELECT hdr_buckets(hdr_histogram(v)) AS b
                   FROM (VALUES (1::UBIGINT), (18446744073709551615), (77)) t(v))",
        )?,
        [row(&[&MAX_BUCKETS.to_string(), "3", "1", "true"])]
    );

    // Many histograms in one chunk and over several chunks, with NULLs and empty histograms
    // between them: each row has its own buckets. Row i has the values 1..=i % 50 (none for a
    // multiple of 50), and is NULL for a multiple of 7.
    let result = rows(
        &connection,
        "WITH histograms AS (
             SELECT i, CASE WHEN i % 7 = 0 THEN NULL ELSE h END AS h
             FROM (SELECT i, hdr_histogram(v) FILTER (v <= i % 50) AS h
                   FROM range(5000) t(i), range(1, 50) u(v) GROUP BY i))
         SELECT i, hdr_buckets(h)::VARCHAR, len(hdr_buckets(h)) FROM histograms ORDER BY i",
    )?;
    assert_eq!(result.len(), 5000);
    let (mut nulls, mut empties) = (0, 0);
    for (index, cells) in result.iter().enumerate() {
        let i = index as u64;
        assert_eq!(cells[0], i.to_string());
        if i.is_multiple_of(7) {
            assert_eq!(cells[1..], ["NULL", "NULL"], "row {i}");
            nulls += 1;
            continue;
        }
        let expected = kernel_answers(&histogram_of(1..=i % 50));
        assert_eq!(cells[1], expected.buckets, "row {i}");
        if i.is_multiple_of(50) {
            assert_eq!(cells[1..], ["[]", "0"], "row {i}");
            empties += 1;
        }
    }
    assert!(nulls > 700 && empties > 80, "{nulls} {empties}");
    Ok(())
}

#[test]
fn the_picture_is_the_kernel_s_text() -> Result<()> {
    let connection = connect()?;
    let ascii = value(
        &connection,
        "SELECT hdr_ascii(hdr_histogram(v)) FROM (VALUES (2), (2), (2), (100), (4000)) t(v)",
    )?;
    assert_eq!(
        ascii,
        kernel_answers(&histogram_of([2, 2, 2, 100, 4000])).ascii
    );
    let lines: Vec<&str> = ascii.lines().collect();
    assert_eq!(
        lines[0],
        "5 samples | min 2 | max 4015 | mean 822.8 | stdev 1593.1"
    );
    // The header, and the buckets 2-3, 4-7, ..., 2048-4095.
    assert_eq!(lines.len(), 2 + 11);
    assert!(lines[2].ends_with(&"#".repeat(40)), "{}", lines[2]);
    assert!(lines[12].contains("100.0%"), "{}", lines[12]);
    assert_eq!(
        value(
            &connection,
            "SELECT hdr_ascii(hdr_histogram(v)) FROM (SELECT 1 AS v WHERE false)"
        )?,
        "(empty histogram)"
    );
    Ok(())
}

/// Values that each precision keeps differently: exact ones, and ones two digits round.
const SPREAD: &str = "(0), (1), (3), (19), (199), (1999), (2001), (12345), (99999), (123456), \
                      (1234567), (98765432), (NULL)";
const SPREAD_RECORDED: [u64; 12] = [
    0, 1, 3, 19, 199, 1999, 2001, 12345, 99999, 123456, 1234567, 98765432,
];

/// The bytes of the one histogram `sql` returns, as hex.
fn hex_of(connection: &Connection, sql: &str) -> Result<String> {
    value(connection, &format!("SELECT lower(hex(h)) FROM ({sql}) q"))
}

#[test]
fn each_precision_answers_as_the_kernel_does() -> Result<()> {
    let connection = connect()?;
    for sigfigs in MIN_SIGFIGS..=MAX_SIGFIGS {
        let sql = format!("SELECT hdr_histogram(v, {sigfigs}) AS h FROM (VALUES {SPREAD}) t(v)");
        let expected = histogram_at(sigfigs, SPREAD_RECORDED);
        for threads in [1, 4] {
            connection.execute(format!("SET threads = {threads}"), Parameters::None)?;
            assert_eq!(
                answers_of(&connection, &sql),
                kernel_answers(&expected),
                "{sigfigs} figures, {threads} threads"
            );
        }
        // On one thread, the kernel's bytes: the one state that saw the rows merged into the
        // state of the result, which `init` made with the call's precision.
        connection.execute("SET threads = 1", Parameters::None)?;
        let mut merged = HdrHistogram::with_sigfigs(sigfigs).unwrap();
        merged.merge(&expected).unwrap();
        let bytes = hex_of(&connection, &sql)?;
        assert_eq!(bytes, hex(&merged.serialize().unwrap()), "{sigfigs}");
        let read = HdrHistogram::deserialize(&merged.serialize().unwrap()).unwrap();
        assert_eq!(read.sigfigs(), sigfigs);
    }

    // Without `sigfigs`, two figures: the bytes of `sigfigs` 2 and of the kernel's default.
    let default = hex_of(
        &connection,
        &format!("SELECT hdr_histogram(v) AS h FROM (VALUES {SPREAD}) t(v)"),
    )?;
    let two = hex_of(
        &connection,
        &format!("SELECT hdr_histogram(v, 2) AS h FROM (VALUES {SPREAD}) t(v)"),
    )?;
    assert_eq!(default, two);
    let mut merged = HdrHistogram::default();
    merged.merge(&histogram_of(SPREAD_RECORDED)).unwrap();
    assert_eq!(default, hex(&merged.serialize().unwrap()));

    // A parameter of a prepared statement: DuckDB binds the statement again with its value.
    connection.execute(
        format!(
            "PREPARE with_sigfigs AS SELECT {} FROM (
                 SELECT hdr_histogram(v, ?) AS h FROM (VALUES {SPREAD}) t(v)) q",
            every_answer("h")
        ),
        Parameters::None,
    )?;
    for sigfigs in [1_u8, 4] {
        let result = rows(&connection, &format!("EXECUTE with_sigfigs({sigfigs})"))?;
        assert_eq!(
            answers(&result[0]),
            kernel_answers(&histogram_at(sigfigs, SPREAD_RECORDED)),
            "{sigfigs}"
        );
    }
    let error = rows(&connection, "EXECUTE with_sigfigs(9)").unwrap_err();
    assert!(error.message.contains("from 0 to 5, not 9"), "{error}");

    // Any integer type, and a constant expression.
    let expected = kernel_answers(&histogram_at(3, SPREAD_RECORDED));
    for sigfigs in [
        "3::TINYINT",
        "3::UTINYINT",
        "3::BIGINT",
        "3::UBIGINT",
        "3::HUGEINT",
        "3::UHUGEINT",
        "1 + 2",
        "CAST('3' AS INTEGER)",
    ] {
        assert_eq!(
            answers_of(
                &connection,
                &format!("SELECT hdr_histogram(v, {sigfigs}) AS h FROM (VALUES {SPREAD}) t(v)")
            ),
            expected,
            "{sigfigs}"
        );
    }
    Ok(())
}

#[test]
fn a_precision_that_is_not_one_is_refused_when_the_statement_is_bound() -> Result<()> {
    let connection = connect()?;
    connection.execute(
        "CREATE TABLE t AS SELECT i AS v FROM range(10) t(i)",
        Parameters::None,
    )?;
    for (sigfigs, what) in [
        ("6", "6"),
        ("-1", "-1"),
        ("256", "256"),
        (
            "170141183460469231731687303715884105727",
            "170141183460469231731687303715884105727",
        ),
        (
            "340282366920938463463374607431768211455::UHUGEINT",
            "340282366920938463463374607431768211455",
        ),
        ("NULL", "NULL"),
        ("NULL::INTEGER", "NULL"),
        ("2.5", "a DECIMAL(2,1)"),
        ("3.0::DOUBLE", "a DOUBLE"),
        ("3::DECIMAL(3, 0)", "a DECIMAL(3,0)"),
        ("'3'", "a VARCHAR"),
        ("true", "a BOOLEAN"),
        ("v", "a value that is not a constant"),
        ("v % 3", "a value that is not a constant"),
        ("(SELECT 3)", "a value that is not a constant"),
        ("(random() * 3)::INTEGER", "a value that is not a constant"),
    ] {
        let sql = format!("SELECT hdr_histogram(v, {sigfigs}) FROM t");
        let error = rows(&connection, &sql).unwrap_err();
        let expected = format!(
            "hdr_histogram: the number of significant figures (the second argument) must be a \
             constant integer from 0 to 5, not {what}"
        );
        assert!(error.message.contains(&expected), "{sql}: {error}");
        // Nothing ran: EXPLAIN binds the statement and fails the same way.
        assert!(
            rows(&connection, &format!("EXPLAIN {sql}")).is_err(),
            "{sql}"
        );
    }
    // Also where there are no rows and no groups.
    let error = rows(
        &connection,
        "SELECT v, hdr_histogram(v, 9) FROM t WHERE false GROUP BY v",
    )
    .unwrap_err();
    assert!(error.message.contains("from 0 to 5, not 9"), "{error}");
    assert_eq!(value(&connection, "SELECT 42")?, "42");
    Ok(())
}

#[test]
fn parallel_aggregation_combines_states_of_the_call_s_precision() -> Result<()> {
    // Fewer groups than `GROUPED`: a state of three figures for values up to 1.2 million is
    // some 100 KiB (the table of the kernel's documentation), and DuckDB keeps one per group
    // and thread.
    const GROUPS: u64 = 1_000;
    let connection = connect()?;
    connection.execute(NUMBERS, Parameters::None)?;
    connection.execute("SET threads = 4", Parameters::None)?;
    for sigfigs in [1_u8, 3] {
        let select = format!(
            "SELECT g, lower(hex(h)), {} FROM (
                 SELECT i % {GROUPS} AS g, hdr_histogram(i, {sigfigs}) AS h FROM numbers GROUP BY g) q
             ORDER BY g",
            every_answer("h")
        );
        let result = rows(&connection, &select)?;
        assert_eq!(result.len() as u64, GROUPS);
        let mut combined = 0;
        for (group, cells) in result.iter().enumerate() {
            let group = group as u64;
            let values = || (group..ROWS).step_by(GROUPS as usize);
            if group.is_multiple_of(37) {
                assert_eq!(
                    answers(&cells[2..]),
                    kernel_answers(&histogram_at(sigfigs, values())),
                    "group {group}, {sigfigs} figures"
                );
            }
            assert_eq!(cells[2], (ROWS / GROUPS).to_string(), "group {group}");
            let mut recorded = HdrHistogram::with_sigfigs(sigfigs).unwrap();
            values().for_each(|i| recorded.record(i));
            // Every state, the empty ones DuckDB combined into included, had the precision:
            // a state of another would have given the result its own.
            assert_eq!(cells[3], recorded.min().to_string(), "group {group}");
            assert_eq!(cells[4], recorded.max().to_string(), "group {group}");
            if cells[1] != hex(&recorded.serialize().unwrap()) {
                combined += 1;
            }
        }
        assert!(
            combined as u64 > GROUPS / 2,
            "{combined} of {GROUPS} groups were combined"
        );
    }
    // And a window, whose states DuckDB makes and combines in its own way.
    let result = rows(
        &connection,
        "SELECT i, hdr_max(hdr_histogram(i, 3) OVER (ORDER BY i ROWS BETWEEN 2 PRECEDING AND CURRENT ROW)),
                hdr_count(hdr_histogram(i, 0) OVER (PARTITION BY i % 3))
         FROM range(20000, 30000) t(i) ORDER BY i",
    )?;
    let mut finer = 0;
    for cells in &result {
        let i: u64 = cells[0].parse().unwrap();
        assert_eq!(cells[1], histogram_at(3, [i]).max().to_string(), "row {i}");
        // Two figures would say otherwise for most rows.
        if cells[1] != histogram_of([i]).max().to_string() {
            finer += 1;
        }
        // 10,000 values in three partitions; zero figures count them as well.
        let partition = (20_000..30_000).filter(|j| j % 3 == i % 3).count();
        assert_eq!(cells[2], partition.to_string(), "row {i}");
    }
    assert!(finer > 5_000, "{finer}");
    assert_eq!(result.len(), 10_000);
    Ok(())
}

#[test]
fn three_figures_give_tighter_percentiles_than_two() -> Result<()> {
    let connection = connect()?;
    // 10,000 to 19,990 in steps of 10: the exact median is 14,990 and the 90th percentile 18,990.
    let percentiles = |sigfigs: u8| -> Result<Vec<f64>> {
        Ok(rows(
            &connection,
            &format!(
                "SELECT hdr_percentile(h, 0.5), hdr_percentile(h, 0.9), hdr_max(h)
                 FROM (SELECT hdr_histogram(10000 + 10 * i, {sigfigs}) AS h FROM range(1000) t(i))"
            ),
        )?[0]
            .iter()
            .map(|cell| cell.parse().unwrap())
            .collect())
    };
    let (two, three) = (percentiles(2)?, percentiles(3)?);
    for (exact, (two, three)) in [14_990.0, 18_990.0, 19_990.0]
        .iter()
        .zip(two.iter().zip(&three))
    {
        assert!(
            (three - exact).abs() < (two - exact).abs(),
            "{exact}: {two} {three}"
        );
        assert!((three - exact).abs() <= exact / 1000.0, "{exact}: {three}");
    }
    // The buckets and the picture read the precision from the BLOB too.
    let sql = "SELECT hdr_histogram(10000 + 10 * i, 3) AS h FROM range(1000) t(i)";
    assert_eq!(
        answers_of(&connection, sql),
        kernel_answers(&histogram_at(3, (0..1000).map(|i| 10_000 + 10 * i)))
    );
    Ok(())
}
