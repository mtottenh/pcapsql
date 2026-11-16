#!/usr/bin/env bash
# Fail if docs/duckdb-extension-reference.md and the built extension disagree about what the
# extension registers.
#
#   check-reference.sh <path to pcapsql.duckdb_extension> <DuckDB version>
#
# What the extension registers is asked of DuckDB, not of the sources: the functions and settings
# the stock DuckDB shell (scripts/fetch-duckdb.sh) has after LOAD and did not have before. The
# reference must
#   - name every such table function, scalar function, aggregate function, macro and setting,
#     in backticks: `name(...)` or `name`
#   - give the number of the scalar functions, of the aggregate functions and of the macros
#     in its summary table: | Scalar functions | 48 |
#   - name every parameter of the table functions: `name`, or `name := ...` in a signature
#   - not name a function (`name(` in backticks) or a setting (`pcapsql_...`) that the shell does
#     not have after LOAD. DuckDB's own functions pass: they exist too.
# The replacement scan (FROM 'x.pcap') is not listed by DuckDB anywhere and is not checked.
#
# DuckDB lists no copy functions either (duckdb_functions() has none), so the copy format is
# probed instead, with a COPY ... TO that has an option no format has. The extension's format
# refuses it with a message that lists its options; a format that is not registered is a catalog
# error. The reference must
#   - name the format: `FORMAT pcap`
#   - name every option of that list, in backticks: `LINKTYPE`
#   - not name another format (FORMAT name) that DuckDB does not have after LOAD.
set -euo pipefail

if [ $# -ne 2 ]; then
    echo "usage: $0 <extension file> <DuckDB version>" >&2
    exit 2
fi
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
extension=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
reference=$(cd "$here/../../docs" && pwd)/duckdb-extension-reference.md

duckdb=$(DUCKDB_VERSION=$2 "$here/fetch-duckdb.sh" cli)

sql="
CREATE TEMP TABLE before AS
    SELECT DISTINCT function_type AS kind, function_name AS name FROM duckdb_functions()
    UNION ALL SELECT 'setting', name FROM duckdb_settings();
LOAD '$extension';
CREATE TEMP TABLE after AS
    SELECT DISTINCT function_type AS kind, function_name AS name FROM duckdb_functions()
    UNION ALL SELECT 'setting', name FROM duckdb_settings();
CREATE TEMP TABLE registered AS SELECT * FROM after EXCEPT SELECT * FROM before;
CREATE TEMP TABLE reference AS SELECT content AS doc FROM read_text('$reference');

SELECT 'registered: ' || count(*) FILTER (kind = 'table') || ' table functions, '
    || count(*) FILTER (kind = 'scalar') || ' scalar functions, '
    || count(*) FILTER (kind = 'aggregate') || ' aggregate functions, '
    || count(*) FILTER (kind = 'macro') || ' macros, '
    || count(*) FILTER (kind = 'setting') || ' settings'
FROM registered;

SELECT 'MISSING from the reference: ' || kind || ' ' || name
FROM registered, reference
WHERE NOT (contains(doc, '\`' || name || '(') OR contains(doc, '\`' || name || '\`'))
ORDER BY ALL;

-- What duckdb_functions() calls a function is what the reference must count it as: its
-- summary gives the number of each kind.
SELECT 'MISSING from the reference: the count of ' || kind || ' functions, as | ' || label || ' | ' || n || ' |'
FROM (
    SELECT kind, count(*) AS n,
           CASE kind WHEN 'scalar' THEN 'Scalar functions' WHEN 'aggregate' THEN 'Aggregate functions'
                     ELSE 'Macros' END AS label
    FROM registered WHERE kind IN ('scalar', 'aggregate', 'macro') GROUP BY kind
), reference
WHERE NOT contains(doc, '| ' || label || ' | ' || n || ' |')
ORDER BY ALL;

SELECT 'MISSING from the reference: parameter ' || parameter || ' of ' || string_agg(function_name, ', ' ORDER BY function_name)
FROM (
    SELECT DISTINCT function_name, unnest(parameters) AS parameter
    FROM duckdb_functions()
    WHERE function_type = 'table' AND function_name IN (SELECT name FROM registered)
), reference
WHERE NOT (contains(doc, '\`' || parameter || '\`') OR contains(doc, parameter || ' := '))
GROUP BY parameter
ORDER BY ALL;

SELECT 'NOT REGISTERED, but in the reference: ' || name
FROM (
    SELECT DISTINCT unnest(regexp_extract_all(doc, '\`([a-z][a-z0-9_]*)\(', 1)) AS name FROM reference
    UNION
    SELECT DISTINCT unnest(regexp_extract_all(doc, '\`(pcapsql_[a-z0-9_]+)\`', 1)) FROM reference
)
WHERE name NOT IN (SELECT name FROM after)
ORDER BY ALL;
"

result=$("$duckdb" -unsigned -list -noheader -c "$sql")

# What the format $1 answers to a statement with an option no format has. Nothing is written:
# the statement fails when it is bound.
probe_format() {
    "$duckdb" -unsigned -no-agent -list -noheader -c "LOAD '$extension';
        COPY (SELECT ''::BLOB AS raw_data, TIMESTAMP '2000-01-01' AS timestamp)
        TO 'check-reference-probe' (FORMAT $1, PCAPSQL_NO_SUCH_OPTION);" 2>&1 || true
}
probe=$(probe_format pcap)
case $probe in
*"the options of the format are "*)
    # "... are LINKTYPE, SNAPLEN and PRECISION"
    options=$(echo "${probe##*the options of the format are }" | head -n 1 | tr -c 'A-Z_\n' ' ')
    result+=$'\n'"registered: copy format pcap, options: $(echo $options)"
    grep -q -F '`FORMAT pcap`' "$reference" ||
        result+=$'\n'"MISSING from the reference: the copy format, as \`FORMAT pcap\`"
    for option in $options; do
        grep -q -F "\`$option\`" "$reference" ||
            result+=$'\n'"MISSING from the reference: option $option of the copy format pcap"
    done
    ;;
*) result+=$'\n'"MISSING from the extension: the copy format pcap: $probe" ;;
esac
for format in $(grep -o -E 'FORMAT [a-z_]+' "$reference" | cut -d' ' -f2 | sort -u); do
    case $(probe_format "$format") in
    *"Copy Function with name $format does not exist"*)
        result+=$'\n'"NOT REGISTERED, but in the reference: copy format $format"
        ;;
    esac
done
echo "$result" | sed 's/^/check-reference: /'
case $result in
*MISSING* | *"NOT REGISTERED"*)
    echo "check-reference: FAILED: docs/duckdb-extension-reference.md and $1 disagree" >&2
    exit 1
    ;;
"registered: "*) echo "check-reference: ok" ;;
*)
    echo "check-reference: FAILED: no answer from DuckDB" >&2
    exit 1
    ;;
esac
