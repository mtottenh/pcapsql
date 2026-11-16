#!/usr/bin/env bash
# Fail if docs/duckdb-extension-reference.md and the built extension disagree about what the
# extension registers.
#
#   check-reference.sh <path to pcapsql.duckdb_extension> <DuckDB version>
#
# What the extension registers is asked of DuckDB, not of the sources: the functions and settings
# the stock DuckDB shell (scripts/fetch-duckdb.sh) has after LOAD and did not have before. The
# reference must
#   - name every such table function, scalar function, macro and setting, in backticks:
#     `name(...)` or `name`
#   - name every parameter of the table functions: `name`, or `name := ...` in a signature
#   - not name a function (`name(` in backticks) or a setting (`pcapsql_...`) that the shell does
#     not have after LOAD. DuckDB's own functions pass: they exist too.
# The replacement scan (FROM 'x.pcap') is not listed by DuckDB anywhere and is not checked.
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
    || count(*) FILTER (kind = 'macro') || ' macros, '
    || count(*) FILTER (kind = 'setting') || ' settings'
FROM registered;

SELECT 'MISSING from the reference: ' || kind || ' ' || name
FROM registered, reference
WHERE NOT (contains(doc, '\`' || name || '(') OR contains(doc, '\`' || name || '\`'))
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
