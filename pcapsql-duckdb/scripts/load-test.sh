#!/usr/bin/env bash
# LOAD the built extension in the stock DuckDB command-line shell and call each kind of function.
#
#   load-test.sh <path to pcapsql.duckdb_extension> <DuckDB version> <extension version>
#
# The shell is the release binary from GitHub (scripts/fetch-duckdb.sh), not a build of ours, so
# this is the check that the artifact loads in the DuckDB a user has: the ABI stamp, the platform,
# the entrypoint symbol and the pinned C API all have to match for LOAD to succeed.
set -euo pipefail

if [ $# -ne 3 ]; then
    echo "usage: $0 <extension file> <DuckDB version> <extension version>" >&2
    exit 2
fi
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# LOAD wants an absolute path.
extension=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
duckdb_version=$2
extension_version=$3

duckdb=$(DUCKDB_VERSION=$duckdb_version "$here/fetch-duckdb.sh" cli)
echo "load-test: $("$duckdb" -csv -noheader -c 'SELECT library_version, source_id FROM pragma_version()')"
echo "load-test: $extension"

sql="
LOAD '$extension';
SELECT extension_name, loaded, extension_version FROM duckdb_extensions() WHERE extension_name = 'pcapsql';
SELECT count(*) FROM pcap_protocols();
SELECT name, field_count FROM pcap_protocols() WHERE name = 'frames';
SELECT ip4('192.168.1.1'), ip4_to_string(3232235777), ip4('not an address') IS NULL, ip4_to_string(NULL) IS NULL;
SELECT count(*), count(DISTINCT ip4_to_string(i::UINTEGER)) FROM range(5000) t(i);
"
expected="pcapsql,true,$extension_version
28
frames,5
3232235777,192.168.1.1,true,true
5000,5000"

actual=$("$duckdb" -unsigned -csv -noheader -c "$sql")
if [ "$actual" != "$expected" ]; then
    echo "load-test: FAILED" >&2
    diff <(echo "$expected") <(echo "$actual") >&2 || true
    exit 1
fi
echo "$actual"
echo "load-test: ok"
