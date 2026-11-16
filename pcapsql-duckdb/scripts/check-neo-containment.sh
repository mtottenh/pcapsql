#!/usr/bin/env bash
# Fail if `duckdb_neo` is named outside the engine glue.
#
# The DuckDB C API v2 is unstable, and `duckdb-neo` changes with every DuckDB release. Confining
# its use to src/engine/ (plus the two entrypoint crates, ext/ and itest/) keeps an upgrade to one
# directory. Every other Rust source in the repository must stay free of it.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

if git grep --untracked -n -w duckdb_neo -- '*.rs' \
    ':(exclude)pcapsql-duckdb/src/engine/' \
    ':(exclude)pcapsql-duckdb/ext/' \
    ':(exclude)pcapsql-duckdb/itest/' \
    ':(exclude)research_notes/'; then
    echo "check-neo-containment: duckdb_neo is used outside pcapsql-duckdb/src/engine/, ext/ and itest/" >&2
    exit 1
fi
echo "check-neo-containment: ok"
