#!/usr/bin/env bash
# Fail if the extension reaches a file other than through DuckDB's file system.
#
# Every open goes through src/engine/fs.rs (`DuckFile`), so that remote paths work and DuckDB's
# access rules (`enable_external_access`, `allowed_directories`) hold. This looks for `std::fs`
# and for pcapsql-core's own file readers, which open with `std::fs`, in the extension's sources
# (src/ and ext/; the tests in itest/ write their fixtures with `std::fs`). Comment lines are
# ignored. clippy.toml enforces the same through clippy's `disallowed_types` and
# `disallowed_methods`; this check needs no build.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

if git grep --untracked -n -E 'std::fs|FilePacketSource|MmapPacketSource|CloudPacketSource' -- \
    'pcapsql-duckdb/src/*.rs' 'pcapsql-duckdb/ext/*.rs' |
    grep -v -E '^[^:]+:[0-9]+:[[:space:]]*//'; then
    echo "check-no-std-fs: the extension must open files through engine::fs::DuckFile" >&2
    exit 1
fi
echo "check-no-std-fs: ok"
