#!/usr/bin/env bash
# Fetch a DuckDB release artifact from the GitHub release and print where it is.
#
#   fetch-duckdb.sh lib   prints the directory holding libduckdb and its headers (for DUCKDB_LIB_DIR)
#   fetch-duckdb.sh cli   prints the path of the duckdb command-line shell
#
# Artifacts are cached under $PCAPSQL_DUCKDB_CACHE (default: pcapsql-duckdb/.duckdb-release), one
# directory per DuckDB version, and verified against scripts/duckdb-release.sha256.
#
# GitHub is used rather than install.duckdb.org, where `duckdb-neo`'s own download feature goes,
# so that the same command works in CI and behind network policies that only allow GitHub.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
version=${DUCKDB_VERSION:-v2.0.0}
cache=${PCAPSQL_DUCKDB_CACHE:-$here/../.duckdb-release}/$version

case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) platform=linux-amd64 library=libduckdb.so ;;
    Linux-aarch64) platform=linux-arm64 library=libduckdb.so ;;
    Darwin-*) platform=osx-universal library=libduckdb.dylib ;;
    *)
        echo "fetch-duckdb: no DuckDB release artifact is known for $(uname -s) $(uname -m)" >&2
        exit 1
        ;;
esac

case "${1:-}" in
    lib) archive=duckdb-shared-libs-$platform.tar.gz directory=$cache/lib result=$cache/lib marker=$library ;;
    cli) archive=duckdb-cli-$platform.tar.gz directory=$cache/cli result=$cache/cli/duckdb marker=duckdb ;;
    *)
        echo "usage: $0 lib|cli" >&2
        exit 2
        ;;
esac

if [ ! -e "$directory/$marker" ]; then
    expected=$(awk -v version="$version" -v archive="$archive" \
        '$2 == version "/" archive { print $1 }' "$here/duckdb-release.sha256")
    if [ -z "$expected" ]; then
        echo "fetch-duckdb: no checksum for $version/$archive in scripts/duckdb-release.sha256" >&2
        exit 1
    fi

    # Unpack beside the destination and rename, so an interrupted run leaves nothing half-filled.
    mkdir -p "$cache"
    scratch=$(mktemp -d "$cache/fetch.XXXXXX")
    trap 'rm -rf "$scratch"' EXIT
    curl --fail --silent --show-error --location --retry 3 --output "$scratch/$archive" \
        "https://github.com/duckdb/duckdb/releases/download/$version/$archive"

    if command -v sha256sum >/dev/null; then
        actual=$(sha256sum "$scratch/$archive" | cut -d' ' -f1)
    else
        actual=$(shasum -a 256 "$scratch/$archive" | cut -d' ' -f1)
    fi
    if [ "$actual" != "$expected" ]; then
        echo "fetch-duckdb: checksum mismatch for $version/$archive" >&2
        echo "  expected $expected" >&2
        echo "  actual   $actual" >&2
        exit 1
    fi

    mkdir "$scratch/unpacked"
    tar -xzf "$scratch/$archive" -C "$scratch/unpacked"
    rm -rf "$directory"
    mv "$scratch/unpacked" "$directory"
fi

echo "$result"
