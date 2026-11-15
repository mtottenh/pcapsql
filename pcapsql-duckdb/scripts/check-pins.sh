#!/usr/bin/env bash
# Fail if the places that name the targeted DuckDB release disagree.
#
# A build of the extension loads in exactly one DuckDB release (the C API v2 is unstable), and
# that release is written down in several files. docs/duckdb-upgrade-runbook.md lists them; this
# script checks that they say the same thing, so that an upgrade that misses one fails `make
# check` instead of producing an artifact that does not load. It reads files only: no build, no
# network, no submodule checkout.
#
# What must agree with TARGET_DUCKDB_VERSION of the Makefile (vMAJOR.MINOR.PATCH):
#   - the `duckdb-neo` pin of the three manifests, `=0.<MAJOR><MINOR:02><PATCH:02>.<n>`, the same
#     in each, and the version both lock files resolved
#   - `api_version` of the two entrypoints (ext/src/lib.rs, itest/src/lib.rs)
#   - the default of scripts/fetch-duckdb.sh, and a checksum for every archive it can fetch
#   - `duckdb_version` of the distribution workflow, and the artifact names that contain it
# And separately:
#   - the extension-ci-tools commit: the submodule and the workflow that calls its reusable
#     workflow name the same one
#   - the community descriptor carries the workspace version and this build directory
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

failures=0
fail() {
    echo "check-pins: $*" >&2
    failures=$((failures + 1))
}

target=$(sed -n 's/^TARGET_DUCKDB_VERSION=//p' pcapsql-duckdb/Makefile)
if ! [[ $target =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    echo "check-pins: TARGET_DUCKDB_VERSION of pcapsql-duckdb/Makefile is '$target', not vMAJOR.MINOR.PATCH" >&2
    exit 1
fi
# duckdb-neo 0.20000.x targets DuckDB 2.0.0: the middle component is MAJOR, MINOR and PATCH with
# two digits for each of the last two.
neo_prefix=$(printf '0.%d%02d%02d.' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}")

# The duckdb-neo pin of each manifest.
pin=
for manifest in pcapsql-duckdb/Cargo.toml pcapsql-duckdb/ext/Cargo.toml pcapsql-duckdb/itest/Cargo.toml; do
    found=$(sed -n 's/^duckdb-neo = { version = "\([^"]*\)".*/\1/p' "$manifest")
    case $found in
    "=$neo_prefix"*) ;;
    *) fail "$manifest pins duckdb-neo '$found'; $target needs '=${neo_prefix}<n>'" ;;
    esac
    if [ -z "$pin" ]; then
        pin=$found
    elif [ "$found" != "$pin" ]; then
        fail "$manifest pins duckdb-neo '$found', pcapsql-duckdb/Cargo.toml '$pin'"
    fi
done

# What the lock files resolved.
for lock in Cargo.lock pcapsql-duckdb/itest/Cargo.lock; do
    locked=$(awk '$0 == "name = \"duckdb-neo\"" { getline; gsub(/version = |"/, ""); print }' "$lock")
    if [ "=$locked" != "$pin" ]; then
        fail "$lock has duckdb-neo '$locked', the manifests pin '$pin'"
    fi
done

# The entrypoints: of the loadable extension, and of the one the in-process tests register.
for entrypoint in pcapsql-duckdb/ext/src/lib.rs pcapsql-duckdb/itest/src/lib.rs; do
    if ! grep -q "api_version = \"$target\"" "$entrypoint"; then
        fail "$entrypoint: the entrypoint's api_version is not \"$target\""
    fi
done

# The release artifacts the tests download.
if ! grep -q "^version=\${DUCKDB_VERSION:-$target}\$" pcapsql-duckdb/scripts/fetch-duckdb.sh; then
    fail "pcapsql-duckdb/scripts/fetch-duckdb.sh does not default to $target"
fi
for archive in duckdb-shared-libs duckdb-cli; do
    for platform in linux-amd64 linux-arm64 osx-universal; do
        if ! grep -q -E "^[0-9a-f]{64}  $target/$archive-$platform\.tar\.gz\$" pcapsql-duckdb/scripts/duckdb-release.sha256; then
            fail "pcapsql-duckdb/scripts/duckdb-release.sha256 has no checksum for $target/$archive-$platform.tar.gz"
        fi
    done
done

# The distribution workflow.
workflow=.github/workflows/duckdb-dist.yml
if ! grep -q -E "^ +duckdb_version: $target\$" "$workflow"; then
    fail "$workflow: duckdb_version is not $target"
fi
if grep -o -E 'pcapsql-v[0-9]+\.[0-9]+\.[0-9]+-extension' "$workflow" | grep -v -x "pcapsql-$target-extension"; then
    fail "$workflow: an artifact name above is not of $target"
fi

# The extension-ci-tools commit: the submodule (as committed) and the workflow.
tools=$(git ls-files --stage pcapsql-duckdb/extension-ci-tools | awk '{ print $2 }')
called=$(sed -n 's|^ *uses: duckdb/extension-ci-tools/.github/workflows/_extension_distribution.yml@\([0-9a-f]*\).*|\1|p' "$workflow")
passed=$(sed -n 's/^ *ci_tools_version: \([0-9a-f]*\).*/\1/p' "$workflow")
if [ "$called" != "$tools" ] || [ "$passed" != "$tools" ]; then
    fail "$workflow calls extension-ci-tools at '$called' and passes ci_tools_version '$passed'; the submodule is at '$tools'"
fi

# The community descriptor.
descriptor=pcapsql-duckdb/community/description.yml
version=$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml)
if ! grep -q -E "^  version: $version\$" "$descriptor"; then
    fail "$descriptor: extension.version is not the workspace version $version"
fi
if ! grep -q -E "^  build_directory: pcapsql-duckdb\$" "$descriptor"; then
    fail "$descriptor: repo.build_directory is not pcapsql-duckdb"
fi

if [ "$failures" -ne 0 ]; then
    echo "check-pins: $failures disagreement(s); see docs/duckdb-upgrade-runbook.md" >&2
    exit 1
fi
echo "check-pins: ok ($target, duckdb-neo $pin, extension-ci-tools ${tools:0:7}, extension $version)"
