#!/usr/bin/env bash
# Build the extension against a newer `duckdb-neo` than the one it is pinned to, to see what the
# next upgrade will break before a DuckDB release forces it.
#
#   canary.sh crates   the newest duckdb-neo published on crates.io
#   canary.sh main     the main branch of https://github.com/duckdb/duckdb-rs
#
# The C API v2 is unstable: `duckdb-neo` changes with every DuckDB release and is pinned exactly
# (see docs/duckdb-upgrade-runbook.md). This script moves the pin of the three manifests to the
# candidate in the working tree, runs the checks below and puts the manifests and lock files
# back when it ends (CANARY_KEEP=1 leaves them, as the start of an upgrade).
#
#   1. `cargo check` of the loadable extension: does src/engine/ still compile?
#   2. If the candidate targets the DuckDB release the Makefile targets (a new duckdb-neo for
#      the same DuckDB): `make release test_release load_test_release itest`, the whole suite.
#      A candidate for another DuckDB release stops after step 1: the artifact would not load
#      in the pinned release, and nothing here knows the checksums of the new one.
#      CANARY_COMPILE_ONLY=1 stops after step 1 in any case.
#
# Exit status: 0 if every step that ran passed, 1 otherwise. A summary goes to standard output
# and, in GitHub Actions, to the job summary.
set -euo pipefail

mode=${1:-crates}
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$here/.."

manifests=(Cargo.toml ext/Cargo.toml itest/Cargo.toml)
locks=(../Cargo.lock itest/Cargo.lock)

summary() {
    echo "canary: $*"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        echo "- $*" >> "$GITHUB_STEP_SUMMARY"
    fi
}

target=$(sed -n 's/^TARGET_DUCKDB_VERSION=//p' Makefile)
pin=$(sed -n 's/^duckdb-neo = { version = "=\([^"]*\)".*/\1/p' Cargo.toml)

# The DuckDB release a duckdb-neo version is for: 0.20000.2 is for v2.0.0, 0.20103.0 for v2.1.3.
duckdb_release() {
    local middle
    middle=$(echo "$1" | cut -d. -f2)
    echo "v$((middle / 10000)).$((middle / 100 % 100)).$((middle % 100))"
}

patch=()
flags=
case $mode in
crates)
    # The sparse index of crates.io: one JSON object per published version.
    candidate=$(curl --fail --silent --show-error --location --retry 3 https://index.crates.io/du/ck/duckdb-neo |
        python3 -c '
import json, sys
versions = [json.loads(line) for line in sys.stdin if line.strip()]
versions = [v["vers"] for v in versions if not v["yanked"] and "-" not in v["vers"]]
print(max(versions, key=lambda v: tuple(int(part) for part in v.split("."))))')
    source="duckdb-neo $candidate from crates.io"
    ;;
main)
    repository=https://github.com/duckdb/duckdb-rs
    candidate=$(curl --fail --silent --show-error --location --retry 3 \
        https://raw.githubusercontent.com/duckdb/duckdb-rs/main/crates/duckdb-neo/Cargo.toml |
        sed -n 's/^version = "\([^"]*\)".*/\1/p' | head -n 1)
    for crate in duckdb-neo libduckdb-sys duckdb-loadable-macros; do
        for setting in "git=\"$repository\"" 'branch="main"'; do
            patch+=(--config "patch.crates-io.$crate.$setting")
            # The same, quoted for the shell of a make recipe.
            flags+=" --config 'patch.crates-io.$crate.$setting'"
        done
    done
    source="duckdb-neo $candidate from the main branch of duckdb-rs"
    ;;
*)
    echo "usage: $0 crates|main" >&2
    exit 2
    ;;
esac
if ! [[ $candidate =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "canary: could not find the candidate version (got '$candidate')" >&2
    exit 1
fi

candidate_release=$(duckdb_release "$candidate")
summary "pinned: duckdb-neo $pin for DuckDB $target; candidate: $source, for DuckDB $candidate_release"

if [ "$mode" = crates ] && [ "$candidate" = "$pin" ]; then
    summary "the pin is the newest published duckdb-neo: nothing newer to build against"
    if [ "${CANARY_FORCE:-0}" != 1 ]; then
        exit 0
    fi
fi

# Move the pin, and put everything back on the way out.
backup=$(mktemp -d)
restore() {
    if [ "${CANARY_KEEP:-0}" = 1 ]; then
        echo "canary: CANARY_KEEP=1: the manifests and lock files stay as the canary left them"
    else
        for file in "${manifests[@]}" "${locks[@]}"; do
            cp "$backup/$(echo "$file" | tr / _)" "$file"
        done
    fi
    rm -rf "$backup"
}
for file in "${manifests[@]}" "${locks[@]}"; do
    cp "$file" "$backup/$(echo "$file" | tr / _)"
done
trap restore EXIT
if [ "$candidate" != "$pin" ]; then
    sed -i.canary "s/^\(duckdb-neo = { version = \"=\)$pin\"/\1$candidate\"/" "${manifests[@]}"
    rm -f Cargo.toml.canary ext/Cargo.toml.canary itest/Cargo.toml.canary
fi

status=0

if cargo check --package pcapsql-duckdb-ext ${patch[@]+"${patch[@]}"}; then
    summary "cargo check of the loadable extension: passed"
else
    summary "cargo check of the loadable extension: FAILED (src/engine/ needs the changes of an upgrade)"
    status=1
fi

if [ "$status" -ne 0 ] || [ "${CANARY_COMPILE_ONLY:-0}" = 1 ]; then
    :
elif [ "$candidate_release" != "$target" ]; then
    summary "the candidate is for DuckDB $candidate_release, the tree for $target: the artifact was not built or loaded. Follow docs/duckdb-upgrade-runbook.md"
else
    # rust.Makefile and the itest target both take extra cargo arguments.
    for step in configure release test_release load_test_release itest; do
        if make "$step" CARGO_OVERRIDE_DUCKDB_RS_FLAG="$flags" ITEST_ARGS="$flags"; then
            summary "make $step: passed"
        else
            summary "make $step: FAILED"
            status=1
            break
        fi
    done
fi

exit "$status"
