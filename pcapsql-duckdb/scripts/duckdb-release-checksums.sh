#!/usr/bin/env bash
# Print the lines of scripts/duckdb-release.sha256 for one DuckDB release.
#
#   duckdb-release-checksums.sh v2.0.0 > scripts/duckdb-release.sha256
#
# Downloads the six archives scripts/fetch-duckdb.sh can ask for (the shared library and the
# command-line shell, for linux-amd64, linux-arm64 and osx-universal) from the GitHub release and
# hashes them. The checksums are trust on first use: they pin what GitHub served over HTTPS on
# the day of the upgrade, so that every later build and test run uses the same bytes. Run it
# once per upgrade (docs/duckdb-upgrade-runbook.md), and compare with a second machine or
# network if the release is to be trusted further than that.
set -euo pipefail

if [ $# -ne 1 ]; then
    echo "usage: $0 <DuckDB version, e.g. v2.0.0>" >&2
    exit 2
fi
version=$1

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

for archive in duckdb-shared-libs duckdb-cli; do
    for platform in linux-amd64 linux-arm64 osx-universal; do
        file=$archive-$platform.tar.gz
        curl --fail --silent --show-error --location --retry 3 --output "$scratch/$file" \
            "https://github.com/duckdb/duckdb/releases/download/$version/$file"
        if command -v sha256sum >/dev/null; then
            sum=$(sha256sum "$scratch/$file" | cut -d' ' -f1)
        else
            sum=$(shasum -a 256 "$scratch/$file" | cut -d' ' -f1)
        fi
        echo "$sum  $version/$file"
        rm "$scratch/$file"
    done
done
