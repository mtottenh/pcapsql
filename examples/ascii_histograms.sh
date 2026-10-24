#!/usr/bin/env bash
# Print distributions from a capture with hdr_histogram() + hdr_ascii().
#
# hdr_histogram(value) is an aggregate that builds an HdrHistogram;
# hdr_ascii(hist) renders it as log-scale buckets with count, percent,
# cumulative percent and a bar. The other hdr_* functions (hdr_percentile,
# hdr_count, ...) read from the same histogram value.
#
# Queries run with --format raw, which prints values with no table border,
# header or quoting, so each histogram appears exactly as rendered.
#
# Usage: ./examples/ascii_histograms.sh [capture.pcap]
#   PCAPSQL=/path/to/pcapsql overrides the binary (default: debug build,
#   then pcapsql on PATH).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PCAP="${1:-$ROOT/fuzz/corpus/fuzz_pcap_reader/tcp-ecn-sample.pcap}"

if [ -z "${PCAPSQL:-}" ]; then
    if [ -x "$ROOT/target/debug/pcapsql" ]; then
        PCAPSQL="$ROOT/target/debug/pcapsql"
    else
        PCAPSQL=pcapsql
    fi
fi

q() {
    "$PCAPSQL" "$PCAP" --format raw -e "$1"
}

echo "Capture: $PCAP"
echo

echo "### Frame sizes (bytes)"
q "SELECT hdr_ascii(hdr_histogram(length)) FROM frames"
echo

echo "### Frame sizes by direction (bytes)"
# One histogram per group: GROUP BY gives one hdr_histogram per row. The
# label is joined to the histogram with a newline (chr(10)) so it prints on
# its own line rather than as a tab-separated column.
q "SELECT concat('-- ', dir, ': ', n, ' packets, median ', p50, ' bytes', chr(10), h)
   FROM (
     SELECT CASE WHEN dst_port = 80 THEN 'client -> server'
                 ELSE 'server -> client' END   AS dir,
            count(*)                           AS n,
            CAST(hdr_percentile(hdr_histogram(length), 0.5) AS BIGINT) AS p50,
            hdr_ascii(hdr_histogram(length))   AS h
     FROM tcp_packets
     GROUP BY 1
   )
   ORDER BY dir"
echo

echo "### TCP advertised window (bytes, unscaled)"
q "SELECT hdr_ascii(hdr_histogram(window)) FROM tcp"
echo

echo "### Packet inter-arrival time (microseconds)"
# Timestamps cast to BIGINT are microseconds; LAG gives the gap to the
# previous frame. Values span many orders of magnitude, which is where the
# log-scale buckets help.
q "WITH t AS (SELECT CAST(timestamp AS BIGINT) AS ts FROM frames),
        g AS (SELECT ts - LAG(ts) OVER (ORDER BY ts) AS gap_us FROM t)
   SELECT concat('p50 ', CAST(hdr_percentile(hdr_histogram(gap_us), 0.5) AS BIGINT),
                 ' us, p99 ', CAST(hdr_percentile(hdr_histogram(gap_us), 0.99) AS BIGINT),
                 ' us', chr(10), hdr_ascii(hdr_histogram(gap_us)))
   FROM g
   WHERE gap_us IS NOT NULL"
