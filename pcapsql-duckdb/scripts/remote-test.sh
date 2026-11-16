#!/usr/bin/env bash
# Read captures over HTTP, through DuckDB's `httpfs` extension, and compare with the same
# captures read from disk.
#
#   remote-test.sh [--require-httpfs] <path to pcapsql.duckdb_extension> <DuckDB version>
#
# The extension opens every capture through DuckDB's file-system API, so a URL is a capture as
# soon as an extension that serves URLs is loaded. This starts scripts/range-http-server.py on
# 127.0.0.1 over a directory of captures (legacy pcap, pcapng, gzip, zstd where the `zstd`
# command exists, and a generated capture of about 28 MB), and in the release's command-line
# shell (scripts/fetch-duckdb.sh) checks that
#
#   - `frames`, protocol tables and a `*_packets` view of each capture have the same rows read
#     from the URL as read from the file;
#   - `filename` is the URL; a list of URLs, and of a URL and a file, is read as one table;
#   - a remote capture is read as one partition, where the same file on disk is split;
#   - a filter on `frame_number` is pushed down, and it and `LIMIT` end the read: neither asks
#     the server for anything in the second half of a 28 MB capture;
#   - a URL the server has no file for is an error that names the URL;
#   - `SET enable_external_access = false` refuses the URL without a request to the server;
#   - every capture was in fact requested from the server, in ranges.
#
# Exit status: 0 when every check passed, 1 when one failed, 2 for wrong usage, and 77 when
# `INSTALL httpfs` failed, which is what happens without access to extensions.duckdb.org: the
# test was not run. With --require-httpfs that is a failure (1) too, which is what CI wants.
set -euo pipefail

skip_status=77
require_httpfs=false
if [ "${1:-}" = "--require-httpfs" ]; then
    require_httpfs=true
    shift
fi
if [ $# -ne 2 ]; then
    echo "usage: $0 [--require-httpfs] <extension file> <DuckDB version>" >&2
    exit 2
fi
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# LOAD wants an absolute path.
extension=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
duckdb_version=$2

fail() {
    echo "remote-test: FAILED: $*" >&2
    exit 1
}

duckdb=$(DUCKDB_VERSION=$duckdb_version "$here/fetch-duckdb.sh" cli)
echo "remote-test: $("$duckdb" -csv -noheader -c 'SELECT library_version, source_id FROM pragma_version()')"
echo "remote-test: $extension"

# `httpfs` comes from extensions.duckdb.org, once; later runs find it installed.
if ! installed=$("$duckdb" -csv -noheader -c "INSTALL httpfs;" 2>&1); then
    if $require_httpfs; then
        fail "INSTALL httpfs: $installed"
    fi
    echo "remote-test: SKIPPED: httpfs cannot be installed, so no capture was read over HTTP:"
    echo "$installed" | sed 's/^/remote-test:     /'
    exit $skip_status
fi
"$duckdb" -csv -noheader -c "LOAD httpfs;" || fail "httpfs is installed and does not load"

# ---- the captures, and the server over them ----

corpus=$(cd "$here/../../fuzz/corpus/fuzz_pcap_reader" && pwd)
scratch=$(mktemp -d)
server_pid=
cleanup() {
    if [ -n "$server_pid" ]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -rf "$scratch"
}
trap cleanup EXIT

served=$scratch/served
mkdir "$served"
cp "$corpus/dns.cap" "$corpus/ldap-ssl.pcapng" "$corpus/v6-http.cap" "$served/"
gzip -c "$corpus/dns.cap" > "$served/dns.cap.gz"

# A legacy pcap of 200,000 frames, two TCP segments for each UDP datagram, with payloads of 40
# to 103 bytes: more frames than one partition holds and several times the size from which a
# file on disk is split, so the local read of it is a parallel one.
big_frames=200000
python3 - "$served/big.pcap" "$big_frames" <<'EOF'
import struct
import sys

path, frames = sys.argv[1], int(sys.argv[2])
ethernet = bytes.fromhex("020000000002" "020000000001" "0800")
with open(path, "wb") as out:
    out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for i in range(frames):
        payload = bytes((i + j) & 0xFF for j in range(40 + i % 64))
        source, destination = 1024 + i % 5000, 53 if i % 3 == 0 else 443
        if i % 3 == 0:
            protocol = 17
            transport = struct.pack(">HHHH", source, destination, 8 + len(payload), 0)
        else:
            protocol = 6
            transport = struct.pack(
                ">HHIIBBHHH", source, destination, i, i // 2, 5 << 4, 0x18, 4096, 0, 0
            )
        ip = struct.pack(
            ">BBHHHBBHII",
            0x45, 0, 20 + len(transport) + len(payload), i & 0xFFFF, 0, 64, protocol, 0,
            0x0A000000 | (i % 250 + 1), 0x0A010000 | (i % 199 + 1),
        )
        frame = ethernet + ip + transport + payload
        out.write(struct.pack("<IIII", 1700000000 + i // 1000, i % 1000 * 1000, len(frame), len(frame)))
        out.write(frame)
EOF
gzip -c "$served/big.pcap" > "$served/big.pcap.gz"
if command -v zstd >/dev/null; then
    zstd -q -c "$corpus/v6-http.cap" > "$served/v6-http.cap.zst"
else
    echo "remote-test: no zstd command here: no zstd-compressed capture is read"
fi

log=$scratch/requests.log
: > "$log"
python3 "$here/range-http-server.py" --directory "$served" --port-file "$scratch/port" --log "$log" &
server_pid=$!
for _ in $(seq 100); do
    [ -s "$scratch/port" ] && break
    kill -0 "$server_pid" 2>/dev/null || fail "the HTTP server did not start"
    sleep 0.1
done
[ -s "$scratch/port" ] || fail "the HTTP server did not report its port"
base=http://127.0.0.1:$(cat "$scratch/port")
echo "remote-test: serving $(find "$served" -type f | wc -l | tr -d ' ') captures at $base"

# ---- helpers ----

# sql <statements>: the result as CSV. Four threads, so that a file that can be split is.
sql() {
    "$duckdb" -unsigned -csv -noheader -c "LOAD httpfs; LOAD '$extension'; SET threads = 4; $1"
}

# expect <what> <expected> <statements>
expect() {
    local actual
    actual=$(sql "$3" 2>&1) || fail "$1: $actual"
    if [ "$actual" != "$2" ]; then
        echo "remote-test: FAILED: $1" >&2
        diff <(echo "$2") <(echo "$actual") >&2 || true
        exit 1
    fi
}

# refused <what> <statements>: the error of statements that must fail, and not by a crash.
refused() {
    local output status=0
    output=$(sql "$2" 2>&1) || status=$?
    if [ "$status" -eq 0 ]; then
        fail "$1: no error: $output"
    fi
    if [ "$status" -ge 126 ]; then
        fail "$1: the shell ended with status $status: $output"
    fi
    echo "$output"
}

# The lines of the request log for <file>, from line <from> on.
requests() {
    tail -n "+$1" "$log" | awk -F '\t' -v path="/$2" '$2 == path'
}
log_lines() {
    echo $(($(wc -l < "$log") + 1))
}

# same_rows <file> <table>: the table of the capture has the same rows, as often, from the URL
# and from the file, and has rows at all.
same_rows() {
    local remote="read_pcap('$base/$1', protocol := '$2')" on_disk="read_pcap('$served/$1', protocol := '$2')"
    local rows
    rows=$(sql "SELECT count(*) FROM $on_disk;")
    [ "$rows" -gt 0 ] || fail "$2 of $1 has no rows: the comparison would show nothing"
    expect "$2 of $1: rows from the URL and from the file" "$rows,0,0" "
        SELECT (SELECT count(*) FROM $remote),
               (SELECT count(*) FROM (SELECT * FROM $remote EXCEPT ALL SELECT * FROM $on_disk)),
               (SELECT count(*) FROM (SELECT * FROM $on_disk EXCEPT ALL SELECT * FROM $remote));"
    echo "remote-test: $1: $2: $rows rows, the same from the URL"
}

# ---- every table kind of every capture ----

same_tables() {
    local file=$1 table
    shift
    for table in "$@"; do
        same_rows "$file" "$table"
    done
}
same_tables dns.cap frames udp dns dns_packets
same_tables ldap-ssl.pcapng frames ipv6 tcp tcp_packets
same_tables v6-http.cap frames ipv6 udp udp_packets
same_tables dns.cap.gz frames udp dns dns_packets
same_tables big.pcap frames udp tcp tcp_packets
same_tables big.pcap.gz frames udp
if [ -e "$served/v6-http.cap.zst" ]; then
    same_tables v6-http.cap.zst frames ipv6 tcp tcp_packets
fi

# Rows come in file order from a URL as they do from a file.
expect "big.pcap: frame numbers from the URL are in order" "$big_frames,true" "
    SELECT count(*), bool_and(frame_number = n) FROM (SELECT frame_number, row_number() OVER () AS n FROM read_frames('$base/big.pcap'));"

# ---- filename, lists ----

expect "filename of a URL" "$base/dns.cap,38" "
    SELECT filename, count(*) FROM read_dns('$base/dns.cap', filename := true) GROUP BY ALL;"
expect "a list of URLs" "$base/dns.cap.gz,38,38
$base/ldap-ssl.pcapng,$(sql "SELECT count(*), max(frame_number) FROM read_frames('$served/ldap-ssl.pcapng');")
$base/v6-http.cap,$(sql "SELECT count(*), max(frame_number) FROM read_frames('$served/v6-http.cap');")" "
    SELECT filename, count(*), max(frame_number)
    FROM read_frames(['$base/dns.cap.gz', '$base/ldap-ssl.pcapng', '$base/v6-http.cap'], filename := true)
    GROUP BY ALL ORDER BY ALL;"
expect "a URL and a file in one list" "false,38
true,38" "
    SELECT starts_with(filename, 'http://'), count(*)
    FROM read_udp(['$served/dns.cap', '$base/dns.cap'], filename := true, strict := true)
    GROUP BY ALL ORDER BY ALL;"
expect "a URL where a table goes" "38,3706" "SELECT count(*), sum(length) FROM '$base/dns.cap';"

# ---- one partition; filter pushdown; LIMIT ----

# The DEBUG record of a scan says how many partitions it reads the file in and why, and what it
# filters by. scan_record <query over one scan>: the result of the query, and then
# `partitions: N (why)`, followed by `; filter: ...` if the scan has one. The shell says on
# stdout that the logging settings were changed; those lines are dropped.
scan_record() {
    sql "CALL enable_logging(level = 'debug', storage = 'memory');
         $1;
         SELECT message FROM duckdb_logs WHERE type = 'pcapsql' AND message LIKE '%: scanning %';" 2>&1 |
        awk '
            # The notice is coloured, and its last escape sequence starts the first result line.
            { gsub(/\033\[[0-9;]*m/, "") }
            /^[0-9]/ { print; next }
            /: scanning / {
                record = $0
                gsub(/^"|"$/, "", record)
                partitions = record
                sub(/.*: partitions: /, "partitions: ", partitions)
                sub(/\).*/, ")", partitions)
                filter = index(record, "; filter: ")
                print partitions (filter ? substr(record, filter) : "")
            }'
}
split=$(scan_record "SELECT count(*) FROM read_frames('$served/big.pcap')")
case $split in
"$big_frames"$'\n'"partitions: 1 "*) fail "big.pcap on disk should be read in several partitions: $split" ;;
"$big_frames"$'\n'"partitions: "*) ;;
*) fail "no DEBUG record of the scan of big.pcap on disk: $split" ;;
esac
one=$(scan_record "SELECT count(*) FROM read_frames('$base/big.pcap')")
if [ "$one" != "$big_frames"$'\n'"partitions: 1 (a remote file is not indexed)" ]; then
    fail "big.pcap from the URL should be read as one partition: $one"
fi
echo "remote-test: big.pcap: ${split#*$'\n'} on disk, one partition from the URL"

# A scan that stops early asks the server for less than the file holds. What it asks for is
# measured two ways, over the GET requests for big.pcap since line <from> of the log:
#
#   fetched <from>  the bytes the server sent;
#   reach <from>    the end of the furthest byte range asked for (the first byte past it), or
#                   of what was sent for a request without a closed range.
#
# How `httpfs` reads is its business, so the bounds leave it room: frames 1000 to 1009 and the
# first chunk of rows a LIMIT needs are in the first 300 kB, the extension reads a remote file
# 4 MiB at a time (`fs::REMOTE_BUFFER`) and `httpfs` buffers 1 MB on top, and the file is about
# 28 MB. A read that ended early stays well within the first half of it; one that did not end
# early reaches its end. The bytes sent are bounded by the file size only, since bind and scan
# each open the file and nothing says `httpfs` caches what the first open fetched.
big_size=$(wc -c < "$served/big.pcap" | tr -d ' ')
fetched() {
    requests "$1" big.pcap | awk -F '\t' '$1 == "GET" { bytes += $5 } END { print bytes + 0 }'
}
reach() {
    requests "$1" big.pcap | awk -F '\t' '
        $1 == "GET" {
            end = $5
            if (match($3, /^bytes=[0-9]+-[0-9]+$/)) {
                split(substr($3, 7), bounds, "-")
                end = bounds[2] + 1
            } else if (match($3, /^bytes=[0-9]+-$/)) {
                end = substr($3, 7, RLENGTH - 7) + $5
            }
            if (end > furthest) furthest = end
        }
        END { print furthest + 0 }'
}
# ended_early <what> <from>: the GET requests since line <from> stayed in the first half of
# big.pcap and fetched less than all of it.
ended_early() {
    local reached bytes
    reached=$(reach "$2")
    bytes=$(fetched "$2")
    [ "$bytes" -gt 0 ] || fail "$1: nothing of big.pcap was fetched: the request log has no GET for it"
    if [ "$reached" -ge $((big_size / 2)) ]; then
        fail "$1: the read of big.pcap reached byte $reached of $big_size: it did not end early"
    fi
    if [ "$bytes" -ge "$big_size" ]; then
        fail "$1: $bytes bytes of big.pcap were fetched, which has $big_size: the read did not end early"
    fi
    echo "remote-test: $1: fetched $bytes of $big_size bytes of big.pcap, none past byte $reached, in $(requests "$2" big.pcap | awk -F '\t' '$1 == "GET"' | wc -l | tr -d ' ') requests"
}

from=$(log_lines)
pushed=$(scan_record "SELECT count(*), min(frame_number), max(frame_number) FROM read_frames('$base/big.pcap') WHERE frame_number BETWEEN 1000 AND 1009")
if [ "$pushed" != "10,1000,1009"$'\n'"partitions: 1 (a remote file is not indexed); filter: frame_number in [1000, 1009]" ]; then
    fail "a filter on frame_number should be pushed down into the scan of the URL: $pushed"
fi
ended_early "frames 1000 to 1009, pushed down" "$from"
expect "the same filter, not pushed down" "10,1000,1009" "
    SET pcapsql_filter_pushdown = false;
    SELECT count(*), min(frame_number), max(frame_number) FROM read_frames('$base/big.pcap') WHERE frame_number BETWEEN 1000 AND 1009;"
expect "a filter on frame_number over a protocol table" "$(sql "SELECT count(*), sum(src_port) FROM read_tcp('$served/big.pcap') WHERE frame_number > 199000;")" "
    SELECT count(*), sum(src_port) FROM read_tcp('$base/big.pcap') WHERE frame_number > 199000;"
echo "remote-test: big.pcap: frame_number filters agree with the file"

from=$(log_lines)
expect "LIMIT 5" "1
2
3
4
5" "SELECT frame_number FROM read_frames('$base/big.pcap') LIMIT 5;"
# The scan is one partition, so one worker: DuckDB stops calling it once the LIMIT is met, after
# the first chunk of rows.
ended_early "LIMIT 5" "$from"

# ---- errors ----

from=$(log_lines)
missing=$(refused "a URL the server has no file for" "SELECT count(*) FROM read_frames('$base/missing.pcap');")
case $missing in
*"$base/missing.pcap"*) echo "remote-test: 404: ${missing%%$'\n'*}" ;;
*) fail "the error for a missing file does not name the URL: $missing" ;;
esac
[ -n "$(requests "$from" missing.pcap)" ] || fail "the server was not asked for missing.pcap"
missing=$(refused "a missing file among several" "SELECT count(*) FROM read_frames(['$base/dns.cap', '$base/missing.pcap']);")
case $missing in
*"$base/missing.pcap"*) ;;
*) fail "the error for a missing file in a list does not name the URL: $missing" ;;
esac

# With external access off, DuckDB's file system refuses the open, `httpfs` loaded or not: the
# server sees no request.
from=$(log_lines)
denied=$(refused "enable_external_access = false" "SET enable_external_access = false; SELECT count(*) FROM read_frames('$base/dns.cap');")
if [ "$(log_lines)" -ne "$from" ]; then
    fail "enable_external_access = false: the server was asked for: $(tail -n "+$from" "$log")"
fi
echo "remote-test: no external access: ${denied%%$'\n'*}"

# ---- what the server saw ----

for file in "$served"/*; do
    name=$(basename "$file")
    [ -n "$(requests 1 "$name" | awk -F '\t' '$1 == "GET" && $5 > 0')" ] ||
        fail "the server sent nothing of $name: it was not read over HTTP"
done
ranged=$(awk -F '\t' '$4 == 206' "$log" | wc -l | tr -d ' ')
echo "remote-test: $(wc -l < "$log" | tr -d ' ') requests: $(awk -F '\t' '$1 == "HEAD"' "$log" | wc -l | tr -d ' ') HEAD, $ranged answered with a range"
# How `httpfs` fetches a file is its business too.
[ "$ranged" -gt 0 ] || echo "remote-test: NOTE: no request was for a range: httpfs fetched whole files"
echo "remote-test: ok"
