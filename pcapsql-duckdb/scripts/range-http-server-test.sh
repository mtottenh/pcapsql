#!/usr/bin/env bash
# Checks scripts/range-http-server.py with curl: what scripts/remote-test.sh relies on, and can
# be checked without DuckDB's `httpfs`.
#
#   range-http-server-test.sh
#
# Whole files, ranges of every form, HEAD, 404 for what is not a file of the directory, several
# requests over one connection and at once, a client that hangs up, and the request log.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
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

directory=$scratch/served
size=100000
mkdir -p "$directory/sub"
python3 -c "import sys; sys.stdout.buffer.write(bytes(i * 7 % 256 for i in range($size)))" > "$directory/a.bin"
: > "$directory/empty"
echo outside > "$scratch/outside"
echo inside > "$directory/sub/x"

log=$scratch/requests.log
python3 "$here/range-http-server.py" --directory "$directory" --port-file "$scratch/port" --log "$log" &
server_pid=$!
for _ in $(seq 100); do
    [ -s "$scratch/port" ] && break
    sleep 0.1
done
url=http://127.0.0.1:$(cat "$scratch/port")

checks=0
ok() {
    checks=$((checks + 1))
}
fail() {
    echo "range-http-server-test: FAILED: $*" >&2
    exit 1
}
# <count> bytes of a.bin from <offset>.
slice() {
    tail -c "+$(($1 + 1))" "$directory/a.bin" | head -c "$2"
}
status() {
    curl -s -o /dev/null -w '%{http_code}' "$@"
}
headers() {
    curl -s -D - -o /dev/null "$@" | tr -d '\r'
}
# body <what> <offset> <count> <curl arguments>: the body is that slice of a.bin.
body() {
    local what=$1 offset=$2 count=$3
    shift 3
    curl -s "$@" | cmp -s - <(slice "$offset" "$count") || fail "$what: the body is not bytes $offset+$count"
    ok
}
# has <what> <text> <line>...: each line is one of the text's.
has() {
    local what=$1 text=$2 line
    shift 2
    for line in "$@"; do
        grep -qxF "$line" <<<"$text" || fail "$what: no line '$line' in: $text"
    done
    ok
}
is() {
    [ "$2" = "$3" ] || fail "$1: $2, not $3"
    ok
}

# The whole file.
body "GET" 0 $size "$url/a.bin"
has "GET" "$(headers "$url/a.bin")" "HTTP/1.1 200 OK" "Content-Length: $size" "Accept-Ranges: bytes"
body "a query string" 0 10 -r 0-9 "$url/a.bin?version=1"
is "an empty file" "$(status "$url/empty")" 200

# Ranges.
body "bytes=0-0" 0 1 -r 0-0 "$url/a.bin"
body "bytes=10-19" 10 10 -r 10-19 "$url/a.bin"
body "bytes=99990-" 99990 10 -r 99990- "$url/a.bin"
body "a range across a 64 KiB chunk" 65530 16 -r 65530-65545 "$url/a.bin"
body "a last byte past the end" 99990 10 -r 99990-200000 "$url/a.bin"
body "bytes=-25, the last 25" 99975 25 -r -25 "$url/a.bin"
body "a suffix longer than the file" 0 $size -r -200000 "$url/a.bin"
has "bytes=10-19" "$(headers -r 10-19 "$url/a.bin")" \
    "HTTP/1.1 206 Partial Content" "Content-Range: bytes 10-19/$size" "Content-Length: 10" "Accept-Ranges: bytes"
has "bytes=-25" "$(headers -r -25 "$url/a.bin")" "HTTP/1.1 206 Partial Content" "Content-Range: bytes 99975-99999/$size"
has "a range from the end on" "$(headers -r $size- "$url/a.bin")" \
    "HTTP/1.1 416 Range Not Satisfiable" "Content-Range: bytes */$size" "Content-Length: 0"
is "a range of an empty file" "$(status -r 5-9 "$url/empty")" 416
# A Range header that is not one byte range is ignored.
is "a last byte before the first" "$(status -H 'Range: bytes=5-2' "$url/a.bin")" 200
is "two ranges" "$(status -H 'Range: bytes=0-1,5-6' "$url/a.bin")" 200
is "a unit other than bytes" "$(status -H 'Range: lines=0-1' "$url/a.bin")" 200

# HEAD: the headers of the GET and no body.
has "HEAD" "$(headers -I "$url/a.bin")" "HTTP/1.1 200 OK" "Content-Length: $size" "Accept-Ranges: bytes"
has "HEAD of a range" "$(headers -I -r 0-99 "$url/a.bin")" "HTTP/1.1 206 Partial Content" "Content-Length: 100"
[ "$(curl -s -I "$url/a.bin" | wc -c)" -lt 1000 ] || fail "HEAD has a body"
ok

# Only the files of the directory are there.
for path in missing.pcap "" sub sub/x ../outside %2e%2e/outside ..%2foutside a.bin/; do
    is "GET /$path" "$(status --path-as-is "$url/$path")" 404
done
is "HEAD of a missing file" "$(status -I "$url/missing.pcap")" 404
is "POST" "$(status -X POST -d x "$url/a.bin")" 405
is "GET after a POST" "$(status "$url/a.bin")" 200

# Four requests over one connection, one of them a 404.
verbose=$(curl -s -v -r 0-9 "$url/a.bin" -o "$scratch/1" --next -s -v -r 20-29 "$url/a.bin" -o "$scratch/2" \
    --next -s -v "$url/missing.pcap" -o "$scratch/3" --next -s -v -r -5 "$url/a.bin" -o "$scratch/4" 2>&1)
if ! { cmp -s "$scratch/1" <(slice 0 10) && cmp -s "$scratch/2" <(slice 20 10) && cmp -s "$scratch/4" <(slice 99995 5); }; then
    fail "requests over one connection: wrong bodies"
fi
is "requests over one connection: reuses" "$(grep -c 'Re-using existing' <<<"$verbose")" 3

# Twenty at once.
for i in $(seq 20); do
    (curl -s -r "$((i * 1000))-$((i * 1000 + 499))" "$url/a.bin" | cmp -s - <(slice $((i * 1000)) 500) ||
        echo "$i" >> "$scratch/parallel-failures") &
    requests[i]=$!
done
wait "${requests[@]}"
[ ! -e "$scratch/parallel-failures" ] || fail "parallel requests: wrong bodies for $(tr '\n' ' ' < "$scratch/parallel-failures")"
ok

# A client that hangs up in the middle of a body does not stop the server.
python3 - "$url" <<'EOF'
import socket
import sys
import urllib.parse

url = urllib.parse.urlsplit(sys.argv[1])
with socket.create_connection((url.hostname, url.port)) as connection:
    connection.sendall(b"GET /a.bin HTTP/1.1\r\nHost: localhost\r\n\r\n")
    connection.recv(100)
EOF
is "GET after a client hung up" "$(status "$url/a.bin")" 200

# The log: method, path, Range, status, bytes of body sent.
sleep 0.3
awk -F '\t' 'NF != 5 { exit 1 }' "$log" || fail "a line of the log does not have five fields: $(cat "$log")"
has "the log" "$(cat "$log")" \
    "$(printf 'GET\t/a.bin\t-\t200\t%s' $size)" \
    "$(printf 'GET\t/a.bin\tbytes=10-19\t206\t10')" \
    "$(printf 'GET\t/a.bin\tbytes=-25\t206\t25')" \
    "$(printf 'GET\t/a.bin\tbytes=%s-\t416\t0' $size)" \
    "$(printf 'HEAD\t/a.bin\t-\t200\t0')" \
    "$(printf 'HEAD\t/a.bin\tbytes=0-99\t206\t0')" \
    "$(printf 'GET\t/missing.pcap\t-\t404\t0')" \
    "$(printf 'POST\t/a.bin\t-\t405\t0')"

echo "range-http-server-test: ok ($checks checks, $(wc -l < "$log" | tr -d ' ') requests)"
