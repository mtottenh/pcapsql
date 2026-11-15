#!/usr/bin/env bash
# LOAD the built extension in the stock DuckDB command-line shell, call each kind of function and
# read captures.
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

# Captures: small real ones the repository has as seeds of the reader fuzzer, and two made from
# one of them here: a gzip-compressed copy, and a copy cut off inside a record.
captures=$(cd "$here/../../fuzz/corpus/fuzz_pcap_reader" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
gzip -c "$captures/dns.cap" > "$scratch/dns.cap.gz"
head -c 2000 "$captures/dns.cap" > "$scratch/cut.cap"

sql="
LOAD '$extension';
SELECT extension_name, loaded, extension_version FROM duckdb_extensions() WHERE extension_name = 'pcapsql';
SELECT count(*) FROM pcap_protocols();
SELECT name, field_count, kind FROM pcap_protocols() WHERE name = 'frames';
SELECT column_name, column_type, nullable FROM pcap_schema('ethernet') WHERE column_name IN ('timestamp', 'src_mac');
SELECT ip4('192.168.1.1'), ip4_to_string(3232235777), ip4('not an address') IS NULL, ip4_to_string(NULL) IS NULL;
SELECT count(*), count(DISTINCT ip4_to_string(i::UINTEGER)) FROM range(5000) t(i);
SELECT count(*) FROM duckdb_functions() WHERE function_type = 'scalar' AND function_name IN (
    'ip4', 'ip4_to_string', 'ip6', 'ip6_to_string', 'mac', 'mac_to_string', 'ip_in_cidr', 'ip6_in_cidr',
    'tcp_flags_str', 'has_tcp_flag', 'dns_type_name', 'dns_rcode_name', 'ip_proto_name', 'ethertype_name',
    'pcap_hex', 'pcap_unhex');
SELECT ip6_to_string(ip6('2001:db8::1')), mac_to_string(mac('AABBCCDDEEFF')), pcap_hex(pcap_unhex('0xDEAD'));
SELECT ip_in_cidr(ip4('192.168.1.100'), '192.168.0.0/16'), ip6_in_cidr(ip6('fe80::1'), 'fe80::/10'), ip_in_cidr(1, 'bogus') IS NULL;
SELECT tcp_flags_str(18), has_tcp_flag(18, 'syn'), dns_type_name(28), dns_rcode_name(3), ip_proto_name(6), ethertype_name(2048);
SELECT count(*) FILTER (ip_in_cidr(i::UINTEGER, '0.0.1.0/24')), count(DISTINCT tcp_flags_str(i::USMALLINT)) FROM range(5000) t(i);
SELECT format_ip4(3232235777), format_ip6(ip6('::1')), format_mac(mac('AABBCCDDEEFF')), format_ip4_list([ip4('10.0.0.1'), ip4('10.0.0.2')]);
SELECT count(*), sum(length), min(timestamp) FROM read_pcap('$captures/dns.cap');
SELECT frame_number, query_name, format_ip4_list(answer_ip4s), typeof(timestamp) FROM read_dns('$captures/dns.cap') WHERE frame_number = 10;
SELECT frame_number, ip6_to_string(answer_ip6s[1]) FROM read_pcap('$captures/dns.cap', protocol := 'dns') WHERE len(answer_ip6s) > 0;
SELECT count(*), max(encap_depth), max(tunnel_id) FROM read_ethernet('$captures/vxlan_simple.pcap');
SELECT count(*), count(DISTINCT frame_number) FROM read_tcp('$captures/ldap-ssl.pcapng', strict := true);
SELECT count(*), sum(length) FROM read_frames('$scratch/dns.cap.gz', strict := true);
SELECT parse_filename(filename), count(*), max(frame_number) FROM read_frames(['$scratch/dns.cap.gz', '$captures/v6*'], filename := true) GROUP BY ALL ORDER BY ALL;
SELECT frame_number FROM read_udp(['$captures/dns.cap', '$scratch/dns.cap.gz'], strict := true) WHERE frame_number IN (1, 38);
SELECT count(*), sum(length) FROM '$captures/dns.cap';
SELECT count(*) FROM '$scratch/*.cap.gz' WHERE length > 100;
"
expected="pcapsql,true,$extension_version
28
frames,6,frames
timestamp,TIMESTAMP_NS,false
src_mac,BLOB,true
3232235777,192.168.1.1,true,true
5000,5000
16
2001:db8::1,aa:bb:cc:dd:ee:ff,dead
true,true,true
\"SYN,ACK\",true,AAAA,NXDOMAIN,TCP,IPv4
256,512
192.168.1.1,::1,aa:bb:cc:dd:ee:ff,\"[10.0.0.1, 10.0.0.2]\"
38,3706,2005-03-30 08:47:46.496046
10,www.netbsd.org,[204.152.190.12],TIMESTAMP_NS
12,2001:4f8:4:7:2e0:81ff:fe52:9a6b
14,2001:4f8:4:7:2e0:81ff:fe52:9a6b
24,2001:4f8:0:2::d
10,1,200
36,36
38,3706
dns.cap.gz,38,38
v6-http.cap,55,55
v6.pcap,161,161
1
38
1
38
38,3706
11"

actual=$("$duckdb" -unsigned -csv -noheader -c "$sql")
if [ "$actual" != "$expected" ]; then
    echo "load-test: FAILED" >&2
    diff <(echo "$expected") <(echo "$actual") >&2 || true
    exit 1
fi
echo "$actual"

# A capture that ends inside a record: the complete frames and a warning, which the shell shows
# with the result; an error when strict. A scan never ends short in silence.
truncated=$("$duckdb" -unsigned -csv -noheader -c "LOAD '$extension'; SELECT count(*), max(frame_number) FROM read_udp('$scratch/cut.cap');" 2>&1)
case $truncated in
*"is truncated"*"17,17"*) echo "load-test: truncated: 17 complete frames and a warning" ;;
*)
    echo "load-test: FAILED: a truncated capture should return 17 frames with a warning: $truncated" >&2
    exit 1
    ;;
esac
if truncated=$("$duckdb" -unsigned -csv -noheader -c "LOAD '$extension'; SELECT count(*) FROM read_udp('$scratch/cut.cap', strict := true);" 2>&1); then
    echo "load-test: FAILED: a truncated capture was read with strict := true: $truncated" >&2
    exit 1
fi
case $truncated in
*"is truncated"*) echo "load-test: strict: ${truncated%%$'\n'*}" ;;
*)
    echo "load-test: FAILED: unexpected error for a truncated capture: $truncated" >&2
    exit 1
    ;;
esac
# A pattern that matches nothing, and a file among several that is not a capture, are errors
# that name it.
for sql in "SELECT count(*) FROM read_frames('$scratch/*.pcapng')" \
    "SELECT count(*) FROM read_frames(['$captures/dns.cap', '$here/load-test.sh'])"; do
    if refused=$("$duckdb" -unsigned -csv -noheader -c "LOAD '$extension'; $sql;" 2>&1); then
        echo "load-test: FAILED: $sql returned $refused" >&2
        exit 1
    fi
    case $refused in
    *"no file matches the pattern '$scratch/*.pcapng'"* | *"load-test.sh' is not a capture file"*)
        echo "load-test: refused: ${refused%%$'\n'*}"
        ;;
    *)
        echo "load-test: FAILED: unexpected error for $sql: $refused" >&2
        exit 1
        ;;
    esac
done
echo "load-test: ok"
