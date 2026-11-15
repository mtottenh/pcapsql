#!/usr/bin/env bash
# LOAD the built extension in the stock DuckDB command-line shell, call each kind of function,
# read captures and write one.
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
# The generated capture of HTTP/2 over TLS 1.3 and its key log (pcapsql_testgen::tls).
fixtures=$(cd "$here/../../pcapsql-testgen/fixtures" && pwd)
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
    'pcap_hex', 'pcap_unhex', 'icmp_type_name', 'icmp_code_name', 'icmpv6_type_name', 'icmpv6_code_name',
    'dns_class_name', 'dscp_name', 'ecn_name', 'bgp_message_type_name', 'bgp_origin_name',
    'ospf_packet_type_name', 'ospf_lsa_type_name', 'gtp_message_type_name', 'ntp_mode_name',
    'ntp_stratum_name', 'tls_record_type_name', 'tls_version_name', 'is_private_ip', 'is_loopback_ip',
    'is_multicast_ip', 'is_multicast_ip6', 'is_link_local_ip6', 'mac_is_broadcast', 'mac_is_multicast',
    'mac_is_local');
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
SELECT current_setting('pcapsql_filter_pushdown'), count(*), min(frame_number), max(frame_number) FROM read_frames('$scratch/dns.cap.gz') WHERE frame_number > 4 AND frame_number < 10;
SELECT frame_number FROM read_dns('$captures/dns.cap') WHERE timestamp >= TIMESTAMP '2005-03-30 08:47:50' AND timestamp < TIMESTAMP '2005-03-30 08:48:00';
SELECT count(*) FROM read_udp('$scratch/cut.cap', strict := true) WHERE frame_number <= 10;
SELECT count(*), count(*) FILTER (name IN (SELECT name FROM pcap_protocols())) FROM pcap_views();
SELECT name, protocol, column_count FROM pcap_views() WHERE name = 'tcp_packets';
SELECT column_name, column_type, nullable FROM pcap_schema('tcp_packets') WHERE column_name IN ('timestamp', 'src_ip_v4', 'ttl');
SELECT frame_number, ip4_to_string(src_ip_v4), src_port, dst_port, transport, query_name, typeof(timestamp) FROM read_dns_packets('$captures/dns.cap') WHERE frame_number = 1;
SELECT count(*), count(DISTINCT transport), max(src_port) FROM read_pcap('$scratch/dns.cap.gz', protocol := 'dns_packets', strict := true);
SELECT parse_filename(filename), count(*), min(ttl) FROM read_tcp_packets(['$captures/http.pcap', '$captures/v6-http.cap'], filename := true) GROUP BY ALL ORDER BY ALL;
SELECT count(*), min(frame_number), max(frame_number) FROM read_dns_packets('$captures/dns.cap') WHERE frame_number > 4 AND frame_number < 10;
SELECT (SELECT count(*) FROM read_ndp_packets('$captures/v6.pcap')), (SELECT count(*) FROM read_icmpv6('$captures/v6.pcap') WHERE type BETWEEN 133 AND 137);
SELECT name, field_count FROM pcap_protocols() WHERE kind = 'stream' ORDER BY name;
SELECT frame_number, connection_id, client_ip, server_port, state, typeof(start_time) FROM read_tcp_connections('$captures/v6-http.cap', strict := true);
SELECT parse_filename(filename), frame_number, method, status_code FROM read_http_messages(['$captures/http-chunked-gzip.pcap', '$captures/v6-http.cap'], filename := true) WHERE frame_number > 4;
SELECT sni, is_decrypted, (SELECT count(*) FROM read_pcap('$fixtures/tls13_http2.pcap', protocol := 'http2')) FROM read_tls_sessions('$fixtures/tls13_http2.pcap');
SELECT sni, is_decrypted FROM read_tls_sessions('$fixtures/tls13_http2.pcap', keylog := '$fixtures/tls13_http2.keys');
SELECT h.frame_number, h.frame_type, h.method, h.status, c.server_port FROM read_http2('$fixtures/tls13_http2.pcap', keylog := '$fixtures/tls13_http2.keys') h JOIN read_tcp_connections('$fixtures/tls13_http2.pcap') c USING (connection_id) WHERE h.stream_id = 1 ORDER BY h.frame_number;
SELECT version, is_decrypted, (SELECT count(*) FROM read_http2('$fixtures/tls12_http2.pcap', keylog := '$fixtures/tls12_http2.keys')) FROM read_tls_sessions('$fixtures/tls12_http2.pcap', keylog := '$fixtures/tls12_http2.keys');
SELECT frame_number, method, status_code FROM read_http_messages('$fixtures/tls12_http1.pcap', keylog := '$fixtures/tls12_http1.keys');
SET pcapsql_keylog = '$fixtures/tls13_http2.keys';
SELECT count(*), (SELECT is_decrypted FROM read_tls_sessions('$fixtures/tls13_http2.pcap', keylog := '')) FROM read_http2('$fixtures/tls13_http2.pcap');
COPY (SELECT * FROM read_frames('$captures/dns.cap') ORDER BY frame_number) TO '$scratch/copy.pcap' (FORMAT pcap, PRECISION 'us', SNAPLEN 65535);
COPY (SELECT f.* FROM read_frames('$scratch/dns.cap.gz') f JOIN read_dns('$scratch/dns.cap.gz') d USING (frame_number) WHERE d.is_query ORDER BY frame_number) TO '$scratch/queries.pcap';
SELECT count(*), count(*) FILTER (is_query), min(typeof(timestamp)) FROM read_dns('$scratch/queries.pcap');
"
expected="pcapsql,true,$extension_version
32
frames,6,frames
timestamp,TIMESTAMP_NS,false
src_mac,BLOB,true
3232235777,192.168.1.1,true,true
5000,5000
40
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
11
true,5,5,9
3
4
5
6
10
21,0
tcp_packets,tcp,20
timestamp,TIMESTAMP_NS,false
src_ip_v4,UINTEGER,true
ttl,UTINYINT,true
1,192.168.170.8,32795,53,UDP,google.com,TIMESTAMP_NS
38,1,32797
http.pcap,1,128
v6-http.cap,10,64
5,5,9
20,20
http2,34
http_messages,17
tcp_connections,20
tls_sessions,12
46,1,2001:6f8:102d:0:2d0:9ff:fee3:e8de,80,last_ack,TIMESTAMP_NS
http-chunked-gzip.pcap,24,NULL,200
v6-http.cap,49,GET,NULL
v6-http.cap,51,NULL,200
example.test,false,0
example.test,true
10,HEADERS,GET,NULL,443
11,HEADERS,NULL,200,443
12,DATA,NULL,NULL,443
TLS 1.2,true,8
8,GET,NULL
10,NULL,200
8,false
19,19,TIMESTAMP_NS"

actual=$("$duckdb" -unsigned -csv -noheader -c "$sql")
if [ "$actual" != "$expected" ]; then
    echo "load-test: FAILED" >&2
    diff <(echo "$expected") <(echo "$actual") >&2 || true
    exit 1
fi
echo "$actual"

# COPY ... TO (FORMAT pcap): with the unit and the snapshot length of its header, the copy of a
# little-endian microsecond capture is that capture.
if ! cmp -s "$scratch/copy.pcap" "$captures/dns.cap"; then
    echo "load-test: FAILED: the copy of dns.cap is not dns.cap" >&2
    exit 1
fi
echo "load-test: copy: byte-identical to dns.cap"

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
