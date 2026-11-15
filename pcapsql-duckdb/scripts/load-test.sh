#!/usr/bin/env bash
# LOAD the built extension in the stock DuckDB command-line shell and call each kind of function.
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

sql="
LOAD '$extension';
SELECT extension_name, loaded, extension_version FROM duckdb_extensions() WHERE extension_name = 'pcapsql';
SELECT count(*) FROM pcap_protocols();
SELECT name, field_count FROM pcap_protocols() WHERE name = 'frames';
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
"
expected="pcapsql,true,$extension_version
28
frames,5
3232235777,192.168.1.1,true,true
5000,5000
16
2001:db8::1,aa:bb:cc:dd:ee:ff,dead
true,true,true
\"SYN,ACK\",true,AAAA,NXDOMAIN,TCP,IPv4
256,512
192.168.1.1,::1,aa:bb:cc:dd:ee:ff,\"[10.0.0.1, 10.0.0.2]\""

actual=$("$duckdb" -unsigned -csv -noheader -c "$sql")
if [ "$actual" != "$expected" ]; then
    echo "load-test: FAILED" >&2
    diff <(echo "$expected") <(echo "$actual") >&2 || true
    exit 1
fi
echo "$actual"
echo "load-test: ok"
