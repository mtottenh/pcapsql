//! Golden query corpus: cross-phase result-identity guard.
//!
//! Fixed, hand-crafted captures are queried with a corpus covering every
//! populated protocol table plus joins, aggregates, LIMIT, views, list
//! columns, `raw_data`, VLAN and VXLAN encapsulation, the time UDFs, and
//! queries that reference the same table twice. The second capture uses the
//! Linux "cooked" (SLL) link type, as `tcpdump -i any` writes, so the
//! non-Ethernet link-layer path is guarded too; the routing capture pins the
//! full `SELECT *` column set of the routing and tunnel tables. Results are compared
//! byte-for-byte against checked-in snapshots, so any refactor that changes
//! query results — row content, order, types, or formatting — fails loudly.
//!
//! Regenerate snapshots after an *intentional* change with:
//! ```text
//! PCAPSQL_GOLDEN_UPDATE=1 cargo test -p pcapsql-datafusion --test golden_corpus
//! ```
//! and review the diff like any other code change.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use arrow::util::pretty::pretty_format_batches;
use pcapsql_datafusion::query::{EngineOptions, QueryEngine, RetentionPolicy, SourceSpec};
use pcapsql_testgen::{legacy_pcap, GenPacket, LegacyVariant};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Packet crafting (deterministic, byte-exact)
// ---------------------------------------------------------------------------

const MAC_A: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const MAC_B: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const BCAST: [u8; 6] = [0xff; 6];

fn eth(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(14 + payload.len());
    p.extend_from_slice(&dst);
    p.extend_from_slice(&src);
    p.extend_from_slice(&ethertype.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, id: u16, payload: &[u8]) -> Vec<u8> {
    let total = (20 + payload.len()) as u16;
    let mut p = Vec::with_capacity(20 + payload.len());
    p.push(0x45); // version 4, IHL 5
    p.push(0x00); // DSCP/ECN
    p.extend_from_slice(&total.to_be_bytes());
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0x40, 0x00]); // DF
    p.push(64); // ttl
    p.push(proto);
    p.extend_from_slice(&[0x00, 0x00]); // checksum (unverified)
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(payload);
    p
}

fn tcp(sp: u16, dp: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(20 + payload.len());
    p.extend_from_slice(&sp.to_be_bytes());
    p.extend_from_slice(&dp.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&ack.to_be_bytes());
    p.push(0x50); // data offset 5, no options
    p.push(flags);
    p.extend_from_slice(&65535u16.to_be_bytes()); // window
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // checksum, urgent
    p.extend_from_slice(payload);
    p
}

fn udp(sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
    let len = (8 + payload.len()) as u16;
    let mut p = Vec::with_capacity(8 + payload.len());
    p.extend_from_slice(&sp.to_be_bytes());
    p.extend_from_slice(&dp.to_be_bytes());
    p.extend_from_slice(&len.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend_from_slice(payload);
    p
}

/// DNS A query for example.com (id 0x1234, RD).
fn dns_query() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&0x1234u16.to_be_bytes()); // id
    p.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
    p.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // qd=1 an=0 ns=0 ar=0
    p.extend_from_slice(b"\x07example\x03com\x00");
    p.extend_from_slice(&[0, 1, 0, 1]); // QTYPE A, QCLASS IN
    p
}

/// DNS response with one A answer (93.184.216.34, ttl 300).
fn dns_response() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&0x1234u16.to_be_bytes());
    p.extend_from_slice(&0x8180u16.to_be_bytes()); // QR, RD, RA
    p.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]); // qd=1 an=1
    p.extend_from_slice(b"\x07example\x03com\x00");
    p.extend_from_slice(&[0, 1, 0, 1]);
    p.extend_from_slice(&[0xC0, 0x0C]); // name: pointer to offset 12
    p.extend_from_slice(&[0, 1, 0, 1]); // TYPE A, CLASS IN
    p.extend_from_slice(&300u32.to_be_bytes()); // TTL
    p.extend_from_slice(&[0, 4, 93, 184, 216, 34]); // RDLENGTH + RDATA
    p
}

/// ARP request: who-has 10.0.0.2 tell 10.0.0.1.
fn arp_request() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&[0, 1]); // htype ethernet
    p.extend_from_slice(&[0x08, 0x00]); // ptype IPv4
    p.push(6);
    p.push(4);
    p.extend_from_slice(&[0, 1]); // request
    p.extend_from_slice(&MAC_A);
    p.extend_from_slice(&[10, 0, 0, 1]);
    p.extend_from_slice(&[0; 6]);
    p.extend_from_slice(&[10, 0, 0, 2]);
    p
}

/// ICMP echo request (id 1, seq 1).
fn icmp_echo() -> Vec<u8> {
    let mut p = vec![8, 0, 0, 0]; // type 8, code 0, checksum 0
    p.extend_from_slice(&[0, 1, 0, 1]); // id, seq
    p.extend_from_slice(&[0xAB; 8]);
    p
}

fn ipv6(src16: [u8; 16], dst16: [u8; 16], next: u8, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(40 + payload.len());
    p.extend_from_slice(&[0x60, 0, 0, 0]); // version 6
    p.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    p.push(next);
    p.push(64); // hop limit
    p.extend_from_slice(&src16);
    p.extend_from_slice(&dst16);
    p.extend_from_slice(payload);
    p
}

const IP6_A: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const IP6_B: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

const ETH_IP4: u16 = 0x0800;
const ETH_IP6: u16 = 0x86DD;
const ETH_ARP: u16 = 0x0806;
const ETH_VLAN: u16 = 0x8100;

/// 802.1Q tag: priority 3, DEI 0, VLAN id `vid`, followed by the inner
/// ethertype — inserted between the Ethernet header and its payload.
fn vlan_tagged(
    dst: [u8; 6],
    src: [u8; 6],
    vid: u16,
    inner_ethertype: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut tci = Vec::with_capacity(4 + payload.len());
    tci.extend_from_slice(&((3u16 << 13) | (vid & 0x0FFF)).to_be_bytes());
    tci.extend_from_slice(&inner_ethertype.to_be_bytes());
    tci.extend_from_slice(payload);
    eth(dst, src, ETH_VLAN, &tci)
}

/// VXLAN header (flags I, VNI `vni`) wrapping an inner Ethernet frame.
fn vxlan(vni: u32, inner: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(8 + inner.len());
    p.extend_from_slice(&[0x08, 0, 0, 0]); // flags: VNI valid
    p.extend_from_slice(&vni.to_be_bytes()[1..]); // 24-bit VNI
    p.push(0); // reserved
    p.extend_from_slice(inner);
    p
}

/// Linux cooked capture (SLL, LINKTYPE 113) header in front of an L3 payload:
/// packet type, ARPHRD_ETHER, address length 6, 8-byte address, protocol.
fn sll(pkttype: u16, src: [u8; 6], protocol: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(16 + payload.len());
    p.extend_from_slice(&pkttype.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes()); // ARPHRD_ETHER
    p.extend_from_slice(&6u16.to_be_bytes());
    p.extend_from_slice(&src);
    p.extend_from_slice(&[0, 0]); // address padding to 8 bytes
    p.extend_from_slice(&protocol.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

/// Linux cooked capture v2 (SLL2, LINKTYPE 276) header in front of an L3
/// payload: protocol, reserved, interface index, ARPHRD_ETHER, packet type,
/// address length 6, 8-byte address.
fn sll2(pkttype: u8, ifindex: u32, src: [u8; 6], protocol: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(20 + payload.len());
    p.extend_from_slice(&protocol.to_be_bytes());
    p.extend_from_slice(&[0, 0]); // reserved (MBZ)
    p.extend_from_slice(&ifindex.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes()); // ARPHRD_ETHER
    p.push(pkttype);
    p.push(6);
    p.extend_from_slice(&src);
    p.extend_from_slice(&[0, 0]); // address padding to 8 bytes
    p.extend_from_slice(payload);
    p
}

const LINKTYPE_ETHERNET: u16 = 1;
const LINKTYPE_LINUX_SLL: u16 = 113;
const LINKTYPE_LINUX_SLL2: u16 = 276;

fn to_capture(frames: Vec<Vec<u8>>, link_type: u16) -> Vec<u8> {
    let packets: Vec<GenPacket> = frames
        .into_iter()
        .enumerate()
        .map(|(i, data)| {
            let origlen = data.len() as u32;
            GenPacket {
                ts_sec: 1_700_000_000 + i as u32,
                ts_frac: (i as u32) * 1_000,
                data,
                origlen,
            }
        })
        .collect();
    legacy_pcap(LegacyVariant::LeMicro, link_type, 65535, &packets).bytes
}

/// The Linux SLL corpus capture: 3 frames (DNS query, TCP SYN, ICMP echo)
/// under a cooked-capture header instead of Ethernet.
fn sll_capture() -> Vec<u8> {
    let a = [10, 0, 0, 1];
    let b = [10, 0, 0, 2];
    let frames: Vec<Vec<u8>> = vec![
        // 1: DNS query a -> 8.8.8.8 (outgoing)
        sll(
            4,
            MAC_A,
            ETH_IP4,
            &ipv4(a, [8, 8, 8, 8], 17, 1, &udp(40000, 53, &dns_query())),
        ),
        // 2: TCP SYN a:40001 -> b:443 (outgoing)
        sll(
            4,
            MAC_A,
            ETH_IP4,
            &ipv4(a, b, 6, 2, &tcp(40001, 443, 5000, 0, 0x02, &[])),
        ),
        // 3: ICMP echo request, received (packet type 0 = to us)
        sll(0, MAC_B, ETH_IP4, &ipv4(b, a, 1, 3, &icmp_echo())),
    ];
    to_capture(frames, LINKTYPE_LINUX_SLL)
}

/// The Linux SLL2 corpus capture: 4 frames (DNS query, TCP SYN, ICMP echo,
/// IPv6 TCP SYN) under the v2 cooked-capture header, spread over two
/// interface indexes the way `tcpdump -i any` records them.
fn sll2_capture() -> Vec<u8> {
    let a = [10, 0, 0, 1];
    let b = [10, 0, 0, 2];
    let frames: Vec<Vec<u8>> = vec![
        // 1: DNS query a -> 8.8.8.8, outgoing on interface 2
        sll2(
            4,
            2,
            MAC_A,
            ETH_IP4,
            &ipv4(a, [8, 8, 8, 8], 17, 1, &udp(40000, 53, &dns_query())),
        ),
        // 2: TCP SYN a:40001 -> b:443, outgoing on interface 2
        sll2(
            4,
            2,
            MAC_A,
            ETH_IP4,
            &ipv4(a, b, 6, 2, &tcp(40001, 443, 5000, 0, 0x02, &[])),
        ),
        // 3: ICMP echo request, received on interface 3
        sll2(0, 3, MAC_B, ETH_IP4, &ipv4(b, a, 1, 3, &icmp_echo())),
        // 4: IPv6 TCP SYN, received on interface 3
        sll2(
            0,
            3,
            MAC_B,
            ETH_IP6,
            &ipv6(IP6_B, IP6_A, 6, &tcp(50000, 22, 7000, 0, 0x02, &[])),
        ),
    ];
    to_capture(frames, LINKTYPE_LINUX_SLL2)
}

/// A TLS record (type 0x16 handshake, record version `rec_version`) wrapping
/// one handshake message of type `hs_type`.
fn tls_handshake_record(rec_version: u16, hs_type: u8, body: &[u8]) -> Vec<u8> {
    let mut hs = vec![hs_type];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(body);
    let mut rec = vec![0x16];
    rec.extend_from_slice(&rec_version.to_be_bytes());
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// ClientHello offering TLS_AES_128_GCM_SHA256 / TLS_AES_256_GCM_SHA384 with
/// SNI and ALPN extensions.
fn client_hello(sni: &str, alpn: &str) -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x11; 32]); // random
    body.push(0); // session id
    body.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]); // cipher suites
    body.extend_from_slice(&[0x01, 0x00]); // compression: null
    let mut exts = Vec::new();
    // server_name: list(len) -> type 0, name(len), name
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&((sni.len() + 3) as u16).to_be_bytes());
    sni_ext.push(0);
    sni_ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(sni.as_bytes());
    exts.extend_from_slice(&[0x00, 0x00]);
    exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sni_ext);
    // application_layer_protocol_negotiation: list(len) -> proto(len), proto
    let mut alpn_ext = Vec::new();
    alpn_ext.extend_from_slice(&((alpn.len() + 1) as u16).to_be_bytes());
    alpn_ext.push(alpn.len() as u8);
    alpn_ext.extend_from_slice(alpn.as_bytes());
    exts.extend_from_slice(&[0x00, 0x10]);
    exts.extend_from_slice(&(alpn_ext.len() as u16).to_be_bytes());
    exts.extend_from_slice(&alpn_ext);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    tls_handshake_record(0x0301, 0x01, &body)
}

/// ServerHello selecting `cipher`, negotiating TLS 1.3 through the
/// supported_versions extension (legacy version field stays 0x0303).
fn server_hello(cipher: u16) -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x22; 32]); // random
    body.push(0); // session id
    body.extend_from_slice(&cipher.to_be_bytes());
    body.push(0); // compression: null
    body.extend_from_slice(&[0x00, 0x06, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]); // supported_versions: 1.3
    tls_handshake_record(0x0303, 0x02, &body)
}

/// Pad every frame to the 60-byte Ethernet minimum the way a NIC or SPAN
/// port does; the padding is not IP payload and must not reach reassembly.
fn pad_frames(frames: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    frames
        .into_iter()
        .map(|mut f| {
            if f.len() < 60 {
                f.resize(60, 0);
            }
            f
        })
        .collect()
}

const HTTP_REQUEST: &[u8] = b"GET /index.html HTTP/1.1\r\nHost: example.test\r\n\
User-Agent: pcapsql-corpus/1.0\r\nAccept: text/plain\r\n\r\n";
const HTTP_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nServer: corpus\r\nContent-Type: text/plain\r\n\
Content-Length: 5\r\n\r\nhello";

/// The stream-analysis corpus capture: a complete HTTP/1.1 exchange on port
/// 80 (handshake, request, response, orderly close) followed by a TLS
/// handshake on port 443 (ClientHello with SNI/ALPN, ServerHello) that the
/// client resets. Exercises TCP reassembly, `tcp_connections`,
/// `http_messages` and `tls_sessions` without a keylog.
fn http_capture() -> Vec<u8> {
    to_capture(http_frames(), LINKTYPE_ETHERNET)
}

/// `http_capture()` with every frame padded to the Ethernet minimum.
fn padded_http_capture() -> Vec<u8> {
    to_capture(pad_frames(http_frames()), LINKTYPE_ETHERNET)
}

fn http_frames() -> Vec<Vec<u8>> {
    let a = [10, 0, 0, 1];
    let b = [10, 0, 0, 2];
    let seg = |src: [u8; 4], dst: [u8; 4], id: u16, tcp_bytes: Vec<u8>| -> Vec<u8> {
        let (smac, dmac) = if src == a {
            (MAC_A, MAC_B)
        } else {
            (MAC_B, MAC_A)
        };
        eth(dmac, smac, ETH_IP4, &ipv4(src, dst, 6, id, &tcp_bytes))
    };
    let req_len = HTTP_REQUEST.len() as u32;
    let resp_len = HTTP_RESPONSE.len() as u32;
    let ch = client_hello("example.test", "h2");
    let sh = server_hello(0x1301);
    let ch_len = ch.len() as u32;
    let frames: Vec<Vec<u8>> = vec![
        // --- HTTP/1.1: a:40002 -> b:80 ---
        // 1 SYN, 2 SYN-ACK, 3 ACK
        seg(a, b, 1, tcp(40002, 80, 1000, 0, 0x02, &[])),
        seg(b, a, 2, tcp(80, 40002, 5000, 1001, 0x12, &[])),
        seg(a, b, 3, tcp(40002, 80, 1001, 5001, 0x10, &[])),
        // 4 request, 5 response
        seg(a, b, 4, tcp(40002, 80, 1001, 5001, 0x18, HTTP_REQUEST)),
        seg(
            b,
            a,
            5,
            tcp(80, 40002, 5001, 1001 + req_len, 0x18, HTTP_RESPONSE),
        ),
        // 6 FIN-ACK client, 7 FIN-ACK server, 8 final ACK
        seg(
            a,
            b,
            6,
            tcp(40002, 80, 1001 + req_len, 5001 + resp_len, 0x11, &[]),
        ),
        seg(
            b,
            a,
            7,
            tcp(80, 40002, 5001 + resp_len, 1002 + req_len, 0x11, &[]),
        ),
        seg(
            a,
            b,
            8,
            tcp(40002, 80, 1002 + req_len, 5002 + resp_len, 0x10, &[]),
        ),
        // --- TLS: a:40003 -> b:443 ---
        // 9 SYN, 10 SYN-ACK, 11 ACK
        seg(a, b, 9, tcp(40003, 443, 2000, 0, 0x02, &[])),
        seg(b, a, 10, tcp(443, 40003, 7000, 2001, 0x12, &[])),
        seg(a, b, 11, tcp(40003, 443, 2001, 7001, 0x10, &[])),
        // 12 ClientHello, 13 ServerHello, 14 RST from the client
        seg(a, b, 12, tcp(40003, 443, 2001, 7001, 0x18, &ch)),
        seg(b, a, 13, tcp(443, 40003, 7001, 2001 + ch_len, 0x18, &sh)),
        seg(a, b, 14, tcp(40003, 443, 2001 + ch_len, 7001, 0x14, &[])),
    ];
    frames
}

// ---------------------------------------------------------------------------
// Routing / tunnel capture: BGP, OSPF, GTP and IPv6 extension headers. Each
// table's `SELECT *` snapshot pins every column.
// ---------------------------------------------------------------------------

/// A BGP message: 16-byte marker, length, type, body.
fn bgp_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut m = vec![0xff; 16];
    m.extend_from_slice(&((19 + body.len()) as u16).to_be_bytes());
    m.push(msg_type);
    m.extend_from_slice(body);
    m
}

/// OPEN from AS 4200000001 (AS_TRANS in the 2-byte field, the real AS in the
/// 4-byte-AS capability) with MULTIPROTOCOL and ROUTE_REFRESH capabilities.
fn bgp_open() -> Vec<u8> {
    let caps: &[u8] = &[
        1, 4, 0, 1, 0, 1, // MULTIPROTOCOL: AFI 1 (IPv4), SAFI 1 (unicast)
        2, 0, // ROUTE_REFRESH
        65, 4, 0xfa, 0x56, 0xea, 0x01, // 4-BYTE-AS: 4200000001
    ];
    let mut body = vec![4]; // version
    body.extend_from_slice(&23456u16.to_be_bytes()); // my AS: AS_TRANS
    body.extend_from_slice(&90u16.to_be_bytes()); // hold time
    body.extend_from_slice(&[10, 1, 0, 1]); // BGP identifier
    body.push((caps.len() + 2) as u8); // optional parameters length
    body.push(2); // parameter type: capabilities
    body.push(caps.len() as u8);
    body.extend_from_slice(caps);
    bgp_message(1, &body)
}

fn bgp_path_attr(flags: u8, type_code: u8, value: &[u8]) -> Vec<u8> {
    let mut a = vec![flags, type_code, value.len() as u8];
    a.extend_from_slice(value);
    a
}

/// UPDATE withdrawing two prefixes and announcing two with every path
/// attribute the parser decodes.
fn bgp_update() -> Vec<u8> {
    let withdrawn: &[u8] = &[24, 192, 0, 2, 16, 198, 51]; // 192.0.2.0/24, 198.51.0.0/16
    let mut attrs = Vec::new();
    attrs.extend(bgp_path_attr(0x40, 1, &[0])); // ORIGIN: IGP
                                                // AS_PATH: AS_SEQUENCE of 65002 65003 65004 (2-byte ASNs)
    attrs.extend(bgp_path_attr(
        0x40,
        2,
        &[2, 3, 0xfd, 0xea, 0xfd, 0xeb, 0xfd, 0xec],
    ));
    attrs.extend(bgp_path_attr(0x40, 3, &[10, 1, 0, 2])); // NEXT_HOP
    attrs.extend(bgp_path_attr(0x80, 4, &100u32.to_be_bytes())); // MULTI_EXIT_DISC
    attrs.extend(bgp_path_attr(0x40, 5, &200u32.to_be_bytes())); // LOCAL_PREF
    attrs.extend(bgp_path_attr(0x40, 6, &[])); // ATOMIC_AGGREGATE
    attrs.extend(bgp_path_attr(0xc0, 7, &[0xfd, 0xea, 10, 1, 0, 2])); // AGGREGATOR: AS 65002, 10.1.0.2
    let nlri: &[u8] = &[24, 203, 0, 113, 25, 198, 51, 100, 0]; // 203.0.113.0/24, 198.51.100.0/25
    let mut body = Vec::new();
    body.extend_from_slice(&(withdrawn.len() as u16).to_be_bytes());
    body.extend_from_slice(withdrawn);
    body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    body.extend_from_slice(&attrs);
    body.extend_from_slice(nlri);
    bgp_message(2, &body)
}

/// An OSPFv2 packet: 24-byte header (checksum left zero, null authentication)
/// and the type-specific body.
fn ospf_packet(ptype: u8, router_id: [u8; 4], body: &[u8]) -> Vec<u8> {
    let mut p = vec![2, ptype];
    p.extend_from_slice(&((24 + body.len()) as u16).to_be_bytes());
    p.extend_from_slice(&router_id);
    p.extend_from_slice(&[0, 0, 0, 1]); // area 0.0.0.1
    p.extend_from_slice(&[0, 0]); // checksum
    p.extend_from_slice(&[0, 0]); // AuType: null
    p.extend_from_slice(&[0; 8]); // authentication
    p.extend_from_slice(body);
    p
}

/// A 20-byte LSA header.
fn ospf_lsa_header(
    age: u16,
    ls_type: u8,
    ls_id: [u8; 4],
    adv: [u8; 4],
    seq: u32,
    len: u16,
) -> Vec<u8> {
    let mut h = age.to_be_bytes().to_vec();
    h.push(0x02); // options: E
    h.push(ls_type);
    h.extend_from_slice(&ls_id);
    h.extend_from_slice(&adv);
    h.extend_from_slice(&seq.to_be_bytes());
    h.extend_from_slice(&[0, 0]); // checksum
    h.extend_from_slice(&len.to_be_bytes());
    h
}

/// Hello with two neighbours.
fn ospf_hello(router_id: [u8; 4]) -> Vec<u8> {
    let mut body = vec![255, 255, 255, 0]; // network mask
    body.extend_from_slice(&10u16.to_be_bytes()); // hello interval
    body.push(0x02); // options: E
    body.push(1); // router priority
    body.extend_from_slice(&40u32.to_be_bytes()); // dead interval
    body.extend_from_slice(&[10, 2, 0, 1]); // DR
    body.extend_from_slice(&[10, 2, 0, 2]); // BDR
    body.extend_from_slice(&[10, 2, 0, 2]); // neighbour
    body.extend_from_slice(&[10, 2, 0, 3]); // neighbour
    ospf_packet(1, router_id, &body)
}

/// Database Description carrying one LSA header.
fn ospf_dd(router_id: [u8; 4]) -> Vec<u8> {
    let mut body = 1500u16.to_be_bytes().to_vec(); // interface MTU
    body.push(0x42); // options: O, E
    body.push(0x07); // flags: I, M, MS
    body.extend_from_slice(&0x0000_1234u32.to_be_bytes()); // DD sequence
    body.extend(ospf_lsa_header(
        1,
        1,
        [10, 2, 0, 2],
        [10, 2, 0, 2],
        0x8000_0001,
        36,
    ));
    ospf_packet(2, router_id, &body)
}

/// Link State Update with one Router-LSA (header plus a minimal body).
fn ospf_lsu(router_id: [u8; 4]) -> Vec<u8> {
    let mut body = 1u32.to_be_bytes().to_vec(); // number of LSAs
    body.extend(ospf_lsa_header(5, 1, router_id, router_id, 0x8000_0002, 36));
    body.extend_from_slice(&[0x02, 0x00, 0x00, 0x01]); // flags, 1 link
    body.extend_from_slice(&[10, 2, 0, 0, 255, 255, 255, 0, 3, 0, 0, 10]); // stub link
    ospf_packet(4, router_id, &body)
}

/// Link State Acknowledgment of two LSA headers.
fn ospf_lsack(router_id: [u8; 4]) -> Vec<u8> {
    let mut body = ospf_lsa_header(5, 1, [10, 2, 0, 1], [10, 2, 0, 1], 0x8000_0002, 36);
    body.extend(ospf_lsa_header(
        7,
        2,
        [10, 2, 0, 1],
        [10, 2, 0, 1],
        0x8000_0003,
        32,
    ));
    ospf_packet(5, router_id, &body)
}

/// GTPv1-U G-PDU with sequence number, N-PDU number and two extension
/// headers (PDU Session Container, UDP Port) in front of `inner`.
fn gtpv1_gpdu(teid: u32, inner: &[u8]) -> Vec<u8> {
    let ext: &[u8] = &[
        1, 0x10, 0x00, 0x40, // PDU Session Container (4 bytes), next: UDP Port
        1, 0x1f, 0x90, 0x00, // UDP Port 8080, next: none
    ];
    let mut p = vec![0x37, 0xff]; // v1, PT=1, E, S, PN; G-PDU
    p.extend_from_slice(&((4 + ext.len() + inner.len()) as u16).to_be_bytes());
    p.extend_from_slice(&teid.to_be_bytes());
    p.extend_from_slice(&7u16.to_be_bytes()); // sequence
    p.push(42); // N-PDU number
    p.push(0x85); // next extension header: PDU Session Container
    p.extend_from_slice(ext);
    p.extend_from_slice(inner);
    p
}

/// GTPv2-C header with no IEs: T flag set, P flag as given.
fn gtpv2(piggyback: bool, msg_type: u8, teid: u32, seq: u32) -> Vec<u8> {
    let mut p = vec![0x48 | if piggyback { 0x10 } else { 0 }, msg_type];
    p.extend_from_slice(&8u16.to_be_bytes()); // length: TEID + sequence/spare
    p.extend_from_slice(&teid.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes()[1..]); // 24-bit sequence
    p.push(0); // spare
    p
}

/// Hop-by-Hop (PadN), Type 2 Routing (RFC 6275: Hdr Ext Len 2, one segment
/// left, a 16-byte home address) and Fragment (first fragment, more to
/// follow) extension headers in front of a UDP payload.
fn ipv6_ext_chain(udp_payload: &[u8]) -> Vec<u8> {
    let mut p = vec![43, 0, 1, 4, 0, 0, 0, 0]; // Hop-by-Hop -> Routing
    p.extend_from_slice(&[44, 2, 2, 1, 0, 0, 0, 0]); // Routing type 2, 1 left -> Fragment
    p.extend_from_slice(&IP6_A); // home address
    p.extend_from_slice(&[17, 0, 0x00, 0x01]); // Fragment -> UDP; offset 0, M=1
    p.extend_from_slice(&0xbeefu32.to_be_bytes()); // identification
    p.extend_from_slice(udp_payload);
    p
}

/// Routing and tunnelling protocols on an Ethernet link. Frames are grouped
/// by protocol, each group appended after the previous ones, so a table's
/// `SELECT *` snapshot does not move when another protocol's frames are added.
fn routing_capture() -> Vec<u8> {
    let a = [10, 1, 0, 1];
    let b = [10, 1, 0, 2];
    let g1 = [10, 3, 0, 1];
    let g2 = [10, 3, 0, 2];
    let inner = ipv4(
        [192, 168, 1, 1],
        [192, 168, 1, 2],
        17,
        7,
        &udp(5000, 6000, &[0x44; 4]),
    );
    let gtp = |id: u16, sp: u16, dp: u16, msg: &[u8]| {
        eth(
            MAC_B,
            MAC_A,
            ETH_IP4,
            &ipv4(g1, g2, 17, id, &udp(sp, dp, msg)),
        )
    };
    let r1 = [10, 2, 0, 1];
    let ospf = |id: u16, pkt: &[u8]| {
        eth(
            [0x01, 0x00, 0x5e, 0x00, 0x00, 0x05],
            MAC_A,
            ETH_IP4,
            &ipv4(r1, [224, 0, 0, 5], 89, id, pkt),
        )
    };
    let bgp = |src: [u8; 4], dst: [u8; 4], id: u16, sp: u16, dp: u16, msg: &[u8]| {
        let seg = tcp(sp, dp, 1000 + u32::from(id), 1, 0x18, msg);
        eth(MAC_B, MAC_A, ETH_IP4, &ipv4(src, dst, 6, id, &seg))
    };
    let frames: Vec<Vec<u8>> = vec![
        // 1: BGP OPEN a -> b
        bgp(a, b, 1, 40179, 179, &bgp_open()),
        // 2: BGP KEEPALIVE b -> a
        bgp(b, a, 2, 179, 40179, &bgp_message(4, &[])),
        // 3: BGP UPDATE b -> a
        bgp(b, a, 3, 179, 40179, &bgp_update()),
        // 4: BGP NOTIFICATION a -> b: Cease / Administrative Shutdown
        bgp(a, b, 4, 40179, 179, &bgp_message(3, &[6, 2])),
        // 5: BGP ROUTE-REFRESH a -> b: IPv4 unicast
        bgp(a, b, 5, 40179, 179, &bgp_message(5, &[0, 1, 0, 1])),
        // 6-9: OSPF Hello, Database Description, Link State Update and
        // Acknowledgment from router 10.2.0.1 to AllSPFRouters.
        ospf(6, &ospf_hello(r1)),
        ospf(7, &ospf_dd(r1)),
        ospf(8, &ospf_lsu(r1)),
        ospf(9, &ospf_lsack(r1)),
        // 10: GTPv1-U G-PDU (sequence, N-PDU, extension headers) carrying an
        // IPv4/UDP packet; 11-12: GTPv2-C Create Session Request / Response,
        // the response flagged as piggybacked.
        gtp(10, 2152, 2152, &gtpv1_gpdu(0x1001, &inner)),
        gtp(11, 2123, 2123, &gtpv2(false, 32, 0, 1)),
        gtp(12, 2123, 2123, &gtpv2(true, 33, 0x2000, 1)),
        // 13: IPv6 with Hop-by-Hop, Routing and Fragment extension headers;
        // 14: IPv6 without extension headers.
        eth(
            MAC_B,
            MAC_A,
            ETH_IP6,
            &ipv6(
                IP6_A,
                IP6_B,
                0,
                &ipv6_ext_chain(&udp(1024, 2048, &[0x66; 4])),
            ),
        ),
        eth(
            MAC_A,
            MAC_B,
            ETH_IP6,
            &ipv6(IP6_B, IP6_A, 17, &udp(2048, 1024, &[0x77; 4])),
        ),
    ];
    to_capture(frames, LINKTYPE_ETHERNET)
}

/// Tunnelled traffic whose inner and outer transports differ, so a view that
/// paired layers across encapsulation levels would show: VXLAN carrying TCP,
/// GTP-U carrying ICMP, IP-in-IP carrying UDP, VXLAN carrying ARP, and one
/// untunnelled TCP frame as the control.
fn tunnels_capture() -> Vec<u8> {
    let a = [10, 5, 0, 1];
    let b = [10, 5, 0, 2];
    let in_a = [192, 168, 7, 1];
    let in_b = [192, 168, 7, 2];
    let inner_eth = |ethertype: u16, payload: &[u8]| {
        eth(
            [0x02, 0, 0, 0, 0, 0x77],
            [0x02, 0, 0, 0, 0, 0x88],
            ethertype,
            payload,
        )
    };
    let frames: Vec<Vec<u8>> = vec![
        // 1: VXLAN (VNI 7) a:49152 -> b:4789 carrying Ethernet/IPv4/TCP
        //    192.168.7.1:40000 -> 192.168.7.2:443 SYN
        eth(
            MAC_B,
            MAC_A,
            ETH_IP4,
            &ipv4(
                a,
                b,
                17,
                1,
                &udp(
                    49152,
                    4789,
                    &vxlan(
                        7,
                        &inner_eth(
                            ETH_IP4,
                            &ipv4(in_a, in_b, 6, 1, &tcp(40000, 443, 500, 0, 0x02, &[])),
                        ),
                    ),
                ),
            ),
        ),
        // 2: GTP-U (TEID 0x1001) a:2152 -> b:2152 carrying IPv4/ICMP echo
        //    192.168.7.1 -> 192.168.7.2
        eth(
            MAC_B,
            MAC_A,
            ETH_IP4,
            &ipv4(
                a,
                b,
                17,
                2,
                &udp(
                    2152,
                    2152,
                    &gtpv1_gpdu(0x1001, &ipv4(in_a, in_b, 1, 2, &icmp_echo())),
                ),
            ),
        ),
        // 3: IP-in-IP (protocol 4) a -> b carrying IPv4/UDP
        //    192.168.7.1:5000 -> 192.168.7.2:6000
        eth(
            MAC_B,
            MAC_A,
            ETH_IP4,
            &ipv4(
                a,
                b,
                4,
                3,
                &ipv4(in_a, in_b, 17, 3, &udp(5000, 6000, &[0x55; 4])),
            ),
        ),
        // 4: VXLAN (VNI 8) a:49153 -> b:4789 carrying Ethernet/ARP request
        eth(
            MAC_B,
            MAC_A,
            ETH_IP4,
            &ipv4(
                a,
                b,
                17,
                4,
                &udp(49153, 4789, &vxlan(8, &inner_eth(ETH_ARP, &arp_request()))),
            ),
        ),
        // 5: plain TCP a:40001 -> b:80 SYN (control: one level)
        eth(
            MAC_B,
            MAC_A,
            ETH_IP4,
            &ipv4(a, b, 6, 5, &tcp(40001, 80, 900, 0, 0x02, &[])),
        ),
    ];
    to_capture(frames, LINKTYPE_ETHERNET)
}

/// The fixed Ethernet corpus capture: 11 frames covering
/// tcp/udp/dns/arp/icmp/ipv6 plus one VLAN-tagged and one VXLAN-encapsulated
/// frame (the latter carries an inner Ethernet/IPv4/UDP frame).
fn corpus_capture() -> Vec<u8> {
    let a = [10, 0, 0, 1];
    let b = [10, 0, 0, 2];
    let frames: Vec<Vec<u8>> = vec![
        // 1: TCP SYN a:40000 -> b:80
        eth(
            MAC_B,
            MAC_A,
            ETH_IP4,
            &ipv4(a, b, 6, 1, &tcp(40000, 80, 1000, 0, 0x02, &[])),
        ),
        // 2: TCP SYN+ACK back
        eth(
            MAC_A,
            MAC_B,
            ETH_IP4,
            &ipv4(b, a, 6, 2, &tcp(80, 40000, 7000, 1001, 0x12, &[])),
        ),
        // 3: TCP PSH+ACK with payload
        eth(
            MAC_B,
            MAC_A,
            ETH_IP4,
            &ipv4(
                a,
                b,
                6,
                3,
                &tcp(40000, 80, 1001, 7001, 0x18, b"hello pcapsql"),
            ),
        ),
        // 4: DNS query a -> 8.8.8.8
        eth(
            MAC_B,
            MAC_A,
            ETH_IP4,
            &ipv4(a, [8, 8, 8, 8], 17, 4, &udp(33333, 53, &dns_query())),
        ),
        // 5: DNS response back
        eth(
            MAC_A,
            MAC_B,
            ETH_IP4,
            &ipv4([8, 8, 8, 8], a, 17, 5, &udp(53, 33333, &dns_response())),
        ),
        // 6: ARP request (broadcast)
        eth(BCAST, MAC_A, ETH_ARP, &arp_request()),
        // 7: ICMP echo request
        eth(MAC_B, MAC_A, ETH_IP4, &ipv4(a, b, 1, 6, &icmp_echo())),
        // 8: IPv6 UDP
        eth(
            MAC_B,
            MAC_A,
            ETH_IP6,
            &ipv6(IP6_A, IP6_B, 17, &udp(1024, 2048, &[0x11; 4])),
        ),
        // 9: TCP FIN+ACK
        eth(
            MAC_B,
            MAC_A,
            ETH_IP4,
            &ipv4(a, b, 6, 7, &tcp(40000, 80, 1014, 7001, 0x11, &[])),
        ),
        // 10: VLAN 100 tagged IPv4/UDP a:5000 -> b:6000
        vlan_tagged(
            MAC_B,
            MAC_A,
            100,
            ETH_IP4,
            &ipv4(a, b, 17, 8, &udp(5000, 6000, &[0x22; 6])),
        ),
        // 11: VXLAN (VNI 42) a:49152 -> b:4789 carrying inner Ethernet/IPv4/UDP
        //     192.168.1.1:7000 -> 192.168.1.2:8000
        eth(
            MAC_B,
            MAC_A,
            ETH_IP4,
            &ipv4(
                a,
                b,
                17,
                9,
                &udp(
                    49152,
                    4789,
                    &vxlan(
                        42,
                        &eth(
                            [0x02, 0, 0, 0, 0, 0x11],
                            [0x02, 0, 0, 0, 0, 0x22],
                            ETH_IP4,
                            &ipv4(
                                [192, 168, 1, 1],
                                [192, 168, 1, 2],
                                17,
                                1,
                                &udp(7000, 8000, &[0x33; 4]),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    ];
    to_capture(frames, LINKTYPE_ETHERNET)
}

// ---------------------------------------------------------------------------
// The corpus
// ---------------------------------------------------------------------------

/// Which corpus capture a query runs against.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Capture {
    /// `corpus_capture()`: Ethernet link type.
    Eth,
    /// `sll_capture()`: Linux cooked (SLL) link type.
    Sll,
    /// `sll2_capture()`: Linux cooked v2 (SLL2) link type.
    Sll2,
    /// `http_capture()`: reassembled HTTP/1.1 and TLS streams.
    Http,
    /// `routing_capture()`: BGP, OSPF, GTP, IPv6 extension headers.
    Routing,
    /// `tunnels_capture()`: tunnels whose inner and outer transports differ.
    Tunnels,
}

/// (capture, snapshot name, SQL). Every query is fully ordered so output is
/// stable.
const CORPUS: &[(Capture, &str, &str)] = &[
    (
        Capture::Eth,
        "q01_frames",
        "SELECT frame_number, length, original_length, link_type \
         FROM frames ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q02_count",
        "SELECT count(*) AS frames FROM frames",
    ),
    (
        Capture::Eth,
        "q03_ethernet",
        "SELECT frame_number, ethertype FROM ethernet ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q04_ipv4",
        "SELECT frame_number, src_ip, dst_ip, protocol, ttl \
         FROM ipv4 ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q05_tcp",
        "SELECT frame_number, src_port, dst_port, flag_syn, flag_ack, flag_fin \
         FROM tcp ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q06_udp",
        "SELECT frame_number, src_port, dst_port, length \
         FROM udp ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q07_dns",
        "SELECT frame_number, query_name, is_query, answer_count \
         FROM dns ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q08_arp",
        "SELECT frame_number, operation, sender_ip, target_ip \
         FROM arp ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q09_icmp",
        "SELECT frame_number, \"type\", code FROM icmp ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q10_ipv6",
        "SELECT frame_number, next_header, hop_limit FROM ipv6 ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q11_join",
        "SELECT f.frame_number, t.src_port, t.dst_port \
         FROM frames f JOIN tcp t USING (frame_number) ORDER BY f.frame_number",
    ),
    (
        Capture::Eth,
        "q12_agg",
        "SELECT protocol, count(*) AS n FROM ipv4 GROUP BY protocol ORDER BY protocol",
    ),
    (
        Capture::Eth,
        "q13_limit",
        "SELECT frame_number FROM frames ORDER BY frame_number LIMIT 3",
    ),
    (
        Capture::Eth,
        "q14_raw_hex",
        "SELECT frame_number, length(hex(raw_data)) / 2 AS len, \
         substr(hex(raw_data), 1, 24) AS eth_header_prefix \
         FROM frames ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q15_timestamp",
        "SELECT frame_number, timestamp FROM frames ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q16_tcp_packets_view",
        "SELECT frame_number, src_ip_v4, dst_ip_v4, src_port, dst_port \
         FROM tcp_packets ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q17_dns_answers",
        "SELECT frame_number, answer_ip4s, answer_ttls \
         FROM dns WHERE answer_count > 0 ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q18_where",
        "SELECT frame_number FROM tcp WHERE dst_port = 80 ORDER BY frame_number",
    ),
    // --- encapsulation: a parse that prunes or stops early loses these rows ---
    (
        Capture::Eth,
        "q19_vlan",
        "SELECT frame_number, vlan_id, priority, inner_ethertype \
         FROM vlan ORDER BY frame_number",
    ),
    // Views pair layers of one encapsulation level: the VXLAN frame is two
    // UDP rows (outer tunnel, inner payload), each with its own addresses.
    (
        Capture::Eth,
        "q26_udp_packets_vxlan_levels",
        "SELECT frame_number, src_mac, src_ip_v4, dst_ip_v4, src_port, dst_port, \
         encap_depth, tunnel_type FROM udp_packets WHERE frame_number = 11 ORDER BY encap_depth",
    ),
    (
        Capture::Eth,
        "q27_packets_view_vxlan_levels",
        "SELECT frame_number, protocol, eth_src, src_ip_v4, dst_ip_v4, src_port, dst_port, \
         encap_depth, tunnel_type FROM packets WHERE frame_number = 11 ORDER BY encap_depth",
    ),
    (
        Capture::Eth,
        "q20_vxlan",
        "SELECT frame_number, vni FROM vxlan ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q21_ethernet_encap",
        "SELECT frame_number, src_mac, encap_depth, tunnel_type, tunnel_id \
         FROM ethernet WHERE frame_number >= 10 ORDER BY frame_number, encap_depth",
    ),
    (
        Capture::Eth,
        "q22_udp_inner",
        "SELECT frame_number, src_port, dst_port, encap_depth \
         FROM udp WHERE frame_number >= 10 ORDER BY frame_number, encap_depth",
    ),
    (
        Capture::Eth,
        "q23_ipv4_inner",
        "SELECT frame_number, src_ip, dst_ip, encap_depth, tunnel_type \
         FROM ipv4 WHERE encap_depth > 0 ORDER BY frame_number",
    ),
    // --- time UDFs depend on the capture's full time range; these run on a
    //     fresh engine (see FRESH_ENGINE_QUERIES) so an earlier query cannot
    //     have populated the range for them ---
    (
        Capture::Eth,
        "q24_time_udfs",
        "SELECT frame_number, relative_time(timestamp) AS rel, \
         start_time() AS t0, end_time() AS t1 \
         FROM frames ORDER BY frame_number LIMIT 2",
    ),
    (
        Capture::Eth,
        "q25_time_range_only",
        "SELECT start_time() AS t0, end_time() AS t1",
    ),
    // --- the same table referenced twice in one query ---
    (
        Capture::Eth,
        "q26_self_join",
        "SELECT a.frame_number, b.frame_number AS next_frame \
         FROM frames a JOIN frames b ON b.frame_number = a.frame_number + 1 \
         ORDER BY a.frame_number",
    ),
    (
        Capture::Eth,
        "q27_in_subquery",
        "SELECT frame_number FROM frames \
         WHERE frame_number IN (SELECT frame_number FROM tcp WHERE dst_port = 80) \
         ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q28_view_plus_member",
        "SELECT t.frame_number, t.dst_port, u.flag_syn \
         FROM tcp_packets t JOIN tcp u USING (frame_number) ORDER BY t.frame_number",
    ),
    // --- window table functions over frames and a view ---
    (
        Capture::Eth,
        "q30_tumble",
        "SELECT window_start, window_end, count(*) AS n, sum(length) AS bytes \
         FROM tumble(frames, INTERVAL '5' SECOND) GROUP BY 1, 2 ORDER BY 1",
    ),
    (
        Capture::Eth,
        "q31_hop",
        "SELECT window_start, count(*) AS n \
         FROM hop(frames, INTERVAL '5' SECOND, INTERVAL '10' SECOND) GROUP BY 1 ORDER BY 1",
    ),
    (
        Capture::Eth,
        "q32_session",
        "SELECT dst_port, window_start, window_end, count(*) AS n \
         FROM session(tcp_packets, dst_port, INTERVAL '2' SECOND) GROUP BY 1, 2, 3 ORDER BY 1, 2",
    ),
    // --- Linux cooked capture: non-Ethernet link layer ---
    (
        Capture::Sll,
        "s01_sll",
        "SELECT frame_number, packet_type, protocol FROM linux_sll ORDER BY frame_number",
    ),
    (
        Capture::Sll,
        "s02_sll_ipv4",
        "SELECT frame_number, src_ip, dst_ip, protocol FROM ipv4 ORDER BY frame_number",
    ),
    (
        Capture::Sll,
        "s03_sll_udp_tcp_icmp",
        "SELECT (SELECT count(*) FROM udp) AS udp, (SELECT count(*) FROM tcp) AS tcp, \
         (SELECT count(*) FROM icmp) AS icmp",
    ),
    (
        Capture::Sll,
        "s04_sll_dns",
        "SELECT frame_number, query_name, is_query FROM dns ORDER BY frame_number",
    ),
    (
        Capture::Sll,
        "s05_sll_tcp_only",
        "SELECT frame_number, dst_port FROM tcp ORDER BY frame_number",
    ),
    // --- Linux cooked capture v2 (tcpdump -i any on libpcap >= 1.10) ---
    (
        Capture::Sll2,
        "t01_sll2",
        "SELECT frame_number, protocol, interface_index, arphrd_name, packet_type, \
         packet_type_name, addr_len, addr FROM sll2 ORDER BY frame_number",
    ),
    (
        Capture::Sll2,
        "t02_sll2_ipv4_ipv6",
        "SELECT frame_number, ip4_to_string(src_ip) AS src, ip4_to_string(dst_ip) AS dst FROM ipv4 \
         UNION ALL SELECT frame_number, ip6_to_string(src_ip), ip6_to_string(dst_ip) FROM ipv6 \
         ORDER BY frame_number",
    ),
    (
        Capture::Sll2,
        "t03_sll2_per_interface",
        "SELECT s.interface_index, count(*) AS frames, count(t.frame_number) AS tcp \
         FROM sll2 s LEFT JOIN tcp t USING (frame_number) \
         GROUP BY s.interface_index ORDER BY s.interface_index",
    ),
    (
        Capture::Sll2,
        "t04_sll2_dns_icmp",
        "SELECT (SELECT count(*) FROM dns) AS dns, (SELECT count(*) FROM icmp) AS icmp, \
         (SELECT count(*) FROM udp) AS udp",
    ),
    (
        Capture::Sll2,
        "t05_sll2_tcp_only",
        "SELECT frame_number, src_port, dst_port, flag_syn FROM tcp ORDER BY frame_number",
    ),
    // --- Stream analysis: tables built by the stream subscriber of the pass ---
    (
        Capture::Http,
        "u01_tcp_connections",
        "SELECT frame_number, connection_id, client_ip, server_ip, client_port, server_port, \
         state, start_time, end_time, duration_us, first_frame, last_frame, \
         packets_to_server, packets_to_client, bytes_to_server, bytes_to_client, is_complete \
         FROM tcp_connections ORDER BY frame_number",
    ),
    (
        Capture::Http,
        "u02_http_messages",
        "SELECT frame_number, connection_id, direction, is_request, method, uri, http_version, \
         status_code, host, content_type, content_length, user_agent, server \
         FROM http_messages ORDER BY frame_number",
    ),
    (
        Capture::Http,
        "u03_tls_sessions",
        "SELECT frame_number, connection_id, version, cipher_suite, cipher_suite_id, sni, alpn, \
         is_decrypted, server_hello_frame FROM tls_sessions ORDER BY frame_number",
    ),
    (
        Capture::Http,
        "u04_stream_join_packet",
        "SELECT m.frame_number, m.method, m.status_code, t.src_port, t.dst_port, t.flag_psh \
         FROM http_messages m JOIN tcp t USING (frame_number) ORDER BY m.frame_number",
    ),
    (
        Capture::Http,
        "u05_http2_empty",
        "SELECT count(*) AS frames FROM http2",
    ),
    // --- Packet-level HTTP/1.x: the `http` table and the views over it ---
    (
        Capture::Http,
        "u06_http_table",
        "SELECT frame_number, is_request, headers_complete, method, uri, version, status_code, \
         status_text, body_length, host, content_type, content_length, user_agent, server, \
         accept, encap_depth FROM http ORDER BY frame_number",
    ),
    (
        Capture::Http,
        "u07_http_packets_view",
        "SELECT frame_number, src_ip_v4, dst_ip_v4, src_port, dst_port, is_request, method, uri, \
         status_code, host, content_length FROM http_packets ORDER BY frame_number",
    ),
    (
        Capture::Http,
        "u08_packets_view_http_columns",
        "SELECT frame_number, protocol, src_port, dst_port, http_method, http_uri, \
         http_status_code, http_host, tls_sni FROM packets \
         WHERE http_method IS NOT NULL OR http_status_code IS NOT NULL OR tls_sni IS NOT NULL \
         ORDER BY frame_number",
    ),
    (
        Capture::Http,
        "u09_http_vs_http_messages",
        "SELECT h.frame_number, h.method, h.status_code, h.headers_complete, \
         m.method AS stream_method, m.status_code AS stream_status_code \
         FROM http h JOIN http_messages m USING (frame_number) ORDER BY h.frame_number",
    ),
    (
        Capture::Eth,
        "q29_http_not_a_message_start",
        "SELECT count(*) AS http_rows, \
         (SELECT count(*) FROM tcp WHERE dst_port = 80 OR src_port = 80) AS port_80_segments \
         FROM http",
    ),
    // `SELECT *` pins the full column set of each routing / tunnel table
    // (#138): adding a column changes the snapshot, on purpose.
    (
        Capture::Routing,
        "v01_bgp",
        "SELECT * FROM bgp ORDER BY frame_number",
    ),
    (
        Capture::Routing,
        "v02_ospf",
        "SELECT * FROM ospf ORDER BY frame_number",
    ),
    (
        Capture::Routing,
        "v03_gtp",
        "SELECT * FROM gtp ORDER BY frame_number",
    ),
    (
        Capture::Routing,
        "v04_ipv6",
        "SELECT * FROM ipv6 ORDER BY frame_number",
    ),
    // The convenience views project the new columns too.
    (
        Capture::Routing,
        "v05_bgp_packets_view",
        "SELECT * FROM bgp_packets ORDER BY frame_number",
    ),
    (
        Capture::Routing,
        "v06_ospf_packets_view",
        "SELECT * FROM ospf_packets ORDER BY frame_number",
    ),
    // The G-PDU frame carries an inner IPv4/UDP packet; the view's layers join
    // at the GTP header's depth, so the frame is one row with the outer
    // addresses and ports, not the product of both IP and both UDP headers.
    (
        Capture::Routing,
        "v07_gtp_packets_view",
        "SELECT * FROM gtp_packets ORDER BY frame_number",
    ),
    (
        Capture::Routing,
        "v08_gtp_frame_levels",
        "SELECT frame_number, src_ip_v4, dst_ip_v4, src_port, dst_port, encap_depth, tunnel_type \
         FROM udp_packets WHERE frame_number = 10 ORDER BY encap_depth",
    ),
    // --- tunnels whose inner and outer transports differ: every view row
    // --- combines headers of one encapsulation level only.
    (
        Capture::Tunnels,
        "t01_tcp_packets_levels",
        "SELECT frame_number, src_mac, src_ip_v4, dst_ip_v4, src_port, dst_port, encap_depth, \
         tunnel_type FROM tcp_packets ORDER BY frame_number, encap_depth",
    ),
    (
        Capture::Tunnels,
        "t02_udp_packets_levels",
        "SELECT frame_number, src_mac, src_ip_v4, dst_ip_v4, src_port, dst_port, encap_depth, \
         tunnel_type FROM udp_packets ORDER BY frame_number, encap_depth",
    ),
    (
        Capture::Tunnels,
        "t03_icmp_packets_levels",
        "SELECT frame_number, src_ip_v4, dst_ip_v4, type, encap_depth, tunnel_type \
         FROM icmp_packets ORDER BY frame_number, encap_depth",
    ),
    (
        Capture::Tunnels,
        "t04_arp_packets_levels",
        "SELECT frame_number, src_mac, operation, sender_ip, encap_depth, tunnel_type \
         FROM arp_packets ORDER BY frame_number, encap_depth",
    ),
    (
        Capture::Tunnels,
        "t05_packets_levels",
        "SELECT frame_number, encap_depth, tunnel_type, protocol, eth_src, src_ip_v4, dst_ip_v4, \
         ip_protocol, src_port, dst_port, icmp_type, arp_operation \
         FROM packets ORDER BY frame_number, encap_depth",
    ),
    (
        Capture::Tunnels,
        "t06_packets_one_row_per_level",
        "SELECT count(*) AS rows, count(DISTINCT frame_number) AS frames FROM packets",
    ),
    (
        Capture::Tunnels,
        "t07_tunneled_packets",
        "SELECT frame_number, outer_src_ipv4, outer_dst_ipv4, inner_src_ipv4, inner_dst_ipv4 \
         FROM tunneled_packets ORDER BY frame_number",
    ),
    // The `packets` view lists a frame's levels with a full join of the
    // network and link-layer tables, which is one row per level only while
    // the parser emits at most one network header and one Ethernet header
    // per (frame, depth). Pin that invariant: the result must be empty.
    (Capture::Tunnels, "t08_one_header_per_level", ONE_HEADER_PER_LEVEL),
    (Capture::Eth, "q28_one_header_per_level", ONE_HEADER_PER_LEVEL),
    (Capture::Routing, "v09_one_header_per_level", ONE_HEADER_PER_LEVEL),
    // --- frame-join fusion (RetentionPolicy::None fuses, CacheOnTouch joins;
    // --- the harness requires both to agree). Shapes the matcher must get
    // --- right or leave alone: one table under two aliases with filters
    // --- pushed under each, an ORDER BY on the root's depth without its
    // --- frame_number, LIMIT with OFFSET over a view, a derived table's own
    // --- LIMIT on the preserved side of a left join, and a left join under
    // --- a LIMIT.
    (
        Capture::Routing,
        "f01_same_table_two_aliases",
        "SELECT u0.src_port AS outer_port, u1.src_port AS inner_port \
         FROM frames f JOIN udp u0 ON f.frame_number = u0.frame_number \
         JOIN udp u1 ON u1.frame_number = u0.frame_number \
         WHERE u0.encap_depth = 0 AND u1.encap_depth = 1 ORDER BY f.frame_number",
    ),
    (
        Capture::Routing,
        "f02_order_by_root_depth",
        "SELECT u.encap_depth, f.timestamp FROM udp u \
         JOIN frames f ON u.frame_number = f.frame_number ORDER BY u.encap_depth, f.timestamp",
    ),
    (
        Capture::Eth,
        "f03_view_limit_offset",
        "SELECT frame_number, src_port FROM udp_packets LIMIT 2 OFFSET 1",
    ),
    (
        Capture::Routing,
        "f04_derived_table_limit_under_left_join",
        "SELECT d.frame_number, d.src_port, ip4.encap_depth FROM \
         (SELECT f.frame_number, udp.src_port FROM frames f \
          JOIN udp ON f.frame_number = udp.frame_number LIMIT 1) d \
         LEFT JOIN ipv4 ip4 ON ip4.frame_number = d.frame_number \
         ORDER BY d.frame_number, d.src_port, ip4.encap_depth",
    ),
    (
        Capture::Eth,
        "f05_left_join_under_limit",
        "SELECT f.frame_number, tcp.src_port FROM frames f \
         LEFT JOIN tcp ON f.frame_number = tcp.frame_number LIMIT 3",
    ),
    (
        Capture::Eth,
        "f06_view_joined_with_member",
        "SELECT t.frame_number, t.src_port, u.dst_port FROM tcp_packets t \
         JOIN tcp u ON u.frame_number = t.frame_number ORDER BY t.frame_number",
    ),
];

/// Frames with two network headers or two Ethernet headers at one depth
/// (see `t08_one_header_per_level`).
const ONE_HEADER_PER_LEVEL: &str = "\
    SELECT 'network' AS header, frame_number, encap_depth, count(*) AS n FROM ( \
        SELECT frame_number, encap_depth FROM ipv4 \
        UNION ALL SELECT frame_number, encap_depth FROM ipv6 \
        UNION ALL SELECT frame_number, encap_depth FROM arp) \
    GROUP BY 1, 2, 3 HAVING count(*) > 1 \
    UNION ALL \
    SELECT 'ethernet', frame_number, encap_depth, count(*) FROM ethernet \
    GROUP BY 1, 2, 3 HAVING count(*) > 1 \
    ORDER BY 1, 2, 3";

/// Queries that must be the *first* query a fresh engine runs: their result
/// depends on engine-wide state (the capture time range) that any earlier
/// query would otherwise establish as a side effect.
const FRESH_ENGINE_QUERIES: &[&str] = &["q24_time_udfs", "q25_time_range_only"];

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

async fn engine(path: &Path, partitions: usize) -> QueryEngine {
    QueryEngine::open(
        SourceSpec::Path(path.to_path_buf()),
        EngineOptions {
            batch_size: 1000,
            target_partitions: Some(partitions),
            index_stride: Some(4),
            ..Default::default()
        },
    )
    .await
    .expect("build engine")
}

async fn run(engine: &QueryEngine, sql: &str) -> String {
    let batches = engine.query(sql).await.unwrap_or_else(|e| {
        panic!("query failed: {sql}\n{e}");
    });
    pretty_format_batches(&batches).expect("format").to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn golden_corpus_matches_snapshots() {
    let dir = TempDir::new().unwrap();
    let eth_path = dir.path().join("corpus.pcap");
    std::fs::write(&eth_path, corpus_capture()).unwrap();
    let sll_path = dir.path().join("corpus_sll.pcap");
    std::fs::write(&sll_path, sll_capture()).unwrap();
    let sll2_path = dir.path().join("corpus_sll2.pcap");
    std::fs::write(&sll2_path, sll2_capture()).unwrap();
    let http_path = dir.path().join("corpus_http.pcap");
    std::fs::write(&http_path, http_capture()).unwrap();
    let routing_path = dir.path().join("corpus_routing.pcap");
    std::fs::write(&routing_path, routing_capture()).unwrap();
    let tunnels_path = dir.path().join("corpus_tunnels.pcap");
    std::fs::write(&tunnels_path, tunnels_capture()).unwrap();

    let update = std::env::var("PCAPSQL_GOLDEN_UPDATE").is_ok();
    if update {
        std::fs::create_dir_all(golden_dir()).unwrap();
    }

    let eth = (engine(&eth_path, 2).await, engine(&eth_path, 1).await);
    let sll = (engine(&sll_path, 2).await, engine(&sll_path, 1).await);
    let sll2 = (engine(&sll2_path, 2).await, engine(&sll2_path, 1).await);
    let http = (engine(&http_path, 2).await, engine(&http_path, 1).await);
    let routing = (
        engine(&routing_path, 2).await,
        engine(&routing_path, 1).await,
    );
    let tunnels = (
        engine(&tunnels_path, 2).await,
        engine(&tunnels_path, 1).await,
    );
    // One-shot CLI path: RetentionPolicy::None streams rather than
    // materializes. Its results must be identical.
    let streaming = |path: &Path| {
        QueryEngine::open(
            SourceSpec::Path(path.to_path_buf()),
            EngineOptions {
                batch_size: 1000,
                target_partitions: Some(2),
                index_stride: Some(4),
                retention: RetentionPolicy::None,
                ..Default::default()
            },
        )
    };
    let eth_streamed = streaming(&eth_path).await.expect("build streaming engine");
    let sll_streamed = streaming(&sll_path).await.expect("build streaming engine");
    let sll2_streamed = streaming(&sll2_path).await.expect("build streaming engine");
    let http_streamed = streaming(&http_path).await.expect("build streaming engine");
    let routing_streamed = streaming(&routing_path)
        .await
        .expect("build streaming engine");
    let tunnels_streamed = streaming(&tunnels_path)
        .await
        .expect("build streaming engine");

    let mut failures = Vec::new();
    for (capture, name, sql) in CORPUS {
        let path = match capture {
            Capture::Eth => &eth_path,
            Capture::Sll => &sll_path,
            Capture::Sll2 => &sll2_path,
            Capture::Http => &http_path,
            Capture::Routing => &routing_path,
            Capture::Tunnels => &tunnels_path,
        };
        // Fresh engines (materialized and streaming) for queries whose result
        // depends on engine-wide state no earlier query may have established.
        let fresh_engines = if FRESH_ENGINE_QUERIES.contains(name) {
            Some((
                engine(path, 2).await,
                engine(path, 1).await,
                streaming(path).await.expect("build streaming engine"),
            ))
        } else {
            None
        };
        let (e2, e1, streamed) = match (&fresh_engines, capture) {
            (Some(f), _) => (&f.0, &f.1, &f.2),
            (None, Capture::Eth) => (&eth.0, &eth.1, &eth_streamed),
            (None, Capture::Sll) => (&sll.0, &sll.1, &sll_streamed),
            (None, Capture::Sll2) => (&sll2.0, &sll2.1, &sll2_streamed),
            (None, Capture::Http) => (&http.0, &http.1, &http_streamed),
            (None, Capture::Routing) => (&routing.0, &routing.1, &routing_streamed),
            (None, Capture::Tunnels) => (&tunnels.0, &tunnels.1, &tunnels_streamed),
        };
        let got = run(e2, sql).await;

        // Partition-count independence is part of the contract.
        let got_p1 = run(e1, sql).await;
        assert_eq!(
            got, got_p1,
            "{name}: results differ between 1 and 2 partitions"
        );
        // Streaming (one-shot) vs materialized (REPL) must agree.
        let got_stream = run(streamed, sql).await;
        assert_eq!(
            got, got_stream,
            "{name}: streaming result differs from materialized"
        );

        let snap_path = golden_dir().join(format!("{name}.snap"));
        if update {
            std::fs::write(&snap_path, &got).unwrap();
            continue;
        }
        let expected = std::fs::read_to_string(&snap_path).unwrap_or_else(|e| {
            panic!(
                "missing snapshot {} ({e}); run with PCAPSQL_GOLDEN_UPDATE=1 to create",
                snap_path.display()
            )
        });
        if got != expected {
            failures.push(format!(
                "=== {name} ===\n--- expected ---\n{expected}\n--- got ---\n{got}\n"
            ));
        }
    }

    // The whole corpus of a capture at once, from concurrent tasks on one
    // engine, under both retention policies: results must still match the
    // snapshots. Queries that must be the first on a fresh engine are left
    // out.
    if !update {
        let captures = [
            (Capture::Eth, &eth_path),
            (Capture::Sll, &sll_path),
            (Capture::Sll2, &sll2_path),
            (Capture::Http, &http_path),
            (Capture::Routing, &routing_path),
            (Capture::Tunnels, &tunnels_path),
        ];
        for (capture, path) in captures {
            for retention in [RetentionPolicy::CacheOnTouch, RetentionPolicy::None] {
                let eng = Arc::new(
                    QueryEngine::open(
                        SourceSpec::Path(path.to_path_buf()),
                        EngineOptions {
                            batch_size: 1000,
                            target_partitions: Some(2),
                            index_stride: Some(4),
                            retention,
                            ..Default::default()
                        },
                    )
                    .await
                    .expect("build engine"),
                );
                let mut tasks = tokio::task::JoinSet::new();
                for (c, name, sql) in CORPUS {
                    if *c != capture || FRESH_ENGINE_QUERIES.contains(name) {
                        continue;
                    }
                    let eng = eng.clone();
                    tasks.spawn(async move { (*name, run(&eng, sql).await) });
                }
                while let Some(joined) = tasks.join_next().await {
                    let (name, got) = joined.expect("query task");
                    let expected =
                        std::fs::read_to_string(golden_dir().join(format!("{name}.snap")))
                            .expect("snapshot");
                    if got != expected {
                        failures.push(format!(
                            "=== {name} (concurrent, {retention:?}) ===\n\
                             --- expected ---\n{expected}\n--- got ---\n{got}\n"
                        ));
                    }
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "golden corpus mismatches:\n{}",
        failures.join("\n")
    );
}

/// Stream tables are built by a subscriber of the one packet pass: a query
/// mixing a stream table and a packet table reads the capture once, as one
/// partition (reassembly order), and reports which tables pinned it. Under
/// `CacheOnTouch` the stream table is then served from cache.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stream_tables_share_the_packet_pass() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("corpus_http.pcap");
    std::fs::write(&path, http_capture()).unwrap();
    let mixed = "SELECT m.method, t.dst_port FROM http_messages m \
                 JOIN tcp t USING (frame_number) ORDER BY m.frame_number";

    for retention in [RetentionPolicy::CacheOnTouch, RetentionPolicy::None] {
        let eng = QueryEngine::open(
            SourceSpec::Path(path.clone()),
            EngineOptions {
                batch_size: 1000,
                target_partitions: Some(2),
                index_stride: Some(4),
                retention,
                ..Default::default()
            },
        )
        .await
        .expect("open engine");

        let out = run(&eng, mixed).await;
        assert!(out.contains("GET"), "{out}");
        let stats = eng.last_parse_stats();
        assert_eq!(
            stats.parse_passes, 1,
            "{retention:?}: one read for a mixed query"
        );
        assert_eq!(
            stats.partitions, 1,
            "{retention:?}: reassembly pins one partition"
        );
        assert_eq!(stats.stream_tables, vec!["http_messages".to_string()]);
        assert_eq!(stats.rows_built.get("http_messages"), Some(&2));
        assert!(stats.complete_scan);

        // A plain packet query afterwards is not pinned: the same engine
        // splits this capture into its two requested partitions.
        run(&eng, "SELECT count(*) FROM udp").await;
        let stats = eng.last_parse_stats();
        assert!(stats.stream_tables.is_empty());
        assert_eq!(
            stats.partitions, 2,
            "{retention:?}: unpinned query uses both partitions"
        );

        let again = run(&eng, "SELECT count(*) AS n FROM http_messages").await;
        assert!(again.contains("| 2 "), "{again}");
        let stats = eng.last_parse_stats();
        match retention {
            RetentionPolicy::CacheOnTouch => {
                assert_eq!(stats.parse_passes, 0, "stream table served from cache")
            }
            RetentionPolicy::None => {
                assert_eq!(stats.parse_passes, 1);
                assert_eq!(stats.partitions, 1);
            }
        }
    }
}

/// Ethernet trailer padding is not TCP payload: a padded capture must
/// reassemble exactly like the unpadded one (same messages, same byte
/// counts), and the TLS 1.3 negotiation must be read from supported_versions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stream_tables_ignore_ethernet_padding() {
    let dir = TempDir::new().unwrap();
    let plain = dir.path().join("plain.pcap");
    let padded = dir.path().join("padded.pcap");
    std::fs::write(&plain, http_capture()).unwrap();
    std::fs::write(&padded, padded_http_capture()).unwrap();
    assert!(std::fs::metadata(&padded).unwrap().len() > std::fs::metadata(&plain).unwrap().len());

    let queries = [
        "SELECT frame_number, method, status_code, host, content_length FROM http_messages \
         ORDER BY frame_number",
        "SELECT connection_id, bytes_to_server, bytes_to_client, state, duration_us \
         FROM tcp_connections ORDER BY connection_id",
        "SELECT version, cipher_suite, sni, alpn FROM tls_sessions",
    ];
    let (e_plain, e_padded) = (engine(&plain, 1).await, engine(&padded, 1).await);
    for sql in queries {
        let a = run(&e_plain, sql).await;
        let b = run(&e_padded, sql).await;
        assert_eq!(a, b, "padding changed the result of: {sql}\n{a}\n{b}");
    }
    let http = run(&e_padded, "SELECT count(*) AS n FROM http_messages").await;
    assert!(http.contains("| 2 "), "{http}");
    let bytes = run(
        &e_padded,
        "SELECT bytes_to_server FROM tcp_connections WHERE server_port = 80",
    )
    .await;
    assert!(bytes.contains("| 100 "), "{bytes}");
    let tls = run(&e_padded, "SELECT version FROM tls_sessions").await;
    assert!(tls.contains("TLS 1.3"), "{tls}");
}

/// NTP packet (48 bytes): LI=0, VN=4, mode=3 (client), stratum 2, poll 6,
/// precision -20, root delay 0.5 s, root dispersion 0.25 s, ref id
/// 10.0.0.9, transmit timestamp 2023-11-14T22:13:20Z (NTP era 0).
fn ntp_client_packet() -> Vec<u8> {
    let mut p = vec![0x23, 2, 6, 0xEC];
    p.extend_from_slice(&0x0000_8000u32.to_be_bytes()); // root delay 0.5
    p.extend_from_slice(&0x0000_4000u32.to_be_bytes()); // root dispersion 0.25
    p.extend_from_slice(&[10, 0, 0, 9]);
    p.extend_from_slice(&[0u8; 24]); // reference, origin, receive: unset
    let ntp_seconds: u32 = 1_700_000_000 + 2_208_988_800;
    p.extend_from_slice(&ntp_seconds.to_be_bytes());
    p.extend_from_slice(&0x8000_0000u32.to_be_bytes()); // + 0.5 s
    p
}

/// The `ntp` table shipped with Int8/Float64 columns no builder supported,
/// so any capture with NTP failed to materialize. Pin that it works and that
/// the values are in real units.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ntp_table_materializes_with_real_units() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ntp.pcap");
    let frame = eth(
        MAC_B,
        MAC_A,
        ETH_IP4,
        &ipv4(
            [10, 0, 0, 1],
            [10, 0, 0, 9],
            17,
            1,
            &udp(123, 123, &ntp_client_packet()),
        ),
    );
    std::fs::write(&path, to_capture(vec![frame], LINKTYPE_ETHERNET)).unwrap();
    let eng = engine(&path, 1).await;
    let out = run(
        &eng,
        "SELECT version, mode, stratum, poll, precision, root_delay, root_dispersion, \
         reference_id, transmit_ts FROM ntp",
    )
    .await;
    assert!(out.contains("| 4 "), "{out}");
    assert!(out.contains("| -20 "), "precision must be signed: {out}");
    assert!(out.contains("| 0.5 "), "root delay in seconds: {out}");
    assert!(out.contains("| 0.25 "), "root dispersion in seconds: {out}");
    assert!(out.contains("10.0.0.9"), "{out}");
    assert!(
        out.contains("1700000000.5"),
        "transmit_ts as Unix seconds: {out}"
    );
    // SELECT * exercises every column's builder.
    let all = run(&eng, "SELECT * FROM ntp").await;
    assert!(all.contains("| 2 "), "{all}");
}
