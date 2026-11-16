//! A projected parse is the full parse with fewer fields.
//!
//! Every parser with a projected parse (a field list,
//! `Protocol::field_names`) is held to it for every layer it parses in the
//! packets of the fuzz corpus (`common/fuzz_corpus.rs`) and of the golden
//! captures (`pcapsql_testgen::corpus`): asked for no field, for each of its
//! fields alone, for every field but one, and for a few subsets drawn at
//! random (from the layer's bytes, so the same on every run), it leaves the
//! same bytes, the same hints for the layer after and the same status and
//! error as its full parse, and of the full parse's fields it writes
//! exactly those asked for, in their order. The subsets of several fields
//! are the ones that show the order of the fields, and a field that depends
//! on work done for another.
//!
//! And a scope that projects these parsers, to no field (as the layers
//! under a queried table are parsed), to one field each or to every field
//! but one, gives every packet the full parse's layers: the same parsers,
//! tunnel context, payloads and errors, with the fields restricted to the
//! projection.

#[path = "common/fuzz_corpus.rs"]
mod fuzz_corpus;

use std::collections::{BTreeMap, HashMap};
use std::io::Cursor;
use std::sync::atomic::{AtomicUsize, Ordering};

use fuzz_corpus::{captures, inputs, wrap, HEADERS, LINK_TYPES};
use pcapsql_core::io::{
    FilePacketSource, PacketReader, PacketSource, ReadPacketReader, StreamHeader,
};
use pcapsql_core::protocol::{
    parse_packet, FieldEntry, FieldSet, HintKey, LayerRef, ParseBuf, ParseContext, ParseScope,
    Protocol, TunnelType,
};
use pcapsql_core::{default_registry, ProtocolRegistry};
use pcapsql_testgen::corpus as golden;

/// The parsers that must have a projected parse.
const PROJECTED: [&str; 9] = [
    "dns",
    "ethernet",
    "ipv4",
    "ipv6",
    "linux_sll",
    "sll2",
    "tcp",
    "udp",
    "vlan",
];

/// How many subsets drawn at random each layer is also asked for.
const RANDOM_SUBSETS: usize = 4;

/// Every field of a list of `len`, as a mask of positions.
fn all_of(len: usize) -> u64 {
    if len >= 64 {
        u64::MAX
    } else {
        (1 << len) - 1
    }
}

/// The names of `names` at the positions of the bits of `mask`.
fn names_in(names: &'static [&'static str], mask: u64) -> impl Iterator<Item = &'static str> {
    names
        .iter()
        .enumerate()
        .filter(move |(position, _)| mask >> position & 1 != 0)
        .map(|(_, name)| *name)
}

/// The next number of a splitmix64 sequence.
fn next_random(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// A seed from the bytes a layer is parsed from (FNV-1a over its length and
/// its first bytes): the same subsets on every run, whatever thread or
/// order the layer is compared in.
fn seed_of(parser: &str, data: &[u8]) -> u64 {
    let length = data.len().to_le_bytes();
    let bytes = parser
        .bytes()
        .chain(length)
        .chain(data.iter().take(64).copied());
    bytes.fold(0xCBF2_9CE4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01B3)
    })
}

/// The projections a layer of a parser with `len` fields is compared in, as
/// masks of positions: no field, each field alone, every field but one, and
/// [`RANDOM_SUBSETS`] drawn from `seed`.
fn subsets(len: usize, seed: u64) -> Vec<u64> {
    let all = all_of(len);
    let mut subsets = vec![0];
    subsets.extend((0..len).map(|j| 1 << j));
    subsets.extend((0..len).map(|j| all & !(1 << j)));
    let mut state = seed;
    subsets.extend((0..RANDOM_SUBSETS).map(|_| next_random(&mut state) & all));
    subsets
}

/// A scope, with the fields each parser it projects is asked for (a mask of
/// positions in its list). The parsers it does not project write all their
/// fields.
type Projecting = (ParseScope, BTreeMap<&'static str, u64>);

/// The scopes compared with the full parse, one per packet in turn: every
/// parser with a projected parse projected to no field, then each to its
/// field `j` (modulo its number of fields), then each to every field but
/// that one; over consecutive packets, every one of those.
struct Scopes(Vec<Projecting>);

impl Scopes {
    fn new(registry: &ProtocolRegistry) -> Self {
        let projected = || {
            registry
                .all_parsers()
                .filter(|parser| !parser.field_names().is_empty())
        };
        let most = projected()
            .map(|parser| parser.field_names().len())
            .max()
            .expect("parsers with a projected parse");
        let scope = |mask: &dyn Fn(usize) -> u64| {
            let mut scope = ParseScope::full();
            let mut masks = BTreeMap::new();
            for parser in projected() {
                let names = parser.field_names();
                let mask = mask(names.len());
                let fields = names_in(names, mask).map(String::from).collect();
                scope = scope.with_projection(parser.name(), fields);
                masks.insert(parser.name(), mask);
            }
            (scope, masks)
        };
        let mut scopes = vec![scope(&|_| 0)];
        scopes.extend((0..most).map(|j| scope(&|len| 1 << (j % len))));
        scopes.extend((0..most).map(|j| scope(&|len| all_of(len) & !(1 << (j % len)))));
        Self(scopes)
    }

    /// The scope packet number `packet` is compared in.
    fn for_packet(&self, packet: usize) -> &Projecting {
        &self.0[packet % self.0.len()]
    }
}

/// A layer as the walk records it, fields aside: the parser, the tunnel
/// context, where the payload is and the error.
type Context<'a> = (
    &'static str,
    u8,
    TunnelType,
    Option<u64>,
    *const u8,
    usize,
    Option<&'a str>,
);

fn context_of<'a>(layer: &LayerRef<'_, 'a>) -> Context<'a> {
    (
        layer.name(),
        layer.encap_depth(),
        layer.tunnel_type(),
        layer.tunnel_id(),
        layer.payload().as_ptr(),
        layer.payload().len(),
        layer.error(),
    )
}

/// Per field of `full`, its bit in the list `names` (0 for a field the
/// list does not have).
fn field_bits(names: &[&str], full: &[FieldEntry<'_>]) -> Vec<u64> {
    full.iter()
        .map(|(key, _)| {
            names
                .iter()
                .position(|name| name == key)
                .map_or(0, |p| 1 << p)
        })
        .collect()
}

/// Which of a full parse's fields a projected parse writes: all of them,
/// or those whose bit ([`field_bits`]) is in a mask.
#[derive(Debug, Clone, Copy)]
enum Wanted<'b> {
    All,
    Masked(&'b [u64], u64),
}

/// Panics unless `got` is `full` restricted to `wanted`, in order.
fn assert_restricted(
    got: &[FieldEntry<'_>],
    full: &[FieldEntry<'_>],
    wanted: Wanted<'_>,
    at: impl Fn() -> String,
) {
    let kept = |i: usize| match wanted {
        Wanted::All => true,
        Wanted::Masked(bits, mask) => bits[i] & mask != 0,
    };
    let expected = || {
        full.iter()
            .enumerate()
            .filter(move |(i, _)| kept(*i))
            .map(|(_, field)| field)
    };
    if !got.iter().eq(expected()) {
        let expected: Vec<_> = expected().collect();
        panic!("{}: fields {got:?}, expected {expected:?}", at());
    }
}

/// How often each field of each parser was in a layer the comparisons
/// covered: that the packets reach every field.
#[derive(Default)]
struct Coverage {
    packets: usize,
    /// Per parser: the layers compared, and per field (by position) the
    /// layers whose full parse had it.
    layers: BTreeMap<&'static str, (usize, Vec<usize>)>,
}

impl Coverage {
    fn add(&mut self, other: Coverage) {
        self.packets += other.packets;
        for (parser, (layers, fields)) in other.layers {
            let (total, counts) = self
                .layers
                .entry(parser)
                .or_insert_with(|| (0, vec![0; fields.len()]));
            *total += layers;
            for (count, more) in counts.iter_mut().zip(fields) {
                *count += more;
            }
        }
    }
}

/// Compares packets, keeping its buffers from one to the next.
struct Checker<'s> {
    registry: &'s ProtocolRegistry,
    scopes: &'s Scopes,
    full: ParseBuf,
    projected: ParseBuf,
    /// The projections already resolved, by field list and mask.
    resolved: HashMap<(usize, u64), FieldSet>,
    coverage: Coverage,
}

impl<'s> Checker<'s> {
    fn new(registry: &'s ProtocolRegistry, scopes: &'s Scopes) -> Self {
        Self {
            registry,
            scopes,
            full: ParseBuf::new(),
            projected: ParseBuf::new(),
            resolved: HashMap::new(),
            coverage: Coverage::default(),
        }
    }

    /// Both comparisons for one packet.
    fn packet(&mut self, link_type: u16, data: &[u8], what: &dyn Fn() -> String) {
        self.layers(link_type, data, what);
        self.scope(link_type, data, what);
        self.coverage.packets += 1;
    }

    /// Every layer of `data`, walked parser by parser: each parser with a
    /// projected parse, asked for each of its [`subsets`], against its full
    /// parse.
    fn layers(&mut self, link_type: u16, data: &[u8], what: &dyn Fn() -> String) {
        let mut full = self.full.for_packet();
        let mut context = ParseContext::new(link_type);
        let mut remaining = data;
        while !remaining.is_empty() {
            let Some(parser) = self.registry.find_parser(&context) else {
                break;
            };
            let before = full.len();
            let parsed = full.parse_layer(parser, remaining, &context, None);
            let names = parser.field_names();
            if !names.is_empty() {
                let kept = full.len() > before;
                let full_fields = full.get(before).map_or(&[][..], |layer| layer.fields());
                let (layers, fields) = self
                    .coverage
                    .layers
                    .entry(parser.name())
                    .or_insert_with(|| (0, vec![0; names.len()]));
                *layers += 1;
                for (position, name) in names.iter().enumerate() {
                    if full_fields.iter().any(|(key, _)| key == name) {
                        fields[position] += 1;
                    }
                }
                let bits = field_bits(names, full_fields);
                for mask in subsets(names.len(), seed_of(parser.name(), remaining)) {
                    let projection = *self
                        .resolved
                        .entry((names.as_ptr() as usize, mask))
                        .or_insert_with(|| FieldSet::resolve(names, names_in(names, mask)));
                    let mut layers = self.projected.for_packet();
                    let projected =
                        layers.parse_layer(parser, remaining, &context, Some(projection));
                    let at = || {
                        let fields: Vec<_> = names_in(names, mask).collect();
                        format!("{}: {} asked for {fields:?}", what(), parser.name())
                    };
                    assert!(
                        std::ptr::eq(projected.remaining, parsed.remaining),
                        "{}: remaining bytes",
                        at()
                    );
                    assert_eq!(projected.child_hints, parsed.child_hints, "{}", at());
                    assert_eq!(projected.status, parsed.status, "{}", at());
                    assert_eq!(layers.len() == 1, kept, "{}: kept as a layer", at());
                    let got = layers.last().map_or(&[][..], |layer| layer.fields());
                    assert_restricted(got, full_fields, Wanted::Masked(&bits, mask), at);
                }
            }
            if !parsed.is_ok() {
                break;
            }
            if let Some(tunnel_type) = parsed.hint(HintKey::TunnelType) {
                context.push_tunnel(
                    TunnelType::from_u64(tunnel_type),
                    parsed.hint(HintKey::TunnelId),
                );
            }
            context.parent_protocol = Some(parser.name());
            context.hints = parsed.child_hints;
            context.offset += remaining.len() - parsed.remaining.len();
            remaining = parsed.remaining;
        }
    }

    /// `data` parsed in a projecting scope against its full parse.
    fn scope(&mut self, link_type: u16, data: &[u8], what: &dyn Fn() -> String) {
        let registry = self.registry;
        let full = parse_packet(
            registry,
            link_type,
            data,
            &ParseScope::full(),
            &mut self.full,
        );
        let (scope, wanted) = self.scopes.for_packet(self.coverage.packets);
        let projected = parse_packet(registry, link_type, data, scope, &mut self.projected);
        let at = |i: usize| format!("{} (link type {link_type}), layer {i}", what());
        assert_eq!(projected.len(), full.len(), "{}", at(full.len()));
        for (i, (expected, got)) in full.iter().zip(projected.iter()).enumerate() {
            assert_eq!(context_of(&got), context_of(&expected), "{}", at(i));
            // A parser the scope does not project writes every field.
            match wanted.get(expected.name()) {
                None => assert_restricted(got.fields(), expected.fields(), Wanted::All, || at(i)),
                Some(&mask) => {
                    let names = registry.get_parser(expected.name()).unwrap().field_names();
                    let bits = field_bits(names, expected.fields());
                    let fields = Wanted::Masked(&bits, mask);
                    assert_restricted(got.fields(), expected.fields(), fields, || at(i));
                }
            }
        }
    }

    /// Every packet `reader` delivers.
    fn capture<R: PacketReader>(&mut self, mut reader: R, name: &str) {
        // A capture that cannot be read further ends there.
        while let Ok(1..) = reader.process_packets(1024, |packet| {
            let what = || format!("{name} frame {}", packet.frame_number);
            self.packet(packet.link_type, packet.data, &what);
            Ok(())
        }) {}
    }
}

#[test]
fn projected_parses_are_the_full_parse_restricted_to_the_projection() {
    let registry = default_registry();
    let mut with_list: Vec<&str> = registry
        .all_parsers()
        .filter(|parser| !parser.field_names().is_empty())
        .map(|parser| parser.name())
        .collect();
    with_list.sort_unstable();
    assert_eq!(with_list, PROJECTED);
    let scopes = Scopes::new(&registry);

    // The captures, golden and fuzz.
    let mut checker = Checker::new(&registry, &scopes);
    let golden = [
        ("corpus", golden::corpus_capture()),
        ("sll", golden::sll_capture()),
        ("sll2", golden::sll2_capture()),
        ("http", golden::http_capture()),
        ("padded http", golden::padded_http_capture()),
        ("routing", golden::routing_capture()),
        ("tunnels", golden::tunnels_capture()),
        ("views", golden::views_capture()),
    ];
    for (name, capture) in golden {
        let mut read = Cursor::new(capture);
        let (header, head) = StreamHeader::probe(&mut read).expect("a capture header");
        let reader = ReadPacketReader::sequential(read, &header, head).expect("a reader");
        checker.capture(reader, name);
    }
    for path in captures() {
        let name = path.file_name().expect("a file").to_string_lossy();
        let reader = FilePacketSource::open(&path)
            .and_then(|source| source.sequential_reader())
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        checker.capture(reader, &name);
    }
    let mut coverage = checker.coverage;

    // The other corpus files, as frames, on a few threads.
    let inputs = inputs();
    let next = AtomicUsize::new(0);
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get().min(8));
    let covered: Vec<Coverage> = std::thread::scope(|threads_scope| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                threads_scope.spawn(|| {
                    let mut checker = Checker::new(&registry, &scopes);
                    while let Some((name, data)) = inputs.get(next.fetch_add(1, Ordering::Relaxed))
                    {
                        for link_type in LINK_TYPES {
                            checker.packet(link_type, data, &|| name.clone());
                        }
                        for (header_name, header) in HEADERS {
                            let frame = wrap(header, data);
                            let what = || format!("{name} behind the {header_name} header");
                            checker.packet(1, &frame, &what);
                        }
                    }
                    checker.coverage
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().expect("a worker"))
            .collect()
    });
    for more in covered {
        coverage.add(more);
    }

    // The packets reach every parser, and every field of each.
    println!("{} packets", coverage.packets);
    assert!(coverage.packets > 70_000, "{} packets", coverage.packets);
    for name in PROJECTED {
        let (layers, fields) = &coverage.layers[name];
        let names = registry.get_parser(name).unwrap().field_names();
        println!("{name}: {layers} layers");
        for (field, count) in names.iter().zip(fields) {
            assert!(*count > 0, "no {name} layer has {field}");
        }
    }
}
