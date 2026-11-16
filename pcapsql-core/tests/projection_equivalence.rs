//! A projected parse is the full parse with fewer fields.
//!
//! Every parser with a projected parse (a field list,
//! `Protocol::field_names`) is held to it for every layer it parses in the
//! packets of the fuzz corpus (`common/fuzz_corpus.rs`) and of the golden
//! captures (`pcapsql_testgen::corpus`): asked for no field, and for each of
//! its fields alone, it leaves the same bytes, the same hints for the layer
//! after and the same status and error as its full parse, and of the full
//! parse's fields it writes exactly those asked for, in their order.
//!
//! And a scope that projects these parsers, to no field (as the layers
//! under a queried table are parsed) or to one field each, gives every
//! packet the full parse's layers: the same parsers, tunnel context,
//! payloads and errors, with the fields restricted to the projection.

#[path = "common/fuzz_corpus.rs"]
mod fuzz_corpus;

use std::collections::{BTreeMap, HashSet};
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

/// A scope, with the field each parser it projects is asked for (`None`:
/// no field). The parsers it does not project write all their fields.
type Projecting = (ParseScope, BTreeMap<&'static str, Option<&'static str>>);

/// The scopes compared with the full parse.
struct Scopes {
    /// Every parser with a projected parse projected to no field.
    transit: Projecting,
    /// Scope `j` projects each of those parsers to its field `j` (modulo
    /// its number of fields): over consecutive packets, every field alone.
    single: Vec<Projecting>,
}

impl Scopes {
    fn new(registry: &ProtocolRegistry) -> Self {
        let projected = || {
            registry
                .all_parsers()
                .filter(|parser| !parser.field_names().is_empty())
        };
        let mut transit = (ParseScope::full(), BTreeMap::new());
        for parser in projected() {
            transit.0 = transit.0.with_projection(parser.name(), HashSet::new());
            transit.1.insert(parser.name(), None);
        }
        let most = projected()
            .map(|parser| parser.field_names().len())
            .max()
            .expect("parsers with a projected parse");
        let single = (0..most)
            .map(|j| {
                let mut scope = ParseScope::full();
                let mut fields = BTreeMap::new();
                for parser in projected() {
                    let names = parser.field_names();
                    let field = names[j % names.len()];
                    scope = scope.with_projection(parser.name(), HashSet::from([field.into()]));
                    fields.insert(parser.name(), Some(field));
                }
                (scope, fields)
            })
            .collect();
        Self { transit, single }
    }

    /// The scope packet number `packet` is compared in: in turn the
    /// transit scope and each single-field one.
    fn for_packet(&self, packet: usize) -> &Projecting {
        match packet % (self.single.len() + 1) {
            0 => &self.transit,
            j => &self.single[j - 1],
        }
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

/// Which of a full parse's fields a projected parse writes.
#[derive(Debug, Clone, Copy)]
enum Wanted<'n> {
    All,
    Nothing,
    Only(&'n str),
}

/// Panics unless `got` is `full` restricted to `wanted`, in order.
fn assert_restricted(
    got: &[FieldEntry<'_>],
    full: &[FieldEntry<'_>],
    wanted: Wanted<'_>,
    at: impl Fn() -> String,
) {
    let kept = |(key, _): &&FieldEntry<'_>| match wanted {
        Wanted::All => true,
        Wanted::Nothing => false,
        Wanted::Only(name) => *key == name,
    };
    if !got.iter().eq(full.iter().filter(kept)) {
        let expected: Vec<_> = full.iter().filter(kept).collect();
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
    coverage: Coverage,
}

impl<'s> Checker<'s> {
    fn new(registry: &'s ProtocolRegistry, scopes: &'s Scopes) -> Self {
        Self {
            registry,
            scopes,
            full: ParseBuf::new(),
            projected: ParseBuf::new(),
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
    /// projected parse, asked for no field and for each field alone,
    /// against its full parse.
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
                let asked = std::iter::once(None).chain(names.iter().copied().map(Some));
                for field in asked {
                    let projection = FieldSet::resolve(names, field);
                    let mut layers = self.projected.for_packet();
                    let projected =
                        layers.parse_layer(parser, remaining, &context, Some(projection));
                    let at = || format!("{}: {} asked for {field:?}", what(), parser.name());
                    assert!(
                        std::ptr::eq(projected.remaining, parsed.remaining),
                        "{}: remaining bytes",
                        at()
                    );
                    assert_eq!(projected.child_hints, parsed.child_hints, "{}", at());
                    assert_eq!(projected.status, parsed.status, "{}", at());
                    assert_eq!(layers.len() == 1, kept, "{}: kept as a layer", at());
                    let got = layers.last().map_or(&[][..], |layer| layer.fields());
                    let wanted = field.map_or(Wanted::Nothing, Wanted::Only);
                    assert_restricted(got, full_fields, wanted, at);
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
            let fields = match wanted.get(expected.name()) {
                None => Wanted::All,
                Some(None) => Wanted::Nothing,
                Some(Some(name)) => Wanted::Only(name),
            };
            assert_restricted(got.fields(), expected.fields(), fields, || at(i));
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
