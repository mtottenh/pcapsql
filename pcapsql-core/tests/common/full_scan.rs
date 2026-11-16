//! The parser chain of a packet as a scan of every parser chooses it, to
//! hold the registry's dispatch tables against.
//!
//! `parse_packet` finds a layer's parser in tables built from the parsers'
//! [`Dispatch`](pcapsql_core::protocol::Dispatch) rules. This walk asks every
//! registered parser's `can_parse` for every layer instead
//! ([`ProtocolRegistry::find_parser`]), which is what the parse loop did
//! before there were tables, and otherwise does what the loop does.
//!
//! A file of its own, without the rest of `common`, because the DataFusion
//! frontend's golden test includes it too (by `#[path]`) for its captures.

use pcapsql_core::io::PacketReader;
use pcapsql_core::protocol::{
    parse_packet, HintKey, ParseBuf, ParseContext, ParseScope, Protocol, TunnelType,
};
use pcapsql_core::ProtocolRegistry;

/// A layer of a chain: the parser, and the tunnel context it was parsed in.
pub type ChainLayer = (&'static str, u8, TunnelType, Option<u64>);

/// The layers of `data`, each parser chosen by asking all of them.
pub fn full_scan_chain(
    registry: &ProtocolRegistry,
    link_type: u16,
    data: &[u8],
) -> Vec<ChainLayer> {
    let mut chain = Vec::new();
    let mut buf = ParseBuf::new();
    let mut layers = buf.for_packet();
    let mut context = ParseContext::new(link_type);
    let mut remaining = data;
    while !remaining.is_empty() {
        let Some(parser) = registry.find_parser(&context) else {
            break;
        };
        let before = layers.len();
        let result = layers.parse_layer(parser, remaining, &context, None);
        // An error without fields is not a layer; any error ends the walk.
        if layers.len() > before {
            chain.push((
                parser.name(),
                context.encap_depth,
                context.current_tunnel_type(),
                context.current_tunnel_id(),
            ));
        }
        if !result.is_ok() {
            break;
        }
        if let Some(tunnel_type) = result.hint(HintKey::TunnelType) {
            context.push_tunnel(
                TunnelType::from_u64(tunnel_type),
                result.hint(HintKey::TunnelId),
            );
        }
        context.parent_protocol = Some(parser.name());
        context.hints = result.child_hints;
        context.offset += remaining.len() - result.remaining.len();
        remaining = result.remaining;
    }
    chain
}

/// The layers of `data` as `parse_packet` gives them.
pub fn dispatched_chain(
    registry: &ProtocolRegistry,
    link_type: u16,
    data: &[u8],
) -> Vec<ChainLayer> {
    let mut buf = ParseBuf::new();
    let layers = parse_packet(registry, link_type, data, &ParseScope::full(), &mut buf);
    let chain = layers.iter().map(|layer| {
        (
            layer.name(),
            layer.encap_depth(),
            layer.tunnel_type(),
            layer.tunnel_id(),
        )
    });
    chain.collect()
}

/// Panics unless `parse_packet` gives `data` the layers the full scan does.
/// Returns the number of layers.
pub fn assert_same_chain(
    registry: &ProtocolRegistry,
    link_type: u16,
    data: &[u8],
    what: &dyn std::fmt::Display,
) -> usize {
    let expected = full_scan_chain(registry, link_type, data);
    let dispatched = dispatched_chain(registry, link_type, data);
    assert_eq!(
        dispatched, expected,
        "{what} (link type {link_type}): the dispatch tables and a full scan disagree"
    );
    expected.len()
}

/// [`assert_same_chain`] for every packet `reader` delivers. Returns the
/// number of packets and of layers, for the caller to check that there were
/// some.
pub fn assert_same_chains<R: PacketReader>(
    registry: &ProtocolRegistry,
    mut reader: R,
    what: &dyn std::fmt::Display,
) -> (usize, usize) {
    let (mut packets, mut layers) = (0, 0);
    loop {
        let delivered = reader.process_packets(1024, |packet| {
            let frame = format!("{what} frame {}", packet.frame_number);
            layers += assert_same_chain(registry, packet.link_type, packet.data, &frame);
            packets += 1;
            Ok(())
        });
        // A capture that cannot be read further ends there.
        if !matches!(delivered, Ok(n) if n > 0) {
            return (packets, layers);
        }
    }
}
