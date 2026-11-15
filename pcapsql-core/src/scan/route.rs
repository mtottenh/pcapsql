//! Routing: which rows a frame adds to which output.
//!
//! **Unstable API** (see the [module](super) documentation).
//!
//! A [`Router`] takes one frame at a time (the packet and its parsed
//! layers) and writes the frame's rows to the sinks of a
//! [`CompiledScan`]'s outputs: the frame's row to `frames`, each layer's
//! row to the protocol table named after it, subject to the output's row
//! predicate and row cap, and the frame's joined rows to each fused join
//! ([`FusedScan`](super::FusedScan)). It is the per-partition state of a
//! scan's per-packet outputs: make one per partition.
//!
//! # Bounded sinks
//!
//! A sink reports [`Full`](super::Full) when it has no room for another row.
//! The router never writes to a sink that is full. It queues every output
//! whose rows must be taken now ([`Router::take_flush`]); the caller empties
//! those sinks and carries on. A frame can have several rows for one output
//! (a tunnelled packet has two `ipv4` layers, and as many rows in a join
//! anchored on `ipv4`), so a sink can fill in the middle of a frame.
//! [`Router::route_frame`] then returns [`Routed::Redeliver`]: the frame is
//! not finished, and the same frame must be routed again once the queued
//! outputs were emptied. The router remembers, per output, which of the
//! frame's rows it has written, and skips them: no row is lost and none is
//! written twice, however small the sinks are and however many rows a frame
//! has.
//!
//! The loop around a router is therefore:
//!
//! ```ignore
//! let routed = router.route_frame(&mut sinks, &packet, &layers);
//! while let Some(output) = router.take_flush() {
//!     // take the rows out of sinks[output.0 as usize] and hand them on
//! }
//! // Routed::Redeliver: route the same frame again
//! ```
//!
//! A consumer that hands rows on from inside the packet callback (a push
//! engine) does all of it there and loops on `Redeliver`. A consumer whose
//! caller owns the output buffer (a pull engine) cannot: it leaves the
//! packet callback with [`Pause::Before`](crate::io::Pause::Before) on
//! `Redeliver` (the reader delivers the same packet again, and it is parsed
//! again, which gives the same layers) and with
//! [`Pause::After`](crate::io::Pause::After) when the frame was consumed but
//! a flush is pending.

use super::fused::FusedState;
use super::plan::{CompiledScan, Feed, OutputId};
use super::predicate::CompiledPredicate;
use super::row::{write_frame_row, write_layer_row, FieldResolver};
use super::sink::RowSink;
use crate::io::PacketRef;
use crate::ParseResult;

/// What became of a frame given to [`Router::route_frame`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Routed {
    /// Every row of the frame is written, or not wanted: the packet is
    /// consumed. Outputs may still be waiting in [`Router::take_flush`].
    Consumed,
    /// A sink filled before all of the frame's rows were written. Empty the
    /// outputs of [`Router::take_flush`], then route the same frame again;
    /// the rows already written are skipped.
    Redeliver,
}

/// The state of one output within a partition.
#[derive(Debug)]
struct Cursor {
    feed: Feed,
    resolver: FieldResolver,
    predicate: Option<CompiledPredicate>,
    /// Rows written.
    rows: u64,
    /// The output is done when `rows >= limit`: its row cap, `u64::MAX`
    /// without one, 0 once it is closed.
    limit: u64,
    /// While a frame is being redelivered: the index of the first of its
    /// layers this output has not handled (for `frames`, 0 while its row is
    /// unwritten; for a fused join, the index of the first of the frame's
    /// joined rows). 0 otherwise.
    next: usize,
    /// The sink is full and has not been taken yet.
    blocked: bool,
    /// A row of the current frame is waiting for the blocked sink.
    stalled: bool,
    /// The output is in the flush queue.
    queued: bool,
}

impl Cursor {
    #[inline]
    fn done(&self) -> bool {
        self.rows >= self.limit
    }

    #[inline]
    fn routed(&self) -> bool {
        matches!(self.feed, Feed::Frames | Feed::Layer(_) | Feed::Fused)
    }
}

/// Routes frames to the sinks of a compiled scan's per-packet outputs:
/// `frames`, the protocol tables and the fused joins. See the
/// [module](self) documentation.
#[derive(Debug)]
pub struct Router {
    /// One per output of the plan, in the plan's order.
    outputs: Box<[Cursor]>,
    /// The `frames` output, if the plan has one.
    frames: Option<usize>,
    /// The output (if any) for each layer name seen so far. Layer names are
    /// the parsers' `&'static str`s, so a pointer compare finds the entry.
    layers: Vec<(&'static str, Option<usize>)>,
    /// The fused joins: each output's index and its join state. Empty in a
    /// plan without any, which then pays one test per frame for them.
    fused: Vec<(usize, FusedState)>,
    /// Outputs whose rows must be taken now.
    flush: Vec<u16>,
    /// The frame being redelivered.
    pending: Option<u64>,
}

impl Router {
    /// The router of one partition of `plan`.
    pub fn new(plan: &CompiledScan) -> Self {
        let outputs: Box<[Cursor]> = plan
            .outputs()
            .iter()
            .map(|output| Cursor {
                feed: output.feed(),
                resolver: FieldResolver::new(&output.columns),
                // The predicate remembers where it found each field in the
                // previous row: every partition has its own copy.
                predicate: output.predicate().cloned(),
                rows: 0,
                limit: output.fetch().unwrap_or(u64::MAX),
                next: 0,
                blocked: false,
                stalled: false,
                queued: false,
            })
            .collect();
        let frames = outputs.iter().position(|c| c.feed == Feed::Frames);
        let fused = plan
            .outputs()
            .iter()
            .enumerate()
            .filter_map(|(index, output)| Some((index, FusedState::new(output.fused()?))))
            .collect();
        Self {
            outputs,
            frames,
            layers: Vec::new(),
            fused,
            flush: Vec::new(),
            pending: None,
        }
    }

    /// Write the rows of one frame: `packet` and its parsed `layers`, in
    /// the order [`parse_packet`](crate::parse_packet) returns them.
    ///
    /// `sinks[i]` is the sink of output `i` of the plan
    /// ([`CompiledScan::outputs`]).
    ///
    /// A row is written to an output unless the output is done (it reached
    /// its row cap or was [closed](Self::close_output)) or its predicate
    /// (for a fused join, its filter) drops the row. An output whose sink
    /// reported `Full`, or that reached its row cap with this frame, is
    /// queued for [`take_flush`](Self::take_flush). Take every queued output
    /// before routing again: the router does not write to a full sink, so
    /// until then its rows cannot make progress.
    ///
    /// # Panics
    ///
    /// If `sinks` is shorter than the outputs this frame has rows for.
    // Not inlined into the packet callback of a driver. The compiler's choice
    // depended on what else was instantiated for the sink, and inlined, the
    // loop below kept less in registers: a scan of four tables ran 2% more
    // instructions. Out of line it is compiled the same whatever the plan.
    #[inline(never)]
    pub fn route_frame<S: RowSink>(
        &mut self,
        sinks: &mut [S],
        packet: &PacketRef<'_>,
        layers: &[(&'static str, ParseResult<'_>)],
    ) -> Routed {
        if self
            .pending
            .is_some_and(|frame| frame != packet.frame_number)
        {
            // The frame that was to be redelivered never came back.
            self.forget_frame();
        }
        let Self {
            outputs,
            frames,
            layers: layer_outputs,
            fused,
            flush,
            ..
        } = self;
        let mut redeliver = false;

        // `frames` is fed from the packet record, not from parse results,
        // and has no predicate (its columns are not parser fields).
        if let Some(index) = *frames {
            let out = &mut outputs[index];
            if !out.done() && out.next == 0 {
                if out.blocked {
                    out.stalled = true;
                    redeliver = true;
                } else {
                    let full = write_frame_row(&mut sinks[index], &mut out.resolver, packet);
                    out.rows += 1;
                    out.blocked = full.is_break();
                    // A full sink goes out; so does a partial one the moment
                    // the row cap is reached, since nothing will be added to
                    // it (a LIMIT on a live pipe would otherwise wait for
                    // input that is not wanted).
                    if (out.blocked || out.done()) && !out.queued {
                        out.queued = true;
                        flush.push(index as u16);
                    }
                }
            }
        }

        for (position, (name, layer)) in layers.iter().enumerate() {
            let Some(index) = output_for_layer(layer_outputs, outputs, name) else {
                continue;
            };
            let out = &mut outputs[index];
            if out.done() || position < out.next {
                continue;
            }
            if let Some(predicate) = &mut out.predicate {
                // Conservative: only a positively false comparison drops
                // the row; the engine re-checks everything kept.
                if !predicate.keeps(layer) {
                    continue;
                }
            }
            if out.blocked {
                if !out.stalled {
                    out.stalled = true;
                    out.next = position;
                }
                redeliver = true;
                continue;
            }
            let full = write_layer_row(&mut sinks[index], &mut out.resolver, packet, layer);
            out.rows += 1;
            out.blocked = full.is_break();
            if (out.blocked || out.done()) && !out.queued {
                out.queued = true;
                flush.push(index as u16);
            }
        }

        if !fused.is_empty() && route_fused(outputs, fused, flush, sinks, packet, layers) {
            redeliver = true;
        }

        if redeliver {
            // An output that is not waiting has handled the whole frame.
            for out in outputs.iter_mut() {
                if !std::mem::take(&mut out.stalled) {
                    out.next = usize::MAX;
                }
            }
            self.pending = Some(packet.frame_number);
            Routed::Redeliver
        } else {
            if self.pending.is_some() {
                self.forget_frame();
            }
            Routed::Consumed
        }
    }

    /// Drop the resume state of a redelivered frame.
    #[cold]
    fn forget_frame(&mut self) {
        self.pending = None;
        for out in self.outputs.iter_mut() {
            out.next = 0;
            out.stalled = false;
        }
    }

    /// The next output whose rows must be taken now: its sink is full, or
    /// it reached its row cap and holds its last rows (possibly none).
    /// `None` when no output is waiting. Taking an output tells the router
    /// that its sink is being emptied.
    #[inline]
    pub fn take_flush(&mut self) -> Option<OutputId> {
        let index = self.flush.pop()?;
        let out = &mut self.outputs[usize::from(index)];
        out.queued = false;
        out.blocked = false;
        Some(OutputId(index))
    }

    /// True while an output is waiting in [`take_flush`](Self::take_flush).
    #[inline]
    pub fn has_flush(&self) -> bool {
        !self.flush.is_empty()
    }

    /// The consumer of `output` is gone: write nothing more to it.
    pub fn close_output(&mut self, output: OutputId) {
        if let Some(out) = self.outputs.get_mut(usize::from(output.0)) {
            out.limit = 0;
        }
    }

    /// True when `output` takes no further row: it reached its row cap or
    /// was closed.
    pub fn is_done(&self, output: OutputId) -> bool {
        self.outputs[usize::from(output.0)].done()
    }

    /// True when every output this router feeds (`frames`, the protocol
    /// tables and the fused joins) is done, so that nothing it could still
    /// write would be observed. Also true when it feeds none.
    pub fn all_done(&self) -> bool {
        self.outputs.iter().all(|out| !out.routed() || out.done())
    }

    /// The rows written to `output` so far.
    pub fn rows(&self, output: OutputId) -> u64 {
        self.outputs[usize::from(output.0)].rows
    }
}

/// Write the frame's joined rows to the fused joins. Returns whether a row
/// is waiting for a full sink.
///
/// Kept out of line: [`Router::route_frame`] is the packet loop of every
/// scan, and a scan without a fused join never gets here.
#[inline(never)]
fn route_fused<S: RowSink>(
    outputs: &mut [Cursor],
    fused: &mut [(usize, FusedState)],
    flush: &mut Vec<u16>,
    sinks: &mut [S],
    packet: &PacketRef<'_>,
    layers: &[(&'static str, ParseResult<'_>)],
) -> bool {
    let mut redeliver = false;
    for (index, state) in fused {
        let index = *index;
        let out = &mut outputs[index];
        if out.done() || out.next == usize::MAX {
            continue;
        }
        // Evaluated again when the frame is redelivered: the same frame
        // gives the same rows, numbered the same way.
        let rows = state.join(layers);
        for row in out.next..rows {
            if !state.keeps(row, packet, layers) {
                continue;
            }
            if out.blocked {
                out.stalled = true;
                out.next = row;
                redeliver = true;
                break;
            }
            let full = state.write_row(&mut sinks[index], row, packet, layers);
            out.rows += 1;
            out.blocked = full.is_break();
            if (out.blocked || out.done()) && !out.queued {
                out.queued = true;
                flush.push(index as u16);
            }
            if out.done() {
                break;
            }
        }
    }
    redeliver
}

/// The output fed by layers named `layer`, if any.
#[inline]
fn output_for_layer(
    cache: &mut Vec<(&'static str, Option<usize>)>,
    outputs: &[Cursor],
    layer: &'static str,
) -> Option<usize> {
    if let Some((_, output)) = cache.iter().find(|(name, _)| std::ptr::eq(*name, layer)) {
        return *output;
    }
    let output = outputs.iter().position(|c| c.feed == Feed::Layer(layer));
    cache.push((layer, output));
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::testing::{Cell, RecordingSink};
    use crate::scan::{Catalog, CmpOp, RowPredicate, ScanPlan, TableScan};
    use crate::{FieldValue, TunnelType};
    use smallvec::SmallVec;

    fn packet(frame_number: u64) -> PacketRef<'static> {
        PacketRef {
            frame_number,
            timestamp_ns: 1_000 * frame_number as i64,
            captured_len: 3,
            original_len: 3,
            link_type: 1,
            data: &[1, 2, 3],
        }
    }

    fn udp(src_port: u16, depth: u8) -> ParseResult<'static> {
        let mut fields = SmallVec::new();
        fields.push(("src_port", FieldValue::UInt16(src_port)));
        ParseResult {
            fields,
            remaining: &[],
            child_hints: SmallVec::new(),
            error: None,
            encap_depth: depth,
            tunnel_type: TunnelType::None,
            tunnel_id: None,
        }
    }

    /// A scan of `tables`: each a name, its columns, and a row cap.
    fn compile(tables: &[(&str, &[&str], Option<u64>)]) -> CompiledScan {
        compile_with(tables, None)
    }

    fn compile_with(
        tables: &[(&str, &[&str], Option<u64>)],
        udp_predicate: Option<(&str, CmpOp, i64)>,
    ) -> CompiledScan {
        let catalog = Catalog::builtin();
        let tables = tables
            .iter()
            .map(|(name, columns, fetch)| {
                let (id, def) = catalog.table(name).unwrap();
                let col = |n: &&str| def.column(n).unwrap().0;
                let predicate = udp_predicate
                    .filter(|_| *name == "udp")
                    .map(|(column, op, value)| RowPredicate::cmp(col(&column), op, value));
                TableScan {
                    table: id,
                    columns: columns.iter().map(col).collect(),
                    predicate,
                    fetch: *fetch,
                }
            })
            .collect();
        let plan = ScanPlan {
            tables,
            ..Default::default()
        };
        plan.compile(catalog, &crate::default_registry()).unwrap()
    }

    fn sinks(plan: &CompiledScan, capacity: Option<usize>) -> Vec<RecordingSink> {
        plan.outputs()
            .iter()
            .map(|o| RecordingSink::new(&o.columns, capacity))
            .collect()
    }

    /// Route `frames` (each a frame number and its layers), taking rows out
    /// of the sinks whenever the router asks. Returns the rows per output
    /// and the number of redeliveries.
    fn run(
        plan: &CompiledScan,
        capacity: Option<usize>,
        frames: &[(u64, Vec<(&'static str, ParseResult<'static>)>)],
    ) -> (Vec<Vec<Vec<Cell>>>, usize, Router) {
        let mut router = Router::new(plan);
        let mut sinks = sinks(plan, capacity);
        let mut rows = vec![Vec::new(); sinks.len()];
        let mut redeliveries = 0;
        for (frame_number, layers) in frames {
            loop {
                let routed = router.route_frame(&mut sinks, &packet(*frame_number), layers);
                // Every full sink is queued.
                assert!(router.has_flush() || !sinks.iter().any(RecordingSink::is_full));
                while let Some(output) = router.take_flush() {
                    let i = usize::from(output.0);
                    rows[i].extend(sinks[i].take_rows());
                }
                assert!(sinks.iter().all(|s| !s.is_full()), "a full sink is queued");
                match routed {
                    Routed::Consumed => break,
                    Routed::Redeliver => redeliveries += 1,
                }
            }
        }
        for (i, sink) in sinks.iter_mut().enumerate() {
            rows[i].extend(sink.take_rows());
        }
        (rows, redeliveries, router)
    }

    const UDP: &str = "udp";
    const ETHERNET: &str = "ethernet";

    /// Frames with 1, 3, 0 and 2 `udp` layers.
    fn frames() -> Vec<(u64, Vec<(&'static str, ParseResult<'static>)>)> {
        vec![
            (1, vec![(ETHERNET, udp(0, 0)), (UDP, udp(10, 0))]),
            (
                2,
                vec![
                    (UDP, udp(20, 0)),
                    (ETHERNET, udp(0, 0)),
                    (UDP, udp(21, 1)),
                    (UDP, udp(22, 2)),
                ],
            ),
            (3, vec![(ETHERNET, udp(0, 0))]),
            (4, vec![(UDP, udp(40, 0)), (UDP, udp(41, 1))]),
        ]
    }

    fn udp_row(frame: u64, port: u16) -> Vec<Cell> {
        vec![Cell::U64(frame), Cell::U16(port)]
    }

    #[test]
    fn layers_go_to_their_tables_and_frames_gets_one_row_each() {
        let plan = compile(&[
            ("frames", &["frame_number", "length"], None),
            ("udp", &["frame_number", "src_port"], None),
        ]);
        let (rows, redeliveries, router) = run(&plan, None, &frames());
        assert_eq!(redeliveries, 0);
        assert_eq!(
            rows[0],
            (1..=4)
                .map(|n| vec![Cell::U64(n), Cell::U32(3)])
                .collect::<Vec<_>>()
        );
        assert_eq!(
            rows[1],
            vec![
                udp_row(1, 10),
                udp_row(2, 20),
                udp_row(2, 21),
                udp_row(2, 22),
                udp_row(4, 40),
                udp_row(4, 41),
            ]
        );
        assert_eq!(router.rows(OutputId(0)), 4);
        assert_eq!(router.rows(OutputId(1)), 6);
        assert!(!router.all_done());
    }

    /// Whatever the sinks' capacity, the rows are those of unbounded sinks,
    /// in order; a sink that fills in the middle of a frame costs a
    /// redelivery.
    #[test]
    fn any_capacity_yields_the_unbounded_rows() {
        let plan = compile(&[
            ("frames", &["frame_number", "length"], None),
            ("udp", &["frame_number", "src_port"], None),
        ]);
        let (expected, _, _) = run(&plan, None, &frames());
        for capacity in 1..=8 {
            let (rows, redeliveries, _) = run(&plan, Some(capacity), &frames());
            assert_eq!(rows, expected, "capacity {capacity}");
            let expected_redeliveries = match capacity {
                // Frame 2: full after each of its first two rows. Frame 4:
                // after its first.
                1 => 3,
                // Full after frame 2's first row (the sink held one), or
                // after its second.
                2 | 3 => 1,
                // Full after frame 4's first row.
                5 => 1,
                // The sink fills with the last row of a frame, or not at
                // all.
                _ => 0,
            };
            assert_eq!(redeliveries, expected_redeliveries, "capacity {capacity}");
        }
    }

    /// A frame with far more rows than the sink holds spans many drains.
    #[test]
    fn a_frame_with_more_rows_than_the_sink_holds() {
        let plan = compile(&[("udp", &["frame_number", "src_port"], None)]);
        let layers: Vec<_> = (0..100).map(|i| (UDP, udp(i, 0))).collect();
        let frames = vec![(7, layers), (8, vec![(UDP, udp(1000, 0))])];
        let (expected, _, _) = run(&plan, None, &frames);
        assert_eq!(expected[0].len(), 101);
        for capacity in [1, 2, 3, 7, 99, 100, 101] {
            let (rows, redeliveries, _) = run(&plan, Some(capacity), &frames);
            assert_eq!(rows, expected, "capacity {capacity}");
            // One redelivery per drain that leaves rows of frame 7 unwritten.
            assert_eq!(redeliveries, 99 / capacity, "capacity {capacity}");
        }
    }

    #[test]
    fn predicate_drops_rows_before_they_reach_the_sink() {
        let plan = compile_with(
            &[("udp", &["frame_number", "src_port"], None)],
            Some(("src_port", CmpOp::GtEq, 21)),
        );
        let expected = vec![
            udp_row(2, 21),
            udp_row(2, 22),
            udp_row(4, 40),
            udp_row(4, 41),
        ];
        for capacity in [None, Some(1), Some(2), Some(3)] {
            let (rows, _, router) = run(&plan, capacity, &frames());
            assert_eq!(rows[0], expected, "capacity {capacity:?}");
            assert_eq!(router.rows(OutputId(0)), 4);
        }
    }

    /// A capped output stops in the middle of a frame, is queued at once
    /// with its partial rows, and is done.
    #[test]
    fn row_cap_stops_an_output_and_queues_it() {
        let plan = compile(&[
            ("frames", &["frame_number"], Some(3)),
            ("udp", &["frame_number", "src_port"], Some(2)),
        ]);
        for capacity in [None, Some(1), Some(2), Some(5)] {
            let (rows, _, router) = run(&plan, capacity, &frames());
            assert_eq!(rows[0].len(), 3, "capacity {capacity:?}");
            assert_eq!(rows[1], vec![udp_row(1, 10), udp_row(2, 20)]);
            assert!(router.is_done(OutputId(0)) && router.is_done(OutputId(1)));
            assert!(router.all_done());
        }

        // The cap is reached on frame 2: the output is queued then, not at
        // the end of the pass.
        let mut router = Router::new(&plan);
        let mut sinks = sinks(&plan, None);
        let frames = frames();
        assert_eq!(
            router.route_frame(&mut sinks, &packet(1), &frames[0].1),
            Routed::Consumed
        );
        assert_eq!(router.take_flush(), None);
        assert_eq!(
            router.route_frame(&mut sinks, &packet(2), &frames[1].1),
            Routed::Consumed
        );
        assert_eq!(router.take_flush(), Some(OutputId(1)));
        assert_eq!(router.take_flush(), None);
        assert!(router.is_done(OutputId(1)));
        assert!(!router.all_done());
    }

    #[test]
    fn a_zero_row_cap_writes_nothing() {
        let plan = compile(&[("udp", &["src_port"], Some(0))]);
        let (rows, redeliveries, router) = run(&plan, Some(1), &frames());
        assert!(rows[0].is_empty());
        assert_eq!(redeliveries, 0);
        assert!(router.all_done());
    }

    /// A closed output takes no further row, also when one of its rows was
    /// waiting for a redelivery.
    #[test]
    fn a_closed_output_is_skipped() {
        let plan = compile(&[
            ("frames", &["frame_number"], None),
            ("udp", &["frame_number", "src_port"], None),
        ]);
        let mut router = Router::new(&plan);
        let mut sinks = sinks(&plan, Some(1));
        let frames = frames();
        // Frame 2 has three udp rows: the sink is full after the first.
        assert_eq!(
            router.route_frame(&mut sinks, &packet(2), &frames[1].1),
            Routed::Redeliver
        );
        let mut taken = Vec::new();
        while let Some(output) = router.take_flush() {
            taken.push(output);
            sinks[usize::from(output.0)].take_rows();
        }
        taken.sort();
        assert_eq!(taken, [OutputId(0), OutputId(1)]);
        router.close_output(OutputId(1));
        assert_eq!(
            router.route_frame(&mut sinks, &packet(2), &frames[1].1),
            Routed::Consumed
        );
        // Nothing was added: frames had its row, udp is closed.
        assert_eq!(router.take_flush(), None);
        assert_eq!(router.rows(OutputId(0)), 1);
        assert_eq!(router.rows(OutputId(1)), 1);
        assert!(!router.all_done());
        router.close_output(OutputId(0));
        assert!(router.all_done());
    }

    /// Routing again without emptying a full sink writes nothing to it and
    /// asks for the frame again: a full sink is never written to.
    #[test]
    fn an_unflushed_sink_is_not_written_to() {
        let plan = compile(&[("udp", &["frame_number", "src_port"], None)]);
        let mut router = Router::new(&plan);
        let mut sinks = sinks(&plan, Some(1));
        let frames = frames();
        assert_eq!(
            router.route_frame(&mut sinks, &packet(1), &frames[0].1),
            Routed::Consumed
        );
        assert!(router.has_flush());
        // Not taken. The next frame cannot be written.
        for _ in 0..3 {
            assert_eq!(
                router.route_frame(&mut sinks, &packet(4), &frames[3].1),
                Routed::Redeliver
            );
            assert_eq!(sinks[0].rows(), 1);
        }
        assert_eq!(router.take_flush(), Some(OutputId(0)));
        assert_eq!(sinks[0].take_rows(), vec![udp_row(1, 10)]);
        assert_eq!(
            router.route_frame(&mut sinks, &packet(4), &frames[3].1),
            Routed::Redeliver
        );
        assert_eq!(router.take_flush(), Some(OutputId(0)));
        assert_eq!(sinks[0].take_rows(), vec![udp_row(4, 40)]);
        assert_eq!(
            router.route_frame(&mut sinks, &packet(4), &frames[3].1),
            Routed::Consumed
        );
        assert_eq!(sinks[0].take_rows(), vec![udp_row(4, 41)]);
    }

    /// A frame that was to be redelivered but never came back does not
    /// leave its cursor behind for the next frame.
    #[test]
    fn an_abandoned_redelivery_is_forgotten() {
        let plan = compile(&[("udp", &["frame_number", "src_port"], None)]);
        let mut router = Router::new(&plan);
        let mut sinks = sinks(&plan, Some(2));
        let frames = frames();
        assert_eq!(
            router.route_frame(&mut sinks, &packet(2), &frames[1].1),
            Routed::Redeliver
        );
        assert_eq!(router.take_flush(), Some(OutputId(0)));
        sinks[0].take_rows();
        // Frame 4 instead of frame 2 again: both of its rows are written.
        assert_eq!(
            router.route_frame(&mut sinks, &packet(4), &frames[3].1),
            Routed::Consumed
        );
        assert_eq!(sinks[0].take_rows(), vec![udp_row(4, 40), udp_row(4, 41)]);
    }

    #[test]
    fn rows_without_columns_are_counted() {
        let plan = compile(&[("frames", &[], None), ("udp", &[], None)]);
        let (rows, _, router) = run(&plan, Some(2), &frames());
        assert_eq!(rows[0], vec![Vec::<Cell>::new(); 4]);
        assert_eq!(rows[1], vec![Vec::<Cell>::new(); 6]);
        assert_eq!(router.rows(OutputId(1)), 6);
    }
}
