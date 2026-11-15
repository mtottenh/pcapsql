//! The driver: one partition of a scan, read step by step.
//!
//! **Unstable API** (see the [module](super) documentation).
//!
//! A [`PartitionScan`] owns the reader of one partition (a whole capture, or
//! one [`PacketRange`](crate::io::PacketRange) of it) and the partition's
//! [`Router`]. [`PartitionScan::step`] reads packets, parses each with the
//! compiled plan's scope and routes its rows into the caller's sinks, until
//! there is something for the caller to do. The scan can be resumed after
//! every step, so the same driver serves both kinds of engine:
//!
//! - a **push** engine (DataFusion) loops over `step`, hands the rows of a
//!   [`Step::Flush`] to its consumer, and does its own bookkeeping (progress,
//!   time-based flushes) between steps;
//! - a **pull** engine (DuckDB) calls `step` once per output chunk it is
//!   asked for, with the chunk as the sink, and returns to its caller on
//!   `Flush`.
//!
//! ```ignore
//! let mut scan = PartitionScan::new(reader, plan, registry);
//! loop {
//!     match scan.step(&mut sinks, 1024)? {
//!         Step::More => {}
//!         Step::Flush(output) => { /* take the rows of sinks[output.0] */ }
//!         Step::Done | Step::End => break,
//!     }
//! }
//! ```
//!
//! # What a step guarantees
//!
//! - **No sink is overfilled.** A sink that reported
//!   [`Full`](super::Full) is not written to again before `step` has
//!   returned [`Step::Flush`] for it.
//! - **No row is lost and none is written twice.** A frame whose rows do not
//!   all fit (a tunnelled packet has several rows in one table) is left with
//!   the reader ([`Pause::Before`]); the next step is shown the same packet,
//!   parses it again and writes the rows that are still missing. A frame may
//!   have more rows than a sink holds.
//! - **Side effects happen once per frame.** The [`FrameObserver`] sees a
//!   frame once, however often it is shown; [`ScanStats::packets`] counts
//!   the packets the reader consumed.
//!
//! # The frame predicate
//!
//! The plan's [`FramePredicate`](super::FramePredicate)
//! ([`CompiledScan::frames`]) is enforced here, exactly: a packet gives rows
//! if and only if the predicate accepts it. A packet it rejects is consumed
//! from the reader and nothing else: it is not parsed, not routed, not shown
//! to the [`FrameObserver`] and not counted against a row cap. (An observer
//! therefore sees the accepted frames only. Stream reassembly needs every
//! packet, and
//! [`ScanPlan::compile`](super::ScanPlan::compile) refuses a plan that has
//! both stream tables and a frame predicate.)
//!
//! Frame numbers ascend within a partition, so the scan ends
//! ([`Step::End`]) as soon as no later frame can match: after consuming the
//! last frame the upper frame bound admits, without reading the one behind
//! it (on a live capture that packet may never come). Timestamps need not
//! ascend, so a time bound never ends a scan: it is checked packet by
//! packet to the end of the partition. A predicate nothing can satisfy
//! ([`FramePredicate::is_empty`](super::FramePredicate::is_empty)) ends the
//! scan before the first read.
//!
//! When the predicate is [all](super::FramePredicate::all) the packet loop
//! tests one flag per packet and is otherwise what it was without a
//! predicate.

use std::ops::ControlFlow;
use std::sync::Arc;

use super::plan::{CompiledScan, OutputId};
use super::route::{Routed, Router};
use super::sink::RowSink;
use crate::io::{PacketReader, PacketRef, Pause};
use crate::protocol::{parse_packet_into, LayerBuf};
use crate::{Error, ParseResult, ProtocolRegistry};

/// Why [`PartitionScan::step`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Step {
    /// The packets asked for were consumed (or all the reader had at hand),
    /// and no output is waiting. Call `step` again.
    More,
    /// The rows of this output must be taken out of its sink now: the sink
    /// is full, or the output reached its row cap and its sink holds its
    /// last rows (possibly none). Empty the sink, then call `step` again:
    /// the scan writes to the sink again as soon as `step` is re-entered.
    Flush(OutputId),
    /// Every output reached its row cap or was closed, and the observer
    /// wants no further frame: nothing the scan could still produce would be
    /// seen. The rest of the partition was not read.
    Done,
    /// The end of the partition, or of the frames the plan's
    /// [frame predicate](CompiledScan::frames) can accept in it (the rest of
    /// the partition was not read). The sinks may hold rows that never
    /// filled them.
    End,
}

/// What a partition scan has read and written so far.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanStats {
    /// Packets consumed from the reader: those the scan produced rows
    /// from and those the frame predicate rejected
    /// ([`skipped`](Self::skipped)). It is how far the reader has got, which
    /// is what progress reporting wants, and what the scan cost in I/O. With
    /// an inclusive upper frame bound `n`, on a partition starting at frame
    /// `s`, it never exceeds `n - s + 1`.
    pub packets: u64,
    /// Of [`packets`](Self::packets), those the plan's frame predicate
    /// rejected: read, but not parsed. `packets - skipped` frames were
    /// accepted. Always 0 without a frame predicate.
    pub skipped: u64,
    /// The earliest timestamp of an accepted packet, in nanoseconds;
    /// `i64::MAX` before the first one.
    pub min_ts_ns: i64,
    /// The latest timestamp of an accepted packet, in nanoseconds;
    /// `i64::MIN` before the first one.
    pub max_ts_ns: i64,
    /// Rows written per output, indexed by [`OutputId`].
    pub rows: Box<[u64]>,
}

impl ScanStats {
    fn new(outputs: usize) -> Self {
        Self {
            packets: 0,
            skipped: 0,
            min_ts_ns: i64::MAX,
            max_ts_ns: i64::MIN,
            rows: vec![0; outputs].into(),
        }
    }

    /// The `[earliest, latest]` timestamp of the accepted packets in
    /// nanoseconds, once there is one.
    pub fn time_range_ns(&self) -> Option<(i64, i64)> {
        (self.min_ts_ns <= self.max_ts_ns).then_some((self.min_ts_ns, self.max_ts_ns))
    }
}

impl Default for ScanStats {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Sees every frame of a partition scan that the plan's frame predicate
/// accepts (every frame, when there is none) once, parsed, before its rows
/// are routed: the hook for what a frontend derives from frames besides the
/// routed rows (stream reassembly).
///
/// It is a type parameter of [`PartitionScan`], so the call is static and a
/// scan without an observer ([`NoObserver`]) pays nothing for the hook. The
/// scan owns the observer; [`PartitionScan::observer_mut`] reaches it
/// between steps and [`PartitionScan::finish`] gives it back.
pub trait FrameObserver {
    /// What [`observe`](Self::observe) fails with, and with it
    /// [`PartitionScan::step`]: the frontend's own error type, so that a
    /// failure of what it derives from the frames reaches it as it was
    /// raised. A reader's error ([`enum@Error`]) converts into it.
    type Error: From<Error>;

    /// `packet` and its parsed `layers`, in the order
    /// [`parse_packet`](crate::parse_packet) returns them (parsed with the
    /// plan's scope).
    ///
    /// Called exactly once per frame, in capture order, also for a frame
    /// that is shown to the scan several times because its rows did not fit
    /// the sinks. An error stops the scan: [`PartitionScan::step`] returns
    /// it, with the frame consumed.
    fn observe(
        &mut self,
        packet: &PacketRef<'_>,
        layers: &[(&'static str, ParseResult<'_>)],
    ) -> Result<(), Self::Error>;

    /// Whether the observer still needs frames once every routed output is
    /// done. While it does, the scan does not report [`Step::Done`]. It is
    /// asked at the start of each step, not per frame.
    fn wants_frames(&self) -> bool {
        true
    }
}

/// The observer of a scan that has none.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoObserver;

impl FrameObserver for NoObserver {
    type Error = Error;

    #[inline(always)]
    fn observe(
        &mut self,
        _packet: &PacketRef<'_>,
        _layers: &[(&'static str, ParseResult<'_>)],
    ) -> Result<(), Error> {
        Ok(())
    }

    #[inline(always)]
    fn wants_frames(&self) -> bool {
        false
    }
}

/// One partition of a compiled scan, read step by step. See the
/// [module](self) documentation.
///
/// The outputs it writes are the plan's per-packet outputs (what a
/// [`Router`] routes): `frames`, the protocol tables and the fused joins.
/// Stream tables are not built here yet; a frontend that has them builds
/// them in its [`FrameObserver`].
pub struct PartitionScan<R: PacketReader, O: FrameObserver = NoObserver> {
    reader: R,
    plan: Arc<CompiledScan>,
    registry: Arc<ProtocolRegistry>,
    router: Router,
    observer: O,
    /// Storage for the layers of the packet being routed, reused from one
    /// packet to the next.
    layers: LayerBuf,
    /// The number of the last frame the observer saw (frames are numbered
    /// from 1). A frame shown again has this number.
    observed_frame: u64,
    /// The plan has a frame predicate other than `all`.
    filtered: bool,
    /// The frame predicate accepts no further frame of the partition.
    ended: bool,
    stats: ScanStats,
}

impl<R: PacketReader> PartitionScan<R> {
    /// A scan of what `reader` delivers: a whole capture, or one range of
    /// it. `registry` must be the one `plan` was compiled for.
    pub fn new(reader: R, plan: Arc<CompiledScan>, registry: Arc<ProtocolRegistry>) -> Self {
        Self::with_observer(reader, plan, registry, NoObserver)
    }
}

impl<R: PacketReader, O: FrameObserver> PartitionScan<R, O> {
    /// [`new`](PartitionScan::new), with an observer that is shown every
    /// frame once.
    pub fn with_observer(
        reader: R,
        plan: Arc<CompiledScan>,
        registry: Arc<ProtocolRegistry>,
        observer: O,
    ) -> Self {
        let router = Router::new(&plan);
        let stats = ScanStats::new(plan.outputs().len());
        let filtered = !plan.frames().is_all();
        let ended = plan.frames().is_empty();
        Self {
            reader,
            plan,
            registry,
            router,
            observer,
            layers: LayerBuf::new(),
            observed_frame: 0,
            filtered,
            ended,
            stats,
        }
    }

    /// Read and route packets until an output must be taken
    /// ([`Step::Flush`]), `max_packets` were consumed ([`Step::More`]),
    /// nothing more is wanted ([`Step::Done`]) or the partition ends
    /// ([`Step::End`]). Packets the plan's frame predicate rejects are
    /// consumed (they count towards `max_packets`) and give no rows; the
    /// partition also ends where the predicate accepts no later frame.
    ///
    /// `sinks[i]` is the sink of output `i` of the plan
    /// ([`CompiledScan::outputs`]). On `Flush`, empty that output's sink
    /// before the next call. When several outputs are waiting, each call
    /// returns one of them, before any packet is read.
    ///
    /// An error is the reader's (the scan can be stepped again when the
    /// reader can be read again, as after a read timeout), as the
    /// observer's error type, or the observer's own.
    ///
    /// # Panics
    ///
    /// If `sinks` is shorter than the outputs a frame has rows for.
    #[inline]
    pub fn step<S: RowSink>(
        &mut self,
        sinks: &mut [S],
        max_packets: usize,
    ) -> Result<Step, O::Error> {
        if let Some(output) = self.router.take_flush() {
            return Ok(Step::Flush(output));
        }
        if self.ended {
            return Ok(Step::End);
        }
        if self.router.all_done() && !self.observer.wants_frames() {
            return Ok(Step::Done);
        }
        if max_packets == 0 {
            return Ok(Step::More);
        }

        let Self {
            reader,
            plan,
            registry,
            router,
            observer,
            layers,
            observed_frame,
            filtered,
            ended,
            stats,
        } = self;
        let scope = plan.scope();
        let frames = plan.frames();
        let filtered = *filtered;
        let mut failed = None;
        let delivered = reader.process_packets_flow(max_packets, |packet| {
            // True when the frame after this one cannot match either: the
            // scan ends once this one is consumed.
            let mut last = false;
            if filtered {
                if frames.past_end(packet.frame_number) {
                    // Frame numbers ascend: nothing from here on matches.
                    // (Only the first packet of a partition gets here; later
                    // ones are stopped by `last` below.)
                    *ended = true;
                    return ControlFlow::Break(Pause::Before);
                }
                last = packet
                    .frame_number
                    .checked_add(1)
                    .is_none_or(|next| frames.past_end(next));
                if !frames.accepts(&packet) {
                    stats.skipped += 1;
                    if last {
                        *ended = true;
                        return ControlFlow::Break(Pause::After);
                    }
                    return ControlFlow::Continue(());
                }
            }
            // Per-packet link type is correct even for PCAPNG multi-interface.
            let mut layers = layers.for_packet();
            parse_packet_into(registry, packet.link_type, packet.data, scope, &mut layers);
            if packet.frame_number != *observed_frame {
                // The first time this frame is shown.
                *observed_frame = packet.frame_number;
                stats.min_ts_ns = stats.min_ts_ns.min(packet.timestamp_ns);
                stats.max_ts_ns = stats.max_ts_ns.max(packet.timestamp_ns);
                if let Err(error) = observer.observe(&packet, &layers) {
                    failed = Some(error);
                    return ControlFlow::Break(Pause::After);
                }
            }
            match router.route_frame(sinks, &packet, &layers) {
                // Rows of the frame are waiting for a full sink: the reader
                // keeps the packet and shows it again.
                Routed::Redeliver => ControlFlow::Break(Pause::Before),
                Routed::Consumed if last => {
                    *ended = true;
                    ControlFlow::Break(Pause::After)
                }
                Routed::Consumed if router.has_flush() => ControlFlow::Break(Pause::After),
                Routed::Consumed => ControlFlow::Continue(()),
            }
        })?;
        stats.packets += delivered.consumed as u64;
        for (index, rows) in stats.rows.iter_mut().enumerate() {
            *rows = router.rows(OutputId(index as u16));
        }
        if let Some(error) = failed {
            return Err(error);
        }
        if let Some(output) = router.take_flush() {
            return Ok(Step::Flush(output));
        }
        if *ended || (delivered.consumed == 0 && delivered.paused.is_none()) {
            return Ok(Step::End);
        }
        Ok(Step::More)
    }

    /// The consumer of `output` is gone: write nothing more to it. Rows its
    /// sink still holds are the caller's to drop.
    pub fn close_output(&mut self, output: OutputId) {
        self.router.close_output(output);
    }

    /// True when `output` takes no further row: it reached its row cap or
    /// was closed.
    pub fn output_done(&self, output: OutputId) -> bool {
        self.router.is_done(output)
    }

    /// The plan being scanned.
    pub fn plan(&self) -> &Arc<CompiledScan> {
        &self.plan
    }

    /// The partition's reader.
    pub fn reader(&self) -> &R {
        &self.reader
    }

    /// The partition's reader, to set a read timeout or to ask why a step
    /// failed ([`PacketReader::take_read_timeout`]).
    pub fn reader_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    /// The scan's observer.
    pub fn observer(&self) -> &O {
        &self.observer
    }

    /// The scan's observer, between steps.
    pub fn observer_mut(&mut self) -> &mut O {
        &mut self.observer
    }

    /// What was read and written so far, as of the last step.
    pub fn stats(&self) -> &ScanStats {
        &self.stats
    }

    /// End the scan: its statistics and its observer.
    pub fn finish(self) -> (ScanStats, O) {
        (self.stats, self.observer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::{Delivered, PacketPosition};
    use crate::scan::testing::{Cell, RecordingSink};
    use crate::scan::{Catalog, FramePredicate, ScanPlan, TableScan};
    use std::ops::Bound;

    /// A reader over frames held in memory.
    struct Frames {
        frames: Vec<Vec<u8>>,
        next: usize,
        /// Fail the read before this frame index, once.
        fail_before: Option<usize>,
        /// The highest frame number shown to a callback.
        shown: u64,
    }

    /// Ethernet/IPv4/UDP to `port` around `payload`.
    fn udp_frame(i: u8, port: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x08, 0x00];
        p.extend_from_slice(&[0x45, 0]);
        p.extend_from_slice(&(28 + payload.len() as u16).to_be_bytes());
        p.extend_from_slice(&[0, i, 0x40, 0, 64, 17, 0, 0]);
        p.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        p.extend_from_slice(&[0x30, i]);
        p.extend_from_slice(&port.to_be_bytes());
        p.extend_from_slice(&(8 + payload.len() as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(payload);
        p
    }

    /// One row per table.
    fn frame(i: u8) -> Vec<u8> {
        udp_frame(i, 9999, &[])
    }

    /// [`frame`] inside VXLAN: two rows in `ethernet`.
    fn tunnelled(i: u8) -> Vec<u8> {
        let mut vxlan = vec![0x08, 0, 0, 0, 0, 0, i, 0];
        vxlan.extend_from_slice(&frame(i));
        udp_frame(i, 4789, &vxlan)
    }

    impl Frames {
        fn new(count: u8) -> Self {
            Self {
                frames: (0..count).map(frame).collect(),
                next: 0,
                fail_before: None,
                shown: 0,
            }
        }
    }

    impl PacketReader for Frames {
        fn process_packets_flow<F>(&mut self, max: usize, mut f: F) -> Result<Delivered, Error>
        where
            F: FnMut(PacketRef<'_>) -> ControlFlow<Pause>,
        {
            let mut consumed = 0;
            while consumed < max && self.next < self.frames.len() {
                if self.fail_before == Some(self.next) {
                    if consumed > 0 {
                        break;
                    }
                    self.fail_before = None;
                    return Err(Error::Io(std::io::Error::other("no input")));
                }
                let data = &self.frames[self.next];
                let packet = PacketRef {
                    frame_number: self.next as u64 + 1,
                    timestamp_ns: 1_000 * (self.next as i64 + 1),
                    captured_len: data.len() as u32,
                    original_len: data.len() as u32,
                    link_type: 1,
                    data,
                };
                self.shown = self.shown.max(packet.frame_number);
                match f(packet) {
                    ControlFlow::Continue(()) => {
                        self.next += 1;
                        consumed += 1;
                    }
                    ControlFlow::Break(Pause::After) => {
                        self.next += 1;
                        return Ok(Delivered {
                            consumed: consumed + 1,
                            paused: Some(Pause::After),
                        });
                    }
                    ControlFlow::Break(Pause::Before) => {
                        return Ok(Delivered {
                            consumed,
                            paused: Some(Pause::Before),
                        });
                    }
                }
            }
            Ok(Delivered {
                consumed,
                paused: None,
            })
        }

        fn position(&self) -> PacketPosition {
            PacketPosition {
                byte_offset: 0,
                frame_number: self.next as u64,
            }
        }

        fn link_type(&self) -> u32 {
            1
        }
    }

    fn plan(tables: &[(&str, Option<u64>)]) -> Arc<CompiledScan> {
        plan_of(tables, FramePredicate::all())
    }

    fn plan_of(tables: &[(&str, Option<u64>)], frames: FramePredicate) -> Arc<CompiledScan> {
        let catalog = Catalog::builtin();
        let tables = tables
            .iter()
            .map(|(name, fetch)| {
                let (id, def) = catalog.table(name).unwrap();
                TableScan {
                    table: id,
                    columns: vec![def.column("frame_number").unwrap().0],
                    predicate: None,
                    fetch: *fetch,
                }
            })
            .collect();
        let plan = ScanPlan {
            tables,
            frames,
            ..Default::default()
        };
        Arc::new(plan.compile(catalog, &crate::default_registry()).unwrap())
    }

    fn frame_range(lower: Bound<u64>, upper: Bound<u64>) -> FramePredicate {
        FramePredicate {
            frames: (lower, upper),
            ..FramePredicate::all()
        }
    }

    /// A scan of `count` frames with a frame predicate and an observer.
    fn filtered(
        count: u8,
        tables: &[(&str, Option<u64>)],
        frames: FramePredicate,
    ) -> PartitionScan<Frames, Seen> {
        PartitionScan::with_observer(
            Frames::new(count),
            plan_of(tables, frames),
            Arc::new(crate::default_registry()),
            Seen::default(),
        )
    }

    fn sinks(plan: &CompiledScan, capacity: Option<usize>) -> Vec<RecordingSink> {
        plan.outputs()
            .iter()
            .map(|o| RecordingSink::new(&o.columns, capacity))
            .collect()
    }

    fn numbers(rows: Vec<Vec<Cell>>) -> Vec<u64> {
        rows.into_iter()
            .map(|row| match row[0] {
                Cell::U64(n) => n,
                ref other => panic!("frame_number is {other:?}"),
            })
            .collect()
    }

    /// Counts what it is shown.
    #[derive(Default)]
    struct Seen {
        frames: Vec<u64>,
        fail_at: Option<u64>,
        until: Option<u64>,
    }

    impl FrameObserver for Seen {
        type Error = Error;

        fn observe(
            &mut self,
            packet: &PacketRef<'_>,
            _layers: &[(&'static str, ParseResult<'_>)],
        ) -> Result<(), Error> {
            self.frames.push(packet.frame_number);
            if self.fail_at == Some(packet.frame_number) {
                return Err(Error::Io(std::io::Error::other("observer")));
            }
            Ok(())
        }

        fn wants_frames(&self) -> bool {
            self.until
                .is_none_or(|until| self.frames.last().is_none_or(|last| *last < until))
        }
    }

    fn scan(count: u8, tables: &[(&str, Option<u64>)]) -> PartitionScan<Frames> {
        PartitionScan::new(
            Frames::new(count),
            plan(tables),
            Arc::new(crate::default_registry()),
        )
    }

    #[test]
    fn steps_report_more_then_end() {
        let mut scan = scan(5, &[("frames", None)]);
        let mut sinks = sinks(scan.plan(), None);
        assert_eq!(scan.step(&mut sinks, 0).unwrap(), Step::More);
        assert_eq!(scan.stats().packets, 0);
        assert_eq!(scan.stats().time_range_ns(), None);
        assert_eq!(scan.step(&mut sinks, 2).unwrap(), Step::More);
        assert_eq!(scan.stats().packets, 2);
        assert_eq!(scan.step(&mut sinks, 2).unwrap(), Step::More);
        // Fewer than asked for, and not the end yet.
        assert_eq!(scan.step(&mut sinks, 2).unwrap(), Step::More);
        assert_eq!(scan.stats().packets, 5);
        assert_eq!(scan.step(&mut sinks, 2).unwrap(), Step::End);
        assert_eq!(scan.step(&mut sinks, 2).unwrap(), Step::End);
        assert_eq!(numbers(sinks[0].take_rows()), [1, 2, 3, 4, 5]);
        let (stats, NoObserver) = scan.finish();
        assert_eq!(stats.packets, 5);
        assert_eq!(stats.time_range_ns(), Some((1_000, 5_000)));
        assert_eq!(*stats.rows, [5]);
    }

    #[test]
    fn a_full_sink_is_flushed_before_it_is_written_again() {
        let mut scan = scan(5, &[("frames", None), ("ethernet", None)]);
        let mut sinks = sinks(scan.plan(), Some(2));
        let mut rows = [Vec::new(), Vec::new()];
        let mut flushes = 0;
        loop {
            match scan.step(&mut sinks, usize::MAX).unwrap() {
                Step::Flush(OutputId(output)) => {
                    let sink = &mut sinks[usize::from(output)];
                    assert!(sink.is_full());
                    rows[usize::from(output)].extend(numbers(sink.take_rows()));
                    flushes += 1;
                }
                Step::More => {}
                Step::End => break,
                Step::Done => panic!("nothing is capped"),
            }
        }
        // Both sinks fill on frames 2 and 4: each is reported on its own.
        assert_eq!(flushes, 4);
        for (i, sink) in sinks.iter_mut().enumerate() {
            rows[i].extend(numbers(sink.take_rows()));
            assert_eq!(rows[i], [1, 2, 3, 4, 5]);
        }
        assert_eq!(scan.stats().packets, 5);
        assert_eq!(*scan.stats().rows, [5, 5]);
    }

    #[test]
    fn row_caps_end_the_scan_with_done() {
        let mut scan = scan(9, &[("frames", Some(3)), ("ethernet", Some(1))]);
        let mut sinks = sinks(scan.plan(), None);
        // Each output is handed out when it reaches its cap, partly filled.
        assert_eq!(
            scan.step(&mut sinks, 100).unwrap(),
            Step::Flush(OutputId(1))
        );
        assert_eq!(numbers(sinks[1].take_rows()), [1]);
        assert!(scan.output_done(OutputId(1)));
        assert!(!scan.output_done(OutputId(0)));
        assert_eq!(
            scan.step(&mut sinks, 100).unwrap(),
            Step::Flush(OutputId(0))
        );
        assert_eq!(numbers(sinks[0].take_rows()), [1, 2, 3]);
        // The scan stops at the frame that reached the last cap.
        assert_eq!(scan.step(&mut sinks, 100).unwrap(), Step::Done);
        assert_eq!(scan.step(&mut sinks, 100).unwrap(), Step::Done);
        assert_eq!(scan.stats().packets, 3);
        assert_eq!(*scan.stats().rows, [3, 1]);
    }

    #[test]
    fn closing_every_output_ends_the_scan() {
        let mut scan = scan(9, &[("frames", None), ("ethernet", Some(2))]);
        let mut sinks = sinks(scan.plan(), None);
        assert_eq!(scan.step(&mut sinks, 1).unwrap(), Step::More);
        scan.close_output(OutputId(0));
        assert_eq!(scan.step(&mut sinks, 1).unwrap(), Step::Flush(OutputId(1)));
        assert_eq!(scan.step(&mut sinks, 1).unwrap(), Step::Done);
        // Nothing was written to the closed output after it was closed.
        assert_eq!(numbers(sinks[0].take_rows()), [1]);
        assert_eq!(numbers(sinks[1].take_rows()), [1, 2]);
    }

    /// The observer sees a frame once although the frame is shown to the
    /// scan once per row that did not fit, and keeps the scan going after
    /// the outputs are done for as long as it wants frames.
    #[test]
    fn the_observer_sees_each_frame_once() {
        let observer = Seen {
            until: Some(6),
            ..Default::default()
        };
        let plan = plan(&[("frames", Some(4)), ("ethernet", Some(8))]);
        let mut reader = Frames::new(0);
        reader.frames = (0..9).map(tunnelled).collect();
        let mut scan = PartitionScan::with_observer(
            reader,
            Arc::clone(&plan),
            Arc::new(crate::default_registry()),
            observer,
        );
        // A frame's second `ethernet` row does not fit: every frame that
        // has rows is shown twice.
        let mut sinks = sinks(&plan, Some(1));
        let mut flushes = 0;
        let last = loop {
            match scan.step(&mut sinks, 1).unwrap() {
                Step::Flush(OutputId(output)) => {
                    sinks[usize::from(output)].take_rows();
                    flushes += 1;
                }
                Step::More => {}
                last => break last,
            }
        };
        assert_eq!(last, Step::Done);
        // Per frame: `frames`, and `ethernet` twice.
        assert_eq!(flushes, 12);
        assert_eq!(scan.observer().frames, [1, 2, 3, 4, 5, 6]);
        let (stats, observer) = scan.finish();
        assert_eq!(stats.packets, 6);
        assert_eq!(*stats.rows, [4, 8]);
        assert_eq!(observer.frames.len(), 6);
    }

    #[test]
    fn an_observer_error_stops_the_step() {
        let observer = Seen {
            fail_at: Some(3),
            ..Default::default()
        };
        let plan = plan(&[("frames", None)]);
        let mut scan = PartitionScan::with_observer(
            Frames::new(5),
            Arc::clone(&plan),
            Arc::new(crate::default_registry()),
            observer,
        );
        let mut sinks = sinks(&plan, None);
        let error = scan.step(&mut sinks, 100).unwrap_err();
        assert!(error.to_string().contains("observer"), "{error}");
        // The frame was consumed, and not routed.
        assert_eq!(scan.stats().packets, 3);
        assert_eq!(numbers(sinks[0].take_rows()), [1, 2]);
    }

    /// An observer fails with its own error type, and the step returns that
    /// error as it was raised; a reader's error is converted into the type.
    #[test]
    fn a_step_fails_with_the_observer_s_error_type() {
        #[derive(Debug, PartialEq)]
        enum Failure {
            Observer(u64),
            Reader(String),
        }
        impl From<Error> for Failure {
            fn from(error: Error) -> Self {
                Failure::Reader(error.to_string())
            }
        }
        struct FailsAt(u64);
        impl FrameObserver for FailsAt {
            type Error = Failure;

            fn observe(
                &mut self,
                packet: &PacketRef<'_>,
                _layers: &[(&'static str, ParseResult<'_>)],
            ) -> Result<(), Failure> {
                if packet.frame_number == self.0 {
                    return Err(Failure::Observer(packet.frame_number));
                }
                Ok(())
            }
        }
        let plan = plan(&[("frames", None)]);
        let scan = |reader: Frames| {
            PartitionScan::with_observer(
                reader,
                Arc::clone(&plan),
                Arc::new(crate::default_registry()),
                FailsAt(3),
            )
        };
        let mut sinks = sinks(&plan, None);
        assert_eq!(
            scan(Frames::new(5)).step(&mut sinks, 100),
            Err(Failure::Observer(3))
        );
        let mut reader = Frames::new(5);
        reader.fail_before = Some(0);
        assert!(matches!(
            scan(reader).step(&mut sinks, 100),
            Err(Failure::Reader(_))
        ));
    }

    /// A read error leaves the scan where it was: the next step carries on.
    #[test]
    fn a_step_can_be_retried_after_a_read_error() {
        let mut scan = scan(4, &[("frames", None)]);
        scan.reader_mut().fail_before = Some(2);
        let mut sinks = sinks(scan.plan(), None);
        assert_eq!(scan.step(&mut sinks, 100).unwrap(), Step::More);
        assert_eq!(scan.stats().packets, 2);
        assert!(scan.step(&mut sinks, 100).is_err());
        assert_eq!(scan.stats().packets, 2);
        assert_eq!(scan.step(&mut sinks, 100).unwrap(), Step::More);
        assert_eq!(scan.step(&mut sinks, 100).unwrap(), Step::End);
        assert_eq!(numbers(sinks[0].take_rows()), [1, 2, 3, 4]);
        assert_eq!(scan.reader().position().frame_number, 4);
    }

    /// A frame range gives the rows of exactly its frames, to every output
    /// and to the observer; the frames before it are read and not parsed,
    /// and nothing behind its last frame is read at all.
    #[test]
    fn a_frame_range_selects_frames_and_ends_the_scan() {
        let mut scan = filtered(
            9,
            &[("frames", None), ("udp", None)],
            frame_range(Bound::Excluded(2), Bound::Included(5)),
        );
        let mut sinks = sinks(scan.plan(), None);
        assert_eq!(scan.step(&mut sinks, 100).unwrap(), Step::End);
        assert_eq!(scan.step(&mut sinks, 100).unwrap(), Step::End);
        assert_eq!(numbers(sinks[0].take_rows()), [3, 4, 5]);
        assert_eq!(numbers(sinks[1].take_rows()), [3, 4, 5]);
        // Frame 6 was never asked of the reader.
        assert_eq!(scan.reader().shown, 5);
        assert_eq!(scan.reader().position().frame_number, 5);
        let (stats, seen) = scan.finish();
        assert_eq!(seen.frames, [3, 4, 5]);
        assert_eq!((stats.packets, stats.skipped), (5, 2));
        assert_eq!(stats.time_range_ns(), Some((3_000, 5_000)));
        assert_eq!(*stats.rows, [3, 3]);
    }

    /// The upper frame bound ends the scan in whichever step reaches it,
    /// and an exclusive bound one frame earlier.
    #[test]
    fn the_upper_frame_bound_ends_the_scan_in_any_step() {
        for (upper, last) in [(Bound::Included(4), 4), (Bound::Excluded(4), 3)] {
            let mut scan = filtered(9, &[("frames", None)], frame_range(Bound::Unbounded, upper));
            let mut sinks = sinks(scan.plan(), None);
            let mut steps = 0;
            while scan.step(&mut sinks, 1).unwrap() == Step::More {
                steps += 1;
            }
            // The step that consumes the last frame reports the end.
            assert_eq!(steps, last - 1);
            assert_eq!(scan.reader().shown, last);
            assert_eq!(scan.stats().packets, last);
            assert_eq!(scan.stats().skipped, 0);
            assert_eq!(
                numbers(sinks[0].take_rows()),
                (1..=last).collect::<Vec<_>>()
            );
        }
    }

    /// The last frame of the range can also be one the time bounds reject:
    /// the scan still ends there.
    #[test]
    fn the_scan_ends_on_a_rejected_last_frame() {
        let frames = FramePredicate {
            frames: (Bound::Unbounded, Bound::Included(4)),
            time_ns: (Bound::Unbounded, Bound::Excluded(3_000)),
        };
        let mut scan = filtered(9, &[("frames", None)], frames);
        let mut sinks = sinks(scan.plan(), None);
        assert_eq!(scan.step(&mut sinks, 100).unwrap(), Step::End);
        assert_eq!(numbers(sinks[0].take_rows()), [1, 2]);
        assert_eq!(scan.reader().shown, 4);
        let (stats, seen) = scan.finish();
        assert_eq!(seen.frames, [1, 2]);
        assert_eq!((stats.packets, stats.skipped), (4, 2));
        assert_eq!(stats.time_range_ns(), Some((1_000, 2_000)));
    }

    /// Time bounds select packets and never end a scan: timestamps need not
    /// ascend, so every packet of the partition is looked at.
    #[test]
    fn a_time_range_selects_packets_to_the_end_of_the_partition() {
        let frames = FramePredicate {
            time_ns: (Bound::Included(2_000), Bound::Excluded(4_000)),
            ..FramePredicate::all()
        };
        let mut scan = filtered(6, &[("frames", None), ("ipv4", None)], frames);
        let mut sinks = sinks(scan.plan(), None);
        assert_eq!(scan.step(&mut sinks, 100).unwrap(), Step::More);
        assert_eq!(scan.step(&mut sinks, 100).unwrap(), Step::End);
        assert_eq!(numbers(sinks[0].take_rows()), [2, 3]);
        assert_eq!(numbers(sinks[1].take_rows()), [2, 3]);
        let (stats, seen) = scan.finish();
        assert_eq!(seen.frames, [2, 3]);
        assert_eq!((stats.packets, stats.skipped), (6, 4));
    }

    /// Rejected packets count towards `max_packets` (a step stays bounded)
    /// and not towards a row cap.
    #[test]
    fn rejected_packets_count_as_packets_not_as_rows() {
        let mut scan = filtered(
            9,
            &[("frames", Some(2))],
            frame_range(Bound::Included(4), Bound::Unbounded),
        );
        let mut sinks = sinks(scan.plan(), None);
        assert_eq!(scan.step(&mut sinks, 3).unwrap(), Step::More);
        assert_eq!((scan.stats().packets, scan.stats().skipped), (3, 3));
        assert_eq!(sinks[0].rows(), 0);
        assert_eq!(scan.step(&mut sinks, 3).unwrap(), Step::Flush(OutputId(0)));
        assert_eq!(numbers(sinks[0].take_rows()), [4, 5]);
        assert_eq!((scan.stats().packets, scan.stats().skipped), (5, 3));
    }

    /// A partition that starts behind the upper bound ends at its first
    /// packet, which stays with the reader.
    #[test]
    fn a_partition_behind_the_range_ends_at_once() {
        let mut scan = filtered(
            9,
            &[("frames", None)],
            frame_range(Bound::Unbounded, Bound::Included(2)),
        );
        // As if the partition started at frame 4.
        scan.reader_mut().next = 3;
        let mut sinks = sinks(scan.plan(), None);
        assert_eq!(scan.step(&mut sinks, 100).unwrap(), Step::End);
        assert_eq!(scan.step(&mut sinks, 100).unwrap(), Step::End);
        assert_eq!(sinks[0].rows(), 0);
        assert_eq!(scan.reader().position().frame_number, 3);
        let (stats, seen) = scan.finish();
        assert!(seen.frames.is_empty());
        assert_eq!((stats.packets, stats.skipped), (0, 0));
    }

    /// A predicate nothing satisfies never touches the reader.
    #[test]
    fn an_empty_predicate_reads_nothing() {
        let inverted = frame_range(Bound::Included(5), Bound::Included(3));
        let no_time = FramePredicate {
            time_ns: (Bound::Excluded(7), Bound::Excluded(8)),
            ..FramePredicate::all()
        };
        for frames in [inverted, no_time] {
            let mut scan = filtered(9, &[("frames", None)], frames);
            // A read would fail.
            scan.reader_mut().fail_before = Some(0);
            let mut sinks = sinks(scan.plan(), None);
            assert_eq!(scan.step(&mut sinks, 100).unwrap(), Step::End);
            assert_eq!(sinks[0].rows(), 0);
            assert_eq!(scan.reader().shown, 0);
            assert_eq!(scan.stats().packets, 0);
        }
    }

    /// The last frame of the range filling a sink: the rows are handed out
    /// first, the end is reported by the next step, and nothing more is
    /// read. With a tunnelled last frame whose rows do not fit, the frame
    /// is shown again until they are all written.
    #[test]
    fn the_end_of_the_range_waits_for_full_sinks() {
        let mut scan = filtered(
            9,
            &[("frames", None)],
            frame_range(Bound::Unbounded, Bound::Included(4)),
        );
        let mut sinks = sinks(scan.plan(), Some(2));
        let mut rows = Vec::new();
        for _ in 0..2 {
            assert_eq!(
                scan.step(&mut sinks, 100).unwrap(),
                Step::Flush(OutputId(0))
            );
            rows.extend(numbers(sinks[0].take_rows()));
        }
        assert_eq!(scan.step(&mut sinks, 100).unwrap(), Step::End);
        assert_eq!(rows, [1, 2, 3, 4]);
        assert_eq!(scan.reader().shown, 4);
    }

    #[test]
    fn the_end_of_the_range_waits_for_a_frame_shown_again() {
        let mut scan = filtered(
            0,
            &[("ethernet", None)],
            frame_range(Bound::Included(2), Bound::Included(3)),
        );
        scan.reader_mut().frames = (0..6).map(tunnelled).collect();
        let mut sinks = sinks(scan.plan(), Some(1));
        let mut rows = Vec::new();
        loop {
            match scan.step(&mut sinks, 100).unwrap() {
                Step::Flush(OutputId(0)) => rows.extend(numbers(sinks[0].take_rows())),
                Step::End => break,
                other => panic!("{other:?}"),
            }
        }
        rows.extend(numbers(sinks[0].take_rows()));
        assert_eq!(rows, [2, 2, 3, 3]);
        assert_eq!(scan.reader().shown, 3);
        let (stats, seen) = scan.finish();
        assert_eq!(seen.frames, [2, 3]);
        assert_eq!((stats.packets, stats.skipped), (3, 1));
    }
}
