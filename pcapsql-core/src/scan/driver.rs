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

use std::ops::ControlFlow;
use std::sync::Arc;

use super::plan::{CompiledScan, OutputId};
use super::route::{Routed, Router};
use super::sink::RowSink;
use crate::io::{PacketReader, PacketRef, Pause};
use crate::{parse_packet, Error, ParseResult, ProtocolRegistry};

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
    /// The end of the partition. The sinks may hold rows that never filled
    /// them.
    End,
}

/// What a partition scan has read and written so far.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanStats {
    /// Packets consumed from the reader.
    pub packets: u64,
    /// The earliest packet timestamp seen, in nanoseconds; `i64::MAX` before
    /// the first packet.
    pub min_ts_ns: i64,
    /// The latest packet timestamp seen, in nanoseconds; `i64::MIN` before
    /// the first packet.
    pub max_ts_ns: i64,
    /// Rows written per output, indexed by [`OutputId`]. Outputs the scan
    /// does not route (fused joins, for now) stay at 0.
    pub rows: Box<[u64]>,
}

impl ScanStats {
    fn new(outputs: usize) -> Self {
        Self {
            packets: 0,
            min_ts_ns: i64::MAX,
            max_ts_ns: i64::MIN,
            rows: vec![0; outputs].into(),
        }
    }

    /// The `[earliest, latest]` packet timestamp in nanoseconds, once a
    /// packet was seen.
    pub fn time_range_ns(&self) -> Option<(i64, i64)> {
        (self.min_ts_ns <= self.max_ts_ns).then_some((self.min_ts_ns, self.max_ts_ns))
    }
}

impl Default for ScanStats {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Sees every frame of a partition scan once, parsed, before its rows are
/// routed: the hook for what a frontend derives from frames besides the
/// routed rows (stream reassembly, outputs it builds itself).
///
/// It is a type parameter of [`PartitionScan`], so the call is static and a
/// scan without an observer ([`NoObserver`]) pays nothing for the hook. The
/// scan owns the observer; [`PartitionScan::observer_mut`] reaches it
/// between steps and [`PartitionScan::finish`] gives it back.
pub trait FrameObserver {
    /// `packet` and its parsed `layers`, in the order
    /// [`parse_packet`] returns them (parsed with the plan's scope).
    ///
    /// Called exactly once per frame, in capture order, also for a frame
    /// that is shown to the scan several times because its rows did not fit
    /// the sinks. An error stops the scan: [`PartitionScan::step`] returns
    /// it, with the frame consumed.
    fn observe(
        &mut self,
        packet: &PacketRef<'_>,
        layers: &[(&'static str, ParseResult<'_>)],
    ) -> Result<(), Error>;

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
/// The outputs it writes are the plan's `frames` and protocol-table outputs
/// (what a [`Router`] routes). Fused joins and stream tables are not built
/// here yet; a frontend that has them builds them in its [`FrameObserver`].
pub struct PartitionScan<R: PacketReader, O: FrameObserver = NoObserver> {
    reader: R,
    plan: Arc<CompiledScan>,
    registry: Arc<ProtocolRegistry>,
    router: Router,
    observer: O,
    /// The number of the last frame the observer saw (frames are numbered
    /// from 1). A frame shown again has this number.
    observed_frame: u64,
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
        Self {
            reader,
            plan,
            registry,
            router,
            observer,
            observed_frame: 0,
            stats,
        }
    }

    /// Read and route packets until an output must be taken
    /// ([`Step::Flush`]), `max_packets` were consumed ([`Step::More`]),
    /// nothing more is wanted ([`Step::Done`]) or the partition ends
    /// ([`Step::End`]).
    ///
    /// `sinks[i]` is the sink of output `i` of the plan
    /// ([`CompiledScan::outputs`]); a slice that stops before the fused
    /// joins will do. On `Flush`, empty that output's sink before the next
    /// call. When several outputs are waiting, each call returns one of
    /// them, before any packet is read.
    ///
    /// An error is the reader's (the scan can be stepped again when the
    /// reader can be read again, as after a read timeout) or the
    /// observer's.
    ///
    /// # Panics
    ///
    /// If `sinks` is shorter than the outputs a frame has rows for.
    #[inline]
    pub fn step<S: RowSink>(&mut self, sinks: &mut [S], max_packets: usize) -> Result<Step, Error> {
        if let Some(output) = self.router.take_flush() {
            return Ok(Step::Flush(output));
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
            observed_frame,
            stats,
        } = self;
        let scope = plan.scope();
        let mut failed = None;
        let delivered = reader.process_packets_flow(max_packets, |packet| {
            // Per-packet link type is correct even for PCAPNG multi-interface.
            let layers = parse_packet(registry, packet.link_type, packet.data, scope);
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
        if delivered.consumed == 0 && delivered.paused.is_none() {
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
    /// was closed. Always false for an output the scan does not route.
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
    use crate::scan::{Catalog, ScanPlan, TableScan};

    /// A reader over frames held in memory.
    struct Frames {
        frames: Vec<Vec<u8>>,
        next: usize,
        /// Fail the read before this frame index, once.
        fail_before: Option<usize>,
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
            ..Default::default()
        };
        Arc::new(plan.compile(catalog, &crate::default_registry()).unwrap())
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
}
