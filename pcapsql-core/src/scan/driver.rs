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
//! - **Side effects happen once per frame.** Stream reassembly sees a
//!   frame once, however often it is shown; [`ScanStats::packets`] counts
//!   the packets the reader consumed.
//!
//! # Stream tables
//!
//! A plan with [stream tables](super::TableKind::Stream) is scanned the
//! same way, as one partition. While the packets are read, the scan feeds
//! the TCP segment of every frame to stream analysis (reassembly, then the
//! TLS and HTTP stream parsers; `scan/stream.rs`); a row cap on another
//! output does not stop it. When the reader has no more packets the stream
//! tables have their rows, and the steps from then on write them to the
//! sinks of those outputs: [`Step::Flush`] whenever one is full, then
//! [`Step::End`]. A pull engine therefore sees a stream table as a source
//! that gives nothing ([`Step::More`]) until the capture is read, and a
//! push engine needs no code for it at all.
//! [`PartitionScan::with_keylog`] gives the analysis the keys to decrypt
//! TLS with.
//!
//! # The frame predicate
//!
//! The plan's [`FramePredicate`](super::FramePredicate)
//! ([`CompiledScan::frames`]) is enforced here, exactly: a packet gives rows
//! if and only if the predicate accepts it. A packet it rejects is consumed
//! from the reader and nothing else: it is not parsed, not routed and not
//! counted against a row cap. (Stream reassembly needs every packet, and
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
use super::stream::{StreamAnalysis, StreamWriter};
use crate::io::{PacketReader, Pause};
use crate::protocol::{parse_packet, ParseBuf};
use crate::{Error, KeyLog, ProtocolRegistry};

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
    /// Every output reached its row cap or was closed: nothing the scan
    /// could still produce would be seen. The rest of the partition was not
    /// read. (A stream table that is not closed keeps the scan reading: it
    /// has no rows before the partition ends.)
    Done,
    /// The end of the partition, or of the frames the plan's
    /// [frame predicate](CompiledScan::frames) can accept in it (the rest of
    /// the partition was not read), with the rows of the plan's stream
    /// tables written. The sinks may hold rows that never filled them.
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

/// One partition of a compiled scan, read step by step. What a step
/// guarantees is written at the top of `scan/driver.rs`.
///
/// The outputs it writes are the plan's ([`CompiledScan::outputs`]):
/// `frames`, the protocol tables and the fused joins packet by packet, and
/// the stream tables when the partition ends.
pub struct PartitionScan<R: PacketReader> {
    reader: R,
    plan: Arc<CompiledScan>,
    registry: Arc<ProtocolRegistry>,
    router: Router,
    /// Stream reassembly, in a plan with stream tables, until the partition
    /// ends.
    analysis: Option<Box<StreamAnalysis>>,
    /// What the analysis became: the stream tables' rows, being written.
    writer: Option<Box<StreamWriter>>,
    /// Storage for the layers of the packet being routed, reused from one
    /// packet to the next.
    layers: ParseBuf,
    /// The number of the last frame that was parsed for the first time
    /// (frames are numbered from 1). A frame shown again has this number.
    seen_frame: u64,
    /// The plan has a frame predicate other than `all`.
    filtered: bool,
    /// No further packet is read: the partition ended, or the frame
    /// predicate accepts no further frame of it.
    ended: bool,
    stats: ScanStats,
}

impl<R: PacketReader> PartitionScan<R> {
    /// A scan of what `reader` delivers: a whole capture, or one range of
    /// it. `registry` must be the one `plan` was compiled for.
    pub fn new(reader: R, plan: Arc<CompiledScan>, registry: Arc<ProtocolRegistry>) -> Self {
        let router = Router::new(&plan);
        let stats = ScanStats::new(plan.outputs().len());
        let filtered = !plan.frames().is_all();
        let ended = plan.frames().is_empty();
        let analysis = plan
            .requires_single_partition()
            .then(|| Box::new(StreamAnalysis::new(None)));
        Self {
            reader,
            plan,
            registry,
            router,
            analysis,
            writer: None,
            layers: ParseBuf::new(),
            seen_frame: 0,
            filtered,
            ended,
            stats,
        }
    }

    /// Decrypt TLS with `keylog` when building the plan's stream tables:
    /// `tls_sessions.is_decrypted` and the rows of `http2` depend on it.
    /// Nothing else does, and a scan without stream tables ignores it. To
    /// be called before the first [`step`](Self::step).
    pub fn with_keylog(mut self, keylog: &KeyLog) -> Self {
        if let Some(analysis) = &mut self.analysis {
            **analysis = StreamAnalysis::new(Some(keylog));
        }
        self
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
    /// An error is the reader's or stream analysis's. The rows of packets
    /// consumed before it are in the sinks and counted in
    /// [`stats`](PartitionScan::stats). Stepping again is only meaningful
    /// when the reader says it can be read again: after a read timeout
    /// ([`PacketReader::take_read_timeout`]) the next step carries on where
    /// this one stopped. After any other reader error (a malformed or
    /// truncated record, a failed read) or an analysis error, stop
    /// stepping the partition.
    ///
    /// # Panics
    ///
    /// If `sinks` is shorter than the outputs a frame has rows for.
    #[inline]
    pub fn step<S: RowSink>(&mut self, sinks: &mut [S], max_packets: usize) -> Result<Step, Error> {
        if let Some(output) = self.router.take_flush() {
            return Ok(Step::Flush(output));
        }
        if self.ended {
            return Ok(self.end(sinks));
        }
        if self.router.all_done() {
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
            analysis,
            layers,
            seen_frame,
            filtered,
            ended,
            stats,
            ..
        } = self;
        let scope = plan.scope();
        let frames = plan.frames();
        let filtered = *filtered;
        let mut failed = None;
        // Packets consumed in this call, for the stats when the reader fails
        // after delivering some (its count is then lost with the result).
        let mut consumed = 0u64;
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
                    consumed += 1;
                    if last {
                        *ended = true;
                        return ControlFlow::Break(Pause::After);
                    }
                    return ControlFlow::Continue(());
                }
            }
            // Per-packet link type is correct even for PCAPNG multi-interface.
            let layers = parse_packet(registry, packet.link_type, packet.data, scope, layers);
            if packet.frame_number != *seen_frame {
                // The first time this frame is shown.
                *seen_frame = packet.frame_number;
                stats.min_ts_ns = stats.min_ts_ns.min(packet.timestamp_ns);
                stats.max_ts_ns = stats.max_ts_ns.max(packet.timestamp_ns);
                if let Some(analysis) = analysis {
                    if let Err(error) = analysis.observe(&packet, &layers) {
                        consumed += 1;
                        failed = Some(error);
                        return ControlFlow::Break(Pause::After);
                    }
                }
            }
            match router.route_frame(sinks, &packet, &layers) {
                // Rows of the frame are waiting for a full sink: the reader
                // keeps the packet and shows it again.
                Routed::Redeliver => ControlFlow::Break(Pause::Before),
                Routed::Consumed => {
                    consumed += 1;
                    if last {
                        *ended = true;
                        ControlFlow::Break(Pause::After)
                    } else if router.has_flush() {
                        ControlFlow::Break(Pause::After)
                    } else {
                        ControlFlow::Continue(())
                    }
                }
            }
        });
        // Rows already in the sinks are counted whether or not the reader
        // failed.
        for (index, rows) in stats.rows.iter_mut().enumerate() {
            *rows = router.rows(OutputId(index as u16));
        }
        let delivered = match delivered {
            Ok(delivered) => delivered,
            Err(error) => {
                stats.packets += consumed;
                return Err(error);
            }
        };
        stats.packets += delivered.consumed as u64;
        if let Some(error) = failed {
            return Err(error);
        }
        if let Some(output) = router.take_flush() {
            return Ok(Step::Flush(output));
        }
        if delivered.consumed == 0 && delivered.paused.is_none() {
            *ended = true;
        }
        if *ended {
            return Ok(self.end(sinks));
        }
        Ok(Step::More)
    }

    /// No further packet is read. In a plan with stream tables their rows
    /// are due now: write as many as fit.
    #[cold]
    fn end<S: RowSink>(&mut self, sinks: &mut [S]) -> Step {
        if let Some(analysis) = self.analysis.take() {
            let tables = analysis.finish(&self.plan);
            self.writer = Some(Box::new(StreamWriter::new(tables)));
        }
        let Some(writer) = &mut self.writer else {
            return Step::End;
        };
        let flush = writer.write(&self.plan, &mut self.router, sinks);
        for (index, rows) in self.stats.rows.iter_mut().enumerate() {
            *rows = self.router.rows(OutputId(index as u16));
        }
        match flush {
            Some(output) => Step::Flush(output),
            None => Step::End,
        }
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

    /// What was read and written so far, as of the last step.
    pub fn stats(&self) -> &ScanStats {
        &self.stats
    }

    /// End the scan: its statistics, and the reader it was given.
    pub fn finish(self) -> (ScanStats, R) {
        (self.stats, self.reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::{Delivered, PacketPosition, PacketRef};
    use crate::scan::testing::{Cell, RecordingSink};
    use crate::scan::{Catalog, FramePredicate, ScanPlan, TableScan};
    use std::ops::Bound;

    /// A reader over frames held in memory.
    struct Frames {
        frames: Vec<Vec<u8>>,
        next: usize,
        /// Fail the read before this frame index, once.
        fail_before: Option<usize>,
        /// Fail there even after delivering packets in the same call (a
        /// malformed record), instead of reporting those first (a timeout).
        fail_hard: bool,
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
                fail_hard: false,
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
                    if consumed > 0 && !self.fail_hard {
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

    /// A scan of `count` frames with a frame predicate.
    fn filtered(
        count: u8,
        tables: &[(&str, Option<u64>)],
        frames: FramePredicate,
    ) -> PartitionScan<Frames> {
        PartitionScan::new(
            Frames::new(count),
            plan_of(tables, frames),
            Arc::new(crate::default_registry()),
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
        let (stats, _) = scan.finish();
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

    /// A reader that fails after delivering packets in the same call: the
    /// packets and rows already written are still counted.
    #[test]
    fn a_read_error_after_delivering_keeps_the_counts() {
        let mut scan = scan(4, &[("frames", None), ("udp", None)]);
        scan.reader_mut().fail_before = Some(2);
        scan.reader_mut().fail_hard = true;
        let mut sinks = sinks(scan.plan(), None);
        assert!(scan.step(&mut sinks, 100).is_err());
        assert_eq!(numbers(sinks[0].take_rows()), [1, 2]);
        assert_eq!(scan.stats().packets, 2);
        assert_eq!(*scan.stats().rows, [2, 2]);
    }

    /// A frame range gives the rows of exactly its frames, to every
    /// output; the frames before it are read and not parsed, and nothing
    /// behind its last frame is read at all.
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
        let (stats, _) = scan.finish();
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
        let (stats, _) = scan.finish();
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
        let (stats, _) = scan.finish();
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
        let (stats, _) = scan.finish();
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
        let (stats, _) = scan.finish();
        assert_eq!((stats.packets, stats.skipped), (3, 1));
    }
}
