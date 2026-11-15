//! The state of a running streaming window aggregate.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use arrow::array::{
    Array, ArrayRef, BooleanArray, RecordBatch, TimestampMicrosecondArray, UInt32Array,
};
use arrow::compute::{cast, filter, take};
use arrow::datatypes::{DataType, SchemaRef};
use arrow::row::{OwnedRow, RowConverter, SortField};
use datafusion::common::{DataFusionError, Result, ScalarValue};
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::logical_expr::Accumulator;
use datafusion::physical_expr::aggregate::AggregateFunctionExpr;
use datafusion::physical_expr::PhysicalExpr;
use datafusion::physical_plan::metrics::{Count, Gauge, MetricBuilder};

use super::config::{MemoryLimitPolicy, WindowSpec};
use super::exec::StreamingWindowAggregateExec;
use pcapsql_core::windowing::{WatermarkConfig, WatermarkEmitStrategy, WatermarkGenerator};

/// The accumulators of one `(slice, group)`.
type Accumulators = Vec<Box<dyn Accumulator>>;

/// One group's state within one slice.
struct GroupState {
    /// Accumulators still taking rows.
    live: Accumulators,
    /// For a sliced hop: the states frozen out of `live` each time a window
    /// containing this slice was emitted (`frozen[piece][aggregate]`), to be
    /// merged into the later windows that contain the slice too. A frozen
    /// accumulator cannot take rows again (`state()` consumes it), so `live`
    /// is replaced by a fresh one; rows arriving after a freeze land there.
    frozen: Vec<Vec<Vec<ScalarValue>>>,
    /// Rows have reached `live` since it was created or last frozen; an
    /// untouched `live` is not worth a piece.
    dirty: bool,
}

/// The groups of one slice, keyed by the encoded non-window group values
/// (`None` when the query groups by the window alone).
type SliceGroups = BTreeMap<Option<OwnedRow>, GroupState>;

/// Per-partition aggregate state.
pub(super) struct AggregateState {
    spec: WindowSpec,
    ts_index: usize,
    group_exprs: Vec<Arc<dyn PhysicalExpr>>,
    window_start_pos: usize,
    window_end_pos: Option<usize>,
    /// Group expressions other than the window columns, with their output
    /// positions.
    key_positions: Vec<usize>,
    key_converter: Option<RowConverter>,
    aggr_expr: Vec<Arc<AggregateFunctionExpr>>,
    filter_expr: Vec<Option<Arc<dyn PhysicalExpr>>>,
    schema: SchemaRef,
    /// Open state by slice start: one slice per window (tumble, a hop whose
    /// size is not a multiple of its slide) or per slide (a sliced hop).
    slices: BTreeMap<i64, SliceGroups>,
    watermark: WatermarkGenerator,
    /// Every window ending at or before this has been emitted (by the
    /// watermark, the idle timeout, end of input or the memory limit). For a
    /// sliced hop this is also where the pending window is derived from:
    /// the next one starts `size - slide` before it, and a slice is only
    /// ever inserted if some window containing it is still open.
    closed_through: i64,
    /// What the state above weighs, as last accounted to the pool.
    reservation: MemoryReservation,
    on_memory_limit: MemoryLimitPolicy,
    late_rows: Count,
    windows_emitted: Count,
    windows_forced: Count,
    watermark_metric: Gauge,
    state_bytes_metric: Gauge,
}

impl AggregateState {
    pub(super) fn try_new(
        exec: &StreamingWindowAggregateExec,
        partition: usize,
        reservation: MemoryReservation,
    ) -> Result<Self> {
        let group_exprs: Vec<Arc<dyn PhysicalExpr>> = exec
            .group_by
            .expr()
            .iter()
            .map(|(e, _)| Arc::clone(e))
            .collect();
        let key_positions: Vec<usize> = (0..group_exprs.len())
            .filter(|&i| i != exec.window_start_pos && Some(i) != exec.window_end_pos)
            .collect();
        let key_converter = if key_positions.is_empty() {
            None
        } else {
            let fields = key_positions
                .iter()
                .map(|&i| Ok(SortField::new(exec.schema.field(i).data_type().clone())))
                .collect::<Result<Vec<_>>>()?;
            Some(RowConverter::new(fields)?)
        };
        Ok(Self {
            spec: exec.spec.clone(),
            ts_index: exec.ts_index,
            group_exprs,
            window_start_pos: exec.window_start_pos,
            window_end_pos: exec.window_end_pos,
            key_positions,
            key_converter,
            aggr_expr: exec.aggr_expr.clone(),
            filter_expr: exec.filter_expr.clone(),
            schema: Arc::clone(&exec.schema),
            slices: BTreeMap::new(),
            watermark: WatermarkGenerator::new(WatermarkConfig {
                allowed_lateness: exec.config.allowed_lateness,
                emit_strategy: WatermarkEmitStrategy::EveryEvent,
                track_late_events: false,
            }),
            closed_through: i64::MIN,
            reservation,
            on_memory_limit: exec.config.on_memory_limit,
            late_rows: MetricBuilder::new(&exec.metrics).counter("late_rows", partition),
            windows_emitted: MetricBuilder::new(&exec.metrics)
                .counter("windows_emitted", partition),
            windows_forced: MetricBuilder::new(&exec.metrics).counter("windows_forced", partition),
            watermark_metric: MetricBuilder::new(&exec.metrics).gauge("watermark_us", partition),
            state_bytes_metric: MetricBuilder::new(&exec.metrics).gauge("state_bytes", partition),
        })
    }

    /// The point before which a window counts as closed.
    fn horizon(&self) -> i64 {
        self.watermark
            .current()
            .as_micros()
            .max(self.closed_through)
    }

    /// Whether any state is open.
    pub(super) fn is_empty(&self) -> bool {
        self.slices.is_empty()
    }

    /// Windows containing the slice at `slice` that are closed at `horizon`:
    /// a sliced hop's windows are `slice - j * slide` for `j` in
    /// `0..size/slide`, and window `w` is closed once `w + size <= horizon`.
    /// For an unsliced window the slice is the window: 0 or 1.
    fn closed_windows_of(&self, slice: i64, horizon: i64) -> i64 {
        let size = self.spec.size_us();
        let slide = self.spec.slice_us();
        let k = size / slide;
        // Closed: slice - j*slide + size <= horizon, i.e. j >= (slice + size - horizon) / slide.
        // The horizon starts at i64::MIN (no watermark yet): saturate.
        let still_open = slice.saturating_add(size).saturating_sub(horizon);
        let first_closed = if still_open <= 0 {
            0
        } else {
            still_open.saturating_add(slide - 1) / slide
        };
        (k - first_closed).clamp(0, k)
    }

    /// The bytes the open state holds: accumulators, frozen states and keys.
    fn state_bytes(&self) -> usize {
        // Per entry: the map node, the key, the vectors.
        const OVERHEAD: usize = 96;
        self.slices
            .values()
            .flat_map(|groups| groups.iter())
            .map(|(key, group)| {
                OVERHEAD
                    + key.as_ref().map(|k| k.as_ref().len()).unwrap_or(0)
                    + group.live.iter().map(|a| a.size()).sum::<usize>()
                    + group
                        .frozen
                        .iter()
                        .flat_map(|piece| piece.iter())
                        .flat_map(|states| states.iter())
                        .map(ScalarValue::size)
                        .sum::<usize>()
            })
            .sum()
    }

    /// Account the state to the memory pool; when it does not fit, apply the
    /// policy: fail, or emit the oldest windows (appended to `out`) until it
    /// does.
    fn account(&mut self, out: &mut Vec<RecordBatch>) -> Result<()> {
        loop {
            let bytes = self.state_bytes();
            self.state_bytes_metric.set(bytes);
            match self.reservation.try_resize(bytes) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    let windows = self.open_windows();
                    let groups: usize = self.slices.values().map(BTreeMap::len).sum();
                    if self.on_memory_limit == MemoryLimitPolicy::Error || windows <= 1 {
                        let hint = if self.on_memory_limit == MemoryLimitPolicy::Error {
                            "lower --allowed-lateness, use a larger window or fewer group \
                             columns, raise --memory-limit, or --on-memory-limit close-oldest"
                        } else {
                            "the newest window alone does not fit: use a larger window or \
                             fewer group columns, or raise --memory-limit"
                        };
                        return Err(DataFusionError::ResourcesExhausted(format!(
                            "the streaming aggregate holds {bytes} bytes of state for {windows} \
                             open windows ({groups} group entries), more than the memory limit \
                             allows; {hint} ({e})"
                        )));
                    }
                    let forced = self.emit_oldest()?;
                    self.windows_forced.add(forced.len());
                    out.extend(forced);
                }
            }
        }
    }

    /// Open windows: for a sliced hop, those from the oldest pending window
    /// to the one starting at the newest slice; otherwise one per slice.
    fn open_windows(&self) -> usize {
        if !self.spec.sliced() {
            return self.slices.len();
        }
        match (self.pending_window(), self.slices.keys().next_back()) {
            (Some(next), Some(&last)) => ((last - next) / self.spec.slice_us() + 1) as usize,
            _ => 0,
        }
    }

    /// Emit the oldest open window before its time (memory limit).
    fn emit_oldest(&mut self) -> Result<Vec<RecordBatch>> {
        let size = self.spec.size_us();
        if self.spec.sliced() {
            let Some(w) = self.pending_window() else {
                return Ok(Vec::new());
            };
            self.emit_hop_windows_through(w.saturating_add(size))
        } else {
            let Some(&start) = self.slices.keys().next() else {
                return Ok(Vec::new());
            };
            let groups = self.slices.remove(&start).expect("window present");
            self.closed_through = self.closed_through.max(start + size);
            Ok(vec![self.emit_window(start, size, groups)?])
        }
    }

    /// Fold one input batch into the open windows; returns the windows the
    /// watermark closed, in start order.
    pub(super) fn process(&mut self, batch: &RecordBatch) -> Result<Vec<RecordBatch>> {
        let n = batch.num_rows();
        if n == 0 {
            return Ok(Vec::new());
        }
        let horizon_before = self.horizon();
        let ts = batch
            .column(self.ts_index)
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .ok_or_else(|| {
                DataFusionError::Internal(
                    "streaming aggregate: timestamp column is not Timestamp(Microsecond)".into(),
                )
            })?;
        let starts = self.group_exprs[self.window_start_pos]
            .evaluate(batch)?
            .into_array(n)?;
        let starts = starts
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .ok_or_else(|| {
                DataFusionError::Internal(
                    "streaming aggregate: window_start is not Timestamp(Microsecond)".into(),
                )
            })?;
        let key_rows = match &self.key_converter {
            Some(converter) => {
                let columns = self
                    .key_positions
                    .iter()
                    .map(|&i| self.group_exprs[i].evaluate(batch)?.into_array(n))
                    .collect::<Result<Vec<_>>>()?;
                Some(converter.convert_columns(&columns)?)
            }
            None => None,
        };
        let args: Vec<Vec<ArrayRef>> = self
            .aggr_expr
            .iter()
            .map(|agg| {
                agg.expressions()
                    .iter()
                    .map(|e| e.evaluate(batch)?.into_array(n))
                    .collect::<Result<Vec<_>>>()
            })
            .collect::<Result<Vec<_>>>()?;
        let masks: Vec<Option<BooleanArray>> = self
            .filter_expr
            .iter()
            .map(|f| match f {
                Some(f) => {
                    let array = f.evaluate(batch)?.into_array(n)?;
                    let mask = array
                        .as_any()
                        .downcast_ref::<BooleanArray>()
                        .ok_or_else(|| {
                            DataFusionError::Internal(
                                "aggregate FILTER did not evaluate to a boolean".into(),
                            )
                        })?
                        .clone();
                    Ok(Some(mask))
                }
                None => Ok(None),
            })
            .collect::<Result<Vec<_>>>()?;

        // Bucket rows by (slice, group). A row whose windows have all been
        // emitted is late; for a sliced hop a row may be late for some of
        // its windows and counted for the rest, and the late ones are
        // counted (as the per-window expansion would have).
        let size = self.spec.size_us();
        let mut buckets: HashMap<(i64, Option<OwnedRow>), Vec<u32>> = HashMap::new();
        let mut late = 0usize;
        for i in 0..n {
            if ts.is_null(i) || starts.is_null(i) {
                // No event time: the row belongs to no window (unreachable
                // from `frames.timestamp`, which is not nullable; a view with
                // a nullable timestamp drops such rows here, uncounted).
                continue;
            }
            self.watermark.observe(ts.value(i));
            let start = starts.value(i);
            late += self.closed_windows_of(start, horizon_before) as usize;
            if start + size <= horizon_before {
                continue;
            }
            let key = key_rows.as_ref().map(|rows| rows.row(i).owned());
            buckets.entry((start, key)).or_default().push(i as u32);
        }
        if late > 0 {
            self.late_rows.add(late);
        }
        for ((start, key), indices) in buckets {
            let indices = UInt32Array::from(indices);
            let groups = self.slices.entry(start).or_default();
            let group = match groups.get_mut(&key) {
                Some(g) => g,
                None => {
                    let fresh = self
                        .aggr_expr
                        .iter()
                        .map(|a| a.create_accumulator())
                        .collect::<Result<Vec<_>>>()?;
                    groups.entry(key).or_insert(GroupState {
                        live: fresh,
                        frozen: Vec::new(),
                        dirty: false,
                    })
                }
            };
            group.dirty = true;
            let accumulators = &mut group.live;
            for (k, acc) in accumulators.iter_mut().enumerate() {
                let mut values = args[k]
                    .iter()
                    .map(|a| Ok(take(a.as_ref(), &indices, None)?))
                    .collect::<Result<Vec<ArrayRef>>>()?;
                if let Some(mask) = &masks[k] {
                    let mask = take(mask, &indices, None)?;
                    let mask = mask
                        .as_any()
                        .downcast_ref::<BooleanArray>()
                        .expect("boolean mask");
                    values = values
                        .iter()
                        .map(|a| Ok(filter(a.as_ref(), mask)?))
                        .collect::<Result<Vec<_>>>()?;
                }
                acc.update_batch(&values)?;
            }
        }

        let wm = self.watermark.current().as_micros();
        if wm > 0 {
            self.watermark_metric.set(wm as usize);
        }
        let mut out = self.emit_closed(wm)?;
        // Every window ending at or before the watermark is closed now,
        // emitted or (empty) not: a later row for one is late, and a sliced
        // hop must not emit it after the fact.
        self.closed_through = self.closed_through.max(wm);
        self.account(&mut out)?;
        Ok(out)
    }

    /// Emit every window whose end is at or before `horizon`.
    fn emit_closed(&mut self, horizon: i64) -> Result<Vec<RecordBatch>> {
        if self.spec.sliced() {
            return self.emit_hop_windows_through(horizon);
        }
        let size = self.spec.size_us();
        let closed: Vec<i64> = self
            .slices
            .keys()
            .copied()
            .take_while(|start| start + size <= horizon)
            .collect();
        let mut out = Vec::with_capacity(closed.len());
        for start in closed {
            let groups = self.slices.remove(&start).expect("window present");
            self.closed_through = self.closed_through.max(start + size);
            out.push(self.emit_window(start, size, groups)?);
        }
        Ok(out)
    }

    /// Emit every open window (idle timeout, end of input).
    pub(super) fn emit_all(&mut self) -> Result<Vec<RecordBatch>> {
        self.emit_closed(i64::MAX)
    }

    /// Sliced hop: the oldest window not yet emitted, while any slice is
    /// open. It is the later of the first window containing the oldest slice
    /// and the window after the last one emitted (`closed_through - size`):
    /// a slice older than the latter is never inserted (all its windows are
    /// closed), so it always covers the oldest slice, and a long gap in the
    /// stream is jumped rather than walked window by window.
    fn pending_window(&self) -> Option<i64> {
        let size = self.spec.size_us();
        let slide = self.spec.slice_us();
        let &first = self.slices.keys().next()?;
        let earliest = first - size + slide;
        // Windows starting at or before `closed_through - size` are closed;
        // the first slide-aligned start after that is the next candidate.
        let last_closed = self.closed_through.saturating_sub(size);
        let after_closed = last_closed
            .div_euclid(slide)
            .saturating_mul(slide)
            .saturating_add(slide);
        Some(earliest.max(after_closed))
    }

    /// Sliced hop: emit, in start order, every window ending at or before
    /// `horizon`, merging the slices it covers; drop a slice once the last
    /// window containing it (the one starting at it) has been emitted.
    fn emit_hop_windows_through(&mut self, horizon: i64) -> Result<Vec<RecordBatch>> {
        let size = self.spec.size_us();
        let mut out = Vec::new();
        while let Some(w) = self.pending_window() {
            if w.saturating_add(size) > horizon {
                break;
            }
            let covered: Vec<i64> = self.slices.range(w..w + size).map(|(s, _)| *s).collect();
            debug_assert!(
                !covered.is_empty(),
                "the pending window covers the oldest slice"
            );
            out.push(self.emit_hop_window(w, &covered)?);
            // Slice `w` was in its last window.
            self.slices.remove(&w);
            self.closed_through = self.closed_through.max(w + size);
        }
        Ok(out)
    }

    /// Sliced hop: one window from the slices it covers. Each slice's live
    /// accumulators are frozen into states (and replaced, since freezing
    /// consumes them) so later windows covering the slice merge the same
    /// states again; the window's own accumulators are fresh ones that merge
    /// every piece of every covered slice. A live set that took no rows
    /// since the last freeze is left alone, so a slice that received its
    /// rows in order holds one piece however many windows it is in.
    fn emit_hop_window(&mut self, start: i64, covered: &[i64]) -> Result<RecordBatch> {
        let size = self.spec.size_us();
        // pieces[group][aggregate] = the state rows to merge.
        let mut pieces: BTreeMap<Option<OwnedRow>, Vec<Vec<Vec<ScalarValue>>>> = BTreeMap::new();
        for s in covered {
            let groups = self.slices.get_mut(s).expect("covered slice");
            for (key, group) in groups.iter_mut() {
                if group.dirty {
                    let states = group
                        .live
                        .iter_mut()
                        .map(|a| a.state())
                        .collect::<Result<Vec<_>>>()?;
                    group.live = self
                        .aggr_expr
                        .iter()
                        .map(|a| a.create_accumulator())
                        .collect::<Result<Vec<_>>>()?;
                    group.frozen.push(states);
                    group.dirty = false;
                }
                let into = pieces
                    .entry(key.clone())
                    .or_insert_with(|| vec![Vec::new(); self.aggr_expr.len()]);
                for piece in &group.frozen {
                    for (k, states) in piece.iter().enumerate() {
                        into[k].push(states.clone());
                    }
                }
            }
        }
        let mut merged: SliceGroups = BTreeMap::new();
        for (key, per_agg) in pieces {
            let mut live = Vec::with_capacity(self.aggr_expr.len());
            for (k, agg) in self.aggr_expr.iter().enumerate() {
                let mut acc = agg.create_accumulator()?;
                let rows = &per_agg[k];
                if let Some(first) = rows.first() {
                    let columns = (0..first.len())
                        .map(|j| ScalarValue::iter_to_array(rows.iter().map(|r| r[j].clone())))
                        .collect::<Result<Vec<ArrayRef>>>()?;
                    acc.merge_batch(&columns)?;
                }
                live.push(acc);
            }
            merged.insert(
                key,
                GroupState {
                    live,
                    frozen: Vec::new(),
                    dirty: true,
                },
            );
        }
        self.emit_window(start, size, merged)
    }

    fn emit_window(&mut self, start: i64, size: i64, groups: SliceGroups) -> Result<RecordBatch> {
        let n = groups.len();
        let mut columns: Vec<ArrayRef> = Vec::with_capacity(self.schema.fields().len());
        let keys: Vec<ArrayRef> = match &self.key_converter {
            Some(converter) => {
                let rows: Vec<_> = groups
                    .keys()
                    .map(|k| k.as_ref().expect("keyed group").row())
                    .collect();
                converter.convert_rows(rows)?
            }
            None => Vec::new(),
        };
        let mut key_iter = keys.into_iter();
        for (pos, field) in self
            .schema
            .fields()
            .iter()
            .enumerate()
            .take(self.group_exprs.len())
        {
            let tz = match field.data_type() {
                DataType::Timestamp(_, tz) => tz.clone(),
                _ => None,
            };
            let column: ArrayRef = if pos == self.window_start_pos {
                Arc::new(TimestampMicrosecondArray::from(vec![start; n]).with_timezone_opt(tz))
            } else if Some(pos) == self.window_end_pos {
                Arc::new(
                    TimestampMicrosecondArray::from(vec![start + size; n]).with_timezone_opt(tz),
                )
            } else {
                key_iter.next().expect("one array per key expression")
            };
            columns.push(cast_to(column, field.data_type())?);
        }
        let mut results: Vec<Vec<ScalarValue>> = vec![Vec::with_capacity(n); self.aggr_expr.len()];
        for mut group in groups.into_values() {
            for (k, acc) in group.live.iter_mut().enumerate() {
                results[k].push(acc.evaluate()?);
            }
        }
        for (k, values) in results.into_iter().enumerate() {
            let field = self.schema.field(self.group_exprs.len() + k);
            let array = if values.is_empty() {
                arrow::array::new_empty_array(field.data_type())
            } else {
                ScalarValue::iter_to_array(values)?
            };
            columns.push(cast_to(array, field.data_type())?);
        }
        self.windows_emitted.add(1);
        Ok(RecordBatch::try_new(Arc::clone(&self.schema), columns)?)
    }
}

fn cast_to(array: ArrayRef, data_type: &DataType) -> Result<ArrayRef> {
    if array.data_type() == data_type {
        Ok(array)
    } else {
        Ok(cast(array.as_ref(), data_type)?)
    }
}
