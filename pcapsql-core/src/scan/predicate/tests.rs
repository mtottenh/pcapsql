use super::*;
use crate::io::PacketPosition;
use crate::scan::Catalog;
use crate::TunnelType;
use std::net::{IpAddr, Ipv4Addr};

/// The fields of a hand-built row.
type Row = Vec<(&'static str, FieldValue<'static>)>;

fn layer(fields: Row) -> Row {
    fields
}

/// `row` as a layer outside any tunnel.
fn of(row: &Row) -> LayerRef<'_, 'static> {
    LayerRef::new("test", row)
}

fn tcp_layer() -> Row {
    layer(vec![
        ("src_port", FieldValue::UInt16(12345)),
        ("dst_port", FieldValue::UInt16(80)),
        ("flags", FieldValue::UInt16(0x02)),
    ])
}

fn ipv4_layer() -> Row {
    layer(vec![
        (
            "src_ip",
            FieldValue::IpAddr(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        ),
        ("ttl", FieldValue::UInt8(64)),
    ])
}

fn table(name: &str) -> &'static TableDef {
    Catalog::builtin().table(name).expect("table").1
}

fn col(table: &TableDef, name: &str) -> ColId {
    table.column(name).expect("column").0
}

/// `column <op> value` on `table`, compiled.
fn compiled(
    table: &TableDef,
    column: &str,
    op: CmpOp,
    value: impl Into<Literal>,
) -> Option<CompiledPredicate> {
    RowPredicate::cmp(col(table, column), op, value).compile(table)
}

#[test]
fn int_compare_keeps_and_drops() {
    let tcp = table("tcp");
    let row = tcp_layer();
    let mut keep = compiled(tcp, "dst_port", CmpOp::Eq, 80).unwrap();
    assert!(keep.keeps(of(&row)));
    let mut drop = compiled(tcp, "dst_port", CmpOp::Eq, 443).unwrap();
    assert!(!drop.keeps(of(&row)));
}

#[test]
fn every_operator_compares_integers_and_strings() {
    let tcp = table("tcp");
    let row = tcp_layer(); // dst_port = 80
    for (op, below, equal, above) in [
        (CmpOp::Eq, false, true, false),
        (CmpOp::NotEq, true, false, true),
        (CmpOp::Lt, false, false, true),
        (CmpOp::LtEq, false, true, true),
        (CmpOp::Gt, true, false, false),
        (CmpOp::GtEq, true, true, false),
    ] {
        for (literal, expected) in [(79, below), (80, equal), (81, above)] {
            let mut p = compiled(tcp, "dst_port", op, literal).unwrap();
            assert_eq!(p.keeps(of(&row)), expected, "80 {op:?} {literal}");
        }
    }

    let dns = table("dns");
    let row = layer(vec![("query_name", FieldValue::Str("m.example"))]);
    for (op, below, equal, above) in [
        (CmpOp::Eq, false, true, false),
        (CmpOp::NotEq, true, false, true),
        (CmpOp::Lt, false, false, true),
        (CmpOp::LtEq, false, true, true),
        (CmpOp::Gt, true, false, false),
        (CmpOp::GtEq, true, true, false),
    ] {
        for (literal, expected) in [("a", below), ("m.example", equal), ("z", above)] {
            let mut p = compiled(dns, "query_name", op, literal).unwrap();
            assert_eq!(p.keeps(of(&row)), expected, "m.example {op:?} {literal}");
        }
    }
}

#[test]
fn swapped_operators() {
    assert_eq!(CmpOp::Lt.swapped(), CmpOp::Gt);
    assert_eq!(CmpOp::LtEq.swapped(), CmpOp::GtEq);
    assert_eq!(CmpOp::Gt.swapped(), CmpOp::Lt);
    assert_eq!(CmpOp::GtEq.swapped(), CmpOp::LtEq);
    assert_eq!(CmpOp::Eq.swapped(), CmpOp::Eq);
    assert_eq!(CmpOp::NotEq.swapped(), CmpOp::NotEq);
}

/// An absent field is SQL NULL, whose semantics belong to the engine:
/// the row is kept whatever the operator.
#[test]
fn missing_field_keeps_the_row() {
    let tcp = table("tcp");
    let row = tcp_layer();
    for op in [CmpOp::Eq, CmpOp::NotEq, CmpOp::Lt, CmpOp::Gt] {
        let mut p = compiled(tcp, "mss", op, 1460).unwrap();
        assert!(p.keeps(of(&row)), "{op:?}");
    }
}

#[test]
fn ipv4_compares_as_the_u32_its_column_stores() {
    let ipv4 = table("ipv4");
    let row = ipv4_layer();
    let ip = i64::from(u32::from(Ipv4Addr::new(192, 168, 1, 1)));
    assert!(compiled(ipv4, "src_ip", CmpOp::Eq, ip)
        .unwrap()
        .keeps(of(&row)));
    assert!(!compiled(ipv4, "src_ip", CmpOp::Eq, ip + 1)
        .unwrap()
        .keeps(of(&row)));
    // A string against the address is not confidently comparable: keep.
    assert!(compiled(ipv4, "src_ip", CmpOp::Eq, "10.0.0.1")
        .unwrap()
        .keeps(of(&row)));
}

#[test]
fn values_of_another_type_keep_the_row() {
    let tcp = table("tcp");
    // An integer literal against a string value, and the reverse.
    let row = layer(vec![("dst_port", FieldValue::Str("80"))]);
    assert!(compiled(tcp, "dst_port", CmpOp::Eq, 443)
        .unwrap()
        .keeps(of(&row)));
    let row = tcp_layer();
    assert!(compiled(tcp, "dst_port", CmpOp::Eq, "443")
        .unwrap()
        .keeps(of(&row)));
    // A u64 that does not fit i64 is undecided; one that fits compares.
    let row = layer(vec![("dst_port", FieldValue::UInt64(u64::MAX))]);
    assert!(compiled(tcp, "dst_port", CmpOp::Eq, 1)
        .unwrap()
        .keeps(of(&row)));
    let row = layer(vec![("dst_port", FieldValue::UInt64(2))]);
    assert!(!compiled(tcp, "dst_port", CmpOp::Eq, 1)
        .unwrap()
        .keeps(of(&row)));
    // Booleans compare as 0 and 1, owned strings as strings.
    let row = layer(vec![("dst_port", FieldValue::Bool(true))]);
    assert!(!compiled(tcp, "dst_port", CmpOp::Eq, 0)
        .unwrap()
        .keeps(of(&row)));
    let row = layer(vec![("dst_port", FieldValue::Str("x"))]);
    assert!(!compiled(tcp, "dst_port", CmpOp::Eq, "y")
        .unwrap()
        .keeps(of(&row)));
    // Null, bytes, MAC and IPv6 values are never compared.
    for value in [
        FieldValue::Null,
        FieldValue::Bytes(&[1, 2]),
        FieldValue::MacAddr([0; 6]),
        FieldValue::IpAddr(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
    ] {
        let row = layer(vec![("dst_port", value)]);
        assert!(compiled(tcp, "dst_port", CmpOp::Eq, 1)
            .unwrap()
            .keeps(of(&row)));
        assert!(compiled(tcp, "dst_port", CmpOp::Eq, "1")
            .unwrap()
            .keeps(of(&row)));
    }
}

#[test]
fn and_needs_every_comparison() {
    let tcp = table("tcp");
    let row = tcp_layer();
    let both = |src: i64| {
        RowPredicate::And(vec![
            RowPredicate::cmp(col(tcp, "dst_port"), CmpOp::Eq, 80),
            RowPredicate::And(vec![RowPredicate::cmp(
                col(tcp, "src_port"),
                CmpOp::Gt,
                src,
            )]),
        ])
        .compile(tcp)
        .unwrap()
    };
    assert!(both(10_000).keeps(of(&row)));
    assert!(!both(60_000).keeps(of(&row)));
}

#[test]
fn predicates_that_cannot_drop_a_row_compile_to_none() {
    let tcp = table("tcp");
    assert!(RowPredicate::And(vec![]).compile(tcp).is_none());
    // No per-layer source.
    assert!(compiled(tcp, "frame_number", CmpOp::Eq, 1).is_none());
    assert!(compiled(tcp, "timestamp", CmpOp::Gt, 1).is_none());
    // A literal the context column is never compared with.
    assert!(compiled(tcp, "encap_depth", CmpOp::Eq, "0").is_none());
    assert!(compiled(tcp, "tunnel_id", CmpOp::Eq, "7").is_none());
    assert!(compiled(tcp, "tunnel_type", CmpOp::Eq, 1).is_none());
    // A column the table does not have.
    assert!(RowPredicate::cmp(ColId(u16::MAX), CmpOp::Eq, 1)
        .compile(tcp)
        .is_none());
    // `frames` rows and stream-table rows are not built from a layer.
    let frames = table("frames");
    assert!(compiled(frames, "length", CmpOp::Gt, 100).is_none());
    let connections = table("tcp_connections");
    let first = connections.columns().next().unwrap().0;
    assert!(RowPredicate::cmp(first, CmpOp::Eq, 1)
        .compile(connections)
        .is_none());
    // What is left of a mixed conjunction still applies.
    let mut mixed = RowPredicate::And(vec![
        RowPredicate::cmp(col(tcp, "frame_number"), CmpOp::Eq, 1),
        RowPredicate::cmp(col(tcp, "dst_port"), CmpOp::Eq, 443),
    ])
    .compile(tcp)
    .unwrap();
    assert!(!mixed.keeps(of(&tcp_layer())));
}

#[test]
fn context_columns_compare_with_the_layer_context() {
    let tcp = table("tcp");
    let row = tcp_layer();
    let inner = of(&row).in_tunnel(1, TunnelType::Vxlan, Some(42));
    let outer = of(&row);

    let mut depth0 = compiled(tcp, "encap_depth", CmpOp::Eq, 0).unwrap();
    assert!(depth0.keeps(outer));
    assert!(!depth0.keeps(inner));

    let mut vxlan = compiled(tcp, "tunnel_type", CmpOp::Eq, "vxlan").unwrap();
    assert!(vxlan.keeps(inner));
    // Outside a tunnel the column is NULL: undecided.
    assert!(vxlan.keeps(outer));
    let mut gre = compiled(tcp, "tunnel_type", CmpOp::Eq, "gre").unwrap();
    assert!(!gre.keeps(inner));
    assert!(gre.keeps(outer));

    let mut id = compiled(tcp, "tunnel_id", CmpOp::Eq, 42).unwrap();
    assert!(id.keeps(inner));
    assert!(id.keeps(outer));
    let mut other = compiled(tcp, "tunnel_id", CmpOp::NotEq, 42).unwrap();
    assert!(!other.keeps(inner));
    assert!(other.keeps(outer));
    // An id above i64::MAX is undecided.
    let inner = of(&row).in_tunnel(1, TunnelType::Vxlan, Some(u64::MAX));
    assert!(id.keeps(inner));
    assert!(other.keeps(inner));
}

/// The hint follows a field that changes position between rows.
#[test]
fn hinted_lookup_follows_a_moving_field() {
    let tcp = table("tcp");
    let mut p = compiled(tcp, "dst_port", CmpOp::Eq, 80).unwrap();
    let first = tcp_layer();
    let moved = layer(vec![
        ("dst_port", FieldValue::UInt16(443)),
        ("src_port", FieldValue::UInt16(80)),
    ]);
    let absent = layer(vec![("src_port", FieldValue::UInt16(80))]);
    assert!(p.keeps(of(&first)));
    assert!(!p.keeps(of(&moved)));
    assert!(p.keeps(of(&absent)));
    assert!(p.keeps(of(&first)));
}

#[test]
fn for_each_column_visits_nested_comparisons() {
    let p = RowPredicate::And(vec![
        RowPredicate::cmp(ColId(3), CmpOp::Eq, 1),
        RowPredicate::And(vec![RowPredicate::cmp(ColId(5), CmpOp::Eq, "x")]),
    ]);
    let mut seen = Vec::new();
    p.for_each_column(&mut |c| seen.push(c));
    assert_eq!(seen, vec![ColId(3), ColId(5)]);
}

fn packet(frame_number: u64, timestamp_ns: i64) -> PacketRef<'static> {
    PacketRef {
        frame_number,
        timestamp_ns,
        captured_len: 0,
        original_len: 0,
        link_type: 1,
        data: &[],
    }
}

fn range(first: u64, end: Option<u64>) -> PacketRange {
    PacketRange {
        start: PacketPosition {
            byte_offset: 0,
            frame_number: first,
        },
        end: end.map(|frame_number| PacketPosition {
            byte_offset: 0,
            frame_number,
        }),
    }
}

#[test]
fn all_accepts_everything() {
    let all = FramePredicate::all();
    assert!(all.is_all());
    assert_eq!(all, FramePredicate::default());
    assert!(all.accepts(&packet(1, i64::MIN)));
    assert!(all.accepts(&packet(u64::MAX, i64::MAX)));
    assert!(!all.past_end(u64::MAX));
    assert!(all.may_overlap(&PacketRange::whole(), None));
    assert!(all.may_overlap(&range(5, Some(9)), Some((0, 10))));

    for bounded in [
        FramePredicate {
            frames: (Bound::Included(1), Bound::Unbounded),
            ..FramePredicate::all()
        },
        FramePredicate {
            frames: (Bound::Unbounded, Bound::Excluded(9)),
            ..FramePredicate::all()
        },
        FramePredicate {
            time_ns: (Bound::Excluded(0), Bound::Unbounded),
            ..FramePredicate::all()
        },
        FramePredicate {
            time_ns: (Bound::Unbounded, Bound::Included(0)),
            ..FramePredicate::all()
        },
    ] {
        assert!(!bounded.is_all(), "{bounded:?}");
    }
}

#[test]
fn none_accepts_nothing() {
    let none = FramePredicate::none();
    assert!(none.is_empty());
    assert!(!none.is_all());
    assert!(!none.accepts(&packet(1, 0)));
    assert!(!none.accepts(&packet(0, 0)));
    assert!(none.past_end(1));
    assert_eq!(none.intersect(&FramePredicate::all()), none);
}

/// A comparison with a constant is the range of the values it holds
/// for, on the frame number or on the timestamp and nothing else.
#[test]
fn a_comparison_is_its_range() {
    const OPS: [CmpOp; 5] = [CmpOp::Eq, CmpOp::Lt, CmpOp::LtEq, CmpOp::Gt, CmpOp::GtEq];
    let frames = [1, 2, 3, 4, 5, 6, 100, u64::MAX - 1, u64::MAX];
    let times = [i64::MIN, -1_000_000_001, -1, 0, 1, 999, 1000, i64::MAX];
    for op in OPS {
        for constant in frames.into_iter().chain([0]) {
            let predicate = FramePredicate::frame_number(op, constant).unwrap();
            assert_eq!(predicate.time_ns, FramePredicate::all().time_ns);
            for frame in frames {
                assert_eq!(
                    predicate.accepts(&packet(frame, 0)),
                    op.holds(&frame, &constant),
                    "frame {frame} {op:?} {constant}"
                );
            }
        }
        for constant in times {
            let predicate = FramePredicate::timestamp_ns(op, constant).unwrap();
            assert_eq!(predicate.frames, FramePredicate::all().frames);
            for time in times {
                assert_eq!(
                    predicate.accepts(&packet(1, time)),
                    op.holds(&time, &constant),
                    "time {time} {op:?} {constant}"
                );
            }
        }
    }
    // `<>` leaves a hole: not a range.
    assert_eq!(FramePredicate::frame_number(CmpOp::NotEq, 5), None);
    assert_eq!(FramePredicate::timestamp_ns(CmpOp::NotEq, 5), None);
}

/// Every pair of bounds on a small domain: the intersection accepts
/// what both accept, in either order, and intersecting again changes
/// nothing.
#[test]
fn intersection_is_exact_commutative_and_idempotent() {
    let bounds = |values: std::ops::RangeInclusive<u64>| -> Vec<Bound<u64>> {
        let mut bounds = vec![Bound::Unbounded];
        for value in values {
            bounds.push(Bound::Included(value));
            bounds.push(Bound::Excluded(value));
        }
        bounds
    };
    let mut predicates = Vec::new();
    for lower in bounds(1..=4) {
        for upper in bounds(1..=4) {
            predicates.push(FramePredicate {
                frames: (lower, upper),
                ..FramePredicate::all()
            });
        }
    }
    for a in &predicates {
        for b in &predicates {
            let both = a.intersect(b);
            for frame in 0..=6 {
                assert_eq!(
                    both.accepts(&packet(frame, 0)),
                    a.accepts(&packet(frame, 0)) && b.accepts(&packet(frame, 0)),
                    "{a:?} and {b:?}: frame {frame}"
                );
            }
            assert_eq!(both, b.intersect(a), "{a:?} and {b:?}");
            assert_eq!(both.intersect(b), both, "{a:?} and {b:?}");
            assert_eq!(both.intersect(a), both, "{a:?} and {b:?}");
        }
    }
    // The same on timestamps, across zero, and both ranges at once.
    let early = FramePredicate {
        time_ns: (Bound::Included(-5), Bound::Excluded(7)),
        ..FramePredicate::all()
    };
    let late = FramePredicate {
        frames: (Bound::Unbounded, Bound::Included(9)),
        time_ns: (Bound::Excluded(-5), Bound::Included(9)),
    };
    assert_eq!(
        early.intersect(&late),
        FramePredicate {
            frames: (Bound::Unbounded, Bound::Included(9)),
            time_ns: (Bound::Excluded(-5), Bound::Excluded(7)),
        }
    );
    assert_eq!(early.intersect(&FramePredicate::all()), early);
}

#[test]
fn accepts_applies_both_ranges_with_their_bound_kinds() {
    let p = FramePredicate {
        frames: (Bound::Included(10), Bound::Excluded(20)),
        time_ns: (Bound::Excluded(1_000), Bound::Included(2_000)),
    };
    let accepted: Vec<bool> = [
        (9, 1_500),  // below the frame range
        (10, 1_500), // first frame
        (19, 1_500), // last frame
        (20, 1_500), // excluded upper frame bound
        (15, 1_000), // excluded lower time bound
        (15, 1_001),
        (15, 2_000), // included upper time bound
        (15, 2_001),
    ]
    .iter()
    .map(|&(frame, ts)| p.accepts(&packet(frame, ts)))
    .collect();
    assert_eq!(
        accepted,
        [false, true, true, false, false, true, true, false]
    );

    let p = FramePredicate {
        frames: (Bound::Excluded(10), Bound::Included(20)),
        time_ns: (Bound::Included(-5), Bound::Excluded(5)),
    };
    assert!(!p.accepts(&packet(10, 0)));
    assert!(p.accepts(&packet(11, -5)));
    assert!(p.accepts(&packet(20, 4)));
    assert!(!p.accepts(&packet(20, 5)));
    assert!(!p.accepts(&packet(21, 0)));
}

#[test]
fn past_end_follows_the_upper_frame_bound_only() {
    let included = FramePredicate {
        frames: (Bound::Included(5), Bound::Included(20)),
        time_ns: (Bound::Unbounded, Bound::Included(0)),
    };
    assert!(!included.past_end(1)); // before the range is not past it
    assert!(!included.past_end(20));
    assert!(included.past_end(21));

    let excluded = FramePredicate {
        frames: (Bound::Unbounded, Bound::Excluded(20)),
        ..FramePredicate::all()
    };
    assert!(!excluded.past_end(19));
    assert!(excluded.past_end(20));

    // Time bounds never end a scan: timestamps need not ascend.
    let time_only = FramePredicate {
        time_ns: (Bound::Unbounded, Bound::Included(0)),
        ..FramePredicate::all()
    };
    assert!(!time_only.past_end(u64::MAX));
}

/// `last_frame` is the frame before the first that is `past_end`.
#[test]
fn last_frame_is_the_last_frame_the_upper_bound_admits() {
    let upper = |bound| FramePredicate {
        frames: (Bound::Included(5), bound),
        time_ns: (Bound::Unbounded, Bound::Included(0)),
    };
    assert_eq!(upper(Bound::Unbounded).last_frame(), None);
    assert_eq!(upper(Bound::Included(20)).last_frame(), Some(20));
    assert_eq!(upper(Bound::Excluded(20)).last_frame(), Some(19));
    assert_eq!(
        upper(Bound::Included(u64::MAX)).last_frame(),
        Some(u64::MAX)
    );
    // No frame at all: frame numbers start at 1.
    assert_eq!(upper(Bound::Included(0)).last_frame(), None);
    assert_eq!(upper(Bound::Excluded(1)).last_frame(), None);
    assert_eq!(upper(Bound::Excluded(0)).last_frame(), None);
    for bound in [Bound::Included(1), Bound::Excluded(2), Bound::Included(7)] {
        let predicate = upper(bound);
        let last = predicate.last_frame().unwrap();
        assert!(!predicate.past_end(last), "{bound:?}");
        assert!(predicate.past_end(last + 1), "{bound:?}");
    }
    // A time bound says nothing of frame numbers.
    assert_eq!(
        FramePredicate::timestamp_ns(CmpOp::Lt, 5)
            .unwrap()
            .last_frame(),
        None
    );
}

/// `past_end(n)` implies that no frame from `n` on is accepted.
#[test]
fn is_empty_means_no_packet_matches() {
    use Bound::*;
    let frames = |lower, upper| FramePredicate {
        frames: (lower, upper),
        ..FramePredicate::all()
    };
    let time = |lower, upper| FramePredicate {
        time_ns: (lower, upper),
        ..FramePredicate::all()
    };
    assert!(!FramePredicate::all().is_empty());
    for empty in [
        frames(Included(5), Included(4)),
        frames(Included(5), Excluded(5)),
        frames(Excluded(5), Included(5)),
        frames(Excluded(5), Excluded(6)),
        frames(Excluded(u64::MAX), Unbounded),
        frames(Unbounded, Excluded(1)),
        frames(Unbounded, Included(0)),
        frames(Unbounded, Excluded(0)),
        time(Included(5), Included(4)),
        time(Excluded(-1), Excluded(0)),
        time(Unbounded, Excluded(i64::MIN)),
        time(Excluded(i64::MAX), Unbounded),
    ] {
        assert!(empty.is_empty(), "{empty:?}");
    }
    for some in [
        frames(Included(5), Included(5)),
        frames(Excluded(5), Excluded(7)),
        frames(Unbounded, Included(1)),
        frames(Unbounded, Excluded(2)),
        frames(Included(u64::MAX), Unbounded),
        time(Included(-3), Included(-3)),
        time(Excluded(-2), Excluded(0)),
        time(Unbounded, Included(i64::MIN)),
    ] {
        assert!(!some.is_empty(), "{some:?}");
    }
    // Exhaustively over a small domain: empty exactly when nothing is
    // accepted.
    let bounds = |v: i64| [Unbounded, Included(v), Excluded(v)];
    for low in 0..6i64 {
        for high in 0..6i64 {
            for lower in bounds(low) {
                for upper in bounds(high) {
                    let p = time(lower, upper);
                    let any = (-2..9).any(|ts| p.accepts(&packet(1, ts)));
                    assert_eq!(p.is_empty(), !any, "{p:?}");
                    let as_u64 = |b: Bound<i64>| match b {
                        Unbounded => Unbounded,
                        Included(v) => Included(v as u64),
                        Excluded(v) => Excluded(v as u64),
                    };
                    let p = frames(as_u64(lower), as_u64(upper));
                    let any = (1..9).any(|frame| p.accepts(&packet(frame, 0)));
                    assert_eq!(p.is_empty(), !any, "{p:?}");
                }
            }
        }
    }
}

#[test]
fn past_end_agrees_with_accepts() {
    let bounds = |v: u64| [Bound::Unbounded, Bound::Included(v), Bound::Excluded(v)];
    for lower in bounds(3) {
        for upper in bounds(6) {
            let p = FramePredicate {
                frames: (lower, upper),
                ..FramePredicate::all()
            };
            for n in 0..10u64 {
                let later = (n..12).any(|m| p.accepts(&packet(m, 0)));
                assert_eq!(p.past_end(n), !later, "{p:?} at {n}");
            }
        }
    }
}

#[test]
fn may_overlap_is_exact_about_frame_ranges() {
    let bounds = |v: u64| [Bound::Unbounded, Bound::Included(v), Bound::Excluded(v)];
    for lower in bounds(4) {
        for upper in bounds(8) {
            let p = FramePredicate {
                frames: (lower, upper),
                ..FramePredicate::all()
            };
            for first in 1..12u64 {
                // Ranges with an end (including empty ones) ...
                for end in first..14 {
                    let any = (first..end).any(|n| p.accepts(&packet(n, 0)));
                    assert_eq!(
                        p.may_overlap(&range(first, Some(end)), None),
                        any,
                        "{p:?} over {first}..{end}"
                    );
                }
                // ... and to the end of the capture.
                let any = (first..40).any(|n| p.accepts(&packet(n, 0)));
                assert_eq!(
                    p.may_overlap(&range(first, None), None),
                    any,
                    "{p:?} from {first}"
                );
            }
        }
    }
}

#[test]
fn may_overlap_uses_known_timestamps() {
    let p = FramePredicate {
        frames: (Bound::Unbounded, Bound::Unbounded),
        time_ns: (Bound::Included(100), Bound::Excluded(200)),
    };
    let whole = PacketRange::whole();
    // Unknown timestamps cannot rule a range out.
    assert!(p.may_overlap(&whole, None));
    assert!(!p.may_overlap(&whole, Some((0, 99))));
    assert!(p.may_overlap(&whole, Some((0, 100))));
    assert!(p.may_overlap(&whole, Some((150, 160))));
    assert!(p.may_overlap(&whole, Some((199, 500))));
    assert!(!p.may_overlap(&whole, Some((200, 500))));
    assert!(p.may_overlap(&whole, Some((0, 500))));

    let p = FramePredicate {
        frames: (Bound::Unbounded, Bound::Unbounded),
        time_ns: (Bound::Excluded(100), Bound::Included(200)),
    };
    assert!(!p.may_overlap(&whole, Some((0, 100))));
    assert!(p.may_overlap(&whole, Some((0, 101))));
    assert!(p.may_overlap(&whole, Some((200, 500))));
    assert!(!p.may_overlap(&whole, Some((201, 500))));

    // Both must allow the range.
    let p = FramePredicate {
        frames: (Bound::Included(10), Bound::Unbounded),
        time_ns: (Bound::Included(100), Bound::Unbounded),
    };
    assert!(!p.may_overlap(&range(1, Some(10)), Some((100, 200))));
    assert!(!p.may_overlap(&range(10, Some(20)), Some((0, 99))));
    assert!(p.may_overlap(&range(10, Some(20)), Some((0, 100))));
}
