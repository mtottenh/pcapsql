use std::io::Cursor;

use pcapsql_core::io::{build_boundary_index, PacketPosition, PcapFormat};
use pcapsql_testgen::{
    legacy_pcap, pcapng, GenPacket, LegacyVariant, PcapngInterface, PcapngPacket, PcapngSection,
};

use super::*;

/// Frames of the test captures, and the stride of their indexes.
const FRAMES: u32 = 4000;
const STRIDE: u64 = 500;

/// The data of packet `i`: 60 to 99 bytes that are the packet's own.
fn data(i: u32) -> Vec<u8> {
    (0..60 + i % 40).map(|j| (i * 7 + j) as u8).collect()
}

fn legacy() -> Vec<u8> {
    let packets: Vec<GenPacket> = (0..FRAMES)
        .map(|i| GenPacket {
            ts_sec: 1_700_000_000 + i / 100,
            ts_frac: i,
            data: data(i),
            origlen: 100,
        })
        .collect();
    legacy_pcap(LegacyVariant::LeMicro, 1, 65535, &packets).bytes
}

fn ng() -> Vec<u8> {
    let section = PcapngSection {
        interfaces: vec![PcapngInterface {
            link_type: 1,
            tsresol: 6,
            snaplen: 65535,
            if_tsoffset: 0,
        }],
        packets: (0..FRAMES)
            .map(|i| PcapngPacket {
                interface_id: 0,
                ts_sec: 1_700_000_000 + u64::from(i / 100),
                ts_frac_units: u64::from(i),
                data: data(i),
                origlen: 100,
            })
            .collect(),
    };
    pcapng(&[section]).bytes
}

fn index_of(bytes: &[u8]) -> Arc<BoundaryIndex> {
    let format = PcapFormat::detect(bytes).unwrap();
    let len = bytes.len() as u64;
    Arc::new(build_boundary_index(Cursor::new(bytes), format, STRIDE, len, None, 0).unwrap())
}

/// `index` kept with what `bytes`, the capture it is the index of, look like.
fn cached(bytes: &[u8], index: Arc<BoundaryIndex>) -> Cached {
    let size = bytes.len() as u64;
    let fingerprint = Fingerprint::of(&mut &bytes[..], size).unwrap();
    Cached::new(index, fingerprint, &mut &bytes[..]).unwrap()
}

/// What the checks say of `cached` for the file `bytes`, the records at `frames` included.
fn check(cached: &Cached, bytes: &[u8], frames: &[u64]) -> Result<(), Stale> {
    let now = Fingerprint::of(&mut &bytes[..], bytes.len() as u64).unwrap();
    cached.check_file(&now)?;
    cached.check_records(&mut &bytes[..], frames.iter().copied())
}

/// The frames of every checkpoint of `index`.
fn checkpoints(index: &BoundaryIndex) -> Vec<u64> {
    index.checkpoints.iter().map(|c| c.frame_number).collect()
}

/// A small index of `checkpoints` checkpoints, for the tests of the cache's bookkeeping.
fn small(stride: u64, checkpoints: u64) -> Cached {
    let bytes = legacy();
    let mut index = (*index_of(&bytes)).clone();
    index.stride = stride;
    index.checkpoints.truncate(checkpoints as usize);
    index.checkpoints.shrink_to_fit();
    cached(&bytes, Arc::new(index))
}

#[test]
fn an_index_is_found_by_its_path_and_stride() {
    let cache = IndexCache::default();
    assert!(cache.get("a.pcap", 500).is_none());
    assert!(cache.insert("a.pcap", small(500, 2)));
    assert!(cache.insert("a.pcap", small(1000, 2)));
    assert!(cache.insert("b.pcap", small(500, 2)));
    assert_eq!(cache.usage().0, 3);
    assert_eq!(cache.get("a.pcap", 500).unwrap().index.stride, 500);
    assert_eq!(cache.get("a.pcap", 1000).unwrap().index.stride, 1000);
    assert!(cache.get("a.pcap", 250).is_none());
    // The path as it is written: another spelling of the same file is another entry.
    assert!(cache.get("./a.pcap", 500).is_none());
    assert!(cache.get("c.pcap", 500).is_none());
}

#[test]
fn an_index_kept_again_takes_the_place_of_the_last() {
    let cache = IndexCache::default();
    cache.insert("a.pcap", small(500, 8));
    let (_, eight) = cache.usage();
    cache.insert("a.pcap", small(500, 2));
    let (entries, two) = cache.usage();
    assert_eq!(entries, 1);
    assert!(two < eight, "{two} {eight}");
    assert_eq!(cache.get("a.pcap", 500).unwrap().index.checkpoints.len(), 2);
}

#[test]
fn the_index_used_longest_ago_goes_first() {
    let cache = IndexCache::with_limits(3, MAX_BYTES);
    for path in ["a", "b", "c"] {
        assert!(cache.insert(path, small(500, 2)));
    }
    // `a` is used again, so `b` is now the one used longest ago.
    assert!(cache.get("a", 500).is_some());
    cache.insert("d", small(500, 2));
    assert_eq!(cache.usage().0, 3);
    assert!(cache.get("b", 500).is_none());
    for path in ["a", "c", "d"] {
        assert!(cache.get(path, 500).is_some(), "{path}");
    }
    // A lookup that finds nothing changes nothing.
    assert!(cache.get("b", 500).is_none());
    cache.insert("e", small(500, 2));
    assert!(cache.get("a", 500).is_none());
}

#[test]
fn the_cache_keeps_to_its_bytes() {
    let one = weight("p00", &small(500, 4).index);
    // Room for four such entries.
    let cache = IndexCache::with_limits(MAX_ENTRIES, 4 * one + one / 2);
    for i in 0..10 {
        assert!(cache.insert(&format!("p{i:02}"), small(500, 4)));
        let (entries, bytes) = cache.usage();
        assert!(bytes <= 4 * one + one / 2, "{i}: {bytes}");
        assert_eq!(entries, (i + 1).min(4), "{i}");
    }
    // The last four are left.
    for i in 0..10 {
        assert_eq!(cache.get(&format!("p{i:02}"), 500).is_some(), i >= 6, "{i}");
    }
    // An index larger than a quarter of the limit is not kept, and drops nothing.
    assert!(!cache.insert("large", small(500, 8)));
    assert_eq!(cache.usage().0, 4);
    assert!(cache.get("large", 500).is_none());
    // A cache with no room keeps nothing.
    let none = IndexCache::with_limits(0, MAX_BYTES);
    assert!(!none.insert("a", small(500, 2)));
    assert_eq!(none.usage(), (0, 0));
}

#[test]
fn the_default_limits_hold_a_large_index() {
    // A capture of 4 billion frames at the default stride, which is as many checkpoints as
    // an index may have to be kept.
    let bytes = legacy();
    let mut index = (*index_of(&bytes)).clone();
    let checkpoint = index.checkpoints[0].clone();
    index.checkpoints = vec![checkpoint; MAX_CHECKPOINTS];
    let cached = Cached {
        index: Arc::new(index),
        fingerprint: Fingerprint::of(&mut &bytes[..], bytes.len() as u64).unwrap(),
        marks: vec![0; MAX_CHECKPOINTS].into(),
    };
    let weight = weight("x", &cached.index);
    assert!(weight <= MAX_BYTES / 4, "{weight}");
    assert!(weight > MAX_CHECKPOINTS * 64, "{weight}");
}

/// What a vector has room for counts, not only what it holds: the vector of checkpoints the
/// pass grows has room for up to twice as many. A path counts by its length.
#[test]
fn the_weight_of_an_index_is_what_it_takes_in_memory() {
    let mut index = (*index_of(&legacy())).clone();
    index.checkpoints.shrink_to_fit();
    let tight = weight("a", &index);
    index.checkpoints.reserve_exact(index.checkpoints.len());
    let roomy = weight("a", &index);
    assert_eq!(
        roomy - tight,
        (index.checkpoints.capacity() - index.checkpoints.len()) * size_of::<Checkpoint>()
    );
    assert_eq!(weight("abcd", &index) - weight("a", &index), 3);
    // More than the index alone: its marks and its place in the map.
    let alone = size_of::<BoundaryIndex>() + index.checkpoints.len() * size_of::<Checkpoint>();
    assert!(
        tight > alone + index.checkpoints.len() * size_of::<u64>(),
        "{tight}"
    );
}

#[test]
fn an_index_too_large_is_not_admitted() {
    let entry = small(500, 4);
    let one = weight("a", &entry.index);
    let cache = IndexCache::with_limits(MAX_ENTRIES, 4 * one);
    assert!(cache.admits("a", &entry.index));
    // A longer path is a heavier entry.
    assert!(!cache.admits(&"a".repeat(64), &entry.index));
    assert!(!IndexCache::with_limits(0, MAX_BYTES).admits("a", &entry.index));
    assert!(cache.insert("a", entry));
}

#[test]
fn forget_drops_the_index_of_a_path_and_stride() {
    let cache = IndexCache::default();
    cache.insert("a", small(500, 2));
    cache.insert("a", small(1000, 2));
    cache.insert("b", small(500, 2));
    cache.forget("a", 500);
    assert!(cache.get("a", 500).is_none());
    assert!(cache.get("a", 1000).is_some());
    assert!(cache.get("b", 500).is_some());
    cache.forget("a", 1000);
    cache.forget("b", 500);
    assert_eq!(cache.usage(), (0, 0));
    // Nothing to forget.
    cache.forget("a", 500);
    assert_eq!(cache.usage(), (0, 0));
}

#[test]
fn an_index_of_the_file_it_was_built_from_passes_every_check() {
    for bytes in [legacy(), ng()] {
        let index = index_of(&bytes);
        assert!(index.checkpoints.len() >= 8);
        // More than both edges, so that the middle of the file is in neither.
        assert!(bytes.len() as u64 > 4 * EDGE_BYTES, "{}", bytes.len());
        let cached = cached(&bytes, index.clone());
        assert_eq!(check(&cached, &bytes, &checkpoints(&index)), Ok(()));
        // A frame that is no checkpoint's is passed over.
        assert_eq!(check(&cached, &bytes, &[2, 3, 499]), Ok(()));
    }
}

#[test]
fn a_file_of_another_size_or_with_other_edges_is_not_the_file() {
    for bytes in [legacy(), ng()] {
        let cached = cached(&bytes, index_of(&bytes));
        let size = bytes.len() as u64;

        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(
            check(&cached, &longer, &[]),
            Err(Stale::Size {
                was: size,
                is: size + 1
            })
        );
        let shorter = &bytes[..bytes.len() - 1];
        assert!(matches!(
            check(&cached, shorter, &[]),
            Err(Stale::Size { .. })
        ));

        // One byte in the first 64 KiB, and one in the last.
        for (at, stale) in [
            (100, Stale::Head),
            (EDGE_BYTES as usize - 1, Stale::Head),
            (bytes.len() - EDGE_BYTES as usize, Stale::Tail),
            (bytes.len() - 1, Stale::Tail),
        ] {
            let mut changed = bytes.clone();
            changed[at] ^= 1;
            assert_eq!(check(&cached, &changed, &[]), Err(stale), "byte {at}");
        }
    }
}

#[test]
fn a_record_that_changed_at_a_checkpoint_is_found_where_it_is_looked_for() {
    for bytes in [legacy(), ng()] {
        let index = index_of(&bytes);
        let cached = cached(&bytes, index.clone());
        // A checkpoint in the middle of the file, outside both edges.
        let middle = index
            .checkpoints
            .iter()
            .find(|c| c.byte_offset > 2 * EDGE_BYTES)
            .unwrap();
        let (frame, offset) = (middle.frame_number, middle.byte_offset as usize);
        assert!((offset as u64) < bytes.len() as u64 - 2 * EDGE_BYTES);
        // The first and the last of the bytes looked at: the record's time, and the start of
        // its packet.
        for at in [offset + 4, offset + MARK_BYTES as usize - 1] {
            let mut changed = bytes.clone();
            changed[at] ^= 0x10;
            assert_eq!(
                check(&cached, &changed, &checkpoints(&index)),
                Err(Stale::Record { frame }),
                "byte {at}"
            );
            // Only where the scan relies on a record starting.
            assert_eq!(check(&cached, &changed, &[1, frame + STRIDE]), Ok(()));
        }
        // A record that moved: the bytes at the checkpoint are now those before it.
        let mut moved = bytes.clone();
        moved.copy_within(offset - 16..offset + 64, offset - 12);
        assert_eq!(
            check(&cached, &moved, &[frame]),
            Err(Stale::Record { frame })
        );
    }
}

/// What the checks do not see, as the module documentation says: a change between the bytes
/// looked at, here the content of a packet and the time of a frame in the middle of a window.
#[test]
fn a_change_between_the_bytes_looked_at_passes() {
    for bytes in [legacy(), ng()] {
        let index = index_of(&bytes);
        let cached = cached(&bytes, index.clone());
        let at = index
            .checkpoints
            .iter()
            .find(|c| c.byte_offset > 2 * EDGE_BYTES)
            .unwrap()
            .byte_offset as usize
            + 200;
        let mut changed = bytes.clone();
        changed[at] ^= 0xff;
        assert_eq!(check(&cached, &changed, &checkpoints(&index)), Ok(()));
    }
}

#[test]
fn a_file_too_short_to_read_at_a_checkpoint_is_unreadable() {
    let bytes = legacy();
    let index = index_of(&bytes);
    let cached = cached(&bytes, index.clone());
    let last = index.checkpoints.last().unwrap();
    let cut = &bytes[..last.byte_offset as usize + 8];
    // The size check would see it first; the record check on its own says it cannot read.
    assert!(matches!(
        cached.check_records(&mut &cut[..], [last.frame_number]),
        Err(Stale::Unreadable(_))
    ));
}

#[test]
fn the_records_relied_on_are_where_ranges_start_and_end_and_the_last_checkpoint() {
    let bytes = legacy();
    let index = index_of(&bytes);
    let at = |frame: u64| PacketPosition {
        byte_offset: index
            .checkpoints
            .iter()
            .find(|c| c.frame_number == frame)
            .unwrap()
            .byte_offset,
        frame_number: frame,
    };
    let ranges = [
        PacketRange {
            start: at(1001),
            end: Some(at(2001)),
        },
        PacketRange {
            start: at(2001),
            end: Some(at(2501)),
        },
        PacketRange {
            start: at(3001),
            end: None,
        },
    ];
    assert_eq!(relied_on(&index, &ranges), [1001, 2001, 2501, 3001, 3501]);
    assert_eq!(relied_on(&index, &[]), [3501]);
    assert_eq!(index.packet_count, u64::from(FRAMES));
}

#[test]
fn only_an_index_of_the_whole_capture_is_kept() {
    let bytes = legacy();
    let index = index_of(&bytes);
    let frames = u64::from(FRAMES);
    assert!(is_whole(&index, None));
    // A bound past the last frame: the pass got to the end.
    assert!(is_whole(&index, Some(frames + 1)));
    // A bound at the last frame: the pass stopped there and cannot know that it was the
    // last, nor at any frame before.
    let mut partial = (*index).clone();
    partial.packet_count = 3000;
    assert!(!is_whole(&partial, Some(3000)));
    assert!(!is_whole(&index, Some(frames)));
    assert!(is_whole(&partial, Some(3001)));

    assert!(worth_keeping(&index, None));
    assert!(!worth_keeping(&partial, Some(3000)));
    let mut dense = (*index).clone();
    dense.checkpoints = vec![dense.checkpoints[0].clone(); MAX_CHECKPOINTS + 1];
    assert!(!worth_keeping(&dense, None));
    dense.checkpoints.pop();
    assert!(worth_keeping(&dense, None));
}

#[test]
fn a_reason_is_a_sentence_part() {
    let reasons = [
        Stale::Size { was: 10, is: 12 }.to_string(),
        Stale::Head.to_string(),
        Stale::Tail.to_string(),
        Stale::Record { frame: 3001 }.to_string(),
        Stale::Unreadable("end of file".into()).to_string(),
    ];
    assert_eq!(
        reasons,
        [
            "the file was 10 bytes and is 12",
            "the first 64 KiB of the file changed",
            "the last 64 KiB of the file changed",
            "the record of frame 3001 changed",
            "the file could not be read: end of file",
        ]
    );
}

/// A kept index cut at a bound on `frame_number` is the index the pass builds when it stops
/// there, but for the timestamps of its last window.
#[test]
fn a_kept_index_cut_at_a_frame_is_that_of_a_pass_to_it() {
    use super::super::layout::first_frames;
    use pcapsql_core::io::build_boundary_index_to;

    for bytes in [legacy(), ng()] {
        let format = PcapFormat::detect(&bytes).unwrap();
        let len = bytes.len() as u64;
        let whole = index_of(&bytes);
        for last in [1, 2, 499, 500, 501, 1000, 3999, 4000, 4001, 10_000] {
            let pass = build_boundary_index_to(
                Cursor::new(&bytes[..]),
                format,
                STRIDE,
                len,
                None,
                0,
                Some(last),
            )
            .unwrap();
            let cut = first_frames(&whole, Some(last));
            assert_eq!(cut.packet_count, pass.packet_count, "{last}");
            assert_eq!(cut.checkpoints.len(), pass.checkpoints.len(), "{last}");
            let windows = cut.checkpoints.len();
            for (i, (a, b)) in cut.checkpoints.iter().zip(&pass.checkpoints).enumerate() {
                assert_eq!(a.frame_number, b.frame_number);
                assert_eq!(a.byte_offset, b.byte_offset);
                assert_eq!(a.interface_state, b.interface_state);
                if i + 1 < windows {
                    assert_eq!((a.min_ts, a.max_ts), (b.min_ts, b.max_ts), "{last}");
                }
            }
            assert_eq!(
                (
                    cut.format,
                    cut.link_type,
                    cut.snaplen,
                    cut.stride,
                    cut.source_len
                ),
                (
                    pass.format,
                    pass.link_type,
                    pass.snaplen,
                    pass.stride,
                    pass.source_len
                )
            );
        }
        // No bound, or one past the end: the index itself.
        assert!(Arc::ptr_eq(&first_frames(&whole, None), &whole));
        assert!(Arc::ptr_eq(
            &first_frames(&whole, Some(u64::from(FRAMES))),
            &whole
        ));
    }
}
