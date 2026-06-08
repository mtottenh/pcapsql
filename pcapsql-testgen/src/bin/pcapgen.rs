//! `pcapgen` — a tiny CLI that writes deterministic PCAP/PCAPNG test fixtures.
//!
//! Usage:
//!   pcapgen <kind> <out_path> [seed] [count]
//!
//! `kind` is one of:
//!   legacy-le-micro, legacy-be-micro, legacy-le-nano, legacy-be-nano,
//!   pcapng, pcapng-multi-iface, pcapng-multi-section, pcapng-midstream-iface,
//!   oversized, jumbo, truncated
//!
//! The generated `bytes` are written to `out_path`; the number of expected
//! frames is printed to stdout. Used by docker / test setup scripts.

use std::process::ExitCode;

use pcapsql_testgen::{
    generate, jumbo_straddle_capture, oversized_frame_capture, truncated_capture, CaptureSpec,
    Format, GeneratedCapture,
};

const USAGE: &str = "usage: pcapgen <kind> <out_path> [seed] [count]\n\
kinds: legacy-le-micro, legacy-be-micro, legacy-le-nano, legacy-be-nano,\n\
       pcapng, pcapng-multi-iface, pcapng-multi-section, pcapng-midstream-iface,\n\
       oversized, jumbo, truncated";

fn main() -> ExitCode {
    // Only std::env::args is used (no clap).
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    }

    let kind = args[1].as_str();
    let out_path = args[2].as_str();
    let seed: u64 = args.get(3).map(|s| s.parse().unwrap_or(0)).unwrap_or(0);
    let count: usize = args.get(4).map(|s| s.parse().unwrap_or(16)).unwrap_or(16);

    let capture = match build(kind, seed, count) {
        Some(c) => c,
        None => {
            eprintln!("unknown kind: {kind}\n{USAGE}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = std::fs::write(out_path, &capture.bytes) {
        eprintln!("failed to write {out_path}: {e}");
        return ExitCode::FAILURE;
    }

    // Print the number of expected frames to stdout for scripts to consume.
    println!("{}", capture.expected.len());
    ExitCode::SUCCESS
}

/// Build a capture for the requested kind, or `None` if the kind is unknown.
fn build(kind: &str, seed: u64, count: usize) -> Option<GeneratedCapture> {
    let legacy = |format: Format| CaptureSpec {
        format,
        seed,
        packet_count: count,
        min_size: 14,
        max_size: 512,
        link_type: 1,
        ..Default::default()
    };

    let capture = match kind {
        "legacy-le-micro" => generate(&legacy(Format::LegacyLeMicro)),
        "legacy-be-micro" => generate(&legacy(Format::LegacyBeMicro)),
        "legacy-le-nano" => generate(&legacy(Format::LegacyLeNano)),
        "legacy-be-nano" => generate(&legacy(Format::LegacyBeNano)),
        "pcapng" => generate(&CaptureSpec {
            format: Format::Pcapng,
            seed,
            packet_count: count,
            min_size: 14,
            max_size: 512,
            link_type: 1,
            interfaces: vec![6],
            sections: 1,
            add_interface_midstream: false,
        }),
        "pcapng-multi-iface" => generate(&CaptureSpec {
            format: Format::Pcapng,
            seed,
            packet_count: count,
            min_size: 14,
            max_size: 512,
            link_type: 1,
            interfaces: vec![6, 9],
            sections: 1,
            add_interface_midstream: false,
        }),
        "pcapng-multi-section" => generate(&CaptureSpec {
            format: Format::Pcapng,
            seed,
            packet_count: count,
            min_size: 14,
            max_size: 512,
            link_type: 1,
            interfaces: vec![6],
            sections: 3,
            add_interface_midstream: false,
        }),
        "pcapng-midstream-iface" => generate(&CaptureSpec {
            format: Format::Pcapng,
            seed,
            packet_count: count,
            min_size: 14,
            max_size: 512,
            link_type: 1,
            interfaces: vec![6],
            sections: 1,
            add_interface_midstream: true,
        }),
        // A frame larger than the 262_144-byte read buffer.
        "oversized" => oversized_frame_capture(300_000),
        // A jumbo frame straddling a partition seam, with normal frames around.
        "jumbo" => jumbo_straddle_capture(seed, 280_000, count.max(1)),
        // A capture cut off mid-record.
        "truncated" => truncated_capture(seed),
        _ => return None,
    };

    Some(capture)
}
