//! Text formatting of the values the CLI prints outside a result table.

/// Format a byte count with binary units (KiB, MiB, …).
pub(super) fn format_bytes_binary(b: usize) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

/// Format a byte count with decimal units (KB, MB, GB).
pub(super) fn format_bytes_decimal(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.1} GB", bytes as f64 / 1_000_000_000.0)
    } else if bytes >= 1_000_000 {
        format!("{:.1} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.1} KB", bytes as f64 / 1_000.0)
    } else {
        format!("{bytes} B")
    }
}

/// Format a microsecond Unix timestamp as ISO 8601 UTC.
pub(super) fn format_timestamp_us(us: i64) -> String {
    // Convert to broken-down time components
    let secs_since_epoch = us / 1_000_000;
    let subsec_us = us % 1_000_000;

    // Calculate date/time components (simplified UTC calculation)
    let days_since_epoch = secs_since_epoch / 86400;
    let time_of_day = secs_since_epoch % 86400;

    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Calculate year, month, day from days since epoch (1970-01-01)
    let (year, month, day) = days_to_ymd(days_since_epoch);

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}.{subsec_us:06}Z")
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: i64) -> (i64, u32, u32) {
    // Algorithm from Howard Hinnant's date algorithms
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Format a duration in microseconds as human-readable string.
pub(super) fn format_duration_us(us: i64) -> String {
    let total_secs = us / 1_000_000;
    let subsec_ms = (us % 1_000_000) / 1000;

    let hours = total_secs / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;

    if hours > 0 {
        format!("{hours}h {mins}m {secs}.{subsec_ms:03}s")
    } else if mins > 0 {
        format!("{mins}m {secs}.{subsec_ms:03}s")
    } else {
        format!("{secs}.{subsec_ms:03}s")
    }
}

/// Format a count with thousands separators.
pub(super) fn format_count(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i.is_multiple_of(3) {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

/// Render an ASCII bar for histogram display.
pub(super) fn render_bar(value: u64, max_value: u64, max_width: usize) -> String {
    if max_value == 0 {
        return String::new();
    }
    let width = ((value as f64 / max_value as f64) * max_width as f64) as usize;
    "█".repeat(width.max(1))
}

/// Format an Arrow array value at a given index as a string.
pub(super) fn format_arrow_value(array: &dyn arrow::array::Array, index: usize) -> String {
    use arrow::array::{
        BinaryArray, Float32Array, Float64Array, Int16Array, Int32Array, Int64Array, Int8Array,
        StringArray, UInt16Array, UInt32Array, UInt64Array, UInt8Array,
    };

    if array.is_null(index) {
        return "NULL".to_string();
    }

    // Try various types
    if let Some(a) = array.as_any().downcast_ref::<StringArray>() {
        return a.value(index).to_string();
    }
    if let Some(a) = array.as_any().downcast_ref::<Int64Array>() {
        return a.value(index).to_string();
    }
    if let Some(a) = array.as_any().downcast_ref::<UInt64Array>() {
        return a.value(index).to_string();
    }
    if let Some(a) = array.as_any().downcast_ref::<Int32Array>() {
        return a.value(index).to_string();
    }
    if let Some(a) = array.as_any().downcast_ref::<UInt32Array>() {
        return a.value(index).to_string();
    }
    if let Some(a) = array.as_any().downcast_ref::<Int16Array>() {
        return a.value(index).to_string();
    }
    if let Some(a) = array.as_any().downcast_ref::<UInt16Array>() {
        return a.value(index).to_string();
    }
    if let Some(a) = array.as_any().downcast_ref::<Int8Array>() {
        return a.value(index).to_string();
    }
    if let Some(a) = array.as_any().downcast_ref::<UInt8Array>() {
        return a.value(index).to_string();
    }
    if let Some(a) = array.as_any().downcast_ref::<Float64Array>() {
        return format!("{:.2}", a.value(index));
    }
    if let Some(a) = array.as_any().downcast_ref::<Float32Array>() {
        return format!("{:.2}", a.value(index));
    }
    if let Some(a) = array.as_any().downcast_ref::<BinaryArray>() {
        let bytes = a.value(index);
        if bytes.len() <= 8 {
            return bytes.iter().map(|b| format!("{b:02x}")).collect();
        } else {
            let prefix: String = bytes[..8].iter().map(|b| format!("{b:02x}")).collect();
            return format!("{prefix}...");
        }
    }

    let dt = array.data_type();
    format!("{dt:?}")
}

/// Format bytes as a standard hexdump (16 bytes per line, hex + ASCII).
pub(super) fn format_hexdump(frame_number: u64, data: &[u8]) -> String {
    let mut output = String::new();
    output.push_str(&format!("Frame {} ({} bytes):\n", frame_number, data.len()));

    for (chunk_idx, chunk) in data.chunks(16).enumerate() {
        let offset = chunk_idx * 16;

        // Offset
        output.push_str(&format!("{offset:08x}  "));

        // Hex bytes (space after 8 bytes)
        for (i, byte) in chunk.iter().enumerate() {
            if i == 8 {
                output.push(' ');
            }
            output.push_str(&format!("{byte:02x} "));
        }

        // Padding for incomplete last line
        if chunk.len() < 16 {
            for _ in 0..(16 - chunk.len()) {
                output.push_str("   ");
            }
            if chunk.len() <= 8 {
                output.push(' ');
            }
        }

        // ASCII representation
        output.push_str(" |");
        for byte in chunk {
            if *byte >= 32 && *byte < 127 {
                output.push(*byte as char);
            } else {
                output.push('.');
            }
        }
        // Pad ASCII if incomplete
        for _ in chunk.len()..16 {
            output.push(' ');
        }
        output.push_str("|\n");
    }

    output
}
