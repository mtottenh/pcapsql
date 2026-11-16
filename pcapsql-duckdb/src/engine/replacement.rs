//! The replacement scan: a capture file named where a table is expected.
//!
//! ```sql
//! SELECT count(*) FROM 'capture.pcap';
//! SELECT * FROM 'captures/*.pcapng.gz' WHERE length > 1000;
//! ```
//!
//! DuckDB asks the registered replacement scans about a table name it cannot resolve. A name
//! that [`is_capture_path`] is answered with `read_pcap(<name>)`, the `frames` table of the
//! capture; a glob pattern is passed on as it is, since `read_pcap` expands it. Any other name
//! is left to DuckDB and to the replacement scans of other extensions.
//!
//! Tables and views come first: DuckDB only asks when the catalog (and the `search_path`) has
//! nothing of that name, so a table that is called `x.pcap` is read as the table. Nothing is
//! looked up here: whether the file exists is `read_pcap`'s to say, with its own error.

use duckdb_neo::{
    connection::Context,
    extension::Extension,
    qualified_name::QualifiedName,
    replacement_scan::{
        ReplacementHandle, ReplacementScanBuilder, ReplacementScanCallbacks, ReplacementType,
    },
    types::ToValue,
    Result,
};

use super::guard;

/// The function a capture path is read with.
const FUNCTION: &str = "read_pcap";

/// The file name extensions of a capture, lower case.
const CAPTURE_EXTENSIONS: [&str; 3] = [".pcap", ".pcapng", ".cap"];

/// The extensions a compressed capture has after its own, lower case.
const COMPRESSION_EXTENSIONS: [&str; 2] = [".gz", ".zst"];

pub(super) fn register(extension: &Extension) -> Result<()> {
    ReplacementScanBuilder::new(CapturePaths).register(extension)
}

/// Whether a table name is the path of a capture: it ends in `.pcap`, `.pcapng` or `.cap`,
/// optionally followed by `.gz` or `.zst`, in any case.
///
/// The extension decides, not the content: the file is not opened here, and a capture under
/// another name is read with `read_pcap('...')`.
pub fn is_capture_path(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let plain = COMPRESSION_EXTENSIONS
        .iter()
        .find_map(|extension| name.strip_suffix(extension))
        .unwrap_or(&name);
    CAPTURE_EXTENSIONS
        .iter()
        .any(|extension| plain.ends_with(extension))
}

struct CapturePaths;

impl ReplacementScanCallbacks for CapturePaths {
    fn scan(
        &self,
        context: &Context,
        name: &QualifiedName,
        handle: ReplacementHandle<'_>,
    ) -> Result<()> {
        guard::run("the replacement scan", || {
            let name = name.get_view()?;
            // `FROM 'x.pcap'` is a name of one part. With a schema or a catalog in front it is
            // a table someone means, which DuckDB did not find.
            if name.catalog.is_some() || name.schema.is_some() || !is_capture_path(&name.table) {
                return Ok(());
            }
            handle.set_reference(ReplacementType::Table(QualifiedName::from_parts(&[
                FUNCTION,
            ])?))?;
            handle.add_parameter(name.table.value(context)?)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_paths_are_told_by_their_extension() {
        for path in [
            "x.pcap",
            "x.pcapng",
            "x.cap",
            "x.pcap.gz",
            "x.pcapng.gz",
            "x.cap.gz",
            "x.pcap.zst",
            "x.pcapng.zst",
            "x.cap.zst",
            "X.PCAP",
            "x.PcapNG.GZ",
            "/var/captures/2024-01-01 night.pcap",
            "captures/*.pcap",
            "captures/**/eth[01].pcapng.zst",
            "s3://bucket/key/x.cap.gz",
            ".pcap",
        ] {
            assert!(is_capture_path(path), "{path}");
        }
        for name in [
            "",
            "pcap",
            "frames",
            "x.pcap.txt",
            "x.pcapx",
            "x.pcap.bz2",
            "x.gz",
            "x.zst",
            "x.csv",
            "x.parquet",
            "xpcap",
            "x.pcap ",
            "x.pcap.gz.gz",
        ] {
            assert!(!is_capture_path(name), "{name}");
        }
    }
}
