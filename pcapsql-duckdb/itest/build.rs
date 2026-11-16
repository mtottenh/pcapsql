//! Takes the capture builders and the query corpus out of the DataFusion frontend's golden test,
//! so that the differential test (`tests/golden_differential.rs`) reads exactly the captures and
//! runs exactly the queries the committed DataFusion snapshots were made from.
//!
//! `pcapsql-datafusion/tests/golden_corpus.rs` is a test file, not a library, and this crate must
//! not depend on `pcapsql-datafusion`. The part of it between its "Packet crafting" and "Harness"
//! section headings is plain Rust over `pcapsql-testgen` (frame builders, the capture builders,
//! the `Capture` enum and the `CORPUS` table); it is copied to `OUT_DIR` and included by
//! `src/golden.rs`. A copy made at build time cannot drift from the original.

use std::{env, fs, path::PathBuf};

const SOURCE: &str = "../../pcapsql-datafusion/tests/golden_corpus.rs";
const FIRST_SECTION: &str = "// Packet crafting";
const END_SECTION: &str = "// Harness";

fn main() {
    println!("cargo:rerun-if-changed={SOURCE}");
    println!("cargo:rerun-if-changed=build.rs");
    let text = fs::read_to_string(SOURCE).unwrap_or_else(|error| panic!("{SOURCE}: {error}"));
    let lines: Vec<&str> = text.lines().collect();
    let heading = |title: &str| {
        lines
            .iter()
            .position(|line| line.starts_with(title))
            .unwrap_or_else(|| panic!("{SOURCE} has no section heading '{title}'"))
    };
    // Each heading sits between two `// ----` rules; take from the first heading to the rule
    // above the end heading.
    let (start, end) = (heading(FIRST_SECTION), heading(END_SECTION) - 1);
    assert!(start < end, "{SOURCE}: the sections are out of order");
    let extract = lines[start..end].join("\n");
    for needed in ["fn corpus_capture()", "const CORPUS:", "enum Capture"] {
        assert!(
            extract.contains(needed),
            "{SOURCE}: '{needed}' is not in the extract"
        );
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    fs::write(out.join("golden_corpus_extract.rs"), extract).expect("write the extract");
}
