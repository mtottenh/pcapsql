# Fuzz Testing pcapsql

This document describes how to run fuzz tests for pcapsql's protocol parsers using [cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html).

## Prerequisites

Install cargo-fuzz (requires nightly Rust):

```bash
cargo install cargo-fuzz
```

## Available Fuzz Targets

| Target | Description | Priority |
|--------|-------------|----------|
| `fuzz_pcap_reader` | PCAP/PCAPNG format parsing | P0 |
| `fuzz_protocol_chain` | Protocol parsing chain (24+ parsers) | P0 |
| `fuzz_compression` | Compression detection and decompression | P0 |

## Running Fuzz Tests

### List Available Targets

```bash
cargo fuzz list
```

### Run a Fuzz Target

```bash
# Run indefinitely (Ctrl+C to stop)
cargo fuzz run fuzz_protocol_chain

# Run for a specific duration (5 minutes)
cargo fuzz run fuzz_protocol_chain -- -max_total_time=300

# Run with specific number of jobs
cargo fuzz run fuzz_protocol_chain -- -jobs=4

# Run with memory limit (useful for compression fuzzing)
cargo fuzz run fuzz_compression -- -rss_limit_mb=2048
```

### Use Custom Seed Corpus

```bash
# Run with specific corpus directory
cargo fuzz run fuzz_protocol_chain fuzz/corpus/fuzz_protocol_chain

# Merge corpus (deduplicate and minimize)
cargo fuzz cmin fuzz_protocol_chain
```

## Triaging Crashes

When a crash is found, cargo-fuzz saves the crashing input to `fuzz/artifacts/<target>/`.

### Reproduce a Crash

```bash
# Reproduce with the crashing input
cargo fuzz run fuzz_protocol_chain fuzz/artifacts/fuzz_protocol_chain/crash-<hash>
```

### Minimize Crashing Input

```bash
# Find the smallest input that still triggers the crash
cargo fuzz tmin fuzz_protocol_chain fuzz/artifacts/fuzz_protocol_chain/crash-<hash>
```

### Debug with GDB

```bash
# Build without sanitizers for easier debugging
cargo fuzz run fuzz_protocol_chain -- -runs=0
# Then use gdb on the binary in fuzz/target/
```

## Adding New Fuzz Targets

1. Create a new file in `fuzz/fuzz_targets/`:

```rust
// fuzz/fuzz_targets/fuzz_new_target.rs
#![no_main]

use libfuzzer_sys::fuzz_target;
use pcapsql_core::protocol::{YourParser, Protocol, ParseContext};

fuzz_target!(|data: &[u8]| {
    let parser = YourParser::new();
    let context = ParseContext::default();

    // This should never panic
    let _ = parser.parse(data, &context);
});
```

2. Add the binary target to `fuzz/Cargo.toml`:

```toml
[[bin]]
name = "fuzz_new_target"
path = "fuzz_targets/fuzz_new_target.rs"
test = false
doc = false
bench = false
```

3. Create a seed corpus directory:

```bash
mkdir -p fuzz/corpus/fuzz_new_target
# Add seed files (valid protocol data)
```

4. Run the new target:

```bash
cargo fuzz run fuzz_new_target
```

## Corpus Management

### Seed Corpus Structure

```
fuzz/corpus/
├── fuzz_pcap_reader/       # PCAP/PCAPNG files
├── fuzz_protocol_chain/    # Raw packet data
└── fuzz_compression/       # Compressed files
```

### Generating Seed Data

Use scapy to generate valid packet seeds:

```bash
uvx --with scapy python3 -c "
from scapy.all import *
pkt = Ether()/IP()/TCP()
with open('fuzz/corpus/fuzz_protocol_chain/tcp_pkt', 'wb') as f:
    f.write(bytes(pkt))
"
```

### Importing Real Traffic

```bash
# Extract packets from a PCAP file
tshark -r capture.pcap -T raw -F raw > fuzz/corpus/fuzz_protocol_chain/
```

## Coverage

### Generate Coverage Report

```bash
cargo fuzz coverage fuzz_protocol_chain
```

### View Coverage

Coverage data is written to `fuzz/coverage/fuzz_protocol_chain/`.

## CI Integration

For continuous fuzzing, consider:

1. **Nightly runs**: Run fuzz tests nightly with `--max_total_time=3600`
2. **OSS-Fuzz**: Submit to Google's OSS-Fuzz for 24/7 fuzzing
3. **Regression tests**: Add crashing inputs to unit tests after fixing

Example GitHub Actions workflow:

```yaml
name: Fuzz Testing
on:
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight

jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz
      - name: Run fuzz targets
        run: |
          for target in $(cargo fuzz list); do
            cargo fuzz run $target -- -max_total_time=300
          done
```

## Troubleshooting

### Build Errors

If you see workspace errors, ensure `fuzz` is in the `exclude` list in the root `Cargo.toml`:

```toml
[workspace]
exclude = ["fuzz"]
```

### Out of Memory

For targets that may allocate large amounts of memory:

```bash
cargo fuzz run fuzz_compression -- -rss_limit_mb=4096
```

### Slow Fuzzing

- Use `-jobs=N` to run multiple fuzzing processes
- Minimize the corpus with `cargo fuzz cmin`
- Reduce the size of seed inputs

## References

- [cargo-fuzz Book](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [libFuzzer Documentation](https://llvm.org/docs/LibFuzzer.html)
- [OSS-Fuzz Rust Guide](https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/)
