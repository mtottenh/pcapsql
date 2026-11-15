//! Deterministic PRNG: SplitMix64.

/// A tiny, fully-deterministic PRNG (SplitMix64).
///
/// SplitMix64 is the standard "seed expander" used to initialise other PRNGs;
/// it is more than good enough for generating reproducible test payloads and
/// sizes. Identical seeds produce identical streams on every platform, which is
/// what makes the generated captures byte-identical.
#[derive(Clone, Debug)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Create a new generator from a seed.
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Return the next 64-bit value and advance the state.
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        // Constants from the reference SplitMix64 implementation.
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Return a value in `[low, high]` inclusive. If `low >= high`, returns `low`.
    #[inline]
    pub fn next_in_range(&mut self, low: usize, high: usize) -> usize {
        if low >= high {
            return low;
        }
        let span = (high - low + 1) as u64;
        low + (self.next_u64() % span) as usize
    }
}
