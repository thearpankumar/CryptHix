//! Padmé (Nikitin et al., PETS 2019), written from FS-54 rather than from `crypthix-core`.

/// `padme(L)`: for `L ≥ 2`, `E = ⌊log2 L⌋`, `S = ⌊log2 E⌋ + 1`, `z = E − S`, and `L` rounded up
/// to a multiple of `2^z`; `L` itself below 2.
pub(crate) fn padme(len: u64) -> u64 {
    if len < 2 {
        return len;
    }
    let e = floor_log2(len);
    let s = floor_log2(e) + 1;
    let step = 1u64 << (e - s);
    len.div_ceil(step) * step
}

/// `⌊log2 x⌋` for `x ≥ 1`, by counting halvings.
fn floor_log2(mut x: u64) -> u64 {
    let mut log = 0;
    while x > 1 {
        x >>= 1;
        log += 1;
    }
    log
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worked_values_and_the_overhead_bound() {
        // Worked values, and the paper's bound of 12% overhead.
        assert_eq!(padme(9), 10);
        assert_eq!(padme(1_025), 1_088);
        assert_eq!(padme(1 << 20), 1 << 20);
        for len in [100u64, 1_000, 65_536 + 7, 3_000_000] {
            let padded = padme(len);
            assert!(padded >= len && (padded - len) * 100 < len * 12, "{len}");
        }
    }
}
