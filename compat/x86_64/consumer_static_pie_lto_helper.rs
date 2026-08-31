//! Cross-crate bitcode input for the private x86 static-PIE LTO consumer.
//!
//! The helper deliberately requests one compiler ABI routine instead of
//! allowing Rust's target sysroot to provide it.  Both final links must resolve
//! `__udivti3` from the bounded crabc-owned x86 helper archive.
#![no_std]

unsafe extern "C" {
    fn __udivti3(numerator: u128, denominator: u128) -> u128;
}

/// Keeps a non-trivial cross-crate route for the control/LTO comparison.
///
/// This function is intentionally neither exported under a fixed symbol nor
/// marked `inline`: it remains a callable Rust symbol without LTO and is
/// eligible for whole-program internalization in the full-LTO lane.
pub fn fingerprint(seed: u64) -> u128 {
    let numerator = ((seed as u128) << 96) ^ 0x8e2f_5a91_4d77_c3b1_1020_3040_5060_7081_u128;
    let denominator = (seed as u128 & 31) + 17;
    // SAFETY: `denominator` is always in 17..=48 and therefore nonzero.  The
    // function has the target compiler ABI implemented by the owned archive.
    unsafe { __udivti3(numerator, denominator) }
}
