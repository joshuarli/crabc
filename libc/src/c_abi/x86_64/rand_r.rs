//! Linux/x86-64 selected static C `rand_r` leaf.
//!
//! Provenance is fixed to musl 1.2.6 (`9fa28ece75d8a2191de7c5bb53bed224c5947417`),
//! under musl's MIT license recorded in its `COPYRIGHT` file. The complete
//! source closure is `src/prng/rand_r.c`: it advances the caller-owned
//! unsigned seed with the specified 32-bit linear recurrence, applies musl's
//! four-stage tempering transform, and returns the nonnegative high 31 bits.
//!
//! This leaf owns only that caller-state transform. It has no process-global
//! PRNG state, errno, TLS, syscall, allocator, entropy, locale, mutable
//! runtime, or other random entry point. It is a private selected static
//! artifact, not `rand`/`srand` or BSD random-family support, libc.so, a CRT,
//! loader, sysroot, or public x86 support claim.

use core::ffi::{c_int, c_uint};

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 C rand_r leaf requires little-endian Linux/x86-64");

const LCG_MULTIPLIER: c_uint = 1_103_515_245;
const LCG_INCREMENT: c_uint = 12_345;
const TEMPER_LEFT_7_MASK: c_uint = 0x9d2c_5680;
const TEMPER_LEFT_15_MASK: c_uint = 0xefc6_0000;

#[inline]
fn temper(mut value: c_uint) -> c_uint {
    value ^= value >> 11;
    value ^= (value << 7) & TEMPER_LEFT_7_MASK;
    value ^= (value << 15) & TEMPER_LEFT_15_MASK;
    value ^ (value >> 18)
}

/// Advance one caller-owned seed and return musl's deterministic 31-bit value.
///
/// # Safety
///
/// `seed` must be non-null and designate one writable `unsigned` object. The
/// call updates that object exactly once. As in musl, a null or invalid pointer
/// is outside this C entry point's contract rather than a separately validated
/// error case.
#[no_mangle]
pub unsafe extern "C" fn rand_r(seed: *mut c_uint) -> c_int {
    // SAFETY: the C contract supplies one readable and writable unsigned seed.
    let next = unsafe { seed.read() }
        .wrapping_mul(LCG_MULTIPLIER)
        .wrapping_add(LCG_INCREMENT);
    // SAFETY: the same C contract keeps the caller-owned seed writable.
    unsafe { seed.write(next) };

    // Musl divides an unsigned tempered word by two. The logical shift below
    // is exactly that operation and always fits the nonnegative C `int` range.
    (temper(next) >> 1) as c_int
}
