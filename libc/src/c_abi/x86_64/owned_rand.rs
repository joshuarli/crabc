//! Owned Linux/x86-64 C `rand` / `srand` compatibility state.
//!
//! The behavior maps to musl 1.2.6 release revision
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, `src/prng/rand.c`
//! (SHA-256 `83ac507f40f71ce90477290ca255dffb91e4256226616e46fa044ad1b136c24d`),
//! under musl's MIT license in `COPYRIGHT`. Musl stores a process-global 64-bit
//! state, writes `unsigned s - 1` in `srand`, advances it once in `rand`, and
//! returns the high nonnegative 31 bits.
//!
//! `rand_pcg` 0.10.2 supplies the complete recurrence through documented
//! `Lcg64Xsh32::from_state`, `advance`, and `state` methods. It and its only
//! normal transitive dependency `rand_core` 0.10.1 are target-gated no_std
//! Rust crates; this boundary does not copy the recurrence locally.
//!
//! Musl's plain mutable state has a C data race under concurrent calls. This
//! owner deliberately strengthens that undefined concurrent behavior: its
//! relaxed compare-and-swap loop serializes successful state transitions.
//! Single-thread and externally serialized observations match the source;
//! no claim is made about matching musl's racy concurrent schedules. The
//! state has no allocator, errno, TLS, cancellation, entropy, PID, atfork, or
//! fork-reset behavior. Normal fork copy-on-write gives child and parent their
//! independent copied state, exactly as a plain source global does.

use core::ffi::{c_int, c_uint};
use core::sync::atomic::{AtomicU64, Ordering};

use rand_pcg::Lcg64Xsh32;

// Musl's static storage begins as zero. Keeping this one process-global atomic
// makes the serialized successful transition the sole public rand state owner.
static RAND_STATE: AtomicU64 = AtomicU64::new(0);

/// Set the process-global C `rand` state from musl's 32-bit unsigned seed.
///
/// `wrapping_sub` happens while the value is still C `unsigned`, before the
/// resulting 32-bit word widens to the source's 64-bit state. In particular,
/// `srand(0)` stores `0x00000000ffffffff`, not an all-ones 64-bit word.
#[no_mangle]
pub extern "C" fn srand(seed: c_uint) {
    RAND_STATE.store(u64::from(seed.wrapping_sub(1)), Ordering::Relaxed);
}

/// Advance the process-global C `rand` state and return musl's 31-bit value.
///
/// Each retry reconstructs the reviewed dependency's recurrence from the last
/// observed state. Only a successful compare-and-swap publishes and returns a
/// transition, so concurrent callers cannot lose or duplicate a state update.
#[no_mangle]
pub extern "C" fn rand() -> c_int {
    let mut old = RAND_STATE.load(Ordering::Relaxed);
    loop {
        let mut generator = Lcg64Xsh32::from_state(old, 0);
        generator.advance(1);
        let next = generator.state();
        match RAND_STATE.compare_exchange_weak(old, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return (next >> 33) as c_int,
            Err(observed) => old = observed,
        }
    }
}
