//! Selected static Linux/x86-64 GNU `sigisemptyset` C boundary.
//!
//! This is a direct, deliberately one-symbol adaptation of pinned musl 1.2.6
//! revision `9fa28ece75d8a2191de7c5bb53bed224c5947417` under musl's MIT
//! license. Its complete source mapping is `src/signal/sigisemptyset.c`.
//! Musl's `_NSIG / 8 / sizeof *set->__bits` calculation is one on x86-64:
//! public `sigset_t` remains 128-byte storage, but this GNU predicate examines
//! only its first eight-byte kernel-visible word. The remaining fifteen words
//! are intentionally ignored and remain caller-resident.
//!
//! This leaf has no syscall or C error-state path. It owns neither signal
//! actions/handlers, masks, process delivery, waits, descriptors, timers,
//! pthread policy, nor the adjacent GNU `sigandset`/`sigorset` extensions.

use core::ffi::{c_int, c_void};

// Keep musl's source expression visible and make an accidental x86 width
// change a compile-time error before the direct one-word translation below.
const SST_SIZE: usize = 65 / 8 / core::mem::size_of::<u64>();
const _: [(); 1] = [(); SST_SIZE];

/// Report whether musl's kernel-visible x86 signal-set word is empty.
///
/// # Safety
///
/// `set` must point to readable storage for one public x86 `sigset_t`. As in
/// musl, this boundary dereferences the pointer directly and inspects only its
/// first unsigned-long word.
#[no_mangle]
pub unsafe extern "C" fn sigisemptyset(set: *const c_void) -> c_int {
    // SAFETY: the C caller owns readable public signal-set storage. The
    // compile-time assertion above fixes musl's x86 loop extent to one word.
    let word = unsafe { core::ptr::read_unaligned(set.cast::<u64>()) };
    if word == 0 { 1 } else { 0 }
}
