//! Selected static Linux/x86-64 GNU `sigandset`/`sigorset` C boundary.
//!
//! This is a direct, deliberately two-symbol adaptation of pinned musl 1.2.6
//! revision `9fa28ece75d8a2191de7c5bb53bed224c5947417` under musl's MIT
//! license. Its complete source mappings are `src/signal/sigandset.c` and
//! `src/signal/sigorset.c`. Both source files derive `SST_SIZE` from `_NSIG`.
//! On x86-64, `_NSIG=65` and an eight-byte `unsigned long` make that count one:
//! each helper reads its left and right first public words, writes exactly the
//! destination first word, and leaves all fifteen public tail words untouched.
//!
//! The source order reads both operands before assigning the destination word,
//! so the direct translation keeps supported destination/operand aliasing
//! observable. This leaf has no syscall or C error-state path. It owns neither
//! signal actions/handlers, masks, process delivery, waits, descriptors,
//! timers, pthread policy, nor the adjacent GNU `sigisemptyset` predicate.

use core::ffi::{c_int, c_void};

// Keep musl's source expression visible and make an accidental x86 width
// change a compile-time error before the direct one-word translations below.
const SST_SIZE: usize = 65 / 8 / core::mem::size_of::<u64>();
const _: [(); 1] = [(); SST_SIZE];

/// Store the bitwise intersection of musl's selected x86 signal-set words.
///
/// # Safety
///
/// `dest` must point to writable storage and `left`/`right` to readable
/// storage for public x86 `sigset_t` values. As in musl, this boundary
/// dereferences the pointers directly and inspects/writes only their first
/// unsigned-long word.
#[no_mangle]
pub unsafe extern "C" fn sigandset(
    dest: *mut c_void,
    left: *const c_void,
    right: *const c_void,
) -> c_int {
    // SAFETY: the C caller owns public signal-set storage. Reading both source
    // words before the write preserves musl's direct-assignment aliasing order.
    let left_word = unsafe { core::ptr::read_unaligned(left.cast::<u64>()) };
    let right_word = unsafe { core::ptr::read_unaligned(right.cast::<u64>()) };
    unsafe { core::ptr::write_unaligned(dest.cast::<u64>(), left_word & right_word) };
    0
}

/// Store the bitwise union of musl's selected x86 signal-set words.
///
/// # Safety
///
/// `dest` must point to writable storage and `left`/`right` to readable
/// storage for public x86 `sigset_t` values. As in musl, this boundary
/// dereferences the pointers directly and inspects/writes only their first
/// unsigned-long word.
#[no_mangle]
pub unsafe extern "C" fn sigorset(
    dest: *mut c_void,
    left: *const c_void,
    right: *const c_void,
) -> c_int {
    // SAFETY: the C caller owns public signal-set storage. Reading both source
    // words before the write preserves musl's direct-assignment aliasing order.
    let left_word = unsafe { core::ptr::read_unaligned(left.cast::<u64>()) };
    let right_word = unsafe { core::ptr::read_unaligned(right.cast::<u64>()) };
    unsafe { core::ptr::write_unaligned(dest.cast::<u64>(), left_word | right_word) };
    0
}
