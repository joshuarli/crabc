//! Selected static Linux/x86-64 POSIX signal-set mutation C boundary.
//!
//! This is a direct, deliberately three-symbol adaptation of pinned musl 1.2.6
//! revision `9fa28ece75d8a2191de7c5bb53bed224c5947417` under musl's MIT
//! license. Its complete source mapping is `src/signal/sigaddset.c`,
//! `src/signal/sigdelset.c`, and `src/signal/sigfillset.c`. Those files use
//! `_NSIG=65` and an eight-byte `unsigned long` on x86-64: `sigaddset` and
//! `sigdelset` validate `sig-1` and reject musl's reserved 32--34 range before
//! modifying one selected word, while `sigfillset` writes only the first word
//! `0xfffffffc7fffffff`. Public `sigset_t` remains 128 bytes, so all fifteen
//! tail words stay caller-resident.
//!
//! This leaf has no syscall path. Its only error-state behavior is musl's
//! direct `EINVAL` result for invalid/reserved `sigaddset`/`sigdelset` input;
//! successful calls preserve a stale errno. It owns neither signal delivery,
//! actions/handlers, masks, process signaling, waits, descriptors, timers,
//! pthread policy, nor a general signal-management framework.

use core::ffi::{c_int, c_void};

use super::errno;

const EINVAL: c_int = 22;

// Keep musl's source expression visible and reject an accidental x86 word or
// _NSIG change before translating its selected one-word operations below.
const SST_SIZE: usize = 65 / 8 / core::mem::size_of::<u64>();
const _: [(); 1] = [(); SST_SIZE];
const WORD_BITS: u32 = (8 * core::mem::size_of::<u64>()) as u32;
const SIGFILLSET_FIRST_WORD: u64 = 0xfffffffc7fffffff;

#[inline(always)]
fn invalid_argument() -> c_int {
    // SAFETY: The selected static C ABI owns one initial-TLS errno slot.
    unsafe { errno::set_errno(EINVAL) };
    -1
}

#[inline]
fn selected_word_and_bit(signal: c_int) -> Option<(usize, u32)> {
    // This is the defined unsigned form of musl's `unsigned s = sig-1` and
    // `sig-32U < 3` validation. The accepted x86 range makes its source word
    // index zero, as asserted by `SST_SIZE` above.
    let selected = (signal as u32).wrapping_sub(1);
    if selected >= 65 - 1 || (signal as u32).wrapping_sub(32) < 3 {
        return None;
    }
    Some((
        (selected / 8 / core::mem::size_of::<u64>() as u32) as usize,
        selected & (WORD_BITS - 1),
    ))
}

/// Add one application-visible signal to a public x86 signal set.
///
/// # Safety
///
/// `set` must point to writable storage for one public x86 `sigset_t`. As in
/// musl, valid input dereferences the selected public word directly.
#[no_mangle]
pub unsafe extern "C" fn sigaddset(set: *mut c_void, signal: c_int) -> c_int {
    let Some((word_index, bit)) = selected_word_and_bit(signal) else {
        return invalid_argument();
    };
    // SAFETY: the validated x86 index is musl's sole selected word, and the C
    // caller owns writable public signal-set storage.
    unsafe {
        let word_pointer = set.cast::<u64>().add(word_index);
        let word = core::ptr::read_unaligned(word_pointer);
        core::ptr::write_unaligned(word_pointer, word | (1_u64 << bit));
    }
    0
}

/// Remove one application-visible signal from a public x86 signal set.
///
/// # Safety
///
/// `set` must point to writable storage for one public x86 `sigset_t`. As in
/// musl, valid input dereferences the selected public word directly.
#[no_mangle]
pub unsafe extern "C" fn sigdelset(set: *mut c_void, signal: c_int) -> c_int {
    let Some((word_index, bit)) = selected_word_and_bit(signal) else {
        return invalid_argument();
    };
    // SAFETY: the validated x86 index is musl's sole selected word, and the C
    // caller owns writable public signal-set storage.
    unsafe {
        let word_pointer = set.cast::<u64>().add(word_index);
        let word = core::ptr::read_unaligned(word_pointer);
        core::ptr::write_unaligned(word_pointer, word & !(1_u64 << bit));
    }
    0
}

/// Fill the first kernel-visible word with all musl application signals.
///
/// # Safety
///
/// `set` must point to writable storage for one public x86 `sigset_t`. Musl's
/// x86 `sigfillset.c` path writes only this first unsigned-long word.
#[no_mangle]
pub unsafe extern "C" fn sigfillset(set: *mut c_void) -> c_int {
    // SAFETY: the C caller owns writable public signal-set storage.
    unsafe { core::ptr::write_unaligned(set.cast::<u64>(), SIGFILLSET_FIRST_WORD) };
    0
}
