//! Pinned-musl BSD `random` state owner for the native owned runtime.
//!
//! This is a provenance-preserving semantic port of musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
//! `src/prng/random.c` (SHA-256
//! `3a47a757115e2a2ea7b1242a0000100ad802c27c2a398b4d8b8360d768780209`).
//! Copyright © 2005-2020 Rich Felker, et al.
//!
//! Permission is hereby granted, free of charge, to any person obtaining a
//! copy of this software and associated documentation files (the "Software"),
//! to deal in the Software without restriction, including without limitation
//! the rights to use, copy, modify, merge, publish, distribute, sublicense,
//! and/or sell copies of the Software, and to permit persons to whom the
//! Software is furnished to do so, subject to the following conditions: the
//! above copyright notice and this permission notice shall be included in all
//! copies or substantial portions of the Software.
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//! IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//! FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//! AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//! LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//! FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//! DEALINGS IN THE SOFTWARE.
//!
//! Its mapping is direct: `init`, `n`, `i`, `j`, and `x` are the static image
//! and scalar fields below; `lcg31`, `lcg64`, `savestate`, `loadstate`,
//! `__srandom`, and the four public entries retain the source operation order.
//!
//! Unlike the historical paused AArch64 lexical copy, this owner retains the
//! source lock boundary. `RandomLock` serializes every public state mutation
//! and participates in the owned `fork` transaction at musl
//! `fork.c`'s `__random_lockptr` position: after the available quick-exit and
//! before named-IPC/stdio locks. Parent completion releases it; child
//! completion clears the copied lock while retaining its copied generator
//! state. `_Fork` and `CLONE_VM` preserve musl's narrower async-signal-safe
//! behavior and intentionally do not claim a general copied-lock repair.
//! The native owner always acquires that source lock rather than eliding it
//! before musl's `libc.need_locks` transition; this follows the existing
//! native-private-owner convention and does not alter generator outputs,
//! state transitions, or the C ABI.
//!
//! `initstate` and `setstate` keep C's caller-owned state storage contract.
//! The caller supplies writable storage for the selected size and keeps the
//! active state buffer alive until another `initstate` or `setstate` selects a
//! live replacement. This Rust port deliberately extends its byte-storage
//! implementation to unaligned state pointers with raw unaligned word access;
//! that defined Rust translation is not a claim that musl's `uint32_t *` cast
//! accepts unaligned C storage. As in musl, `setstate` trusts a state image
//! produced by this family; an invalid pointer, insufficient backing storage,
//! corrupted state header, or an unsynchronized external access to active
//! storage violates the C caller contract.
//! This non-cryptographic legacy state is never an entropy, secret, allocator,
//! or hardening source.

use core::ffi::{c_char, c_long, c_uint};
use core::sync::atomic::{AtomicI32, Ordering};


static mut RANDOM_INIT: [u32; 32] = [
    0x00000000, 0x5851f42d, 0xc0b18ccf, 0xcbb5f646, 0xc7033129, 0x30705b04,
    0x20fd5db4, 0x9a8b7f78, 0x502959d8, 0xab894868, 0x6c0356a7, 0x88cdb7ff,
    0xb477d43f, 0x70a3a52b, 0xa8e4baf1, 0xfd8341fc, 0x8ae16fd9, 0x742d2f7a,
    0x0d1f0796, 0x76035e09, 0x40f7702c, 0x6fa72ca5, 0xaaa84157, 0x58a0df74,
    0xc74a0364, 0xae533cc4, 0x04185faf, 0x6de3b115, 0x0cab8628, 0xf043bfa4,
    0x398150e9, 0x37521657,
];

// This preserves musl `__lock`'s sign-bit ownership and congestion word,
// including its bounded spin and private futex wait/wake path. A plain busy
// spin lock could starve an owner preempted below a real-time waiter.
static RANDOM_LOCK: AtomicI32 = AtomicI32::new(0);
static mut RANDOM_N: u32 = 31;
static mut RANDOM_I: u32 = 3;
static mut RANDOM_J: u32 = 0;
// Initialize this under RANDOM_LOCK rather than constructing a mutable-static
// pointer constant. Every later value is the raw first data-word address of
// either RANDOM_INIT or a caller-owned state image.
static mut RANDOM_X: *mut u8 = core::ptr::null_mut();

struct RandomLock;

impl RandomLock {
    #[inline]
    fn acquire() -> Self {
        // SAFETY: RANDOM_LOCK is process-private, aligned, and static. The
        // matching Drop or fork completion releases this exact acquisition.
        unsafe { lock_random() };
        Self
    }
}

impl Drop for RandomLock {
    fn drop(&mut self) {
        // SAFETY: RandomLock is constructed only after lock_random succeeds.
        unsafe { unlock_random() };
    }
}

/// Pinned musl `src/thread/__lock.c` with `RANDOM_LOCK` as its source word.
#[inline]
unsafe fn lock_random() {
    super::musl_lock::lock(&RANDOM_LOCK);
}

/// Release the random-state lock word as pinned musl `__unlock`.
#[inline]
unsafe fn unlock_random() {
    super::musl_lock::unlock(&RANDOM_LOCK);
}

#[inline]
unsafe fn ensure_default_storage() {
    if unsafe { RANDOM_X.is_null() } {
        // SAFETY: RANDOM_INIT is process-lifetime 32-bit storage; no references
        // are formed and the held lock excludes every state-owner mutation.
        unsafe { RANDOM_X = core::ptr::addr_of_mut!(RANDOM_INIT).cast::<u8>().add(4) };
    }
}

#[inline]
unsafe fn state_word(state: *mut u8, index: usize) -> *mut u8 {
    // SAFETY: public state-pointer callers retain the exact selected state
    // backing. Internal callers pass RANDOM_INIT. Index bounds are fixed by
    // musl's five state classes or by that same caller state-image contract.
    unsafe { state.add(index * core::mem::size_of::<u32>()) }
}

#[inline]
unsafe fn load_word(state: *mut u8, index: usize) -> u32 {
    // SAFETY: raw unaligned load avoids creating a Rust reference into C state.
    unsafe { state_word(state, index).cast::<u32>().read_unaligned() }
}

#[inline]
unsafe fn store_word(state: *mut u8, index: usize, value: u32) {
    // SAFETY: raw unaligned store preserves the C byte-storage contract without
    // requiring source pointers to be Rust-aligned.
    unsafe { state_word(state, index).cast::<u32>().write_unaligned(value) };
}

#[inline]
fn lcg31(value: u32) -> u32 {
    value
        .wrapping_mul(1_103_515_245)
        .wrapping_add(12_345)
        & 0x7fff_ffff
}

#[inline]
fn lcg64(value: u64) -> u64 {
    value.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1)
}

/// Save musl's n/i/j header immediately before the active data words.
///
/// The lock is held, `RANDOM_X` is initialized, and the active state backing
/// remains writable for the duration of this operation.
#[inline]
unsafe fn save_state() -> *mut u8 {
    let x = unsafe { RANDOM_X };
    let header = unsafe { x.sub(core::mem::size_of::<u32>()) };
    let encoded = unsafe { (RANDOM_N << 16) | (RANDOM_I << 8) | RANDOM_J };
    unsafe { store_word(header, 0, encoded) };
    header
}

/// Install musl's packed caller state image without interpreting it as a Rust
/// reference. The public `setstate` caller promises a live source-produced
/// image, including a valid n/i/j header and its matching backing capacity.
#[inline]
unsafe fn load_state(state: *mut u8) {
    let header = unsafe { load_word(state, 0) };
    unsafe {
        RANDOM_X = state.add(core::mem::size_of::<u32>());
        RANDOM_N = header >> 16;
        RANDOM_I = (header >> 8) & 0xff;
        RANDOM_J = header & 0xff;
    }
}

/// Musl `__srandom`, called with RANDOM_LOCK held.
#[inline]
unsafe fn seed_state(seed: u32) {
    let n = unsafe { RANDOM_N };
    let x = unsafe { RANDOM_X };
    if n == 0 {
        unsafe { store_word(x, 0, seed) };
        return;
    }
    unsafe {
        RANDOM_I = if n == 31 || n == 7 { 3 } else { 1 };
        RANDOM_J = 0;
    }
    let mut state = u64::from(seed);
    for index in 0..n as usize {
        state = lcg64(state);
        unsafe { store_word(x, index, (state >> 32) as u32) };
    }
    let first = unsafe { load_word(x, 0) };
    unsafe { store_word(x, 0, first | 1) };
}

/// Seed the process-global legacy BSD random state.
#[no_mangle]
pub extern "C" fn srandom(seed: c_uint) {
    let _lock = RandomLock::acquire();
    unsafe {
        ensure_default_storage();
        seed_state(seed);
    }
}

/// Switch to a caller-owned BSD random state image and seed it.
///
/// # Safety
///
/// For a size of at least eight, `state` must remain writable for `size` bytes
/// and retained until the active state changes again; no external task may
/// read or mutate that backing without synchronizing with all calls to this family. It
/// may be unaligned as a defined Rust-port extension, not as a claim about
/// musl's aligned `uint32_t *` C access. Sizes below eight return null before
/// observing `state` and leave both errno and the active state unchanged.
#[no_mangle]
pub unsafe extern "C" fn initstate(seed: c_uint, state: *mut c_char, size: usize) -> *mut c_char {
    if size < 8 {
        return core::ptr::null_mut();
    }
    let _lock = RandomLock::acquire();
    unsafe {
        ensure_default_storage();
        let previous = save_state();
        RANDOM_N = if size < 32 {
            0
        } else if size < 64 {
            7
        } else if size < 128 {
            15
        } else if size < 256 {
            31
        } else {
            63
        };
        RANDOM_X = state.cast::<u8>().add(core::mem::size_of::<u32>());
        seed_state(seed);
        save_state();
        previous.cast::<c_char>()
    }
}

/// Switch to a caller-owned BSD random state image.
///
/// # Safety
///
/// `state` must be a live, writable image previously initialized by this BSD
/// random family, with the backing capacity required by its packed n/i/j
/// header. It stays retained after selection until a later switch, and no
/// external task reads or mutates either selected buffer without synchronizing with all
/// calls to this family. The active previous state remains writable through
/// this call. Unaligned images are a defined Rust-port extension only.
#[no_mangle]
pub unsafe extern "C" fn setstate(state: *mut c_char) -> *mut c_char {
    let _lock = RandomLock::acquire();
    unsafe {
        ensure_default_storage();
        let previous = save_state();
        load_state(state.cast::<u8>());
        previous.cast::<c_char>()
    }
}

/// Advance the process-global legacy BSD random state.
#[no_mangle]
pub extern "C" fn random() -> c_long {
    let _lock = RandomLock::acquire();
    unsafe {
        ensure_default_storage();
        let n = RANDOM_N;
        let x = RANDOM_X;
        if n == 0 {
            let value = lcg31(load_word(x, 0));
            store_word(x, 0, value);
            return value as c_long;
        }
        let index_i = RANDOM_I as usize;
        let index_j = RANDOM_J as usize;
        let value = load_word(x, index_i).wrapping_add(load_word(x, index_j));
        store_word(x, index_i, value);
        RANDOM_I += 1;
        if RANDOM_I == n {
            RANDOM_I = 0;
        }
        RANDOM_J += 1;
        if RANDOM_J == n {
            RANDOM_J = 0;
        }
        (value >> 1) as c_long
    }
}

/// Acquire musl `fork.c`'s random lock position before raw fork.
///
/// # Safety
///
/// The owned fork transaction invokes exactly one matching parent or child
/// completion before application callbacks or normal random calls resume.
pub(super) unsafe fn pthread_fork_prepare() {
    unsafe { lock_random() };
}

/// Complete the original parent's (or raw-failure) random-lock transaction.
///
/// # Safety
///
/// A matching `pthread_fork_prepare` holds the lock in this process.
pub(super) unsafe fn pthread_fork_parent() {
    unsafe { unlock_random() };
}

/// Make the copied random lock callable in the sole ordinary-fork child.
///
/// # Safety
///
/// The child follows the matching owned fork preparation and no vanished task
/// can still own the copied lock.
pub(super) unsafe fn pthread_fork_child() {
    RANDOM_LOCK.store(0, Ordering::Relaxed);
}
