//! Selected static Linux/x86-64 C `bsearch` ABI boundary.
//!
//! This leaf owns exactly `bsearch`: a stateless, allocation-free binary
//! lookup over caller-owned contiguous byte records through one caller-owned
//! comparison callback. It is not a sorting implementation, `search.h`
//! trees or hashes, locale-aware ordering, callback registration, C++
//! exception or C longjmp transport across Rust, libc.so, a CRT, a loader, a
//! sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417, under musl's MIT license:
//! `src/stdlib/bsearch.c::bsearch` maps directly to this loop. The checked multiplication return is intentional only outside musl's valid
//! caller-owned C array domain, where the source multiplication/pointer
//! expression would already be undefined; valid arrays retain its exact
//! midpoint and comparator-branch sequence.
//!
//! No path reads or writes TLS, errno, allocation, locks, locale, callback
//! registries, process state, or a syscall boundary.

use core::{
    ffi::{c_int, c_void},
    ptr::null_mut,
};

type CmpFn = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

/// Search a sorted caller-owned record array.
///
/// # Safety
///
/// For nonzero nel, base must address nel times width readable bytes and key
/// must be readable by cmp. The multiplication must not overflow. cmp must be
/// a non-null C-ABI callback that returns normally and establishes a
/// consistent ordering over valid record pointers.
#[no_mangle]
pub unsafe extern "C" fn bsearch(
    key: *const c_void,
    base: *const c_void,
    nel: usize,
    width: usize,
    cmp: CmpFn,
) -> *mut c_void {
    let mut base = base.cast::<u8>();
    let mut nel = nel;
    while nel > 0 {
        let Some(offset) = width.checked_mul(nel / 2) else {
            return null_mut();
        };
        let trial = unsafe { base.add(offset) };
        let sign = unsafe { cmp(key, trial.cast::<c_void>()) };
        if sign < 0 {
            nel /= 2;
        } else if sign > 0 {
            base = unsafe { trial.add(width) };
            nel -= nel / 2 + 1;
        } else {
            return trial.cast_mut().cast::<c_void>();
        }
    }
    null_mut()
}
