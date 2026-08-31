//! Selected static Linux/x86-64 C linear-search ABI boundary.
//!
//! This leaf owns exactly `lfind` and `lsearch`: state-free linear lookup and
//! caller-owned append through one caller-owned comparison callback. It owns
//! neither a binary lookup, a sorting callback, a search container, allocation,
//! locale-aware ordering, callback registration, C++ exception or C longjmp
//! transport across Rust, libc.so, a CRT, a loader, a sysroot, or public x86
//! support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417, under musl's MIT license:
//! `src/search/lsearch.c::{lsearch,lfind}` maps directly to the two loops
//! below. For a valid caller-owned record array, they retain musl's forward
//! first-match scan; `lfind` leaves the count untouched, while a missed
//! `lsearch` publishes `n + 1` before copying width bytes into record n.
//! Wrapping offset arithmetic only avoids a Rust overflow trap outside that
//! C-defined record-allocation domain; it does not provide a fallback there.
//!
//! No path reads or writes TLS, errno, allocation, locks, locale, callback
//! registries, process state, or a syscall boundary.

use core::{
    ffi::{c_int, c_void},
    ptr::null_mut,
};

type CmpFn = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

#[inline]
fn record_pointer(base: *const u8, index: usize, width: usize) -> *const u8 {
    base.wrapping_add(index.wrapping_mul(width))
}

/// Search caller-owned records from the first element onward.
///
/// # Safety
///
/// nelp must be readable. For a nonzero count, base must address count times
/// width readable bytes. key must be readable by cmp, and cmp must be a
/// non-null C-ABI callback that returns normally for each valid record pointer.
#[no_mangle]
pub unsafe extern "C" fn lfind(
    key: *const c_void,
    base: *const c_void,
    nelp: *mut usize,
    width: usize,
    cmp: CmpFn,
) -> *mut c_void {
    let count = unsafe { nelp.read() };
    let base = base.cast::<u8>();
    let mut index = 0;

    while index < count {
        let record = record_pointer(base, index, width);
        if unsafe { cmp(key, record.cast::<c_void>()) } == 0 {
            return record.cast_mut().cast::<c_void>();
        }
        index = index.wrapping_add(1);
    }
    null_mut()
}

/// Search caller-owned records, appending key bytes after a miss.
///
/// # Safety
///
/// nelp must be readable and writable. base must address count times width
/// readable bytes and capacity for one additional width-byte record; key must
/// address width readable bytes that do not overlap that destination. cmp must
/// be a non-null C-ABI callback that returns normally for each valid record
/// pointer. The count and record-address arithmetic must describe a valid C
/// record allocation.
#[no_mangle]
pub unsafe extern "C" fn lsearch(
    key: *const c_void,
    base: *mut c_void,
    nelp: *mut usize,
    width: usize,
    cmp: CmpFn,
) -> *mut c_void {
    let count = unsafe { nelp.read() };
    let base = base.cast::<u8>();
    let mut index = 0;

    while index < count {
        let record = record_pointer(base, index, width);
        if unsafe { cmp(key, record.cast::<c_void>()) } == 0 {
            return record.cast_mut().cast::<c_void>();
        }
        index = index.wrapping_add(1);
    }

    let Some(next_count) = count.checked_add(1) else {
        return null_mut();
    };
    let record = record_pointer(base, count, width).cast_mut();
    // Musl commits the new count before its memcpy. Retain that observable
    // ordering for the valid caller-owned array domain.
    unsafe { nelp.write(next_count) };
    let key = key.cast::<u8>();
    let mut offset = 0;
    while offset < width {
        let byte = unsafe { key.wrapping_add(offset).read() };
        unsafe { record.wrapping_add(offset).write(byte) };
        offset = offset.wrapping_add(1);
    }
    record.cast::<c_void>()
}
