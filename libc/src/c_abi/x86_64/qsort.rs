//! Selected static Linux/x86-64 C `qsort` ABI boundary.
//!
//! This leaf owns exactly the public `qsort` entry and its non-exported
//! smoothsort worker. It sorts caller-owned contiguous byte records through
//! one caller-owned two-argument C comparison callback. It is not a public
//! `qsort_r`/`__qsort_r` ABI, `bsearch`, lfind/lsearch, `search.h` trees or
//! hashes, locale-aware ordering, callback registration, C++ exception or C
//! longjmp transport across Rust, libc.so, a CRT, a loader, a sysroot, or
//! public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417, under musl's MIT license:
//! `src/stdlib/qsort.c::__qsort_r` maps to the private
//! `qsort_with_context` smoothsort worker, including its O(1) cycling buffer;
//! `src/stdlib/qsort_nr.c::qsort` maps to `qsort` and its two-argument
//! comparator adapter. The public musl `__qsort_r`/weak `qsort_r` names stay
//! in `callback_algorithms.rs` as a thin context-ABI wrapper over this exact
//! worker. That target-local export split preserves the source algorithm and
//! qsort_r behavior while letting a qsort-only archive extraction omit the
//! qsort_r ABI entirely.
//!
//! The fixed smoothsort algorithm retains musl's unstable equal-key ordering.
//! A defensive nel-times-width overflow return is intentional and occurs only
//! outside the valid caller-owned C array domain. No path reads or writes TLS,
//! errno, allocation, locks, locale, callback registries, or process state.
//! The smoothsort work arrays use explicit raw-pointer access: their
//! musl-established indices are internally bounded, and avoiding Rust slice
//! bounds paths keeps this stateless leaf from selecting panic support or the
//! separate errno/TLS owner.

use core::ffi::{c_int, c_void};

type QsortCmp = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;
pub(super) type QsortContextCmp =
    unsafe extern "C" fn(*const c_void, *const c_void, *mut c_void) -> c_int;

const AR_LEN: usize = 14 * core::mem::size_of::<usize>() + 1;
const LP_LEN: usize = 12 * core::mem::size_of::<usize>();

#[derive(Clone, Copy)]
struct QsortP {
    first: usize,
    second: usize,
}

#[inline]
unsafe fn qsort_word(words: *const usize, index: usize) -> usize {
    // Every caller preserves musl qsort.c's fixed LP_LEN work-array bounds.
    unsafe { words.add(index).read() }
}

#[inline]
unsafe fn qsort_record_pointer(entries: *const *mut u8, index: usize) -> *mut u8 {
    // Musl qsort.c's Leonardo-state bounds keep every stored path length and
    // temporary slot within its exact 14*sizeof(size_t)+1 work array.
    unsafe { entries.add(index).read() }
}

#[inline]
unsafe fn qsort_copy_nonoverlapping(source: *const u8, destination: *mut u8, bytes: usize) {
    // qsort.c establishes non-overlapping record/temporary ranges before each
    // copy. Keep that source invariant while spelling the copy as an explicit
    // byte loop: core::ptr::copy_nonoverlapping retains a debug unsafe-
    // precondition path that would pull this stateless leaf's panic/TLS owner.
    let mut index = 0usize;
    while index < bytes {
        unsafe {
            destination
                .add(index)
                .write(source.add(index).read());
        }
        index = index.wrapping_add(1);
    }
}

#[inline]
unsafe fn set_qsort_record_pointer(entries: *mut *mut u8, index: usize, value: *mut u8) {
    // See qsort_record_pointer for the source-preserved bounded-index proof.
    unsafe { entries.add(index).write(value) };
}

#[inline]
fn qsort_pntz(p: QsortP) -> i32 {
    if p.first != 1 {
        p.first.wrapping_sub(1).trailing_zeros() as i32
    } else if p.second != 0 {
        (8 * core::mem::size_of::<usize>()) as i32 + p.second.trailing_zeros() as i32
    } else {
        0
    }
}

unsafe fn qsort_cycle(width: usize, entries: *mut *mut u8, n: usize) {
    if n < 2 {
        return;
    }
    let mut temporary = [0u8; 256];
    unsafe { set_qsort_record_pointer(entries, n, temporary.as_mut_ptr()) };
    let mut remaining = width;
    while remaining > 0 {
        let chunk = if remaining < temporary.len() {
            remaining
        } else {
            temporary.len()
        };
        let first = unsafe { qsort_record_pointer(entries, 0) };
        let temporary_destination = unsafe { qsort_record_pointer(entries, n) };
        unsafe { qsort_copy_nonoverlapping(first, temporary_destination, chunk) };
        let mut index = 0usize;
        while index < n {
            let next = unsafe { qsort_record_pointer(entries, index.wrapping_add(1)) };
            let current = unsafe { qsort_record_pointer(entries, index) };
            unsafe { qsort_copy_nonoverlapping(next, current, chunk) };
            unsafe {
                set_qsort_record_pointer(entries, index, current.add(chunk));
            }
            index = index.wrapping_add(1);
        }
        remaining = remaining.wrapping_sub(chunk);
    }
}

#[inline]
fn qsort_shl(p: &mut QsortP, mut n: i32) {
    let bits = (8 * core::mem::size_of::<usize>()) as i32;
    if n >= bits {
        p.second = p.first;
        p.first = 0;
        n -= bits;
        if n == 0 {
            return;
        }
    }
    // Musl's state machine reaches this with 0 < n < word width. Wrapping
    // shifts retain those results without adding a Rust invalid-shift path.
    let shift = n as u32;
    let opposite_shift = (bits - n) as u32;
    p.second = p.second.wrapping_shl(shift) | p.first.wrapping_shr(opposite_shift);
    p.first = p.first.wrapping_shl(shift);
}

#[inline]
fn qsort_shr(p: &mut QsortP, mut n: i32) {
    let bits = (8 * core::mem::size_of::<usize>()) as i32;
    if n >= bits {
        p.first = p.second;
        p.second = 0;
        n -= bits;
        if n == 0 {
            return;
        }
    }
    // See qsort_shl's source-state invariant.
    let shift = n as u32;
    let opposite_shift = (bits - n) as u32;
    p.first = p.first.wrapping_shr(shift) | p.second.wrapping_shl(opposite_shift);
    p.second = p.second.wrapping_shr(shift);
}

unsafe fn qsort_sift(
    head: *mut u8,
    width: usize,
    cmp: QsortContextCmp,
    argument: *mut c_void,
    pshift: i32,
    lp: *const usize,
) {
    // Like musl's automatic `ar` array, each slot is written before the
    // smoothsort path reads it. Leaving unused slots uninitialized avoids
    // selecting a compiler-lowered memset from this otherwise self-contained
    // stateless artifact.
    let mut entries_storage = core::mem::MaybeUninit::<[*mut u8; AR_LEN]>::uninit();
    let entries = entries_storage.as_mut_ptr().cast::<*mut u8>();
    unsafe { set_qsort_record_pointer(entries, 0, head) };
    let mut count = 1usize;
    let mut head = head;
    let mut pshift = pshift;

    while pshift > 1 {
        let right = unsafe { head.sub(width) };
        let left_offset = width.wrapping_add(unsafe { qsort_word(lp, (pshift - 2) as usize) });
        let left = unsafe { head.sub(left_offset) };
        let root = unsafe { qsort_record_pointer(entries, 0) };

        if unsafe { cmp(root.cast::<c_void>(), left.cast::<c_void>(), argument) } >= 0
            && unsafe { cmp(root.cast::<c_void>(), right.cast::<c_void>(), argument) } >= 0
        {
            break;
        }
        if unsafe { cmp(left.cast::<c_void>(), right.cast::<c_void>(), argument) } >= 0 {
            unsafe { set_qsort_record_pointer(entries, count, left) };
            count = count.wrapping_add(1);
            head = left;
            pshift -= 1;
        } else {
            unsafe { set_qsort_record_pointer(entries, count, right) };
            count = count.wrapping_add(1);
            head = right;
            pshift -= 2;
        }
    }
    unsafe { qsort_cycle(width, entries, count) };
}

unsafe fn qsort_trinkle(
    head: *mut u8,
    width: usize,
    cmp: QsortContextCmp,
    argument: *mut c_void,
    mut p: QsortP,
    pshift: i32,
    trusty: i32,
    lp: *const usize,
) {
    // See qsort_sift: every used path slot is written before its first read.
    let mut entries_storage = core::mem::MaybeUninit::<[*mut u8; AR_LEN]>::uninit();
    let entries = entries_storage.as_mut_ptr().cast::<*mut u8>();
    unsafe { set_qsort_record_pointer(entries, 0, head) };
    let mut count = 1usize;
    let mut head = head;
    let mut pshift = pshift;
    let mut trusty = trusty;

    while p.first != 1 || p.second != 0 {
        let stepson = unsafe { head.sub(qsort_word(lp, pshift as usize)) };
        let root = unsafe { qsort_record_pointer(entries, 0) };
        if unsafe { cmp(stepson.cast::<c_void>(), root.cast::<c_void>(), argument) } <= 0 {
            break;
        }
        if trusty == 0 && pshift > 1 {
            let right = unsafe { head.sub(width) };
            let left_offset = width.wrapping_add(unsafe { qsort_word(lp, (pshift - 2) as usize) });
            let left = unsafe { head.sub(left_offset) };
            if unsafe { cmp(right.cast::<c_void>(), stepson.cast::<c_void>(), argument) } >= 0
                || unsafe { cmp(left.cast::<c_void>(), stepson.cast::<c_void>(), argument) } >= 0
            {
                break;
            }
        }

        unsafe { set_qsort_record_pointer(entries, count, stepson) };
        count = count.wrapping_add(1);
        head = stepson;
        let trail = qsort_pntz(p);
        qsort_shr(&mut p, trail);
        pshift += trail;
        trusty = 0;
    }
    if trusty == 0 {
        unsafe { qsort_cycle(width, entries, count) };
        unsafe { qsort_sift(head, width, cmp, argument, pshift, lp) };
    }
}

/// Run musl qsort.c's smoothsort worker through a context-bearing callback.
///
/// This is deliberately Rust-module-private instead of the public musl
/// `__qsort_r` spelling. `callback_algorithms.rs` owns that ABI/weak-alias
/// boundary and delegates here; qsort's `qsort_nr.c` adapter calls this worker
/// directly so its standalone static archive candidate cannot extract qsort_r.
pub(super) unsafe fn qsort_with_context(
    base: *mut c_void,
    nel: usize,
    width: usize,
    cmp: QsortContextCmp,
    argument: *mut c_void,
) {
    let Some(size) = width.checked_mul(nel) else {
        return;
    };
    if size == 0 {
        return;
    }

    let mut lp = [0usize; LP_LEN];
    let lp_words = lp.as_mut_ptr();
    unsafe {
        lp_words.write(width);
        lp_words.add(1).write(width);
    }
    let mut li = 2usize;
    while li < LP_LEN {
        let Some(next) = unsafe { qsort_word(lp_words, li.wrapping_sub(2)) }
            .checked_add(unsafe { qsort_word(lp_words, li.wrapping_sub(1)) })
            .and_then(|value| value.checked_add(width))
        else {
            break;
        };
        unsafe { lp_words.add(li).write(next) };
        if next >= size {
            break;
        }
        li = li.wrapping_add(1);
    }

    let mut head = base.cast::<u8>();
    let high = unsafe { head.add(size.wrapping_sub(width)) };
    let mut p = QsortP {
        first: 1,
        second: 0,
    };
    let mut pshift = 1i32;

    while head < high {
        if (p.first & 3) == 3 {
            unsafe { qsort_sift(head, width, cmp, argument, pshift, lp_words) };
            qsort_shr(&mut p, 2);
            pshift += 2;
        } else {
            if unsafe { qsort_word(lp_words, (pshift - 1) as usize) }
                >= (high as usize).wrapping_sub(head as usize)
            {
                unsafe { qsort_trinkle(head, width, cmp, argument, p, pshift, 0, lp_words) };
            } else {
                unsafe { qsort_sift(head, width, cmp, argument, pshift, lp_words) };
            }

            if pshift == 1 {
                qsort_shl(&mut p, 1);
                pshift = 0;
            } else {
                qsort_shl(&mut p, pshift - 1);
                pshift = 1;
            }
        }

        p.first |= 1;
        head = unsafe { head.add(width) };
    }

    unsafe { qsort_trinkle(head, width, cmp, argument, p, pshift, 0, lp_words) };

    while pshift != 1 || p.first != 1 || p.second != 0 {
        if pshift <= 1 {
            let trail = qsort_pntz(p);
            qsort_shr(&mut p, trail);
            pshift += trail;
        } else {
            qsort_shl(&mut p, 2);
            pshift -= 2;
            p.first ^= 7;
            qsort_shr(&mut p, 1);
            unsafe {
                qsort_trinkle(
                    head.sub(qsort_word(lp_words, pshift as usize).wrapping_add(width)),
                    width,
                    cmp,
                    argument,
                    p,
                    pshift + 1,
                    1,
                    lp_words,
                )
            };
            qsort_shl(&mut p, 1);
            p.first |= 1;
            unsafe {
                qsort_trinkle(
                    head.sub(width),
                    width,
                    cmp,
                    argument,
                    p,
                    pshift,
                    1,
                    lp_words,
                )
            };
        }
        head = unsafe { head.sub(width) };
    }
}

unsafe extern "C" fn qsort_wrap_cmp(
    left: *const c_void,
    right: *const c_void,
    context: *mut c_void,
) -> c_int {
    let cmp: QsortCmp = unsafe { core::mem::transmute(context) };
    unsafe { cmp(left, right) }
}

/// Sort caller-owned records through C qsort.
///
/// # Safety
///
/// For a nonzero nel-times-width product, base must address that many writable
/// bytes as valid records. The multiplication must not overflow. cmp must be
/// a non-null C-ABI callback that returns normally and imposes a consistent
/// ordering. C++ exceptions and C longjmp may not cross this Rust code.
#[no_mangle]
pub unsafe extern "C" fn qsort(base: *mut c_void, nel: usize, width: usize, cmp: QsortCmp) {
    unsafe { qsort_with_context(base, nel, width, qsort_wrap_cmp, cmp as *mut c_void) };
}
