//! Bounded Linux/x86-64 explicit_bzero/swab C ABI boundary.
//!
//! This opt-in owner maps pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` (musl MIT):
//!
//! - `src/string/explicit_bzero.c::explicit_bzero` calls `memset` and follows
//!   it with an empty volatile asm memory barrier carrying the returned pointer.
//! - `src/string/swab.c::swab` copies independent source/destination bytes in
//!   reversed pairs while the signed count remains greater than one.
//!
//! The selected x86 owner preserves that closure: `explicit_bzero` calls the
//! existing selected `memset` and has an opaque memory-clobbering compiler
//! barrier; `swab` has only its direct pair loop. Neither entry introduces
//! allocation, TLS, syscall, mutable runtime state, locale, or policy.

use core::ffi::{c_int, c_void};

// Keep the pinned musl source's direct dependency on the already selected x86
// bulk-memory owner rather than duplicating a second clearing routine.
unsafe extern "C" {
    fn memset(destination: *mut c_void, byte: c_int, count: usize) -> *mut c_void;
}

/// Erase a caller-owned byte range without allowing the compiler to erase the
/// call as a dead ordinary memory write.
///
/// # Safety
///
/// `destination` must designate a writable C byte range of `count` bytes for
/// the call. It must not have conflicting concurrent access. This retains
/// musl's direct `memset` dependency and passes its returned pointer to an
/// opaque memory-clobbering compiler barrier; it does not inspect the range.
#[no_mangle]
pub unsafe extern "C" fn explicit_bzero(destination: *mut c_void, count: usize) {
    // SAFETY: the caller supplies the same valid writable range required by
    // the selected x86 memset implementation.
    let cleared = unsafe { memset(destination, 0, count) };
    // SAFETY: this target-private empty asm is the musl-shaped compiler
    // barrier. Omitting `nomem` gives LLVM a memory clobber, while carrying
    // `cleared` prevents the preceding memset call from becoming dead work.
    unsafe {
        core::arch::asm!(
            "/* {cleared} */",
            cleared = in(reg) cleared,
            options(nostack, preserves_flags),
        );
    }
}

/// Copy independent bytes in swapped pairs, leaving an odd final byte alone.
///
/// # Safety
///
/// When `count > 1`, `source` must be readable and `destination` writable for
/// `count` bytes, and their ranges must not overlap. This is the concrete C
/// `restrict` precondition retained from musl. Nonpositive and one-byte counts
/// perform no pointer access or write.
#[no_mangle]
pub unsafe extern "C" fn swab(source: *const c_void, destination: *mut c_void, count: isize) {
    let mut remaining = count;
    let mut source = source.cast::<u8>();
    let mut destination = destination.cast::<u8>();

    while remaining > 1 {
        // SAFETY: the caller's nonoverlapping readable/writable count-byte
        // ranges cover each pair while `remaining > 1`.
        let first = unsafe { source.read() };
        // SAFETY: the second byte is within the same caller-owned pair.
        let second = unsafe { source.add(1).read() };
        // SAFETY: the two destination bytes are writable and disjoint from
        // the source range by the documented C restrict precondition.
        unsafe {
            destination.write(second);
            destination.add(1).write(first);
            source = source.add(2);
            destination = destination.add(2);
        }
        remaining -= 2;
    }
}
