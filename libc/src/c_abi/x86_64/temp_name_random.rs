//! Shared Linux/x86-64 translation of musl's private temporary-name suffix.
//!
//! Pinned musl 1.2.6 release commit
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417, under musl's MIT license,
//! maps src/temp/__randname.c::__randname to [randomize_suffix]. The source
//! derives six non-cryptographic characters from CLOCK_REALTIME and the
//! calling thread id, then writes only the caller-owned six-byte template
//! suffix. It is shared by the selected historical mktemp, tmpnam, and
//! tempnam compatibility leaves; it does not allocate, reserve, create, open,
//! unlink, or provide a safe temporary-file policy.
//!
//! Musl's `__randname` reaches a VDSO-first `__clock_gettime` path and reads
//! its initialized pthread TCB's tid. The staged x86 static C ABI owns neither
//! a VDSO dispatcher nor a general TCB, so the existing mktemp port's direct
//! `clock_gettime=228` and `gettid=186` observations are retained here as the
//! target-local adaptation. A seccomp policy can therefore select this
//! helper's fail closed result where musl might still produce a suffix through
//! its VDSO/TCB path. Pinned musl's source also ignores a failed clock
//! observation. A valid Linux 5.10 CLOCK_REALTIME query and gettid do not
//! normally fail; if either raw observation does fail, this helper returns the
//! Linux errno so its C-ABI caller does not derive a suffix from invalid
//! storage.

use core::ffi::c_int;
use core::mem::{align_of, size_of};

use super::raw_syscall;

pub(super) const TEMPLATE_SUFFIX_BYTES: usize = 6;
const CLOCK_REALTIME: i64 = 0;

/// Private Linux/x86-64 clock_gettime output storage.
#[repr(C)]
struct Timespec {
    seconds: i64,
    nanoseconds: i64,
}

const _: () = {
    assert!(size_of::<Timespec>() == 16);
    assert!(align_of::<Timespec>() == 8);
};

#[inline]
fn raw_error(result: i64) -> Option<c_int> {
    if (-4_095..=-1).contains(&result) {
        Some(result.wrapping_neg() as c_int)
    } else {
        None
    }
}

/// Apply musl's source-selected non-cryptographic six-byte name mapping.
///
/// # Safety
///
/// suffix must address exactly [TEMPLATE_SUFFIX_BYTES] writable bytes. The
/// caller owns the complete template and must serialize any concurrent
/// mutation or observation of it. This helper does not validate pathname,
/// buffer, allocation, or temporary-file policy.
#[inline]
pub(super) unsafe fn randomize_suffix(suffix: *mut u8) -> Result<(), c_int> {
    let mut time = Timespec {
        seconds: 0,
        nanoseconds: 0,
    };
    // SAFETY: time is complete writable Linux timespec storage and
    // CLOCK_REALTIME is the source-selected scalar clock id.
    let time_result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_CLOCK_GETTIME,
            CLOCK_REALTIME,
            (&mut time as *mut Timespec).cast::<u8>() as usize as i64,
        )
    };
    if let Some(error) = raw_error(time_result) {
        return Err(error);
    }
    // SAFETY: gettid has no pointer arguments and its direct Linux result is
    // only used as musl's per-thread scalar contribution.
    let thread_result = unsafe { raw_syscall::syscall0(raw_syscall::SYS_GETTID) };
    if let Some(error) = raw_error(thread_result) {
        return Err(error);
    }

    let mut random = (time.seconds as u64)
        .wrapping_add(time.nanoseconds as u64)
        .wrapping_add((thread_result as u64).wrapping_mul(65_537));
    for index in 0..TEMPLATE_SUFFIX_BYTES {
        let letter = b'A'
            .wrapping_add((random & 15) as u8)
            .wrapping_add(if random & 16 != 0 { 32 } else { 0 });
        // SAFETY: caller supplies exactly six writable suffix bytes and the
        // loop index stays within that fixed source-selected range.
        unsafe { core::ptr::write(suffix.wrapping_add(index), letter) };
        random >>= 5;
    }
    Ok(())
}
