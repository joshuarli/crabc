//! Selected static Linux/x86-64 historical C `mktemp` boundary.
//!
//! This is a deliberately narrow port of pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.
//! Musl `src/temp/mktemp.c::mktemp` validates one mutable C template ending
//! in six `X` bytes, calls `src/temp/__randname.c::__randname` to replace that
//! suffix, and probes it with `stat`. A missing name returns the same mutated
//! buffer with `errno=ENOENT`; an invalid template and a non-missing lookup
//! failure clear its first byte; one hundred occupied candidates end with
//! `errno=EEXIST`. Source-function mapping: musl `mktemp` and `__randname`
//! map to [`mktemp`] and its private helpers in this module.
//!
//! The source's six-byte time/TID mapping is preserved exactly: `CLOCK_REALTIME`
//! seconds plus nanoseconds plus `gettid * 65537`, shifted five bits per
//! output byte into `A`-`P`/`a`-`p`. It is not entropy, a PRNG, or a security
//! guarantee. `mktemp` only observes a pathname; another actor can create or
//! replace it before any later use. It does not create, open, reserve, unlink,
//! or return an authority-bearing descriptor/handle.
//!
//! This historical C ABI leaf deliberately excludes `tmpnam`, `tempnam`,
//! `mkstemp`/`mkstemps`/`mkostemp`/`mkostemps`, `mkdtemp`, `tmpfile`, generic
//! temporary-file policy, directory-descriptor or file-descriptor authority,
//! `name_to_handle_at`/`open_by_handle_at`, allocation, Rust facade APIs,
//! cancellation, dynamic runtime, CRT, loader, sysroot, and public x86
//! support. A raw `clock_gettime` or `gettid` failure—outside the ordinary
//! Linux source path—clears the template and publishes that error rather than
//! deriving a name from uninitialized time storage.

use core::ffi::{c_char, c_int};
use core::mem::{align_of, size_of};

use super::{errno, raw_syscall};

const TEMPLATE_SUFFIX_BYTES: usize = 6;
const MAX_ATTEMPTS: usize = 100;
const CLOCK_REALTIME: i64 = 0;
const AT_FDCWD: c_int = -100;
const ENOENT: c_int = 2;
const EEXIST: c_int = 17;
const EINVAL: c_int = 22;

/// Private Linux/x86-64 `clock_gettime` output storage.
#[repr(C)]
struct Timespec {
    seconds: i64,
    nanoseconds: i64,
}

/// Private output storage for the exact x86 `newfstatat` kernel record.
///
/// `mktemp` only needs its success/failure result, so this is intentionally
/// not the public C `struct stat` owner. The fixed 144-byte, eight-aligned
/// scratch preserves the Linux/x86-64 syscall output contract without pulling
/// in the separately selected metadata C ABI leaf.
#[repr(C, align(8))]
struct KernelStatScratch {
    bytes: [u8; 144],
}

const _: () = {
    assert!(size_of::<Timespec>() == 16);
    assert!(align_of::<Timespec>() == 8);
    assert!(size_of::<KernelStatScratch>() == 144);
    assert!(align_of::<KernelStatScratch>() == 8);
};

#[inline]
fn raw_error(result: i64) -> Option<c_int> {
    if (-4_095..=-1).contains(&result) {
        Some(result.wrapping_neg() as c_int)
    } else {
        None
    }
}

/// Return the byte length of one caller-owned NUL-terminated C string.
///
/// # Safety
///
/// `text` must point to a readable NUL-terminated C string for the complete
/// scan. This is the source-compatible `mktemp` template precondition; no
/// bounded Rust string policy is introduced here.
#[inline]
unsafe fn c_string_length(text: *const c_char) -> usize {
    let mut length = 0_usize;
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    length
}

#[inline]
unsafe fn has_template_suffix(template: *const u8, length: usize) -> bool {
    if length < TEMPLATE_SUFFIX_BYTES {
        return false;
    }
    let suffix = unsafe { template.add(length - TEMPLATE_SUFFIX_BYTES) };
    for index in 0..TEMPLATE_SUFFIX_BYTES {
        if unsafe { *suffix.add(index) } != b'X' {
            return false;
        }
    }
    true
}

/// Apply musl's source-selected non-cryptographic six-byte name mapping.
///
/// # Safety
///
/// `suffix` must address six writable bytes. The caller has already checked
/// the complete C template and supplies its final six `X` bytes.
#[inline]
unsafe fn randomize_suffix(suffix: *mut u8) -> Result<(), c_int> {
    let mut time = Timespec {
        seconds: 0,
        nanoseconds: 0,
    };
    // SAFETY: `time` is complete writable Linux timespec storage and
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
        unsafe { *suffix.add(index) = letter };
        random >>= 5;
    }
    Ok(())
}

/// Generate a legacy candidate pathname by replacing a trailing `XXXXXX`.
///
/// This returns the same template pointer. On a generated unoccupied name,
/// Linux's `ENOENT` remains in C `errno`; it does not reserve or create that
/// name. The function is therefore inherently racy and must not be used for
/// a security, ownership, or authority decision.
///
/// # Safety
///
/// `template` must be non-null and point to a readable NUL-terminated C
/// string whose first byte is writable for the full call. If its final six
/// bytes are `XXXXXX`, those six bytes must also be writable. The caller owns
/// the template's lifetime and must externally serialize concurrent mutation,
/// observation, and pathname-resolution use of it. As in the historical C
/// API, invalid pointers and an unterminated string are caller bugs, not
/// converted into a Rust or handle-based error model.
#[no_mangle]
pub unsafe extern "C" fn mktemp(template: *mut c_char) -> *mut c_char {
    // SAFETY: public C caller upholds the documented complete readable
    // NUL-terminated template contract.
    let length = unsafe { c_string_length(template) };
    let template_bytes = template.cast::<u8>();
    // SAFETY: the same caller contract keeps the scanned suffix readable.
    if unsafe { !has_template_suffix(template_bytes, length) } {
        // SAFETY: public C caller supplies writable first-byte storage.
        unsafe { *template = 0 };
        // SAFETY: this C ABI leaf owns publication of its selected error.
        unsafe { errno::set_errno(EINVAL) };
        return template;
    }

    // SAFETY: the suffix check established the offset and public caller owns
    // these six writable template bytes for the call.
    let suffix = unsafe { template_bytes.add(length - TEMPLATE_SUFFIX_BYTES) };
    for _ in 0..MAX_ATTEMPTS {
        // SAFETY: `suffix` remains the six writable final template bytes.
        if let Err(error) = unsafe { randomize_suffix(suffix) } {
            // SAFETY: the public caller supplies writable first-byte storage;
            // this error-only boundary fails closed rather than using invalid
            // time/TID data.
            unsafe { *template = 0 };
            // SAFETY: selected x86 C errno publication for this failure.
            unsafe { errno::set_errno(error) };
            return template;
        }

        let mut metadata = KernelStatScratch { bytes: [0; 144] };
        // SAFETY: `template` is the caller-owned complete pathname and the
        // local scratch has the exact Linux/x86-64 output extent/alignment.
        let lookup = unsafe {
            raw_syscall::syscall4(
                raw_syscall::SYS_NEWFSTATAT,
                i64::from(AT_FDCWD),
                template as usize as i64,
                (&mut metadata as *mut KernelStatScratch).cast::<u8>() as usize as i64,
                0,
            )
        };
        if let Some(error) = raw_error(lookup) {
            // SAFETY: this is the selected raw Linux error after the one
            // source-compatible pathname probe.
            unsafe { errno::set_errno(error) };
            if error != ENOENT {
                // SAFETY: non-missing lookup failures clear the caller's
                // first template byte exactly as musl's historical contract.
                unsafe { *template = 0 };
            }
            return template;
        }
    }

    // SAFETY: all source-selected candidate probes found an existing entry;
    // the public caller supplied writable first-byte storage.
    unsafe { *template = 0 };
    // SAFETY: fixed exhaustion result for musl's one-hundred-attempt loop.
    unsafe { errno::set_errno(EEXIST) };
    template
}
