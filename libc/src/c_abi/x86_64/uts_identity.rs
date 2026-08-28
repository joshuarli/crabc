//! Selected static Linux/x86-64 C UTS-namespace identity boundary.
//!
//! This leaf owns one coherent, bounded native C UTS-identity block:
//! `gethostname`, `sethostname`, `getdomainname`, and `setdomainname`. It
//! composes the separately selected private `uname` record seam, the raw
//! Linux syscall register boundary, and the selected initial-TLS C `errno`
//! slot. It is not namespace creation/entry/control, gethostid/sethostid,
//! system-file parsing, processor/page-count or load discovery, `sysconf`, a
//! system-information framework, process identity, a general C/POSIX runtime,
//! libc.so, CRT, pthread/TLS lifecycle, dynamic TLS, loader, sysroot,
//! allocator, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/unistd/gethostname.c` maps directly to [`gethostname`].
//! - `src/linux/sethostname.c` maps directly to [`sethostname`].
//! - `src/misc/getdomainname.c` maps directly to [`getdomainname`].
//! - `src/misc/setdomainname.c` maps directly to [`setdomainname`].
//!
//! Musl's `gethostname` caps its copy at the complete 65-byte public
//! `utsname.nodename` field and forces a final NUL only when that copied range
//! is exhausted. `getdomainname` instead requires room for the full domain
//! field through its NUL and returns `EINVAL` without writing on a zero or
//! too-small buffer. Its musl source calls `uname` without checking its
//! result;
//! Linux 5.10's valid stack-record call succeeds. This Rust translation
//! returns an otherwise impossible raw `uname` error rather than read an
//! uninitialized record, and rejects a hypothetically non-NUL-terminated
//! kernel field rather than use musl's unbounded string scan. Those defined
//! defensive error paths are the only intentional source-level differences
//! and are not fallbacks.

use core::ffi::{c_char, c_int};
use core::mem::MaybeUninit;

use super::{c_status, errno, raw_syscall, system_observation};

const EINVAL: c_int = 22;

#[inline]
unsafe fn read_utsname() -> Result<system_observation::UtsName, i64> {
    let mut name = MaybeUninit::<system_observation::UtsName>::uninit();
    // SAFETY: `name` is one complete writable public `utsname` record.
    let result = unsafe { system_observation::uname_raw(name.as_mut_ptr()) };
    if result < 0 {
        return Err(result);
    }
    // SAFETY: a successful Linux uname syscall initializes the complete
    // public 390-byte record, as pinned by system_observation's ABI contract.
    Ok(unsafe { name.assume_init() })
}

#[inline]
fn field_nul_length(
    field: &[c_char; system_observation::UTS_FIELD_BYTES],
) -> Option<usize> {
    let mut length = 0;
    while length < field.len() {
        if field[length] == 0 {
            return Some(length);
        }
        length += 1;
    }
    None
}

/// Copy the current UTS hostname using musl's bounded copy rule.
///
/// # Safety
///
/// When `length` is nonzero, `output` must designate writable storage for at
/// least `min(length, 65)` bytes for the call's duration. A zero `length`
/// permits a null `output` and performs no output write. The caller owns any
/// concurrent UTS-namespace identity policy.
#[no_mangle]
pub unsafe extern "C" fn gethostname(output: *mut c_char, length: usize) -> c_int {
    let name = match unsafe { read_utsname() } {
        Ok(name) => name,
        Err(result) => return c_status(result),
    };
    let bounded_length = core::cmp::min(length, system_observation::UTS_FIELD_BYTES);
    let mut index = 0;

    while index < bounded_length {
        let byte = name.node_name[index];
        // SAFETY: the caller provides writable storage for exactly the
        // bounded musl copy extent whenever `length` is nonzero.
        unsafe { output.add(index).write(byte) };
        if byte == 0 {
            break;
        }
        index += 1;
    }
    if bounded_length != 0 && index == bounded_length {
        // SAFETY: the final byte belongs to the same caller-provided bounded
        // output range. This is musl's forced-NUL truncation rule.
        unsafe { output.add(bounded_length - 1).write(0) };
    }
    0
}

/// Copy the current UTS domain name only when the full value fits.
///
/// # Safety
///
/// When `length` is nonzero, `output` must designate writable storage for
/// `length` bytes for the call's duration. A zero `length` permits a null
/// `output`, returns `-1`, and writes `EINVAL`. The caller owns any concurrent
/// UTS-namespace identity policy.
#[no_mangle]
pub unsafe extern "C" fn getdomainname(output: *mut c_char, length: usize) -> c_int {
    let name = match unsafe { read_utsname() } {
        Ok(name) => name,
        Err(result) => return c_status(result),
    };
    let domain_length = match field_nul_length(&name.domain_name) {
        Some(length) => length,
        // Linux's UTS field is NUL-terminated on the 5.10 baseline. Do not
        // emulate musl's unbounded strlen if a malformed external record
        // violates that kernel contract: preserve Rust memory safety with the
        // same direct EINVAL result used for a non-fitting public buffer.
        None => {
            // SAFETY: this selected C leaf owns the direct local EINVAL slot.
            unsafe { errno::set_errno(EINVAL) };
            return -1;
        }
    };
    if length == 0 || domain_length >= length {
        // SAFETY: this is the selected C wrapper's own direct EINVAL result
        // for musl's no-truncation buffer contract.
        unsafe { errno::set_errno(EINVAL) };
        return -1;
    }
    // SAFETY: the successful branch requires a buffer larger than the exact
    // domain length, so the complete NUL-terminated field prefix fits.
    unsafe {
        core::ptr::copy_nonoverlapping(
            name.domain_name.as_ptr(),
            output,
            domain_length + 1,
        );
    }
    0
}

/// Replace the hostname in the calling UTS namespace through Linux.
///
/// # Safety
///
/// `name` must designate `length` readable bytes when the caller expects a
/// successful kernel copy. The change affects every task sharing the calling
/// UTS namespace, so callers must arrange namespace isolation, synchronization,
/// and restoration as appropriate. This wrapper supplies no namespace policy.
#[no_mangle]
pub unsafe extern "C" fn sethostname(name: *const c_char, length: usize) -> c_int {
    // SAFETY: the caller supplies the raw Linux pointer/length contract. The
    // two scalar words occupy rdi/rsi for x86 sethostname=170.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_SETHOSTNAME,
            name as usize as i64,
            length as i64,
        )
    };
    c_status(result)
}

/// Replace the domain name in the calling UTS namespace through Linux.
///
/// # Safety
///
/// `name` must designate `length` readable bytes when the caller expects a
/// successful kernel copy. The change affects every task sharing the calling
/// UTS namespace, so callers must arrange namespace isolation, synchronization,
/// and restoration as appropriate. This wrapper supplies no namespace policy.
#[no_mangle]
pub unsafe extern "C" fn setdomainname(name: *const c_char, length: usize) -> c_int {
    // SAFETY: the caller supplies the raw Linux pointer/length contract. The
    // two scalar words occupy rdi/rsi for x86 setdomainname=171.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_SETDOMAINNAME,
            name as usize as i64,
            length as i64,
        )
    };
    c_status(result)
}
