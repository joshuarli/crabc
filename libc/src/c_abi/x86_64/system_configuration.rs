//! Selected static Linux/x86-64 C system-configuration boundary.
//!
//! This module owns one closed, allocation-free C configuration block:
//! `sysconf`, `confstr`, `pathconf`, `fpathconf`, `getpagesize`, and
//! `getdtablesize`. It deliberately composes only the raw Linux register
//! boundary for `getdtablesize` and the selected initial-TLS C `errno` slot.
//! It is not general system information, filesystem capacity observation,
//! `/proc` parsing, a C startup/auxv owner, a dynamic libc, CRT, pthread/TLS
//! lifecycle, loader, sysroot, allocator, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/conf/sysconf.c` maps to the explicitly selected two-selector
//!   [`sysconf`] surface.
//! - `src/conf/confstr.c` maps to [`confstr`].
//! - `src/conf/pathconf.c` and `src/conf/fpathconf.c` map to [`pathconf`] and
//!   [`fpathconf`], including their deliberate path- and fd-independent table.
//! - `src/legacy/getpagesize.c` maps to [`getpagesize`].
//! - `src/legacy/getdtablesize.c` maps to [`getdtablesize`].
//!
//! The corresponding AArch64 implementation now follows this same table, and
//! `tests/path_configuration_exports.rs` dynamically compares it to pinned
//! musl without filesystem access. That focused agreement does not make this a
//! complete musl `sysconf` table: selectors which would need scheduler,
//! `sysinfo`, or startup-owned auxv state remain outside the admitted boundary.
//! Linux/x86-64's base page size is architecturally 4096 bytes, so unlike the
//! variable-page-size AArch64 implementation this selected `getpagesize`
//! surface does not need a future auxv owner.

use core::ffi::{c_char, c_int, c_long, c_ulong};
use core::mem::{align_of, offset_of, size_of};

use super::{c_status, errno, raw_syscall};

const EINVAL: c_int = 22;

const SC_CLK_TCK: c_int = 2;
const SC_PAGE_SIZE: c_int = 30;

const CS_PATH: c_int = 0;
const CS_POSIX_V6_WIDTH_RESTRICTED_ENVS: c_int = 1;
const CS_POSIX_V7_WIDTH_RESTRICTED_ENVS: c_int = 5;
const CS_POSIX_V6_ILP32_OFF32_CFLAGS: c_int = 1116;
const CS_POSIX_V7_THREADS_LDFLAGS: c_int = 1151;

const PC_LINK_MAX: c_int = 0;
const PC_MAX_CANON: c_int = 1;
const PC_MAX_INPUT: c_int = 2;
const PC_NAME_MAX: c_int = 3;
const PC_PATH_MAX: c_int = 4;
const PC_PIPE_BUF: c_int = 5;
const PC_CHOWN_RESTRICTED: c_int = 6;
const PC_NO_TRUNC: c_int = 7;
const PC_VDISABLE: c_int = 8;
const PC_SYNC_IO: c_int = 9;
const PC_ASYNC_IO: c_int = 10;
const PC_PRIO_IO: c_int = 11;
const PC_SOCK_MAXBUF: c_int = 12;
const PC_FILESIZEBITS: c_int = 13;
const PC_REC_INCR_XFER_SIZE: c_int = 14;
const PC_REC_MAX_XFER_SIZE: c_int = 15;
const PC_REC_MIN_XFER_SIZE: c_int = 16;
const PC_REC_XFER_ALIGN: c_int = 17;
const PC_ALLOC_SIZE_MIN: c_int = 18;
const PC_SYMLINK_MAX: c_int = 19;
const PC_2_SYMLINKS: c_int = 20;

const RLIMIT_NOFILE: c_int = 7;
const X86_64_LINUX_PAGE_SIZE: c_int = 4096;

/// Exact x86 public `struct rlimit` storage needed by `getdtablesize`.
///
/// The existing selected process-resources artifact owns the public C resource
/// boundary. This local private record retains the same LP64 kernel layout so
/// this configuration block can remain one closed archive artifact rather than
/// coupling to a broader process-resource API.
#[repr(C)]
struct Rlimit {
    current: c_ulong,
    maximum: c_ulong,
}

const _: () = {
    assert!(size_of::<Rlimit>() == 16);
    assert!(align_of::<Rlimit>() == 8);
    assert!(offset_of!(Rlimit, current) == 0);
    assert!(offset_of!(Rlimit, maximum) == 8);
};

/// Return one selected `sysconf` value.
///
/// The public x86 selector namespace remains available in `<unistd.h>`, but
/// this bounded static artifact admits only Linux's fixed `USER_HZ` value and
/// the x86-64 base page size. Any other selector is a direct `EINVAL`, rather
/// than a fabricated scheduler, system-information, or auxv fallback.
#[no_mangle]
pub extern "C" fn sysconf(name: c_int) -> c_long {
    match name {
        SC_CLK_TCK => 100,
        SC_PAGE_SIZE => c_long::from(X86_64_LINUX_PAGE_SIZE),
        _ => {
            // SAFETY: this selected C ABI owns the calling thread's initial-TLS
            // errno publication for rejected scalar selectors.
            unsafe { errno::set_errno(EINVAL) };
            -1
        }
    }
}

#[inline]
fn confstr_value(name: c_int) -> Option<&'static [u8]> {
    match name {
        CS_PATH => Some(b"/bin:/usr/bin\0"),
        CS_POSIX_V6_WIDTH_RESTRICTED_ENVS | CS_POSIX_V7_WIDTH_RESTRICTED_ENVS => {
            Some(b"\0")
        }
        CS_POSIX_V6_ILP32_OFF32_CFLAGS..=CS_POSIX_V7_THREADS_LDFLAGS => Some(b"\0"),
        _ => None,
    }
}

/// Query or copy a selected POSIX configuration string.
///
/// `buf` may be null only when `len` is zero. When it is non-null, it must
/// designate `len` writable bytes for the call. Like musl, a too-small output
/// buffer receives the maximal NUL-terminated prefix and the function returns
/// the full required size including that NUL byte.
///
/// # Safety
///
/// When `buf` is non-null and `len` is nonzero, it must designate `len`
/// writable bytes for the complete copy and terminator write.
#[no_mangle]
pub unsafe extern "C" fn confstr(name: c_int, buf: *mut c_char, len: usize) -> usize {
    let Some(value) = confstr_value(name) else {
        // SAFETY: this selected C ABI owns the calling thread's initial-TLS
        // errno publication for rejected scalar selectors.
        unsafe { errno::set_errno(EINVAL) };
        return 0;
    };

    let value_len = value.len() - 1;
    if !buf.is_null() && len != 0 {
        let copy_len = core::cmp::min(len - 1, value_len);
        // SAFETY: the caller owns `len` writable bytes when supplying a
        // non-null output pointer. `copy_len < len`, so the terminator write
        // remains inside that C object.
        unsafe {
            core::ptr::copy_nonoverlapping(value.as_ptr(), buf.cast::<u8>(), copy_len);
            *buf.add(copy_len) = 0;
        }
    }
    value_len + 1
}

#[inline(always)]
fn pathconf_value(name: c_int) -> Option<c_long> {
    let value = match name {
        PC_LINK_MAX => 8,
        PC_MAX_CANON | PC_MAX_INPUT | PC_NAME_MAX => 255,
        PC_PATH_MAX | PC_PIPE_BUF => 4096,
        PC_CHOWN_RESTRICTED | PC_NO_TRUNC | PC_SYNC_IO | PC_2_SYMLINKS => 1,
        PC_VDISABLE => 0,
        PC_ASYNC_IO | PC_PRIO_IO | PC_SOCK_MAXBUF | PC_SYMLINK_MAX => -1,
        PC_FILESIZEBITS => 64,
        PC_REC_INCR_XFER_SIZE
        | PC_REC_MAX_XFER_SIZE
        | PC_REC_MIN_XFER_SIZE
        | PC_REC_XFER_ALIGN
        | PC_ALLOC_SIZE_MIN => X86_64_LINUX_PAGE_SIZE,
        _ => return None,
    };
    Some(c_long::from(value))
}

// Keep this scalar table decision inside both public entry points so the
// artifact's entry-point disassembly check proves it cannot acquire a hidden
// filesystem syscall.
#[inline(always)]
unsafe fn selected_pathconf(name: c_int) -> c_long {
    match pathconf_value(name) {
        Some(value) => value,
        None => {
            // SAFETY: this selected C ABI owns the calling thread's initial-TLS
            // errno publication for rejected scalar selectors.
            unsafe { errno::set_errno(EINVAL) };
            -1
        }
    }
}

/// Return a selected path configuration value for an open descriptor.
///
/// Musl's selected Linux contract is table-based, so `fd` is deliberately not
/// dereferenced or passed to Linux. Valid selectors therefore do not fail for
/// an invalid descriptor; valid indeterminate `-1` values preserve `errno`.
#[no_mangle]
pub extern "C" fn fpathconf(_fd: c_int, name: c_int) -> c_long {
    // SAFETY: this helper only publishes EINVAL for an invalid scalar selector.
    unsafe { selected_pathconf(name) }
}

/// Return a selected path configuration value for a pathname.
///
/// Musl's selected Linux contract is table-based, so `path` is deliberately
/// not dereferenced or passed to Linux. Valid selectors therefore do not fail
/// for a null or missing pathname; valid indeterminate `-1` values preserve
/// `errno`.
#[no_mangle]
pub extern "C" fn pathconf(_path: *const c_char, name: c_int) -> c_long {
    // SAFETY: this helper only publishes EINVAL for an invalid scalar selector.
    unsafe { selected_pathconf(name) }
}

/// Return Linux/x86-64's fixed base page size.
///
/// The x86-64 Linux ABI has a 4096-byte base page size; this is not an auxv
/// reader and does not claim the future x86 C startup/runtime contract.
#[no_mangle]
pub extern "C" fn getpagesize() -> c_int {
    X86_64_LINUX_PAGE_SIZE
}

/// Return the calling process's soft descriptor limit clamped to `INT_MAX`.
///
/// The result directly follows musl's `getdtablesize` normal path. The raw
/// `prlimit64` error is translated through the selected initial-TLS errno slot;
/// an error cannot fabricate a descriptor-table size.
#[no_mangle]
pub extern "C" fn getdtablesize() -> c_int {
    let mut limit = Rlimit {
        current: 0,
        maximum: 0,
    };
    // SAFETY: Linux/x86-64 `prlimit64=302` consumes the target pid, resource,
    // null new-limit, and writable old-limit in rdi/rsi/rdx/r10. This stack
    // record has the exact 16-byte x86 public/kernel `rlimit` layout.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_PRLIMIT64,
            0,
            i64::from(RLIMIT_NOFILE),
            0,
            core::ptr::addr_of_mut!(limit) as usize as i64,
        )
    };
    if c_status(result) != 0 {
        return -1;
    }
    if limit.current < c_ulong::try_from(c_int::MAX).unwrap_or(c_ulong::MAX) {
        limit.current as c_int
    } else {
        c_int::MAX
    }
}
