//! Owned Linux/x86-64 C system-configuration boundary.
//!
//! This aggregate-only module retains the frozen configuration block
//! (`confstr`, `pathconf`, `fpathconf`, `getpagesize`, `getdtablesize`, and
//! the fixed `sysconf` selectors) while adding the two Linux 5.10
//! auxv-derived signal-stack selectors required by the installed POSIX
//! runtime. The frozen `system_configuration.rs` remains selected outside
//! `x86-owned-static-runtime`; this file cannot widen that earlier archive.
//! It borrows the already-owned immutable auxv observation and initial-TLS C
//! `errno` publication, but owns neither startup nor signal-stack storage.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/conf/sysconf.c` maps `_SC_CLK_TCK=2`, `_SC_PAGE_SIZE=30`,
//!   `_SC_MINSIGSTKSZ=249`, and `_SC_SIGSTKSZ=250` to [`sysconf`]. The latter
//!   two retain the source's `AT_MINSIGSTKSZ` clamp and working-space addition
//!   through [`minimum_signal_stack_size`] and [`signal_stack_size`]. The
//!   source's wider rlimit, scheduler, and system-information table remains
//!   outside this owned configuration slice. Its defined far nonnegative
//!   invalid route is `EINVAL`; its unchecked negative signed index remains
//!   outside differential admission.
//! - `src/conf/confstr.c` maps to [`confstr`].
//! - `src/conf/fpathconf.c` maps to [`fpathconf`]'s deliberate
//!   fd-independent selector table. The selected positive selector boundary is
//!   0 through 20 plus the defined nonnegative out-of-range `EINVAL` result;
//!   musl's unchecked negative C-array index remains outside differential admission.
//! - `src/conf/pathconf.c` maps to [`pathconf`], which delegates to that
//!   `fpathconf(-1, name)` table without dereferencing its pathname. Its
//!   selected positive-selector boundary is therefore also 0 through 20 plus
//!   the defined nonnegative out-of-range `EINVAL` result; the delegated
//!   unchecked negative C-array index remains outside differential admission.
//! - `src/legacy/getpagesize.c` maps to [`getpagesize`].
//! - `src/legacy/getdtablesize.c` maps to [`getdtablesize`].
//!
//! This remains a selected configuration slice rather than a complete musl
//! `sysconf` table. Linux/x86-64's base page size is architecturally 4096.
//! The signal-stack selectors are available only after the installed runtime's
//! existing startup path publishes the validated initial auxv; Linux 5.10
//! supplies `AT_MINSIGSTKSZ`, so no pre-baseline fallback is added.

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong};
use core::mem::{align_of, offset_of, size_of};

use super::{auxv_observation, c_status, errno, raw_syscall};

const EINVAL: c_int = 22;

const SC_CLK_TCK: c_int = 2;
const SC_PAGE_SIZE: c_int = 30;
const SC_MINSIGSTKSZ: c_int = 249;
const SC_SIGSTKSZ: c_int = 250;
const AT_MINSIGSTKSZ: c_ulong = 51;
const MINSIGSTKSZ: c_uint = 2_048;
const SIGSTKSZ: c_uint = 8_192;

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
/// Linux/x86-64's fixed 4 KiB base page is shared with the separate selected
/// system-information leaf. It is an architectural x86 fact, not an auxv or
/// C startup dependency.
pub(super) const X86_64_LINUX_PAGE_SIZE: c_int = 4096;

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

/// Return musl's Linux 5.10 minimum alternate-signal-stack size.
///
/// `sysconf.c` first takes the kernel-provided signal-frame size from the
/// validated initial auxv, clamps it to one KiB below the public historical
/// minimum, and adds one KiB of application working space. The source stores
/// its result in C `unsigned`; keep that x86 32-bit wrap boundary explicit.
/// The installed runtime publishes `AT_MINSIGSTKSZ` before application code,
/// so this is not a pre-5.10 fallback or a second auxv owner.
pub(super) fn minimum_signal_stack_size() -> usize {
    // SAFETY: the installed static/dynamic startup has already published its
    // validated immutable auxiliary vector before calling public C code.
    let mut signal_frame_size = unsafe { auxv_observation::__getauxval(AT_MINSIGSTKSZ) };
    let floor = c_ulong::from(MINSIGSTKSZ - 1_024);
    if signal_frame_size < floor {
        signal_frame_size = floor;
    }
    (signal_frame_size as c_uint).wrapping_add(1_024) as usize
}

/// Return musl's Linux 5.10 default alternate-signal-stack size.
pub(super) fn signal_stack_size() -> usize {
    (minimum_signal_stack_size() as c_uint)
        .wrapping_add(SIGSTKSZ - MINSIGSTKSZ) as usize
}

/// Return one owned `sysconf` value.
///
/// The installed aggregate adds only the two signal-stack selectors to the
/// frozen fixed `USER_HZ`/page-size selection. It does not fabricate the
/// source table's scheduler, rlimit, or system-information closures. The
/// pinned source directly indexes negative selectors without a source-defined
/// result, so this differential boundary admits only these four direct values
/// plus a far nonnegative-invalid `EINVAL` result.
#[no_mangle]
pub extern "C" fn sysconf(name: c_int) -> c_long {
    match name {
        SC_CLK_TCK => 100,
        SC_PAGE_SIZE => c_long::from(X86_64_LINUX_PAGE_SIZE),
        SC_MINSIGSTKSZ => minimum_signal_stack_size() as c_long,
        SC_SIGSTKSZ => signal_stack_size() as c_long,
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
        // Unlike musl's internal `snprintf` shortcut, copy the selected small
        // literal byte-by-byte. This retains musl's query/truncation result
        // while keeping the isolated `confstr` static candidate free of a
        // stdio or compiler-memory-helper closure.
        //
        // SAFETY: the caller owns `len` writable bytes when supplying a
        // non-null output pointer. `copy_len < len` and `copy_len <= value_len`,
        // so the source reads and destination/terminator writes remain inside
        // their respective objects.
        unsafe {
            let source = value.as_ptr();
            let mut index = 0usize;
            while index < copy_len {
                buf.add(index).write(source.add(index).read() as c_char);
                index += 1;
            }
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
/// dereferenced or passed to Linux. Valid selectors therefore do not fail for an invalid
/// descriptor; valid indeterminate `-1` values preserve `errno`.
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
/// `errno`. As in musl's delegated `fpathconf(-1, name)` source closure, this
/// selected safe translation publishes `EINVAL` for every invalid Rust scalar,
/// while the pinned C source's negative signed index remains outside the
/// differential contract.
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
/// Musl's source closure is `src/legacy/getdtablesize.c` through
/// `src/misc/getrlimit.c`: its successful `prlimit64` normal path supplies the
/// `RLIMIT_NOFILE` record. Linux 5.10 is above musl's historical
/// `SYS_getrlimit` fallback boundary, so this selected x86 leaf deliberately
/// does not invent that fallback. Musl's legacy caller ignores a failed
/// `getrlimit` and reads an uninitialized local record; this safer leaf instead
/// translates the raw `prlimit64` error through initial-TLS errno and returns
/// `-1`, so an error cannot fabricate a descriptor-table size.
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
