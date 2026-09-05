//! Selected static Linux/x86-64 C descriptor-I/O boundary.
//!
//! This leaf owns one bounded native C descriptor block: `close`, scalar
//! transfer (`read` and `write`), positioned transfer (`pread` and `pwrite`),
//! position/truncation/synchronization requests (`lseek`, `ftruncate`,
//! `fsync`, and `fdatasync`), duplication (`dup`, `dup2`, and `dup3`), and
//! pipe creation (`pipe` and `pipe2`). It composes only the raw Linux syscall
//! register boundary and the selected initial-TLS C `errno` writer. It is not
//! C pathname/open or generic fcntl command support, or vector-I/O support,
//! a filesystem policy layer,
//! stdio, a general C/POSIX runtime, libc.so, CRT, pthread/TLS lifecycle,
//! dynamic TLS, loader, sysroot, allocator, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/unistd/read.c`, `src/unistd/write.c`, `src/unistd/close.c`,
//!   `src/unistd/lseek.c`, `src/unistd/pread.c`, `src/unistd/pwrite.c`,
//!   `src/unistd/pipe.c`, `src/unistd/pipe2.c`, `src/unistd/dup.c`,
//!   `src/unistd/dup2.c`, `src/unistd/dup3.c`, and
//!   `src/unistd/ftruncate.c` map to the correspondingly named wrappers below.
//! - `src/unistd/fsync.c` and `src/unistd/fdatasync.c` map to the two
//!   synchronization request wrappers.
//!
//! Musl routes `read`, `write`, `pread`, `pwrite`, `close`, `fsync`, and
//! `fdatasync` through cancellation-point machinery, and `close` coordinates
//! an AIO hook. The owned product routes all seven transfers/close/sync
//! entries through its SIGCANCEL/PC-window owner; legacy fixtures retain
//! direct Linux syscalls. The close point preserves musl's masked-state bypass
//! and post-syscall cancellation exclusion, together with its `close`
//! `EINTR` success mapping, the `dup2`/`dup3` `EBUSY` retry loops, and the
//! current musl `pwrite` algorithm: remap C offset `-1` to `-2` before the
//! kernel can interpret `-1` as the pwritev2 current-offset sentinel, use
//! `pwritev2(RWF_NOAPPEND)` first, then on `EOPNOTSUPP`/`ENOSYS` reject an
//! `O_APPEND` descriptor with `EOPNOTSUPP` before a direct `pwrite64`
//! fallback. This matters because a naive Linux `pwrite64` can append despite
//! the positioned-write contract.
//!
//! Linux 5.10 is the project baseline. Accordingly, `pipe2` has no legacy
//! `ENOSYS` fallback, while the explicit pwritev2 feature/error branch is the
//! pinned musl semantic algorithm rather than a pre-baseline kernel fallback.

use core::ffi::{c_int, c_long, c_void};

use super::{c_off_status, c_ssize_status, c_status, errno, raw_syscall};

const EINTR: i64 = 4;
const EBUSY: i64 = 16;
const EINVAL: c_int = 22;
const ENOSYS: i64 = 38;
const EOPNOTSUPP: i64 = 95;
const F_GETFL: i64 = 3;
const O_APPEND: i64 = 0x400;
const RWF_NOAPPEND: i64 = 0x20;

/// The private one-element iovec passed to Linux `pwritev2`.
///
/// This anchors Linux/x86-64's two-word `iovec` ABI locally without selecting
/// public C vector-I/O declarations or exports.
#[repr(C)]
struct IoVec {
    base: *const c_void,
    length: usize,
}

const _: [(); 16] = [(); core::mem::size_of::<IoVec>()];
const _: [(); 8] = [(); core::mem::align_of::<IoVec>()];

#[inline]
fn invalid_argument() -> c_int {
    // SAFETY: the selected static C ABI owns the calling initial-TLS errno
    // slot, and this is the local `dup3(old, old, ...)` EINVAL path.
    unsafe { errno::set_errno(EINVAL) };
    -1
}

#[inline]
fn retry_dup2(old_descriptor: c_int, new_descriptor: c_int) -> i64 {
    loop {
        // SAFETY: both arguments are scalar Linux descriptor words. The
        // kernel owns atomic replacement and validates their current state.
        let result = unsafe {
            raw_syscall::syscall2(
                raw_syscall::SYS_DUP2,
                i64::from(old_descriptor),
                i64::from(new_descriptor),
            )
        };
        if result != -EBUSY {
            return result;
        }
    }
}

#[inline]
fn retry_dup3(old_descriptor: c_int, new_descriptor: c_int, flags: c_int) -> i64 {
    loop {
        // SAFETY: the scalar descriptors and flags are passed untouched to
        // Linux. The kernel validates flags and owns atomic replacement.
        let result = unsafe {
            raw_syscall::syscall3(
                raw_syscall::SYS_DUP3,
                i64::from(old_descriptor),
                i64::from(new_descriptor),
                i64::from(flags),
            )
        };
        if result != -EBUSY {
            return result;
        }
    }
}

/// Close one descriptor through Linux `close(2)`.
///
/// This selected non-pthread leaf has no AIO coordination or descriptor
/// lifetime/race policy. It follows musl's direct wrapper convention that a
/// raw `EINTR` result reports C success and never retries the close, because a
/// retry could close an unrelated recycled descriptor. In the owned runtime,
/// ENABLE is a cancellation point before close; MASKED/DISABLE execute close
/// without delivery, and EINTR after close never becomes cancellation.
#[no_mangle]
pub extern "C" fn close(file_descriptor: c_int) -> c_int {
    // SAFETY: `file_descriptor` is a scalar Linux descriptor word; the kernel
    // validates it and owns the close lifetime transition.
    #[cfg(feature = "x86-owned-static-runtime")]
    let result = unsafe {
        super::pthread_cancel::syscall_cp(
            raw_syscall::SYS_CLOSE, i64::from(file_descriptor),
            0,
            0,
            0,
            0,
            0,
        )
    };
    #[cfg(not(feature = "x86-owned-static-runtime"))]
    let result = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_CLOSE, i64::from(file_descriptor))
    };
    if result == -EINTR {
        0
    } else {
        c_status(result)
    }
}

/// Read up to `count` bytes through Linux `read(2)`.
///
/// # Safety
///
/// If Linux examines the buffer, `buffer` must designate `count` writable
/// bytes for the syscall's duration. The caller owns descriptor lifetime and
/// concurrent offset policy. The owned runtime uses musl's cancellation-point
/// syscall; the older private direct-static fixture retains raw syscall behavior.
#[no_mangle]
pub unsafe extern "C" fn read(
    file_descriptor: c_int,
    buffer: *mut c_void,
    count: usize,
) -> isize {
    // SAFETY: the caller supplies the complete raw Linux read buffer contract.
    #[cfg(feature = "x86-owned-static-runtime")]
    let result = unsafe { super::pthread_cancel::syscall_cp(raw_syscall::SYS_READ,
        file_descriptor as i64, buffer as i64, count as i64, 0, 0, 0) };
    #[cfg(not(feature = "x86-owned-static-runtime"))]
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_READ,
            i64::from(file_descriptor),
            buffer as usize as i64,
            count as i64,
        )
    };
    c_ssize_status(result)
}

/// Write up to `count` bytes through Linux `write(2)`.
///
/// # Safety
///
/// If Linux examines the buffer, `buffer` must designate `count` readable
/// bytes for the syscall's duration. The caller owns descriptor lifetime,
/// shared-offset synchronization, and SIGPIPE policy. The owned runtime uses
/// musl's cancellation-point syscall; the older private fixture remains raw.
#[no_mangle]
pub unsafe extern "C" fn write(
    file_descriptor: c_int,
    buffer: *const c_void,
    count: usize,
) -> isize {
    // SAFETY: the caller supplies the complete raw Linux write buffer
    // contract, including signal/descriptor policy.
    #[cfg(feature = "x86-owned-static-runtime")]
    let result = unsafe { super::pthread_cancel::syscall_cp(raw_syscall::SYS_WRITE,
        file_descriptor as i64, buffer as i64, count as i64, 0, 0, 0) };
    #[cfg(not(feature = "x86-owned-static-runtime"))]
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_WRITE,
            i64::from(file_descriptor),
            buffer as usize as i64,
            count as i64,
        )
    };
    c_ssize_status(result)
}

/// Read at a fixed signed offset through Linux `pread64(2)`.
///
/// # Safety
///
/// If Linux examines the buffer, `buffer` must designate `count` writable
/// bytes for the syscall's duration. `offset` is passed as the exact signed
/// x86 `off_t` word. The owned runtime provides musl's cancellation point;
/// callers must register cleanup for resources that cannot be abandoned.
#[no_mangle]
pub unsafe extern "C" fn pread(
    file_descriptor: c_int,
    buffer: *mut c_void,
    count: usize,
    offset: c_long,
) -> isize {
    // SAFETY: the caller supplies the complete raw Linux positioned-read
    // buffer contract; x86 passes the fourth syscall word in r10.
    #[cfg(feature = "x86-owned-static-runtime")]
    let result = unsafe {
        super::pthread_cancel::syscall_cp(
            raw_syscall::SYS_PREAD64,
            i64::from(file_descriptor),
            buffer as usize as i64,
            count as i64,
            offset,
            0,
            0,
        )
    };
    #[cfg(not(feature = "x86-owned-static-runtime"))]
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_PREAD64,
            i64::from(file_descriptor),
            buffer as usize as i64,
            count as i64,
            offset,
        )
    };
    c_ssize_status(result)
}

/// Write at a fixed signed offset with musl's `O_APPEND` protection.
///
/// # Safety
///
/// If Linux examines the buffer, `buffer` must designate `count` readable
/// bytes for the syscall's duration. `offset` is the exact signed x86
/// `off_t` word. The caller owns descriptor lifetime and shared file state;
/// the owned runtime provides musl's cancellation points on both the primary
/// pwritev2 attempt and positioned fallback, with caller-owned cleanup.
#[no_mangle]
pub unsafe extern "C" fn pwrite(
    file_descriptor: c_int,
    buffer: *const c_void,
    count: usize,
    offset: c_long,
) -> isize {
    // Linux pwritev2 reserves -1 as its current-offset sentinel, whereas C
    // pwrite(-1) must be an invalid negative positioned offset. Musl changes
    // it to -2 before either kernel path; preserve that exact observable rule.
    let kernel_offset = if offset == -1 { -2 } else { offset };
    let iovec = IoVec {
        base: buffer,
        length: count,
    };
    // SAFETY: the caller supplies the complete raw Linux buffer contract.
    // The private iovec stays live for the pwritev2 syscall, and x86's split
    // offset/flags occupy r10/r8/r9 exactly as in musl's source wrapper.
    #[cfg(feature = "x86-owned-static-runtime")]
    let result = unsafe {
        super::pthread_cancel::syscall_cp(
            raw_syscall::SYS_PWRITEV2,
            i64::from(file_descriptor),
            core::ptr::addr_of!(iovec) as usize as i64,
            1,
            kernel_offset,
            kernel_offset >> 32,
            RWF_NOAPPEND,
        )
    };
    #[cfg(not(feature = "x86-owned-static-runtime"))]
    let result = unsafe {
        raw_syscall::syscall6(
            raw_syscall::SYS_PWRITEV2,
            i64::from(file_descriptor),
            core::ptr::addr_of!(iovec) as usize as i64,
            1,
            kernel_offset,
            kernel_offset >> 32,
            RWF_NOAPPEND,
        )
    };
    if result != -EOPNOTSUPP && result != -ENOSYS {
        return c_ssize_status(result);
    }

    // SAFETY: F_GETFL takes scalar descriptor/command words. This is a
    // private adaptation detail, not a use of the separately selected public
    // C fcntl status-control entry.
    let status_flags = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_FCNTL,
            i64::from(file_descriptor),
            F_GETFL,
        )
    };
    if status_flags < 0 {
        return c_ssize_status(status_flags);
    }
    if status_flags & O_APPEND != 0 {
        // SAFETY: the selected initial-TLS slot owns this documented musl
        // fallback result; no caller memory is touched on this branch.
        unsafe { errno::set_errno(EOPNOTSUPP as c_int) };
        return -1;
    }

    // SAFETY: the caller's positioned-write buffer contract still holds; the
    // fallback retains the original signed offset word in x86 r10.
    #[cfg(feature = "x86-owned-static-runtime")]
    let fallback = unsafe {
        super::pthread_cancel::syscall_cp(
            raw_syscall::SYS_PWRITE64,
            i64::from(file_descriptor),
            buffer as usize as i64,
            count as i64,
            kernel_offset,
            0,
            0,
        )
    };
    #[cfg(not(feature = "x86-owned-static-runtime"))]
    let fallback = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_PWRITE64,
            i64::from(file_descriptor),
            buffer as usize as i64,
            count as i64,
            kernel_offset,
        )
    };
    c_ssize_status(fallback)
}

/// Set or query a descriptor's signed x86 `off_t` through Linux `lseek(2)`.
///
/// The kernel validates `whence` and the descriptor. This leaf does not add a
/// filesystem-position policy or synchronize shared open-file descriptions.
#[no_mangle]
pub extern "C" fn lseek(file_descriptor: c_int, offset: c_long, whence: c_int) -> c_long {
    // SAFETY: all three arguments are scalar Linux words; x86's third syscall
    // word is rdx and the kernel validates descriptor/offset/whence semantics.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_LSEEK,
            i64::from(file_descriptor),
            offset,
            i64::from(whence),
        )
    };
    c_off_status(result)
}

/// Resize a descriptor through Linux `ftruncate(2)`.
///
/// `length` is passed as the exact signed x86 `off_t` word. Filesystem policy,
/// metadata ownership, and concurrent file-description synchronization remain
/// outside this narrow descriptor artifact.
#[no_mangle]
pub extern "C" fn ftruncate(file_descriptor: c_int, length: c_long) -> c_int {
    // SAFETY: both arguments are scalar Linux words; the kernel validates the
    // descriptor and signed length.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_FTRUNCATE,
            i64::from(file_descriptor),
            length,
        )
    };
    c_status(result)
}

/// Request Linux `fsync(2)` for a descriptor.
///
/// A successful return is only Linux/filesystem writeback acceptance. It does
/// not claim media-cache or power-loss durability. The owned runtime supplies
/// musl's cancellation point; legacy fixtures retain the direct syscall.
#[no_mangle]
pub extern "C" fn fsync(file_descriptor: c_int) -> c_int {
    // SAFETY: `file_descriptor` is a scalar Linux descriptor word.
    #[cfg(feature = "x86-owned-static-runtime")]
    let result = unsafe {
        super::pthread_cancel::syscall_cp(
            raw_syscall::SYS_FSYNC, i64::from(file_descriptor),
            0,
            0,
            0,
            0,
            0,
        )
    };
    #[cfg(not(feature = "x86-owned-static-runtime"))]
    let result = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_FSYNC, i64::from(file_descriptor))
    };
    c_status(result)
}

/// Request Linux `fdatasync(2)` for a descriptor.
///
/// A successful return is only Linux/filesystem writeback acceptance. It does
/// not claim media-cache or power-loss durability. The owned runtime supplies
/// musl's cancellation point; legacy fixtures retain the direct syscall.
#[no_mangle]
pub extern "C" fn fdatasync(file_descriptor: c_int) -> c_int {
    // SAFETY: `file_descriptor` is a scalar Linux descriptor word.
    #[cfg(feature = "x86-owned-static-runtime")]
    let result = unsafe {
        super::pthread_cancel::syscall_cp(
            raw_syscall::SYS_FDATASYNC, i64::from(file_descriptor),
            0,
            0,
            0,
            0,
            0,
        )
    };
    #[cfg(not(feature = "x86-owned-static-runtime"))]
    let result = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_FDATASYNC, i64::from(file_descriptor))
    };
    c_status(result)
}

/// Duplicate a descriptor through Linux `dup(2)`.
///
/// The kernel owns allocation of the new descriptor and the shared
/// open-file-description relationship. This leaf adds no descriptor registry
/// or concurrent lifetime policy.
#[no_mangle]
pub extern "C" fn dup(old_descriptor: c_int) -> c_int {
    // SAFETY: `old_descriptor` is a scalar Linux descriptor word.
    let result = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_DUP, i64::from(old_descriptor))
    };
    c_status(result)
}

/// Atomically duplicate `old_descriptor` onto `new_descriptor`.
///
/// Linux owns descriptor replacement. As in musl, a transient raw `EBUSY` is
/// retried; this artifact does not otherwise define concurrent close/dup
/// lifetime policy.
#[no_mangle]
pub extern "C" fn dup2(old_descriptor: c_int, new_descriptor: c_int) -> c_int {
    c_status(retry_dup2(old_descriptor, new_descriptor))
}

/// Atomically duplicate `old_descriptor` with Linux `dup3(2)` flags.
///
/// `old_descriptor == new_descriptor` is rejected locally with `EINVAL`, as
/// musl requires. For zero flags, musl uses the same `dup2` retry path; other
/// flags use `dup3` with the matching transient-`EBUSY` retry loop. This leaf
/// does not define a broader descriptor-lifetime policy.
#[no_mangle]
pub extern "C" fn dup3(
    old_descriptor: c_int,
    new_descriptor: c_int,
    flags: c_int,
) -> c_int {
    if old_descriptor == new_descriptor {
        return invalid_argument();
    }
    if flags == 0 {
        c_status(retry_dup2(old_descriptor, new_descriptor))
    } else {
        c_status(retry_dup3(old_descriptor, new_descriptor, flags))
    }
}

/// Create an unflagged pipe through Linux `pipe(2)`.
///
/// # Safety
///
/// `file_descriptors` must designate writable storage for two C `int` values
/// when Linux writes its result. The caller owns descriptor lifetime and pipe
/// endpoint synchronization; this leaf adds no stream or SIGPIPE policy.
#[no_mangle]
pub unsafe extern "C" fn pipe(file_descriptors: *mut c_int) -> c_int {
    // SAFETY: the caller supplies the raw two-int writable output region.
    let result = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_PIPE, file_descriptors as usize as i64)
    };
    c_status(result)
}

/// Create a pipe with Linux `pipe2(2)` flags.
///
/// # Safety
///
/// `file_descriptors` must designate writable storage for two C `int` values
/// when Linux writes its result. `flags` reaches Linux unchanged for kernel
/// validation. This leaf has no pre-5.10 fallback, descriptor registry, or
/// pipe endpoint synchronization policy.
#[no_mangle]
pub unsafe extern "C" fn pipe2(file_descriptors: *mut c_int, flags: c_int) -> c_int {
    if flags == 0 {
        // SAFETY: zero-flag musl behavior is exactly the selected `pipe`
        // output-pointer contract above.
        return unsafe { pipe(file_descriptors) };
    }
    // SAFETY: the caller supplies the raw two-int writable output region;
    // flags are scalar Linux words validated by the kernel.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_PIPE2,
            file_descriptors as usize as i64,
            i64::from(flags),
        )
    };
    c_status(result)
}
