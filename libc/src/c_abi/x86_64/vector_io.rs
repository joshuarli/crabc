//! Selected static Linux/x86-64 C vector-I/O boundary.
//!
//! This leaf owns only `readv`, `writev`, `preadv`, and `pwritev` over the
//! Linux two-word `iovec` ABI. It deliberately passes the caller's iovec
//! pointer and count directly to Linux: the kernel owns pointer accessibility,
//! aggregate-length, and iovec-count validation. It is not scalar descriptor
//! I/O, stdio, a general cancellation implementation, libc.so, CRT, loader,
//! sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/unistd/readv.c` and `src/unistd/writev.c` map to the corresponding
//!   direct wrappers below.
//! - `src/unistd/preadv.c` maps to [`preadv`] and its signed offset split into
//!   x86 Linux `pos_l`/`pos_h` syscall words.
//! - `src/unistd/pwritev.c` maps to [`pwritev`], including musl's `-1` to
//!   `-2` offset remap, `pwritev2(RWF_NOAPPEND)` first attempt, and
//!   `EOPNOTSUPP`/`ENOSYS` `F_GETFL`/`O_APPEND` boundary before a `pwritev`
//!   fallback.
//!
//! Musl routes all four operations through cancellation-point machinery. The
//! owned product routes `readv` and `writev` through its SIGCANCEL/PC-window
//! owner. Legacy fixtures and positioned vector I/O remain direct syscalls.

use core::ffi::{c_int, c_long, c_void};

use super::{c_ssize_status, errno, raw_syscall};

const ENOSYS: i64 = 38;
const EOPNOTSUPP: i64 = 95;
const F_GETFL: i64 = 3;
const O_APPEND: i64 = 0x400;
const RWF_NOAPPEND: i64 = 0x20;

/// Linux/x86-64's public two-word `struct iovec` representation.
///
/// The wrappers never inspect this record; keeping its exact ABI local merely
/// gives the raw syscall pointer a concrete Rust type.
#[repr(C)]
pub struct IoVec {
    base: *mut c_void,
    length: usize,
}

const _: [(); 16] = [(); core::mem::size_of::<IoVec>()];
const _: [(); 8] = [(); core::mem::align_of::<IoVec>()];

/// Read through a caller-owned vector list with Linux `readv(2)`.
///
/// # Safety
///
/// `iov` and every iovec Linux may examine must remain valid and writable for
/// the syscall duration. The caller owns descriptor lifetime, aggregate
/// buffer bounds, shared-offset synchronization, and all signal policy.
/// Owned-runtime selection includes musl's syscall cancellation point.
#[no_mangle]
pub unsafe extern "C" fn readv(file_descriptor: c_int, iov: *const IoVec, iovcnt: c_int) -> isize {
    // SAFETY: the caller owns the complete raw vector-I/O contract. Linux
    // validates the iovec count and each memory range without a libc-side
    // prevalidation pass.
    #[cfg(feature = "x86-owned-static-runtime")]
    let result = unsafe { super::pthread_cancel::syscall_cp(raw_syscall::SYS_READV,
        file_descriptor as i64, iov as i64, iovcnt as i64, 0, 0, 0) };
    #[cfg(not(feature = "x86-owned-static-runtime"))]
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_READV,
            i64::from(file_descriptor),
            iov as usize as i64,
            i64::from(iovcnt),
        )
    };
    c_ssize_status(result)
}

/// Write through a caller-owned vector list with Linux `writev(2)`.
///
/// # Safety
///
/// `iov` and every iovec Linux may examine must remain valid and readable for
/// the syscall duration. The caller owns descriptor lifetime, aggregate
/// buffer bounds, shared-offset synchronization, and SIGPIPE policy.
/// Owned-runtime selection includes musl's syscall cancellation point.
#[no_mangle]
pub unsafe extern "C" fn writev(file_descriptor: c_int, iov: *const IoVec, iovcnt: c_int) -> isize {
    // SAFETY: the caller owns the complete raw vector-I/O contract.
    #[cfg(feature = "x86-owned-static-runtime")]
    let result = unsafe { super::pthread_cancel::syscall_cp(raw_syscall::SYS_WRITEV,
        file_descriptor as i64, iov as i64, iovcnt as i64, 0, 0, 0) };
    #[cfg(not(feature = "x86-owned-static-runtime"))]
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_WRITEV,
            i64::from(file_descriptor),
            iov as usize as i64,
            i64::from(iovcnt),
        )
    };
    c_ssize_status(result)
}

/// Read a vector list at a fixed signed offset with Linux `preadv(2)`.
///
/// # Safety
///
/// `iov` and every iovec Linux may examine must remain valid and writable for
/// the syscall duration. `offset` is passed as the exact signed LP64 `off_t`;
/// the caller owns descriptor lifetime and concurrent file-state policy.
#[no_mangle]
pub unsafe extern "C" fn preadv(
    file_descriptor: c_int,
    iov: *const IoVec,
    iovcnt: c_int,
    offset: c_long,
) -> isize {
    // Linux/x86-64's legacy preadv ABI takes the signed 64-bit C offset as
    // two machine words in r10/r8, low word first. Arithmetic shift keeps the
    // signed high word for negative-offset kernel validation.
    let result = unsafe {
        raw_syscall::syscall5(
            raw_syscall::SYS_PREADV,
            i64::from(file_descriptor),
            iov as usize as i64,
            i64::from(iovcnt),
            offset,
            offset >> 32,
        )
    };
    c_ssize_status(result)
}

/// Write a vector list at a fixed signed offset with musl's append protection.
///
/// # Safety
///
/// `iov` and every iovec Linux may examine must remain valid and readable for
/// the syscall duration. The caller owns descriptor lifetime, vector storage,
/// and concurrent file-state policy. This direct static leaf intentionally
/// omits musl's pthread cancellation-point behavior.
#[no_mangle]
pub unsafe extern "C" fn pwritev(
    file_descriptor: c_int,
    iov: *const IoVec,
    iovcnt: c_int,
    offset: c_long,
) -> isize {
    // Linux pwritev2 reserves -1 as the current-offset sentinel. C pwritev
    // must instead reject it as an invalid positioned offset, so retain musl's
    // -1 -> -2 transformation before either kernel path.
    let kernel_offset = if offset == -1 { -2 } else { offset };
    // SAFETY: the caller owns the vector-I/O lifetime/accessibility contract;
    // r10/r8 split the offset and r9 carries RWF_NOAPPEND exactly as Linux
    // x86-64 requires.
    let result = unsafe {
        raw_syscall::syscall6(
            raw_syscall::SYS_PWRITEV2,
            i64::from(file_descriptor),
            iov as usize as i64,
            i64::from(iovcnt),
            kernel_offset,
            kernel_offset >> 32,
            RWF_NOAPPEND,
        )
    };
    if result != -EOPNOTSUPP && result != -ENOSYS {
        return c_ssize_status(result);
    }

    // SAFETY: F_GETFL accepts only scalar descriptor/command words. This is
    // private implementation detail needed by musl's positioned-write rule;
    // it does not select a general public C fcntl boundary.
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
        // SAFETY: this selected static C ABI owns the initial-TLS errno slot.
        unsafe { errno::set_errno(EOPNOTSUPP as c_int) };
        return -1;
    }

    // SAFETY: the caller's vector-I/O contract remains live for the fallback;
    // split offset words match Linux x86-64's preadv/pwritev ABI.
    let fallback = unsafe {
        raw_syscall::syscall5(
            raw_syscall::SYS_PWRITEV,
            i64::from(file_descriptor),
            iov as usize as i64,
            i64::from(iovcnt),
            kernel_offset,
            kernel_offset >> 32,
        )
    };
    c_ssize_status(fallback)
}
