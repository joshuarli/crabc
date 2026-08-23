//! Stateless Linux/AArch64 event operations.

use crate::{Errno, RawFd, Result};
use crate::syscall::{decode, decode_i32, syscall1, syscall2, syscall3, syscall4, syscall5, syscall6, SYS_EPOLL_CREATE1, SYS_EPOLL_CTL, SYS_EPOLL_PWAIT, SYS_EVENTFD2, SYS_PPOLL, SYS_PSELECT6, SYS_READ, SYS_WRITE};

/// Creates a Linux event descriptor without using libc or TLS `errno`.
#[inline]
pub fn eventfd(initval: u32, flags: u32) -> Result<RawFd> {
    // SAFETY: Linux validates the initial value and flags.
    decode(unsafe { syscall2(SYS_EVENTFD2, initval as usize, flags as usize) })
        .map(|fd| fd as RawFd)
}

/// Reads one complete Linux eventfd counter record without using libc or
/// TLS `errno`.
///
/// Linux eventfd records are exactly one little-endian `u64`. The value is
/// kept in a stack slot owned by this operation, so callers receive the
/// typed counter value rather than a raw byte buffer. A successful
/// eventfd read always consumes and returns the complete eight-byte
/// record; a different successful count is rejected as an I/O contract
/// violation.
#[inline]
pub fn eventfd_read(fd: RawFd) -> Result<u64> {
    let mut value = 0_u64;
    // SAFETY: `value` is aligned writable storage for exactly one eventfd
    // record and remains live for the direct syscall.
    let count = decode(unsafe {
        syscall3(
            SYS_READ,
            fd as usize,
            (&mut value as *mut u64).cast::<u8>() as usize,
            core::mem::size_of::<u64>(),
        )
    })?;
    if count != core::mem::size_of::<u64>() {
        return Err(Errno::IO);
    }
    Ok(value)
}

/// Writes one complete Linux eventfd counter record without using libc or
/// TLS `errno`.
///
/// `value` is the eventfd increment. Linux rejects `u64::MAX` and reports
/// counter overflow according to the descriptor's blocking mode. The
/// helper always submits exactly one eight-byte little-endian record and
/// reports any other successful count as an I/O contract violation.
#[inline]
pub fn eventfd_write(fd: RawFd, value: u64) -> Result<()> {
    // SAFETY: `value` is aligned readable storage for exactly one eventfd
    // record and remains live for the direct syscall.
    let count = decode(unsafe {
        syscall3(
            SYS_WRITE,
            fd as usize,
            (&value as *const u64).cast::<u8>() as usize,
            core::mem::size_of::<u64>(),
        )
    })?;
    if count != core::mem::size_of::<u64>() {
        return Err(Errno::IO);
    }
    Ok(())
}

/// Creates a Linux epoll descriptor without using libc or TLS `errno`.
#[inline]
pub fn epoll_create1(flags: u32) -> Result<RawFd> {
    // SAFETY: Linux validates the epoll flags; no user memory is accessed
    // by this operation.
    decode(unsafe { syscall1(SYS_EPOLL_CREATE1, flags as usize) }).map(|fd| fd as RawFd)
}

/// Adds, modifies, or removes a descriptor from an epoll interest list.
///
/// # Safety
///
/// For `EPOLL_CTL_ADD` and `EPOLL_CTL_MOD`, `event` must point to one
/// readable Linux/AArch64 `struct epoll_event`; for `EPOLL_CTL_DEL`, it
/// may be null as required by Linux. The descriptor arguments are passed
/// directly to the kernel for validation.
#[inline]
pub unsafe fn epoll_ctl_raw(
    epoll_fd: RawFd,
    operation: u32,
    source_fd: RawFd,
    event: *const u8,
) -> Result<()> {
    // SAFETY: The caller owns the optional event pointer contract; Linux
    // validates the operation and both descriptors.
    decode(unsafe {
        syscall4(
            SYS_EPOLL_CTL,
            epoll_fd as usize,
            operation as usize,
            source_fd as usize,
            event as usize,
        )
    })
    .map(|_| ())
}

/// Waits for epoll readiness with an optional Linux signal mask.
///
/// The timeout is the `epoll_pwait` millisecond representation: `-1`
/// waits indefinitely and zero performs a non-blocking query. This is the
/// shared seam used by both the direct Rust facade and the C errno facade.
///
/// # Safety
///
/// `events` must point to writable storage for `maxevents` Linux/AArch64
/// `struct epoll_event` records. `sigmask` must be null or point to a
/// kernel-sized Linux signal mask of `sigsetsize` bytes.
#[inline]
pub unsafe fn epoll_pwait_raw(
    epoll_fd: RawFd,
    events: *mut u8,
    maxevents: usize,
    timeout: i32,
    sigmask: *const u8,
    sigsetsize: usize,
) -> Result<usize> {
    // SAFETY: The caller owns all pointed-to Linux ABI layouts. Linux
    // validates the descriptor, count, timeout, and signal-mask values.
    decode(unsafe {
        syscall6(
            SYS_EPOLL_PWAIT,
            epoll_fd as usize,
            events as usize,
            maxevents,
            timeout as usize,
            sigmask as usize,
            sigsetsize,
        )
    })
}

/// Waits for epoll readiness without changing a signal mask.
///
/// # Safety
///
/// The `events` pointer must be writable for `maxevents` epoll records.
#[inline]
pub unsafe fn epoll_wait_raw(
    epoll_fd: RawFd,
    events: *mut u8,
    maxevents: usize,
    timeout: i32,
) -> Result<usize> {
    // A null mask leaves the calling thread's signal mask unchanged. The
    // kernel's AArch64 sigset size is eight bytes even for this null mask.
    unsafe {
        epoll_pwait_raw(
            epoll_fd,
            events,
            maxevents,
            timeout,
            core::ptr::null(),
            core::mem::size_of::<usize>(),
        )
    }
}

/// Waits for descriptor readiness through Linux/AArch64 `pselect6`.
///
/// Linux mutates the supplied timeout and the descriptor sets in place;
/// the typed facade owns copies where its public contract requires
/// immutability. The final syscall argument is Linux's private pair of a
/// signal-mask pointer and its byte size, not the public 128-byte musl
/// `sigset_t` size.
///
/// # Safety
///
/// The descriptor-set pointers must be null or point to writable storage
/// for the kernel's bit-vector representation. `timeout` must be null or
/// point to writable Linux/AArch64 `timespec` storage. `sigmask` must be
/// null or point to a kernel-sized signal mask of `sigsetsize` bytes.
#[inline]
pub unsafe fn pselect6_raw(
    nfds: i32,
    readfds: *mut u8,
    writefds: *mut u8,
    exceptfds: *mut u8,
    timeout: *mut u8,
    sigmask: *const u8,
    sigsetsize: usize,
) -> Result<i32> {
    #[repr(C)]
    struct KernelSigmask {
        mask: *const u8,
        size: usize,
    }

    let signal_argument = KernelSigmask {
        mask: sigmask,
        size: sigsetsize,
    };
    // SAFETY: The caller owns the pointed-to descriptor sets, timeout,
    // and optional kernel signal mask. The stack pair is the exact
    // AArch64 pselect6 argument-6 layout and remains live for the call.
    decode_i32(unsafe {
        syscall6(
            SYS_PSELECT6,
            nfds as usize,
            readfds as usize,
            writefds as usize,
            exceptfds as usize,
            timeout as usize,
            (&signal_argument as *const KernelSigmask) as usize,
        )
    })
}

/// Waits for events using the Linux `ppoll` ABI without libc or TLS
/// `errno`.
///
/// # Safety
///
/// `fds` must point to `nfds` writable Linux `struct pollfd` records (or
/// be deliberately forwarded as an invalid C ABI pointer). When non-null,
/// `timeout` must point to one Linux/AArch64 `timespec`. `sigmask` and
/// `sigsetsize` must form a valid Linux kernel signal-mask argument.
#[inline]
pub unsafe fn ppoll_raw(
    fds: *mut u8,
    nfds: usize,
    timeout: *const u8,
    sigmask: *const u8,
    sigsetsize: usize,
) -> Result<usize> {
    // SAFETY: The caller owns all pointed-to Linux ABI layouts. Linux
    // validates their values and returns the ready descriptor count.
    decode(unsafe {
        syscall5(
            SYS_PPOLL,
            fds as usize,
            nfds,
            timeout as usize,
            sigmask as usize,
            sigsetsize,
        )
    })
}
