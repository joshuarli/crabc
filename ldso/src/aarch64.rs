//! Linux/AArch64 syscall instruction and number boundary for `ldso`.

/// Linux/AArch64 `read`.
pub(crate) const SYS_READ: i64 = 63;
/// Linux/AArch64 `write`.
pub(crate) const SYS_WRITE: i64 = 64;
/// Linux/AArch64 `openat`.
pub(crate) const SYS_OPENAT: i64 = 56;
/// Linux/AArch64 `close`.
pub(crate) const SYS_CLOSE: i64 = 57;
/// Linux/AArch64 `fstat`.
pub(crate) const SYS_FSTAT: i64 = 80;
/// Linux/AArch64 `lseek`.
pub(crate) const SYS_LSEEK: i64 = 62;
/// Linux/AArch64 `mmap`.
pub(crate) const SYS_MMAP: i64 = 222;
/// Linux/AArch64 `mprotect`.
pub(crate) const SYS_MPROTECT: i64 = 226;
/// Linux/AArch64 `munmap`.
pub(crate) const SYS_MUNMAP: i64 = 215;
/// Linux/AArch64 `readlinkat`.
pub(crate) const SYS_READLINKAT: i64 = 78;
/// Linux/AArch64 `gettid`.
pub(crate) const SYS_GETTID: i64 = 178;
/// Linux/AArch64 `exit`.
pub(crate) const SYS_EXIT: i64 = 93;

#[inline(always)]
pub(crate) unsafe fn syscall1(n: i64, a1: i64) -> i64 {
    let result: i64;
    // SAFETY: The caller supplies the Linux syscall number and argument ABI.
    unsafe {
        core::arch::asm!(
            "svc #0",
            inlateout("x8") n => _,
            inlateout("x0") a1 => result,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
pub(crate) unsafe fn syscall2(n: i64, a1: i64, a2: i64) -> i64 {
    let result: i64;
    // SAFETY: The caller supplies the Linux syscall number and argument ABI.
    unsafe {
        core::arch::asm!(
            "svc #0",
            inlateout("x8") n => _,
            inlateout("x0") a1 => result,
            inlateout("x1") a2 => _,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
pub(crate) unsafe fn syscall3(n: i64, a1: i64, a2: i64, a3: i64) -> i64 {
    let result: i64;
    // SAFETY: The caller supplies the Linux syscall number and argument ABI.
    unsafe {
        core::arch::asm!(
            "svc #0",
            inlateout("x8") n => _,
            inlateout("x0") a1 => result,
            inlateout("x1") a2 => _,
            inlateout("x2") a3 => _,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
pub(crate) unsafe fn syscall4(n: i64, a1: i64, a2: i64, a3: i64, a4: i64) -> i64 {
    let result: i64;
    // SAFETY: The caller supplies the Linux syscall number and argument ABI.
    unsafe {
        core::arch::asm!(
            "svc #0",
            inlateout("x8") n => _,
            inlateout("x0") a1 => result,
            inlateout("x1") a2 => _,
            inlateout("x2") a3 => _,
            inlateout("x3") a4 => _,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
pub(crate) unsafe fn syscall5(
    n: i64,
    a1: i64,
    a2: i64,
    a3: i64,
    a4: i64,
    a5: i64,
) -> i64 {
    let result: i64;
    // SAFETY: The caller supplies the Linux syscall number and argument ABI.
    unsafe {
        core::arch::asm!(
            "svc #0",
            inlateout("x8") n => _,
            inlateout("x0") a1 => result,
            inlateout("x1") a2 => _,
            inlateout("x2") a3 => _,
            inlateout("x3") a4 => _,
            inlateout("x4") a5 => _,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
pub(crate) unsafe fn syscall6(
    n: i64,
    a1: i64,
    a2: i64,
    a3: i64,
    a4: i64,
    a5: i64,
    a6: i64,
) -> i64 {
    let result: i64;
    // SAFETY: The caller supplies the Linux syscall number and argument ABI.
    unsafe {
        core::arch::asm!(
            "svc #0",
            inlateout("x8") n => _,
            inlateout("x0") a1 => result,
            inlateout("x1") a2 => _,
            inlateout("x2") a3 => _,
            inlateout("x3") a4 => _,
            inlateout("x4") a5 => _,
            inlateout("x5") a6 => _,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
pub(crate) unsafe fn syscall_noreturn1(n: i64, a1: i64) -> ! {
    // SAFETY: The caller supplies a non-returning Linux syscall contract.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") n,
            in("x0") a1,
            options(noreturn, nostack),
        );
    }
}
