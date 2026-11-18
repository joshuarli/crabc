//! Concrete Linux/x86-64 syscall instruction and number boundary for libc.
//!
//! C ABI adaptation, errno publication, and process-global policy remain in
//! the surrounding libc modules. This file owns only the raw Linux/x86-64
//! register ABI and the matching syscall-number table. The selected static
//! metadata leaf uses `fstat` and `newfstatat`; the credential leaf uses its
//! selected identity syscalls; the selected process-context leaf uses its
//! scalar identity, group/session, and mask syscalls; the selected
//! descriptor-entry leaf uses `open`, `openat`, and its private post-open
//! `fcntl` request; the selected descriptor-I/O leaf uses its named transfer,
//! lifecycle, and pipe syscalls; the selected vector-I/O leaf uses readv,
//! writev, and positioned split-offset vector transfer syscalls;
//! the selected one-entry FIFO leaf uses `mknodat` with fixed current-directory
//! and zero-device arguments; and the owned filesystem-mechanism block uses
//! its source-selected metadata, ownership, special-node, namespace,
//! allocation, lock, and vectored-I/O requests;
//! the selected filesystem-access leaf uses direct `access`, legacy
//! `faccessat`, and flags-bearing `faccessat2` requests; and the selected
//! extended-attribute leaf uses the complete path, no-follow-path, and
//! descriptor xattr syscall family;
//! the selected readiness/signal-waits leaf uses its named Linux wait syscalls;
//! the selected socket-transport leaf uses its direct Linux socket lifecycle
//! and byte-transfer syscalls; the selected socket-message/options leaf uses
//! its direct socket-option, padded-message, batched-receive, and SIOCATMARK
//! syscall forms; and the selected nanosleep leaf uses its direct
//! two-pointer relative sleep syscall. The separately selected bounded
//! system-information leaf uses `sysinfo` and the fixed-size
//! `sched_getaffinity` CPU mask here; its public processor helper deliberately
//! ignores a raw affinity failure in the musl-defined CPU-0 fallback case.
//! The separately selected bounded `flock` leaf uses direct `flock=73`, the
//! regular-file transfer leaf uses direct `sendfile=40`, the GNU descriptor-
//! range copy leaf uses direct `copy_file_range=326`, the GNU descriptor-to-
//! pipe transfer leaf uses direct `splice=275`, the GNU pipe-buffer duplication
//! leaf uses direct `tee=276`; and the GNU descriptor-range writeback leaf uses
//! direct `sync_file_range=277`.
//! The separately selected bounded
//! pthread create/explicit-exit/join leaf, private normal-mutex sibling, and
//! private condition-variable handoff use mmap, munmap, futex, gettid
//! identity validation, the selected raw thread exit, the direct C11
//! `thrd_yield` sched_yield=24 boundary, the separate status-returning POSIX
//! `sched_yield` boundary, the paired read-only scheduler-priority bounds
//! calls, and GNU current-CPU observation use this module. The separately
//! selected
//! bootstrapped-main pthread task-name pair uses direct prctl=157 here;
//! it does not expose a general prctl C API. Static Initial
//! TLS v1 additionally uses arch_prctl(ARCH_SET_FS) while it validates and
//! installs one final-executable TLS image before C TLS exists; its distinct
//! private musl-shaped assembly boundary owns clone and normal-return child
//! exit so this generic register module does not become a public clone API.
//! The separately selected per-range memory-locking, direct Linux 5.10
//! membarrier branch, no-cancellation mapping synchronization, and
//! anonymous-memory-descriptor leaves use their named direct syscalls here.
//! All other public C wrappers remain unintegrated until their own ABI
//! boundaries are tested.
//! The separately selected one-symbol POSIX message-queue attribute leaf uses
//! `mq_getsetattr=245` here; it does not select queue lifecycle, transfer, or
//! notification behavior.
//!
//! Linux/x86-64 enters the kernel with `syscall`: `rax` holds the syscall
//! number and result, then arguments one through six are `rdi`, `rsi`, `rdx`,
//! `r10`, `r8`, and `r9`. In particular, arguments four through six are not
//! in the normal System V C ABI's `rcx`, `r8`, and `r9` sequence. Hardware
//! overwrites `rcx` and `r11`; each returning wrapper declares both clobbers
//! and intentionally does not claim `nomem`, because pointer-bearing Linux
//! calls can read or write arbitrary caller-visible memory.

use core::arch::asm;

/// Issue a zero-argument raw Linux/x86-64 syscall.
///
/// # Safety
///
/// `n` must name a Linux/x86-64 syscall whose arguments are empty. This does
/// not decode Linux's `-4095..=-1` errno result range or establish any C ABI
/// policy.
#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn syscall0(n: i64) -> i64 {
    let result: i64;
    // SAFETY: The caller upholds the raw Linux syscall contract documented
    // above. `syscall` clobbers `rcx` and `r11`.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") n => result,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

/// Issue a one-argument raw Linux/x86-64 syscall.
///
/// # Safety
///
/// `n` and `a1` must satisfy the named kernel syscall's complete contract,
/// including validity, lifetime, and accessibility of every pointer encoded
/// in `a1`. The raw signed result is returned unchanged.
#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn syscall1(n: i64, a1: i64) -> i64 {
    let result: i64;
    // SAFETY: `rdi` is Linux/x86-64 syscall argument one; the caller owns all
    // kernel-facing argument validity.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") n => result,
            in("rdi") a1,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

/// Issue a two-argument raw Linux/x86-64 syscall.
///
/// # Safety
///
/// `n`, `a1`, and `a2` must satisfy the named kernel syscall's complete raw
/// contract. The wrapper neither validates arguments nor translates errno.
#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn syscall2(n: i64, a1: i64, a2: i64) -> i64 {
    let result: i64;
    // SAFETY: Linux/x86-64 syscall arguments one/two occupy `rdi`/`rsi`.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") n => result,
            in("rdi") a1,
            in("rsi") a2,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

/// Issue a three-argument raw Linux/x86-64 syscall.
///
/// # Safety
///
/// `n` and all arguments must satisfy the named kernel syscall's complete
/// raw contract. The wrapper neither validates arguments nor translates errno.
#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn syscall3(n: i64, a1: i64, a2: i64, a3: i64) -> i64 {
    let result: i64;
    // SAFETY: Linux/x86-64 syscall arguments one through three occupy
    // `rdi`/`rsi`/`rdx`.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") n => result,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

/// Issue a four-argument raw Linux/x86-64 syscall.
///
/// # Safety
///
/// `n` and all arguments must satisfy the named kernel syscall's complete
/// raw contract. In particular, `a4` is passed in `r10`, not the normal C ABI
/// fourth-argument register `rcx`.
#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn syscall4(n: i64, a1: i64, a2: i64, a3: i64, a4: i64) -> i64 {
    let result: i64;
    // SAFETY: Linux/x86-64 moves syscall argument four from the C ABI's `rcx`
    // position to `r10` before entering the kernel.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") n => result,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

/// Issue a five-argument raw Linux/x86-64 syscall.
///
/// # Safety
///
/// `n` and all arguments must satisfy the named kernel syscall's complete
/// raw contract. Arguments four/five must be the exact `r10`/`r8` machine
/// words expected by that syscall.
#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn syscall5(
    n: i64,
    a1: i64,
    a2: i64,
    a3: i64,
    a4: i64,
    a5: i64,
) -> i64 {
    let result: i64;
    // SAFETY: Linux/x86-64 syscall arguments four/five occupy `r10`/`r8`.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") n => result,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

/// Issue a six-argument raw Linux/x86-64 syscall.
///
/// # Safety
///
/// `n` and all arguments must satisfy the named kernel syscall's complete
/// raw contract. Arguments four through six must be the exact `r10`/`r8`/`r9`
/// machine words expected by that syscall.
#[inline(always)]
#[cfg(target_arch = "x86_64")]
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
    // SAFETY: Linux/x86-64 syscall argument six occupies `r9`.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") n => result,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            in("r9") a6,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

/// Issue a one-argument raw Linux/x86-64 syscall that cannot return.
///
/// # Safety
///
/// `n` and `a1` must satisfy the named kernel syscall's raw contract, and the
/// syscall must not return on any reachable kernel path (for example,
/// `SYS_EXIT` or `SYS_EXIT_GROUP`). A returning syscall would violate this
/// function's `!` contract.
#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn syscall_noreturn1(n: i64, a1: i64) -> ! {
    // SAFETY: The caller guarantees a non-returning raw Linux syscall.
    unsafe {
        asm!(
            "syscall",
            in("rax") n,
            in("rdi") a1,
            options(noreturn, nostack),
        );
    }
}

// Linux AArch64 entry follows musl 1.2.6 arch/aarch64/syscall_arch.h.
#[inline(always)]
#[cfg(target_arch = "aarch64")]
pub(crate) unsafe fn syscall0(n: i64) -> i64 {
    let result: i64;
    // SAFETY: the caller guarantees the raw syscall and its arguments are valid.
    unsafe { core::arch::asm!(
        "svc #0",
        inlateout("x8") n => _,
        lateout("x0") result,
        options(nostack),
    ); }
    result
}
#[inline(always)]
#[cfg(target_arch = "aarch64")]
pub(crate) unsafe fn syscall1(n: i64, a1: i64) -> i64 {
    let result: i64;
    // SAFETY: the caller guarantees the raw syscall and its arguments are valid.
    unsafe { core::arch::asm!(
        "svc #0",
        inlateout("x8") n => _,
        inlateout("x0") a1 => result,
        options(nostack),
    ); }
    result
}
#[inline(always)]
#[cfg(target_arch = "aarch64")]
pub(crate) unsafe fn syscall2(n: i64, a1: i64, a2: i64) -> i64 {
    let result: i64;
    // SAFETY: the caller guarantees the raw syscall and its arguments are valid.
    unsafe { core::arch::asm!(
        "svc #0",
        inlateout("x8") n => _,
        inlateout("x0") a1 => result,
        inlateout("x1") a2 => _,
        options(nostack),
    ); }
    result
}
#[inline(always)]
#[cfg(target_arch = "aarch64")]
pub(crate) unsafe fn syscall3(n: i64, a1: i64, a2: i64, a3: i64) -> i64 {
    let result: i64;
    // SAFETY: the caller guarantees the raw syscall and its arguments are valid.
    unsafe { core::arch::asm!(
        "svc #0",
        inlateout("x8") n => _,
        inlateout("x0") a1 => result,
        inlateout("x1") a2 => _,
        inlateout("x2") a3 => _,
        options(nostack),
    ); }
    result
}
#[inline(always)]
#[cfg(target_arch = "aarch64")]
pub(crate) unsafe fn syscall4(n: i64, a1: i64, a2: i64, a3: i64, a4: i64) -> i64 {
    let result: i64;
    // SAFETY: the caller guarantees the raw syscall and its arguments are valid.
    unsafe { core::arch::asm!(
        "svc #0",
        inlateout("x8") n => _,
        inlateout("x0") a1 => result,
        inlateout("x1") a2 => _,
        inlateout("x2") a3 => _,
        inlateout("x3") a4 => _,
        options(nostack),
    ); }
    result
}
#[inline(always)]
#[cfg(target_arch = "aarch64")]
pub(crate) unsafe fn syscall5(n: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64) -> i64 {
    let result: i64;
    // SAFETY: the caller guarantees the raw syscall and its arguments are valid.
    unsafe { core::arch::asm!(
        "svc #0",
        inlateout("x8") n => _,
        inlateout("x0") a1 => result,
        inlateout("x1") a2 => _,
        inlateout("x2") a3 => _,
        inlateout("x3") a4 => _,
        inlateout("x4") a5 => _,
        options(nostack),
    ); }
    result
}
#[inline(always)]
#[cfg(target_arch = "aarch64")]
pub(crate) unsafe fn syscall6(n: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64, a6: i64) -> i64 {
    let result: i64;
    // SAFETY: the caller guarantees the raw syscall and its arguments are valid.
    unsafe { core::arch::asm!(
        "svc #0",
        inlateout("x8") n => _,
        inlateout("x0") a1 => result,
        inlateout("x1") a2 => _,
        inlateout("x2") a3 => _,
        inlateout("x3") a4 => _,
        inlateout("x4") a5 => _,
        inlateout("x5") a6 => _,
        options(nostack),
    ); }
    result
}
#[inline(always)]
#[cfg(target_arch = "aarch64")]
pub(crate) unsafe fn syscall_noreturn1(n: i64, a1: i64) -> ! {
    // SAFETY: the caller guarantees the raw syscall and its arguments are valid.
    unsafe { core::arch::asm!(
        "svc #0",
        in("x8") n,
        in("x0") a1,
        options(noreturn, nostack),
    ); }
}

// Linux numbers: musl 1.2.6 arch/aarch64/bits/syscall.h.in and x86-64 UAPI.
// Linux 5.10 x86-64 UAPI syscall numbers. These intentionally retain the
// `i64` names and types the surrounding C ABI source consumes; this file is
// its target-specific single source of truth when x86-64 composition is added.
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_READ: i64 = 0;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_READ: i64 = 63;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_WRITE: i64 = 1;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_WRITE: i64 = 64;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_OPEN: i64 = 2;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_CLOSE: i64 = 3;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_CLOSE: i64 = 57;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_FSTAT: i64 = 5;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_FSTAT: i64 = 80;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_POLL: i64 = 7;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_LSEEK: i64 = 8;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_LSEEK: i64 = 62;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MMAP: i64 = 9;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MMAP: i64 = 222;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MPROTECT: i64 = 10;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MPROTECT: i64 = 226;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MUNMAP: i64 = 11;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MUNMAP: i64 = 215;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_BRK: i64 = 12;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_BRK: i64 = 214;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MSYNC: i64 = 26;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MSYNC: i64 = 227;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_RT_SIGACTION: i64 = 13;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_RT_SIGACTION: i64 = 134;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_RT_SIGPROCMASK: i64 = 14;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_RT_SIGPROCMASK: i64 = 135;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_IOCTL: i64 = 16;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_IOCTL: i64 = 29;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_ACCESS: i64 = 21;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_PIPE: i64 = 22;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SELECT: i64 = 23;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SCHED_YIELD: i64 = 24;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SCHED_YIELD: i64 = 124;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MREMAP: i64 = 25;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MREMAP: i64 = 216;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MINCORE: i64 = 27;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MINCORE: i64 = 232;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MADVISE: i64 = 28;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MADVISE: i64 = 233;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SHMGET: i64 = 29;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SHMGET: i64 = 194;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SHMAT: i64 = 30;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SHMAT: i64 = 196;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SHMCTL: i64 = 31;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SHMCTL: i64 = 195;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_DUP: i64 = 32;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_DUP: i64 = 23;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_DUP2: i64 = 33;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_PAUSE: i64 = 34;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_NANOSLEEP: i64 = 35;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_NANOSLEEP: i64 = 101;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_GETITIMER: i64 = 36;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_GETITIMER: i64 = 102;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SETITIMER: i64 = 38;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SETITIMER: i64 = 103;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_TIMES: i64 = 100;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_TIMES: i64 = 153;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SOCKET: i64 = 41;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SOCKET: i64 = 198;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_CONNECT: i64 = 42;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_CONNECT: i64 = 203;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_ACCEPT: i64 = 43;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_ACCEPT: i64 = 202;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SENDTO: i64 = 44;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SENDTO: i64 = 206;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_RECVFROM: i64 = 45;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_RECVFROM: i64 = 207;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SENDMSG: i64 = 46;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SENDMSG: i64 = 211;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_RECVMSG: i64 = 47;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_RECVMSG: i64 = 212;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SHUTDOWN: i64 = 48;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SHUTDOWN: i64 = 210;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_BIND: i64 = 49;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_BIND: i64 = 200;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_LISTEN: i64 = 50;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_LISTEN: i64 = 201;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_GETSOCKNAME: i64 = 51;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_GETSOCKNAME: i64 = 204;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_GETPEERNAME: i64 = 52;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_GETPEERNAME: i64 = 205;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SOCKETPAIR: i64 = 53;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SOCKETPAIR: i64 = 199;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SETSOCKOPT: i64 = 54;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SETSOCKOPT: i64 = 208;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_GETSOCKOPT: i64 = 55;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_GETSOCKOPT: i64 = 209;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_EXECVE: i64 = 59;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_EXECVE: i64 = 221;
/// Linux 5.10 x86-64 `execveat` is the direct `fexecve` kernel boundary.
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_EXECVEAT: i64 = 322;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_EXECVEAT: i64 = 281;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_WAIT4: i64 = 61;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_WAIT4: i64 = 260;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_KILL: i64 = 62;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_KILL: i64 = 129;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_UNAME: i64 = 63;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_UNAME: i64 = 160;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SEMGET: i64 = 64;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SEMGET: i64 = 190;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SEMOP: i64 = 65;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SEMOP: i64 = 193;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SEMCTL: i64 = 66;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SEMCTL: i64 = 191;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SEMTIMEDOP: i64 = 220;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SEMTIMEDOP: i64 = 192;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SHMDT: i64 = 67;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SHMDT: i64 = 197;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MSGGET: i64 = 68;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MSGGET: i64 = 186;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MSGSND: i64 = 69;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MSGSND: i64 = 189;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MSGRCV: i64 = 70;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MSGRCV: i64 = 188;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MSGCTL: i64 = 71;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MSGCTL: i64 = 187;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_FCNTL: i64 = 72;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_FCNTL: i64 = 25;
/// Linux x86-64 `sendfile` uses `rdi/rsi/rdx/r10` for its four arguments.
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SENDFILE: i64 = 40;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SENDFILE: i64 = 71;
/// Linux x86-64 `fallocate` uses `rdi/rsi/rdx/r10` for its four arguments.
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_FALLOCATE: i64 = 285;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_FALLOCATE: i64 = 47;
/// Linux x86-64 `fadvise64` uses `rdi/rsi/rdx/r10` for its four arguments.
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_FADVISE64: i64 = 221;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_FADVISE64: i64 = 223;
/// Linux x86-64 `splice` uses `rdi/rsi/rdx/r10/r8/r9` for six words.
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SPLICE: i64 = 275;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SPLICE: i64 = 76;
/// Linux x86-64 `tee` uses `rdi/rsi/rdx/r10` for its four arguments.
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_TEE: i64 = 276;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_TEE: i64 = 77;
/// Linux x86-64 `copy_file_range` uses `rdi/rsi/rdx/r10/r8/r9` for six words.
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_COPY_FILE_RANGE: i64 = 326;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_COPY_FILE_RANGE: i64 = 285;
/// Linux x86-64 `readahead` uses `rdi/rsi/rdx` for its three arguments.
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_READAHEAD: i64 = 187;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_READAHEAD: i64 = 213;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_FSYNC: i64 = 74;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_FSYNC: i64 = 82;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_TRUNCATE: i64 = 76;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_TRUNCATE: i64 = 45;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_FTRUNCATE: i64 = 77;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_FTRUNCATE: i64 = 46;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_GETCWD: i64 = 79;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_GETCWD: i64 = 17;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_CHDIR: i64 = 80;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_CHDIR: i64 = 49;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_RENAME: i64 = 82;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MKDIR: i64 = 83;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_RMDIR: i64 = 84;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_LINK: i64 = 86;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_UNLINK: i64 = 87;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SYMLINK: i64 = 88;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_READLINK: i64 = 89;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_CHMOD: i64 = 90;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_FCHMOD: i64 = 91;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_FCHMOD: i64 = 52;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_CHOWN: i64 = 92;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_FCHOWN: i64 = 93;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_FCHOWN: i64 = 55;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_LCHOWN: i64 = 94;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_UMASK: i64 = 95;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_UMASK: i64 = 166;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_GETTIMEOFDAY: i64 = 96;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_GETTIMEOFDAY: i64 = 169;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_GETRLIMIT: i64 = 97;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_GETRLIMIT: i64 = 163;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_GETRUSAGE: i64 = 98;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_GETRUSAGE: i64 = 165;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SYSINFO: i64 = 99;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SYSINFO: i64 = 179;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SETUID: i64 = 105;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SETUID: i64 = 146;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SETGID: i64 = 106;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SETGID: i64 = 144;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SETPGID: i64 = 109;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SETPGID: i64 = 154;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_GETGROUPS: i64 = 115;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_GETGROUPS: i64 = 158;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SETGROUPS: i64 = 116;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SETGROUPS: i64 = 159;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SETRESUID: i64 = 117;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SETRESUID: i64 = 147;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_GETRESUID: i64 = 118;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_GETRESUID: i64 = 148;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SETRESGID: i64 = 119;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SETRESGID: i64 = 149;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_GETRESGID: i64 = 120;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_GETRESGID: i64 = 150;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_GETPGID: i64 = 121;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_GETPGID: i64 = 155;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SETFSUID: i64 = 122;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SETFSUID: i64 = 151;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SETFSGID: i64 = 123;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SETFSGID: i64 = 152;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_GETSID: i64 = 124;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_GETSID: i64 = 156;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_RT_SIGPENDING: i64 = 127;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_RT_SIGPENDING: i64 = 136;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_RT_SIGTIMEDWAIT: i64 = 128;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_RT_SIGTIMEDWAIT: i64 = 137;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_RT_SIGQUEUEINFO: i64 = 129;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_RT_SIGQUEUEINFO: i64 = 138;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_RT_SIGSUSPEND: i64 = 130;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_RT_SIGSUSPEND: i64 = 133;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SIGALTSTACK: i64 = 131;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SIGALTSTACK: i64 = 132;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MKNOD: i64 = 133;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_PERSONALITY: i64 = 135;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_PERSONALITY: i64 = 92;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_GETPRIORITY: i64 = 140;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_GETPRIORITY: i64 = 141;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SETPRIORITY: i64 = 141;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SETPRIORITY: i64 = 140;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SCHED_GET_PRIORITY_MAX: i64 = 146;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SCHED_GET_PRIORITY_MAX: i64 = 125;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SCHED_GET_PRIORITY_MIN: i64 = 147;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SCHED_GET_PRIORITY_MIN: i64 = 126;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SCHED_RR_GET_INTERVAL: i64 = 148;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SCHED_RR_GET_INTERVAL: i64 = 127;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MLOCK: i64 = 149;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MLOCK: i64 = 228;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MUNLOCK: i64 = 150;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MUNLOCK: i64 = 229;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MLOCKALL: i64 = 151;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MLOCKALL: i64 = 230;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MUNLOCKALL: i64 = 152;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MUNLOCKALL: i64 = 231;
/// Linux x86-64 controlling-terminal hangup request.
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_VHANGUP: i64 = 153;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_VHANGUP: i64 = 58;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_PRCTL: i64 = 157;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_PRCTL: i64 = 167;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SETRLIMIT: i64 = 160;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SETRLIMIT: i64 = 164;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_CHROOT: i64 = 161;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_CHROOT: i64 = 51;
/// Linux x86-64 mount and unmount requests use five and two words.
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MOUNT: i64 = 165;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MOUNT: i64 = 40;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_UMOUNT2: i64 = 166;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_UMOUNT2: i64 = 39;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_ARCH_PRCTL: i64 = 158;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SETHOSTNAME: i64 = 170;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SETHOSTNAME: i64 = 161;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SETDOMAINNAME: i64 = 171;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SETDOMAINNAME: i64 = 162;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_IOPL: i64 = 172;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_IOPERM: i64 = 173;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_TKILL: i64 = 200;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_TKILL: i64 = 130;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_FUTEX: i64 = 202;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_FUTEX: i64 = 98;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SCHED_SETAFFINITY: i64 = 203;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SCHED_SETAFFINITY: i64 = 122;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SCHED_GETAFFINITY: i64 = 204;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SCHED_GETAFFINITY: i64 = 123;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_REMAP_FILE_PAGES: i64 = 216;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_REMAP_FILE_PAGES: i64 = 234;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_TIMER_SETTIME: i64 = 223;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_TIMER_SETTIME: i64 = 110;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_TIMER_GETTIME: i64 = 224;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_TIMER_GETTIME: i64 = 108;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_TIMER_GETOVERRUN: i64 = 225;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_TIMER_GETOVERRUN: i64 = 109;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_TIMER_DELETE: i64 = 226;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_TIMER_DELETE: i64 = 111;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_CLOCK_GETTIME: i64 = 228;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_CLOCK_GETTIME: i64 = 113;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_CLOCK_GETRES: i64 = 229;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_CLOCK_GETRES: i64 = 114;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_CLOCK_NANOSLEEP: i64 = 230;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_CLOCK_NANOSLEEP: i64 = 115;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_EXIT_GROUP: i64 = 231;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_EXIT_GROUP: i64 = 94;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_EPOLL_CTL: i64 = 233;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_EPOLL_CTL: i64 = 21;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_TGKILL: i64 = 234;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_TGKILL: i64 = 131;
// Linux/x86-64 POSIX message queues use the native LP64 time ABI.
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MQ_OPEN: i64 = 240;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MQ_OPEN: i64 = 180;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MQ_UNLINK: i64 = 241;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MQ_UNLINK: i64 = 181;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MQ_TIMEDSEND: i64 = 242;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MQ_TIMEDSEND: i64 = 182;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MQ_TIMEDRECEIVE: i64 = 243;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MQ_TIMEDRECEIVE: i64 = 183;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MQ_NOTIFY: i64 = 244;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MQ_NOTIFY: i64 = 184;
/// Linux x86-64 `mq_getsetattr` uses `rdi/rsi/rdx` for its three arguments.
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MQ_GETSETATTR: i64 = 245;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MQ_GETSETATTR: i64 = 185;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_WAITID: i64 = 247;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_WAITID: i64 = 95;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_INOTIFY_ADD_WATCH: i64 = 254;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_INOTIFY_ADD_WATCH: i64 = 27;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_INOTIFY_RM_WATCH: i64 = 255;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_INOTIFY_RM_WATCH: i64 = 28;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MKDIRAT: i64 = 258;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MKDIRAT: i64 = 34;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MKNODAT: i64 = 259;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MKNODAT: i64 = 33;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_FCHOWNAT: i64 = 260;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_FCHOWNAT: i64 = 54;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_NEWFSTATAT: i64 = 262;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_NEWFSTATAT: i64 = 79;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_UNLINKAT: i64 = 263;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_UNLINKAT: i64 = 35;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_RENAMEAT: i64 = 264;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_RENAMEAT: i64 = 38;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_LINKAT: i64 = 265;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_LINKAT: i64 = 37;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SYMLINKAT: i64 = 266;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SYMLINKAT: i64 = 36;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_READLINKAT: i64 = 267;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_READLINKAT: i64 = 78;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_FCHMODAT: i64 = 268;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_FCHMODAT: i64 = 53;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_PSELECT6: i64 = 270;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_PSELECT6: i64 = 72;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_PPOLL: i64 = 271;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_PPOLL: i64 = 73;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SET_ROBUST_LIST: i64 = 273;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SET_ROBUST_LIST: i64 = 99;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SYNC_FILE_RANGE: i64 = 277;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SYNC_FILE_RANGE: i64 = 84;
/// Linux x86-64 vmsplice uses fd, iovec pointer/count, and splice flags.
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_VMSPLICE: i64 = 278;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_VMSPLICE: i64 = 75;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_UTIMENSAT: i64 = 280;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_UTIMENSAT: i64 = 88;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_EPOLL_PWAIT: i64 = 281;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_EPOLL_PWAIT: i64 = 22;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_TIMERFD_CREATE: i64 = 283;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_TIMERFD_CREATE: i64 = 85;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_TIMERFD_SETTIME: i64 = 286;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_TIMERFD_SETTIME: i64 = 86;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_TIMERFD_GETTIME: i64 = 287;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_TIMERFD_GETTIME: i64 = 87;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_ACCEPT4: i64 = 288;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_ACCEPT4: i64 = 242;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SIGNALFD4: i64 = 289;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SIGNALFD4: i64 = 74;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_EVENTFD2: i64 = 290;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_EVENTFD2: i64 = 19;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_EPOLL_CREATE1: i64 = 291;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_EPOLL_CREATE1: i64 = 20;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_OPENAT: i64 = 257;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_OPENAT: i64 = 56;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_FACCESSAT: i64 = 269;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_FACCESSAT: i64 = 48;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_DUP3: i64 = 292;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_DUP3: i64 = 24;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_PIPE2: i64 = 293;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_PIPE2: i64 = 59;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_INOTIFY_INIT1: i64 = 294;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_INOTIFY_INIT1: i64 = 26;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_RECVMMSG: i64 = 299;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_RECVMMSG: i64 = 243;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_PRLIMIT64: i64 = 302;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_PRLIMIT64: i64 = 261;
/// Linux x86-64 file-handle syscalls use the five/three C words directly;
/// their variable-sized record remains entirely caller-owned.
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_NAME_TO_HANDLE_AT: i64 = 303;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_NAME_TO_HANDLE_AT: i64 = 264;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_OPEN_BY_HANDLE_AT: i64 = 304;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_OPEN_BY_HANDLE_AT: i64 = 265;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_CLOCK_ADJTIME: i64 = 305;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_CLOCK_ADJTIME: i64 = 266;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SYNCFS: i64 = 306;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SYNCFS: i64 = 267;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SENDMMSG: i64 = 307;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SENDMMSG: i64 = 269;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_GETCPU: i64 = 309;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_GETCPU: i64 = 168;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_RENAMEAT2: i64 = 316;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_RENAMEAT2: i64 = 276;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_GETRANDOM: i64 = 318;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_GETRANDOM: i64 = 278;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MEMFD_CREATE: i64 = 319;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MEMFD_CREATE: i64 = 279;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MEMBARRIER: i64 = 324;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MEMBARRIER: i64 = 283;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MLOCK2: i64 = 325;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_MLOCK2: i64 = 284;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_PREADV2: i64 = 327;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_PREADV2: i64 = 286;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_STATFS: i64 = 137;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_STATFS: i64 = 43;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_FSTATFS: i64 = 138;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_FSTATFS: i64 = 44;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_FDATASYNC: i64 = 75;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_FDATASYNC: i64 = 83;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_FLOCK: i64 = 73;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_FLOCK: i64 = 32;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_GETPID: i64 = 39;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_GETPID: i64 = 172;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_EXIT: i64 = 60;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_EXIT: i64 = 93;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_GETPPID: i64 = 110;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_GETPPID: i64 = 173;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SETSID: i64 = 112;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SETSID: i64 = 157;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SYNC: i64 = 162;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SYNC: i64 = 81;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_GETUID: i64 = 102;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_GETUID: i64 = 174;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_GETGID: i64 = 104;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_GETGID: i64 = 176;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_GETEUID: i64 = 107;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_GETEUID: i64 = 175;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_GETEGID: i64 = 108;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_GETEGID: i64 = 177;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_GETTID: i64 = 186;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_GETTID: i64 = 178;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SET_TID_ADDRESS: i64 = 218;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SET_TID_ADDRESS: i64 = 96;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SETXATTR: i64 = 188;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_SETXATTR: i64 = 5;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_LSETXATTR: i64 = 189;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_LSETXATTR: i64 = 6;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_FSETXATTR: i64 = 190;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_FSETXATTR: i64 = 7;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_GETXATTR: i64 = 191;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_GETXATTR: i64 = 8;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_LGETXATTR: i64 = 192;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_LGETXATTR: i64 = 9;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_FGETXATTR: i64 = 193;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_FGETXATTR: i64 = 10;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_LISTXATTR: i64 = 194;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_LISTXATTR: i64 = 11;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_LLISTXATTR: i64 = 195;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_LLISTXATTR: i64 = 12;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_FLISTXATTR: i64 = 196;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_FLISTXATTR: i64 = 13;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_REMOVEXATTR: i64 = 197;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_REMOVEXATTR: i64 = 14;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_LREMOVEXATTR: i64 = 198;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_LREMOVEXATTR: i64 = 15;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_FREMOVEXATTR: i64 = 199;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_FREMOVEXATTR: i64 = 16;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_GETDENTS64: i64 = 217;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_GETDENTS64: i64 = 61;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_CLOCK_SETTIME: i64 = 227;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_CLOCK_SETTIME: i64 = 112;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_CLONE: i64 = 56;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_CLONE: i64 = 220;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_PREAD64: i64 = 17;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_PREAD64: i64 = 67;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_PWRITE64: i64 = 18;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_PWRITE64: i64 = 68;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_PWRITEV2: i64 = 328;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_PWRITEV2: i64 = 287;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_STATX: i64 = 332;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_STATX: i64 = 291;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_READV: i64 = 19;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_READV: i64 = 65;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_WRITEV: i64 = 20;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_WRITEV: i64 = 66;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_PREADV: i64 = 295;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_PREADV: i64 = 69;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_PWRITEV: i64 = 296;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_PWRITEV: i64 = 70;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_FACCESSAT2: i64 = 439;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_FACCESSAT2: i64 = 439;
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_FCHMODAT2: i64 = 452;
#[cfg(target_arch = "aarch64")]
pub(crate) const SYS_FCHMODAT2: i64 = 452;

#[cfg(target_arch = "x86_64")]
pub(crate) const O_LARGEFILE: i64 = 0o100000;
#[cfg(target_arch = "aarch64")]
pub(crate) const O_LARGEFILE: i64 = 0o400000;
#[cfg(target_arch = "x86_64")]
pub(crate) const O_DIRECTORY: i64 = 0o200000;
#[cfg(target_arch = "aarch64")]
pub(crate) const O_DIRECTORY: i64 = 0o40000;
#[cfg(target_arch = "x86_64")]
pub(crate) const O_NOFOLLOW: i64 = 0o400000;
#[cfg(target_arch = "aarch64")]
pub(crate) const O_NOFOLLOW: i64 = 0o100000;
#[cfg(target_arch = "x86_64")]
pub(crate) const O_TMPFILE: i64 = 0o20200000;
#[cfg(target_arch = "aarch64")]
pub(crate) const O_TMPFILE: i64 = 0o20040000;
