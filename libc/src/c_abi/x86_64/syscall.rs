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
//! and zero-device arguments;
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
//! The separately selected bounded `flock` leaf uses direct `flock=73`, and
//! the regular-file transfer leaf uses direct `sendfile=40`.
//! The separately selected bounded
//! pthread create/explicit-exit/join leaf, private normal-mutex sibling, and
//! private condition-variable handoff use mmap, munmap, futex, gettid
//! identity validation, the selected raw thread exit, the direct C11
//! `thrd_yield` sched_yield=24 boundary, and the separate status-returning
//! POSIX `sched_yield` boundary here. The separately selected
//! bootstrapped-main pthread task-name pair uses direct prctl=157 here;
//! it does not expose a general prctl C API. Static Initial
//! TLS v1 additionally uses arch_prctl(ARCH_SET_FS) while it validates and
//! installs one final-executable TLS image before C TLS exists; its distinct
//! private musl-shaped assembly boundary owns clone and normal-return child
//! exit so this generic register module does not become a public clone API.
//! The separately selected per-range memory-locking, no-cancellation mapping
//! synchronization, and anonymous-memory-descriptor leaves use their named
//! direct syscalls here. All other public C wrappers remain unintegrated until
//! their own ABI
//! boundaries have evidence.
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

// Linux 5.10 x86-64 UAPI syscall numbers. These intentionally retain the
// `i64` names and types the surrounding C ABI source consumes; this file is
// its target-specific single source of truth when x86-64 composition is added.
pub(crate) const SYS_READ: i64 = 0;
pub(crate) const SYS_WRITE: i64 = 1;
pub(crate) const SYS_OPEN: i64 = 2;
pub(crate) const SYS_CLOSE: i64 = 3;
pub(crate) const SYS_FSTAT: i64 = 5;
pub(crate) const SYS_POLL: i64 = 7;
pub(crate) const SYS_LSEEK: i64 = 8;
pub(crate) const SYS_MMAP: i64 = 9;
pub(crate) const SYS_MPROTECT: i64 = 10;
pub(crate) const SYS_MUNMAP: i64 = 11;
pub(crate) const SYS_MSYNC: i64 = 26;
pub(crate) const SYS_RT_SIGACTION: i64 = 13;
pub(crate) const SYS_RT_SIGPROCMASK: i64 = 14;
pub(crate) const SYS_IOCTL: i64 = 16;
pub(crate) const SYS_ACCESS: i64 = 21;
pub(crate) const SYS_PIPE: i64 = 22;
pub(crate) const SYS_SELECT: i64 = 23;
pub(crate) const SYS_SCHED_YIELD: i64 = 24;
pub(crate) const SYS_MINCORE: i64 = 27;
pub(crate) const SYS_MADVISE: i64 = 28;
pub(crate) const SYS_SHMGET: i64 = 29;
pub(crate) const SYS_SHMAT: i64 = 30;
pub(crate) const SYS_SHMCTL: i64 = 31;
pub(crate) const SYS_DUP: i64 = 32;
pub(crate) const SYS_DUP2: i64 = 33;
pub(crate) const SYS_PAUSE: i64 = 34;
pub(crate) const SYS_NANOSLEEP: i64 = 35;
pub(crate) const SYS_SETITIMER: i64 = 38;
pub(crate) const SYS_SOCKET: i64 = 41;
pub(crate) const SYS_CONNECT: i64 = 42;
pub(crate) const SYS_ACCEPT: i64 = 43;
pub(crate) const SYS_SENDTO: i64 = 44;
pub(crate) const SYS_RECVFROM: i64 = 45;
pub(crate) const SYS_SENDMSG: i64 = 46;
pub(crate) const SYS_RECVMSG: i64 = 47;
pub(crate) const SYS_SHUTDOWN: i64 = 48;
pub(crate) const SYS_BIND: i64 = 49;
pub(crate) const SYS_LISTEN: i64 = 50;
pub(crate) const SYS_GETSOCKNAME: i64 = 51;
pub(crate) const SYS_GETPEERNAME: i64 = 52;
pub(crate) const SYS_SOCKETPAIR: i64 = 53;
pub(crate) const SYS_SETSOCKOPT: i64 = 54;
pub(crate) const SYS_GETSOCKOPT: i64 = 55;
pub(crate) const SYS_EXECVE: i64 = 59;
pub(crate) const SYS_WAIT4: i64 = 61;
pub(crate) const SYS_KILL: i64 = 62;
pub(crate) const SYS_UNAME: i64 = 63;
pub(crate) const SYS_SEMGET: i64 = 64;
pub(crate) const SYS_SEMOP: i64 = 65;
pub(crate) const SYS_SEMCTL: i64 = 66;
pub(crate) const SYS_SEMTIMEDOP: i64 = 220;
pub(crate) const SYS_SHMDT: i64 = 67;
pub(crate) const SYS_MSGGET: i64 = 68;
pub(crate) const SYS_MSGSND: i64 = 69;
pub(crate) const SYS_MSGRCV: i64 = 70;
pub(crate) const SYS_MSGCTL: i64 = 71;
pub(crate) const SYS_FCNTL: i64 = 72;
/// Linux x86-64 `sendfile` uses `rdi/rsi/rdx/r10` for its four arguments.
pub(crate) const SYS_SENDFILE: i64 = 40;
/// Linux x86-64 `fallocate` uses `rdi/rsi/rdx/r10` for its four arguments.
pub(crate) const SYS_FALLOCATE: i64 = 285;
/// Linux x86-64 `fadvise64` uses `rdi/rsi/rdx/r10` for its four arguments.
pub(crate) const SYS_FADVISE64: i64 = 221;
/// Linux x86-64 `readahead` uses `rdi/rsi/rdx` for its three arguments.
pub(crate) const SYS_READAHEAD: i64 = 187;
pub(crate) const SYS_FSYNC: i64 = 74;
pub(crate) const SYS_TRUNCATE: i64 = 76;
pub(crate) const SYS_FTRUNCATE: i64 = 77;
pub(crate) const SYS_GETCWD: i64 = 79;
pub(crate) const SYS_CHDIR: i64 = 80;
pub(crate) const SYS_RENAME: i64 = 82;
pub(crate) const SYS_MKDIR: i64 = 83;
pub(crate) const SYS_RMDIR: i64 = 84;
pub(crate) const SYS_LINK: i64 = 86;
pub(crate) const SYS_UNLINK: i64 = 87;
pub(crate) const SYS_SYMLINK: i64 = 88;
pub(crate) const SYS_READLINK: i64 = 89;
pub(crate) const SYS_CHMOD: i64 = 90;
pub(crate) const SYS_FCHMOD: i64 = 91;
pub(crate) const SYS_UMASK: i64 = 95;
pub(crate) const SYS_GETTIMEOFDAY: i64 = 96;
pub(crate) const SYS_GETRLIMIT: i64 = 97;
pub(crate) const SYS_GETRUSAGE: i64 = 98;
pub(crate) const SYS_SYSINFO: i64 = 99;
pub(crate) const SYS_SETUID: i64 = 105;
pub(crate) const SYS_SETGID: i64 = 106;
pub(crate) const SYS_SETPGID: i64 = 109;
pub(crate) const SYS_GETGROUPS: i64 = 115;
pub(crate) const SYS_SETGROUPS: i64 = 116;
pub(crate) const SYS_SETRESUID: i64 = 117;
pub(crate) const SYS_GETRESUID: i64 = 118;
pub(crate) const SYS_SETRESGID: i64 = 119;
pub(crate) const SYS_GETRESGID: i64 = 120;
pub(crate) const SYS_GETPGID: i64 = 121;
pub(crate) const SYS_GETSID: i64 = 124;
pub(crate) const SYS_RT_SIGPENDING: i64 = 127;
pub(crate) const SYS_RT_SIGTIMEDWAIT: i64 = 128;
pub(crate) const SYS_RT_SIGQUEUEINFO: i64 = 129;
pub(crate) const SYS_RT_SIGSUSPEND: i64 = 130;
pub(crate) const SYS_SIGALTSTACK: i64 = 131;
pub(crate) const SYS_GETPRIORITY: i64 = 140;
pub(crate) const SYS_SETPRIORITY: i64 = 141;
pub(crate) const SYS_MLOCK: i64 = 149;
pub(crate) const SYS_MUNLOCK: i64 = 150;
pub(crate) const SYS_PRCTL: i64 = 157;
pub(crate) const SYS_SETRLIMIT: i64 = 160;
pub(crate) const SYS_ARCH_PRCTL: i64 = 158;
pub(crate) const SYS_SETHOSTNAME: i64 = 170;
pub(crate) const SYS_SETDOMAINNAME: i64 = 171;
pub(crate) const SYS_TKILL: i64 = 200;
pub(crate) const SYS_FUTEX: i64 = 202;
pub(crate) const SYS_SCHED_SETAFFINITY: i64 = 203;
pub(crate) const SYS_SCHED_GETAFFINITY: i64 = 204;
pub(crate) const SYS_CLOCK_GETTIME: i64 = 228;
pub(crate) const SYS_CLOCK_GETRES: i64 = 229;
pub(crate) const SYS_CLOCK_NANOSLEEP: i64 = 230;
pub(crate) const SYS_EXIT_GROUP: i64 = 231;
pub(crate) const SYS_EPOLL_CTL: i64 = 233;
pub(crate) const SYS_TGKILL: i64 = 234;
pub(crate) const SYS_WAITID: i64 = 247;
pub(crate) const SYS_INOTIFY_ADD_WATCH: i64 = 254;
pub(crate) const SYS_INOTIFY_RM_WATCH: i64 = 255;
pub(crate) const SYS_MKDIRAT: i64 = 258;
pub(crate) const SYS_MKNODAT: i64 = 259;
pub(crate) const SYS_NEWFSTATAT: i64 = 262;
pub(crate) const SYS_UNLINKAT: i64 = 263;
pub(crate) const SYS_LINKAT: i64 = 265;
pub(crate) const SYS_SYMLINKAT: i64 = 266;
pub(crate) const SYS_READLINKAT: i64 = 267;
pub(crate) const SYS_FCHMODAT: i64 = 268;
pub(crate) const SYS_PSELECT6: i64 = 270;
pub(crate) const SYS_PPOLL: i64 = 271;
pub(crate) const SYS_SET_ROBUST_LIST: i64 = 273;
pub(crate) const SYS_UTIMENSAT: i64 = 280;
pub(crate) const SYS_EPOLL_PWAIT: i64 = 281;
pub(crate) const SYS_TIMERFD_CREATE: i64 = 283;
pub(crate) const SYS_TIMERFD_SETTIME: i64 = 286;
pub(crate) const SYS_TIMERFD_GETTIME: i64 = 287;
pub(crate) const SYS_ACCEPT4: i64 = 288;
pub(crate) const SYS_SIGNALFD4: i64 = 289;
pub(crate) const SYS_EVENTFD2: i64 = 290;
pub(crate) const SYS_EPOLL_CREATE1: i64 = 291;
pub(crate) const SYS_OPENAT: i64 = 257;
pub(crate) const SYS_FACCESSAT: i64 = 269;
pub(crate) const SYS_DUP3: i64 = 292;
pub(crate) const SYS_PIPE2: i64 = 293;
pub(crate) const SYS_INOTIFY_INIT1: i64 = 294;
pub(crate) const SYS_RECVMMSG: i64 = 299;
pub(crate) const SYS_PRLIMIT64: i64 = 302;
pub(crate) const SYS_SYNCFS: i64 = 306;
pub(crate) const SYS_SENDMMSG: i64 = 307;
pub(crate) const SYS_RENAMEAT2: i64 = 316;
pub(crate) const SYS_GETRANDOM: i64 = 318;
pub(crate) const SYS_MEMFD_CREATE: i64 = 319;
pub(crate) const SYS_MLOCK2: i64 = 325;
pub(crate) const SYS_STATFS: i64 = 137;
pub(crate) const SYS_FSTATFS: i64 = 138;
pub(crate) const SYS_FDATASYNC: i64 = 75;
pub(crate) const SYS_FLOCK: i64 = 73;
pub(crate) const SYS_GETPID: i64 = 39;
pub(crate) const SYS_EXIT: i64 = 60;
pub(crate) const SYS_GETPPID: i64 = 110;
pub(crate) const SYS_SETSID: i64 = 112;
pub(crate) const SYS_SYNC: i64 = 162;
pub(crate) const SYS_GETUID: i64 = 102;
pub(crate) const SYS_GETGID: i64 = 104;
pub(crate) const SYS_GETEUID: i64 = 107;
pub(crate) const SYS_GETEGID: i64 = 108;
pub(crate) const SYS_GETTID: i64 = 186;
pub(crate) const SYS_SETXATTR: i64 = 188;
pub(crate) const SYS_LSETXATTR: i64 = 189;
pub(crate) const SYS_FSETXATTR: i64 = 190;
pub(crate) const SYS_GETXATTR: i64 = 191;
pub(crate) const SYS_LGETXATTR: i64 = 192;
pub(crate) const SYS_FGETXATTR: i64 = 193;
pub(crate) const SYS_LISTXATTR: i64 = 194;
pub(crate) const SYS_LLISTXATTR: i64 = 195;
pub(crate) const SYS_FLISTXATTR: i64 = 196;
pub(crate) const SYS_REMOVEXATTR: i64 = 197;
pub(crate) const SYS_LREMOVEXATTR: i64 = 198;
pub(crate) const SYS_FREMOVEXATTR: i64 = 199;
pub(crate) const SYS_GETDENTS64: i64 = 217;
pub(crate) const SYS_CLOCK_SETTIME: i64 = 227;
pub(crate) const SYS_CLONE: i64 = 56;
pub(crate) const SYS_PREAD64: i64 = 17;
pub(crate) const SYS_PWRITE64: i64 = 18;
pub(crate) const SYS_PWRITEV2: i64 = 328;
pub(crate) const SYS_READV: i64 = 19;
pub(crate) const SYS_WRITEV: i64 = 20;
pub(crate) const SYS_PREADV: i64 = 295;
pub(crate) const SYS_PWRITEV: i64 = 296;
pub(crate) const SYS_FACCESSAT2: i64 = 439;
