//! Concrete Linux/AArch64 syscall instruction boundary and result decoding.

use core::arch::asm;

use crate::error::MAX_ERRNO;
use crate::{Errno, Result};

pub(crate) const SYS_READ: usize = 63;
pub(crate) const SYS_WRITE: usize = 64;
pub(crate) const SYS_READV: usize = 65;
pub(crate) const SYS_WRITEV: usize = 66;
pub(crate) const SYS_PREAD64: usize = 67;
pub(crate) const SYS_PWRITE64: usize = 68;
pub(crate) const SYS_PREADV: usize = 69;
pub(crate) const SYS_PWRITEV: usize = 70;
pub(crate) const SYS_SENDFILE: usize = 71;
pub(crate) const SYS_VMSPLICE: usize = 75;
pub(crate) const SYS_SPLICE: usize = 76;
pub(crate) const SYS_TEE: usize = 77;
pub(crate) const SYS_COPY_FILE_RANGE: usize = 285;
pub(crate) const SYS_PREADV2: usize = 286;
pub(crate) const SYS_PWRITEV2: usize = 287;
pub(crate) const SYS_LSEEK: usize = 62;
pub(crate) const SYS_FCNTL: usize = 25;
pub(crate) const SYS_DUP: usize = 23;
pub(crate) const SYS_DUP3: usize = 24;
pub(crate) const SYS_CLOSE: usize = 57;
pub(crate) const SYS_FLOCK: usize = 32;
// Linux/AArch64 `mknodat` is the generic syscall numbered 33. The pinned
// Rustix linux_raw backend and crabc's checked-in AArch64 syscall header both
// carry this number; it precedes `mkdirat` (34) in the kernel table.
pub(crate) const SYS_MKNODAT: usize = 33;
pub(crate) const SYS_OPENAT: usize = 56;
pub(crate) const SYS_MEMFD_CREATE: usize = 279;
pub(crate) const SYS_IOCTL: usize = 29;
// Linux/AArch64's inotify descriptor, watch-addition, and watch-removal
// syscalls are generic entries 26 through 28. They remain a small direct
// seam: higher layers own watch and event-buffer lifetimes.
pub(crate) const SYS_INOTIFY_INIT1: usize = 26;
pub(crate) const SYS_INOTIFY_ADD_WATCH: usize = 27;
pub(crate) const SYS_INOTIFY_RM_WATCH: usize = 28;
pub(crate) const SYS_MKDIRAT: usize = 34;
pub(crate) const SYS_UNLINKAT: usize = 35;
pub(crate) const SYS_SYMLINKAT: usize = 36;
pub(crate) const SYS_LINKAT: usize = 37;
pub(crate) const SYS_FACCESSAT: usize = 48;
// Linux added the flags-bearing access check in 5.8. Keep this direct seam
// separate from `faccessat`: AArch64's older syscall has no flags register.
pub(crate) const SYS_FACCESSAT2: usize = 439;
pub(crate) const SYS_FCHMOD: usize = 52;
pub(crate) const SYS_FCHMODAT: usize = 53;
// Linux/AArch64 syscall numbers from the pinned linux-raw-sys AArch64 table:
// fchownat(2) is 54 and fchown(2) is 55. AArch64 has no chown/lchown syscall;
// those pathname forms use fchownat with AT_FDCWD and (for lchown) the
// AT_SYMLINK_NOFOLLOW flag.
pub(crate) const SYS_FCHOWNAT: usize = 54;
pub(crate) const SYS_FCHOWN: usize = 55;
pub(crate) const SYS_TRUNCATE: usize = 45;
pub(crate) const SYS_FTRUNCATE: usize = 46;
pub(crate) const SYS_FALLOCATE: usize = 47;
pub(crate) const SYS_FADVISE64: usize = 223;
pub(crate) const SYS_FSYNC: usize = 82;
pub(crate) const SYS_FDATASYNC: usize = 83;
// AArch64's generic Linux `sync` syscall has no arguments and no status
// contract: Linux documents it as always successful.
pub(crate) const SYS_SYNC: usize = 81;
// AArch64 exposes the generic `sync_file_range` syscall at 84.
pub(crate) const SYS_SYNC_FILE_RANGE: usize = 84;
pub(crate) const SYS_SYNCFS: usize = 267;
pub(crate) const SYS_GETDENTS64: usize = 61;
pub(crate) const SYS_NEWFSTATAT: usize = 79;
pub(crate) const SYS_READLINKAT: usize = 78;
pub(crate) const SYS_GETCWD: usize = 17;
// Linux/AArch64 process working-directory syscalls.  These mutate the
// process-global CWD; the native facade documents the caller coordination
// required around concurrent pathname operations.
pub(crate) const SYS_CHDIR: usize = 49;
pub(crate) const SYS_FCHDIR: usize = 50;
// Linux/AArch64's legacy process-root operation. Keep it separate from the
// C facade so native callers receive direct kernel errors, not TLS errno.
pub(crate) const SYS_CHROOT: usize = 51;
pub(crate) const SYS_FSTAT: usize = 80;
pub(crate) const SYS_STATFS: usize = 43;
pub(crate) const SYS_FSTATFS: usize = 44;
// Linux/AArch64 `statx` is the extended metadata syscall introduced in 4.11.
pub(crate) const SYS_STATX: usize = 291;
pub(crate) const SYS_UTIMENSAT: usize = 88;
pub(crate) const SYS_RENAMEAT2: usize = 276;
pub(crate) const SYS_OPENAT2: usize = 437;
pub(crate) const SYS_SETXATTR: usize = 5;
pub(crate) const SYS_LSETXATTR: usize = 6;
pub(crate) const SYS_FSETXATTR: usize = 7;
pub(crate) const SYS_GETXATTR: usize = 8;
pub(crate) const SYS_LGETXATTR: usize = 9;
pub(crate) const SYS_FGETXATTR: usize = 10;
pub(crate) const SYS_LISTXATTR: usize = 11;
pub(crate) const SYS_LLISTXATTR: usize = 12;
pub(crate) const SYS_FLISTXATTR: usize = 13;
pub(crate) const SYS_REMOVEXATTR: usize = 14;
pub(crate) const SYS_LREMOVEXATTR: usize = 15;
pub(crate) const SYS_FREMOVEXATTR: usize = 16;
pub(crate) const SYS_PIPE2: usize = 59;
pub(crate) const SYS_CLOCK_SETTIME: usize = 112;
pub(crate) const SYS_CLOCK_GETTIME: usize = 113;
pub(crate) const SYS_CLOCK_GETRES: usize = 114;
pub(crate) const SYS_CLOCK_NANOSLEEP: usize = 115;
pub(crate) const SYS_GETITIMER: usize = 102;
pub(crate) const SYS_SETITIMER: usize = 103;
pub(crate) const SYS_TIMER_CREATE: usize = 107;
pub(crate) const SYS_TIMER_GETTIME: usize = 108;
pub(crate) const SYS_TIMER_GETOVERRUN: usize = 109;
pub(crate) const SYS_TIMER_SETTIME: usize = 110;
pub(crate) const SYS_TIMER_DELETE: usize = 111;
pub(crate) const SYS_GETTIMEOFDAY: usize = 169;
pub(crate) const SYS_NANOSLEEP: usize = 101;
pub(crate) const SYS_GETRANDOM: usize = 278;
pub(crate) const SYS_EVENTFD2: usize = 19;
// Linux/AArch64 POSIX message-queue syscalls.  The kernel ABI is fixed-arity
// even though the C mq_open wrapper is variadic; native callers use the typed
// four-argument form below and never cross that C ABI.
pub(crate) const SYS_MQ_OPEN: usize = 180;
pub(crate) const SYS_MQ_UNLINK: usize = 181;
pub(crate) const SYS_MQ_TIMEDSEND: usize = 182;
pub(crate) const SYS_MQ_TIMEDRECEIVE: usize = 183;
pub(crate) const SYS_MQ_GETSETATTR: usize = 185;
pub(crate) const SYS_PPOLL: usize = 73;
pub(crate) const SYS_PSELECT6: usize = 72;
pub(crate) const SYS_EPOLL_CREATE1: usize = 20;
pub(crate) const SYS_EPOLL_CTL: usize = 21;
pub(crate) const SYS_EPOLL_PWAIT: usize = 22;
pub(crate) const SYS_TIMERFD_CREATE: usize = 85;
pub(crate) const SYS_TIMERFD_SETTIME: usize = 86;
pub(crate) const SYS_TIMERFD_GETTIME: usize = 87;
pub(crate) const SYS_SIGNALFD4: usize = 74;
pub(crate) const SYS_SOCKET: usize = 198;
pub(crate) const SYS_SOCKETPAIR: usize = 199;
pub(crate) const SYS_BIND: usize = 200;
pub(crate) const SYS_LISTEN: usize = 201;
pub(crate) const SYS_ACCEPT: usize = 202;
pub(crate) const SYS_SHUTDOWN: usize = 210;
pub(crate) const SYS_CONNECT: usize = 203;
pub(crate) const SYS_GETSOCKNAME: usize = 204;
pub(crate) const SYS_GETPEERNAME: usize = 205;
pub(crate) const SYS_SENDTO: usize = 206;
pub(crate) const SYS_RECVFROM: usize = 207;
pub(crate) const SYS_SETSOCKOPT: usize = 208;
pub(crate) const SYS_GETSOCKOPT: usize = 209;
pub(crate) const SYS_SENDMSG: usize = 211;
pub(crate) const SYS_RECVMSG: usize = 212;
// Linux/AArch64 uses the generic syscall table entries for batched socket
// messages.  Keep these separate from sendmsg/recvmsg: the latter receive a
// single msghdr, while these consume an array of private mmsghdr records.
pub(crate) const SYS_RECVMMSG: usize = 243;
pub(crate) const SYS_SENDMMSG: usize = 269;
pub(crate) const SYS_READAHEAD: usize = 213;
pub(crate) const SYS_ACCEPT4: usize = 242;
pub(crate) const SYS_MUNMAP: usize = 215;
pub(crate) const SYS_MREMAP: usize = 216;
pub(crate) const SYS_MMAP: usize = 222;
pub(crate) const SYS_MPROTECT: usize = 226;
pub(crate) const SYS_MSYNC: usize = 227;
pub(crate) const SYS_MLOCK: usize = 228;
pub(crate) const SYS_MUNLOCK: usize = 229;
pub(crate) const SYS_MINCORE: usize = 232;
pub(crate) const SYS_MADVISE: usize = 233;
// Linux/AArch64 NUMA memory-policy binding.
pub(crate) const SYS_MBIND: usize = 235;
pub(crate) const SYS_MLOCK2: usize = 284;
pub(crate) const SYS_KILL: usize = 129;
pub(crate) const SYS_TGKILL: usize = 131;
pub(crate) const SYS_SIGALTSTACK: usize = 132;
pub(crate) const SYS_RT_SIGSUSPEND: usize = 133;
pub(crate) const SYS_RT_SIGACTION: usize = 134;
pub(crate) const SYS_RT_SIGPROCMASK: usize = 135;
pub(crate) const SYS_RT_SIGPENDING: usize = 136;
pub(crate) const SYS_RT_SIGTIMEDWAIT: usize = 137;
pub(crate) const SYS_RT_SIGQUEUEINFO: usize = 138;
pub(crate) const SYS_MOUNT: usize = 40;
pub(crate) const SYS_UMOUNT2: usize = 39;
pub(crate) const SYS_GETPGID: usize = 155;
pub(crate) const SYS_SETPGID: usize = 154;
pub(crate) const SYS_GETSID: usize = 156;
pub(crate) const SYS_SETSID: usize = 157;
pub(crate) const SYS_UNAME: usize = 160;
pub(crate) const SYS_GETPID: usize = 172;
pub(crate) const SYS_GETPPID: usize = 173;
pub(crate) const SYS_GETRESUID: usize = 148;
pub(crate) const SYS_SETRESUID: usize = 147;
pub(crate) const SYS_GETRESGID: usize = 150;
pub(crate) const SYS_SETRESGID: usize = 149;
pub(crate) const SYS_SETFSUID: usize = 151;
pub(crate) const SYS_SETFSGID: usize = 152;
pub(crate) const SYS_GETGROUPS: usize = 158;
pub(crate) const SYS_GETRUSAGE: usize = 165;
pub(crate) const SYS_UMASK: usize = 166;
// Linux/AArch64 process/thread control multiplexer. Its option-specific
// argument interpretation belongs to the direct raw caller.
pub(crate) const SYS_PRCTL: usize = 167;
pub(crate) const SYS_GETPRIORITY: usize = 141;
pub(crate) const SYS_SETPRIORITY: usize = 140;
pub(crate) const SYS_TIMES: usize = 153;
pub(crate) const SYS_GETUID: usize = 174;
pub(crate) const SYS_GETEUID: usize = 175;
pub(crate) const SYS_GETGID: usize = 176;
pub(crate) const SYS_GETEGID: usize = 177;
pub(crate) const SYS_GETTID: usize = 178;
// Linux/AArch64 `getcpu`, used by the native thread CPU observation seam.
pub(crate) const SYS_GETCPU: usize = 168;
// Linux/AArch64 process-break and legacy virtual-memory operations.  These
// are kept as raw seams because their public libc wrappers have distinct
// sentinel/state conventions.
pub(crate) const SYS_BRK: usize = 214;
pub(crate) const SYS_REMAP_FILE_PAGES: usize = 234;
pub(crate) const SYS_MLOCKALL: usize = 230;
pub(crate) const SYS_MUNLOCKALL: usize = 231;
pub(crate) const SYS_SYSINFO: usize = 179;
pub(crate) const SYS_SCHED_YIELD: usize = 124;
pub(crate) const SYS_SCHED_GET_PRIORITY_MAX: usize = 125;
pub(crate) const SYS_SCHED_GET_PRIORITY_MIN: usize = 126;
pub(crate) const SYS_SCHED_RR_GET_INTERVAL: usize = 127;
pub(crate) const SYS_SCHED_SETAFFINITY: usize = 122;
pub(crate) const SYS_SCHED_GETAFFINITY: usize = 123;
pub(crate) const SYS_FUTEX: usize = 98;
pub(crate) const SYS_CLONE: usize = 220;
pub(crate) const SYS_EXECVE: usize = 221;
pub(crate) const SYS_WAIT4: usize = 260;
pub(crate) const SYS_WAITID: usize = 95;
pub(crate) const SYS_PRLIMIT64: usize = 261;
pub(crate) const SYS_PIDFD_OPEN: usize = 434;
pub(crate) const SYS_EXIT_GROUP: usize = 94;

#[inline(always)]
pub(crate) unsafe fn syscall0(number: usize) -> isize {
    let result: isize;
    // SAFETY: This is the Linux/AArch64 syscall ABI: x8 carries the syscall
    // number, x0 receives its return value, and `svc #0` enters the kernel.
    unsafe {
        asm!(
            "svc #0",
            in("x8") number,
            lateout("x0") result,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
pub(crate) unsafe fn syscall1(number: usize, arg0: usize) -> isize {
    let result: isize;
    // SAFETY: This is the Linux/AArch64 syscall ABI: x8 carries the syscall
    // number, x0 the first argument and return value, and `svc #0` enters the
    // kernel. Callers select the syscall-specific arguments below.
    unsafe {
        asm!(
            "svc #0",
            in("x8") number,
            inlateout("x0") arg0 => result,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
pub(crate) unsafe fn syscall2(number: usize, arg0: usize, arg1: usize) -> isize {
    let result: isize;
    // SAFETY: See `syscall1`; x1 carries the remaining syscall argument.
    unsafe {
        asm!(
            "svc #0",
            in("x8") number,
            inlateout("x0") arg0 => result,
            in("x1") arg1,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
pub(crate) unsafe fn syscall3(number: usize, arg0: usize, arg1: usize, arg2: usize) -> isize {
    let result: isize;
    // SAFETY: See `syscall1`; x1 and x2 carry the remaining syscall arguments.
    unsafe {
        asm!(
            "svc #0",
            in("x8") number,
            inlateout("x0") arg0 => result,
            in("x1") arg1,
            in("x2") arg2,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
pub(crate) unsafe fn syscall4(number: usize, arg0: usize, arg1: usize, arg2: usize, arg3: usize) -> isize {
    let result: isize;
    // SAFETY: See `syscall1`; x1 through x3 carry the remaining arguments.
    unsafe {
        asm!(
            "svc #0",
            in("x8") number,
            inlateout("x0") arg0 => result,
            in("x1") arg1,
            in("x2") arg2,
            in("x3") arg3,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
pub(crate) unsafe fn syscall5(
    number: usize,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
) -> isize {
    let result: isize;
    // SAFETY: See `syscall1`; x1 through x4 carry the remaining arguments.
    unsafe {
        asm!(
            "svc #0",
            in("x8") number,
            inlateout("x0") arg0 => result,
            in("x1") arg1,
            in("x2") arg2,
            in("x3") arg3,
            in("x4") arg4,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
pub(crate) unsafe fn syscall6(
    number: usize,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
) -> isize {
    let result: isize;
    // SAFETY: See `syscall1`; x1 through x5 carry the remaining arguments.
    unsafe {
        asm!(
            "svc #0",
            in("x8") number,
            inlateout("x0") arg0 => result,
            in("x1") arg1,
            in("x2") arg2,
            in("x3") arg3,
            in("x4") arg4,
            in("x5") arg5,
            options(nostack),
        );
    }
    result
}

#[inline]
pub(crate) fn decode(result: isize) -> Result<usize> {
    if result < 0 && result >= -(MAX_ERRNO as isize) {
        // SAFETY: Linux's syscall error convention constrains this to 1..=4095.
        return Err(Errno::from_raw_os_error((-result) as i32));
    }
    Ok(result as usize)
}

#[inline]
pub(crate) fn decode_i32(result: isize) -> Result<i32> {
    if result < 0 && result >= -(MAX_ERRNO as isize) {
        // SAFETY: Linux's syscall error convention constrains this to 1..=4095.
        return Err(Errno::from_raw_os_error((-result) as i32));
    }
    Ok(result as i32)
}

#[inline]
pub(crate) fn decode_i64(result: isize) -> Result<i64> {
    if result < 0 && result >= -(MAX_ERRNO as isize) {
        // SAFETY: Linux's syscall error convention constrains this to 1..=4095.
        return Err(Errno::from_raw_os_error((-result) as i32));
    }
    Ok(result as i64)
}
