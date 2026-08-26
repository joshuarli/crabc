//! Concrete Linux/x86-64 syscall instruction boundary and result decoding.

//! The syscall numbers in this file are checked against Linux `asm/unistd_64.h`
//! by the architecture evidence tooling. Linux/x86-64 uses `syscall`, with
//! `rax` carrying both the syscall number and result, arguments in
//! `rdi`, `rsi`, `rdx`, `r10`, `r8`, and `r9`, and `rcx`/`r11` clobbered.

use core::arch::asm;

use crate::error::MAX_ERRNO;
use crate::{Errno, Result};

pub(crate) const SYS_READ: usize = 0;
pub(crate) const SYS_WRITE: usize = 1;
pub(crate) const SYS_READV: usize = 19;
pub(crate) const SYS_WRITEV: usize = 20;
pub(crate) const SYS_PREAD64: usize = 17;
pub(crate) const SYS_PWRITE64: usize = 18;
pub(crate) const SYS_PREADV: usize = 295;
pub(crate) const SYS_PWRITEV: usize = 296;
pub(crate) const SYS_SENDFILE: usize = 40;
pub(crate) const SYS_VMSPLICE: usize = 278;
pub(crate) const SYS_SPLICE: usize = 275;
pub(crate) const SYS_TEE: usize = 276;
pub(crate) const SYS_COPY_FILE_RANGE: usize = 326;
pub(crate) const SYS_PREADV2: usize = 327;
pub(crate) const SYS_PWRITEV2: usize = 328;
pub(crate) const SYS_LSEEK: usize = 8;
pub(crate) const SYS_FCNTL: usize = 72;
pub(crate) const SYS_DUP: usize = 32;
pub(crate) const SYS_DUP3: usize = 292;
pub(crate) const SYS_CLOSE: usize = 3;
pub(crate) const SYS_FLOCK: usize = 73;
pub(crate) const SYS_MKNODAT: usize = 259;
pub(crate) const SYS_OPENAT: usize = 257;
pub(crate) const SYS_MEMFD_CREATE: usize = 319;
pub(crate) const SYS_IOCTL: usize = 16;
pub(crate) const SYS_INOTIFY_INIT1: usize = 294;
pub(crate) const SYS_INOTIFY_ADD_WATCH: usize = 254;
pub(crate) const SYS_INOTIFY_RM_WATCH: usize = 255;
pub(crate) const SYS_MKDIRAT: usize = 258;
pub(crate) const SYS_UNLINKAT: usize = 263;
pub(crate) const SYS_SYMLINKAT: usize = 266;
pub(crate) const SYS_LINKAT: usize = 265;
pub(crate) const SYS_FACCESSAT: usize = 269;
pub(crate) const SYS_FACCESSAT2: usize = 439;
pub(crate) const SYS_FCHMOD: usize = 91;
pub(crate) const SYS_FCHMODAT: usize = 268;
pub(crate) const SYS_FCHOWNAT: usize = 260;
pub(crate) const SYS_FCHOWN: usize = 93;
pub(crate) const SYS_TRUNCATE: usize = 76;
pub(crate) const SYS_FTRUNCATE: usize = 77;
pub(crate) const SYS_FALLOCATE: usize = 285;
pub(crate) const SYS_FADVISE64: usize = 221;
pub(crate) const SYS_FSYNC: usize = 74;
pub(crate) const SYS_FDATASYNC: usize = 75;
pub(crate) const SYS_SYNC: usize = 162;
pub(crate) const SYS_SYNC_FILE_RANGE: usize = 277;
pub(crate) const SYS_SYNCFS: usize = 306;
pub(crate) const SYS_GETDENTS64: usize = 217;
pub(crate) const SYS_NEWFSTATAT: usize = 262;
pub(crate) const SYS_READLINKAT: usize = 267;
pub(crate) const SYS_GETCWD: usize = 79;
pub(crate) const SYS_CHDIR: usize = 80;
pub(crate) const SYS_FCHDIR: usize = 81;
pub(crate) const SYS_CHROOT: usize = 161;
pub(crate) const SYS_FSTAT: usize = 5;
pub(crate) const SYS_STATFS: usize = 137;
pub(crate) const SYS_FSTATFS: usize = 138;
pub(crate) const SYS_STATX: usize = 332;
pub(crate) const SYS_UTIMENSAT: usize = 280;
pub(crate) const SYS_RENAMEAT2: usize = 316;
pub(crate) const SYS_OPENAT2: usize = 437;
pub(crate) const SYS_SETXATTR: usize = 188;
pub(crate) const SYS_LSETXATTR: usize = 189;
pub(crate) const SYS_FSETXATTR: usize = 190;
pub(crate) const SYS_GETXATTR: usize = 191;
pub(crate) const SYS_LGETXATTR: usize = 192;
pub(crate) const SYS_FGETXATTR: usize = 193;
pub(crate) const SYS_LISTXATTR: usize = 194;
pub(crate) const SYS_LLISTXATTR: usize = 195;
pub(crate) const SYS_FLISTXATTR: usize = 196;
pub(crate) const SYS_REMOVEXATTR: usize = 197;
pub(crate) const SYS_LREMOVEXATTR: usize = 198;
pub(crate) const SYS_FREMOVEXATTR: usize = 199;
pub(crate) const SYS_PIPE2: usize = 293;
pub(crate) const SYS_CLOCK_SETTIME: usize = 227;
pub(crate) const SYS_CLOCK_GETTIME: usize = 228;
pub(crate) const SYS_CLOCK_GETRES: usize = 229;
pub(crate) const SYS_CLOCK_NANOSLEEP: usize = 230;
pub(crate) const SYS_GETITIMER: usize = 36;
pub(crate) const SYS_SETITIMER: usize = 38;
pub(crate) const SYS_TIMER_CREATE: usize = 222;
pub(crate) const SYS_TIMER_GETTIME: usize = 224;
pub(crate) const SYS_TIMER_GETOVERRUN: usize = 225;
pub(crate) const SYS_TIMER_SETTIME: usize = 223;
pub(crate) const SYS_TIMER_DELETE: usize = 226;
pub(crate) const SYS_GETTIMEOFDAY: usize = 96;
pub(crate) const SYS_NANOSLEEP: usize = 35;
pub(crate) const SYS_GETRANDOM: usize = 318;
pub(crate) const SYS_POLL: usize = 7;
pub(crate) const SYS_EVENTFD2: usize = 290;
pub(crate) const SYS_MQ_OPEN: usize = 240;
pub(crate) const SYS_MQ_UNLINK: usize = 241;
pub(crate) const SYS_MQ_TIMEDSEND: usize = 242;
pub(crate) const SYS_MQ_TIMEDRECEIVE: usize = 243;
pub(crate) const SYS_MQ_GETSETATTR: usize = 245;
pub(crate) const SYS_PPOLL: usize = 271;
pub(crate) const SYS_PSELECT6: usize = 270;
pub(crate) const SYS_EPOLL_CREATE1: usize = 291;
pub(crate) const SYS_EPOLL_CTL: usize = 233;
pub(crate) const SYS_EPOLL_PWAIT: usize = 281;
pub(crate) const SYS_TIMERFD_CREATE: usize = 283;
pub(crate) const SYS_TIMERFD_SETTIME: usize = 286;
pub(crate) const SYS_TIMERFD_GETTIME: usize = 287;
pub(crate) const SYS_SIGNALFD4: usize = 289;
pub(crate) const SYS_SOCKET: usize = 41;
pub(crate) const SYS_SOCKETPAIR: usize = 53;
pub(crate) const SYS_BIND: usize = 49;
pub(crate) const SYS_LISTEN: usize = 50;
pub(crate) const SYS_ACCEPT: usize = 43;
pub(crate) const SYS_SHUTDOWN: usize = 48;
pub(crate) const SYS_CONNECT: usize = 42;
pub(crate) const SYS_GETSOCKNAME: usize = 51;
pub(crate) const SYS_GETPEERNAME: usize = 52;
pub(crate) const SYS_SENDTO: usize = 44;
pub(crate) const SYS_RECVFROM: usize = 45;
pub(crate) const SYS_SETSOCKOPT: usize = 54;
pub(crate) const SYS_GETSOCKOPT: usize = 55;
pub(crate) const SYS_SENDMSG: usize = 46;
pub(crate) const SYS_RECVMSG: usize = 47;
pub(crate) const SYS_RECVMMSG: usize = 299;
pub(crate) const SYS_SENDMMSG: usize = 307;
pub(crate) const SYS_READAHEAD: usize = 187;
pub(crate) const SYS_ACCEPT4: usize = 288;
pub(crate) const SYS_MUNMAP: usize = 11;
pub(crate) const SYS_MMAP: usize = 9;
pub(crate) const SYS_MPROTECT: usize = 10;
pub(crate) const SYS_MREMAP: usize = 25;
pub(crate) const SYS_KILL: usize = 62;
pub(crate) const SYS_TGKILL: usize = 234;
pub(crate) const SYS_SIGALTSTACK: usize = 131;
pub(crate) const SYS_RT_SIGSUSPEND: usize = 130;
pub(crate) const SYS_RT_SIGACTION: usize = 13;
pub(crate) const SYS_RT_SIGPROCMASK: usize = 14;
pub(crate) const SYS_RT_SIGPENDING: usize = 127;
pub(crate) const SYS_RT_SIGTIMEDWAIT: usize = 128;
pub(crate) const SYS_RT_SIGQUEUEINFO: usize = 129;
pub(crate) const SYS_MOUNT: usize = 165;
pub(crate) const SYS_UMOUNT2: usize = 166;
pub(crate) const SYS_GETPGID: usize = 121;
pub(crate) const SYS_SETPGID: usize = 109;
pub(crate) const SYS_GETSID: usize = 124;
pub(crate) const SYS_SETSID: usize = 112;
pub(crate) const SYS_UNAME: usize = 63;
pub(crate) const SYS_GETPID: usize = 39;
pub(crate) const SYS_GETPPID: usize = 110;
pub(crate) const SYS_GETRESUID: usize = 118;
pub(crate) const SYS_SETRESUID: usize = 117;
pub(crate) const SYS_GETRESGID: usize = 120;
pub(crate) const SYS_SETRESGID: usize = 119;
pub(crate) const SYS_SETFSUID: usize = 122;
pub(crate) const SYS_SETFSGID: usize = 123;
pub(crate) const SYS_GETGROUPS: usize = 115;
pub(crate) const SYS_GETRUSAGE: usize = 98;
pub(crate) const SYS_UMASK: usize = 95;
pub(crate) const SYS_GETPRIORITY: usize = 140;
pub(crate) const SYS_SETPRIORITY: usize = 141;
pub(crate) const SYS_TIMES: usize = 100;
pub(crate) const SYS_GETUID: usize = 102;
pub(crate) const SYS_GETEUID: usize = 107;
pub(crate) const SYS_GETGID: usize = 104;
pub(crate) const SYS_GETEGID: usize = 108;
pub(crate) const SYS_GETTID: usize = 186;
pub(crate) const SYS_GETCPU: usize = 309;
pub(crate) const SYS_PRCTL: usize = 157;
pub(crate) const SYS_BRK: usize = 12;
pub(crate) const SYS_SYSINFO: usize = 99;
pub(crate) const SYS_SCHED_YIELD: usize = 24;
pub(crate) const SYS_SCHED_GET_PRIORITY_MAX: usize = 146;
pub(crate) const SYS_SCHED_GET_PRIORITY_MIN: usize = 147;
pub(crate) const SYS_SCHED_RR_GET_INTERVAL: usize = 148;
pub(crate) const SYS_SCHED_SETAFFINITY: usize = 203;
pub(crate) const SYS_SCHED_GETAFFINITY: usize = 204;
pub(crate) const SYS_FUTEX: usize = 202;
pub(crate) const SYS_CLONE: usize = 56;
pub(crate) const SYS_EXECVE: usize = 59;
pub(crate) const SYS_WAIT4: usize = 61;
pub(crate) const SYS_WAITID: usize = 247;
pub(crate) const SYS_PRLIMIT64: usize = 302;
pub(crate) const SYS_PIDFD_OPEN: usize = 434;
pub(crate) const SYS_EXIT_GROUP: usize = 231;

#[inline(always)]
pub(crate) unsafe fn syscall0(number: usize) -> isize {
    let result: isize;
    // SAFETY: This is the Linux/x86-64 syscall ABI. `syscall` clobbers
    // `rcx` and `r11`; omitting `nomem` retains the kernel-call memory
    // barrier required for pointer-bearing syscalls.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") number as isize => result,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
pub(crate) unsafe fn syscall1(number: usize, arg0: usize) -> isize {
    let result: isize;
    // SAFETY: `rdi` is Linux/x86-64 syscall argument one.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") number as isize => result,
            in("rdi") arg0,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
pub(crate) unsafe fn syscall2(number: usize, arg0: usize, arg1: usize) -> isize {
    let result: isize;
    // SAFETY: `rdi`/`rsi` carry Linux/x86-64 syscall arguments one/two.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") number as isize => result,
            in("rdi") arg0,
            in("rsi") arg1,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
pub(crate) unsafe fn syscall3(number: usize, arg0: usize, arg1: usize, arg2: usize) -> isize {
    let result: isize;
    // SAFETY: `rdi`/`rsi`/`rdx` carry Linux/x86-64 syscall arguments one through three.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") number as isize => result,
            in("rdi") arg0,
            in("rsi") arg1,
            in("rdx") arg2,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
pub(crate) unsafe fn syscall4(number: usize, arg0: usize, arg1: usize, arg2: usize, arg3: usize) -> isize {
    let result: isize;
    // SAFETY: Linux/x86-64 moves syscall argument four from the C ABI `rcx` register to `r10`.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") number as isize => result,
            in("rdi") arg0,
            in("rsi") arg1,
            in("rdx") arg2,
            in("r10") arg3,
            lateout("rcx") _,
            lateout("r11") _,
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
    // SAFETY: Linux/x86-64 syscall arguments four/five occupy `r10`/`r8`.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") number as isize => result,
            in("rdi") arg0,
            in("rsi") arg1,
            in("rdx") arg2,
            in("r10") arg3,
            in("r8") arg4,
            lateout("rcx") _,
            lateout("r11") _,
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
    // SAFETY: Linux/x86-64 syscall argument six occupies `r9`.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") number as isize => result,
            in("rdi") arg0,
            in("rsi") arg1,
            in("rdx") arg2,
            in("r10") arg3,
            in("r8") arg4,
            in("r9") arg5,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

#[inline]
pub(crate) fn decode(result: isize) -> Result<usize> {
    if result < 0 && result >= -(MAX_ERRNO as isize) {
        // SAFETY: Linux syscall errors are in the inclusive `-4095..=-1` range.
        return Err(Errno::from_raw_os_error((-result) as i32));
    }
    Ok(result as usize)
}

#[inline]
pub(crate) fn decode_i32(result: isize) -> Result<i32> {
    if result < 0 && result >= -(MAX_ERRNO as isize) {
        // SAFETY: Linux syscall errors are in the inclusive `-4095..=-1` range.
        return Err(Errno::from_raw_os_error((-result) as i32));
    }
    Ok(result as i32)
}

#[inline]
pub(crate) fn decode_i64(result: isize) -> Result<i64> {
    if result < 0 && result >= -(MAX_ERRNO as isize) {
        // SAFETY: Linux syscall errors are in the inclusive `-4095..=-1` range.
        return Err(Errno::from_raw_os_error((-result) as i32));
    }
    Ok(result as i64)
}
