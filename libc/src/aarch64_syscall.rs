//! Concrete Linux/AArch64 syscall instruction and number boundary for libc.
//!
//! C ABI adaptation, errno publication, and process-global policy remain
//! in the surrounding libc modules. This file owns only raw register ABI
//! entry and its single authoritative syscall-number table.

#[inline(always)]
pub(crate) unsafe fn syscall0(n: i64) -> i64 {
    let result: i64;
    core::arch::asm!(
        "svc #0",
        inlateout("x8") n => _,
        lateout("x0") result,
        options(nostack),
    );
    result
}
#[inline(always)]
pub(crate) unsafe fn syscall1(n: i64, a1: i64) -> i64 {
    let result: i64;
    core::arch::asm!(
        "svc #0",
        inlateout("x8") n => _,
        inlateout("x0") a1 => result,
        options(nostack),
    );
    result
}
#[inline(always)]
pub(crate) unsafe fn syscall2(n: i64, a1: i64, a2: i64) -> i64 {
    let result: i64;
    core::arch::asm!(
        "svc #0",
        inlateout("x8") n => _,
        inlateout("x0") a1 => result,
        inlateout("x1") a2 => _,
        options(nostack),
    );
    result
}
#[inline(always)]
pub(crate) unsafe fn syscall3(n: i64, a1: i64, a2: i64, a3: i64) -> i64 {
    let result: i64;
    core::arch::asm!(
        "svc #0",
        inlateout("x8") n => _,
        inlateout("x0") a1 => result,
        inlateout("x1") a2 => _,
        inlateout("x2") a3 => _,
        options(nostack),
    );
    result
}
#[inline(always)]
pub(crate) unsafe fn syscall4(n: i64, a1: i64, a2: i64, a3: i64, a4: i64) -> i64 {
    let result: i64;
    core::arch::asm!(
        "svc #0",
        inlateout("x8") n => _,
        inlateout("x0") a1 => result,
        inlateout("x1") a2 => _,
        inlateout("x2") a3 => _,
        inlateout("x3") a4 => _,
        options(nostack),
    );
    result
}
#[inline(always)]
pub(crate) unsafe fn syscall5(n: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64) -> i64 {
    let result: i64;
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
    result
}
#[inline(always)]
pub(crate) unsafe fn syscall6(n: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64, a6: i64) -> i64 {
    let result: i64;
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
    result
}
#[inline(always)]
pub(crate) unsafe fn syscall_noreturn1(n: i64, a1: i64) -> ! {
    core::arch::asm!(
        "svc #0",
        in("x8") n,
        in("x0") a1,
        options(noreturn, nostack),
    );
}

pub(crate) const SYS_READ: i64 = 63;
pub(crate) const SYS_WRITE: i64 = 64;
// pub(crate) const SYS_OPEN: i64 = ???; // missing in aarch64 table
pub(crate) const SYS_CLOSE: i64 = 57;
// pub(crate) const SYS_STAT: i64 = ???; // missing in aarch64 table
pub(crate) const SYS_FSTAT: i64 = 80;
pub(crate) const SYS_LSEEK: i64 = 62;
pub(crate) const SYS_MMAP: i64 = 222;
pub(crate) const SYS_MUNMAP: i64 = 215;
pub(crate) const SYS_RT_SIGACTION: i64 = 134;
pub(crate) const SYS_RT_SIGPROCMASK: i64 = 135;
pub(crate) const SYS_IOCTL: i64 = 29;
// pub(crate) const SYS_ACCESS: i64 = ???; // missing in aarch64 table
pub(crate) const SYS_SHMGET: i64 = 194;
pub(crate) const SYS_SHMAT: i64 = 196;
pub(crate) const SYS_SHMCTL: i64 = 195;
pub(crate) const SYS_DUP: i64 = 23;
pub(crate) const SYS_NANOSLEEP: i64 = 101;
pub(crate) const SYS_SETITIMER: i64 = 103;
// pub(crate) const SYS_ALARM: i64 = ???; // missing in aarch64 table
pub(crate) const SYS_SOCKET: i64 = 198;
pub(crate) const SYS_CONNECT: i64 = 203;
pub(crate) const SYS_ACCEPT: i64 = 202;
pub(crate) const SYS_SENDTO: i64 = 206;
pub(crate) const SYS_RECVFROM: i64 = 207;
pub(crate) const SYS_SHUTDOWN: i64 = 210;
pub(crate) const SYS_BIND: i64 = 200;
pub(crate) const SYS_LISTEN: i64 = 201;
pub(crate) const SYS_GETSOCKNAME: i64 = 204;
pub(crate) const SYS_SOCKETPAIR: i64 = 199;
pub(crate) const SYS_SETSOCKOPT: i64 = 208;
pub(crate) const SYS_EXECVE: i64 = 221;
pub(crate) const SYS_WAIT4: i64 = 260;
pub(crate) const SYS_KILL: i64 = 129;
pub(crate) const SYS_UNAME: i64 = 160;
pub(crate) const SYS_SEMGET: i64 = 190;
pub(crate) const SYS_SEMOP: i64 = 193;
pub(crate) const SYS_SEMCTL: i64 = 191;
pub(crate) const SYS_SEMTIMEDOP: i64 = 192;
pub(crate) const SYS_SHMDT: i64 = 197;
pub(crate) const SYS_MSGGET: i64 = 186;
pub(crate) const SYS_MSGSND: i64 = 189;
pub(crate) const SYS_MSGRCV: i64 = 188;
pub(crate) const SYS_MSGCTL: i64 = 187;
pub(crate) const SYS_FCNTL: i64 = 25;
pub(crate) const SYS_FSYNC: i64 = 82;
pub(crate) const SYS_TRUNCATE: i64 = 45;
pub(crate) const SYS_FTRUNCATE: i64 = 46;
pub(crate) const SYS_GETCWD: i64 = 17;
pub(crate) const SYS_CHDIR: i64 = 49;
// pub(crate) const SYS_SYMLINK: i64 = ???; // missing in aarch64 table
pub(crate) const SYS_FCHMOD: i64 = 52;
pub(crate) const SYS_UMASK: i64 = 166;
pub(crate) const SYS_GETRLIMIT: i64 = 163;
pub(crate) const SYS_SETUID: i64 = 146;
pub(crate) const SYS_SETGID: i64 = 144;
pub(crate) const SYS_SETPGID: i64 = 154;
pub(crate) const SYS_GETGROUPS: i64 = 158;
pub(crate) const SYS_SETGROUPS: i64 = 159;
pub(crate) const SYS_GETPGID: i64 = 155;
pub(crate) const SYS_GETSID: i64 = 156;
pub(crate) const SYS_RT_SIGPENDING: i64 = 136;
pub(crate) const SYS_RT_SIGTIMEDWAIT: i64 = 137;
pub(crate) const SYS_RT_SIGSUSPEND: i64 = 133;
pub(crate) const SYS_SIGALTSTACK: i64 = 132;
pub(crate) const SYS_SETRLIMIT: i64 = 164;
pub(crate) const SYS_SETHOSTNAME: i64 = 161;
pub(crate) const SYS_FUTEX: i64 = 98;
pub(crate) const SYS_CLOCK_GETTIME: i64 = 113;
pub(crate) const SYS_CLOCK_GETRES: i64 = 114;
pub(crate) const SYS_CLOCK_NANOSLEEP: i64 = 115;
pub(crate) const SYS_EXIT_GROUP: i64 = 94;
pub(crate) const SYS_TGKILL: i64 = 131;
pub(crate) const SYS_MKDIRAT: i64 = 34;
pub(crate) const SYS_NEWFSTATAT: i64 = 79;
pub(crate) const SYS_UNLINKAT: i64 = 35;
pub(crate) const SYS_LINKAT: i64 = 37;
pub(crate) const SYS_SYMLINKAT: i64 = 36;
pub(crate) const SYS_READLINKAT: i64 = 78;
pub(crate) const SYS_FCHMODAT: i64 = 53;
pub(crate) const SYS_SET_ROBUST_LIST: i64 = 99;
pub(crate) const SYS_UTIMENSAT: i64 = 88;
pub(crate) const SYS_OPENAT: i64 = 56;
pub(crate) const SYS_FACCESSAT: i64 = 48;
pub(crate) const SYS_DUP3: i64 = 24;
pub(crate) const SYS_PIPE2: i64 = 59;
pub(crate) const SYS_SYNCFS: i64 = 267;
pub(crate) const SYS_RENAMEAT2: i64 = 276;
pub(crate) const SYS_STATFS: i64 = 43;
pub(crate) const SYS_FSTATFS: i64 = 44;
pub(crate) const SYS_FDATASYNC: i64 = 83;
pub(crate) const SYS_GETPID: i64 = 172;
pub(crate) const SYS_EXIT: i64 = 93;
pub(crate) const SYS_GETPPID: i64 = 173;
pub(crate) const SYS_SETSID: i64 = 157;
pub(crate) const SYS_SYNC: i64 = 81;
pub(crate) const SYS_GETUID: i64 = 174;
pub(crate) const SYS_GETGID: i64 = 176;
pub(crate) const SYS_GETEUID: i64 = 175;
pub(crate) const SYS_GETEGID: i64 = 177;
pub(crate) const SYS_GETTID: i64 = 178;
pub(crate) const SYS_CLOCK_SETTIME: i64 = 112;
pub(crate) const SYS_CLONE: i64 = 220;
pub(crate) const SYS_PPOLL: i64 = 73;
pub(crate) const SYS_PREAD64: i64 = 67;
pub(crate) const SYS_PWRITE64: i64 = 68;
