//! Hand-written libSystem declarations for the Darwin backend.
//!
//! This is the complete foreign surface used by the ported facade modules;
//! nothing here is public outside the crate. Each record carries compile-time
//! size, alignment and field-offset assertions taken from the macOS 27 SDK for
//! `aarch64-apple-darwin`. The constants are the SDK values for the same
//! target.
//!
//! `fcntl`, `ioctl`, `openat` and `shm_open` are declared variadic because
//! their C prototypes are. Apple's AArch64 calling convention passes variadic
//! arguments on the stack rather than in registers, so a fixed-arity
//! declaration would place the argument where libSystem does not read it.
//!
//! The `posix_spawn` family, `pthread_sigmask`, `pthread_kill` and
//! `ttyname_r` return an error number instead of setting `errno`.

#![allow(non_camel_case_types)]

#[cfg(feature = "alloc")]
use core::ffi::c_short;
use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::mem::{align_of, offset_of, size_of};

pub(crate) type mode_t = u16;
pub(crate) type dev_t = i32;
pub(crate) type off_t = i64;
pub(crate) type pid_t = i32;
pub(crate) type uid_t = u32;
pub(crate) type gid_t = u32;
pub(crate) type id_t = u32;
pub(crate) type socklen_t = u32;
pub(crate) type sigset_t = u32;
pub(crate) type clockid_t = c_uint;
pub(crate) type clock_t = c_ulong;
pub(crate) type rlim_t = u64;
pub(crate) type suseconds_t = i32;
pub(crate) type posix_spawnattr_t = *mut c_void;
pub(crate) type posix_spawn_file_actions_t = *mut c_void;
pub(crate) type pthread_t = *mut c_void;

pub(crate) const AT_FDCWD: c_int = -2;
pub(crate) const AT_EACCESS: c_int = 0x0010;
pub(crate) const AT_SYMLINK_NOFOLLOW: c_int = 0x0020;
pub(crate) const AT_SYMLINK_FOLLOW: c_int = 0x0040;
pub(crate) const AT_REMOVEDIR: c_int = 0x0080;

pub(crate) const O_RDONLY: c_int = 0x0000;
pub(crate) const O_WRONLY: c_int = 0x0001;
pub(crate) const O_RDWR: c_int = 0x0002;
pub(crate) const O_ACCMODE: c_int = 0x0003;
pub(crate) const O_NONBLOCK: c_int = 0x0000_0004;
pub(crate) const O_APPEND: c_int = 0x0000_0008;
pub(crate) const O_SHLOCK: c_int = 0x0000_0010;
pub(crate) const O_EXLOCK: c_int = 0x0000_0020;
pub(crate) const O_ASYNC: c_int = 0x0000_0040;
pub(crate) const O_SYNC: c_int = 0x0000_0080;
pub(crate) const O_NOFOLLOW: c_int = 0x0000_0100;
pub(crate) const O_CREAT: c_int = 0x0000_0200;
pub(crate) const O_TRUNC: c_int = 0x0000_0400;
pub(crate) const O_EXCL: c_int = 0x0000_0800;
pub(crate) const O_EVTONLY: c_int = 0x0000_8000;
pub(crate) const O_NOCTTY: c_int = 0x0002_0000;
pub(crate) const O_DIRECTORY: c_int = 0x0010_0000;
pub(crate) const O_SYMLINK: c_int = 0x0020_0000;
pub(crate) const O_DSYNC: c_int = 0x0040_0000;
pub(crate) const O_CLOEXEC: c_int = 0x0100_0000;
pub(crate) const O_CLOFORK: c_int = 0x0800_0000;
pub(crate) const O_NOFOLLOW_ANY: c_int = 0x2000_0000;
pub(crate) const O_EXEC: c_int = 0x4000_0000;

pub(crate) const F_DUPFD: c_int = 0;
pub(crate) const F_GETFD: c_int = 1;
pub(crate) const F_SETFD: c_int = 2;
pub(crate) const F_GETFL: c_int = 3;
pub(crate) const F_SETFL: c_int = 4;
pub(crate) const F_GETLK: c_int = 7;
pub(crate) const F_SETLK: c_int = 8;
pub(crate) const F_SETLKW: c_int = 9;
pub(crate) const F_DUPFD_CLOEXEC: c_int = 67;

pub(crate) const FD_CLOEXEC: c_int = 1;

/// `SEEK_SET` as stored in `struct flock`'s `short l_whence`.
pub(crate) const FLOCK_WHENCE_SET: i16 = 0;
pub(crate) const F_RDLCK: i16 = 1;
pub(crate) const F_UNLCK: i16 = 2;
pub(crate) const F_WRLCK: i16 = 3;

pub(crate) const SEEK_SET: c_int = 0;
pub(crate) const SEEK_CUR: c_int = 1;
pub(crate) const SEEK_END: c_int = 2;
pub(crate) const SEEK_HOLE: c_int = 3;
pub(crate) const SEEK_DATA: c_int = 4;

pub(crate) const UTIME_NOW: c_long = -1;
pub(crate) const UTIME_OMIT: c_long = -2;

pub(crate) const RENAME_SWAP: c_uint = 0x0000_0002;
pub(crate) const RENAME_EXCL: c_uint = 0x0000_0004;

pub(crate) const PIPE_BUF: usize = 512;

pub(crate) const SIGHUP: c_int = 1;
pub(crate) const SIGINT: c_int = 2;
pub(crate) const SIGQUIT: c_int = 3;
pub(crate) const SIGILL: c_int = 4;
pub(crate) const SIGTRAP: c_int = 5;
pub(crate) const SIGABRT: c_int = 6;
pub(crate) const SIGEMT: c_int = 7;
pub(crate) const SIGFPE: c_int = 8;
pub(crate) const SIGKILL: c_int = 9;
pub(crate) const SIGBUS: c_int = 10;
pub(crate) const SIGSEGV: c_int = 11;
pub(crate) const SIGSYS: c_int = 12;
pub(crate) const SIGPIPE: c_int = 13;
pub(crate) const SIGALRM: c_int = 14;
pub(crate) const SIGTERM: c_int = 15;
pub(crate) const SIGURG: c_int = 16;
pub(crate) const SIGSTOP: c_int = 17;
pub(crate) const SIGTSTP: c_int = 18;
pub(crate) const SIGCONT: c_int = 19;
pub(crate) const SIGCHLD: c_int = 20;
pub(crate) const SIGTTIN: c_int = 21;
pub(crate) const SIGTTOU: c_int = 22;
pub(crate) const SIGIO: c_int = 23;
pub(crate) const SIGXCPU: c_int = 24;
pub(crate) const SIGXFSZ: c_int = 25;
pub(crate) const SIGVTALRM: c_int = 26;
pub(crate) const SIGPROF: c_int = 27;
pub(crate) const SIGWINCH: c_int = 28;
pub(crate) const SIGINFO: c_int = 29;
pub(crate) const SIGUSR1: c_int = 30;
pub(crate) const SIGUSR2: c_int = 31;
/// One more than the highest signal number.
pub(crate) const NSIG: c_int = 32;

pub(crate) const SA_ONSTACK: c_int = 0x0001;
pub(crate) const SA_RESTART: c_int = 0x0002;
pub(crate) const SA_RESETHAND: c_int = 0x0004;
pub(crate) const SA_NOCLDSTOP: c_int = 0x0008;
pub(crate) const SA_NODEFER: c_int = 0x0010;
pub(crate) const SA_NOCLDWAIT: c_int = 0x0020;
pub(crate) const SA_SIGINFO: c_int = 0x0040;

pub(crate) const SIG_DFL: usize = 0;
pub(crate) const SIG_IGN: usize = 1;

pub(crate) const SIG_BLOCK: c_int = 1;
pub(crate) const SIG_UNBLOCK: c_int = 2;
pub(crate) const SIG_SETMASK: c_int = 3;

pub(crate) const SS_ONSTACK: c_int = 0x0001;
pub(crate) const SS_DISABLE: c_int = 0x0004;
pub(crate) const MINSIGSTKSZ: usize = 32768;

pub(crate) const WNOHANG: c_int = 0x0001;
pub(crate) const WUNTRACED: c_int = 0x0002;
pub(crate) const WCONTINUED: c_int = 0x0010;

pub(crate) const RLIMIT_CPU: c_int = 0;
pub(crate) const RLIMIT_FSIZE: c_int = 1;
pub(crate) const RLIMIT_DATA: c_int = 2;
pub(crate) const RLIMIT_STACK: c_int = 3;
pub(crate) const RLIMIT_CORE: c_int = 4;
/// Also `RLIMIT_RSS`, which the SDK defines as an alias.
pub(crate) const RLIMIT_AS: c_int = 5;
pub(crate) const RLIMIT_MEMLOCK: c_int = 6;
pub(crate) const RLIMIT_NPROC: c_int = 7;
pub(crate) const RLIMIT_NOFILE: c_int = 8;
pub(crate) const RLIM_INFINITY: rlim_t = (1 << 63) - 1;

pub(crate) const RUSAGE_SELF: c_int = 0;
pub(crate) const RUSAGE_CHILDREN: c_int = -1;

pub(crate) const PRIO_MIN: c_int = -20;
pub(crate) const PRIO_MAX: c_int = 20;

pub(crate) const SCHED_OTHER: c_int = 1;
pub(crate) const SCHED_RR: c_int = 2;
pub(crate) const SCHED_FIFO: c_int = 4;

#[cfg(feature = "alloc")]
pub(crate) const POSIX_SPAWN_SETPGROUP: c_short = 0x0002;
#[cfg(feature = "alloc")]
pub(crate) const POSIX_SPAWN_SETSIGMASK: c_short = 0x0008;
#[cfg(feature = "alloc")]
pub(crate) const POSIX_SPAWN_SETSID: c_short = 0x0400;
#[cfg(feature = "alloc")]
pub(crate) const POSIX_SPAWN_CLOEXEC_DEFAULT: c_short = 0x4000;

pub(crate) const CLOCK_REALTIME: clockid_t = 0;
pub(crate) const CLOCK_MONOTONIC_RAW: clockid_t = 4;
pub(crate) const CLOCK_MONOTONIC_RAW_APPROX: clockid_t = 5;
pub(crate) const CLOCK_MONOTONIC: clockid_t = 6;
pub(crate) const CLOCK_UPTIME_RAW: clockid_t = 8;
pub(crate) const CLOCK_UPTIME_RAW_APPROX: clockid_t = 9;
pub(crate) const CLOCK_PROCESS_CPUTIME_ID: clockid_t = 12;
pub(crate) const CLOCK_THREAD_CPUTIME_ID: clockid_t = 16;

pub(crate) const ITIMER_REAL: c_int = 0;
pub(crate) const ITIMER_VIRTUAL: c_int = 1;
pub(crate) const ITIMER_PROF: c_int = 2;

pub(crate) const AF_UNSPEC: c_int = 0;
pub(crate) const AF_UNIX: c_int = 1;
pub(crate) const AF_INET: c_int = 2;
pub(crate) const AF_INET6: c_int = 30;

pub(crate) const MSG_OOB: c_int = 0x0001;
pub(crate) const MSG_PEEK: c_int = 0x0002;
pub(crate) const MSG_DONTROUTE: c_int = 0x0004;
pub(crate) const MSG_EOR: c_int = 0x0008;
pub(crate) const MSG_TRUNC: c_int = 0x0010;
pub(crate) const MSG_CTRUNC: c_int = 0x0020;
pub(crate) const MSG_WAITALL: c_int = 0x0040;
pub(crate) const MSG_DONTWAIT: c_int = 0x0080;
pub(crate) const MSG_NOSIGNAL: c_int = 0x0008_0000;

pub(crate) const SOL_SOCKET: c_int = 0xffff;
pub(crate) const SO_REUSEADDR: c_int = 0x0004;
pub(crate) const SO_BROADCAST: c_int = 0x0020;
pub(crate) const SO_OOBINLINE: c_int = 0x0100;
pub(crate) const SO_TYPE: c_int = 0x1008;

pub(crate) const FIOCLEX: c_ulong = 0x2000_6601;
pub(crate) const FIONCLEX: c_ulong = 0x2000_6602;
pub(crate) const FIONBIO: c_ulong = 0x8004_667e;
pub(crate) const FIONREAD: c_ulong = 0x4004_667f;

/// `PATH_MAX` from `sys/syslimits.h`: the pathname bound including its NUL.
pub(crate) const PATH_MAX: usize = 1024;
/// `MAXSYMLINKS` from `sys/param.h`: the symbolic links one lookup follows.
pub(crate) const MAXSYMLINKS: usize = 32;
/// `PSHMNAMLEN` from `sys/posix_shm.h`: the longest POSIX shared-memory name,
/// counting a leading slash.
pub(crate) const PSHMNAMLEN: usize = 31;

pub(crate) const NCCS: usize = 20;
pub(crate) const VEOF: usize = 0;
pub(crate) const VEOL: usize = 1;
pub(crate) const VEOL2: usize = 2;
pub(crate) const VERASE: usize = 3;
pub(crate) const VWERASE: usize = 4;
pub(crate) const VKILL: usize = 5;
pub(crate) const VREPRINT: usize = 6;
pub(crate) const VINTR: usize = 8;
pub(crate) const VQUIT: usize = 9;
pub(crate) const VSUSP: usize = 10;
pub(crate) const VDSUSP: usize = 11;
pub(crate) const VSTART: usize = 12;
pub(crate) const VSTOP: usize = 13;
pub(crate) const VLNEXT: usize = 14;
pub(crate) const VDISCARD: usize = 15;
pub(crate) const VMIN: usize = 16;
pub(crate) const VTIME: usize = 17;
pub(crate) const VSTATUS: usize = 18;
/// `_POSIX_VDISABLE`: a special-code byte that disables its function.
pub(crate) const POSIX_VDISABLE: u8 = 0xff;

pub(crate) const IGNBRK: c_ulong = 0x0000_0001;
pub(crate) const BRKINT: c_ulong = 0x0000_0002;
pub(crate) const PARMRK: c_ulong = 0x0000_0008;
pub(crate) const ISTRIP: c_ulong = 0x0000_0020;
pub(crate) const INLCR: c_ulong = 0x0000_0040;
pub(crate) const IGNCR: c_ulong = 0x0000_0080;
pub(crate) const ICRNL: c_ulong = 0x0000_0100;
pub(crate) const IXON: c_ulong = 0x0000_0200;
pub(crate) const OPOST: c_ulong = 0x0000_0001;
pub(crate) const CSIZE: c_ulong = 0x0000_0300;
pub(crate) const CS8: c_ulong = 0x0000_0300;
pub(crate) const PARENB: c_ulong = 0x0000_1000;
pub(crate) const ECHO: c_ulong = 0x0000_0008;
pub(crate) const ECHONL: c_ulong = 0x0000_0010;
pub(crate) const ISIG: c_ulong = 0x0000_0080;
pub(crate) const ICANON: c_ulong = 0x0000_0100;
pub(crate) const IEXTEN: c_ulong = 0x0000_0400;

pub(crate) const TCSANOW: c_int = 0;
pub(crate) const TCSADRAIN: c_int = 1;
pub(crate) const TCSAFLUSH: c_int = 2;
pub(crate) const TCIFLUSH: c_int = 1;
pub(crate) const TCOFLUSH: c_int = 2;
pub(crate) const TCIOFLUSH: c_int = 3;
pub(crate) const TCOOFF: c_int = 1;
pub(crate) const TCOON: c_int = 2;
pub(crate) const TCIOFF: c_int = 3;
pub(crate) const TCION: c_int = 4;

pub(crate) const TIOCEXCL: c_ulong = 0x2000_740d;
pub(crate) const TIOCNXCL: c_ulong = 0x2000_740e;
pub(crate) const TIOCSCTTY: c_ulong = 0x2000_7461;
pub(crate) const TIOCGWINSZ: c_ulong = 0x4008_7468;
pub(crate) const TIOCSWINSZ: c_ulong = 0x8008_7467;
/// The name buffer size of `TIOCPTYGNAME`, which `ptsname_r` fills: the
/// longest pseudoterminal slave name plus its NUL.
pub(crate) const PTY_NAME_CAPACITY: usize = 128;

pub(crate) const PROT_READ: c_int = 0x01;
pub(crate) const PROT_WRITE: c_int = 0x02;
pub(crate) const PROT_EXEC: c_int = 0x04;
pub(crate) const MAP_SHARED: c_int = 0x0001;
pub(crate) const MAP_PRIVATE: c_int = 0x0002;
pub(crate) const MAP_ANON: c_int = 0x1000;
pub(crate) const MS_ASYNC: c_int = 0x0001;
pub(crate) const MS_INVALIDATE: c_int = 0x0002;
pub(crate) const MS_SYNC: c_int = 0x0010;
pub(crate) const MADV_NORMAL: c_int = 0;
pub(crate) const MADV_RANDOM: c_int = 1;
pub(crate) const MADV_SEQUENTIAL: c_int = 2;
pub(crate) const MADV_WILLNEED: c_int = 3;
pub(crate) const POSIX_MADV_NORMAL: c_int = 0;
pub(crate) const POSIX_MADV_RANDOM: c_int = 1;
pub(crate) const POSIX_MADV_SEQUENTIAL: c_int = 2;
pub(crate) const POSIX_MADV_WILLNEED: c_int = 3;
pub(crate) const POSIX_MADV_DONTNEED: c_int = 4;
/// The 16 KiB base page of an `aarch64-apple-darwin` process.
pub(crate) const PAGE_SIZE: usize = 16384;

/// `struct iovec`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Iovec {
    pub(crate) iov_base: *mut u8,
    pub(crate) iov_len: usize,
}

/// `struct timespec`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Timespec {
    pub(crate) tv_sec: i64,
    pub(crate) tv_nsec: c_long,
}

/// `struct stat` with 64-bit inodes, the only `stat` ABI on Apple AArch64.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Stat {
    pub(crate) st_dev: dev_t,
    pub(crate) st_mode: mode_t,
    pub(crate) st_nlink: u16,
    pub(crate) st_ino: u64,
    pub(crate) st_uid: u32,
    pub(crate) st_gid: u32,
    pub(crate) st_rdev: dev_t,
    pub(crate) st_atimespec: Timespec,
    pub(crate) st_mtimespec: Timespec,
    pub(crate) st_ctimespec: Timespec,
    pub(crate) st_birthtimespec: Timespec,
    pub(crate) st_size: off_t,
    pub(crate) st_blocks: i64,
    pub(crate) st_blksize: i32,
    pub(crate) st_flags: u32,
    pub(crate) st_gen: u32,
    pub(crate) st_lspare: i32,
    pub(crate) st_qspare: [i64; 2],
}

/// `struct flock`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Flock {
    pub(crate) l_start: off_t,
    pub(crate) l_len: off_t,
    pub(crate) l_pid: i32,
    pub(crate) l_type: i16,
    pub(crate) l_whence: i16,
}

/// `struct dirent` with 64-bit inodes.
#[repr(C)]
pub(crate) struct Dirent {
    pub(crate) d_ino: u64,
    pub(crate) d_seekoff: u64,
    pub(crate) d_reclen: u16,
    pub(crate) d_namlen: u16,
    pub(crate) d_type: u8,
    pub(crate) d_name: [c_char; 1024],
}

/// `struct timeval`; `tv_usec` is a 32-bit `suseconds_t` followed by padding.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Timeval {
    pub(crate) tv_sec: i64,
    pub(crate) tv_usec: suseconds_t,
}

/// `struct itimerval`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Itimerval {
    pub(crate) it_interval: Timeval,
    pub(crate) it_value: Timeval,
}

/// `struct rlimit`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Rlimit {
    pub(crate) rlim_cur: rlim_t,
    pub(crate) rlim_max: rlim_t,
}

/// `struct rusage`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Rusage {
    pub(crate) ru_utime: Timeval,
    pub(crate) ru_stime: Timeval,
    pub(crate) ru_maxrss: c_long,
    pub(crate) ru_ixrss: c_long,
    pub(crate) ru_idrss: c_long,
    pub(crate) ru_isrss: c_long,
    pub(crate) ru_minflt: c_long,
    pub(crate) ru_majflt: c_long,
    pub(crate) ru_nswap: c_long,
    pub(crate) ru_inblock: c_long,
    pub(crate) ru_oublock: c_long,
    pub(crate) ru_msgsnd: c_long,
    pub(crate) ru_msgrcv: c_long,
    pub(crate) ru_nsignals: c_long,
    pub(crate) ru_nvcsw: c_long,
    pub(crate) ru_nivcsw: c_long,
}

/// `struct tms`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Tms {
    pub(crate) tms_utime: clock_t,
    pub(crate) tms_stime: clock_t,
    pub(crate) tms_cutime: clock_t,
    pub(crate) tms_cstime: clock_t,
}

/// `struct sigaction`, the libSystem form whose handler union is one
/// pointer-sized word.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Sigaction {
    pub(crate) sa_handler: usize,
    pub(crate) sa_mask: sigset_t,
    pub(crate) sa_flags: c_int,
}

/// `siginfo_t`. `si_value` is the pointer-sized `union sigval`; `si_addr`
/// is held as an address so the record stays `Send` and `Sync` like the
/// Linux one.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Siginfo {
    pub(crate) si_signo: c_int,
    pub(crate) si_errno: c_int,
    pub(crate) si_code: c_int,
    pub(crate) si_pid: pid_t,
    pub(crate) si_uid: uid_t,
    pub(crate) si_status: c_int,
    pub(crate) si_addr: usize,
    pub(crate) si_value: usize,
    pub(crate) si_band: c_long,
    pub(crate) pad: [c_ulong; 7],
}

/// `stack_t`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct StackT {
    pub(crate) ss_sp: *mut c_void,
    pub(crate) ss_size: usize,
    pub(crate) ss_flags: c_int,
}

/// `struct sockaddr_in`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct SockaddrIn {
    pub(crate) sin_len: u8,
    pub(crate) sin_family: u8,
    pub(crate) sin_port: u16,
    pub(crate) sin_addr: u32,
    pub(crate) sin_zero: [u8; 8],
}

/// `struct sockaddr_in6`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct SockaddrIn6 {
    pub(crate) sin6_len: u8,
    pub(crate) sin6_family: u8,
    pub(crate) sin6_port: u16,
    pub(crate) sin6_flowinfo: u32,
    pub(crate) sin6_addr: [u8; 16],
    pub(crate) sin6_scope_id: u32,
}

/// `struct sockaddr_storage`.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub(crate) struct SockaddrStorage {
    pub(crate) bytes: [u8; 128],
}

/// `struct msghdr`.
#[repr(C)]
pub(crate) struct Msghdr {
    pub(crate) msg_name: *mut c_void,
    pub(crate) msg_namelen: socklen_t,
    pub(crate) msg_iov: *mut Iovec,
    pub(crate) msg_iovlen: c_int,
    pub(crate) msg_control: *mut c_void,
    pub(crate) msg_controllen: socklen_t,
    pub(crate) msg_flags: c_int,
}

/// `struct termios`. `tcflag_t` and `speed_t` are `unsigned long`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Termios {
    pub(crate) c_iflag: c_ulong,
    pub(crate) c_oflag: c_ulong,
    pub(crate) c_cflag: c_ulong,
    pub(crate) c_lflag: c_ulong,
    pub(crate) c_cc: [u8; NCCS],
    pub(crate) c_ispeed: c_ulong,
    pub(crate) c_ospeed: c_ulong,
}

/// `struct winsize`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Winsize {
    pub(crate) ws_row: u16,
    pub(crate) ws_col: u16,
    pub(crate) ws_xpixel: u16,
    pub(crate) ws_ypixel: u16,
}

/// The opaque libSystem directory stream, `DIR`.
#[repr(C)]
pub(crate) struct Dir {
    _opaque: [u8; 0],
}

const _: () = {
    assert!(size_of::<Iovec>() == 16 && align_of::<Iovec>() == 8);
    assert!(offset_of!(Iovec, iov_base) == 0 && offset_of!(Iovec, iov_len) == 8);

    assert!(size_of::<Timespec>() == 16 && align_of::<Timespec>() == 8);
    assert!(offset_of!(Timespec, tv_sec) == 0 && offset_of!(Timespec, tv_nsec) == 8);

    assert!(size_of::<Stat>() == 144 && align_of::<Stat>() == 8);
    assert!(offset_of!(Stat, st_dev) == 0);
    assert!(offset_of!(Stat, st_mode) == 4);
    assert!(offset_of!(Stat, st_nlink) == 6);
    assert!(offset_of!(Stat, st_ino) == 8);
    assert!(offset_of!(Stat, st_uid) == 16);
    assert!(offset_of!(Stat, st_gid) == 20);
    assert!(offset_of!(Stat, st_rdev) == 24);
    assert!(offset_of!(Stat, st_atimespec) == 32);
    assert!(offset_of!(Stat, st_mtimespec) == 48);
    assert!(offset_of!(Stat, st_ctimespec) == 64);
    assert!(offset_of!(Stat, st_birthtimespec) == 80);
    assert!(offset_of!(Stat, st_size) == 96);
    assert!(offset_of!(Stat, st_blocks) == 104);
    assert!(offset_of!(Stat, st_blksize) == 112);
    assert!(offset_of!(Stat, st_flags) == 116);
    assert!(offset_of!(Stat, st_gen) == 120);
    assert!(offset_of!(Stat, st_lspare) == 124);
    assert!(offset_of!(Stat, st_qspare) == 128);

    assert!(size_of::<Flock>() == 24 && align_of::<Flock>() == 8);
    assert!(FLOCK_WHENCE_SET as c_int == SEEK_SET);
    assert!(offset_of!(Flock, l_start) == 0);
    assert!(offset_of!(Flock, l_len) == 8);
    assert!(offset_of!(Flock, l_pid) == 16);
    assert!(offset_of!(Flock, l_type) == 20);
    assert!(offset_of!(Flock, l_whence) == 22);

    assert!(size_of::<Dirent>() == 1048 && align_of::<Dirent>() == 8);
    assert!(offset_of!(Dirent, d_ino) == 0);
    assert!(offset_of!(Dirent, d_seekoff) == 8);
    assert!(offset_of!(Dirent, d_reclen) == 16);
    assert!(offset_of!(Dirent, d_namlen) == 18);
    assert!(offset_of!(Dirent, d_type) == 20);
    assert!(offset_of!(Dirent, d_name) == 21);

    assert!(size_of::<Timeval>() == 16 && align_of::<Timeval>() == 8);
    assert!(offset_of!(Timeval, tv_sec) == 0 && offset_of!(Timeval, tv_usec) == 8);

    assert!(size_of::<Itimerval>() == 32 && align_of::<Itimerval>() == 8);
    assert!(offset_of!(Itimerval, it_interval) == 0 && offset_of!(Itimerval, it_value) == 16);

    assert!(size_of::<Rlimit>() == 16 && align_of::<Rlimit>() == 8);
    assert!(offset_of!(Rlimit, rlim_cur) == 0 && offset_of!(Rlimit, rlim_max) == 8);

    assert!(size_of::<Rusage>() == 144 && align_of::<Rusage>() == 8);
    assert!(offset_of!(Rusage, ru_utime) == 0);
    assert!(offset_of!(Rusage, ru_stime) == 16);
    assert!(offset_of!(Rusage, ru_maxrss) == 32);
    assert!(offset_of!(Rusage, ru_ixrss) == 40);
    assert!(offset_of!(Rusage, ru_idrss) == 48);
    assert!(offset_of!(Rusage, ru_isrss) == 56);
    assert!(offset_of!(Rusage, ru_minflt) == 64);
    assert!(offset_of!(Rusage, ru_majflt) == 72);
    assert!(offset_of!(Rusage, ru_nswap) == 80);
    assert!(offset_of!(Rusage, ru_inblock) == 88);
    assert!(offset_of!(Rusage, ru_oublock) == 96);
    assert!(offset_of!(Rusage, ru_msgsnd) == 104);
    assert!(offset_of!(Rusage, ru_msgrcv) == 112);
    assert!(offset_of!(Rusage, ru_nsignals) == 120);
    assert!(offset_of!(Rusage, ru_nvcsw) == 128);
    assert!(offset_of!(Rusage, ru_nivcsw) == 136);

    assert!(size_of::<Tms>() == 32 && align_of::<Tms>() == 8);
    assert!(offset_of!(Tms, tms_utime) == 0);
    assert!(offset_of!(Tms, tms_stime) == 8);
    assert!(offset_of!(Tms, tms_cutime) == 16);
    assert!(offset_of!(Tms, tms_cstime) == 24);

    assert!(size_of::<Sigaction>() == 16 && align_of::<Sigaction>() == 8);
    assert!(offset_of!(Sigaction, sa_handler) == 0);
    assert!(offset_of!(Sigaction, sa_mask) == 8);
    assert!(offset_of!(Sigaction, sa_flags) == 12);

    assert!(size_of::<Siginfo>() == 104 && align_of::<Siginfo>() == 8);
    assert!(offset_of!(Siginfo, si_signo) == 0);
    assert!(offset_of!(Siginfo, si_errno) == 4);
    assert!(offset_of!(Siginfo, si_code) == 8);
    assert!(offset_of!(Siginfo, si_pid) == 12);
    assert!(offset_of!(Siginfo, si_uid) == 16);
    assert!(offset_of!(Siginfo, si_status) == 20);
    assert!(offset_of!(Siginfo, si_addr) == 24);
    assert!(offset_of!(Siginfo, si_value) == 32);
    assert!(offset_of!(Siginfo, si_band) == 40);
    assert!(offset_of!(Siginfo, pad) == 48);

    assert!(size_of::<StackT>() == 24 && align_of::<StackT>() == 8);
    assert!(offset_of!(StackT, ss_sp) == 0);
    assert!(offset_of!(StackT, ss_size) == 8);
    assert!(offset_of!(StackT, ss_flags) == 16);

    assert!(size_of::<SockaddrIn>() == 16 && align_of::<SockaddrIn>() == 4);
    assert!(offset_of!(SockaddrIn, sin_len) == 0);
    assert!(offset_of!(SockaddrIn, sin_family) == 1);
    assert!(offset_of!(SockaddrIn, sin_port) == 2);
    assert!(offset_of!(SockaddrIn, sin_addr) == 4);
    assert!(offset_of!(SockaddrIn, sin_zero) == 8);

    assert!(size_of::<SockaddrIn6>() == 28 && align_of::<SockaddrIn6>() == 4);
    assert!(offset_of!(SockaddrIn6, sin6_len) == 0);
    assert!(offset_of!(SockaddrIn6, sin6_family) == 1);
    assert!(offset_of!(SockaddrIn6, sin6_port) == 2);
    assert!(offset_of!(SockaddrIn6, sin6_flowinfo) == 4);
    assert!(offset_of!(SockaddrIn6, sin6_addr) == 8);
    assert!(offset_of!(SockaddrIn6, sin6_scope_id) == 24);

    assert!(size_of::<SockaddrStorage>() == 128 && align_of::<SockaddrStorage>() == 8);

    assert!(size_of::<Msghdr>() == 48 && align_of::<Msghdr>() == 8);
    assert!(offset_of!(Msghdr, msg_name) == 0);
    assert!(offset_of!(Msghdr, msg_namelen) == 8);
    assert!(offset_of!(Msghdr, msg_iov) == 16);
    assert!(offset_of!(Msghdr, msg_iovlen) == 24);
    assert!(offset_of!(Msghdr, msg_control) == 32);
    assert!(offset_of!(Msghdr, msg_controllen) == 40);
    assert!(offset_of!(Msghdr, msg_flags) == 44);

    assert!(size_of::<pid_t>() == 4 && size_of::<uid_t>() == 4 && size_of::<gid_t>() == 4);
    assert!(size_of::<id_t>() == 4 && size_of::<socklen_t>() == 4 && size_of::<sigset_t>() == 4);
    assert!(size_of::<clockid_t>() == 4 && size_of::<clock_t>() == 8 && size_of::<rlim_t>() == 8);
    assert!(size_of::<posix_spawnattr_t>() == 8 && size_of::<posix_spawn_file_actions_t>() == 8);
    assert!(size_of::<pthread_t>() == 8);

    assert!(size_of::<Termios>() == 72 && align_of::<Termios>() == 8);
    assert!(offset_of!(Termios, c_iflag) == 0);
    assert!(offset_of!(Termios, c_oflag) == 8);
    assert!(offset_of!(Termios, c_cflag) == 16);
    assert!(offset_of!(Termios, c_lflag) == 24);
    assert!(offset_of!(Termios, c_cc) == 32);
    assert!(offset_of!(Termios, c_ispeed) == 56);
    assert!(offset_of!(Termios, c_ospeed) == 64);

    assert!(size_of::<Winsize>() == 8 && align_of::<Winsize>() == 2);
    assert!(offset_of!(Winsize, ws_row) == 0);
    assert!(offset_of!(Winsize, ws_col) == 2);
    assert!(offset_of!(Winsize, ws_xpixel) == 4);
    assert!(offset_of!(Winsize, ws_ypixel) == 6);

    assert!(size_of::<mode_t>() == 2 && size_of::<dev_t>() == 4 && size_of::<off_t>() == 8);
    assert!(size_of::<c_long>() == 8);
};

unsafe extern "C" {
    pub(crate) safe fn __error() -> *mut c_int;

    pub(crate) unsafe fn close(fd: c_int) -> c_int;
    pub(crate) unsafe fn dup(fd: c_int) -> c_int;
    pub(crate) unsafe fn dup2(fd: c_int, fd2: c_int) -> c_int;
    pub(crate) unsafe fn dup3(fd: c_int, fd2: c_int, flags: c_int) -> c_int;
    pub(crate) unsafe fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    pub(crate) unsafe fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;

    pub(crate) unsafe fn read(fd: c_int, buf: *mut c_void, nbyte: usize) -> isize;
    pub(crate) unsafe fn readv(fd: c_int, iov: *const Iovec, iovcnt: c_int) -> isize;
    pub(crate) unsafe fn pread(fd: c_int, buf: *mut c_void, nbyte: usize, offset: off_t) -> isize;
    pub(crate) unsafe fn preadv(fd: c_int, iov: *const Iovec, iovcnt: c_int, offset: off_t) -> isize;
    pub(crate) unsafe fn write(fd: c_int, buf: *const c_void, nbyte: usize) -> isize;
    pub(crate) unsafe fn writev(fd: c_int, iov: *const Iovec, iovcnt: c_int) -> isize;
    pub(crate) unsafe fn pwrite(fd: c_int, buf: *const c_void, nbyte: usize, offset: off_t) -> isize;
    pub(crate) unsafe fn pwritev(fd: c_int, iov: *const Iovec, iovcnt: c_int, offset: off_t) -> isize;

    pub(crate) unsafe fn pipe2(fds: *mut c_int, flags: c_int) -> c_int;

    pub(crate) unsafe fn access(path: *const c_char, mode: c_int) -> c_int;
    pub(crate) unsafe fn faccessat(fd: c_int, path: *const c_char, mode: c_int, flag: c_int) -> c_int;
    pub(crate) unsafe fn flock(fd: c_int, operation: c_int) -> c_int;
    pub(crate) unsafe fn lseek(fd: c_int, offset: off_t, whence: c_int) -> off_t;
    pub(crate) unsafe fn openat(fd: c_int, path: *const c_char, oflag: c_int, ...) -> c_int;
    pub(crate) unsafe fn fstat(fd: c_int, buf: *mut Stat) -> c_int;
    pub(crate) unsafe fn fstatat(fd: c_int, path: *const c_char, buf: *mut Stat, flag: c_int) -> c_int;
    pub(crate) unsafe fn mkdirat(fd: c_int, path: *const c_char, mode: mode_t) -> c_int;
    pub(crate) unsafe fn mknodat(fd: c_int, path: *const c_char, mode: mode_t, dev: dev_t) -> c_int;
    pub(crate) unsafe fn unlinkat(fd: c_int, path: *const c_char, flag: c_int) -> c_int;
    pub(crate) unsafe fn linkat(
        fd1: c_int,
        path1: *const c_char,
        fd2: c_int,
        path2: *const c_char,
        flag: c_int,
    ) -> c_int;
    pub(crate) unsafe fn symlinkat(path1: *const c_char, fd: c_int, path2: *const c_char) -> c_int;
    pub(crate) unsafe fn renameatx_np(
        fromfd: c_int,
        from: *const c_char,
        tofd: c_int,
        to: *const c_char,
        flags: c_uint,
    ) -> c_int;
    pub(crate) unsafe fn fchmod(fd: c_int, mode: mode_t) -> c_int;
    pub(crate) unsafe fn fchmodat(fd: c_int, path: *const c_char, mode: mode_t, flag: c_int) -> c_int;
    pub(crate) unsafe fn readlinkat(fd: c_int, path: *const c_char, buf: *mut c_char, size: usize)
        -> isize;
    pub(crate) unsafe fn ftruncate(fd: c_int, length: off_t) -> c_int;
    pub(crate) unsafe fn truncate(path: *const c_char, length: off_t) -> c_int;
    pub(crate) unsafe fn utimensat(
        fd: c_int,
        path: *const c_char,
        times: *const Timespec,
        flag: c_int,
    ) -> c_int;
    pub(crate) unsafe fn futimens(fd: c_int, times: *const Timespec) -> c_int;
    pub(crate) unsafe fn fsync(fd: c_int) -> c_int;
    pub(crate) safe fn sync();

    pub(crate) unsafe fn fdopendir(fd: c_int) -> *mut Dir;
    pub(crate) unsafe fn readdir(dirp: *mut Dir) -> *mut Dirent;
    pub(crate) unsafe fn rewinddir(dirp: *mut Dir);
    pub(crate) unsafe fn telldir(dirp: *mut Dir) -> c_long;
    pub(crate) unsafe fn seekdir(dirp: *mut Dir, loc: c_long);
    pub(crate) unsafe fn closedir(dirp: *mut Dir) -> c_int;

    pub(crate) unsafe fn getentropy(buffer: *mut c_void, size: usize) -> c_int;

    pub(crate) safe fn getpid() -> pid_t;
    pub(crate) safe fn getppid() -> pid_t;
    pub(crate) safe fn getuid() -> uid_t;
    pub(crate) safe fn geteuid() -> uid_t;
    pub(crate) safe fn getgid() -> gid_t;
    pub(crate) safe fn getegid() -> gid_t;
    pub(crate) safe fn getpgid(pid: pid_t) -> pid_t;
    pub(crate) safe fn getsid(pid: pid_t) -> pid_t;
    pub(crate) safe fn kill(pid: pid_t, sig: c_int) -> c_int;
    pub(crate) safe fn umask(mask: mode_t) -> mode_t;
    pub(crate) safe fn _exit(status: c_int) -> !;
    pub(crate) unsafe fn chdir(path: *const c_char) -> c_int;
    pub(crate) unsafe fn fchdir(fd: c_int) -> c_int;
    pub(crate) unsafe fn chroot(path: *const c_char) -> c_int;
    pub(crate) unsafe fn getcwd(buf: *mut c_char, size: usize) -> *mut c_char;
    pub(crate) unsafe fn getgroups(size: c_int, list: *mut gid_t) -> c_int;
    pub(crate) safe fn getpriority(which: c_int, who: id_t) -> c_int;
    pub(crate) safe fn setpriority(which: c_int, who: id_t, prio: c_int) -> c_int;
    pub(crate) safe fn sched_get_priority_min(policy: c_int) -> c_int;
    pub(crate) safe fn sched_get_priority_max(policy: c_int) -> c_int;
    pub(crate) unsafe fn getrlimit(resource: c_int, rlp: *mut Rlimit) -> c_int;
    pub(crate) unsafe fn setrlimit(resource: c_int, rlp: *const Rlimit) -> c_int;
    pub(crate) unsafe fn getrusage(who: c_int, usage: *mut Rusage) -> c_int;
    pub(crate) unsafe fn times(buffer: *mut Tms) -> clock_t;
    #[cfg(feature = "alloc")]
    pub(crate) unsafe fn waitpid(pid: pid_t, status: *mut c_int, options: c_int) -> pid_t;
    pub(crate) unsafe fn fchown(fd: c_int, owner: uid_t, group: gid_t) -> c_int;
    pub(crate) unsafe fn fchownat(
        fd: c_int,
        path: *const c_char,
        owner: uid_t,
        group: gid_t,
        flag: c_int,
    ) -> c_int;

    #[cfg(feature = "alloc")]
    pub(crate) unsafe fn posix_spawn(
        pid: *mut pid_t,
        path: *const c_char,
        file_actions: *const posix_spawn_file_actions_t,
        attrp: *const posix_spawnattr_t,
        argv: *const *mut c_char,
        envp: *const *mut c_char,
    ) -> c_int;
    #[cfg(feature = "alloc")]
    pub(crate) unsafe fn posix_spawnattr_init(attr: *mut posix_spawnattr_t) -> c_int;
    #[cfg(feature = "alloc")]
    pub(crate) unsafe fn posix_spawnattr_destroy(attr: *mut posix_spawnattr_t) -> c_int;
    #[cfg(feature = "alloc")]
    pub(crate) unsafe fn posix_spawnattr_setflags(attr: *mut posix_spawnattr_t, flags: c_short)
        -> c_int;
    #[cfg(feature = "alloc")]
    pub(crate) unsafe fn posix_spawnattr_setpgroup(attr: *mut posix_spawnattr_t, pgroup: pid_t)
        -> c_int;
    #[cfg(feature = "alloc")]
    pub(crate) unsafe fn posix_spawnattr_setsigmask(
        attr: *mut posix_spawnattr_t,
        sigmask: *const sigset_t,
    ) -> c_int;
    #[cfg(feature = "alloc")]
    pub(crate) unsafe fn posix_spawn_file_actions_init(
        file_actions: *mut posix_spawn_file_actions_t,
    ) -> c_int;
    #[cfg(feature = "alloc")]
    pub(crate) unsafe fn posix_spawn_file_actions_destroy(
        file_actions: *mut posix_spawn_file_actions_t,
    ) -> c_int;
    #[cfg(feature = "alloc")]
    pub(crate) unsafe fn posix_spawn_file_actions_addclose(
        file_actions: *mut posix_spawn_file_actions_t,
        fd: c_int,
    ) -> c_int;
    #[cfg(feature = "alloc")]
    pub(crate) unsafe fn posix_spawn_file_actions_adddup2(
        file_actions: *mut posix_spawn_file_actions_t,
        fd: c_int,
        newfd: c_int,
    ) -> c_int;
    #[cfg(feature = "alloc")]
    pub(crate) unsafe fn posix_spawn_file_actions_addinherit_np(
        file_actions: *mut posix_spawn_file_actions_t,
        fd: c_int,
    ) -> c_int;

    pub(crate) unsafe fn sigaction(sig: c_int, act: *const Sigaction, oact: *mut Sigaction)
        -> c_int;
    pub(crate) unsafe fn pthread_sigmask(how: c_int, set: *const sigset_t, oset: *mut sigset_t)
        -> c_int;
    pub(crate) unsafe fn sigpending(set: *mut sigset_t) -> c_int;
    pub(crate) unsafe fn sigsuspend(mask: *const sigset_t) -> c_int;
    pub(crate) unsafe fn sigaltstack(ss: *const StackT, oss: *mut StackT) -> c_int;
    pub(crate) safe fn pthread_self() -> pthread_t;
    pub(crate) unsafe fn pthread_kill(thread: pthread_t, sig: c_int) -> c_int;

    pub(crate) unsafe fn clock_gettime(clock_id: clockid_t, tp: *mut Timespec) -> c_int;
    pub(crate) unsafe fn clock_getres(clock_id: clockid_t, tp: *mut Timespec) -> c_int;
    pub(crate) unsafe fn clock_settime(clock_id: clockid_t, tp: *const Timespec) -> c_int;
    pub(crate) unsafe fn nanosleep(rqtp: *const Timespec, rmtp: *mut Timespec) -> c_int;
    pub(crate) unsafe fn gettimeofday(tp: *mut Timeval, tzp: *mut c_void) -> c_int;
    pub(crate) unsafe fn getitimer(which: c_int, value: *mut Itimerval) -> c_int;
    pub(crate) unsafe fn setitimer(which: c_int, value: *const Itimerval, ovalue: *mut Itimerval)
        -> c_int;

    pub(crate) safe fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
    pub(crate) unsafe fn socketpair(domain: c_int, kind: c_int, protocol: c_int, sv: *mut c_int)
        -> c_int;
    pub(crate) unsafe fn setsockopt(
        socket: c_int,
        level: c_int,
        name: c_int,
        value: *const c_void,
        length: socklen_t,
    ) -> c_int;
    pub(crate) unsafe fn getsockopt(
        socket: c_int,
        level: c_int,
        name: c_int,
        value: *mut c_void,
        length: *mut socklen_t,
    ) -> c_int;
    pub(crate) unsafe fn listen(socket: c_int, backlog: c_int) -> c_int;
    pub(crate) unsafe fn accept(socket: c_int, address: *mut u8, length: *mut socklen_t) -> c_int;
    pub(crate) unsafe fn shutdown(socket: c_int, how: c_int) -> c_int;
    pub(crate) unsafe fn connect(socket: c_int, address: *const u8, length: socklen_t) -> c_int;
    pub(crate) unsafe fn bind(socket: c_int, address: *const u8, length: socklen_t) -> c_int;
    pub(crate) unsafe fn getsockname(socket: c_int, address: *mut u8, length: *mut socklen_t)
        -> c_int;
    pub(crate) unsafe fn getpeername(socket: c_int, address: *mut u8, length: *mut socklen_t)
        -> c_int;
    pub(crate) unsafe fn sendto(
        socket: c_int,
        buffer: *const c_void,
        length: usize,
        flags: c_int,
        address: *const u8,
        address_length: socklen_t,
    ) -> isize;
    pub(crate) unsafe fn recvfrom(
        socket: c_int,
        buffer: *mut c_void,
        length: usize,
        flags: c_int,
        address: *mut u8,
        address_length: *mut socklen_t,
    ) -> isize;
    pub(crate) unsafe fn sendmsg(socket: c_int, message: *const Msghdr, flags: c_int) -> isize;
    pub(crate) unsafe fn recvmsg(socket: c_int, message: *mut Msghdr, flags: c_int) -> isize;
    pub(crate) unsafe fn sockatmark(socket: c_int) -> c_int;

    pub(crate) unsafe fn tcgetattr(fd: c_int, termios: *mut Termios) -> c_int;
    pub(crate) unsafe fn tcsetattr(fd: c_int, action: c_int, termios: *const Termios) -> c_int;
    pub(crate) unsafe fn tcdrain(fd: c_int) -> c_int;
    pub(crate) unsafe fn tcflush(fd: c_int, queue: c_int) -> c_int;
    pub(crate) unsafe fn tcflow(fd: c_int, action: c_int) -> c_int;
    pub(crate) unsafe fn tcsendbreak(fd: c_int, duration: c_int) -> c_int;
    pub(crate) unsafe fn tcgetpgrp(fd: c_int) -> pid_t;
    pub(crate) unsafe fn tcsetpgrp(fd: c_int, pgrp: pid_t) -> c_int;
    pub(crate) unsafe fn tcgetsid(fd: c_int) -> pid_t;
    /// Returns an error number rather than setting `errno`.
    pub(crate) unsafe fn ttyname_r(fd: c_int, buffer: *mut c_char, length: usize) -> c_int;
    pub(crate) safe fn setsid() -> pid_t;

    pub(crate) safe fn posix_openpt(flags: c_int) -> c_int;
    pub(crate) unsafe fn grantpt(fd: c_int) -> c_int;
    pub(crate) unsafe fn unlockpt(fd: c_int) -> c_int;
    /// Unlike `ttyname_r`, reports failure as `-1` with `errno` set.
    pub(crate) unsafe fn ptsname_r(fd: c_int, buffer: *mut c_char, length: usize) -> c_int;

    pub(crate) unsafe fn mmap(
        address: *mut c_void,
        length: usize,
        protection: c_int,
        flags: c_int,
        fd: c_int,
        offset: off_t,
    ) -> *mut c_void;
    pub(crate) unsafe fn munmap(address: *mut c_void, length: usize) -> c_int;
    pub(crate) unsafe fn mprotect(address: *mut c_void, length: usize, protection: c_int) -> c_int;
    pub(crate) unsafe fn msync(address: *mut c_void, length: usize, flags: c_int) -> c_int;
    pub(crate) unsafe fn madvise(address: *mut c_void, length: usize, advice: c_int) -> c_int;
    /// Unlike POSIX, reports failure as `-1` with `errno` set.
    pub(crate) unsafe fn posix_madvise(address: *mut c_void, length: usize, advice: c_int)
        -> c_int;
    pub(crate) unsafe fn mlock(address: *const c_void, length: usize) -> c_int;
    pub(crate) unsafe fn munlock(address: *const c_void, length: usize) -> c_int;
    pub(crate) unsafe fn mincore(address: *const c_void, length: usize, vector: *mut c_char)
        -> c_int;
    pub(crate) safe fn getpagesize() -> c_int;

    pub(crate) unsafe fn shm_open(name: *const c_char, oflag: c_int, ...) -> c_int;
    pub(crate) unsafe fn shm_unlink(name: *const c_char) -> c_int;
}
