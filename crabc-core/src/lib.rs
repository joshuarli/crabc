//! Internal, stateless Linux/AArch64 operations shared by crabc's facades.
//!
//! This crate deliberately owns no process-global runtime state.  It is safe
//! to link into both `libc.so` and a Rust application because its operations
//! cross directly to the kernel and its values have no singleton identity.
//! Stateful libc and dynamic-loader facilities must not be added here without
//! an explicit runtime-owner boundary.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(all(target_os = "linux", target_arch = "aarch64", target_endian = "little")))]
compile_error!("crabc-core supports Linux/AArch64 little-endian only");

use core::arch::asm;
use core::ffi::CStr;
use core::fmt;
use core::mem::MaybeUninit;
use core::num::NonZeroI32;

/// A positive Linux errno value returned by a direct kernel operation.
///
/// Unlike libc's thread-local `errno`, this is an ordinary value that remains
/// associated with the operation that failed.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Errno(NonZeroI32);

impl Errno {
    /// Builds an errno from a positive Linux errno value in the syscall range.
    #[inline]
    pub const fn new(raw: i32) -> Option<Self> {
        if raw > 0 && raw <= MAX_ERRNO {
            // SAFETY: The branch proves that `raw` is non-zero.
            Some(Self(unsafe { NonZeroI32::new_unchecked(raw) }))
        } else {
            None
        }
    }

    /// Builds an errno from a positive Linux errno value in the syscall range.
    #[inline]
    pub const fn from_raw(raw: i32) -> Option<Self> {
        Self::new(raw)
    }

    /// Returns the positive Linux errno number.
    #[inline]
    pub const fn raw(self) -> i32 {
        self.0.get()
    }

    /// Returns the positive Linux OS error value.
    #[inline]
    pub const fn raw_os_error(self) -> i32 {
        self.raw()
    }

    /// Constructs an errno from a positive Linux OS error value.
    ///
    /// This mirrors Rustix's infallible constructor for code which already
    /// carries a kernel errno. Use [`Self::from_raw`] when input is untrusted.
    #[inline]
    pub const fn from_raw_os_error(raw: i32) -> Self {
        match Self::new(raw) {
            Some(errno) => errno,
            None => panic!("invalid Linux errno"),
        }
    }
}

macro_rules! linux_errno_constants {
    ($($name:ident = $value:literal,)*) => {
        impl Errno {
            $(
                #[doc = concat!("Linux errno value `", stringify!($name), "`.")]
                pub const $name: Self = Self::from_raw_os_error($value);
            )*
        }
    };
}

// These are the complete Linux errno names exposed by Rustix's Linux-raw
// backend. The numeric values are the pinned musl Linux/AArch64 values; the
// Linux ABI gives them the same values on every supported 64-bit target.
linux_errno_constants! {
    ACCESS = 13,
    ADDRINUSE = 98,
    ADDRNOTAVAIL = 99,
    ADV = 68,
    AFNOSUPPORT = 97,
    AGAIN = 11,
    ALREADY = 114,
    BADE = 52,
    BADF = 9,
    BADFD = 77,
    BADMSG = 74,
    BADR = 53,
    BADRQC = 56,
    BADSLT = 57,
    BFONT = 59,
    BUSY = 16,
    CANCELED = 125,
    CHILD = 10,
    CHRNG = 44,
    COMM = 70,
    CONNABORTED = 103,
    CONNREFUSED = 111,
    CONNRESET = 104,
    DEADLK = 35,
    DEADLOCK = 35,
    DESTADDRREQ = 89,
    DOM = 33,
    DOTDOT = 73,
    DQUOT = 122,
    EXIST = 17,
    FAULT = 14,
    FBIG = 27,
    HOSTDOWN = 112,
    HOSTUNREACH = 113,
    HWPOISON = 133,
    IDRM = 43,
    ILSEQ = 84,
    INPROGRESS = 115,
    INTR = 4,
    INVAL = 22,
    IO = 5,
    ISCONN = 106,
    ISDIR = 21,
    ISNAM = 120,
    KEYEXPIRED = 127,
    KEYREJECTED = 129,
    KEYREVOKED = 128,
    L2HLT = 51,
    L2NSYNC = 45,
    L3HLT = 46,
    L3RST = 47,
    LIBACC = 79,
    LIBBAD = 80,
    LIBEXEC = 83,
    LIBMAX = 82,
    LIBSCN = 81,
    LNRNG = 48,
    LOOP = 40,
    MEDIUMTYPE = 124,
    MFILE = 24,
    MLINK = 31,
    MSGSIZE = 90,
    MULTIHOP = 72,
    NAMETOOLONG = 36,
    NAVAIL = 119,
    NETDOWN = 100,
    NETRESET = 102,
    NETUNREACH = 101,
    NFILE = 23,
    NOANO = 55,
    NOBUFS = 105,
    NOCSI = 50,
    NODATA = 61,
    NODEV = 19,
    NOENT = 2,
    NOEXEC = 8,
    NOKEY = 126,
    NOLCK = 37,
    NOLINK = 67,
    NOMEDIUM = 123,
    NOMEM = 12,
    NOMSG = 42,
    NONET = 64,
    NOPKG = 65,
    NOPROTOOPT = 92,
    NOSPC = 28,
    NOSR = 63,
    NOSTR = 60,
    NOSYS = 38,
    NOTBLK = 15,
    NOTCONN = 107,
    NOTDIR = 20,
    NOTEMPTY = 39,
    NOTNAM = 118,
    NOTRECOVERABLE = 131,
    NOTSOCK = 88,
    NOTSUP = 95,
    NOTTY = 25,
    NOTUNIQ = 76,
    NXIO = 6,
    OPNOTSUPP = 95,
    OVERFLOW = 75,
    OWNERDEAD = 130,
    PERM = 1,
    PFNOSUPPORT = 96,
    PIPE = 32,
    PROTO = 71,
    PROTONOSUPPORT = 93,
    PROTOTYPE = 91,
    RANGE = 34,
    REMCHG = 78,
    REMOTE = 66,
    REMOTEIO = 121,
    RESTART = 85,
    RFKILL = 132,
    ROFS = 30,
    SHUTDOWN = 108,
    SOCKTNOSUPPORT = 94,
    SPIPE = 29,
    SRCH = 3,
    SRMNT = 69,
    STALE = 116,
    STRPIPE = 86,
    TIME = 62,
    TIMEDOUT = 110,
    TOOBIG = 7,
    TOOMANYREFS = 109,
    TXTBSY = 26,
    UCLEAN = 117,
    UNATCH = 49,
    USERS = 87,
    WOULDBLOCK = 11,
    XDEV = 18,
    XFULL = 54,
}

impl fmt::Display for Errno {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.raw().fmt(formatter)
    }
}

/// A typed result from an internal kernel operation.
pub type Result<T> = core::result::Result<T, Errno>;

/// A raw Linux file descriptor for use only at this internal boundary.
pub type RawFd = i32;

/// The special `*at` descriptor representing the process current directory.
pub const AT_FDCWD: RawFd = -100;

const MAX_ERRNO: i32 = 4095;
const SYS_READ: usize = 63;
const SYS_WRITE: usize = 64;
const SYS_LSEEK: usize = 62;
const SYS_FCNTL: usize = 25;
const SYS_DUP: usize = 23;
const SYS_DUP3: usize = 24;
const SYS_CLOSE: usize = 57;
const SYS_FLOCK: usize = 32;
const SYS_OPENAT: usize = 56;
const SYS_IOCTL: usize = 29;
const SYS_MKDIRAT: usize = 34;
const SYS_UNLINKAT: usize = 35;
const SYS_SYMLINKAT: usize = 36;
const SYS_LINKAT: usize = 37;
const SYS_FCHMOD: usize = 52;
const SYS_FCHMODAT: usize = 53;
const SYS_FTRUNCATE: usize = 46;
const SYS_FSYNC: usize = 82;
const SYS_FDATASYNC: usize = 83;
const SYS_GETDENTS64: usize = 61;
const SYS_NEWFSTATAT: usize = 79;
const SYS_READLINKAT: usize = 78;
const SYS_FSTAT: usize = 80;
const SYS_UTIMENSAT: usize = 88;
const SYS_RENAMEAT2: usize = 276;
const SYS_OPENAT2: usize = 437;
const SYS_SETXATTR: usize = 5;
const SYS_LSETXATTR: usize = 6;
const SYS_FSETXATTR: usize = 7;
const SYS_GETXATTR: usize = 8;
const SYS_LGETXATTR: usize = 9;
const SYS_FGETXATTR: usize = 10;
const SYS_LISTXATTR: usize = 11;
const SYS_LLISTXATTR: usize = 12;
const SYS_FLISTXATTR: usize = 13;
const SYS_REMOVEXATTR: usize = 14;
const SYS_LREMOVEXATTR: usize = 15;
const SYS_FREMOVEXATTR: usize = 16;
const SYS_PIPE2: usize = 59;
const SYS_CLOCK_GETTIME: usize = 113;
const SYS_CLOCK_GETRES: usize = 114;
const SYS_GETRANDOM: usize = 278;
const SYS_EVENTFD2: usize = 19;
const SYS_PPOLL: usize = 73;
const SYS_EPOLL_CREATE1: usize = 20;
const SYS_EPOLL_CTL: usize = 21;
const SYS_EPOLL_PWAIT: usize = 22;
const SYS_TIMERFD_CREATE: usize = 85;
const SYS_TIMERFD_SETTIME: usize = 86;
const SYS_TIMERFD_GETTIME: usize = 87;
const SYS_SOCKETPAIR: usize = 199;
const SYS_SENDTO: usize = 206;
const SYS_RECVFROM: usize = 207;
const SYS_MUNMAP: usize = 215;
const SYS_MMAP: usize = 222;
const SYS_MPROTECT: usize = 226;
const SYS_KILL: usize = 129;
const SYS_MOUNT: usize = 40;
const SYS_UMOUNT2: usize = 39;
const SYS_GETPGID: usize = 155;
const SYS_SETPGID: usize = 154;
const SYS_GETSID: usize = 156;
const SYS_SETSID: usize = 157;
const SYS_UNAME: usize = 160;
const SYS_GETPID: usize = 172;
const SYS_GETPPID: usize = 173;
const SYS_GETTID: usize = 178;
const SYS_SYSINFO: usize = 179;
const SYS_SCHED_YIELD: usize = 124;

#[inline(always)]
unsafe fn syscall0(number: usize) -> isize {
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
unsafe fn syscall1(number: usize, arg0: usize) -> isize {
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
unsafe fn syscall2(number: usize, arg0: usize, arg1: usize) -> isize {
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
unsafe fn syscall3(number: usize, arg0: usize, arg1: usize, arg2: usize) -> isize {
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
unsafe fn syscall4(
    number: usize,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
) -> isize {
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
unsafe fn syscall5(
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
unsafe fn syscall6(
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
fn decode(result: isize) -> Result<usize> {
    if result < 0 && result >= -(MAX_ERRNO as isize) {
        // SAFETY: Linux's syscall error convention constrains this to 1..=4095.
        return Err(unsafe { Errno(NonZeroI32::new_unchecked((-result) as i32)) });
    }
    Ok(result as usize)
}

#[inline]
fn decode_i32(result: isize) -> Result<i32> {
    if result < 0 && result >= -(MAX_ERRNO as isize) {
        // SAFETY: Linux's syscall error convention constrains this to 1..=4095.
        return Err(unsafe { Errno(NonZeroI32::new_unchecked((-result) as i32)) });
    }
    Ok(result as i32)
}

#[inline]
fn decode_i64(result: isize) -> Result<i64> {
    if result < 0 && result >= -(MAX_ERRNO as isize) {
        // SAFETY: Linux's syscall error convention constrains this to 1..=4095.
        return Err(unsafe { Errno(NonZeroI32::new_unchecked((-result) as i32)) });
    }
    Ok(result as i64)
}

/// Direct descriptor I/O operations.
pub mod io {
    use super::{
        decode, decode_i32, syscall1, syscall3, RawFd, Result, SYS_CLOSE, SYS_DUP,
        SYS_DUP3, SYS_FCNTL, SYS_IOCTL, SYS_READ, SYS_WRITE,
    };

    /// Linux `F_DUPFD`: duplicate at or above the requested descriptor.
    pub const F_DUPFD: i32 = 0;
    /// Linux `F_GETFD`: read descriptor flags.
    pub const F_GETFD: i32 = 1;
    /// Linux `F_SETFD`: replace descriptor flags.
    pub const F_SETFD: i32 = 2;
    /// Linux `F_DUPFD_CLOEXEC`: duplicate with close-on-exec set.
    pub const F_DUPFD_CLOEXEC: i32 = 1_030;
    /// Linux `FD_CLOEXEC` descriptor flag.
    pub const FD_CLOEXEC: u32 = 1;
    /// Linux `O_CLOEXEC` flag accepted by `dup3`.
    pub const O_CLOEXEC: u32 = 0x80000;

    /// Duplicates `fd` to the lowest available descriptor.
    #[inline]
    pub fn dup(fd: RawFd) -> Result<RawFd> {
        // SAFETY: The kernel validates the descriptor and this syscall has one
        // integer argument with no Rust memory preconditions.
        decode_i32(unsafe { syscall1(SYS_DUP, fd as usize) })
    }

    /// Duplicates `fd` onto `new_fd` with Linux `dup3` flags.
    ///
    /// This is the direct primitive used for both Rustix's `dup2` and `dup3`
    /// operations on AArch64, where Linux exposes no separate `dup2` syscall.
    /// The caller owns the target descriptor and must preserve that ownership
    /// regardless of the result.
    #[inline]
    pub fn dup3(fd: RawFd, new_fd: RawFd, flags: u32) -> Result<()> {
        // SAFETY: The kernel validates both descriptors and the flags; this
        // syscall has no Rust memory arguments.
        decode(unsafe {
            syscall3(
                SYS_DUP3,
                fd as usize,
                new_fd as usize,
                flags as usize,
            )
        })
        .map(|_| ())
    }

    /// Performs Rustix/POSIX `dup2` semantics on AArch64.
    ///
    /// Linux implements this through `dup3`. Unlike `dup3`, equal source and
    /// target descriptors are a successful no-op, as required by `dup2`.
    #[inline]
    pub fn dup2(fd: RawFd, new_fd: RawFd) -> Result<()> {
        if fd == new_fd {
            return Ok(());
        }
        dup3(fd, new_fd, 0)
    }

    /// Reads `FD_*` flags through `fcntl(F_GETFD)`.
    #[inline]
    pub fn fcntl_getfd(fd: RawFd) -> Result<u32> {
        // SAFETY: F_GETFD ignores its third argument; zero is the canonical
        // immediate argument representation on Linux.
        unsafe { fcntl_raw(fd, F_GETFD, core::ptr::null_mut()) }.map(|flags| flags as u32)
    }

    /// Replaces `FD_*` flags through `fcntl(F_SETFD)`.
    #[inline]
    pub fn fcntl_setfd(fd: RawFd, flags: u32) -> Result<()> {
        // SAFETY: F_SETFD takes an immediate integer in the third syscall
        // argument; `fcntl_raw` encodes that integer without dereferencing it.
        unsafe { fcntl_raw(fd, F_SETFD, flags as usize as *mut u8) }.map(|_| ())
    }

    /// Duplicates `fd` at or above `minimum` through `fcntl(F_DUPFD)`.
    #[inline]
    pub fn fcntl_dupfd(fd: RawFd, minimum: RawFd) -> Result<RawFd> {
        // SAFETY: F_DUPFD takes an immediate integer in the third syscall
        // argument; `fcntl_raw` encodes that integer without dereferencing it.
        unsafe { fcntl_raw(fd, F_DUPFD, minimum as u32 as usize as *mut u8) }
    }

    /// Duplicates `fd` at or above `minimum` with close-on-exec set.
    #[inline]
    pub fn fcntl_dupfd_cloexec(fd: RawFd, minimum: RawFd) -> Result<RawFd> {
        // SAFETY: F_DUPFD_CLOEXEC takes an immediate integer in the third
        // syscall argument; `fcntl_raw` encodes that integer directly.
        unsafe {
            fcntl_raw(
                fd,
                F_DUPFD_CLOEXEC,
                minimum as u32 as usize as *mut u8,
            )
        }
    }

    /// Reads into a raw C-compatible buffer without using libc or TLS `errno`.
    ///
    /// # Safety
    ///
    /// `buffer` must be valid for mutable access to `length` bytes for the
    /// duration of the call, unless `length` is zero. The descriptor's I/O
    /// safety is the caller's responsibility.
    #[inline]
    pub unsafe fn read_raw(fd: RawFd, buffer: *mut u8, length: usize) -> Result<usize> {
        // SAFETY: The caller supplies the raw-buffer validity contract and the
        // kernel validates the descriptor.
        decode(unsafe { syscall3(SYS_READ, fd as usize, buffer as usize, length) })
    }

    /// Reads into `buffer` without using libc or TLS `errno`.
    #[inline]
    pub fn read(fd: RawFd, buffer: &mut [u8]) -> Result<usize> {
        // SAFETY: A slice supplies a valid mutable buffer for the exact length.
        unsafe { read_raw(fd, buffer.as_mut_ptr(), buffer.len()) }
    }

    /// Writes a raw C-compatible buffer without using libc or TLS `errno`.
    ///
    /// # Safety
    ///
    /// `buffer` must be valid for immutable access to `length` bytes for the
    /// duration of the call, unless `length` is zero. The descriptor's I/O
    /// safety is the caller's responsibility.
    #[inline]
    pub unsafe fn write_raw(fd: RawFd, buffer: *const u8, length: usize) -> Result<usize> {
        // SAFETY: The caller supplies the raw-buffer validity contract and the
        // kernel validates the descriptor.
        decode(unsafe { syscall3(SYS_WRITE, fd as usize, buffer as usize, length) })
    }

    /// Writes `buffer` without using libc or TLS `errno`.
    #[inline]
    pub fn write(fd: RawFd, buffer: &[u8]) -> Result<usize> {
        // SAFETY: A slice supplies a valid immutable buffer for the exact length.
        unsafe { write_raw(fd, buffer.as_ptr(), buffer.len()) }
    }

    /// Performs an ioctl without using libc or TLS `errno`.
    ///
    /// Linux ioctl returns a signed C `int`. Only the kernel's negative errno
    /// range is an error; other negative values are successful ioctl results
    /// and are preserved exactly in the returned `i32`.
    ///
    /// # Safety
    ///
    /// `argument` must satisfy the memory contract of `request` for the
    /// duration of the call. Requests that carry an integer may pass that
    /// integer through the pointer value without dereferencing it.
    #[inline]
    pub unsafe fn ioctl_raw(fd: RawFd, request: u32, argument: *mut u8) -> Result<i32> {
        // SAFETY: The caller supplies the request-specific argument contract;
        // the kernel validates the descriptor and request.
        decode_i32(unsafe {
            syscall3(SYS_IOCTL, fd as usize, request as usize, argument as usize)
        })
    }

    /// Performs Linux `fcntl` without using libc or TLS `errno`.
    ///
    /// # Safety
    ///
    /// `argument` must satisfy the command-specific Linux `fcntl` contract.
    /// Commands using immediate integers must encode that intent explicitly;
    /// pointer commands must keep their storage valid for the call.
    #[inline]
    pub unsafe fn fcntl_raw(fd: RawFd, command: i32, argument: *mut u8) -> Result<i32> {
        // SAFETY: The caller supplies the command-specific argument contract.
        decode_i32(unsafe {
            syscall3(SYS_FCNTL, fd as usize, command as usize, argument as usize)
        })
    }

    /// Closes a raw descriptor without using libc or TLS `errno`.
    #[inline]
    pub fn close(fd: RawFd) -> Result<()> {
        // SAFETY: The kernel validates the descriptor; `close` has one integer
        // argument and no Rust memory preconditions.
        decode(unsafe { syscall1(SYS_CLOSE, fd as usize) }).map(|_| ())
    }
}

/// Direct stateless filesystem operations.
pub mod fs {
    use super::{
        decode, decode_i64, syscall1, syscall2, syscall3, syscall4, syscall5, CStr, RawFd,
        Result, SYS_FCHMOD, SYS_FCHMODAT, SYS_FDATASYNC, SYS_FLOCK, SYS_FSTAT,
        SYS_FSYNC, SYS_FTRUNCATE, SYS_GETDENTS64, SYS_LINKAT, SYS_FGETXATTR,
        SYS_FLISTXATTR, SYS_FREMOVEXATTR, SYS_FSETXATTR, SYS_GETXATTR, SYS_LGETXATTR,
        SYS_LLISTXATTR, SYS_LREMOVEXATTR, SYS_LSEEK, SYS_LSETXATTR, SYS_LISTXATTR,
        SYS_MKDIRAT, SYS_NEWFSTATAT, SYS_OPENAT, SYS_OPENAT2, SYS_READLINKAT,
        SYS_REMOVEXATTR, SYS_RENAMEAT2, SYS_SETXATTR, SYS_SYMLINKAT, SYS_UNLINKAT,
        SYS_UTIMENSAT,
    };

    /// Linux `SEEK_SET`: position from the beginning of the file.
    pub const SEEK_SET: u32 = 0;
    /// Linux `SEEK_CUR`: position relative to the current file offset.
    pub const SEEK_CUR: u32 = 1;
    /// Linux `SEEK_END`: position relative to the end of the file.
    pub const SEEK_END: u32 = 2;
    /// Linux `SEEK_DATA`: position at the next data region.
    pub const SEEK_DATA: u32 = 3;
    /// Linux `SEEK_HOLE`: position at the next hole.
    pub const SEEK_HOLE: u32 = 4;

    /// Repositions a descriptor using Linux's `lseek` ABI without using libc
    /// or TLS `errno`.
    ///
    /// The signed `offset` is the kernel's `off_t` representation. The
    /// returned position is signed at this low-level boundary because it is
    /// the direct syscall result; successful Linux seeks are non-negative.
    #[inline]
    pub fn lseek(fd: RawFd, offset: i64, whence: u32) -> Result<i64> {
        // SAFETY: The kernel validates the descriptor, offset, and whence.
        decode_i64(unsafe {
            syscall3(
                SYS_LSEEK,
                fd as usize,
                offset as usize,
                whence as usize,
            )
        })
    }

    /// Flushes file data and metadata for an open descriptor without using
    /// libc or TLS `errno`.
    #[inline]
    pub fn fsync(fd: RawFd) -> Result<()> {
        // SAFETY: The kernel validates the descriptor.
        decode(unsafe { syscall1(SYS_FSYNC, fd as usize) }).map(|_| ())
    }

    /// Flushes file data for an open descriptor without using libc or TLS
    /// `errno`.
    #[inline]
    pub fn fdatasync(fd: RawFd) -> Result<()> {
        // SAFETY: The kernel validates the descriptor.
        decode(unsafe { syscall1(SYS_FDATASYNC, fd as usize) }).map(|_| ())
    }

    /// Sets the length of an open file without using libc or TLS `errno`.
    ///
    /// `length` is the signed Linux `loff_t` representation. The kernel
    /// rejects negative lengths with `EINVAL`; retaining that representation
    /// here keeps this seam a direct syscall boundary.
    #[inline]
    pub fn ftruncate(fd: RawFd, length: i64) -> Result<()> {
        // SAFETY: The kernel validates the descriptor and signed file length.
        decode(unsafe { syscall2(SYS_FTRUNCATE, fd as usize, length as usize) }).map(|_| ())
    }

    /// Opens a raw C-compatible path relative to `dirfd` without using libc or
    /// TLS `errno`.
    ///
    /// # Safety
    ///
    /// `path` must point to a NUL-terminated pathname readable by the kernel.
    /// The descriptor's I/O safety is the caller's responsibility.
    #[inline]
    pub unsafe fn openat_raw(
        dirfd: RawFd,
        path: *const u8,
        flags: i32,
        mode: u32,
    ) -> Result<RawFd> {
        // SAFETY: The caller supplies the C-string validity contract. The
        // kernel validates the descriptor and flag/mode combinations.
        decode(unsafe {
            syscall4(
                SYS_OPENAT,
                dirfd as usize,
                path as usize,
                flags as usize,
                mode as usize,
            )
        })
        .map(|fd| fd as RawFd)
    }

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    /// Opens a raw C-compatible path with Linux `openat2` without using libc
    /// or TLS `errno`.
    ///
    /// # Safety
    ///
    /// `path` must point to a NUL-terminated pathname readable by the kernel.
    /// The descriptor's I/O safety is the caller's responsibility.
    #[inline]
    pub unsafe fn openat2_raw(
        dirfd: RawFd,
        path: *const u8,
        flags: u64,
        mode: u64,
        resolve: u64,
    ) -> Result<RawFd> {
        let how = OpenHow {
            flags,
            mode,
            resolve,
        };
        // SAFETY: The caller supplies the C-string validity contract. `how`
        // is the exact Linux/AArch64 open_how ABI and stays live for the call.
        decode(unsafe {
            syscall4(
                SYS_OPENAT2,
                dirfd as usize,
                path as usize,
                core::ptr::addr_of!(how) as usize,
                core::mem::size_of::<OpenHow>(),
            )
        })
        .map(|fd| fd as RawFd)
    }

    /// Opens a C string with Linux `openat2` without using libc or TLS
    /// `errno`.
    #[inline]
    pub fn openat2(
        dirfd: RawFd,
        path: &CStr,
        flags: u64,
        mode: u64,
        resolve: u64,
    ) -> Result<RawFd> {
        // SAFETY: `CStr` supplies a NUL-terminated pathname that remains live
        // for the exact duration of this direct syscall.
        unsafe { openat2_raw(dirfd, path.as_ptr().cast(), flags, mode, resolve) }
    }

    /// Opens `path` relative to `dirfd` without using libc or TLS `errno`.
    ///
    /// `flags` and `mode` retain their Linux C ABI bit representations at this
    /// private, typed-operation boundary; the public Rust facade supplies
    /// strong flag and mode types.
    #[inline]
    pub fn openat(dirfd: RawFd, path: &CStr, flags: i32, mode: u32) -> Result<RawFd> {
        // SAFETY: `CStr` guarantees the raw C-string contract required above.
        unsafe { openat_raw(dirfd, path.as_ptr().cast(), flags, mode) }
    }

    /// Queries the Linux/AArch64 `struct stat` representation for `fd`.
    ///
    /// # Safety
    ///
    /// `buffer` must designate writable storage for the complete target
    /// Linux/AArch64 `struct stat` layout. The descriptor's I/O safety is the
    /// caller's responsibility.
    #[inline]
    pub unsafe fn fstat_raw(fd: RawFd, buffer: *mut u8) -> Result<()> {
        // SAFETY: The caller supplies complete writable `struct stat`
        // storage; the kernel validates the descriptor.
        decode(unsafe { syscall2(SYS_FSTAT, fd as usize, buffer as usize) }).map(|_| ())
    }

    /// Queries the Linux/AArch64 `struct stat` representation for a C path
    /// relative to `dirfd`.
    ///
    /// # Safety
    ///
    /// `path` must point to a readable NUL-terminated pathname and `buffer`
    /// must designate writable storage for the complete target
    /// Linux/AArch64 `struct stat` layout.
    #[inline]
    pub unsafe fn statat_raw(
        dirfd: RawFd,
        path: *const u8,
        buffer: *mut u8,
        flags: u32,
    ) -> Result<()> {
        // SAFETY: The caller supplies the C-string and output-layout
        // contracts; the kernel validates the descriptor and flags.
        decode(unsafe {
            syscall4(
                SYS_NEWFSTATAT,
                dirfd as usize,
                path as usize,
                buffer as usize,
                flags as usize,
            )
        })
        .map(|_| ())
    }

    /// Queries metadata for `path` relative to `dirfd` without using libc or
    /// TLS `errno`.
    ///
    /// # Safety
    ///
    /// `buffer` must designate writable storage for the complete target
    /// Linux/AArch64 `struct stat` layout.
    #[inline]
    pub unsafe fn statat(
        dirfd: RawFd,
        path: &CStr,
        buffer: *mut u8,
        flags: u32,
    ) -> Result<()> {
        // SAFETY: `CStr` establishes the pathname contract; the caller
        // supplies the output-layout contract.
        unsafe { statat_raw(dirfd, path.as_ptr().cast(), buffer, flags) }
    }

    /// Removes `path` relative to `dirfd` without using libc or TLS `errno`.
    #[inline]
    pub fn unlinkat(dirfd: RawFd, path: &CStr, flags: u32) -> Result<()> {
        // SAFETY: `CStr` guarantees the pathname is readable and
        // NUL-terminated; the kernel validates descriptor and flags.
        decode(unsafe {
            syscall3(
                SYS_UNLINKAT,
                dirfd as usize,
                path.as_ptr() as usize,
                flags as usize,
            )
        })
        .map(|_| ())
    }

    /// Creates a directory relative to `dirfd` without using libc or TLS
    /// `errno`.
    #[inline]
    pub fn mkdirat(dirfd: RawFd, path: &CStr, mode: u32) -> Result<()> {
        // SAFETY: `CStr` guarantees the pathname is readable and
        // NUL-terminated; the kernel validates descriptor and mode bits.
        decode(unsafe {
            syscall3(
                SYS_MKDIRAT,
                dirfd as usize,
                path.as_ptr() as usize,
                mode as usize,
            )
        })
        .map(|_| ())
    }

    /// Reads a symbolic-link target relative to `dirfd` without using libc or
    /// TLS `errno`.
    ///
    /// # Safety
    ///
    /// `buffer` must be writable for `length` bytes for the duration of the
    /// call. A successful result reports the initialized prefix length and is
    /// never NUL-terminated by the kernel.
    #[inline]
    pub unsafe fn readlinkat_raw(
        dirfd: RawFd,
        path: &CStr,
        buffer: *mut u8,
        length: usize,
    ) -> Result<usize> {
        // SAFETY: `CStr` supplies the input pathname; the caller supplies
        // writable output storage for exactly `length` bytes.
        decode(unsafe {
            syscall4(
                SYS_READLINKAT,
                dirfd as usize,
                path.as_ptr() as usize,
                buffer as usize,
                length,
            )
        })
    }

    /// Creates a hard link without using libc or TLS `errno`.
    #[inline]
    pub fn linkat(
        old_dirfd: RawFd,
        old_path: &CStr,
        new_dirfd: RawFd,
        new_path: &CStr,
        flags: u32,
    ) -> Result<()> {
        // SAFETY: Both `CStr` inputs are readable NUL-terminated paths; the
        // kernel validates descriptors and link flags.
        decode(unsafe {
            syscall5(
                SYS_LINKAT,
                old_dirfd as usize,
                old_path.as_ptr() as usize,
                new_dirfd as usize,
                new_path.as_ptr() as usize,
                flags as usize,
            )
        })
        .map(|_| ())
    }

    /// Renames a path without using libc or TLS `errno`.
    #[inline]
    pub fn renameat2(
        old_dirfd: RawFd,
        old_path: &CStr,
        new_dirfd: RawFd,
        new_path: &CStr,
        flags: u32,
    ) -> Result<()> {
        // SAFETY: Both `CStr` inputs are readable NUL-terminated paths; the
        // kernel validates descriptors and rename flags.
        decode(unsafe {
            syscall5(
                SYS_RENAMEAT2,
                old_dirfd as usize,
                old_path.as_ptr() as usize,
                new_dirfd as usize,
                new_path.as_ptr() as usize,
                flags as usize,
            )
        })
        .map(|_| ())
    }

    /// Creates a symbolic link without using libc or TLS `errno`.
    #[inline]
    pub fn symlinkat(target: &CStr, new_dirfd: RawFd, new_path: &CStr) -> Result<()> {
        // SAFETY: Both `CStr` inputs are readable NUL-terminated paths; the
        // kernel validates the descriptor.
        decode(unsafe {
            syscall3(
                SYS_SYMLINKAT,
                target.as_ptr() as usize,
                new_dirfd as usize,
                new_path.as_ptr() as usize,
            )
        })
        .map(|_| ())
    }

    /// Changes permissions for an open descriptor without using libc or TLS
    /// `errno`.
    #[inline]
    pub fn fchmod(fd: RawFd, mode: u32) -> Result<()> {
        // SAFETY: The kernel validates the descriptor and permission bits.
        decode(unsafe { syscall2(SYS_FCHMOD, fd as usize, mode as usize) }).map(|_| ())
    }

    /// Changes permissions for `path` relative to `dirfd` without using libc
    /// or TLS `errno`.
    #[inline]
    pub fn fchmodat(dirfd: RawFd, path: &CStr, mode: u32, flags: u32) -> Result<()> {
        // SAFETY: `CStr` supplies the input pathname; the kernel validates the
        // descriptor, permission bits, and flags.
        decode(unsafe {
            syscall4(
                SYS_FCHMODAT,
                dirfd as usize,
                path.as_ptr() as usize,
                mode as usize,
                flags as usize,
            )
        })
        .map(|_| ())
    }

    /// Invokes Linux `utimensat` without using libc or TLS `errno`.
    ///
    /// # Safety
    ///
    /// `path` may be null only for the kernel-defined `futimens` form. When
    /// non-null it must point to a readable NUL-terminated pathname. `times`
    /// must point to two target-Linux `timespec` values for the duration of
    /// the call.
    #[inline]
    pub unsafe fn utimensat_raw(
        dirfd: RawFd,
        path: *const u8,
        times: *const u8,
        flags: u32,
    ) -> Result<()> {
        // SAFETY: The caller supplies the nullable pathname and two-timespec
        // layout contracts; the kernel validates descriptor and flags.
        decode(unsafe {
            syscall4(
                SYS_UTIMENSAT,
                dirfd as usize,
                path as usize,
                times as usize,
                flags as usize,
            )
        })
        .map(|_| ())
    }

    /// Reads raw Linux `getdents64` records without using libc or TLS errno.
    ///
    /// # Safety
    ///
    /// `buffer` must be writable for `length` bytes for the duration of the
    /// call. On success the returned prefix contains kernel `linux_dirent64`
    /// records, which still require record-by-record validation by a facade.
    #[inline]
    pub unsafe fn getdents64_raw(
        fd: RawFd,
        buffer: *mut u8,
        length: usize,
    ) -> Result<usize> {
        // SAFETY: The caller supplies writable output storage for exactly
        // `length` bytes; the kernel validates the directory descriptor.
        decode(unsafe { syscall3(SYS_GETDENTS64, fd as usize, buffer as usize, length) })
    }

    /// Applies a Linux `flock` operation without using libc or TLS `errno`.
    #[inline]
    pub fn flock(fd: RawFd, operation: u32) -> Result<()> {
        // SAFETY: The kernel validates descriptor and flock operation bits.
        decode(unsafe { syscall2(SYS_FLOCK, fd as usize, operation as usize) }).map(|_| ())
    }

    /// Sets an extended attribute without using libc or TLS `errno`.
    ///
    /// # Safety
    ///
    /// `path` and `name` must point to readable NUL-terminated strings.
    /// `value` must be readable for `length` bytes unless `length` is zero.
    #[inline]
    pub unsafe fn setxattr_raw(
        path: *const u8,
        name: *const u8,
        value: *const u8,
        length: usize,
        flags: u32,
    ) -> Result<()> {
        // SAFETY: The caller supplies the pathname/name/value memory
        // contracts; Linux validates flags and filesystem support.
        decode(unsafe {
            syscall5(
                SYS_SETXATTR,
                path as usize,
                name as usize,
                value as usize,
                length,
                flags as usize,
            )
        })
        .map(|_| ())
    }

    /// Sets a no-follow-path extended attribute without using libc or TLS
    /// `errno`.
    ///
    /// # Safety
    ///
    /// Same memory requirements as [`setxattr_raw`].
    #[inline]
    pub unsafe fn lsetxattr_raw(
        path: *const u8,
        name: *const u8,
        value: *const u8,
        length: usize,
        flags: u32,
    ) -> Result<()> {
        // SAFETY: The caller supplies the pathname/name/value memory
        // contracts; Linux validates flags and filesystem support.
        decode(unsafe {
            syscall5(
                SYS_LSETXATTR,
                path as usize,
                name as usize,
                value as usize,
                length,
                flags as usize,
            )
        })
        .map(|_| ())
    }

    /// Sets a descriptor extended attribute without using libc or TLS
    /// `errno`.
    ///
    /// # Safety
    ///
    /// `name` must point to a readable NUL-terminated string. `value` must be
    /// readable for `length` bytes unless `length` is zero.
    #[inline]
    pub unsafe fn fsetxattr_raw(
        fd: RawFd,
        name: *const u8,
        value: *const u8,
        length: usize,
        flags: u32,
    ) -> Result<()> {
        // SAFETY: The caller supplies the name/value memory contracts; Linux
        // validates descriptor, flags, and filesystem support.
        decode(unsafe {
            syscall5(
                SYS_FSETXATTR,
                fd as usize,
                name as usize,
                value as usize,
                length,
                flags as usize,
            )
        })
        .map(|_| ())
    }

    /// Reads an extended attribute without using libc or TLS `errno`.
    ///
    /// # Safety
    ///
    /// `path` and `name` must point to readable NUL-terminated strings.
    /// `value` must be writable for `length` bytes unless `length` is zero.
    #[inline]
    pub unsafe fn getxattr_raw(
        path: *const u8,
        name: *const u8,
        value: *mut u8,
        length: usize,
    ) -> Result<usize> {
        // SAFETY: The caller supplies the pathname/name/output memory
        // contracts; Linux validates filesystem support.
        decode(unsafe {
            syscall4(
                SYS_GETXATTR,
                path as usize,
                name as usize,
                value as usize,
                length,
            )
        })
    }

    /// Reads a no-follow-path extended attribute without using libc or TLS
    /// `errno`.
    ///
    /// # Safety
    ///
    /// Same memory requirements as [`getxattr_raw`].
    #[inline]
    pub unsafe fn lgetxattr_raw(
        path: *const u8,
        name: *const u8,
        value: *mut u8,
        length: usize,
    ) -> Result<usize> {
        // SAFETY: The caller supplies the pathname/name/output memory
        // contracts; Linux validates filesystem support.
        decode(unsafe {
            syscall4(
                SYS_LGETXATTR,
                path as usize,
                name as usize,
                value as usize,
                length,
            )
        })
    }

    /// Reads a descriptor extended attribute without using libc or TLS
    /// `errno`.
    ///
    /// # Safety
    ///
    /// `name` must point to a readable NUL-terminated string. `value` must be
    /// writable for `length` bytes unless `length` is zero.
    #[inline]
    pub unsafe fn fgetxattr_raw(
        fd: RawFd,
        name: *const u8,
        value: *mut u8,
        length: usize,
    ) -> Result<usize> {
        // SAFETY: The caller supplies the name/output memory contracts; Linux
        // validates descriptor and filesystem support.
        decode(unsafe {
            syscall4(
                SYS_FGETXATTR,
                fd as usize,
                name as usize,
                value as usize,
                length,
            )
        })
    }

    /// Lists path extended attributes without using libc or TLS `errno`.
    ///
    /// # Safety
    ///
    /// `path` must point to a readable NUL-terminated string. `list` must be
    /// writable for `length` bytes unless `length` is zero.
    #[inline]
    pub unsafe fn listxattr_raw(
        path: *const u8,
        list: *mut u8,
        length: usize,
    ) -> Result<usize> {
        // SAFETY: The caller supplies the pathname/output memory contracts.
        decode(unsafe { syscall3(SYS_LISTXATTR, path as usize, list as usize, length) })
    }

    /// Lists no-follow-path extended attributes without using libc or TLS
    /// `errno`.
    ///
    /// # Safety
    ///
    /// Same memory requirements as [`listxattr_raw`].
    #[inline]
    pub unsafe fn llistxattr_raw(
        path: *const u8,
        list: *mut u8,
        length: usize,
    ) -> Result<usize> {
        // SAFETY: The caller supplies the pathname/output memory contracts.
        decode(unsafe { syscall3(SYS_LLISTXATTR, path as usize, list as usize, length) })
    }

    /// Lists descriptor extended attributes without using libc or TLS
    /// `errno`.
    ///
    /// # Safety
    ///
    /// `list` must be writable for `length` bytes unless `length` is zero.
    #[inline]
    pub unsafe fn flistxattr_raw(
        fd: RawFd,
        list: *mut u8,
        length: usize,
    ) -> Result<usize> {
        // SAFETY: The caller supplies the output memory contract; Linux
        // validates descriptor and filesystem support.
        decode(unsafe { syscall3(SYS_FLISTXATTR, fd as usize, list as usize, length) })
    }

    /// Removes a path extended attribute without using libc or TLS `errno`.
    ///
    /// # Safety
    ///
    /// `path` and `name` must point to readable NUL-terminated strings.
    #[inline]
    pub unsafe fn removexattr_raw(path: *const u8, name: *const u8) -> Result<()> {
        // SAFETY: The caller supplies the pathname/name memory contracts.
        decode(unsafe { syscall2(SYS_REMOVEXATTR, path as usize, name as usize) }).map(|_| ())
    }

    /// Removes a no-follow-path extended attribute without using libc or TLS
    /// `errno`.
    ///
    /// # Safety
    ///
    /// Same memory requirements as [`removexattr_raw`].
    #[inline]
    pub unsafe fn lremovexattr_raw(path: *const u8, name: *const u8) -> Result<()> {
        // SAFETY: The caller supplies the pathname/name memory contracts.
        decode(unsafe { syscall2(SYS_LREMOVEXATTR, path as usize, name as usize) }).map(|_| ())
    }

    /// Removes a descriptor extended attribute without using libc or TLS
    /// `errno`.
    ///
    /// # Safety
    ///
    /// `name` must point to a readable NUL-terminated string.
    #[inline]
    pub unsafe fn fremovexattr_raw(fd: RawFd, name: *const u8) -> Result<()> {
        // SAFETY: The caller supplies the name memory contract; Linux
        // validates descriptor and filesystem support.
        decode(unsafe { syscall2(SYS_FREMOVEXATTR, fd as usize, name as usize) }).map(|_| ())
    }
}

/// Direct pipe operations.
pub mod pipe {
    use super::{decode, syscall2, MaybeUninit, RawFd, Result, SYS_PIPE2};

    /// Creates a pipe in caller-provided Linux `int[2]` storage without using
    /// libc or TLS `errno`.
    ///
    /// # Safety
    ///
    /// `fds` must either point to writable storage for two Linux `int` values
    /// or be a pointer the caller intentionally passes through to the kernel.
    /// The latter preserves the C ABI's `EFAULT` behavior for an invalid
    /// pointer.
    #[inline]
    pub unsafe fn pipe2_raw(fds: *mut RawFd, flags: u32) -> Result<()> {
        // SAFETY: The caller owns the pointer contract. Linux validates both
        // the output storage and the supplied flags.
        decode(unsafe { syscall2(SYS_PIPE2, fds as usize, flags as usize) }).map(|_| ())
    }

    /// Creates a pipe with Linux `pipe2` without using libc or TLS `errno`.
    #[inline]
    pub fn pipe2(flags: u32) -> Result<(RawFd, RawFd)> {
        let mut fds = MaybeUninit::<[RawFd; 2]>::uninit();
        // SAFETY: `fds` provides writable storage for exactly two Linux C
        // ints. A successful pipe2 initializes both descriptors.
        unsafe { pipe2_raw(fds.as_mut_ptr().cast(), flags)? };
        // SAFETY: Linux pipe2 initialized both descriptors on the successful
        // return above; each is a newly owned non-negative descriptor.
        let [reader, writer] = unsafe { fds.assume_init() };
        Ok((reader, writer))
    }
}

/// Direct kernel random-source operations.
pub mod rand {
    use super::{decode, syscall3, Result, SYS_GETRANDOM};

    /// Reads random bytes without using libc or TLS `errno`.
    ///
    /// # Safety
    ///
    /// `buffer` must be writable for `length` bytes unless `length` is zero.
    #[inline]
    pub unsafe fn getrandom_raw(buffer: *mut u8, length: usize, flags: u32) -> Result<usize> {
        // SAFETY: The caller supplies the output-memory contract; Linux
        // validates the random-source flags.
        decode(unsafe { syscall3(SYS_GETRANDOM, buffer as usize, length, flags as usize) })
    }
}

/// Direct stateless clock queries.
pub mod time {
    use super::{decode, syscall2, syscall4, RawFd, Result, SYS_CLOCK_GETRES, SYS_CLOCK_GETTIME,
        SYS_TIMERFD_CREATE, SYS_TIMERFD_GETTIME, SYS_TIMERFD_SETTIME};

    /// Queries a Linux clock without using libc, vDSO dispatch, or TLS
    /// `errno`.
    ///
    /// # Safety
    ///
    /// `timespec` must be writable for one Linux/AArch64 `struct timespec`.
    #[inline]
    pub unsafe fn clock_gettime_raw(clock_id: i32, timespec: *mut u8) -> Result<()> {
        // SAFETY: The caller supplies exact output storage for the kernel
        // timespec layout; Linux validates the clock identifier.
        decode(unsafe { syscall2(SYS_CLOCK_GETTIME, clock_id as usize, timespec as usize) })
            .map(|_| ())
    }

    /// Queries the resolution of a Linux clock without using libc, vDSO
    /// dispatch, or TLS `errno`.
    ///
    /// # Safety
    ///
    /// `timespec` must be writable for one Linux/AArch64 `struct timespec`.
    #[inline]
    pub unsafe fn clock_getres_raw(clock_id: i32, timespec: *mut u8) -> Result<()> {
        // SAFETY: The caller supplies exact output storage for the kernel
        // timespec layout; Linux validates the clock identifier.
        decode(unsafe { syscall2(SYS_CLOCK_GETRES, clock_id as usize, timespec as usize) })
            .map(|_| ())
    }

    /// Creates a Linux timer descriptor without using libc or TLS `errno`.
    #[inline]
    pub fn timerfd_create(clock_id: i32, flags: u32) -> Result<RawFd> {
        // SAFETY: Linux validates the clock identifier and timer descriptor
        // flags; no user memory is accessed by this operation.
        decode(unsafe { super::syscall2(SYS_TIMERFD_CREATE, clock_id as usize, flags as usize) })
            .map(|fd| fd as RawFd)
    }

    /// Arms or disarms a Linux timer descriptor without using libc or TLS
    /// `errno`.
    ///
    /// # Safety
    ///
    /// `new_value` must point to one writable Linux/AArch64 `struct
    /// itimerspec`, and `old_value` must be null or point to writable storage
    /// for one such value.
    #[inline]
    pub unsafe fn timerfd_settime_raw(
        fd: RawFd,
        flags: u32,
        new_value: *const u8,
        old_value: *mut u8,
    ) -> Result<()> {
        // SAFETY: The caller owns the two `itimerspec` pointer contracts;
        // Linux validates the descriptor and timer flags.
        decode(unsafe {
            syscall4(
                SYS_TIMERFD_SETTIME,
                fd as usize,
                flags as usize,
                new_value as usize,
                old_value as usize,
            )
        })
        .map(|_| ())
    }

    /// Reads a Linux timer descriptor's current setting without using libc or
    /// TLS `errno`.
    ///
    /// # Safety
    ///
    /// `current_value` must point to writable storage for one Linux/AArch64
    /// `struct itimerspec`.
    #[inline]
    pub unsafe fn timerfd_gettime_raw(fd: RawFd, current_value: *mut u8) -> Result<()> {
        // SAFETY: The caller owns the output-memory contract; Linux validates
        // the descriptor.
        decode(unsafe {
            super::syscall2(SYS_TIMERFD_GETTIME, fd as usize, current_value as usize)
        })
        .map(|_| ())
    }
}

/// Direct event-descriptor and polling operations.
pub mod event {
    use super::{decode, syscall1, syscall2, syscall4, syscall5, syscall6, RawFd, Result,
        SYS_EPOLL_CREATE1, SYS_EPOLL_CTL, SYS_EPOLL_PWAIT, SYS_EVENTFD2, SYS_PPOLL};

    /// Creates a Linux event descriptor without using libc or TLS `errno`.
    #[inline]
    pub fn eventfd(initval: u32, flags: u32) -> Result<RawFd> {
        // SAFETY: Linux validates the initial value and flags.
        decode(unsafe { syscall2(SYS_EVENTFD2, initval as usize, flags as usize) })
            .map(|fd| fd as RawFd)
    }

    /// Creates a Linux epoll descriptor without using libc or TLS `errno`.
    #[inline]
    pub fn epoll_create1(flags: u32) -> Result<RawFd> {
        // SAFETY: Linux validates the epoll flags; no user memory is accessed
        // by this operation.
        decode(unsafe { syscall1(SYS_EPOLL_CREATE1, flags as usize) })
            .map(|fd| fd as RawFd)
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
}

/// Direct, connection-oriented Linux socket operations.
pub mod net {
    use super::{
        decode, syscall4, syscall6, MaybeUninit, RawFd, Result, SYS_RECVFROM, SYS_SENDTO,
        SYS_SOCKETPAIR,
    };

    /// Creates a socket pair in caller-provided Linux `int[2]` storage.
    ///
    /// # Safety
    ///
    /// `sockets` must point to writable storage for two Linux `int` values or
    /// be a pointer deliberately forwarded to preserve C ABI `EFAULT`
    /// behavior.
    #[inline]
    pub unsafe fn socketpair_raw(
        domain: i32,
        type_and_flags: u32,
        protocol: i32,
        sockets: *mut RawFd,
    ) -> Result<()> {
        // SAFETY: The caller owns the output-pointer contract. Linux validates
        // the domain, type/flags, and protocol.
        decode(unsafe {
            syscall4(
                SYS_SOCKETPAIR,
                domain as usize,
                type_and_flags as usize,
                protocol as usize,
                sockets as usize,
            )
        })
        .map(|_| ())
    }

    /// Creates a socket pair without using libc or TLS `errno`.
    #[inline]
    pub fn socketpair(
        domain: i32,
        type_and_flags: u32,
        protocol: i32,
    ) -> Result<(RawFd, RawFd)> {
        let mut sockets = MaybeUninit::<[RawFd; 2]>::uninit();
        // SAFETY: `sockets` supplies output storage for exactly two Linux
        // descriptors and a successful syscall initializes both values.
        unsafe { socketpair_raw(domain, type_and_flags, protocol, sockets.as_mut_ptr().cast())? };
        // SAFETY: The successful syscall above initialized both descriptors.
        let [first, second] = unsafe { sockets.assume_init() };
        Ok((first, second))
    }

    /// Sends bytes with the Linux `sendto` ABI.
    ///
    /// # Safety
    ///
    /// `buffer` must be readable for `length` bytes. When non-null, `address`
    /// must point to a readable Linux `sockaddr` of `address_length` bytes.
    #[inline]
    pub unsafe fn sendto_raw(
        socket: RawFd,
        buffer: *const u8,
        length: usize,
        flags: u32,
        address: *const u8,
        address_length: u32,
    ) -> Result<usize> {
        // SAFETY: The caller owns the buffer and optional address contracts.
        decode(unsafe {
            syscall6(
                SYS_SENDTO,
                socket as usize,
                buffer as usize,
                length,
                flags as usize,
                address as usize,
                address_length as usize,
            )
        })
    }

    /// Receives bytes with the Linux `recvfrom` ABI.
    ///
    /// # Safety
    ///
    /// `buffer` must be writable for `length` bytes. The optional address and
    /// address-length pointers must satisfy the Linux `recvfrom` ABI.
    #[inline]
    pub unsafe fn recvfrom_raw(
        socket: RawFd,
        buffer: *mut u8,
        length: usize,
        flags: u32,
        address: *mut u8,
        address_length: *mut u32,
    ) -> Result<usize> {
        // SAFETY: The caller owns every output-pointer contract.
        decode(unsafe {
            syscall6(
                SYS_RECVFROM,
                socket as usize,
                buffer as usize,
                length,
                flags as usize,
                address as usize,
                address_length as usize,
            )
        })
    }
}

/// Direct Linux virtual-memory operations.
pub mod mm {
    use super::{decode, syscall2, syscall3, syscall6, RawFd, Result, SYS_MMAP, SYS_MPROTECT, SYS_MUNMAP};

    /// Creates a mapping with the Linux/AArch64 `mmap` ABI.
    ///
    /// # Safety
    ///
    /// The caller must uphold Linux mapping requirements and Rust pointer
    /// provenance/reference invariants for `address` and the returned range.
    #[inline]
    pub unsafe fn mmap_raw(
        address: *mut u8,
        length: usize,
        protection: u32,
        flags: u32,
        fd: RawFd,
        offset: u64,
    ) -> Result<*mut u8> {
        // SAFETY: The caller owns the mapping contract. `decode` recognizes
        // only the Linux error range, so valid high-address mappings remain
        // successful pointer values.
        decode(unsafe {
            syscall6(
                SYS_MMAP,
                address as usize,
                length,
                protection as usize,
                flags as usize,
                fd as usize,
                offset as usize,
            )
        })
        .map(|address| address as *mut u8)
    }

    /// Removes a Linux mapping.
    ///
    /// # Safety
    ///
    /// The mapped range must be valid for unmapping and have no remaining Rust
    /// references.
    #[inline]
    pub unsafe fn munmap_raw(address: *mut u8, length: usize) -> Result<()> {
        // SAFETY: The caller owns the mapping lifetime/provenance contract.
        decode(unsafe { syscall2(SYS_MUNMAP, address as usize, length) }).map(|_| ())
    }

    /// Changes Linux mapping protection.
    ///
    /// # Safety
    ///
    /// The range must be a valid mapped range, and the caller must preserve
    /// Rust's reference invariants after changing access permissions.
    #[inline]
    pub unsafe fn mprotect_raw(address: *mut u8, length: usize, flags: u32) -> Result<()> {
        // SAFETY: The caller owns the mapped-range and provenance contracts.
        decode(unsafe { syscall3(SYS_MPROTECT, address as usize, length, flags as usize) })
            .map(|_| ())
    }
}

/// Direct process-identity, process-group, and signal operations.
pub mod process {
    use super::{
        decode, decode_i32, syscall0, syscall1, syscall2, Result, SYS_GETPGID, SYS_GETPID,
        SYS_GETPPID, SYS_GETSID, SYS_KILL, SYS_SETPGID, SYS_SETSID,
    };

    /// Returns the caller's Linux process ID.
    #[inline]
    pub fn getpid() -> i32 {
        // Linux guarantees that this syscall succeeds and returns a positive
        // process ID for a running task.
        unsafe { syscall0(SYS_GETPID) as i32 }
    }

    /// Returns the caller's Linux parent process ID, or zero for namespace init.
    #[inline]
    pub fn getppid() -> i32 {
        // Linux guarantees that this syscall succeeds. A zero parent is the
        // documented namespace-init/no-visible-parent representation.
        unsafe { syscall0(SYS_GETPPID) as i32 }
    }

    /// Sends `signal` to the raw Linux process target `pid`.
    #[inline]
    pub fn kill(pid: i32, signal: i32) -> Result<()> {
        // SAFETY: Both arguments are immediate Linux scalar values.
        decode(unsafe { syscall2(SYS_KILL, pid as usize, signal as usize) }).map(|_| ())
    }

    /// Returns a process group ID. `pid == 0` denotes the calling process.
    #[inline]
    pub fn getpgid(pid: i32) -> Result<i32> {
        // SAFETY: `pid` is an immediate Linux scalar value.
        decode_i32(unsafe { syscall1(SYS_GETPGID, pid as usize) })
    }

    /// Assigns a process group. Zero values retain Linux's calling-process meaning.
    #[inline]
    pub fn setpgid(pid: i32, pgid: i32) -> Result<()> {
        // SAFETY: Both arguments are immediate Linux scalar values.
        decode(unsafe { syscall2(SYS_SETPGID, pid as usize, pgid as usize) }).map(|_| ())
    }

    /// Returns a session ID. `pid == 0` denotes the calling process.
    #[inline]
    pub fn getsid(pid: i32) -> Result<i32> {
        // SAFETY: `pid` is an immediate Linux scalar value.
        decode_i32(unsafe { syscall1(SYS_GETSID, pid as usize) })
    }

    /// Creates a session and returns its process ID.
    #[inline]
    pub fn setsid() -> Result<i32> {
        // SAFETY: `setsid` has no user-memory arguments.
        decode_i32(unsafe { syscall0(SYS_SETSID) })
    }

}

/// Direct thread-associated Linux operations.
pub mod thread {
    use super::{decode, syscall0, Result, SYS_GETTID, SYS_SCHED_YIELD};

    /// Returns the caller's Linux thread ID.
    #[inline]
    pub fn gettid() -> i32 {
        // Linux guarantees a positive ID for a running task.
        unsafe { syscall0(SYS_GETTID) as i32 }
    }

    /// Yields the processor to the Linux scheduler.
    #[inline]
    pub fn sched_yield() -> Result<()> {
        // SAFETY: `sched_yield` has no user-memory arguments.
        decode(unsafe { syscall0(SYS_SCHED_YIELD) }).map(|_| ())
    }
}

/// Direct Linux system-information operations.
pub mod system {
    use super::{decode, syscall1, Result, SYS_SYSINFO, SYS_UNAME};
    use core::mem::MaybeUninit;

    /// Linux/AArch64 `new_utsname`, including the Linux domain-name field.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct UtsName {
        pub sysname: [u8; 65],
        pub nodename: [u8; 65],
        pub release: [u8; 65],
        pub version: [u8; 65],
        pub machine: [u8; 65],
        pub domainname: [u8; 65],
    }

    /// Linux/AArch64 `sysinfo` without libc's compatibility-only tail.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Sysinfo {
        pub uptime: i64,
        pub loads: [u64; 3],
        pub totalram: u64,
        pub freeram: u64,
        pub sharedram: u64,
        pub bufferram: u64,
        pub totalswap: u64,
        pub freeswap: u64,
        pub procs: u16,
        pub pad: u16,
        pub totalhigh: u64,
        pub freehigh: u64,
        pub mem_unit: u32,
        // Linux's `struct sysinfo` retains this ABI tail so the 64-bit
        // representation stays 112 bytes after the alignment before
        // `totalhigh`.
        pub reserved: [u8; 4],
    }

    /// Reads Linux kernel and hardware naming information.
    #[inline]
    pub fn uname() -> Result<UtsName> {
        let mut value = MaybeUninit::<UtsName>::uninit();
        // SAFETY: `value` provides exactly one writable Linux/AArch64
        // `new_utsname`; a successful syscall initializes all fields.
        decode(unsafe { syscall1(SYS_UNAME, value.as_mut_ptr() as usize) })?;
        Ok(unsafe { value.assume_init() })
    }

    /// Reads Linux kernel and hardware naming information into C-ABI storage.
    ///
    /// # Safety
    ///
    /// `value` must designate writable Linux/AArch64 `new_utsname` storage,
    /// or may deliberately be an invalid C ABI pointer for kernel validation.
    #[inline]
    pub unsafe fn uname_raw(value: *mut UtsName) -> Result<()> {
        // SAFETY: The caller supplies the output-pointer contract.
        decode(unsafe { syscall1(SYS_UNAME, value as usize) }).map(|_| ())
    }

    /// Reads Linux memory, load, and uptime information.
    #[inline]
    pub fn sysinfo() -> Result<Sysinfo> {
        let mut value = MaybeUninit::<Sysinfo>::uninit();
        // SAFETY: `value` is the exact Linux/AArch64 `sysinfo` ABI.
        decode(unsafe { syscall1(SYS_SYSINFO, value.as_mut_ptr() as usize) })?;
        Ok(unsafe { value.assume_init() })
    }

    /// Reads Linux system information into C-ABI storage.
    ///
    /// # Safety
    ///
    /// `value` must designate writable Linux/AArch64 `sysinfo` storage, or
    /// may deliberately be an invalid C ABI pointer for kernel validation.
    #[inline]
    pub unsafe fn sysinfo_raw(value: *mut Sysinfo) -> Result<()> {
        // SAFETY: The caller supplies the output-pointer contract.
        decode(unsafe { syscall1(SYS_SYSINFO, value as usize) }).map(|_| ())
    }
}

/// Direct Linux mount namespace operations.
pub mod mount {
    use super::{decode, syscall2, syscall5, CStr, Result, SYS_MOUNT, SYS_UMOUNT2};

    /// Mounts a filesystem with the Linux `mount` ABI.
    #[inline]
    pub fn mount(
        source: Option<&CStr>,
        target: &CStr,
        filesystem_type: Option<&CStr>,
        flags: u64,
        data: Option<&CStr>,
    ) -> Result<()> {
        // SAFETY: Every present C string is NUL-terminated and stays live for
        // the syscall. Linux owns interpretation of all mount-specific data.
        decode(unsafe {
            syscall5(
                SYS_MOUNT,
                source.map_or(0, |value| value.as_ptr() as usize),
                target.as_ptr() as usize,
                filesystem_type.map_or(0, |value| value.as_ptr() as usize),
                flags as usize,
                data.map_or(0, |value| value.as_ptr() as usize),
            )
        })
        .map(|_| ())
    }

    /// Mounts a filesystem from raw C-ABI pointers.
    ///
    /// # Safety
    ///
    /// Every non-null string pointer must be a readable NUL-terminated C
    /// string for the call. `data` follows the filesystem-specific Linux
    /// mount contract and may be null.
    #[inline]
    pub unsafe fn mount_raw(
        source: *const u8,
        target: *const u8,
        filesystem_type: *const u8,
        flags: u64,
        data: *const u8,
    ) -> Result<()> {
        // SAFETY: The caller owns all Linux mount pointer contracts.
        decode(unsafe {
            syscall5(
                SYS_MOUNT,
                source as usize,
                target as usize,
                filesystem_type as usize,
                flags as usize,
                data as usize,
            )
        })
        .map(|_| ())
    }

    /// Unmounts a filesystem with the Linux `umount2` ABI.
    #[inline]
    pub fn umount2(target: &CStr, flags: i32) -> Result<()> {
        // SAFETY: `target` supplies a stable NUL-terminated pathname.
        decode(unsafe { syscall2(SYS_UMOUNT2, target.as_ptr() as usize, flags as usize) })
            .map(|_| ())
    }

    /// Unmounts a filesystem from a raw C-ABI target pointer.
    ///
    /// # Safety
    ///
    /// `target` must be a readable NUL-terminated pathname, or may
    /// deliberately be an invalid C ABI pointer for kernel validation.
    #[inline]
    pub unsafe fn umount2_raw(target: *const u8, flags: i32) -> Result<()> {
        // SAFETY: The caller supplies the pathname-pointer contract.
        decode(unsafe { syscall2(SYS_UMOUNT2, target as usize, flags as usize) }).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_i32, system, Errno};

    #[test]
    fn errno_accepts_only_linux_syscall_values() {
        assert_eq!(Errno::from_raw(0), None);
        assert_eq!(Errno::from_raw(4096), None);
        assert_eq!(Errno::from_raw(2).unwrap().raw(), 2);
    }

    #[test]
    fn system_layouts_match_linux_aarch64_kernel_abis() {
        assert_eq!(core::mem::size_of::<system::UtsName>(), 390);
        assert_eq!(core::mem::size_of::<system::Sysinfo>(), 112);
    }

    #[test]
    fn ioctl_result_keeps_negative_non_errno_successes() {
        assert_eq!(decode_i32(0), Ok(0));
        assert_eq!(decode_i32(-1), Err(Errno::from_raw(1).unwrap()));
        assert_eq!(decode_i32(-4095), Err(Errno::from_raw(4095).unwrap()));
        assert_eq!(decode_i32(-4096), Ok(-4096));
    }
}
