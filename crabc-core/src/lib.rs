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
const SYS_FCNTL: usize = 25;
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

/// Direct descriptor I/O operations.
pub mod io {
    use super::{
        decode, decode_i32, syscall1, syscall3, RawFd, Result, SYS_CLOSE,
        SYS_FCNTL, SYS_IOCTL, SYS_READ, SYS_WRITE,
    };

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
        decode, syscall2, syscall3, syscall4, syscall5, CStr, RawFd, Result,
        SYS_FCHMOD, SYS_FCHMODAT, SYS_FLOCK, SYS_FSTAT, SYS_GETDENTS64, SYS_LINKAT,
        SYS_FGETXATTR, SYS_FLISTXATTR, SYS_FREMOVEXATTR, SYS_FSETXATTR, SYS_GETXATTR,
        SYS_LGETXATTR, SYS_LLISTXATTR, SYS_LREMOVEXATTR, SYS_LSETXATTR, SYS_LISTXATTR,
        SYS_MKDIRAT, SYS_NEWFSTATAT, SYS_OPENAT, SYS_OPENAT2, SYS_READLINKAT,
        SYS_REMOVEXATTR, SYS_RENAMEAT2, SYS_SETXATTR, SYS_SYMLINKAT, SYS_UNLINKAT,
        SYS_UTIMENSAT,
    };

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

#[cfg(test)]
mod tests {
    use super::{decode_i32, Errno};

    #[test]
    fn errno_accepts_only_linux_syscall_values() {
        assert_eq!(Errno::from_raw(0), None);
        assert_eq!(Errno::from_raw(4096), None);
        assert_eq!(Errno::from_raw(2).unwrap().raw(), 2);
    }

    #[test]
    fn ioctl_result_keeps_negative_non_errno_successes() {
        assert_eq!(decode_i32(0), Ok(0));
        assert_eq!(decode_i32(-1), Err(Errno::from_raw(1).unwrap()));
        assert_eq!(decode_i32(-4095), Err(Errno::from_raw(4095).unwrap()));
        assert_eq!(decode_i32(-4096), Ok(-4096));
    }
}
