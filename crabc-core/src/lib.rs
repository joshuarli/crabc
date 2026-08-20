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
const SYS_CLOSE: usize = 57;
const SYS_OPENAT: usize = 56;
const SYS_IOCTL: usize = 29;

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
    use super::{decode, decode_i32, syscall1, syscall3, RawFd, Result, SYS_CLOSE, SYS_IOCTL, SYS_READ, SYS_WRITE};

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
    use super::{decode, syscall4, CStr, RawFd, Result, SYS_OPENAT};

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
