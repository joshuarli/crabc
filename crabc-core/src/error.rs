//! Typed Linux error and raw-descriptor boundary values.

use core::fmt;
use core::num::NonZeroI32;

/// Linux's largest syscall-encoded errno value.
pub(crate) const MAX_ERRNO: i32 = 4095;

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
