//! The Darwin error value and its read-immediately conversion from `errno`.

use core::fmt;
use core::num::NonZeroI32;

use super::sys;

/// A positive Darwin errno value returned by a libSystem operation.
///
/// libSystem reports failures through the thread-local `errno` slot. The
/// Darwin backend reads that slot immediately after the failing call and
/// carries the value in this type from then on, so callers never observe
/// `errno` directly. The numbers are Darwin's, not Linux's: compare against
/// the named constants rather than raw integers.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Errno(NonZeroI32);

impl Errno {
    /// Builds an errno from a positive Darwin errno value.
    #[inline]
    pub const fn new(raw: i32) -> Option<Self> {
        match NonZeroI32::new(raw) {
            Some(raw) if raw.get() > 0 => Some(Self(raw)),
            _ => None,
        }
    }

    /// Builds an errno from a positive Darwin errno value.
    #[inline]
    pub const fn from_raw(raw: i32) -> Option<Self> {
        Self::new(raw)
    }

    /// Returns the positive Darwin errno number.
    #[inline]
    pub const fn raw(self) -> i32 {
        self.0.get()
    }

    /// Returns the positive Darwin OS error value.
    #[inline]
    pub const fn raw_os_error(self) -> i32 {
        self.raw()
    }

    /// Constructs an errno from a positive Darwin OS error value.
    ///
    /// Use [`Self::from_raw`] when the input is untrusted.
    ///
    /// # Panics
    ///
    /// Panics if `raw` is not positive.
    #[inline]
    pub const fn from_raw_os_error(raw: i32) -> Self {
        match Self::new(raw) {
            Some(errno) => errno,
            None => panic!("invalid Darwin errno"),
        }
    }
}

macro_rules! darwin_errno_constants {
    ($($name:ident = $value:literal,)*) => {
        impl Errno {
            $(
                #[doc = concat!("Darwin errno value `E", stringify!($name), "`.")]
                pub const $name: Self = Self::from_raw_os_error($value);
            )*
        }
    };
}

// The complete `sys/errno.h` list of the macOS 27 SDK, named as the Linux
// facade names them (`E` prefix removed, `E2BIG` as `TOOBIG`).
darwin_errno_constants! {
    PERM = 1,
    NOENT = 2,
    SRCH = 3,
    INTR = 4,
    IO = 5,
    NXIO = 6,
    TOOBIG = 7,
    NOEXEC = 8,
    BADF = 9,
    CHILD = 10,
    DEADLK = 11,
    NOMEM = 12,
    ACCESS = 13,
    FAULT = 14,
    NOTBLK = 15,
    BUSY = 16,
    EXIST = 17,
    XDEV = 18,
    NODEV = 19,
    NOTDIR = 20,
    ISDIR = 21,
    INVAL = 22,
    NFILE = 23,
    MFILE = 24,
    NOTTY = 25,
    TXTBSY = 26,
    FBIG = 27,
    NOSPC = 28,
    SPIPE = 29,
    ROFS = 30,
    MLINK = 31,
    PIPE = 32,
    DOM = 33,
    RANGE = 34,
    AGAIN = 35,
    WOULDBLOCK = 35,
    INPROGRESS = 36,
    ALREADY = 37,
    NOTSOCK = 38,
    DESTADDRREQ = 39,
    MSGSIZE = 40,
    PROTOTYPE = 41,
    NOPROTOOPT = 42,
    PROTONOSUPPORT = 43,
    SOCKTNOSUPPORT = 44,
    NOTSUP = 45,
    PFNOSUPPORT = 46,
    AFNOSUPPORT = 47,
    ADDRINUSE = 48,
    ADDRNOTAVAIL = 49,
    NETDOWN = 50,
    NETUNREACH = 51,
    NETRESET = 52,
    CONNABORTED = 53,
    CONNRESET = 54,
    NOBUFS = 55,
    ISCONN = 56,
    NOTCONN = 57,
    SHUTDOWN = 58,
    TOOMANYREFS = 59,
    TIMEDOUT = 60,
    CONNREFUSED = 61,
    LOOP = 62,
    NAMETOOLONG = 63,
    HOSTDOWN = 64,
    HOSTUNREACH = 65,
    NOTEMPTY = 66,
    PROCLIM = 67,
    USERS = 68,
    DQUOT = 69,
    STALE = 70,
    REMOTE = 71,
    BADRPC = 72,
    RPCMISMATCH = 73,
    PROGUNAVAIL = 74,
    PROGMISMATCH = 75,
    PROCUNAVAIL = 76,
    NOLCK = 77,
    NOSYS = 78,
    FTYPE = 79,
    AUTH = 80,
    NEEDAUTH = 81,
    PWROFF = 82,
    DEVERR = 83,
    OVERFLOW = 84,
    BADEXEC = 85,
    BADARCH = 86,
    SHLIBVERS = 87,
    BADMACHO = 88,
    CANCELED = 89,
    IDRM = 90,
    NOMSG = 91,
    ILSEQ = 92,
    NOATTR = 93,
    BADMSG = 94,
    MULTIHOP = 95,
    NODATA = 96,
    NOLINK = 97,
    NOSR = 98,
    NOSTR = 99,
    PROTO = 100,
    TIME = 101,
    OPNOTSUPP = 102,
    NOPOLICY = 103,
    NOTRECOVERABLE = 104,
    OWNERDEAD = 105,
    QFULL = 106,
    NOTCAPABLE = 107,
}

impl fmt::Display for Errno {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.raw().fmt(formatter)
    }
}

/// A typed result from a Darwin facade operation.
pub type Result<T> = core::result::Result<T, Errno>;

/// Reads the calling thread's `errno` after a libSystem call reported failure.
///
/// Call this directly on the failing return value, before any other call can
/// overwrite `errno`. A failure that leaves `errno` non-positive breaks
/// libSystem's contract; it is reported as [`Errno::IO`], the facade's error
/// for malformed OS output.
#[inline(always)]
pub(crate) fn last() -> Errno {
    current().unwrap_or(Errno::IO)
}

/// Reads the calling thread's `errno`, returning `None` while it is zero.
///
/// This distinguishes failure from a normal end for calls such as `readdir`
/// that report both with the same return value; pair it with [`clear`].
#[inline(always)]
pub(crate) fn current() -> Option<Errno> {
    let slot = sys::__error();
    // SAFETY: `__error` returns the calling thread's errno slot, which is
    // valid, aligned and live for the whole lifetime of the thread.
    let raw = unsafe { slot.read() };
    Errno::new(raw)
}

/// Clears the calling thread's `errno` before a libSystem call that reports
/// some failures only through `errno`.
#[inline(always)]
pub(crate) fn clear() {
    let slot = sys::__error();
    // SAFETY: as in `current`, the slot is this thread's live errno storage.
    unsafe { slot.write(0) };
}

/// Converts an `int` libSystem result, where `-1` reports failure.
#[inline(always)]
pub(crate) fn check(result: core::ffi::c_int) -> Result<core::ffi::c_int> {
    if result == -1 {
        Err(last())
    } else {
        Ok(result)
    }
}

/// Converts an `ssize_t` libSystem byte count, where `-1` reports failure.
#[inline(always)]
pub(crate) fn check_size(result: isize) -> Result<usize> {
    match usize::try_from(result) {
        Ok(count) => Ok(count),
        Err(_) if result == -1 => Err(last()),
        Err(_) => Err(Errno::IO),
    }
}
