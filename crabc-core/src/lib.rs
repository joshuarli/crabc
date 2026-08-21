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

/// Private, versioned wire contracts for process-singleton crabc runtimes.
///
/// These types are deliberately data-only. They let a native facade reach
/// state owned by `libc.so` or `libldso.so` without mistaking a second linked
/// copy of Rust statics for shared process state. They are not a public C ABI:
/// no installed header names them, and callers must obtain the matching table
/// through the explicitly versioned private entry point.
pub mod runtime {
    use core::ffi::{c_char, c_int, c_void};

    /// First private singleton-runtime table revision.
    pub const V1_ABI_VERSION: u32 = 1;

    /// Maximum copied error or loader-name byte length on the v1 wire.
    ///
    /// A fixed bounded buffer avoids exposing borrowed loader/TLS storage
    /// through the native facade. A truncation bit records a longer source.
    pub const TEXT_CAPACITY: usize = 256;

    /// Opaque handle representation for one libc-owned pthread runtime
    /// object. It is a wire value only; native callers must not inspect or
    /// dereference it.
    pub type ThreadHandleV1 = u64;

    /// Callback ABI used by the private thread creation entry point.
    pub type ThreadStartV1 = unsafe extern "C" fn(*mut c_void) -> *mut c_void;

    /// Destructor ABI used by the private thread-local-key entry point.
    pub type ThreadDestructorV1 = unsafe extern "C" fn(*mut c_void);

    /// Number of key slots owned by the libc runtime in this ABI revision.
    ///
    /// This bound lets the private wrapper reject forged key values before
    /// they reach libc's fixed table. It is not a promise about a public C
    /// `PTHREAD_KEYS_MAX` header constant.
    pub const THREAD_KEY_CAPACITY: u32 = 128;

    /// Owned-text representation used by the private runtime table.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct TextV1 {
        /// Number of meaningful bytes in `bytes`.
        pub len: u16,
        /// Bit 0 means the original text did not fit in `bytes`.
        pub flags: u16,
        /// Text bytes with no required trailing NUL.
        pub bytes: [u8; TEXT_CAPACITY],
    }

    impl TextV1 {
        /// Creates an empty wire value.
        #[inline]
        pub const fn empty() -> Self {
            Self {
                len: 0,
                flags: 0,
                bytes: [0; TEXT_CAPACITY],
            }
        }
    }

    /// Copied loader address metadata. No pointer refers to loader-owned text.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct LoaderAddressV1 {
        /// Mapped image base returned by the loader.
        pub image_base: *mut c_void,
        /// Resolved nearest-symbol address, if any.
        pub symbol_address: *mut c_void,
        /// Copied image name.
        pub image_name: TextV1,
        /// Copied nearest-symbol name.
        pub symbol_name: TextV1,
    }

    impl LoaderAddressV1 {
        /// Creates an empty wire value.
        #[inline]
        pub const fn empty() -> Self {
            Self {
                image_base: core::ptr::null_mut(),
                symbol_address: core::ptr::null_mut(),
                image_name: TextV1::empty(),
                symbol_name: TextV1::empty(),
            }
        }
    }

    /// Private v1 runtime table owned by the loaded crabc runtime.
    ///
    /// Functions return zero on success and `-1` on a loader failure. The
    /// accompanying `TextV1` then owns a best-effort diagnostic. They never
    /// transport a C sentinel/`errno` result across this boundary.
    #[repr(C)]
    pub struct RuntimeV1 {
        /// Must equal [`V1_ABI_VERSION`].
        pub abi_version: u32,
        /// Size supplied by the runtime for append-only compatibility checks.
        pub abi_size: u32,
        /// Opens a DSO or the global process handle when `path` is null.
        pub loader_open: unsafe extern "C" fn(
            path: *const c_char,
            flags: c_int,
            handle: *mut *mut c_void,
            error: *mut TextV1,
        ) -> c_int,
        /// Looks up a DSO symbol and stores its address in `address`.
        pub loader_symbol: unsafe extern "C" fn(
            handle: *mut c_void,
            name: *const c_char,
            address: *mut *mut c_void,
            error: *mut TextV1,
        ) -> c_int,
        /// Releases one DSO handle reference.
        pub loader_close:
            unsafe extern "C" fn(handle: *mut c_void, error: *mut TextV1) -> c_int,
        /// Copies loader-owned address metadata into caller-owned storage.
        pub loader_address: unsafe extern "C" fn(
            address: *const c_void,
            info: *mut LoaderAddressV1,
            error: *mut TextV1,
        ) -> c_int,
        /// Creates a libc-owned pthread using the default attributes. The
        /// returned handle is an opaque `ThreadHandleV1`; errors are positive
        /// pthread error numbers and never TLS errno.
        pub thread_create: unsafe extern "C" fn(
            start: ThreadStartV1,
            arg: *mut c_void,
            handle: *mut ThreadHandleV1,
        ) -> c_int,
        /// Joins a libc-owned pthread and optionally receives its C callback
        /// result pointer.
        pub thread_join: unsafe extern "C" fn(
            handle: ThreadHandleV1,
            result: *mut *mut c_void,
        ) -> c_int,
        /// Detaches a libc-owned pthread handle.
        pub thread_detach: unsafe extern "C" fn(handle: ThreadHandleV1) -> c_int,
        /// Returns the current libc-owned pthread handle.
        pub thread_self: unsafe extern "C" fn(handle: *mut ThreadHandleV1) -> c_int,
        /// Requests cancellation of a libc-owned pthread. Native wrappers
        /// keep this operation unsafe because cancellation bypasses ordinary
        /// Rust destructor and lock invariants.
        pub thread_cancel: unsafe extern "C" fn(handle: ThreadHandleV1) -> c_int,
        /// Changes the current libc-owned pthread cancellation state.
        pub thread_setcancelstate: unsafe extern "C" fn(
            state: u32,
            old_state: *mut u32,
        ) -> c_int,
        /// Changes the current libc-owned pthread cancellation type.
        pub thread_setcanceltype: unsafe extern "C" fn(
            cancel_type: u32,
            old_type: *mut u32,
        ) -> c_int,
        /// Tests the current libc-owned pthread cancellation request.
        pub thread_testcancel: unsafe extern "C" fn(),
        /// Creates a libc-owned thread-local key. The destructor executes in
        /// libc's thread-exit cleanup path and therefore has an unsafe Rust
        /// callback contract.
        pub thread_key_create: unsafe extern "C" fn(
            key: *mut u32,
            destructor: Option<ThreadDestructorV1>,
        ) -> c_int,
        /// Deletes a libc-owned thread-local key.
        pub thread_key_delete: unsafe extern "C" fn(key: u32) -> c_int,
        /// Reads the current thread's value for a libc-owned key.
        pub thread_getspecific: unsafe extern "C" fn(key: u32) -> *mut c_void,
        /// Writes the current thread's value for a libc-owned key.
        pub thread_setspecific: unsafe extern "C" fn(
            key: u32,
            value: *const c_void,
        ) -> c_int,
    }
}

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
const SYS_SIGNALFD4: usize = 74;
const SYS_SOCKET: usize = 198;
const SYS_SOCKETPAIR: usize = 199;
const SYS_CONNECT: usize = 203;
const SYS_SENDTO: usize = 206;
const SYS_RECVFROM: usize = 207;
const SYS_MUNMAP: usize = 215;
const SYS_MMAP: usize = 222;
const SYS_MPROTECT: usize = 226;
const SYS_KILL: usize = 129;
const SYS_TGKILL: usize = 131;
const SYS_SIGALTSTACK: usize = 132;
const SYS_RT_SIGSUSPEND: usize = 133;
const SYS_RT_SIGACTION: usize = 134;
const SYS_RT_SIGPROCMASK: usize = 135;
const SYS_RT_SIGPENDING: usize = 136;
const SYS_RT_SIGTIMEDWAIT: usize = 137;
const SYS_RT_SIGQUEUEINFO: usize = 138;
const SYS_MOUNT: usize = 40;
const SYS_UMOUNT2: usize = 39;
const SYS_GETPGID: usize = 155;
const SYS_SETPGID: usize = 154;
const SYS_GETSID: usize = 156;
const SYS_SETSID: usize = 157;
const SYS_UNAME: usize = 160;
const SYS_GETPID: usize = 172;
const SYS_GETPPID: usize = 173;
const SYS_GETUID: usize = 174;
const SYS_GETTID: usize = 178;
const SYS_SYSINFO: usize = 179;
const SYS_SCHED_YIELD: usize = 124;
const SYS_FUTEX: usize = 98;
const SYS_CLONE: usize = 220;
const SYS_EXECVE: usize = 221;
const SYS_WAIT4: usize = 260;
const SYS_WAITID: usize = 95;
const SYS_EXIT_GROUP: usize = 94;

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
        decode, decode_i32, syscall3, syscall4, syscall6, MaybeUninit, RawFd, Result,
        SYS_CONNECT, SYS_RECVFROM, SYS_SENDTO, SYS_SOCKET, SYS_SOCKETPAIR,
    };

    /// Creates a Linux socket without libc or TLS `errno`.
    #[inline]
    pub fn socket(domain: i32, type_and_flags: u32, protocol: i32) -> Result<RawFd> {
        // SAFETY: Linux validates these scalar socket parameters.
        decode_i32(unsafe {
            super::syscall3(
                SYS_SOCKET,
                domain as usize,
                type_and_flags as usize,
                protocol as usize,
            )
        })
    }

    /// Connects a socket to a caller-owned Linux socket address.
    ///
    /// # Safety
    ///
    /// `address` must point to a readable Linux socket address of
    /// `address_length` bytes for the duration of the syscall.
    #[inline]
    pub unsafe fn connect_raw(
        socket: RawFd,
        address: *const u8,
        address_length: u32,
    ) -> Result<()> {
        // SAFETY: The caller owns the address pointer and length contract.
        decode(unsafe {
            syscall3(
                SYS_CONNECT,
                socket as usize,
                address as usize,
                address_length as usize,
            )
        })
        .map(|_| ())
    }

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

/// Stateless DNS wire and exchange operations shared by native facades.
///
/// This module deliberately owns no resolver configuration, cache, TLS, or
/// libc state. Callers provide bounded nameserver configuration and buffers;
/// the native facade can therefore own its results while the C facade keeps
/// its historical `_res` state at its own ABI boundary.
pub mod resolver {
    use super::{net, Result};

    /// IPv4 address family in the Linux socket ABI.
    pub const AF_INET: u16 = 2;
    /// IPv6 address family in the Linux socket ABI.
    pub const AF_INET6: u16 = 10;
    /// UDP socket type in the Linux socket ABI.
    pub const SOCK_DGRAM: u32 = 2;
    /// Close-on-exec socket flag.
    pub const SOCK_CLOEXEC: u32 = 0x0008_0000;
    /// `MSG_NOSIGNAL`, used for the datagram send operation.
    pub const MSG_NOSIGNAL: u32 = 0x4000;
    /// DNS Internet class.
    pub const CLASS_IN: u16 = 1;
    /// DNS address record.
    pub const TYPE_A: u16 = 1;
    /// DNS canonical-name record.
    pub const TYPE_CNAME: u16 = 5;
    /// DNS pointer record.
    pub const TYPE_PTR: u16 = 12;
    /// DNS IPv6 address record.
    pub const TYPE_AAAA: u16 = 28;
    /// Maximum DNS wire name size, including its root terminator.
    pub const MAX_NAME_WIRE: usize = 256;
    /// Maximum nameservers accepted by the musl resolver configuration.
    pub const MAX_NAMESERVERS: usize = 3;

    /// A caller-owned nameserver endpoint.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct NameServer {
        /// Linux address-family value.
        pub family: u16,
        /// Network-order address bytes in the first four or sixteen bytes.
        pub address: [u8; 16],
        /// UDP port in host byte order. Zero selects DNS port 53.
        pub port: u16,
        /// IPv6 scope identifier, ignored for IPv4.
        pub scope_id: u32,
    }

    impl NameServer {
        /// Builds an IPv4 nameserver using DNS port 53.
        #[inline]
        pub const fn ipv4(address: [u8; 4]) -> Self {
            let mut bytes = [0; 16];
            bytes[0] = address[0];
            bytes[1] = address[1];
            bytes[2] = address[2];
            bytes[3] = address[3];
            Self { family: AF_INET, address: bytes, port: 53, scope_id: 0 }
        }

        /// Builds an IPv6 nameserver using DNS port 53.
        #[inline]
        pub const fn ipv6(address: [u8; 16], scope_id: u32) -> Self {
            Self { family: AF_INET6, address, port: 53, scope_id }
        }
    }

    /// Bounded DNS exchange configuration.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct ExchangeConfig {
        /// Nameservers, in configured order.
        pub nameservers: [NameServer; MAX_NAMESERVERS],
        /// Number of initialized entries in [`Self::nameservers`].
        pub nameserver_count: usize,
        /// Per-server receive timeout in milliseconds.
        pub timeout_ms: u32,
        /// Number of configured-order attempts.
        pub attempts: u8,
    }

    impl ExchangeConfig {
        /// Constructs a one-server configuration with a bounded timeout.
        #[inline]
        pub const fn single(nameserver: NameServer, timeout_ms: u32) -> Self {
            Self {
                nameservers: [nameserver; MAX_NAMESERVERS],
                nameserver_count: 1,
                timeout_ms,
                attempts: 1,
            }
        }
    }

    #[repr(C)]
    struct PollFd {
        fd: i32,
        events: i16,
        revents: i16,
    }

    #[repr(C)]
    struct Timespec {
        seconds: i64,
        nanoseconds: i64,
    }

    #[repr(C)]
    struct SockaddrIn {
        family: u16,
        port: u16,
        address: u32,
        zero: [u8; 8],
    }

    #[repr(C)]
    struct SockaddrIn6 {
        family: u16,
        port: u16,
        flow_info: u32,
        address: [u8; 16],
        scope_id: u32,
    }

    const POLLIN: i16 = 0x0001;
    const POLLERR: i16 = 0x0008;
    const POLLHUP: i16 = 0x0010;
    const POLLNVAL: i16 = 0x0020;

    #[inline]
    fn invalid() -> super::Errno {
        super::Errno::INVAL
    }

    #[inline]
    fn malformed() -> super::Errno {
        super::Errno::BADMSG
    }

    #[inline]
    fn write_wire_name(name: &[u8], output: &mut [u8]) -> Result<usize> {
        if name.is_empty() || output.is_empty() {
            return Err(invalid());
        }
        let mut written = 0usize;
        let mut label_start = 0usize;
        let mut index = 0usize;
        while index <= name.len() {
            let at_end = index == name.len();
            if !at_end && name[index] != b'.' {
                index += 1;
                continue;
            }
            let label_length = index.saturating_sub(label_start);
            if label_length == 0 {
                if !(at_end && index != 0 && name[index - 1] == b'.') {
                    return Err(invalid());
                }
            } else if label_length > 63 || written.checked_add(label_length + 2).is_none() {
                return Err(invalid());
            } else {
                if written + label_length + 1 >= output.len() {
                    return Err(super::Errno::NAMETOOLONG);
                }
                output[written] = label_length as u8;
                output[written + 1..written + 1 + label_length]
                    .copy_from_slice(&name[label_start..index]);
                written += label_length + 1;
            }
            if at_end {
                break;
            }
            label_start = index + 1;
            index += 1;
        }
        if written >= output.len() {
            return Err(super::Errno::NAMETOOLONG);
        }
        output[written] = 0;
        Ok(written + 1)
    }

    /// Encodes one recursive DNS A/AAAA/PTR query into caller storage.
    pub fn encode_query(name: &[u8], record_type: u16, query_id: u16, output: &mut [u8]) -> Result<usize> {
        if output.len() < 12 {
            return Err(super::Errno::MSGSIZE);
        }
        let mut wire_name = [0u8; MAX_NAME_WIRE];
        let name_length = write_wire_name(name, &mut wire_name)?;
        let total = 12usize
            .checked_add(name_length)
            .and_then(|value| value.checked_add(4))
            .ok_or(super::Errno::MSGSIZE)?;
        if total > output.len() {
            return Err(super::Errno::MSGSIZE);
        }
        output[..total].fill(0);
        output[0] = (query_id >> 8) as u8;
        output[1] = query_id as u8;
        output[2] = 0x01;
        output[5] = 0x01;
        output[12..12 + name_length].copy_from_slice(&wire_name[..name_length]);
        let qtype = 12 + name_length;
        output[qtype] = (record_type >> 8) as u8;
        output[qtype + 1] = record_type as u8;
        output[qtype + 2] = 0;
        output[qtype + 3] = CLASS_IN as u8;
        Ok(total)
    }

    /// A validated DNS response borrowing its caller-owned packet buffer.
    pub struct DnsResponse<'packet> {
        packet: &'packet [u8],
        answer_offset: usize,
        answer_count: u16,
        response_code: u8,
        truncated: bool,
    }

    impl<'packet> DnsResponse<'packet> {
        /// Validates transaction, question, and DNS header fields.
        pub fn parse(
            packet: &'packet [u8],
            query_name: &[u8],
            record_type: u16,
            query_id: u16,
        ) -> Result<Self> {
            if packet.len() < 12 {
                return Err(malformed());
            }
            let id = u16::from_be_bytes([packet[0], packet[1]]);
            if id != query_id || packet[2] & 0x80 == 0 || packet[2] & 0x78 != 0 {
                return Err(malformed());
            }
            if u16::from_be_bytes([packet[4], packet[5]]) != 1 {
                return Err(malformed());
            }
            let mut expected_name = [0u8; MAX_NAME_WIRE];
            let expected_length = write_wire_name(query_name, &mut expected_name)?;
            let question_end = skip_name(packet, 12)?;
            if question_end + 4 > packet.len()
                || question_end - 12 != expected_length
                || packet[12..question_end] != expected_name[..expected_length]
                || u16::from_be_bytes([packet[question_end], packet[question_end + 1]]) != record_type
                || u16::from_be_bytes([packet[question_end + 2], packet[question_end + 3]]) != CLASS_IN
            {
                return Err(malformed());
            }
            Ok(Self {
                packet,
                answer_offset: question_end + 4,
                answer_count: u16::from_be_bytes([packet[6], packet[7]]),
                response_code: packet[3] & 0x0f,
                truncated: packet[2] & 0x02 != 0,
            })
        }

        /// Returns the DNS response code from the validated header.
        #[inline]
        pub const fn response_code(&self) -> u8 { self.response_code }

        /// Returns whether the server marked this UDP response truncated.
        #[inline]
        pub const fn truncated(&self) -> bool { self.truncated }

        /// Copies the selected answer's raw RDATA or expanded DNS name.
        pub fn rdata_at(
            &self,
            record_type: u16,
            ordinal: usize,
            output: &mut [u8],
        ) -> Result<Option<usize>> {
            let mut offset = self.answer_offset;
            let mut found = 0usize;
            let mut index = 0u16;
            while index < self.answer_count {
                let name_end = skip_name(self.packet, offset)?;
                if name_end + 10 > self.packet.len() {
                    return Err(malformed());
                }
                let kind = u16::from_be_bytes([self.packet[name_end], self.packet[name_end + 1]]);
                let class = u16::from_be_bytes([self.packet[name_end + 2], self.packet[name_end + 3]]);
                let length = u16::from_be_bytes([self.packet[name_end + 8], self.packet[name_end + 9]]) as usize;
                let data = name_end + 10;
                if data.checked_add(length).filter(|end| *end <= self.packet.len()).is_none() {
                    return Err(malformed());
                }
                if kind == record_type && class == CLASS_IN {
                    if found == ordinal {
                        if record_type == TYPE_CNAME || record_type == TYPE_PTR {
                            let length = expand_name(self.packet, data, output)?;
                            return Ok(Some(length));
                        }
                        if length > output.len() {
                            return Err(super::Errno::MSGSIZE);
                        }
                        output[..length].copy_from_slice(&self.packet[data..data + length]);
                        return Ok(Some(length));
                    }
                    found += 1;
                }
                offset = data + length;
                index += 1;
            }
            Ok(None)
        }
    }

    fn skip_name(packet: &[u8], mut offset: usize) -> Result<usize> {
        let mut jumps = 0usize;
        loop {
            if offset >= packet.len() {
                return Err(malformed());
            }
            let length = packet[offset];
            if length & 0xc0 == 0xc0 {
                if offset + 1 >= packet.len() {
                    return Err(malformed());
                }
                return Ok(offset + 2);
            }
            if length > 63 {
                return Err(malformed());
            }
            offset += 1;
            if length == 0 {
                return Ok(offset);
            }
            if offset + length as usize > packet.len() {
                return Err(malformed());
            }
            offset += length as usize;
            jumps += 1;
            if jumps > 128 {
                return Err(malformed());
            }
        }
    }

    fn expand_name(packet: &[u8], start: usize, output: &mut [u8]) -> Result<usize> {
        let mut offset = start;
        let mut written = 0usize;
        let mut consumed = 0usize;
        let mut jumped = false;
        let mut jumps = 0usize;
        loop {
            if offset >= packet.len() {
                return Err(malformed());
            }
            let length = packet[offset];
            if length & 0xc0 == 0xc0 {
                if offset + 1 >= packet.len() {
                    return Err(malformed());
                }
                let target = ((length as usize & 0x3f) << 8) | packet[offset + 1] as usize;
                if target >= packet.len() || target == offset {
                    return Err(malformed());
                }
                if !jumped {
                    consumed += 2;
                }
                offset = target;
                jumped = true;
                jumps += 1;
                if jumps > 128 {
                    return Err(malformed());
                }
                continue;
            }
            if length > 63 {
                return Err(malformed());
            }
            offset += 1;
            if length == 0 {
                if written == 0 {
                    if output.is_empty() { return Err(super::Errno::MSGSIZE); }
                    output[0] = b'.';
                    return Ok(1);
                }
                let _ = consumed;
                return Ok(written);
            }
            let length = length as usize;
            if offset + length > packet.len() {
                return Err(malformed());
            }
            if written != 0 {
                if written + 1 >= output.len() { return Err(super::Errno::MSGSIZE); }
                output[written] = b'.';
                written += 1;
            }
            if written + length >= output.len() {
                return Err(super::Errno::MSGSIZE);
            }
            output[written..written + length].copy_from_slice(&packet[offset..offset + length]);
            written += length;
            offset += length;
            if !jumped {
                consumed += length + 1;
            }
        }
    }

    /// Sends a DNS query through the explicitly configured nameservers.
    ///
    /// The exchange is UDP-only in this bounded slice. Truncated responses are
    /// returned to the caller for explicit policy handling; no TCP fallback is
    /// hidden behind the native API yet.
    pub fn exchange(config: &ExchangeConfig, query: &[u8], query_id: u16, answer: &mut [u8]) -> Result<usize> {
        if config.nameserver_count == 0
            || config.nameserver_count > MAX_NAMESERVERS
            || config.timeout_ms == 0
            || config.attempts == 0
            || query.len() < 12
            || answer.len() < 12
        {
            return Err(invalid());
        }
        let mut attempt = 0u8;
        while attempt < config.attempts {
            let mut index = 0usize;
            while index < config.nameserver_count {
                let server = config.nameservers[index];
                let fd = match net::socket(server.family as i32, SOCK_DGRAM | SOCK_CLOEXEC, 0) {
                    Ok(fd) => fd,
                    Err(_) => { index += 1; continue; }
                };
                let connected = if server.family == AF_INET {
                    let address = SockaddrIn {
                        family: AF_INET,
                        port: (if server.port == 0 { 53 } else { server.port }).to_be(),
                        address: u32::from_ne_bytes([
                            server.address[0], server.address[1], server.address[2], server.address[3],
                        ]),
                        zero: [0; 8],
                    };
                    // SAFETY: `address` remains alive across the direct syscall.
                    unsafe { net::connect_raw(fd, (&address as *const SockaddrIn).cast(), 16) }
                } else if server.family == AF_INET6 {
                    let address = SockaddrIn6 {
                        family: AF_INET6,
                        port: (if server.port == 0 { 53 } else { server.port }).to_be(),
                        flow_info: 0,
                        address: server.address,
                        scope_id: server.scope_id,
                    };
                    // SAFETY: `address` remains alive across the direct syscall.
                    unsafe { net::connect_raw(fd, (&address as *const SockaddrIn6).cast(), 28) }
                } else {
                    Err(invalid())
                };
                if connected.is_err() {
                    let _ = super::io::close(fd);
                    index += 1;
                    continue;
                }
                let sent = unsafe {
                    net::sendto_raw(fd, query.as_ptr(), query.len(), MSG_NOSIGNAL, core::ptr::null(), 0)
                };
                if sent != Ok(query.len()) {
                    let _ = super::io::close(fd);
                    index += 1;
                    continue;
                }
                let mut poll = PollFd { fd, events: POLLIN, revents: 0 };
                let timeout = Timespec {
                    seconds: (config.timeout_ms / 1000) as i64,
                    nanoseconds: ((config.timeout_ms % 1000) as i64) * 1_000_000,
                };
                let ready = loop {
                    // SAFETY: `poll` and `timeout` are valid local kernel ABI records.
                    match unsafe {
                        super::event::ppoll_raw(
                            (&mut poll as *mut PollFd).cast(),
                            1,
                            (&timeout as *const Timespec).cast(),
                            core::ptr::null(),
                            8,
                        )
                    } {
                        Ok(value) => break value,
                        Err(error) if error == super::Errno::INTR => continue,
                        Err(_) => break 0,
                    }
                };
                if ready > 0 && poll.revents & (POLLIN | POLLERR | POLLHUP | POLLNVAL) != 0 {
                    let received = unsafe {
                        net::recvfrom_raw(
                            fd,
                            answer.as_mut_ptr(),
                            answer.len(),
                            0,
                            core::ptr::null_mut(),
                            core::ptr::null_mut(),
                        )
                    };
                    let _ = super::io::close(fd);
                    if let Ok(length) = received {
                        if length >= 2
                            && u16::from_be_bytes([answer[0], answer[1]]) == query_id
                        {
                            return Ok(length);
                        }
                    }
                } else {
                    let _ = super::io::close(fd);
                }
                index += 1;
            }
            attempt = attempt.saturating_add(1);
        }
        Err(super::Errno::TIMEDOUT)
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

/// Direct Linux/AArch64 signal operations.
///
/// This module exposes only kernel ABI records and direct syscalls. Policy
/// around reserved libc signals, handler lifetimes, and safe Rust vocabulary
/// belongs to `crabc-rs::signal`; C's public `sigaction` record is likewise a
/// distinct ABI boundary in `libc`.
pub mod signal {
    use super::{
        decode, decode_i32, syscall2, syscall3, syscall4, Result,
        SYS_RT_SIGACTION, SYS_RT_SIGPENDING, SYS_RT_SIGPROCMASK,
        SYS_RT_SIGQUEUEINFO, SYS_RT_SIGSUSPEND, SYS_RT_SIGTIMEDWAIT,
        SYS_SIGALTSTACK, SYS_SIGNALFD4,
    };

    /// The Linux/AArch64 signal-set width passed to every `rt_*` syscall.
    ///
    /// Linux's kernel ABI deliberately accepts one 64-bit word here, even
    /// though musl's public `sigset_t` has more storage for source ABI
    /// compatibility.
    pub const KERNEL_SIGSET_SIZE: usize = core::mem::size_of::<u64>();

    /// Linux/AArch64's compact `rt_sigaction` record.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct KernelSigAction {
        pub handler: usize,
        pub flags: u64,
        pub restorer: usize,
        pub mask: u64,
    }

    /// Linux's fixed-size `siginfo_t` transport record.
    ///
    /// The kernel fills only the fields meaningful for the triggering signal.
    /// Consumers must interpret it according to `si_code`.
    #[repr(C, align(8))]
    #[derive(Clone, Copy)]
    pub struct SigInfo {
        pub bytes: [u8; 128],
    }

    impl SigInfo {
        /// A zeroed record suitable for kernel output.
        #[inline]
        pub const fn zeroed() -> Self {
            Self { bytes: [0; 128] }
        }
    }

    /// Linux/AArch64's `stack_t` layout for `sigaltstack`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct SignalStack {
        pub sp: *mut u8,
        pub flags: i32,
        _padding: i32,
        pub size: usize,
    }

    impl SignalStack {
        /// Builds a kernel signal-stack record with the required AArch64
        /// padding initialized to zero.
        #[inline]
        pub const fn new(sp: *mut u8, flags: i32, size: usize) -> Self {
            Self { sp, flags, _padding: 0, size }
        }
    }

    /// Installs or queries a signal action without libc or TLS `errno`.
    ///
    /// # Safety
    ///
    /// `action` and `old_action` must be null or point to valid compact
    /// Linux/AArch64 records for the duration of the call. A non-null handler
    /// and restorer must satisfy the kernel's asynchronous signal ABI.
    #[inline]
    pub unsafe fn rt_sigaction_raw(
        signal: i32,
        action: *const KernelSigAction,
        old_action: *mut KernelSigAction,
    ) -> Result<()> {
        // SAFETY: The caller owns the compact-kernel-record pointer and
        // handler/restorer contracts; the other arguments are scalar values.
        decode(unsafe {
            syscall4(
                SYS_RT_SIGACTION,
                signal as usize,
                action as usize,
                old_action as usize,
                KERNEL_SIGSET_SIZE,
            )
        })
        .map(|_| ())
    }

    /// Changes or queries the calling thread's kernel signal mask.
    ///
    /// # Safety
    ///
    /// `set` and `old_set` must be null or point to one readable/writable
    /// kernel-sized signal-set word, respectively.
    #[inline]
    pub unsafe fn rt_sigprocmask_raw(
        how: i32,
        set: *const u64,
        old_set: *mut u64,
    ) -> Result<()> {
        // SAFETY: The caller owns the kernel signal-set pointer contracts.
        decode(unsafe {
            syscall4(
                SYS_RT_SIGPROCMASK,
                how as usize,
                set as usize,
                old_set as usize,
                KERNEL_SIGSET_SIZE,
            )
        })
        .map(|_| ())
    }

    /// Queries the calling thread's pending signal set.
    ///
    /// # Safety
    ///
    /// `set` must point to writable storage for one kernel-sized signal-set
    /// word.
    #[inline]
    pub unsafe fn rt_sigpending_raw(set: *mut u64) -> Result<()> {
        // SAFETY: The caller owns the kernel signal-set output storage.
        decode(unsafe { syscall2(SYS_RT_SIGPENDING, set as usize, KERNEL_SIGSET_SIZE) })
            .map(|_| ())
    }

    /// Atomically swaps in `set` while waiting for an unblocked signal.
    ///
    /// A successful wait never returns; Linux reports `EINTR` after a handler
    /// runs. The returned error is intentionally preserved as an ordinary
    /// result value rather than being translated through TLS `errno`.
    ///
    /// # Safety
    ///
    /// `set` must point to one readable kernel-sized signal-set word.
    #[inline]
    pub unsafe fn rt_sigsuspend_raw(set: *const u64) -> Result<()> {
        // SAFETY: The caller owns the kernel signal-set input storage.
        decode(unsafe { syscall2(SYS_RT_SIGSUSPEND, set as usize, KERNEL_SIGSET_SIZE) })
            .map(|_| ())
    }

    /// Waits for one signal in `set` and returns its signal number.
    ///
    /// # Safety
    ///
    /// `set` must point to one readable kernel-sized signal-set word.
    /// `info` must be null or point to writable 128-byte Linux `siginfo_t`
    /// storage. `timeout` must be null or point to one Linux/AArch64
    /// `timespec` record.
    #[inline]
    pub unsafe fn rt_sigtimedwait_raw(
        set: *const u64,
        info: *mut SigInfo,
        timeout: *const u8,
    ) -> Result<i32> {
        // SAFETY: The caller owns every pointed-to kernel ABI record.
        decode_i32(unsafe {
            syscall4(
                SYS_RT_SIGTIMEDWAIT,
                set as usize,
                info as usize,
                timeout as usize,
                KERNEL_SIGSET_SIZE,
            )
        })
    }

    /// Queues the supplied Linux `siginfo_t` record to a process.
    ///
    /// # Safety
    ///
    /// `info` must point to a fully initialized Linux signal-information
    /// record whose fields satisfy `rt_sigqueueinfo`'s ABI contract.
    #[inline]
    pub unsafe fn rt_sigqueueinfo_raw(
        pid: i32,
        signal: i32,
        info: *const SigInfo,
    ) -> Result<()> {
        // SAFETY: The caller owns the signal-info input record contract.
        decode(unsafe {
            syscall3(
                SYS_RT_SIGQUEUEINFO,
                pid as usize,
                signal as usize,
                info as usize,
            )
        })
        .map(|_| ())
    }

    /// Installs or queries an alternate signal stack.
    ///
    /// # Safety
    ///
    /// `stack` and `old_stack` must be null or point to valid Linux/AArch64
    /// `stack_t` records. Any enabled stack memory must remain valid while the
    /// kernel may dispatch a signal on it.
    #[inline]
    pub unsafe fn sigaltstack_raw(
        stack: *const SignalStack,
        old_stack: *mut SignalStack,
    ) -> Result<()> {
        // SAFETY: The caller owns both `stack_t` pointer contracts.
        decode(unsafe { syscall2(SYS_SIGALTSTACK, stack as usize, old_stack as usize) })
            .map(|_| ())
    }

    /// Creates or updates a Linux `signalfd4` descriptor.
    ///
    /// # Safety
    ///
    /// `mask` must point to one readable Linux kernel-sized signal-set word.
    /// When `fd` is non-negative it must designate an existing signalfd
    /// descriptor. `flags` uses Linux's `SFD_*` bit representation.
    #[inline]
    pub unsafe fn signalfd4_raw(
        fd: i32,
        mask: *const u64,
        flags: u32,
    ) -> Result<i32> {
        // SAFETY: The caller owns the mask pointer and descriptor contracts.
        decode_i32(unsafe {
            syscall4(
                SYS_SIGNALFD4,
                fd as usize,
                mask as usize,
                KERNEL_SIGSET_SIZE,
                flags as usize,
            )
        })
    }
}

/// Direct process-identity, process-group, and signal operations.
pub mod process {
    use super::{
        decode, decode_i32, syscall0, syscall1, syscall2, syscall3, syscall4, syscall5, Result,
        SYS_CLONE, SYS_EXECVE, SYS_EXIT_GROUP, SYS_GETPGID, SYS_GETPID, SYS_GETPPID,
        SYS_GETSID, SYS_GETUID, SYS_KILL, SYS_SETPGID, SYS_SETSID, SYS_TGKILL, SYS_WAIT4,
        SYS_WAITID,
    };

    /// The low-byte clone exit signal used by Linux's fork-equivalent clone.
    pub const CLONE_FORK_FLAGS: u64 = 17;

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

    /// Returns the caller's real Linux user ID.
    #[inline]
    pub fn getuid() -> u32 {
        // Linux guarantees that `getuid` succeeds and returns a `uid_t`.
        unsafe { syscall0(SYS_GETUID) as u32 }
    }

    /// Sends `signal` to the raw Linux process target `pid`.
    #[inline]
    pub fn kill(pid: i32, signal: i32) -> Result<()> {
        // SAFETY: Both arguments are immediate Linux scalar values.
        decode(unsafe { syscall2(SYS_KILL, pid as usize, signal as usize) }).map(|_| ())
    }

    /// Sends a signal to one exact thread in a process.
    #[inline]
    pub fn tgkill(tgid: i32, tid: i32, signal: i32) -> Result<()> {
        // SAFETY: All arguments are immediate Linux scalar values.
        decode(unsafe {
            syscall3(
                SYS_TGKILL,
                tgid as usize,
                tid as usize,
                signal as usize,
            )
        })
        .map(|_| ())
    }

    /// Creates a child process using the raw Linux fork-equivalent clone.
    ///
    /// This is deliberately only a kernel primitive. It does not run libc or
    /// facade atfork handlers, repair runtime state, or make arbitrary Rust
    /// execution in a multithreaded child safe.
    #[inline]
    pub fn fork_raw() -> Result<i32> {
        // SAFETY: `SIGCHLD` and a null child stack form Linux's documented
        // fork-equivalent `clone` invocation. No parent/child TID, TLS, or
        // namespace flags are requested, so their ignored argument registers
        // are immaterial.
        decode_i32(unsafe { syscall2(SYS_CLONE, CLONE_FORK_FLAGS as usize, 0) })
    }

    /// Executes a new program image through Linux `execve`.
    ///
    /// On success this syscall does not return. A successful `Ok(())` is kept
    /// in the type solely to model the direct syscall seam consistently.
    ///
    /// # Safety
    ///
    /// `path` must name a readable NUL-terminated pathname. `argv` and `envp`
    /// must be null-terminated arrays of readable NUL-terminated strings (or
    /// a null `envp` only where the kernel ABI permits it).
    #[inline]
    pub unsafe fn execve_raw(
        path: *const u8,
        argv: *const *const u8,
        envp: *const *const u8,
    ) -> Result<()> {
        // SAFETY: The caller owns every pointer/array/string contract.
        decode(unsafe {
            syscall3(
                SYS_EXECVE,
                path as usize,
                argv as usize,
                envp as usize,
            )
        })
        .map(|_| ())
    }

    /// Waits for a child process state change through Linux `wait4`.
    ///
    /// `pid` and `options` retain the Linux `waitpid` encoding. A successful
    /// zero means `WNOHANG` found no waitable child.
    ///
    /// # Safety
    ///
    /// `status` must be null or point to writable Linux `int` storage.
    #[inline]
    pub unsafe fn wait4_raw(pid: i32, status: *mut i32, options: u32) -> Result<i32> {
        // SAFETY: This convenience form explicitly declines rusage output.
        unsafe { wait4_with_rusage_raw(pid, status, options, core::ptr::null_mut()) }
    }

    /// Waits for a child process state change through Linux `wait4`, with an
    /// optional caller-owned kernel `struct rusage` output record.
    ///
    /// # Safety
    ///
    /// `status` and `rusage` must each be null or point to writable storage
    /// for their exact Linux/AArch64 records.
    #[inline]
    pub unsafe fn wait4_with_rusage_raw(
        pid: i32,
        status: *mut i32,
        options: u32,
        rusage: *mut u8,
    ) -> Result<i32> {
        // SAFETY: The caller owns the optional status-output storage; the
        // optional rusage output has the same caller-owned ABI contract.
        decode_i32(unsafe {
            syscall4(
                SYS_WAIT4,
                pid as usize,
                status as usize,
                options as usize,
                rusage as usize,
            )
        })
    }

    /// Waits through Linux `waitid` and fills a 128-byte `siginfo_t` record.
    ///
    /// # Safety
    ///
    /// `info` must point to writable, eight-byte-aligned Linux `siginfo_t`
    /// storage. `id_type`, `id`, and `options` must use Linux `waitid`
    /// encodings.
    #[inline]
    pub unsafe fn waitid_raw(
        id_type: u32,
        id: u32,
        info: *mut super::signal::SigInfo,
        options: u32,
    ) -> Result<()> {
        // SAFETY: The caller owns the output-record contract and supplies
        // Linux scalar encodings for the remaining immediate arguments.
        decode(unsafe {
            syscall5(
                SYS_WAITID,
                id_type as usize,
                id as usize,
                info as usize,
                options as usize,
                0,
            )
        })
        .map(|_| ())
    }

    /// Terminates the current Linux thread group without invoking Rust destructors
    /// or the public C ABI.
    #[inline]
    pub fn exit_immediately(status: i32) -> ! {
        // SAFETY: `exit_group` has one immediate scalar argument and cannot
        // return after a successful kernel entry.
        unsafe { syscall1(SYS_EXIT_GROUP, status as usize) };
        // Linux cannot return from a successful exit syscall. If a hostile or
        // non-Linux execution environment did, continuing would be unsound.
        panic!("Linux exit_group syscall returned")
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
    use super::{decode, syscall0, syscall6, Result, SYS_FUTEX, SYS_GETTID, SYS_SCHED_YIELD};

    /// `FUTEX_WAIT`, waiting while the futex word still equals `expected`.
    pub const FUTEX_WAIT: u32 = 0;
    /// `FUTEX_WAKE`, waking up to the requested number of waiters.
    pub const FUTEX_WAKE: u32 = 1;
    /// Use process-private futex hashing. Process-shared objects omit this bit.
    pub const FUTEX_PRIVATE_FLAG: u32 = 128;

    /// Performs a raw Linux futex operation.
    ///
    /// This is the stateless kernel seam used by native Rust synchronization
    /// objects and by the C facade. The timeout pointer, when non-null, must
    /// point to a Linux/AArch64 `struct timespec`; for `FUTEX_WAIT` it is a
    /// relative timeout.
    ///
    /// # Safety
    ///
    /// `address` must be a valid, four-byte-aligned futex word readable for
    /// the duration of the syscall. `timeout` must be null or point to a
    /// readable Linux/AArch64 timespec. `operation` must be a supported
    /// futex operation plus any valid futex flags.
    #[inline]
    pub unsafe fn futex_raw(
        address: *const u32,
        operation: u32,
        expected: u32,
        timeout: *const u8,
        secondary: *const u32,
        value3: u32,
    ) -> Result<usize> {
        // SAFETY: The caller owns the futex word and optional timeout memory
        // contracts; all remaining arguments are immediate kernel values.
        decode(unsafe {
            syscall6(
                SYS_FUTEX,
                address as usize,
                operation as usize,
                expected as usize,
                timeout as usize,
                secondary as usize,
                value3 as usize,
            )
        })
    }

    /// Waits while `address` still contains `expected`.
    ///
    /// `timeout` is a nullable pointer to a relative Linux/AArch64 timespec.
    /// `private` selects `FUTEX_PRIVATE_FLAG`; set it to false for a
    /// process-shared synchronization object.
    ///
    /// # Safety
    ///
    /// The futex word and optional timeout must satisfy the contracts of
    /// [`futex_raw`].
    #[inline]
    pub unsafe fn futex_wait(
        address: *const u32,
        expected: u32,
        private: bool,
        timeout: *const u8,
    ) -> Result<()> {
        let operation = FUTEX_WAIT | if private { FUTEX_PRIVATE_FLAG } else { 0 };
        // SAFETY: The caller supplied the futex and timeout contracts.
        unsafe { futex_raw(address, operation, expected, timeout, core::ptr::null(), 0) }
            .map(|_| ())
    }

    /// Wakes up to `count` waiters sleeping on `address`.
    ///
    /// Set `private` to false for a process-shared synchronization object.
    /// The returned count is the number of waiters woken by the kernel.
    ///
    /// # Safety
    ///
    /// `address` must be a valid, four-byte-aligned futex word readable for
    /// the duration of the syscall.
    #[inline]
    pub unsafe fn futex_wake(
        address: *const u32,
        count: u32,
        private: bool,
    ) -> Result<usize> {
        let operation = FUTEX_WAKE | if private { FUTEX_PRIVATE_FLAG } else { 0 };
        // SAFETY: The caller supplied the futex-word contract.
        unsafe { futex_raw(address, operation, count, core::ptr::null(), core::ptr::null(), 0) }
    }

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
