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

/// Direct, typed access to the calling thread's AArch64 floating-point state.
pub mod fenv;
/// Allocation-free character-set conversion shared by the native and C facades.
pub mod iconv;
/// Stateless byte-oriented filename pattern matching shared by both facades.
pub mod pattern;
/// Direct, allocation-free reads of Linux's process auxiliary vector.
pub mod param;
/// Pure byte-string algorithms shared by native text operations.
pub mod text;
/// Linux/AArch64 vDSO discovery and typed time dispatch.
mod vdso;

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

    /// Opaque handle representation for one libc-owned buffered memory stream.
    ///
    /// This is a private wire value only. Native callers must neither inspect
    /// nor dereference it; the loaded libc owns the underlying `FILE` and its
    /// allocation lifetime.
    pub type CFileHandleV1 = *mut c_void;

    /// Private memory-stream mode values accepted by `cfile_open_memory`.
    ///
    /// These describe the same six direction/start-position combinations as
    /// `fmemopen`, but are deliberately not C mode-string bytes. Keeping the
    /// values typed on this wire prevents a native facade from transporting a
    /// caller-owned C string into libc's process-singleton stdio state.
    pub const CFILE_MODE_READ: u32 = 0;
    pub const CFILE_MODE_WRITE: u32 = 1;
    pub const CFILE_MODE_APPEND: u32 = 2;
    pub const CFILE_MODE_READ_UPDATE: u32 = 3;
    pub const CFILE_MODE_WRITE_UPDATE: u32 = 4;
    pub const CFILE_MODE_APPEND_UPDATE: u32 = 5;

    /// Private memory-stream seek-origin values accepted by `cfile_seek`.
    pub const CFILE_SEEK_START: u32 = 0;
    pub const CFILE_SEEK_CURRENT: u32 = 1;
    pub const CFILE_SEEK_END: u32 = 2;

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

    /// One copied record in a native loaded-image snapshot.
    ///
    /// Pointer fields are process addresses copied as values from the loader;
    /// they do not point at loader-owned records and do not grant permission to
    /// dereference an image after its lifetime has ended. Text is copied into
    /// the fixed [`TextV1`] wire representation before the operation returns.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct LoaderImageV1 {
        /// Relocated load address of the image.
        pub image_base: *mut c_void,
        /// Address of the image's mapped ELF program-header table.
        pub program_headers: *const c_void,
        /// Number of entries in `program_headers`.
        pub program_header_count: u16,
        /// Reserved wire padding; must be zero.
        pub _reserved: u16,
        /// Loader load-event count at the snapshot boundary.
        pub additions: u64,
        /// Loader unload-event count at the snapshot boundary.
        pub removals: u64,
        /// One-based TLS module ID, or zero when the image has no TLS.
        pub tls_module: usize,
        /// Current-thread TLS data address, or null when the image has no TLS.
        pub tls_data: *mut c_void,
        /// Copied image name.
        pub image_name: TextV1,
    }

    impl LoaderImageV1 {
        /// Creates an empty output record.
        #[inline]
        pub const fn empty() -> Self {
            Self {
                image_base: core::ptr::null_mut(),
                program_headers: core::ptr::null(),
                program_header_count: 0,
                _reserved: 0,
                additions: 0,
                removals: 0,
                tls_module: 0,
                tls_data: core::ptr::null_mut(),
                image_name: TextV1::empty(),
            }
        }
    }

    /// Copied information for one loader handle.
    ///
    /// This is the owned native counterpart of the useful `RTLD_DI_LINKMAP`
    /// fields. It deliberately contains no `link_map *`, next/previous links,
    /// or borrowed name pointer.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct LoaderInformationV1 {
        /// Relocated load address of the image.
        pub image_base: *mut c_void,
        /// Address of the image's dynamic section, copied as an opaque value.
        pub dynamic_address: *mut c_void,
        /// Copied image name.
        pub image_name: TextV1,
    }

    impl LoaderInformationV1 {
        /// Creates an empty output record.
        #[inline]
        pub const fn empty() -> Self {
            Self {
                image_base: core::ptr::null_mut(),
                dynamic_address: core::ptr::null_mut(),
                image_name: TextV1::empty(),
            }
        }
    }

    /// Maximum number of records the current loader can return in one bounded
    /// snapshot. This is a private wire bound, not a public ELF limit.
    pub const LOADER_SNAPSHOT_CAPACITY: usize = 16;

    /// Private v1 runtime table owned by the loaded crabc runtime.
    ///
    /// Each callback documents its own non-success status: loader operations
    /// use `-1` plus copied `TextV1` diagnostics, while pthread and CFile
    /// operations return positive Linux/pthread error values. None transports
    /// a public C sentinel or TLS `errno` result across this boundary.
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
        /// Opens a libc-owned buffered view over a caller-borrowed byte
        /// buffer. `mode` is one of the private `CFILE_MODE_*` values; all
        /// failures are positive Linux errno values, never C sentinels/TLS
        /// errno. The runtime does not retain the handle after `cfile_close`.
        pub cfile_open_memory: unsafe extern "C" fn(
            buffer: *mut u8,
            length: usize,
            mode: u32,
            handle: *mut CFileHandleV1,
        ) -> c_int,
        /// Reads up to `length` bytes, returning the count through `read`.
        /// A short successful read at end-of-file returns zero status.
        pub cfile_read: unsafe extern "C" fn(
            handle: CFileHandleV1,
            buffer: *mut u8,
            length: usize,
            read: *mut usize,
        ) -> c_int,
        /// Writes up to `length` bytes, returning the count through `written`.
        /// A short successful write is represented by its count, not a C
        /// sentinel; an actual stream failure is a positive errno status.
        pub cfile_write: unsafe extern "C" fn(
            handle: CFileHandleV1,
            buffer: *const u8,
            length: usize,
            written: *mut usize,
        ) -> c_int,
        /// Flushes buffered output for one memory stream.
        pub cfile_flush: unsafe extern "C" fn(handle: CFileHandleV1) -> c_int,
        /// Seeks within one memory stream and returns the resulting absolute
        /// byte position through `position`.
        pub cfile_seek: unsafe extern "C" fn(
            handle: CFileHandleV1,
            offset: i64,
            origin: u32,
            position: *mut u64,
        ) -> c_int,
        /// Returns the current absolute byte position.
        pub cfile_tell: unsafe extern "C" fn(
            handle: CFileHandleV1,
            position: *mut u64,
        ) -> c_int,
        /// Copies the end-of-file indicator as zero or one.
        pub cfile_eof: unsafe extern "C" fn(
            handle: CFileHandleV1,
            eof: *mut u8,
        ) -> c_int,
        /// Copies the stream-error indicator as zero or one.
        pub cfile_error: unsafe extern "C" fn(
            handle: CFileHandleV1,
            error: *mut u8,
        ) -> c_int,
        /// Rewinds one memory stream and clears its EOF/error indicators.
        pub cfile_reset: unsafe extern "C" fn(handle: CFileHandleV1) -> c_int,
        /// Closes one memory stream and releases all libc-owned allocations.
        /// The caller must discard the handle after this call regardless of
        /// whether the returned close/flush status is successful.
        pub cfile_close: unsafe extern "C" fn(handle: CFileHandleV1) -> c_int,
        /// Copies the loader's current image records into caller-owned output.
        /// The callback-free operation holds the loader lock only while it
        /// copies records; it never exposes `link_map` storage or calls user
        /// code while locked.
        pub loader_snapshot: unsafe extern "C" fn(
            records: *mut LoaderImageV1,
            capacity: usize,
            count: *mut usize,
            generation: *mut u64,
            error: *mut TextV1,
        ) -> c_int,
        /// Copies useful `RTLD_DI_LINKMAP` information for one loader handle.
        /// The output contains no loader-owned `link_map *`.
        pub loader_information: unsafe extern "C" fn(
            handle: *mut c_void,
            info: *mut LoaderInformationV1,
            error: *mut TextV1,
        ) -> c_int,
    }

    /// Minimum table size containing all pre-introspection v1 callbacks.
    ///
    /// New consumers must accept an older table whose `abi_size` reaches this
    /// boundary, then gate the append-only introspection fields separately.
    pub const V1_LEGACY_SIZE: usize = core::mem::offset_of!(RuntimeV1, loader_snapshot);
}

const MAX_ERRNO: i32 = 4095;
const SYS_READ: usize = 63;
const SYS_WRITE: usize = 64;
const SYS_READV: usize = 65;
const SYS_WRITEV: usize = 66;
const SYS_PREAD64: usize = 67;
const SYS_PWRITE64: usize = 68;
const SYS_PREADV: usize = 69;
const SYS_PWRITEV: usize = 70;
const SYS_SENDFILE: usize = 71;
const SYS_VMSPLICE: usize = 75;
const SYS_SPLICE: usize = 76;
const SYS_TEE: usize = 77;
const SYS_COPY_FILE_RANGE: usize = 285;
const SYS_PREADV2: usize = 286;
const SYS_PWRITEV2: usize = 287;
const SYS_LSEEK: usize = 62;
const SYS_FCNTL: usize = 25;
const SYS_DUP: usize = 23;
const SYS_DUP3: usize = 24;
const SYS_CLOSE: usize = 57;
const SYS_FLOCK: usize = 32;
// Linux/AArch64 `mknodat` is the generic syscall numbered 33. The pinned
// Rustix linux_raw backend and crabc's checked-in AArch64 syscall header both
// carry this number; it precedes `mkdirat` (34) in the kernel table.
const SYS_MKNODAT: usize = 33;
const SYS_OPENAT: usize = 56;
const SYS_MEMFD_CREATE: usize = 279;
const SYS_IOCTL: usize = 29;
// Linux/AArch64's inotify descriptor, watch-addition, and watch-removal
// syscalls are generic entries 26 through 28. They remain a small direct
// seam: higher layers own watch and event-buffer lifetimes.
const SYS_INOTIFY_INIT1: usize = 26;
const SYS_INOTIFY_ADD_WATCH: usize = 27;
const SYS_INOTIFY_RM_WATCH: usize = 28;
const SYS_MKDIRAT: usize = 34;
const SYS_UNLINKAT: usize = 35;
const SYS_SYMLINKAT: usize = 36;
const SYS_LINKAT: usize = 37;
const SYS_FACCESSAT: usize = 48;
// Linux added the flags-bearing access check in 5.8. Keep this direct seam
// separate from `faccessat`: AArch64's older syscall has no flags register.
const SYS_FACCESSAT2: usize = 439;
const SYS_FCHMOD: usize = 52;
const SYS_FCHMODAT: usize = 53;
// Linux/AArch64 syscall numbers from the pinned linux-raw-sys AArch64 table:
// fchownat(2) is 54 and fchown(2) is 55. AArch64 has no chown/lchown syscall;
// those pathname forms use fchownat with AT_FDCWD and (for lchown) the
// AT_SYMLINK_NOFOLLOW flag.
const SYS_FCHOWNAT: usize = 54;
const SYS_FCHOWN: usize = 55;
const SYS_TRUNCATE: usize = 45;
const SYS_FTRUNCATE: usize = 46;
const SYS_FALLOCATE: usize = 47;
const SYS_FADVISE64: usize = 223;
const SYS_FSYNC: usize = 82;
const SYS_FDATASYNC: usize = 83;
// AArch64's generic Linux `sync` syscall has no arguments and no status
// contract: Linux documents it as always successful.
const SYS_SYNC: usize = 81;
// AArch64 exposes the generic `sync_file_range` syscall at 84.
const SYS_SYNC_FILE_RANGE: usize = 84;
const SYS_SYNCFS: usize = 267;
const SYS_GETDENTS64: usize = 61;
const SYS_NEWFSTATAT: usize = 79;
const SYS_READLINKAT: usize = 78;
const SYS_GETCWD: usize = 17;
// Linux/AArch64 process working-directory syscalls.  These mutate the
// process-global CWD; the native facade documents the caller coordination
// required around concurrent pathname operations.
const SYS_CHDIR: usize = 49;
const SYS_FCHDIR: usize = 50;
// Linux/AArch64's legacy process-root operation. Keep it separate from the
// C facade so native callers receive direct kernel errors, not TLS errno.
const SYS_CHROOT: usize = 51;
const SYS_FSTAT: usize = 80;
const SYS_STATFS: usize = 43;
const SYS_FSTATFS: usize = 44;
// Linux/AArch64 `statx` is the extended metadata syscall introduced in 4.11.
const SYS_STATX: usize = 291;
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
const SYS_CLOCK_SETTIME: usize = 112;
const SYS_CLOCK_GETTIME: usize = 113;
const SYS_CLOCK_GETRES: usize = 114;
const SYS_CLOCK_NANOSLEEP: usize = 115;
const SYS_GETITIMER: usize = 102;
const SYS_SETITIMER: usize = 103;
const SYS_TIMER_CREATE: usize = 107;
const SYS_TIMER_GETTIME: usize = 108;
const SYS_TIMER_GETOVERRUN: usize = 109;
const SYS_TIMER_SETTIME: usize = 110;
const SYS_TIMER_DELETE: usize = 111;
const SYS_GETTIMEOFDAY: usize = 169;
const SYS_NANOSLEEP: usize = 101;
const SYS_GETRANDOM: usize = 278;
const SYS_EVENTFD2: usize = 19;
// Linux/AArch64 POSIX message-queue syscalls.  The kernel ABI is fixed-arity
// even though the C mq_open wrapper is variadic; native callers use the typed
// four-argument form below and never cross that C ABI.
const SYS_MQ_OPEN: usize = 180;
const SYS_MQ_UNLINK: usize = 181;
const SYS_MQ_TIMEDSEND: usize = 182;
const SYS_MQ_TIMEDRECEIVE: usize = 183;
const SYS_MQ_GETSETATTR: usize = 185;
const SYS_PPOLL: usize = 73;
const SYS_PSELECT6: usize = 72;
const SYS_EPOLL_CREATE1: usize = 20;
const SYS_EPOLL_CTL: usize = 21;
const SYS_EPOLL_PWAIT: usize = 22;
const SYS_TIMERFD_CREATE: usize = 85;
const SYS_TIMERFD_SETTIME: usize = 86;
const SYS_TIMERFD_GETTIME: usize = 87;
const SYS_SIGNALFD4: usize = 74;
const SYS_SOCKET: usize = 198;
const SYS_SOCKETPAIR: usize = 199;
const SYS_BIND: usize = 200;
const SYS_LISTEN: usize = 201;
const SYS_ACCEPT: usize = 202;
const SYS_SHUTDOWN: usize = 210;
const SYS_CONNECT: usize = 203;
const SYS_GETSOCKNAME: usize = 204;
const SYS_GETPEERNAME: usize = 205;
const SYS_SENDTO: usize = 206;
const SYS_RECVFROM: usize = 207;
const SYS_SETSOCKOPT: usize = 208;
const SYS_GETSOCKOPT: usize = 209;
const SYS_SENDMSG: usize = 211;
const SYS_RECVMSG: usize = 212;
// Linux/AArch64 uses the generic syscall table entries for batched socket
// messages.  Keep these separate from sendmsg/recvmsg: the latter receive a
// single msghdr, while these consume an array of private mmsghdr records.
const SYS_RECVMMSG: usize = 243;
const SYS_SENDMMSG: usize = 269;
const SYS_READAHEAD: usize = 213;
const SYS_ACCEPT4: usize = 242;
const SYS_MUNMAP: usize = 215;
const SYS_MREMAP: usize = 216;
const SYS_MMAP: usize = 222;
const SYS_MPROTECT: usize = 226;
const SYS_MSYNC: usize = 227;
const SYS_MLOCK: usize = 228;
const SYS_MUNLOCK: usize = 229;
const SYS_MINCORE: usize = 232;
const SYS_MADVISE: usize = 233;
const SYS_MLOCK2: usize = 284;
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
const SYS_GETRESUID: usize = 148;
const SYS_SETRESUID: usize = 147;
const SYS_GETRESGID: usize = 150;
const SYS_SETRESGID: usize = 149;
const SYS_SETFSUID: usize = 151;
const SYS_SETFSGID: usize = 152;
const SYS_GETGROUPS: usize = 158;
const SYS_GETRUSAGE: usize = 165;
const SYS_UMASK: usize = 166;
const SYS_GETPRIORITY: usize = 141;
const SYS_SETPRIORITY: usize = 140;
const SYS_TIMES: usize = 153;
const SYS_GETUID: usize = 174;
const SYS_GETEUID: usize = 175;
const SYS_GETGID: usize = 176;
const SYS_GETEGID: usize = 177;
const SYS_GETTID: usize = 178;
// Linux/AArch64 `getcpu`, used by the native thread CPU observation seam.
const SYS_GETCPU: usize = 168;
// Linux/AArch64 process-break and legacy virtual-memory operations.  These
// are kept as raw seams because their public libc wrappers have distinct
// sentinel/state conventions.
const SYS_BRK: usize = 214;
const SYS_REMAP_FILE_PAGES: usize = 234;
const SYS_MLOCKALL: usize = 230;
const SYS_MUNLOCKALL: usize = 231;
const SYS_SYSINFO: usize = 179;
const SYS_SCHED_YIELD: usize = 124;
const SYS_SCHED_GET_PRIORITY_MAX: usize = 125;
const SYS_SCHED_GET_PRIORITY_MIN: usize = 126;
const SYS_SCHED_RR_GET_INTERVAL: usize = 127;
const SYS_SCHED_SETAFFINITY: usize = 122;
const SYS_SCHED_GETAFFINITY: usize = 123;
const SYS_FUTEX: usize = 98;
const SYS_CLONE: usize = 220;
const SYS_EXECVE: usize = 221;
const SYS_WAIT4: usize = 260;
const SYS_WAITID: usize = 95;
const SYS_PRLIMIT64: usize = 261;
const SYS_PIDFD_OPEN: usize = 434;
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
        decode, decode_i32, syscall1, syscall3, syscall4, syscall5, syscall6, RawFd, Result, SYS_CLOSE,
        SYS_DUP, SYS_DUP3, SYS_FCNTL, SYS_IOCTL, SYS_PREAD64, SYS_PREADV, SYS_PWRITE64,
        SYS_SENDFILE, SYS_SYNC_FILE_RANGE,
        SYS_PREADV2, SYS_PWRITEV, SYS_PWRITEV2, SYS_READ, SYS_READV, SYS_WRITE, SYS_WRITEV,
    };

    /// One Linux `struct iovec` record for direct vectored I/O.
    ///
    /// This is an ABI record rather than a safe buffer abstraction. Callers
    /// must uphold the pointer and aliasing requirements documented by
    /// [`readv_raw`] and [`writev_raw`]. The layout is the Linux/AArch64
    /// `struct iovec` layout: a pointer followed by a native `size_t` length.
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct Iovec {
        /// Start of the byte range described by this record.
        pub iov_base: *mut u8,
        /// Number of bytes in the range.
        pub iov_len: usize,
    }

    /// Linux `F_DUPFD`: duplicate at or above the requested descriptor.
    pub const F_DUPFD: i32 = 0;
    /// Linux `F_GETFD`: read descriptor flags.
    pub const F_GETFD: i32 = 1;
    /// Linux `F_SETFD`: replace descriptor flags.
    pub const F_SETFD: i32 = 2;
    /// Linux `F_GETFL`: read the open-file-description status flags.
    pub const F_GETFL: i32 = 3;
    /// Linux `F_SETFL`: replace the open-file-description status flags.
    pub const F_SETFL: i32 = 4;
    /// Linux `F_GET_SEALS`: read an inode's sealing flags.
    pub const F_GET_SEALS: i32 = 1_034;
    /// Linux `F_ADD_SEALS`: add sealing flags to an inode.
    pub const F_ADD_SEALS: i32 = 1_033;
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

    /// Reads the open-file-description status flags through `fcntl(F_GETFL)`.
    #[inline]
    pub fn fcntl_getfl(fd: RawFd) -> Result<u32> {
        // SAFETY: F_GETFL ignores its third argument; zero is the canonical
        // immediate argument representation on Linux.
        unsafe { fcntl_raw(fd, F_GETFL, core::ptr::null_mut()) }.map(|flags| flags as u32)
    }

    /// Reads an inode's Linux sealing flags through `fcntl(F_GET_SEALS)`.
    ///
    /// The command has no pointer argument. The returned non-negative C `int`
    /// is preserved as a raw bitset so the safe facade can retain future
    /// kernel-defined seal bits.
    #[inline]
    pub fn fcntl_get_seals(fd: RawFd) -> Result<u32> {
        // SAFETY: F_GET_SEALS ignores its third argument; zero is the
        // canonical immediate argument representation on Linux.
        unsafe { fcntl_raw(fd, F_GET_SEALS, core::ptr::null_mut()) }.map(|flags| flags as u32)
    }

    /// Adds Linux sealing flags to an inode through `fcntl(F_ADD_SEALS)`.
    #[inline]
    pub fn fcntl_add_seals(fd: RawFd, seals: u32) -> Result<()> {
        // SAFETY: F_ADD_SEALS takes the seal bitset as an immediate integer in
        // the third syscall argument; `fcntl_raw` encodes it without
        // dereferencing the value.
        unsafe { fcntl_raw(fd, F_ADD_SEALS, seals as usize as *mut u8) }.map(|_| ())
    }

    /// Replaces the open-file-description status flags through
    /// `fcntl(F_SETFL)`.
    #[inline]
    pub fn fcntl_setfl(fd: RawFd, flags: u32) -> Result<()> {
        // SAFETY: F_SETFL takes an immediate integer in the third syscall
        // argument; `fcntl_raw` encodes that integer without dereferencing it.
        unsafe { fcntl_raw(fd, F_SETFL, flags as usize as *mut u8) }.map(|_| ())
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

    /// Synchronizes a byte range through AArch64's Linux `sync_file_range`
    /// syscall without using libc or TLS `errno`.
    ///
    /// The public operation calls this seam with the kernel's signed `loff_t`
    /// values. AArch64 uses the generic argument order `(fd, offset, nbytes,
    /// flags)` for this syscall.
    #[inline]
    pub fn sync_file_range(fd: RawFd, offset: i64, nbytes: i64, flags: u32) -> Result<()> {
        // SAFETY: The kernel validates the descriptor, flags, and signed byte
        // range. All four arguments are scalar AArch64 syscall registers.
        decode(unsafe {
            syscall4(
                SYS_SYNC_FILE_RANGE,
                fd as usize,
                offset as usize,
                nbytes as usize,
                flags as usize,
            )
        })
        .map(|_| ())
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

    /// Reads into an array of Linux `struct iovec` records without using libc
    /// or TLS `errno`.
    ///
    /// # Safety
    ///
    /// `iovecs` must be null or point to `count` initialized [`Iovec`] records
    /// readable for the duration of the call; a null pointer is permitted only
    /// when `count` is zero. Every non-empty `iov_base` range must be valid for
    /// mutable access for its `iov_len` bytes, and those ranges must be
    /// pairwise disjoint. Empty ranges may use any pointer. The descriptor's
    /// I/O safety is the caller's responsibility.
    #[inline]
    pub unsafe fn readv_raw(
        fd: RawFd,
        iovecs: *const Iovec,
        count: usize,
    ) -> Result<usize> {
        // SAFETY: The caller supplies the iovec-array and pointed-to-buffer
        // validity contracts; the kernel validates the descriptor and count.
        decode(unsafe {
            syscall3(SYS_READV, fd as usize, iovecs as usize, count)
        })
    }

    /// Reads from `offset` without changing the descriptor's file position.
    ///
    /// # Safety
    ///
    /// `buffer` must be valid for mutable access to `length` bytes for the
    /// duration of the call, unless `length` is zero. `offset` is the
    /// non-negative Linux `off_t` value passed to `pread64`; values above
    /// `i64::MAX` are rejected by Linux. The descriptor's I/O safety is the
    /// caller's responsibility.
    #[inline]
    pub unsafe fn pread_raw(
        fd: RawFd,
        buffer: *mut u8,
        length: usize,
        offset: u64,
    ) -> Result<usize> {
        // SAFETY: The caller supplies the raw-buffer validity contract and the
        // kernel validates the descriptor and file offset.
        decode(unsafe {
            syscall4(
                SYS_PREAD64,
                fd as usize,
                buffer as usize,
                length,
                offset as usize,
            )
        })
    }

    /// Reads from `offset` without changing the descriptor's file position.
    #[inline]
    pub fn pread(fd: RawFd, buffer: &mut [u8], offset: u64) -> Result<usize> {
        // SAFETY: A slice supplies a valid mutable buffer for the exact length.
        unsafe { pread_raw(fd, buffer.as_mut_ptr(), buffer.len(), offset) }
    }

    /// Transfers up to `count` bytes from `in_fd` to `out_fd` without using
    /// libc or TLS `errno`.
    ///
    /// A non-null `offset` is an in/out pointer to the input file position:
    /// Linux starts at its value, leaves the input descriptor's shared offset
    /// unchanged, and advances the pointed-to value by the number of bytes
    /// transferred. A null pointer starts at and advances the input
    /// descriptor's shared offset. The output descriptor's shared offset is
    /// advanced in either form.
    ///
    /// # Safety
    ///
    /// `offset` must be null or point to an aligned, writable `u64` for the
    /// duration of the call. When non-null, its value is interpreted by Linux
    /// as a signed `off_t`; values outside that range are rejected by Linux.
    /// The descriptors' I/O validity is the caller's responsibility.
    #[inline]
    pub unsafe fn sendfile_raw(
        out_fd: RawFd,
        in_fd: RawFd,
        offset: *mut u64,
        count: usize,
    ) -> Result<usize> {
        // SAFETY: The caller supplies the optional in/out offset pointer
        // validity contract; Linux validates both descriptors and count.
        decode(unsafe {
            syscall4(
                SYS_SENDFILE,
                out_fd as usize,
                in_fd as usize,
                offset as usize,
                count,
            )
        })
    }

    /// Transfers up to `count` bytes between borrowed descriptors.
    ///
    /// This typed core wrapper keeps the optional offset pointer contract
    /// explicit while avoiding a C ABI or process-global error channel.
    #[inline]
    pub fn sendfile(
        out_fd: RawFd,
        in_fd: RawFd,
        offset: Option<&mut u64>,
        count: usize,
    ) -> Result<usize> {
        let offset = offset.map_or(core::ptr::null_mut(), |offset| offset);
        // SAFETY: `Option<&mut u64>` supplies either a null pointer or an
        // aligned writable pointer valid for the syscall duration.
        unsafe { sendfile_raw(out_fd, in_fd, offset, count) }
    }

    /// Reads from `offset` into an array of Linux `struct iovec` records
    /// without changing the descriptor's file position or using libc/TLS
    /// `errno`.
    ///
    /// Linux's AArch64 `preadv` ABI passes the offset as two 32-bit words:
    /// low word first, then high word. This seam keeps the caller's complete
    /// non-negative `u64` representation until those registers are formed.
    ///
    /// # Safety
    ///
    /// The iovec-array and pointed-to-buffer requirements are the same as for
    /// [`readv_raw`]. `offset` is interpreted as a signed Linux `off_t`; values
    /// above `i64::MAX` are rejected by Linux with `EINVAL`.
    #[inline]
    pub unsafe fn preadv_raw(
        fd: RawFd,
        iovecs: *const Iovec,
        count: usize,
        offset: u64,
    ) -> Result<usize> {
        // SAFETY: The caller supplies the iovec-array and pointed-to-buffer
        // validity contracts; the kernel validates the descriptor, count,
        // and signed file offset.
        decode(unsafe {
            syscall5(
                SYS_PREADV,
                fd as usize,
                iovecs as usize,
                count,
                offset as usize,
                (offset >> 32) as usize,
            )
        })
    }

    /// Reads through Linux `preadv2` without libc or TLS `errno`.
    ///
    /// AArch64 passes the non-negative `offset` as two explicit 32-bit words,
    /// low first and high second. Linux reserves `u64::MAX` as the explicit
    /// current-file-offset sentinel for this operation; every other value is
    /// preserved as a positioned offset.
    ///
    /// # Safety
    ///
    /// The iovec-array and pointed-to-buffer requirements are the same as for
    /// [`readv_raw`]. `flags` must contain only Linux `RWF_*` bits accepted by
    /// the caller's facade contract.
    #[inline]
    pub unsafe fn preadv2_raw(
        fd: RawFd,
        iovecs: *const Iovec,
        count: usize,
        offset: u64,
        flags: u32,
    ) -> Result<usize> {
        // SAFETY: The caller supplies the iovec-array and pointed-to-buffer
        // validity contracts; the kernel validates the descriptor, offset,
        // and flags. The six scalar arguments occupy x0..x5.
        decode(unsafe {
            syscall6(
                SYS_PREADV2,
                fd as usize,
                iovecs as usize,
                count,
                offset as usize,
                (offset >> 32) as usize,
                flags as usize,
            )
        })
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

    /// Writes from an array of Linux `struct iovec` records without using libc
    /// or TLS `errno`.
    ///
    /// # Safety
    ///
    /// `iovecs` must be null or point to `count` initialized [`Iovec`] records
    /// readable for the duration of the call; a null pointer is permitted only
    /// when `count` is zero. Every non-empty `iov_base` range must be valid for
    /// immutable access for its `iov_len` bytes. The descriptor's I/O safety is
    /// the caller's responsibility.
    #[inline]
    pub unsafe fn writev_raw(
        fd: RawFd,
        iovecs: *const Iovec,
        count: usize,
    ) -> Result<usize> {
        // SAFETY: The caller supplies the iovec-array and pointed-to-buffer
        // validity contracts; the kernel validates the descriptor and count.
        decode(unsafe {
            syscall3(SYS_WRITEV, fd as usize, iovecs as usize, count)
        })
    }

    /// Writes at `offset` without changing the descriptor's file position.
    ///
    /// # Safety
    ///
    /// `buffer` must be valid for immutable access to `length` bytes for the
    /// duration of the call, unless `length` is zero. `offset` is the
    /// non-negative Linux `off_t` value passed to `pwrite64`; values above
    /// `i64::MAX` are rejected by Linux. The descriptor's I/O safety is the
    /// caller's responsibility.
    #[inline]
    pub unsafe fn pwrite_raw(
        fd: RawFd,
        buffer: *const u8,
        length: usize,
        offset: u64,
    ) -> Result<usize> {
        // SAFETY: The caller supplies the raw-buffer validity contract and the
        // kernel validates the descriptor and file offset.
        decode(unsafe {
            syscall4(
                SYS_PWRITE64,
                fd as usize,
                buffer as usize,
                length,
                offset as usize,
            )
        })
    }

    /// Writes at `offset` without changing the descriptor's file position.
    #[inline]
    pub fn pwrite(fd: RawFd, buffer: &[u8], offset: u64) -> Result<usize> {
        // SAFETY: A slice supplies a valid immutable buffer for the exact length.
        unsafe { pwrite_raw(fd, buffer.as_ptr(), buffer.len(), offset) }
    }

    /// Writes from an array of Linux `struct iovec` records at `offset`
    /// without changing the descriptor's file position or using libc/TLS
    /// `errno`.
    ///
    /// Linux's AArch64 `pwritev` ABI passes the offset as two 32-bit words:
    /// low word first, then high word. `offset` values above `i64::MAX` are
    /// rejected by Linux with `EINVAL`.
    ///
    /// # Safety
    ///
    /// The iovec-array and pointed-to-buffer requirements are the same as for
    /// [`writev_raw`].
    #[inline]
    pub unsafe fn pwritev_raw(
        fd: RawFd,
        iovecs: *const Iovec,
        count: usize,
        offset: u64,
    ) -> Result<usize> {
        // SAFETY: The caller supplies the iovec-array and pointed-to-buffer
        // validity contracts; the kernel validates the descriptor, count,
        // and signed file offset.
        decode(unsafe {
            syscall5(
                SYS_PWRITEV,
                fd as usize,
                iovecs as usize,
                count,
                offset as usize,
                (offset >> 32) as usize,
            )
        })
    }

    /// Writes through Linux `pwritev2` without libc or TLS `errno`.
    ///
    /// AArch64 passes the non-negative `offset` as two explicit 32-bit words,
    /// low first and high second. Linux reserves `u64::MAX` as the explicit
    /// current-file-offset sentinel for this operation; every other value is
    /// preserved as a positioned offset.
    ///
    /// # Safety
    ///
    /// The iovec-array and pointed-to-buffer requirements are the same as for
    /// [`writev_raw`]. `flags` must contain only Linux `RWF_*` bits accepted by
    /// the caller's facade contract.
    #[inline]
    pub unsafe fn pwritev2_raw(
        fd: RawFd,
        iovecs: *const Iovec,
        count: usize,
        offset: u64,
        flags: u32,
    ) -> Result<usize> {
        // SAFETY: The caller supplies the iovec-array and pointed-to-buffer
        // validity contracts; the kernel validates the descriptor, offset,
        // and flags. The six scalar arguments occupy x0..x5.
        decode(unsafe {
            syscall6(
                SYS_PWRITEV2,
                fd as usize,
                iovecs as usize,
                count,
                offset as usize,
                (offset >> 32) as usize,
                flags as usize,
            )
        })
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
        decode, decode_i32, decode_i64, syscall0, syscall1, syscall2, syscall3, syscall4, syscall5, syscall6,
        CStr, RawFd,
        Result, SYS_FACCESSAT, SYS_FACCESSAT2, SYS_FCHMOD, SYS_FCHMODAT, SYS_FCHOWN, SYS_FCHOWNAT, SYS_FDATASYNC, SYS_FLOCK, SYS_FSTAT, SYS_FSTATFS,
        SYS_FSYNC, SYS_TRUNCATE, SYS_FTRUNCATE, SYS_FALLOCATE, SYS_FADVISE64, SYS_GETDENTS64, SYS_LINKAT, SYS_FGETXATTR,
        SYS_FLISTXATTR, SYS_FREMOVEXATTR, SYS_FSETXATTR, SYS_GETXATTR, SYS_LGETXATTR,
        SYS_LLISTXATTR, SYS_LREMOVEXATTR, SYS_LSEEK, SYS_LSETXATTR, SYS_LISTXATTR,
        SYS_MEMFD_CREATE, SYS_MKDIRAT, SYS_NEWFSTATAT, SYS_OPENAT, SYS_OPENAT2, SYS_READAHEAD,
        SYS_READLINKAT, SYS_STATFS, SYS_COPY_FILE_RANGE,
        SYS_REMOVEXATTR, SYS_RENAMEAT2, SYS_SETXATTR, SYS_SYMLINKAT, SYS_UNLINKAT,
        SYS_SYNC, SYS_SYNCFS, SYS_UTIMENSAT,
        SYS_MKNODAT, SYS_STATX,
    };

    // This is the private Linux/AArch64 wire layout for `struct statx`.
    // Keep it private: callers receive a typed facade value, while this type
    // makes the output pointer passed to the kernel carry the exact ABI size
    // and alignment contract.
    #[repr(C)]
    struct KernelStatxTimestamp {
        tv_sec: i64,
        tv_nsec: u32,
        __reserved: i32,
    }

    #[repr(C)]
    struct KernelStatx {
        stx_mask: u32,
        stx_blksize: u32,
        stx_attributes: u64,
        stx_nlink: u32,
        stx_uid: u32,
        stx_gid: u32,
        stx_mode: u16,
        __spare0: [u16; 1],
        stx_ino: u64,
        stx_size: u64,
        stx_blocks: u64,
        stx_attributes_mask: u64,
        stx_atime: KernelStatxTimestamp,
        stx_btime: KernelStatxTimestamp,
        stx_ctime: KernelStatxTimestamp,
        stx_mtime: KernelStatxTimestamp,
        stx_rdev_major: u32,
        stx_rdev_minor: u32,
        stx_dev_major: u32,
        stx_dev_minor: u32,
        stx_mnt_id: u64,
        stx_dio_mem_align: u32,
        stx_dio_offset_align: u32,
        stx_subvol: u64,
        stx_atomic_write_unit_min: u32,
        stx_atomic_write_unit_max: u32,
        stx_atomic_write_segments_max: u32,
        stx_dio_read_offset_align: u32,
        stx_atomic_write_unit_max_opt: u32,
        __spare2: [u32; 1],
        __spare3: [u64; 8],
    }

    const _: [(); 256] = [(); core::mem::size_of::<KernelStatx>()];
    const STATX_RESERVED: u32 = 0x8000_0000;
    const STATX_KNOWN_MASK: u32 = 0x0000_3fff;

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

    /// Flushes pending filesystem metadata and cached file data for all
    /// filesystems without using libc or TLS `errno`.
    ///
    /// Linux `sync(2)` has process/system-wide scope: it is not limited to the
    /// caller's descriptors or to one mounted filesystem. Linux waits for
    /// writeback I/O completion before returning, while POSIX permits
    /// `sync()` to schedule writes and return before the actual writes finish.
    /// This completion point is kernel/filesystem writeback completion; it is
    /// not a promise that every device's volatile write cache has committed to
    /// nonvolatile media. Linux defines this syscall as always successful, so
    /// the direct seam has the Rustix-shaped `()` return and does not expose an
    /// errno result.
    #[inline]
    pub fn sync() {
        // SAFETY: `sync` takes no arguments. Linux defines the syscall as
        // always successful; discard its raw return exactly as Rustix does.
        let _ = unsafe { syscall0(SYS_SYNC) };
    }

    /// Gives Linux a POSIX filesystem access-pattern advisory through the
    /// AArch64 `fadvise64` ABI without using libc or TLS `errno`.
    ///
    /// `offset` and `length` are the signed Linux/AArch64 `loff_t` values. The
    /// native facade validates its unsigned API before converting to these
    /// arguments.
    #[inline]
    pub fn fadvise64(fd: RawFd, offset: i64, length: i64, advice: u32) -> Result<()> {
        // SAFETY: The kernel validates the descriptor, signed offsets, length,
        // and POSIX_FADV policy value.
        decode(unsafe {
            syscall4(
                SYS_FADVISE64,
                fd as usize,
                offset as usize,
                length as usize,
                advice as usize,
            )
        })
        .map(|_| ())
    }

    /// Initiates Linux file readahead through the AArch64 syscall ABI without
    /// using libc or TLS `errno`.
    ///
    /// `offset` is the signed Linux `loff_t` byte offset. `count` is the
    /// AArch64 `size_t` byte count; the native facade validates the unsigned
    /// caller range and its end before converting `offset` here.
    #[inline]
    pub fn readahead(fd: RawFd, offset: i64, count: usize) -> Result<()> {
        // SAFETY: The kernel validates the descriptor and file type. The
        // scalar arguments are the Linux/AArch64 readahead ABI.
        decode(unsafe {
            syscall3(
                SYS_READAHEAD,
                fd as usize,
                offset as usize,
                count,
            )
        })
        .map(|_| ())
    }

    /// Copies up to `len` bytes between two descriptors through Linux's
    /// `copy_file_range` syscall without using libc or TLS `errno`.
    ///
    /// Each supplied offset is an in/out pointer to a signed Linux `loff_t`:
    /// Linux starts from its value, leaves that descriptor's shared position
    /// unchanged, and advances the pointed-to value by the number of bytes
    /// copied. A null pointer selects and advances the descriptor's shared
    /// position. The final syscall argument is fixed at zero because this
    /// bounded seam does not expose filesystem-specific copy flags.
    ///
    /// The caller must keep each optional offset aligned and writable for the
    /// duration of the call. The descriptors' I/O validity is the caller's
    /// responsibility.
    #[inline]
    pub fn copy_file_range(
        in_fd: RawFd,
        in_offset: Option<&mut u64>,
        out_fd: RawFd,
        out_offset: Option<&mut u64>,
        len: usize,
    ) -> Result<usize> {
        let in_offset = in_offset.map_or(core::ptr::null_mut(), |offset| offset);
        let out_offset = out_offset.map_or(core::ptr::null_mut(), |offset| offset);
        // SAFETY: Optional mutable references provide either null pointers or
        // aligned writable storage for the syscall duration. Linux validates
        // both descriptors, the signed offsets, and the copy range.
        decode(unsafe {
            syscall6(
                SYS_COPY_FILE_RANGE,
                in_fd as usize,
                in_offset as usize,
                out_fd as usize,
                out_offset as usize,
                len,
                0,
            )
        })
    }

    /// Flushes all pending filesystem data associated with the descriptor's
    /// mounted filesystem without using libc or TLS `errno`.
    #[inline]
    pub fn syncfs(fd: RawFd) -> Result<()> {
        // SAFETY: The kernel validates the descriptor and identifies its
        // mounted filesystem for the direct sync operation.
        decode(unsafe { syscall1(SYS_SYNCFS, fd as usize) }).map(|_| ())
    }

    /// Sets the length of a pathname-selected file without using libc or TLS
    /// `errno`.
    ///
    /// `length` is the signed Linux `loff_t` representation. The public
    /// facade validates its unsigned byte-count API before constructing the
    /// pathname or issuing this direct syscall.
    #[inline]
    pub fn truncate(path: &CStr, length: i64) -> Result<()> {
        // SAFETY: `CStr` supplies a readable NUL-terminated pathname, and the
        // kernel validates the signed file length and pathname permissions.
        decode(unsafe {
            syscall2(SYS_TRUNCATE, path.as_ptr() as usize, length as usize)
        })
        .map(|_| ())
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

    /// Allocates or transforms a range in an open file without using libc or
    /// TLS `errno`.
    ///
    /// `offset` and `length` are the signed Linux `loff_t` representation.
    /// The AArch64 Linux ABI passes both values as full-width registers after
    /// the descriptor and `mode` arguments; unlike 32-bit ABIs, no high/low
    /// word splitting is used here.
    #[inline]
    pub fn fallocate(fd: RawFd, mode: u32, offset: i64, length: i64) -> Result<()> {
        // SAFETY: The kernel validates the descriptor, mode, and signed file
        // range. All four arguments are scalar AArch64 syscall registers.
        decode(unsafe {
            syscall4(
                SYS_FALLOCATE,
                fd as usize,
                mode as usize,
                offset as usize,
                length as usize,
            )
        })
        .map(|_| ())
    }

    /// Tests a pathname using Linux's standard `access()` behavior.
    ///
    /// AArch64 has no separate `access` syscall, so musl's public wrapper
    /// selects `faccessat(AT_FDCWD, path, mode, 0)`. The Linux/AArch64 kernel
    /// syscall itself has only the three arguments `(dirfd, path, mode)`; the
    /// public wrapper's trailing zero is not a kernel flags argument. The
    /// kernel resolves `path` from the process current working directory and
    /// checks permissions using the real (not effective) UID and GID. This
    /// seam does not expose the distinct `faccessat2` flags contract.
    #[inline]
    pub fn access(path: &CStr, mode: u32) -> Result<()> {
        // SAFETY: `CStr` guarantees a readable NUL-terminated pathname. The
        // kernel validates the access mode and performs the real-ID check.
        decode(unsafe {
            syscall3(
                SYS_FACCESSAT,
                super::AT_FDCWD as usize,
                path.as_ptr() as usize,
                mode as usize,
            )
        })
        .map(|_| ())
    }

    /// Tests a pathname relative to `dirfd` using Linux's flags-bearing
    /// `faccessat2` contract when `flags` is nonzero.
    ///
    /// An empty flag word uses AArch64's three-argument `faccessat` syscall.
    /// A nonempty flag word uses `faccessat2` directly and therefore preserves
    /// `NOSYS` on kernels predating that syscall; this seam performs no
    /// fallback, credential emulation, or availability caching. The safe
    /// facade restricts the flag word to `AT_EACCESS` and
    /// `AT_SYMLINK_NOFOLLOW`.
    #[inline]
    pub fn accessat(dirfd: RawFd, path: &CStr, mode: u32, flags: u32) -> Result<()> {
        // SAFETY: `CStr` guarantees a readable NUL-terminated pathname. The
        // kernel validates the descriptor, access mode, and supported flags;
        // the facade validates its closed flag set before reaching here.
        decode(if flags == 0 {
            unsafe {
                syscall3(
                    SYS_FACCESSAT,
                    dirfd as usize,
                    path.as_ptr() as usize,
                    mode as usize,
                )
            }
        } else {
            unsafe {
                syscall4(
                    SYS_FACCESSAT2,
                    dirfd as usize,
                    path.as_ptr() as usize,
                    mode as usize,
                    flags as usize,
                )
            }
        })
        .map(|_| ())
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

    /// Creates an anonymous Linux memory file without using libc or TLS
    /// `errno`.
    ///
    /// `name` must remain a valid NUL-terminated byte string for the syscall;
    /// the public facade supplies that contract through `Arg`.
    #[inline]
    pub fn memfd_create(name: &CStr, flags: u32) -> Result<RawFd> {
        // SAFETY: `CStr` supplies the name pointer and Linux validates the
        // name length and MFD flag word.
        decode_i32(unsafe {
            syscall2(
                SYS_MEMFD_CREATE,
                name.as_ptr() as usize,
                flags as usize,
            )
        })
    }

    /// Queries the Linux/AArch64 `struct statx` representation for a C path.
    ///
    /// This is a direct, stateless syscall seam. It intentionally propagates
    /// `ENOSYS` instead of emulating musl's compatibility fallback or caching
    /// process-wide availability state.
    ///
    /// # Safety
    ///
    /// `path` must point to a readable NUL-terminated pathname and `buffer`
    /// must designate writable, correctly aligned storage for the complete
    /// 256-byte Linux/AArch64 `struct statx` layout.
    #[inline]
    pub unsafe fn statx_raw(
        dirfd: RawFd,
        path: *const u8,
        flags: u32,
        mask: u32,
        buffer: *mut u8,
    ) -> Result<()> {
        // Rustix rejects this reserved bit before entering the kernel. Future
        // bits are masked so an extended kernel cannot write beyond the
        // private wire layout known by this crate.
        if mask & STATX_RESERVED != 0 {
            return Err(super::Errno::INVAL);
        }
        let mask = mask & STATX_KNOWN_MASK;
        let buffer = buffer.cast::<KernelStatx>();
        // SAFETY: The caller supplies the path and complete statx output
        // storage contract; the kernel validates dirfd, flags, and mask.
        decode(unsafe {
            syscall5(
                SYS_STATX,
                dirfd as usize,
                path as usize,
                flags as usize,
                mask as usize,
                buffer as usize,
            )
        })
        .map(|_| ())
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

    /// Queries the Linux/AArch64 `struct statfs` representation for `fd`.
    ///
    /// # Safety
    ///
    /// `buffer` must designate writable storage for the complete target
    /// Linux/AArch64 `struct statfs` layout. The descriptor's I/O safety is
    /// the caller's responsibility.
    #[inline]
    pub unsafe fn fstatfs_raw(fd: RawFd, buffer: *mut u8) -> Result<()> {
        // SAFETY: The caller supplies complete writable `struct statfs`
        // storage; the kernel validates the descriptor.
        decode(unsafe { syscall2(SYS_FSTATFS, fd as usize, buffer as usize) }).map(|_| ())
    }

    /// Queries the Linux/AArch64 `struct statfs` representation for a C path.
    ///
    /// # Safety
    ///
    /// `path` must point to a readable NUL-terminated pathname and `buffer`
    /// must designate writable storage for the complete target Linux/AArch64
    /// `struct statfs` layout.
    #[inline]
    pub unsafe fn statfs_raw(path: *const u8, buffer: *mut u8) -> Result<()> {
        // SAFETY: The caller supplies the C-string and output-layout
        // contracts; the kernel validates the path.
        decode(unsafe { syscall2(SYS_STATFS, path as usize, buffer as usize) }).map(|_| ())
    }

    /// Queries filesystem statistics for a C path without using libc or TLS
    /// `errno`.
    #[inline]
    pub fn statfs(path: &CStr, buffer: *mut u8) -> Result<()> {
        // SAFETY: `CStr` establishes the pathname contract; the caller
        // supplies the output-layout contract.
        unsafe { statfs_raw(path.as_ptr().cast(), buffer) }
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

    /// Creates a filesystem node relative to `dirfd` without using libc or
    /// TLS `errno`.
    ///
    /// `mode` contains the Linux file-type and permission bits in the exact
    /// `mknodat(2)` representation. The public facade supplies the file-type
    /// and creation-mode pieces separately so callers cannot accidentally
    /// duplicate or omit the type bits at this boundary.
    #[inline]
    pub fn mknodat(dirfd: RawFd, path: &CStr, mode: u32, dev: u64) -> Result<()> {
        // SAFETY: `CStr` guarantees the pathname is readable and
        // NUL-terminated; the kernel validates the node type, permissions,
        // device number, and directory descriptor.
        decode(unsafe {
            syscall4(
                SYS_MKNODAT,
                dirfd as usize,
                path.as_ptr() as usize,
                mode as usize,
                dev as usize,
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

    /// Changes ownership for an open descriptor through Linux/AArch64's
    /// `fchown` syscall without using libc or TLS `errno`.
    ///
    /// `owner` and `group` are Linux `uid_t`/`gid_t` words. The kernel value
    /// `u32::MAX` is the explicit no-change sentinel for either field; the
    /// typed native facade is responsible for translating `Option` values and
    /// rejecting an invalid raw ID before reaching this seam.
    #[inline]
    pub fn fchown(fd: RawFd, owner: u32, group: u32) -> Result<()> {
        // SAFETY: The kernel validates the descriptor, IDs, and credentials.
        decode(unsafe {
            syscall3(
                SYS_FCHOWN,
                fd as usize,
                owner as usize,
                group as usize,
            )
        })
        .map(|_| ())
    }

    /// Changes pathname-selected ownership through Linux/AArch64's
    /// `fchownat` syscall without using libc or TLS `errno`.
    ///
    /// The `flags` word is intentionally supplied by the typed facade's
    /// ownership-specific flag type; this core seam remains a direct scalar
    /// syscall boundary and does not broaden that safe contract.
    #[inline]
    pub fn fchownat(
        dirfd: RawFd,
        path: &CStr,
        owner: u32,
        group: u32,
        flags: u32,
    ) -> Result<()> {
        // SAFETY: `CStr` supplies the pathname; the kernel validates the
        // descriptor, IDs, flags, and credentials.
        decode(unsafe {
            syscall5(
                SYS_FCHOWNAT,
                dirfd as usize,
                path.as_ptr() as usize,
                owner as usize,
                group as usize,
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
    use super::{
        decode, syscall2, syscall4, syscall6, MaybeUninit, RawFd, Result, SYS_PIPE2, SYS_SPLICE,
        SYS_TEE, SYS_VMSPLICE,
    };

    /// Linux `F_GETPIPE_SZ`—read a pipe's current capacity in bytes.
    const F_GETPIPE_SZ: i32 = 1_032;

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

    /// Reads a Linux pipe's current capacity through the direct `fcntl`
    /// syscall, without libc or TLS `errno`.
    ///
    /// The kernel returns a non-negative byte count for `F_GETPIPE_SZ` and
    /// reports descriptor/type failures directly. A negative value outside
    /// Linux's syscall-error range would not be a valid pipe capacity and is
    /// rejected rather than converted to a large `usize`.
    #[inline]
    pub fn fcntl_getpipe_size(fd: RawFd) -> Result<usize> {
        // SAFETY: F_GETPIPE_SZ has no pointer argument; the null third
        // argument is the canonical immediate representation for this
        // direct fcntl syscall.
        let size = unsafe {
            super::io::fcntl_raw(fd, F_GETPIPE_SZ, core::ptr::null_mut())?
        };
        if size < 0 {
            return Err(super::Errno::RANGE);
        }
        Ok(size as usize)
    }

    /// Duplicates data from one Linux pipe into another without consuming it.
    ///
    /// The kernel may return a short count when fewer than `length` bytes are
    /// available or the destination pipe cannot accept the whole request.
    /// Flags retain Linux's `SPLICE_F_*` representation and kernel errors are
    /// returned unchanged.
    #[inline]
    pub fn tee_raw(
        fd_in: RawFd,
        fd_out: RawFd,
        length: usize,
        flags: u32,
    ) -> Result<usize> {
        // SAFETY: Both descriptors and the scalar length/flags are immediate
        // Linux syscall arguments; the kernel validates pipe direction and
        // capacity requirements.
        decode(unsafe {
            syscall4(
                SYS_TEE,
                fd_in as usize,
                fd_out as usize,
                length,
                flags as usize,
            )
        })
    }

    /// Transfers bytes between a file and a pipe through Linux `splice(2)`.
    ///
    /// `offset_in` and `offset_out` are nullable pointers to Linux `loff_t`
    /// values. A null pointer selects and advances the descriptor's current
    /// offset; a non-null pointer selects an explicit offset and advances the
    /// pointed-to value. At least one descriptor must refer to a pipe, as
    /// required by Linux. The pointers and descriptor lifetimes are owned by
    /// the caller for the duration of this call.
    #[inline]
    pub unsafe fn splice_raw(
        fd_in: RawFd,
        offset_in: *mut u64,
        fd_out: RawFd,
        offset_out: *mut u64,
        length: usize,
        flags: u32,
    ) -> Result<usize> {
        // SAFETY: The caller owns the nullable offset-pointer contracts. All
        // descriptors and scalar values are immediate Linux syscall
        // arguments; the kernel validates pipe direction and flags.
        decode(unsafe {
            syscall6(
                SYS_SPLICE,
                fd_in as usize,
                offset_in as usize,
                fd_out as usize,
                offset_out as usize,
                length,
                flags as usize,
            )
        })
    }

    /// Transfers caller-owned iovec memory to or from a pipe through
    /// Linux `vmsplice(2)`.
    ///
    /// # Safety
    ///
    /// `iovecs` must point to `count` readable Linux [`super::io::Iovec`]
    /// records, and each record must satisfy the direction and lifetime
    /// contract of the selected pipe descriptor. With `SPLICE_F_GIFT`, the
    /// supplied pages must be page-aligned, page-sized, and never modified or
    /// reused after the kernel accepts them. The caller must also ensure that
    /// memory is writable when the pipe's read end is supplied.
    #[inline]
    pub unsafe fn vmsplice_raw(
        fd: RawFd,
        iovecs: *const super::io::Iovec,
        count: usize,
        flags: u32,
    ) -> Result<usize> {
        // SAFETY: The caller owns the iovec-array and pointed-to-memory
        // contracts. Linux validates the descriptor, count, and flags.
        decode(unsafe {
            super::syscall4(
                SYS_VMSPLICE,
                fd as usize,
                iovecs as usize,
                count,
                flags as usize,
            )
        })
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
    use super::{
        decode, decode_i32, syscall1, syscall2, syscall3, syscall4, MaybeUninit, RawFd, Result,
        SYS_CLOCK_GETRES, SYS_CLOCK_NANOSLEEP, SYS_CLOCK_SETTIME,
        SYS_GETITIMER, SYS_GETTIMEOFDAY,
        SYS_NANOSLEEP, SYS_SETITIMER, SYS_TIMER_CREATE, SYS_TIMER_DELETE, SYS_TIMERFD_CREATE,
        SYS_TIMERFD_GETTIME, SYS_TIMERFD_SETTIME, SYS_TIMER_GETOVERRUN, SYS_TIMER_GETTIME,
        SYS_TIMER_SETTIME,
    };

    /// One signed timeval from Linux/AArch64's legacy `getitimer` result.
    ///
    /// This is the exact kernel wire layout: both fields are signed 64-bit
    /// words, with `tv_usec` normalized by Linux to `0..1_000_000`. It is not
    /// a public C `timeval` alias; the native facade validates these fields
    /// before exposing them as Rust [`core::time::Duration`] values.
    #[repr(C)]
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    pub struct KernelItimervalTimeval {
        /// Whole seconds in the interval-timer value.
        pub tv_sec: i64,
        /// Microseconds within `tv_sec`.
        pub tv_usec: i64,
    }

    /// Linux/AArch64's four-word `struct __kernel_old_itimerval` result.
    ///
    /// The kernel writes the interval first and the current value second.
    /// This is a syscall wire record rather than a C ABI type; callers should
    /// validate each nested timeval before converting it to a native value.
    #[repr(C)]
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    pub struct KernelItimerval {
        /// Time between expirations, or zero for a one-shot timer.
        pub it_interval: KernelItimervalTimeval,
        /// Time remaining until the next expiration, or zero when disarmed.
        pub it_value: KernelItimervalTimeval,
    }

    /// One Linux/AArch64 POSIX-timer timespec.
    ///
    /// This private wire record intentionally remains separate from the
    /// public Rust `Timespec`: it exists only to make the timer syscalls'
    /// pointer and layout contract explicit.
    #[repr(C)]
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    pub struct KernelTimerTimespec {
        /// Whole seconds.
        pub tv_sec: i64,
        /// Nanoseconds within the second.
        pub tv_nsec: i64,
    }

    /// Linux/AArch64's POSIX timer setting record.
    #[repr(C)]
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    pub struct KernelItimerspec {
        /// Interval between expirations.
        pub it_interval: KernelTimerTimespec,
        /// Initial or absolute expiration.
        pub it_value: KernelTimerTimespec,
    }

    /// Kernel wall-clock fields returned by AArch64 `gettimeofday`.
    ///
    /// This is a private wire contract for the native Rust facade, not a
    /// public C `timeval` type. Linux reports signed Unix-epoch seconds and a
    /// canonical microsecond remainder in the range `0..1_000_000`.
    #[repr(C)]
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    pub struct KernelWallClockParts {
        /// Signed seconds since the Unix epoch (1970-01-01 00:00:00 UTC).
        pub seconds: i64,
        /// Microseconds within `seconds`, as normalized by Linux.
        pub microseconds: i64,
    }

    /// Queries Linux's UTC wall clock without using libc, vDSO dispatch, or
    /// TLS `errno`.
    #[inline]
    pub fn gettimeofday() -> Result<KernelWallClockParts> {
        let mut value = MaybeUninit::<KernelWallClockParts>::uninit();
        // SAFETY: `value` has the exact two-word AArch64 kernel layout, and a
        // successful syscall initializes both fields.
        unsafe { gettimeofday_raw(value.as_mut_ptr().cast())? };
        // SAFETY: Linux initialized `value` on the successful return above.
        Ok(unsafe { value.assume_init() })
    }

    /// Reads one Linux process interval timer without using libc or TLS
    /// `errno`.
    ///
    /// `which` is the Linux `ITIMER_*` selector (`0`, `1`, or `2`). The
    /// selector remains raw at this syscall boundary so Linux can report
    /// `EINVAL` for unsupported values; the Rust facade supplies the closed
    /// interval-timer vocabulary.
    ///
    /// # Safety
    ///
    /// `value` must point to writable storage for one
    /// [`KernelItimerval`] value. Linux initializes all four words on
    /// success. An invalid pointer may be passed deliberately when testing
    /// the kernel's pointer validation behavior.
    #[inline]
    pub unsafe fn getitimer_raw(which: i32, value: *mut u8) -> Result<()> {
        // SAFETY: The caller owns the result-pointer contract; Linux validates
        // the selector and writes the complete four-word record on success.
        decode(unsafe { syscall2(SYS_GETITIMER, which as usize, value as usize) }).map(|_| ())
    }

    /// Arms or disarms one Linux process interval timer and optionally
    /// returns its previous setting without using libc or TLS `errno`.
    ///
    /// # Safety
    ///
    /// `new_value` must point to one Linux/AArch64 `__kernel_old_itimerval`;
    /// `old_value` must be null or writable storage for the same record.
    #[inline]
    pub unsafe fn setitimer_raw(
        which: i32,
        new_value: *const u8,
        old_value: *mut u8,
    ) -> Result<()> {
        // SAFETY: The caller owns both timeval record pointer contracts;
        // Linux validates the selector and the timeval values.
        decode(unsafe {
            syscall3(
                SYS_SETITIMER,
                which as usize,
                new_value as usize,
                old_value as usize,
            )
        })
        .map(|_| ())
    }

    /// Creates one Linux POSIX timer with a private kernel `sigevent` record.
    ///
    /// # Safety
    ///
    /// `event` must be null or point to the exact 64-byte Linux/AArch64
    /// `sigevent` layout. `timer_id` must point to writable `i32` storage.
    #[inline]
    pub unsafe fn timer_create_raw(
        clock_id: i32,
        event: *const u8,
        timer_id: *mut i32,
    ) -> Result<i32> {
        // SAFETY: The caller owns the event and result-pointer contracts;
        // Linux validates clock and notification values.
        decode_i32(unsafe {
            syscall3(
                SYS_TIMER_CREATE,
                clock_id as usize,
                event as usize,
                timer_id as usize,
            )
        })
    }

    /// Arms or disarms a Linux POSIX timer and optionally returns its old
    /// setting without using libc or TLS `errno`.
    ///
    /// # Safety
    ///
    /// `new_value` must point to an initialized Linux/AArch64 `itimerspec`;
    /// `old_value` must be null or writable storage for one such record.
    #[inline]
    pub unsafe fn timer_settime_raw(
        timer_id: i32,
        flags: i32,
        new_value: *const u8,
        old_value: *mut u8,
    ) -> Result<()> {
        // SAFETY: The caller owns both itimerspec pointer contracts; Linux
        // validates the timer ID, flags, and time values.
        decode(unsafe {
            syscall4(
                SYS_TIMER_SETTIME,
                timer_id as usize,
                flags as usize,
                new_value as usize,
                old_value as usize,
            )
        })
        .map(|_| ())
    }

    /// Reads one Linux POSIX timer's current setting without using libc or
    /// TLS `errno`.
    ///
    /// # Safety
    ///
    /// `value` must point to writable storage for one Linux/AArch64
    /// `itimerspec` record.
    #[inline]
    pub unsafe fn timer_gettime_raw(timer_id: i32, value: *mut u8) -> Result<()> {
        // SAFETY: The caller owns the output-memory contract; Linux validates
        // the timer ID and initializes the complete record on success.
        decode(unsafe { syscall2(SYS_TIMER_GETTIME, timer_id as usize, value as usize) })
            .map(|_| ())
    }

    /// Returns a Linux POSIX timer's overrun count without using libc or TLS
    /// `errno`.
    #[inline]
    pub fn timer_getoverrun_raw(timer_id: i32) -> Result<i32> {
        // SAFETY: The timer ID is a scalar and Linux validates it.
        decode_i32(unsafe { syscall1(SYS_TIMER_GETOVERRUN, timer_id as usize) })
    }

    /// Deletes one Linux POSIX timer without using libc or TLS `errno`.
    #[inline]
    pub fn timer_delete_raw(timer_id: i32) -> Result<()> {
        // SAFETY: The timer ID is a scalar and Linux validates it.
        decode(unsafe { syscall1(SYS_TIMER_DELETE, timer_id as usize) }).map(|_| ())
    }

    /// Performs the Linux/AArch64 `gettimeofday` syscall.
    ///
    /// The second syscall argument is deliberately null: timezone output is a
    /// legacy C process-global concept and is not part of this native query.
    ///
    /// # Safety
    ///
    /// `parts` must point to writable storage for one
    /// [`KernelWallClockParts`] value.
    #[inline]
    pub unsafe fn gettimeofday_raw(parts: *mut u8) -> Result<()> {
        // SAFETY: The caller supplies storage for the kernel's two-word
        // result; the null timezone pointer requests no legacy timezone data.
        decode(unsafe { syscall2(SYS_GETTIMEOFDAY, parts as usize, 0) }).map(|_| ())
    }

    /// Queries Linux realtime through the validated vDSO when present, falling
    /// back to the direct `gettimeofday` syscall with the raw kernel result.
    ///
    /// # Safety
    ///
    /// `timeval` must be null or writable for one Linux/AArch64 timeval; the
    /// optional `timezone` pointer follows the same kernel ABI.
    #[inline]
    pub unsafe fn gettimeofday_status_raw(timeval: *mut u8, timezone: *mut u8) -> i32 {
        // SAFETY: The caller owns both kernel ABI pointers.
        unsafe { crate::vdso::gettimeofday_status(timeval, timezone) }
    }

    /// Sleeps for a relative Linux/AArch64 timespec without using libc or TLS
    /// `errno`.
    ///
    /// Linux initializes `remaining` only when the sleep is interrupted with
    /// `EINTR`; callers must not read it for any other result.
    ///
    /// # Safety
    ///
    /// `request` must point to a readable Linux/AArch64 `struct timespec`.
    /// `remaining` must point to writable storage for one such value.
    #[inline]
    pub unsafe fn nanosleep_raw(request: *const u8, remaining: *mut u8) -> Result<()> {
        // SAFETY: The caller owns both timespec pointer contracts; Linux
        // validates the requested range and writes `remaining` only on EINTR.
        decode(unsafe { syscall2(SYS_NANOSLEEP, request as usize, remaining as usize) })
            .map(|_| ())
    }

    /// Performs Linux/AArch64 `clock_nanosleep` with its native four-argument
    /// syscall ABI, without using libc or TLS `errno`.
    ///
    /// `flags` is zero for a relative request and `1` (`TIMER_ABSTIME`) for an
    /// absolute request. Linux does not write `remaining` for an absolute
    /// request; callers should pass null in that mode.
    ///
    /// # Safety
    ///
    /// `request` must point to a readable Linux/AArch64 `struct timespec`.
    /// For a relative request, `remaining` must point to writable storage for
    /// one such value. For an absolute request, `remaining` must be null.
    #[inline]
    pub unsafe fn clock_nanosleep_raw(
        clock_id: i32,
        flags: u32,
        request: *const u8,
        remaining: *mut u8,
    ) -> Result<()> {
        // SAFETY: The caller owns the timespec pointer contracts; Linux
        // validates the clock identifier, flags, and timespec fields.
        decode(unsafe {
            syscall4(
                SYS_CLOCK_NANOSLEEP,
                clock_id as usize,
                flags as usize,
                request as usize,
                remaining as usize,
            )
        })
        .map(|_| ())
    }

    /// Queries a Linux clock through the validated kernel vDSO when present,
    /// otherwise through the direct syscall, without libc or TLS `errno`.
    ///
    /// # Safety
    ///
    /// `timespec` must be writable for one Linux/AArch64 `struct timespec`.
    #[inline]
    pub unsafe fn clock_gettime_raw(clock_id: i32, timespec: *mut u8) -> Result<()> {
        // SAFETY: The caller supplies exact output storage for the vDSO or
        // direct Linux/AArch64 timespec ABI.
        decode(unsafe { clock_gettime_status_raw(clock_id, timespec) } as isize).map(|_| ())
    }

    /// Queries a Linux clock with the raw kernel success/negative-errno
    /// convention used by the C ABI wrapper.
    ///
    /// The route is the same validated vDSO dispatch and direct-syscall
    /// fallback as [`clock_gettime_raw`], but it avoids constructing an
    /// internal `Result` only to translate it immediately back to C's errno
    /// convention.
    ///
    /// # Safety
    ///
    /// `timespec` must be writable for one Linux/AArch64 `struct timespec`.
    #[inline]
    pub unsafe fn clock_gettime_status_raw(clock_id: i32, timespec: *mut u8) -> i32 {
        // SAFETY: The caller owns the output-pointer contract.
        unsafe { crate::vdso::clock_gettime_status(clock_id, timespec) }
    }

    /// Queries a known vDSO-supported Linux clock without repeating the
    /// generic clock-ID eligibility check on the hot path.
    ///
    /// # Safety
    ///
    /// `clock_id` must be one of Linux/AArch64's fixed vDSO-supported IDs
    /// (0, 1, 4, 5, 6, 7, or 11), and `timespec` must be writable for one
    /// Linux/AArch64 `struct timespec`. Arbitrary user-provided IDs must use
    /// [`clock_gettime_status_raw`] instead.
    #[inline]
    pub unsafe fn clock_gettime_known_vdso_status_raw(
        clock_id: i32,
        timespec: *mut u8,
    ) -> i32 {
        // SAFETY: The caller states the clock-ID and output-pointer contract.
        unsafe { crate::vdso::clock_gettime_known_vdso_status(clock_id, timespec) }
    }

    /// Sets a Linux clock without using libc, vDSO dispatch, or TLS `errno`.
    ///
    /// Linux permits only settable clocks and requires the caller to have
    /// permission to change them. The kernel therefore remains responsible
    /// for returning `EINVAL` for a non-settable clock and `EPERM` when the
    /// caller lacks the required privilege.
    ///
    /// # Safety
    ///
    /// `timespec` must point to a readable Linux/AArch64 `struct timespec`
    /// whose `tv_nsec` field has already been validated as canonical.
    #[inline]
    pub unsafe fn clock_settime_raw(clock_id: i32, timespec: *const u8) -> Result<()> {
        // SAFETY: The caller owns the readable timespec pointer contract and
        // has validated its nanosecond field before crossing this boundary.
        decode(unsafe { syscall2(SYS_CLOCK_SETTIME, clock_id as usize, timespec as usize) })
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
    use super::{
        decode, decode_i32, syscall1, syscall2, syscall3, syscall4, syscall5, syscall6, Errno,
        RawFd, Result, SYS_EPOLL_CREATE1, SYS_EPOLL_CTL, SYS_EPOLL_PWAIT, SYS_EVENTFD2,
        SYS_PPOLL, SYS_PSELECT6, SYS_READ, SYS_WRITE,
    };

    /// Creates a Linux event descriptor without using libc or TLS `errno`.
    #[inline]
    pub fn eventfd(initval: u32, flags: u32) -> Result<RawFd> {
        // SAFETY: Linux validates the initial value and flags.
        decode(unsafe { syscall2(SYS_EVENTFD2, initval as usize, flags as usize) })
            .map(|fd| fd as RawFd)
    }

    /// Reads one complete Linux eventfd counter record without using libc or
    /// TLS `errno`.
    ///
    /// Linux eventfd records are exactly one little-endian `u64`. The value is
    /// kept in a stack slot owned by this operation, so callers receive the
    /// typed counter value rather than a raw byte buffer. A successful
    /// eventfd read always consumes and returns the complete eight-byte
    /// record; a different successful count is rejected as an I/O contract
    /// violation.
    #[inline]
    pub fn eventfd_read(fd: RawFd) -> Result<u64> {
        let mut value = 0_u64;
        // SAFETY: `value` is aligned writable storage for exactly one eventfd
        // record and remains live for the direct syscall.
        let count = decode(unsafe {
            syscall3(
                SYS_READ,
                fd as usize,
                (&mut value as *mut u64).cast::<u8>() as usize,
                core::mem::size_of::<u64>(),
            )
        })?;
        if count != core::mem::size_of::<u64>() {
            return Err(Errno::IO);
        }
        Ok(value)
    }

    /// Writes one complete Linux eventfd counter record without using libc or
    /// TLS `errno`.
    ///
    /// `value` is the eventfd increment. Linux rejects `u64::MAX` and reports
    /// counter overflow according to the descriptor's blocking mode. The
    /// helper always submits exactly one eight-byte little-endian record and
    /// reports any other successful count as an I/O contract violation.
    #[inline]
    pub fn eventfd_write(fd: RawFd, value: u64) -> Result<()> {
        // SAFETY: `value` is aligned readable storage for exactly one eventfd
        // record and remains live for the direct syscall.
        let count = decode(unsafe {
            syscall3(
                SYS_WRITE,
                fd as usize,
                (&value as *const u64).cast::<u8>() as usize,
                core::mem::size_of::<u64>(),
            )
        })?;
        if count != core::mem::size_of::<u64>() {
            return Err(Errno::IO);
        }
        Ok(())
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

    /// Waits for descriptor readiness through Linux/AArch64 `pselect6`.
    ///
    /// Linux mutates the supplied timeout and the descriptor sets in place;
    /// the typed facade owns copies where its public contract requires
    /// immutability. The final syscall argument is Linux's private pair of a
    /// signal-mask pointer and its byte size, not the public 128-byte musl
    /// `sigset_t` size.
    ///
    /// # Safety
    ///
    /// The descriptor-set pointers must be null or point to writable storage
    /// for the kernel's bit-vector representation. `timeout` must be null or
    /// point to writable Linux/AArch64 `timespec` storage. `sigmask` must be
    /// null or point to a kernel-sized signal mask of `sigsetsize` bytes.
    #[inline]
    pub unsafe fn pselect6_raw(
        nfds: i32,
        readfds: *mut u8,
        writefds: *mut u8,
        exceptfds: *mut u8,
        timeout: *mut u8,
        sigmask: *const u8,
        sigsetsize: usize,
    ) -> Result<i32> {
        #[repr(C)]
        struct KernelSigmask {
            mask: *const u8,
            size: usize,
        }

        let signal_argument = KernelSigmask {
            mask: sigmask,
            size: sigsetsize,
        };
        // SAFETY: The caller owns the pointed-to descriptor sets, timeout,
        // and optional kernel signal mask. The stack pair is the exact
        // AArch64 pselect6 argument-6 layout and remains live for the call.
        decode_i32(unsafe {
            syscall6(
                SYS_PSELECT6,
                nfds as usize,
                readfds as usize,
                writefds as usize,
                exceptfds as usize,
                timeout as usize,
                (&signal_argument as *const KernelSigmask) as usize,
            )
        })
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

/// Direct Linux socket operations.
pub mod net {
    use super::{
        decode, decode_i32, syscall2, syscall3, syscall4, syscall5, syscall6, MaybeUninit, RawFd,
        Result,
        SYS_ACCEPT, SYS_ACCEPT4, SYS_BIND, SYS_CONNECT, SYS_GETPEERNAME, SYS_GETSOCKNAME,
        SYS_GETSOCKOPT, SYS_LISTEN, SYS_RECVFROM, SYS_SENDTO, SYS_SETSOCKOPT, SYS_SHUTDOWN,
        SYS_SOCKET, SYS_SOCKETPAIR, SYS_RECVMMSG, SYS_SENDMMSG,
    };

    use super::io::Iovec;

    const SOL_SOCKET: usize = 1;
    const SO_REUSEADDR: usize = 2;
    const SO_BROADCAST: usize = 6;
    const SO_OOBINLINE: usize = 10;
    const SO_TYPE: usize = 3;
    const SO_ERROR: usize = 4;
    const SO_PROTOCOL: usize = 38;
    const SO_DOMAIN: usize = 39;
    const SO_ACCEPTCONN: usize = 30;
    const SO_COOKIE: usize = 57;

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

    /// Sets Linux `SOL_SOCKET/SO_REUSEADDR` without libc or TLS `errno`.
    ///
    /// Linux represents this boolean socket option as a four-byte integer.
    /// The value is kept entirely inside this typed seam; callers cannot
    /// provide an arbitrary option level, name, pointer, or length.
    #[inline]
    pub fn set_socket_reuseaddr(socket: RawFd, enabled: bool) -> Result<()> {
        let value = u32::from(enabled);
        // SAFETY: `value` is a live four-byte integer for the duration of the
        // direct syscall, and Linux validates the descriptor and option.
        decode(unsafe {
            syscall5(
                SYS_SETSOCKOPT,
                socket as usize,
                SOL_SOCKET,
                SO_REUSEADDR,
                (&value as *const u32) as usize,
                core::mem::size_of::<u32>(),
            )
        })
        .map(|_| ())
    }

    /// Gets Linux `SOL_SOCKET/SO_REUSEADDR` without libc or TLS `errno`.
    ///
    /// Linux returns this boolean socket option as a four-byte integer. A
    /// nonzero value is `true`, matching Rustix and the Linux socket ABI.
    #[inline]
    pub fn socket_reuseaddr(socket: RawFd) -> Result<bool> {
        let mut value = MaybeUninit::<u32>::uninit();
        let mut length = core::mem::size_of::<u32>() as u32;
        // SAFETY: `value` and `length` are writable Linux socket-option output
        // storage for the duration of the direct syscall.
        decode(unsafe {
            syscall5(
                SYS_GETSOCKOPT,
                socket as usize,
                SOL_SOCKET,
                SO_REUSEADDR,
                value.as_mut_ptr() as usize,
                (&mut length as *mut u32) as usize,
            )
        })?;
        if length as usize != core::mem::size_of::<u32>() {
            return Err(super::Errno::INVAL);
        }
        // SAFETY: Linux initialized exactly the four bytes described by
        // `length` on successful `getsockopt`.
        Ok(unsafe { value.assume_init() } != 0)
    }

    /// Sets Linux `SOL_SOCKET/SO_BROADCAST` without libc or TLS `errno`.
    ///
    /// Linux represents this boolean socket option as a four-byte integer.
    /// The value is kept entirely inside this typed seam; callers cannot
    /// provide an arbitrary option level, name, pointer, or length.
    #[inline]
    pub fn set_socket_broadcast(socket: RawFd, enabled: bool) -> Result<()> {
        let value = u32::from(enabled);
        // SAFETY: `value` is a live four-byte integer for the duration of the
        // direct syscall, and Linux validates the descriptor and option.
        decode(unsafe {
            syscall5(
                SYS_SETSOCKOPT,
                socket as usize,
                SOL_SOCKET,
                SO_BROADCAST,
                (&value as *const u32) as usize,
                core::mem::size_of::<u32>(),
            )
        })
        .map(|_| ())
    }

    /// Gets Linux `SOL_SOCKET/SO_BROADCAST` without libc or TLS `errno`.
    ///
    /// Linux returns this boolean socket option as a four-byte integer. A
    /// nonzero value is `true`, matching Rustix and the Linux socket ABI.
    #[inline]
    pub fn socket_broadcast(socket: RawFd) -> Result<bool> {
        let mut value = MaybeUninit::<u32>::uninit();
        let mut length = core::mem::size_of::<u32>() as u32;
        // SAFETY: `value` and `length` are writable Linux socket-option output
        // storage for the duration of the direct syscall.
        decode(unsafe {
            syscall5(
                SYS_GETSOCKOPT,
                socket as usize,
                SOL_SOCKET,
                SO_BROADCAST,
                value.as_mut_ptr() as usize,
                (&mut length as *mut u32) as usize,
            )
        })?;
        if length as usize != core::mem::size_of::<u32>() {
            return Err(super::Errno::INVAL);
        }
        // SAFETY: Linux initialized exactly the four bytes described by
        // `length` on successful `getsockopt`.
        Ok(unsafe { value.assume_init() } != 0)
    }

    /// Sets Linux `SOL_SOCKET/SO_OOBINLINE` without libc or TLS `errno`.
    ///
    /// Linux represents this boolean socket option as a four-byte integer.
    /// The value is kept entirely inside this typed seam; callers cannot
    /// provide an arbitrary option level, name, pointer, or length.
    #[inline]
    pub fn set_socket_oobinline(socket: RawFd, enabled: bool) -> Result<()> {
        let value = u32::from(enabled);
        // SAFETY: `value` is a live four-byte integer for the duration of the
        // direct syscall, and Linux validates the descriptor and option.
        decode(unsafe {
            syscall5(
                SYS_SETSOCKOPT,
                socket as usize,
                SOL_SOCKET,
                SO_OOBINLINE,
                (&value as *const u32) as usize,
                core::mem::size_of::<u32>(),
            )
        })
        .map(|_| ())
    }

    /// Gets Linux `SOL_SOCKET/SO_OOBINLINE` without libc or TLS `errno`.
    ///
    /// Linux returns this boolean socket option as a four-byte integer. A
    /// nonzero value is `true`, matching Rustix and the Linux socket ABI.
    #[inline]
    pub fn socket_oobinline(socket: RawFd) -> Result<bool> {
        let mut value = MaybeUninit::<u32>::uninit();
        let mut length = core::mem::size_of::<u32>() as u32;
        // SAFETY: `value` and `length` are writable Linux socket-option output
        // storage for the duration of the direct syscall.
        decode(unsafe {
            syscall5(
                SYS_GETSOCKOPT,
                socket as usize,
                SOL_SOCKET,
                SO_OOBINLINE,
                value.as_mut_ptr() as usize,
                (&mut length as *mut u32) as usize,
            )
        })?;
        if length as usize != core::mem::size_of::<u32>() {
            return Err(super::Errno::INVAL);
        }
        // SAFETY: Linux initialized exactly the four bytes described by
        // `length` on successful `getsockopt`.
        Ok(unsafe { value.assume_init() } != 0)
    }

    /// Gets Linux `SOL_SOCKET/SO_TYPE` without libc or TLS `errno`.
    ///
    /// Linux returns the socket type as a four-byte integer. The option level,
    /// name, output storage, and length are fixed inside this typed seam.
    #[inline]
    pub fn socket_type(socket: RawFd) -> Result<u32> {
        let mut value = MaybeUninit::<u32>::uninit();
        let mut length = core::mem::size_of::<u32>() as u32;
        // SAFETY: `value` and `length` are writable Linux socket-option output
        // storage for the duration of the direct syscall.
        decode(unsafe {
            syscall5(
                SYS_GETSOCKOPT,
                socket as usize,
                SOL_SOCKET,
                SO_TYPE,
                value.as_mut_ptr() as usize,
                (&mut length as *mut u32) as usize,
            )
        })?;
        if length as usize != core::mem::size_of::<u32>() {
            return Err(super::Errno::INVAL);
        }
        // SAFETY: Linux initialized exactly the four bytes described by
        // `length` on successful `getsockopt`.
        Ok(unsafe { value.assume_init() })
    }

    /// Gets Linux `SOL_SOCKET/SO_PROTOCOL` without libc or TLS `errno`.
    ///
    /// Linux returns the protocol as a four-byte integer. The option level,
    /// name, output storage, and length are fixed inside this typed seam.
    #[inline]
    pub fn socket_protocol(socket: RawFd) -> Result<u32> {
        let mut value = MaybeUninit::<u32>::uninit();
        let mut length = core::mem::size_of::<u32>() as u32;
        // SAFETY: `value` and `length` are writable Linux socket-option output
        // storage for the duration of the direct syscall.
        decode(unsafe {
            syscall5(
                SYS_GETSOCKOPT,
                socket as usize,
                SOL_SOCKET,
                SO_PROTOCOL,
                value.as_mut_ptr() as usize,
                (&mut length as *mut u32) as usize,
            )
        })?;
        if length as usize != core::mem::size_of::<u32>() {
            return Err(super::Errno::INVAL);
        }
        // SAFETY: Linux initialized exactly the four bytes described by
        // `length` on successful `getsockopt`.
        Ok(unsafe { value.assume_init() })
    }

    /// Reads the pending Linux `SOL_SOCKET/SO_ERROR` value without libc or
    /// TLS `errno`.
    ///
    /// A successful `getsockopt` returns the pending socket error as a
    /// non-negative integer.  The resolver transport uses this after a
    /// nonblocking TCP connect becomes writable; keeping the query here makes
    /// the pointer and four-byte output layout explicit at the shared kernel
    /// boundary.
    #[inline]
    pub fn socket_error(socket: RawFd) -> Result<i32> {
        let mut value = MaybeUninit::<i32>::uninit();
        let mut length = core::mem::size_of::<i32>() as u32;
        // SAFETY: `value` and `length` are writable Linux socket-option output
        // storage for the duration of the direct syscall.
        decode(unsafe {
            syscall5(
                SYS_GETSOCKOPT,
                socket as usize,
                SOL_SOCKET,
                SO_ERROR,
                value.as_mut_ptr() as usize,
                (&mut length as *mut u32) as usize,
            )
        })?;
        if length as usize != core::mem::size_of::<i32>() {
            return Err(super::Errno::INVAL);
        }
        // SAFETY: Linux initialized exactly the four bytes described by
        // `length` on successful `getsockopt`.
        Ok(unsafe { value.assume_init() })
    }

    /// Gets Linux `SOL_SOCKET/SO_COOKIE` without libc or TLS `errno`.
    ///
    /// Linux returns the socket cookie as one private eight-byte integer. The
    /// cookie's value is preserved exactly; only the option level, name,
    /// output storage, and length are fixed inside this typed seam.
    #[inline]
    pub fn socket_cookie(socket: RawFd) -> Result<u64> {
        let mut value = MaybeUninit::<u64>::uninit();
        let mut length = core::mem::size_of::<u64>() as u32;
        // SAFETY: `value` and `length` are writable Linux socket-option output
        // storage for the duration of the direct syscall.
        decode(unsafe {
            syscall5(
                SYS_GETSOCKOPT,
                socket as usize,
                SOL_SOCKET,
                SO_COOKIE,
                value.as_mut_ptr() as usize,
                (&mut length as *mut u32) as usize,
            )
        })?;
        if length as usize != core::mem::size_of::<u64>() {
            return Err(super::Errno::INVAL);
        }
        // SAFETY: Linux initialized exactly the eight bytes described by
        // `length` on successful `getsockopt`.
        Ok(unsafe { value.assume_init() })
    }

    /// Gets Linux `SOL_SOCKET/SO_DOMAIN` without libc or TLS `errno`.
    ///
    /// Linux returns the address family as one private four-byte signed
    /// integer. Conversion to the facade's narrower `AddressFamily` type is
    /// intentionally performed above this direct wire seam.
    #[inline]
    pub fn socket_domain(socket: RawFd) -> Result<i32> {
        let mut value = MaybeUninit::<i32>::uninit();
        let mut length = core::mem::size_of::<i32>() as u32;
        // SAFETY: `value` and `length` are writable Linux socket-option output
        // storage for the duration of the direct syscall.
        decode(unsafe {
            syscall5(
                SYS_GETSOCKOPT,
                socket as usize,
                SOL_SOCKET,
                SO_DOMAIN,
                value.as_mut_ptr() as usize,
                (&mut length as *mut u32) as usize,
            )
        })?;
        if length as usize != core::mem::size_of::<i32>() {
            return Err(super::Errno::INVAL);
        }
        // SAFETY: Linux initialized exactly the four bytes described by
        // `length` on successful `getsockopt`.
        Ok(unsafe { value.assume_init() })
    }

    /// Gets Linux `SOL_SOCKET/SO_ACCEPTCONN` without libc or TLS `errno`.
    ///
    /// Linux returns the listening state as one private four-byte signed
    /// integer. The safe facade intentionally applies Rustix's raw-nonzero
    /// boolean conversion above this direct wire seam.
    #[inline]
    pub fn socket_acceptconn(socket: RawFd) -> Result<i32> {
        let mut value = MaybeUninit::<i32>::uninit();
        let mut length = core::mem::size_of::<i32>() as u32;
        // SAFETY: `value` and `length` are writable Linux socket-option output
        // storage for the duration of the direct syscall.
        decode(unsafe {
            syscall5(
                SYS_GETSOCKOPT,
                socket as usize,
                SOL_SOCKET,
                SO_ACCEPTCONN,
                value.as_mut_ptr() as usize,
                (&mut length as *mut u32) as usize,
            )
        })?;
        if length as usize != core::mem::size_of::<i32>() {
            return Err(super::Errno::INVAL);
        }
        // SAFETY: Linux initialized exactly the four bytes described by
        // `length` on successful `getsockopt`.
        Ok(unsafe { value.assume_init() })
    }

    /// Enables listening for incoming connections without libc or TLS
    /// `errno`.
    #[inline]
    pub fn listen(socket: RawFd, backlog: i32) -> Result<()> {
        // SAFETY: Linux validates the descriptor and signed backlog scalar;
        // this syscall has no pointer arguments.
        decode(unsafe { syscall2(SYS_LISTEN, socket as usize, backlog as usize) }).map(|_| ())
    }

    /// Accepts one pending connection with the Linux `accept` ABI.
    ///
    /// # Safety
    ///
    /// `address` and `address_length` must be null, or must satisfy the
    /// Linux `accept` output-pointer contract: `address` points to writable
    /// storage whose capacity is described by `*address_length`, and
    /// `address_length` points to writable `socklen_t` storage. The caller is
    /// responsible for validating any returned address bytes before decoding.
    #[inline]
    pub unsafe fn accept_raw(
        socket: RawFd,
        address: *mut u8,
        address_length: *mut u32,
    ) -> Result<RawFd> {
        // SAFETY: The caller owns the optional output-pointer contract; Linux
        // validates the descriptor and initializes the accepted descriptor.
        decode_i32(unsafe {
            syscall3(
                SYS_ACCEPT,
                socket as usize,
                address as usize,
                address_length as usize,
            )
        })
    }

    /// Accepts one pending connection with Linux `accept4` flags.
    ///
    /// # Safety
    ///
    /// `address` and `address_length` have the same nullable output-pointer
    /// contract as [`accept_raw`]. `flags` must contain only Linux
    /// `SOCK_CLOEXEC` and `SOCK_NONBLOCK` bits when called by a typed facade;
    /// this raw seam forwards the word for the kernel to validate.
    #[inline]
    pub unsafe fn accept4_raw(
        socket: RawFd,
        address: *mut u8,
        address_length: *mut u32,
        flags: u32,
    ) -> Result<RawFd> {
        // SAFETY: The caller owns the optional output-pointer contract; Linux
        // validates the descriptor, flags, and initializes the accepted fd.
        decode_i32(unsafe {
            syscall4(
                SYS_ACCEPT4,
                socket as usize,
                address as usize,
                address_length as usize,
                flags as usize,
            )
        })
    }

    /// Shuts down one direction of a Linux socket without libc or TLS
    /// `errno`.
    #[inline]
    pub fn shutdown(socket: RawFd, how: i32) -> Result<()> {
        // SAFETY: Linux validates the descriptor and shutdown mode; this
        // syscall has no pointer arguments.
        decode(unsafe { syscall2(SYS_SHUTDOWN, socket as usize, how as usize) }).map(|_| ())
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

    /// Binds a socket to a caller-owned Linux socket address.
    ///
    /// # Safety
    ///
    /// `address` must point to a readable Linux socket address of
    /// `address_length` bytes for the duration of the syscall.
    #[inline]
    pub unsafe fn bind_raw(
        socket: RawFd,
        address: *const u8,
        address_length: u32,
    ) -> Result<()> {
        // SAFETY: The caller owns the address pointer and length contract.
        decode(unsafe {
            syscall3(
                SYS_BIND,
                socket as usize,
                address as usize,
                address_length as usize,
            )
        })
        .map(|_| ())
    }

    /// Returns a socket's local address into caller-provided Linux storage.
    ///
    /// # Safety
    ///
    /// `address` must point to writable storage whose capacity is described by
    /// `*address_length`, and `address_length` must point to writable Linux
    /// `socklen_t` storage. On success Linux replaces the length with the
    /// number of initialized address bytes; callers must validate that result
    /// before interpreting the storage.
    #[inline]
    pub unsafe fn getsockname_raw(
        socket: RawFd,
        address: *mut u8,
        address_length: *mut u32,
    ) -> Result<()> {
        // SAFETY: The caller owns the output storage and socklen pointer
        // contracts; Linux validates the descriptor and reported capacity.
        decode(unsafe {
            syscall3(
                SYS_GETSOCKNAME,
                socket as usize,
                address as usize,
                address_length as usize,
            )
        })
        .map(|_| ())
    }

    /// Returns a socket's connected peer address into caller-provided Linux
    /// storage.
    ///
    /// # Safety
    ///
    /// `address` must point to writable storage whose capacity is described by
    /// `*address_length`, and `address_length` must point to writable Linux
    /// `socklen_t` storage. On success Linux replaces the length with the
    /// number of initialized address bytes; callers must validate that result
    /// before interpreting the storage.
    #[inline]
    pub unsafe fn getpeername_raw(
        socket: RawFd,
        address: *mut u8,
        address_length: *mut u32,
    ) -> Result<()> {
        // SAFETY: The caller owns the output storage and socklen pointer
        // contracts; Linux validates the descriptor and reported capacity.
        decode(unsafe {
            syscall3(
                SYS_GETPEERNAME,
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

    /// One Linux/AArch64 message header assembled privately for `sendmsg` and
    /// `recvmsg`. The public native facade supplies only typed borrowed iovecs;
    /// callers cannot provide a raw `msghdr`, ancillary pointer, or address
    /// pointer through this seam.
    #[repr(C)]
    struct MessageHeader {
        name: *mut u8,
        name_length: u32,
        iovecs: *mut Iovec,
        iovec_count: usize,
        control: *mut u8,
        control_length: usize,
        flags: u32,
    }

    /// Sends one ordinary vectored message on a connected socket through the
    /// Linux `sendmsg` ABI.
    ///
    /// # Safety
    ///
    /// `iovecs` must be null or point to `count` initialized [`Iovec`] records
    /// readable for the duration of the call. Every non-empty iovec range
    /// must be valid for immutable access for its `iov_len` bytes. A null
    /// iovec pointer is permitted only when `count` is zero. The descriptor's
    /// socket validity is the caller's responsibility.
    #[inline]
    pub unsafe fn sendmsg_raw(
        socket: RawFd,
        iovecs: *const Iovec,
        count: usize,
        flags: u32,
    ) -> Result<usize> {
        let header = MessageHeader {
            name: core::ptr::null_mut(),
            name_length: 0,
            iovecs: iovecs.cast_mut(),
            iovec_count: count,
            control: core::ptr::null_mut(),
            control_length: 0,
            flags: 0,
        };
        // SAFETY: The caller supplies the iovec-array and pointed-to-buffer
        // validity contracts; the private header has no name or control data.
        decode(unsafe {
            syscall3(
                super::SYS_SENDMSG,
                socket as usize,
                (&header as *const MessageHeader) as usize,
                flags as usize,
            )
        })
    }

    /// Receives one ordinary vectored message from a socket through the Linux
    /// `recvmsg` ABI and returns the kernel byte count plus returned message
    /// flags.
    ///
    /// # Safety
    ///
    /// `iovecs` must be null or point to `count` initialized [`Iovec`] records
    /// readable for the duration of the call. Every non-empty iovec range
    /// must be valid for mutable access for its `iov_len` bytes, and those
    /// ranges must be pairwise disjoint. A null iovec pointer is permitted
    /// only when `count` is zero. The descriptor's socket validity is the
    /// caller's responsibility.
    #[inline]
    pub unsafe fn recvmsg_raw(
        socket: RawFd,
        iovecs: *const Iovec,
        count: usize,
        flags: u32,
    ) -> Result<(usize, u32)> {
        let mut header = MessageHeader {
            name: core::ptr::null_mut(),
            name_length: 0,
            iovecs: iovecs.cast_mut(),
            iovec_count: count,
            control: core::ptr::null_mut(),
            control_length: 0,
            flags: 0,
        };
        // SAFETY: The caller supplies the iovec-array and pointed-to-buffer
        // validity contracts; the private header has no name or control data.
        let bytes = decode(unsafe {
            syscall3(
                super::SYS_RECVMSG,
                socket as usize,
                (&mut header as *mut MessageHeader) as usize,
                flags as usize,
            )
        })?;
        Ok((bytes, header.flags))
    }

    /// Sends an array of Linux/AArch64 private `mmsghdr` records.
    ///
    /// The records are assembled by the native facade. This raw seam keeps
    /// the Linux `mmsghdr` layout out of the public Rust API while preserving
    /// the kernel's count-returning partial-success contract.
    ///
    /// # Safety
    ///
    /// `messages` must be null when `count` is zero, or point to `count`
    /// initialized, contiguous AArch64 `mmsghdr` records. Every nested
    /// header and iovec must satisfy Linux's read-only send contract, and the
    /// records remain valid for the syscall duration.
    #[inline]
    pub unsafe fn sendmmsg_raw(
        socket: RawFd,
        messages: *mut u8,
        count: u32,
        flags: u32,
    ) -> Result<usize> {
        // SAFETY: The caller owns the private mmsghdr array and its nested
        // iovec/source-buffer contracts.
        decode(unsafe {
            syscall4(
                SYS_SENDMMSG,
                socket as usize,
                messages as usize,
                count as usize,
                flags as usize,
            )
        })
    }

    /// Receives an array of Linux/AArch64 private `mmsghdr` records.
    ///
    /// `timeout` is the optional mutable Linux `timespec` consumed and
    /// updated by `recvmmsg`; callers must observe the value after the call.
    /// A positive return is the number of messages initialized, even if a
    /// later message would have blocked or failed.
    ///
    /// # Safety
    ///
    /// `messages` must be null when `count` is zero, or point to `count`
    /// initialized, contiguous AArch64 `mmsghdr` records. Every nested
    /// header and iovec must satisfy Linux's writable receive contract, and
    /// `timeout` must be null or point to writable `timespec` storage. All
    /// pointed-to records and buffers remain valid for the syscall duration.
    #[inline]
    pub unsafe fn recvmmsg_raw(
        socket: RawFd,
        messages: *mut u8,
        count: u32,
        flags: u32,
        timeout: *mut u8,
    ) -> Result<usize> {
        // SAFETY: The caller owns the private mmsghdr array, timeout, and all
        // nested destination-buffer contracts.
        decode(unsafe {
            syscall5(
                SYS_RECVMMSG,
                socket as usize,
                messages as usize,
                count as usize,
                flags as usize,
                timeout as usize,
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
    /// Stream socket type in the Linux socket ABI.
    pub const SOCK_STREAM: u32 = 1;
    /// Nonblocking socket creation flag in the Linux socket ABI.
    const SOCK_NONBLOCK: u32 = 0x0000_0800;
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
    const POLLOUT: i16 = 0x0004;
    const POLLERR: i16 = 0x0008;
    const POLLHUP: i16 = 0x0010;
    const POLLNVAL: i16 = 0x0020;
    const CLOCK_MONOTONIC: i32 = 1;

    enum UdpResponse {
        Complete(usize),
        Truncated,
    }

    struct ServerAddress {
        family: i32,
        storage: [u8; 28],
        length: u32,
    }

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

    fn server_address(server: NameServer) -> Result<ServerAddress> {
        let mut result = ServerAddress {
            family: server.family as i32,
            storage: [0; 28],
            length: 0,
        };
        match server.family {
            AF_INET => {
                let address = SockaddrIn {
                    family: AF_INET,
                    port: (if server.port == 0 { 53 } else { server.port }).to_be(),
                    address: u32::from_ne_bytes([
                        server.address[0], server.address[1], server.address[2], server.address[3],
                    ]),
                    zero: [0; 8],
                };
                // SAFETY: `address` is a live, initialized C-layout record and
                // the source slice covers exactly its private Linux ABI size.
                let bytes = unsafe {
                    core::slice::from_raw_parts(
                        (&address as *const SockaddrIn).cast::<u8>(),
                        core::mem::size_of::<SockaddrIn>(),
                    )
                };
                result.storage[..bytes.len()].copy_from_slice(bytes);
                result.length = bytes.len() as u32;
            }
            AF_INET6 => {
                let address = SockaddrIn6 {
                    family: AF_INET6,
                    port: (if server.port == 0 { 53 } else { server.port }).to_be(),
                    flow_info: 0,
                    address: server.address,
                    scope_id: server.scope_id,
                };
                // SAFETY: `address` is a live, initialized C-layout record and
                // the source slice covers exactly its private Linux ABI size.
                let bytes = unsafe {
                    core::slice::from_raw_parts(
                        (&address as *const SockaddrIn6).cast::<u8>(),
                        core::mem::size_of::<SockaddrIn6>(),
                    )
                };
                result.storage[..bytes.len()].copy_from_slice(bytes);
                result.length = bytes.len() as u32;
            }
            _ => return Err(invalid()),
        }
        Ok(result)
    }

    fn monotonic_millis() -> Result<i64> {
        let mut value = Timespec { seconds: 0, nanoseconds: 0 };
        // SAFETY: `value` is the exact two-word Linux/AArch64 timespec output
        // record and remains live for the direct syscall.
        unsafe {
            super::time::clock_gettime_raw(CLOCK_MONOTONIC, (&mut value as *mut Timespec).cast())?
        };
        Ok(value
            .seconds
            .saturating_mul(1_000)
            .saturating_add(value.nanoseconds / 1_000_000))
    }

    fn deadline_after(timeout_ms: u32) -> Result<i64> {
        Ok(monotonic_millis()?.saturating_add(timeout_ms as i64))
    }

    fn remaining_millis(deadline: i64) -> Result<u32> {
        let now = monotonic_millis()?;
        if now >= deadline {
            return Ok(0);
        }
        Ok((deadline - now).min(u32::MAX as i64) as u32)
    }

    fn poll_until(fd: i32, events: i16, deadline: i64) -> Result<bool> {
        loop {
            let remaining = remaining_millis(deadline)?;
            if remaining == 0 {
                return Ok(false);
            }
            let mut poll = PollFd { fd, events, revents: 0 };
            let timeout = Timespec {
                seconds: (remaining / 1_000) as i64,
                nanoseconds: ((remaining % 1_000) as i64) * 1_000_000,
            };
            // SAFETY: `poll` and `timeout` are valid local Linux ABI records.
            match unsafe {
                super::event::ppoll_raw(
                    (&mut poll as *mut PollFd).cast(),
                    1,
                    (&timeout as *const Timespec).cast(),
                    core::ptr::null(),
                    8,
                )
            } {
                Ok(0) => return Ok(false),
                Ok(_) => {
                    return Ok(poll.revents & (events | POLLERR | POLLHUP | POLLNVAL) != 0);
                }
                Err(error) if error == super::Errno::INTR => continue,
                Err(error) => return Err(error),
            }
        }
    }

    fn send_all(fd: i32, bytes: &[u8], deadline: i64) -> Result<()> {
        let mut offset = 0usize;
        while offset < bytes.len() {
            if remaining_millis(deadline)? == 0 {
                return Err(super::Errno::TIMEDOUT);
            }
            // A connected stream uses the same Linux sendto ABI with a null
            // destination; MSG_NOSIGNAL keeps a failed DNS peer from raising
            // SIGPIPE in the caller.
            let sent = unsafe {
                net::sendto_raw(
                    fd,
                    bytes[offset..].as_ptr(),
                    bytes.len() - offset,
                    MSG_NOSIGNAL,
                    core::ptr::null(),
                    0,
                )
            };
            match sent {
                Ok(0) => return Err(super::Errno::PIPE),
                Ok(length) => offset += length,
                Err(error) if error == super::Errno::INTR => continue,
                Err(error) if error == super::Errno::AGAIN || error == super::Errno::WOULDBLOCK => {
                    if !poll_until(fd, POLLOUT, deadline)? {
                        return Err(super::Errno::TIMEDOUT);
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn send_datagram(fd: i32, bytes: &[u8], deadline: i64) -> Result<()> {
        loop {
            if remaining_millis(deadline)? == 0 {
                return Err(super::Errno::TIMEDOUT);
            }
            // A DNS query must remain one UDP datagram. A short successful
            // send is therefore a failed server attempt, never a partial
            // query which can be retried as a second datagram.
            let sent = unsafe {
                net::sendto_raw(
                    fd,
                    bytes.as_ptr(),
                    bytes.len(),
                    MSG_NOSIGNAL,
                    core::ptr::null(),
                    0,
                )
            };
            match sent {
                Ok(length) if length == bytes.len() => return Ok(()),
                Ok(_) => return Err(super::Errno::MSGSIZE),
                Err(error) if error == super::Errno::INTR => continue,
                Err(error) if error == super::Errno::AGAIN || error == super::Errno::WOULDBLOCK => {
                    if !poll_until(fd, POLLOUT, deadline)? {
                        return Err(super::Errno::TIMEDOUT);
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn receive_exact(fd: i32, bytes: &mut [u8], deadline: i64) -> Result<()> {
        let mut offset = 0usize;
        while offset < bytes.len() {
            if !poll_until(fd, POLLIN, deadline)? {
                return Err(super::Errno::TIMEDOUT);
            }
            let received = unsafe {
                net::recvfrom_raw(
                    fd,
                    bytes[offset..].as_mut_ptr(),
                    bytes.len() - offset,
                    0,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                )
            };
            match received {
                Ok(0) => return Err(super::Errno::CONNRESET),
                Ok(length) => offset += length,
                Err(error) if error == super::Errno::INTR || error == super::Errno::AGAIN || error == super::Errno::WOULDBLOCK => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn udp_exchange(fd: i32, query_id: u16, answer: &mut [u8], deadline: i64) -> Result<UdpResponse> {
        loop {
            if !poll_until(fd, POLLIN, deadline)? {
                return Err(super::Errno::TIMEDOUT);
            }
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
            let length = match received {
                Ok(length) => length,
                Err(error) if error == super::Errno::INTR || error == super::Errno::AGAIN || error == super::Errno::WOULDBLOCK => continue,
                Err(error) => return Err(error),
            };
            // Ignore short, non-response, wrong-transaction, and empty-
            // question packets without abandoning this nameserver. A valid
            // response can legally follow all of them on the same socket.
            if length < 12
                || u16::from_be_bytes([answer[0], answer[1]]) != query_id
                || answer[2] & 0x80 == 0
                || u16::from_be_bytes([answer[4], answer[5]]) == 0
            {
                continue;
            }
            if answer[2] & 0x02 != 0 {
                return Ok(UdpResponse::Truncated);
            }
            return Ok(UdpResponse::Complete(length));
        }
    }

    fn tcp_exchange(
        target: &ServerAddress,
        query: &[u8],
        query_id: u16,
        answer: &mut [u8],
        deadline: i64,
    ) -> Result<usize> {
        if query.len() > u16::MAX as usize || answer.len() < 12 {
            return Err(super::Errno::MSGSIZE);
        }
        let fd = net::socket(target.family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)?;
        let result = (|| {
            // SAFETY: `target.storage` contains the exact initialized Linux
            // sockaddr record selected by `server_address`.
            let connected = unsafe { net::connect_raw(fd, target.storage.as_ptr(), target.length) };
            match connected {
                Ok(()) => {}
                Err(error) if error == super::Errno::INPROGRESS || error == super::Errno::ALREADY => {
                    if !poll_until(fd, POLLOUT, deadline)? {
                        return Err(super::Errno::TIMEDOUT);
                    }
                    let pending = net::socket_error(fd)?;
                    if pending != 0 {
                        return Err(super::Errno::from_raw(pending).unwrap_or(super::Errno::IO));
                    }
                }
                Err(error) => return Err(error),
            }

            let frame_length = [(query.len() >> 8) as u8, query.len() as u8];
            send_all(fd, &frame_length, deadline)?;
            send_all(fd, query, deadline)?;

            let mut response_length_bytes = [0u8; 2];
            receive_exact(fd, &mut response_length_bytes, deadline)?;
            let response_length = u16::from_be_bytes(response_length_bytes) as usize;
            if response_length < 12 || response_length > answer.len() {
                return Err(super::Errno::MSGSIZE);
            }
            let response = &mut answer[..response_length];
            receive_exact(fd, response, deadline)?;
            if u16::from_be_bytes([response[0], response[1]]) != query_id
                || response[2] & 0x80 == 0
                || u16::from_be_bytes([response[4], response[5]]) == 0
                || response[2] & 0x02 != 0
            {
                return Err(malformed());
            }
            Ok(response_length)
        })();
        let _ = super::io::close(fd);
        result
    }

    /// Sends a DNS query through the explicitly configured nameservers.
    ///
    /// Each nameserver gets a bounded UDP deadline. Short, malformed, and
    /// wrong-transaction datagrams are ignored until that deadline. A
    /// response with the DNS truncation bit retries the same query over
    /// length-prefixed TCP, with partial I/O and connect progress charged to
    /// the same deadline. Failed servers advance in configured order and the
    /// configured attempt count repeats that order.
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
                let target = match server_address(server) {
                    Ok(value) => value,
                    Err(_) => { index += 1; continue; }
                };
                let deadline = match deadline_after(config.timeout_ms) {
                    Ok(value) => value,
                    Err(_) => { index += 1; continue; }
                };
                let fd = match net::socket(server.family as i32, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0) {
                    Ok(fd) => fd,
                    Err(_) => { index += 1; continue; }
                };
                // SAFETY: `target.storage` contains the exact initialized
                // Linux sockaddr record and remains live across the syscall.
                if unsafe { net::connect_raw(fd, target.storage.as_ptr(), target.length) }.is_err() {
                    let _ = super::io::close(fd);
                    index += 1;
                    continue;
                }
                if send_datagram(fd, query, deadline).is_err() {
                    let _ = super::io::close(fd);
                    index += 1;
                    continue;
                }
                match udp_exchange(fd, query_id, answer, deadline) {
                    Ok(UdpResponse::Complete(length)) => {
                        let _ = super::io::close(fd);
                        return Ok(length);
                    }
                    Ok(UdpResponse::Truncated) => {
                        let _ = super::io::close(fd);
                        if let Ok(length) = tcp_exchange(&target, query, query_id, answer, deadline) {
                            return Ok(length);
                        }
                    }
                    Err(_) => {
                        let _ = super::io::close(fd);
                    }
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
    use super::{
        decode, syscall2, syscall3, syscall4, syscall5, syscall6, RawFd, Result, SYS_MADVISE,
        SYS_MMAP, SYS_MINCORE, SYS_MLOCK, SYS_MLOCK2, SYS_MPROTECT, SYS_MREMAP, SYS_MSYNC,
        SYS_MUNLOCK, SYS_MUNLOCKALL, SYS_MLOCKALL, SYS_MUNMAP, SYS_REMAP_FILE_PAGES,
    };

    const MREMAP_FIXED: u32 = 0x2;

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

    /// Resizes or moves a Linux mapping with the AArch64 `mremap` ABI.
    ///
    /// `flags` is passed to Linux unchanged. The native facade currently
    /// exposes only `MREMAP_MAYMOVE`; this raw seam remains an ABI-level
    /// operation so the facade can own its closed flag policy.
    ///
    /// # Safety
    ///
    /// `address` must be page-aligned, and the range beginning there and
    /// extending for `old_length` bytes, rounded up to a page boundary, must
    /// be a valid mapping owned by the caller. The caller must ensure that
    /// `address + old_length` and `address + new_length` do not wrap. There
    /// must be no Rust references into the old range when the operation may
    /// move it, and callers must treat the old mapping as invalid after any
    /// successful call: only the returned address may be used. If the call
    /// fails, Linux leaves the old mapping available for cleanup.
    #[inline]
    pub unsafe fn mremap_raw(
        address: *mut u8,
        old_length: usize,
        new_length: usize,
        flags: u32,
    ) -> Result<*mut u8> {
        // SAFETY: The caller owns the mapping lifetime/provenance contract;
        // Linux validates lengths, flags, and the mapping itself.
        decode(unsafe {
            syscall4(
                SYS_MREMAP,
                address as usize,
                old_length,
                new_length,
                flags as usize,
            )
        })
        .map(|address| address as *mut u8)
    }

    /// Resizes or moves a Linux mapping to a caller-selected address.
    ///
    /// This is the five-argument form of `mremap`. The kernel receives
    /// `MREMAP_FIXED` in addition to `flags`; the constant is kept private so
    /// the native facade cannot accidentally expose a fixed-address request
    /// through its ordinary operation. The returned address is the only valid
    /// successor of the old mapping after success.
    ///
    /// # Safety
    ///
    /// `address` and `new_address` must be page-aligned. The old range,
    /// rounded up to a page boundary, must be a valid mapping owned by the
    /// caller. The destination range must be valid for the destination
    /// pointer's provenance and must contain no Rust references: Linux may
    /// replace it. There must be no Rust references into the old range either.
    /// The caller must ensure that neither range calculation wraps. After a
    /// successful call, both the old mapping and any destination mapping
    /// replaced by Linux are invalid; only the returned address may be used.
    /// If the call fails, the old mapping remains available for cleanup.
    #[inline]
    pub unsafe fn mremap_fixed_raw(
        address: *mut u8,
        old_length: usize,
        new_length: usize,
        flags: u32,
        new_address: *mut u8,
    ) -> Result<*mut u8> {
        // SAFETY: The caller owns both mapping lifetime/provenance contracts;
        // Linux validates the fixed destination and mapping overlap rules.
        decode(unsafe {
            syscall5(
                SYS_MREMAP,
                address as usize,
                old_length,
                new_length,
                (flags | MREMAP_FIXED) as usize,
                new_address as usize,
            )
        })
        .map(|address| address as *mut u8)
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

    /// Locks a mapped range into memory with Linux `mlock`.
    ///
    /// Linux rounds the range down/up to page boundaries. This is a direct
    /// Linux/AArch64 syscall and does not use libc or thread-local `errno`.
    ///
    /// # Safety
    ///
    /// The range beginning at `address`, rounded down to the applicable page
    /// boundary and extending for `length` bytes rounded up to a page
    /// boundary, must remain mapped and readable for the duration of the
    /// call. The rounded address range must not overflow. The caller must
    /// preserve pointer provenance and Rust reference invariants for the
    /// mapped range.
    #[inline]
    pub unsafe fn mlock_raw(address: *mut u8, length: usize) -> Result<()> {
        // SAFETY: The caller owns the mapped-range and provenance contract;
        // Linux validates the address, range, and process memlock limit.
        decode(unsafe { syscall2(SYS_MLOCK, address as usize, length) }).map(|_| ())
    }

    /// Locks a mapped range into memory with Linux `mlock2` flags.
    ///
    /// `flags` is the Linux `MLOCK_*` bit set. The supported
    /// `MLOCK_ONFAULT` bit requests that pages be locked when they are first
    /// faulted instead of immediately. This is a direct Linux/AArch64 syscall
    /// and does not use libc or thread-local `errno`.
    ///
    /// # Safety
    ///
    /// The range beginning at `address`, rounded down to the applicable page
    /// boundary and extending for `length` bytes rounded up to a page
    /// boundary, must remain mapped and readable for the duration of the
    /// call. The rounded address range must not overflow. The caller must
    /// preserve pointer provenance and Rust reference invariants for the
    /// mapped range. Unsupported flag bits are reported by Linux as an
    /// error.
    #[inline]
    pub unsafe fn mlock2_raw(address: *mut u8, length: usize, flags: u32) -> Result<()> {
        // SAFETY: The caller owns the mapped-range and provenance contract;
        // Linux validates the address, range, flags, and memlock limit.
        decode(unsafe { syscall3(SYS_MLOCK2, address as usize, length, flags as usize) })
            .map(|_| ())
    }

    /// Unlocks a previously locked mapped range with Linux `munlock`.
    ///
    /// Linux rounds the range down/up to page boundaries. This is a direct
    /// Linux/AArch64 syscall and does not use libc or thread-local `errno`.
    ///
    /// # Safety
    ///
    /// The range beginning at `address`, rounded down to the applicable page
    /// boundary and extending for `length` bytes rounded up to a page
    /// boundary, must remain mapped for the duration of the call. The rounded
    /// address range must not overflow. The caller must preserve pointer
    /// provenance and Rust reference invariants for the mapped range.
    #[inline]
    pub unsafe fn munlock_raw(address: *mut u8, length: usize) -> Result<()> {
        // SAFETY: The caller owns the mapped-range and provenance contract;
        // Linux validates the address and range.
        decode(unsafe { syscall2(SYS_MUNLOCK, address as usize, length) }).map(|_| ())
    }

    /// Synchronizes a mapped range with its backing storage.
    ///
    /// This is the Linux/AArch64 `msync` syscall directly; it does not use
    /// libc or thread-local `errno`.
    ///
    /// # Safety
    ///
    /// `address` must be page-aligned and identify a valid mapped range of
    /// `length` bytes. `length` must be non-zero, and the mapping must remain
    /// valid for the duration of the call. The caller must preserve pointer
    /// provenance and Rust reference invariants across an operation which may
    /// write mapped contents back to its backing storage or invalidate cached
    /// data. `flags` must contain a Linux-supported synchronization mode;
    /// invalid combinations are reported by the kernel as [`Errno::INVAL`].
    #[inline]
    pub unsafe fn msync_raw(address: *mut u8, length: usize, flags: u32) -> Result<()> {
        // SAFETY: The caller owns the mapped-range and provenance contracts;
        // Linux validates the synchronization flags and mapping.
        decode(unsafe { syscall3(SYS_MSYNC, address as usize, length, flags as usize) })
            .map(|_| ())
    }

    /// Advises Linux about access to a mapped range.
    ///
    /// # Safety
    ///
    /// `address` must be page-aligned and identify the first byte of a valid
    /// mapped range. `length` must be non-zero, and `address..address+length`
    /// must not overflow and must remain mapped for the duration of the call.
    /// The caller must preserve pointer provenance and Rust reference
    /// invariants across advice that can discard or alter page contents, such
    /// as `MADV_DONTNEED`. Linux rounds the final partial page as specified by
    /// the kernel ABI.
    #[inline]
    pub unsafe fn madvise_raw(address: *mut u8, length: usize, advice: u32) -> Result<()> {
        // SAFETY: The caller owns the mapped-range and provenance contracts;
        // Linux validates the advice value and mapping.
        decode(unsafe { syscall3(SYS_MADVISE, address as usize, length, advice as usize) })
            .map(|_| ())
    }

    /// Applies a POSIX memory-access advisory through Linux's `madvise` ABI.
    ///
    /// The syscall is shared with [`madvise_raw`], but this separate seam is
    /// intentional: POSIX `DONTNEED` has advisory semantics and must not be
    /// confused with Linux's page-discarding `MADV_DONTNEED` policy in a
    /// higher-level facade.
    ///
    /// # Safety
    ///
    /// `address..address+length` must satisfy the Linux advisory syscall's
    /// mapped-range and pointer-validity requirements.
    #[inline]
    pub unsafe fn posix_madvise_raw(
        address: *mut u8,
        length: usize,
        advice: u32,
    ) -> Result<()> {
        // musl's POSIX_MADV_DONTNEED is intentionally a no-op on Linux:
        // issuing Linux MADV_DONTNEED here would discard private anonymous
        // contents and would silently change the POSIX contract.
        if advice == 4 {
            let _ = (address, length);
            return Ok(());
        }
        // SAFETY: The caller owns the mapped-range contract. Linux validates
        // the POSIX advice value and reports invalid values as EINVAL.
        decode(unsafe { syscall3(SYS_MADVISE, address as usize, length, advice as usize) })
            .map(|_| ())
    }

    /// Locks all current/future mappings in the calling process.
    ///
    /// This operation changes process-global VM policy.  It is kept as a
    /// direct raw seam so the native facade can expose that scope explicitly;
    /// no C allocator or thread-local error state is involved.
    #[inline]
    pub fn mlockall_raw(flags: u32) -> Result<()> {
        // SAFETY: `flags` is an immediate Linux bit mask; Linux validates the
        // combinations and process memlock limit.
        decode(unsafe { super::syscall1(SYS_MLOCKALL, flags as usize) }).map(|_| ())
    }

    /// Removes all process-wide memory-lock policy.
    #[inline]
    pub fn munlockall_raw() -> Result<()> {
        // SAFETY: The syscall has no pointer arguments and Linux validates the
        // calling process state.
        decode(unsafe { super::syscall0(SYS_MUNLOCKALL) }).map(|_| ())
    }

    /// Re-maps pages in a legacy file mapping through Linux's
    /// `remap_file_pages` syscall.
    ///
    /// The protection and flags words are deliberately fixed to zero at this
    /// native boundary.  They are C ABI compatibility fields rather than a
    /// Rust policy surface for this legacy operation.
    ///
    /// # Safety
    ///
    /// The caller must provide the page-aligned mapped range and file-page
    /// offset required by Linux, and must not retain Rust references whose
    /// interpretation changes when the mapping is re-arranged.
    #[inline]
    pub unsafe fn remap_file_pages_raw(
        address: *mut u8,
        size: usize,
        page_offset: usize,
    ) -> Result<()> {
        // SAFETY: The caller owns the mapping and pointer-lifetime contract;
        // Linux validates the legacy remapping request.
        decode(unsafe {
            syscall5(
                SYS_REMAP_FILE_PAGES,
                address as usize,
                size,
                0,
                page_offset,
                0,
            )
        })
        .map(|_| ())
    }

    /// Queries Linux page residency for a mapped range.
    ///
    /// Linux writes one byte per page of the range to `vector`; bit zero is
    /// set when that page is resident and the remaining bits are unspecified.
    /// The direct AArch64 syscall is number 232 and returns no count on
    /// success.
    ///
    /// # Safety
    ///
    /// `address` must be page-aligned and identify the first byte of a range
    /// which remains mapped for the duration of the call. `length` must not
    /// make `address..address+length` wrap. `vector` must be writable for the
    /// kernel's page count, namely `ceil(length / page_size)` bytes, and must
    /// remain valid for that duration. The caller must keep this output
    /// storage disjoint from the mapping being queried. A null `vector` is
    /// permitted only when the kernel page count is zero.
    #[inline]
    pub unsafe fn mincore_raw(
        address: *mut u8,
        length: usize,
        vector: *mut u8,
    ) -> Result<()> {
        // SAFETY: The caller supplies the mapped-range and output-vector
        // validity contracts; Linux validates the address and range.
        decode(unsafe { syscall3(SYS_MINCORE, address as usize, length, vector as usize) })
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
        decode, decode_i32, decode_i64, syscall0, syscall1, syscall2, syscall3, syscall4, syscall5,
        CStr, MaybeUninit, RawFd,
        Result,
        SYS_CLONE, SYS_EXECVE, SYS_EXIT_GROUP, SYS_GETGROUPS, SYS_GETPGID, SYS_GETPID, SYS_GETPPID,
        SYS_GETRESGID, SYS_GETRESUID, SYS_GETEGID, SYS_GETEUID, SYS_GETGID, SYS_GETSID,
        SYS_GETPRIORITY, SYS_SETPRIORITY, SYS_GETRUSAGE, SYS_GETUID, SYS_GETCWD, SYS_CHDIR, SYS_FCHDIR,
        SYS_CHROOT,
        SYS_SETFSUID, SYS_SETFSGID,
        SYS_UMASK,
        SYS_KILL, SYS_PIDFD_OPEN, SYS_PRLIMIT64, SYS_SCHED_GET_PRIORITY_MAX, SYS_SCHED_GET_PRIORITY_MIN,
        SYS_TIMES,
        SYS_SETPGID, SYS_SETSID, SYS_TGKILL, SYS_WAIT4, SYS_WAITID,
        SYS_BRK,
    };

    /// Queries or requests Linux's current program break.
    ///
    /// Linux's `brk` syscall does not use the ordinary `-errno` return
    /// convention: it returns the resulting current break, including the
    /// unchanged break when a requested increase cannot be satisfied.  The
    /// C `brk` and `sbrk` adapters compare this value with their request and
    /// provide their respective sentinel/`errno` contracts.  Native callers
    /// receive the kernel value directly and must perform any policy or
    /// comparison themselves.
    ///
    /// # Safety
    ///
    /// `address` is passed directly to Linux.  It may be null to query the
    /// current break; otherwise the caller must obey the Linux program-break
    /// address contract and coordinate with any allocator owning the heap.
    #[inline]
    pub unsafe fn brk_raw(address: *mut u8) -> *mut u8 {
        // SAFETY: The caller owns the Linux program-break contract.  Unlike
        // ordinary syscalls, `brk` returns a valid pointer on allocation
        // failure rather than a negative errno encoding.
        unsafe { syscall1(SYS_BRK, address as usize) as usize as *mut u8 }
    }

    /// Opens a Linux process file descriptor through `pidfd_open`.
    ///
    /// `pid` is a non-zero Linux process or thread ID and `flags` retains the
    /// kernel's `PIDFD_*` bit representation. Linux validates unknown flags
    /// and target lifetime; those errors remain ordinary [`Errno`] values.
    #[inline]
    pub fn pidfd_open_raw(pid: i32, flags: u32) -> Result<RawFd> {
        // SAFETY: Both arguments are immediate Linux/AArch64 syscall values.
        // A successful pidfd_open result is a newly allocated descriptor.
        decode_i32(unsafe { syscall2(SYS_PIDFD_OPEN, pid as usize, flags as usize) })
    }

    /// The Linux/AArch64 `struct rlimit64` returned by `prlimit64`.
    ///
    /// This is the exact two-word kernel ABI record. It remains separate from
    /// the safe facade's infinity-aware `Rlimit` mapping.
    #[repr(C)]
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub struct KernelRlimit64 {
        /// Soft/current limit, or Linux `RLIM64_INFINITY`.
        pub rlim_cur: u64,
        /// Hard/maximum limit, or Linux `RLIM64_INFINITY`.
        pub rlim_max: u64,
    }

    /// Reads one target process's resource limit through Linux `prlimit64`
    /// without libc or TLS `errno`.
    ///
    /// This is a raw core seam: `pid` is the Linux `pid_t` selector and
    /// `resource` is the Linux `RLIMIT_*` number. PID zero asks the kernel for
    /// the calling process; null `new_limit` makes this query read-only. The
    /// public facade supplies the typed process and resource vocabulary.
    #[inline]
    pub fn getrlimit_for_raw(pid: i32, resource: u32) -> Result<KernelRlimit64> {
        let mut result = MaybeUninit::<KernelRlimit64>::uninit();
        // SAFETY: Linux writes the complete `rlimit64` record on success;
        // `new_limit = NULL` makes this a read-only query and the output
        // storage remains live for the syscall.
        decode(unsafe {
            syscall4(
                SYS_PRLIMIT64,
                pid as usize,
                resource as usize,
                0,
                result.as_mut_ptr() as usize,
            )
        })?;
        // SAFETY: Successful prlimit64 initialized both ABI words above.
        Ok(unsafe { result.assume_init() })
    }

    /// Reads the calling process's resource limit through Linux `prlimit64`.
    #[inline]
    pub fn getrlimit_raw(resource: u32) -> Result<KernelRlimit64> {
        getrlimit_for_raw(0, resource)
    }

    /// Changes the calling process's resource limit through Linux `prlimit64`.
    ///
    /// This core seam deliberately targets PID zero, passes a fully
    /// initialized kernel `rlimit64`, and requests no old-limit output. The
    /// typed facade performs any infinity/value validation before crossing
    /// this boundary.
    #[inline]
    pub fn setrlimit_raw(resource: u32, limit: &KernelRlimit64) -> Result<()> {
        // SAFETY: `limit` remains readable for this syscall and is an exact
        // Linux/AArch64 `struct rlimit64` record.
        decode(unsafe {
            syscall4(
                SYS_PRLIMIT64,
                0,
                resource as usize,
                limit as *const KernelRlimit64 as usize,
                0,
            )
        })
        .map(|_| ())
    }

    /// Changes the calling process's file-creation mask and returns the old
    /// mask. Linux's `umask` syscall always returns the previous mask.
    #[inline]
    pub fn umask_raw(mask: u32) -> u32 {
        // SAFETY: `mask` is an immediate Linux mode word and the syscall's
        // return value is the previous mask rather than an errno encoding.
        unsafe { syscall1(SYS_UMASK, mask as usize) as u32 }
    }

    /// One Linux/AArch64 `struct timeval` as embedded in `struct rusage`.
    ///
    /// The pinned musl target uses 64-bit `time_t` and `suseconds_t`, and the
    /// Linux kernel ABI uses the same two signed 64-bit words for its old
    /// timeval record. This is the kernel record only; it is not a public C
    /// `timeval` alias.
    #[repr(C)]
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub struct KernelRusageTimeval {
        /// Whole seconds of CPU time.
        pub tv_sec: i64,
        /// Microseconds within the second.
        pub tv_usec: i64,
    }

    /// The initialized Linux/AArch64 portion of `struct rusage`.
    ///
    /// Linux's `getrusage` syscall writes these 144 bytes: two old timeval
    /// records followed by fourteen signed `long` counters. Musl's public
    /// `struct rusage` appends sixteen reserved `long` words for source
    /// compatibility; the kernel does not initialize that tail, so this
    /// direct seam deliberately omits it. The native facade exposes only the
    /// named initialized observations below.
    #[repr(C)]
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub struct KernelRusage {
        /// User CPU time.
        pub ru_utime: KernelRusageTimeval,
        /// System CPU time.
        pub ru_stime: KernelRusageTimeval,
        /// Maximum resident-set size in KiB on Linux.
        pub ru_maxrss: i64,
        /// Integral shared-memory size (historical Linux field).
        pub ru_ixrss: i64,
        /// Integral unshared-data size (historical Linux field).
        pub ru_idrss: i64,
        /// Integral unshared-stack size (historical Linux field).
        pub ru_isrss: i64,
        /// Number of minor page faults.
        pub ru_minflt: i64,
        /// Number of major page faults.
        pub ru_majflt: i64,
        /// Number of swaps (historical Linux field).
        pub ru_nswap: i64,
        /// Block input operations.
        pub ru_inblock: i64,
        /// Block output operations.
        pub ru_oublock: i64,
        /// IPC messages sent (historical Linux field).
        pub ru_msgsnd: i64,
        /// IPC messages received (historical Linux field).
        pub ru_msgrcv: i64,
        /// Signals received (historical Linux field).
        pub ru_nsignals: i64,
        /// Voluntary context switches.
        pub ru_nvcsw: i64,
        /// Involuntary context switches.
        pub ru_nivcsw: i64,
    }

    /// Reads one Linux resource-usage record through `getrusage`.
    ///
    /// `who` is the raw Linux `RUSAGE_*` selector. The typed facade supplies
    /// the closed selector vocabulary; this core seam keeps the kernel token
    /// explicit and does not accept a caller-provided output pointer. Linux
    /// initializes only [`KernelRusage`]'s 144-byte record; the reserved tail
    /// present in musl's public C struct is intentionally not represented.
    #[inline]
    pub fn getrusage_raw(who: i32) -> Result<KernelRusage> {
        let mut result = MaybeUninit::<KernelRusage>::uninit();
        // SAFETY: `result` is writable storage for exactly the initialized
        // Linux/AArch64 getrusage record, and Linux writes all fields on a
        // successful call. `who` is an immediate selector value.
        decode(unsafe {
            syscall2(
                SYS_GETRUSAGE,
                who as usize,
                result.as_mut_ptr() as usize,
            )
        })?;
        // SAFETY: Successful getrusage initialized every field in the
        // kernel-sized record above; no reserved musl tail is read.
        Ok(unsafe { result.assume_init() })
    }

    /// The four initialized Linux/AArch64 words written by `times(2)`.
    ///
    /// Linux's native `struct tms` uses four signed 64-bit `clock_t` words on
    /// AArch64. This is an internal kernel record rather than a public C ABI
    /// type; the native facade validates the non-negative process-accounting
    /// values before exposing them as Rust tick values.
    #[repr(C)]
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub struct KernelProcessTimes {
        /// User CPU time consumed by the calling process, in clock ticks.
        pub user_ticks: i64,
        /// System CPU time consumed by the calling process, in clock ticks.
        pub system_ticks: i64,
        /// User CPU time of waited-for terminated children, in clock ticks.
        pub children_user_ticks: i64,
        /// System CPU time of waited-for terminated children, in clock ticks.
        pub children_system_ticks: i64,
    }

    /// The process-accounting record and independent elapsed-tick result of
    /// one Linux `times(2)` query.
    ///
    /// Linux's syscall return is not another `struct tms` field: it is the
    /// number of clock ticks since a kernel-defined arbitrary point. It is
    /// retained separately so callers cannot confuse elapsed system ticks
    /// with this process's CPU-accounting fields.
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub struct KernelProcessTimesObservation {
        /// The four words written to the caller's `struct tms` storage.
        pub process: KernelProcessTimes,
        /// The syscall's independent elapsed-tick return value.
        pub elapsed_ticks: i64,
    }

    /// Reads Linux process accounting through the native `times` syscall.
    ///
    /// A caller-owned pointer is deliberately not exposed here: this seam
    /// provides private initialized storage for the exact AArch64 record and
    /// returns it by value. The kernel's signed `clock_t` return is decoded as
    /// an ordinary syscall result; the four process-accounting words are
    /// checked for their documented non-negative range. No C ABI, allocator,
    /// vDSO, or TLS `errno` is involved.
    #[inline]
    pub fn times_raw() -> Result<KernelProcessTimesObservation> {
        let mut process = MaybeUninit::<KernelProcessTimes>::uninit();
        // SAFETY: `process` is writable storage for Linux/AArch64's exact
        // four-word `struct tms`; the kernel initializes all words on success.
        let elapsed_ticks = decode_i64(unsafe {
            syscall1(SYS_TIMES, process.as_mut_ptr() as usize)
        })?;
        // SAFETY: A successful times syscall initializes all four words.
        let process = unsafe { process.assume_init() };
        if process.user_ticks < 0
            || process.system_ticks < 0
            || process.children_user_ticks < 0
            || process.children_system_ticks < 0
        {
            // A conforming Linux kernel reports non-negative process times;
            // never reinterpret a malformed record as a valid Rust value.
            return Err(super::Errno::RANGE);
        }
        Ok(KernelProcessTimesObservation {
            process,
            elapsed_ticks,
        })
    }

    /// Reads one Linux scheduling-priority observation through the native
    /// `getpriority` syscall.
    ///
    /// Linux deliberately does not return the usual nice value here. To keep
    /// every successful result non-negative, the kernel encodes nice values
    /// `[-20, 19]` as `[(19 - nice) + 1]`, or `[40, 1]`; musl and Rustix both
    /// translate that value with `20 - raw`. This core seam preserves the
    /// kernel's encoded success value so the native facade can make that
    /// translation at its typed boundary. A negative syscall result in
    /// Linux's `-errno` range is decoded into the ordinary [`Errno`] result.
    #[inline]
    pub fn getpriority_raw(which: i32, who: u32) -> Result<i32> {
        // SAFETY: `which` and `who` are immediate Linux scalar arguments. The
        // public facade supplies the closed selector and identifier types.
        decode_i32(unsafe { syscall2(SYS_GETPRIORITY, which as usize, who as usize) })
    }

    /// Reads one Linux scheduler policy's maximum and minimum priority.
    ///
    /// The raw policy remains an integer so Linux can report `EINVAL`; the
    /// native facade supplies its closed policy vocabulary and validates the
    /// returned ordering. The two calls are read-only scalar observations.
    #[inline]
    pub fn scheduler_priority_bounds_raw(policy: i32) -> Result<(i32, i32)> {
        let maximum = decode_i32(unsafe {
            syscall1(SYS_SCHED_GET_PRIORITY_MAX, policy as usize)
        })?;
        let minimum = decode_i32(unsafe {
            syscall1(SYS_SCHED_GET_PRIORITY_MIN, policy as usize)
        })?;
        Ok((minimum, maximum))
    }

    /// Sets one Linux scheduling-priority target through `setpriority`.
    ///
    /// `which` and `who` retain the Linux `PRIO_*` selector encoding while the
    /// native facade supplies the closed target and priority types. Kernel
    /// permission and target errors remain ordinary [`Errno`] values; this
    /// seam does not translate through libc's TLS `errno` channel.
    #[inline]
    pub fn setpriority_raw(which: i32, who: u32, priority: i32) -> Result<()> {
        // SAFETY: All arguments are immediate Linux scalar values.
        decode(unsafe {
            syscall3(
                SYS_SETPRIORITY,
                which as usize,
                who as usize,
                priority as usize,
            )
        })
        .map(|_| ())
    }

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

    /// The Linux real, effective, and saved user IDs returned by
    /// `getresuid`.
    #[repr(C)]
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub struct KernelUidTriple {
        /// The process's real user ID.
        pub real: u32,
        /// The process's effective user ID.
        pub effective: u32,
        /// The process's saved-set user ID.
        pub saved: u32,
    }

    /// The Linux real, effective, and saved group IDs returned by
    /// `getresgid`.
    #[repr(C)]
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub struct KernelGidTriple {
        /// The process's real group ID.
        pub real: u32,
        /// The process's effective group ID.
        pub effective: u32,
        /// The process's saved-set group ID.
        pub saved: u32,
    }

    /// Reads the calling process's real, effective, and saved user IDs
    /// through Linux's native `getresuid` syscall.
    ///
    /// The output pointers are private caller-owned storage, so this seam is
    /// read-only and does not expose C ABI pointers or TLS `errno` semantics.
    #[inline]
    pub fn getresuid_raw() -> Result<KernelUidTriple> {
        let mut real = MaybeUninit::<u32>::uninit();
        let mut effective = MaybeUninit::<u32>::uninit();
        let mut saved = MaybeUninit::<u32>::uninit();
        // SAFETY: Each pointer addresses live, writable storage for one
        // Linux/AArch64 uid_t, and Linux initializes all three words on
        // success. The syscall has no process-mutating arguments.
        decode(unsafe {
            syscall3(
                SYS_GETRESUID,
                real.as_mut_ptr() as usize,
                effective.as_mut_ptr() as usize,
                saved.as_mut_ptr() as usize,
            )
        })?;
        // SAFETY: Successful getresuid initialized each output above.
        Ok(KernelUidTriple {
            real: unsafe { real.assume_init() },
            effective: unsafe { effective.assume_init() },
            saved: unsafe { saved.assume_init() },
        })
    }

    /// Reads the calling process's real, effective, and saved group IDs
    /// through Linux's native `getresgid` syscall.
    ///
    /// The output pointers are private caller-owned storage, so this seam is
    /// read-only and does not expose C ABI pointers or TLS `errno` semantics.
    #[inline]
    pub fn getresgid_raw() -> Result<KernelGidTriple> {
        let mut real = MaybeUninit::<u32>::uninit();
        let mut effective = MaybeUninit::<u32>::uninit();
        let mut saved = MaybeUninit::<u32>::uninit();
        // SAFETY: Each pointer addresses live, writable storage for one
        // Linux/AArch64 gid_t, and Linux initializes all three words on
        // success. The syscall has no process-mutating arguments.
        decode(unsafe {
            syscall3(
                SYS_GETRESGID,
                real.as_mut_ptr() as usize,
                effective.as_mut_ptr() as usize,
                saved.as_mut_ptr() as usize,
            )
        })?;
        // SAFETY: Successful getresgid initialized each output above.
        Ok(KernelGidTriple {
            real: unsafe { real.assume_init() },
            effective: unsafe { effective.assume_init() },
            saved: unsafe { saved.assume_init() },
        })
    }

    /// Sets or queries the calling task's Linux filesystem user ID through
    /// `setfsuid`.
    ///
    /// Linux returns the previous filesystem user ID on both a successful and
    /// an unsuccessful requested change. The all-ones input is the kernel's
    /// query form and is therefore retained by this raw seam; the typed
    /// facade owns its `Option<Uid>` conversion and rejects an explicit
    /// all-ones value before reaching the syscall.
    #[inline]
    pub fn setfsuid_raw(uid: u32) -> Result<u32> {
        // SAFETY: `uid` is an immediate Linux uid_t word. Linux applies this
        // credential operation to the calling kernel task and returns the
        // previous filesystem UID as a scalar.
        decode(unsafe { syscall1(SYS_SETFSUID, uid as usize) }).map(|previous| previous as u32)
    }

    /// Sets or queries the calling task's Linux filesystem group ID through
    /// `setfsgid`.
    ///
    /// Linux returns the previous filesystem group ID on both a successful and
    /// an unsuccessful requested change. The all-ones input is the kernel's
    /// query form and is therefore retained by this raw seam; the typed
    /// facade owns its `Option<Gid>` conversion and rejects an explicit
    /// all-ones value before reaching the syscall.
    #[inline]
    pub fn setfsgid_raw(gid: u32) -> Result<u32> {
        // SAFETY: `gid` is an immediate Linux gid_t word. Linux applies this
        // credential operation to the calling kernel task and returns the
        // previous filesystem GID as a scalar.
        decode(unsafe { syscall1(SYS_SETFSGID, gid as usize) }).map(|previous| previous as u32)
    }

    /// Queries or fills the calling process's supplementary group IDs through
    /// Linux's native `getgroups` syscall.
    ///
    /// `groups` must be null when `length` is zero, which performs the Linux
    /// count query. Otherwise it must point to writable storage for `length`
    /// Linux/AArch64 `gid_t` values. Linux returns `EINVAL` when the storage
    /// is too small; the caller may query again and retry because credentials
    /// can change between the two syscalls.
    ///
    /// # Safety
    ///
    /// When `length` is non-zero, `groups` must be aligned and writable for
    /// `length` `u32` values for the duration of the call. When `length` is
    /// zero, `groups` must be null. The pointed-to storage is initialized only
    /// for the number of groups returned by a successful fill.
    #[inline]
    pub unsafe fn getgroups_raw(groups: *mut u32, length: usize) -> Result<usize> {
        // SAFETY: The caller supplies the output-storage contract; Linux
        // validates the requested count and supplementary-group snapshot.
        decode(unsafe { syscall2(SYS_GETGROUPS, length, groups as usize) })
    }

    /// Queries the current number of supplementary group IDs.
    #[inline]
    pub fn getgroups_count_raw() -> Result<usize> {
        // SAFETY: A zero-size Linux getgroups query requires a null list and
        // writes no caller memory.
        unsafe { getgroups_raw(core::ptr::null_mut(), 0) }
    }

    /// Copies the calling process's current working directory through Linux's
    /// native `getcwd` syscall.
    ///
    /// On success Linux initializes exactly the returned number of bytes and
    /// includes the terminating NUL in that count. The caller must provide
    /// writable storage for `length` bytes; the path pointer may be null only
    /// when `length` is zero. A successful call always writes a NUL at the end
    /// of the initialized prefix. Linux reports [`Errno::RANGE`] when the
    /// supplied storage is too small.
    ///
    /// # Safety
    ///
    /// When `length` is non-zero, `buffer` must be aligned and writable for
    /// `length` bytes for the duration of this call. A successful call
    /// initializes only the returned prefix, including its trailing NUL.
    #[inline]
    pub unsafe fn getcwd_raw(buffer: *mut u8, length: usize) -> Result<usize> {
        // SAFETY: The caller supplies writable output storage for the exact
        // requested length; Linux validates the pathname and size.
        decode(unsafe { syscall2(SYS_GETCWD, buffer as usize, length) })
    }

    /// Changes the calling process's current working directory through
    /// Linux's native `chdir` syscall.
    ///
    /// The CWD is process-global on Linux. This direct seam performs no
    /// synchronization, and callers must coordinate concurrent pathname work
    /// when using it through a native facade.
    #[inline]
    pub fn chdir(path: &CStr) -> Result<()> {
        // SAFETY: `CStr` keeps a readable, NUL-terminated pathname alive for
        // the syscall; Linux validates the path and directory permissions.
        decode(unsafe { syscall1(SYS_CHDIR, path.as_ptr() as usize) }).map(|_| ())
    }

    /// Changes the calling process's current working directory to the
    /// directory referenced by `fd` through Linux's native `fchdir` syscall.
    ///
    /// The CWD is process-global on Linux. This direct seam performs no
    /// synchronization, and callers must coordinate concurrent pathname work
    /// when using it through a native facade.
    #[inline]
    pub fn fchdir(fd: RawFd) -> Result<()> {
        // SAFETY: The descriptor is an immediate scalar; Linux validates that
        // it is open and references a directory accessible to the caller.
        decode(unsafe { syscall1(SYS_FCHDIR, fd as usize) }).map(|_| ())
    }

    /// Changes the calling process's root directory through Linux's native
    /// `chroot` syscall.
    ///
    /// This direct seam reports the kernel's permission, pathname, and
    /// filesystem errors as [`Errno`] values. It does not change the current
    /// working directory, and it does not close or otherwise preserve any
    /// descriptor the caller may need after the root change.
    #[inline]
    pub fn chroot(path: &CStr) -> Result<()> {
        // SAFETY: `CStr` keeps a readable, NUL-terminated pathname alive for
        // the syscall; Linux validates the path and caller privilege.
        decode(unsafe { syscall1(SYS_CHROOT, path.as_ptr() as usize) }).map(|_| ())
    }

    /// Returns the caller's real Linux user ID.
    #[inline]
    pub fn getuid() -> u32 {
        // Linux guarantees that `getuid` succeeds and returns a `uid_t`.
        unsafe { syscall0(SYS_GETUID) as u32 }
    }

    /// Returns the caller's effective Linux user ID.
    #[inline]
    pub fn geteuid() -> u32 {
        // Linux guarantees that `geteuid` succeeds and returns a `uid_t`.
        unsafe { syscall0(SYS_GETEUID) as u32 }
    }

    /// Returns the caller's real Linux group ID.
    #[inline]
    pub fn getgid() -> u32 {
        // Linux guarantees that `getgid` succeeds and returns a `gid_t`.
        unsafe { syscall0(SYS_GETGID) as u32 }
    }

    /// Returns the caller's effective Linux group ID.
    #[inline]
    pub fn getegid() -> u32 {
        // Linux guarantees that `getegid` succeeds and returns a `gid_t`.
        unsafe { syscall0(SYS_GETEGID) as u32 }
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
    use super::{
        decode, syscall0, syscall2, syscall3, syscall6, Result, SYS_FUTEX, SYS_GETCPU,
        SYS_GETTID, SYS_SCHED_GETAFFINITY, SYS_SCHED_RR_GET_INTERVAL, SYS_SCHED_SETAFFINITY,
        SYS_SCHED_YIELD, SYS_SETRESGID, SYS_SETRESUID,
    };
    use core::mem::MaybeUninit;

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

    /// Sets the calling task's real, effective, and saved user IDs through
    /// Linux's native `setresuid` syscall.
    ///
    /// The Linux all-ones word (`u32::MAX`) means “leave this ID unchanged.”
    /// This raw seam accepts that kernel ABI word directly; the typed native
    /// facade owns the `Option<Uid>` conversion and rejects an explicit typed
    /// all-ones value before reaching this syscall.
    #[inline]
    pub fn setresuid_raw(ruid: u32, euid: u32, suid: u32) -> Result<()> {
        // SAFETY: All arguments are immediate Linux uid_t words. Linux
        // applies the credential change to the calling kernel task only.
        decode(unsafe {
            syscall3(
                SYS_SETRESUID,
                ruid as usize,
                euid as usize,
                suid as usize,
            )
        })
        .map(|_| ())
    }

    /// Sets the calling task's real, effective, and saved group IDs through
    /// Linux's native `setresgid` syscall.
    ///
    /// The Linux all-ones word (`u32::MAX`) means “leave this ID unchanged.”
    /// This raw seam accepts that kernel ABI word directly; the typed native
    /// facade owns the `Option<Gid>` conversion and rejects an explicit typed
    /// all-ones value before reaching this syscall.
    #[inline]
    pub fn setresgid_raw(rgid: u32, egid: u32, sgid: u32) -> Result<()> {
        // SAFETY: All arguments are immediate Linux gid_t words. Linux
        // applies the credential change to the calling kernel task only.
        decode(unsafe {
            syscall3(
                SYS_SETRESGID,
                rgid as usize,
                egid as usize,
                sgid as usize,
            )
        })
        .map(|_| ())
    }

    /// Returns the Linux CPU on which the calling thread is currently running.
    ///
    /// The Linux/AArch64 `getcpu` syscall writes a `u32` CPU identifier through
    /// its first argument. The output points at private stack storage for the
    /// complete syscall, while the node and cache arguments are deliberately
    /// null because this API observes only the CPU. Rustix exposes this
    /// operation as an infallible `usize`; Linux reports `EFAULT` only when an
    /// output pointer is invalid, which the local storage contract rules out.
    #[inline]
    pub fn sched_getcpu() -> usize {
        let mut cpu = MaybeUninit::<u32>::uninit();
        match decode(unsafe {
            syscall3(
                SYS_GETCPU,
                cpu.as_mut_ptr() as usize,
                core::ptr::null::<u32>() as usize,
                core::ptr::null::<u8>() as usize,
            )
        }) {
            Ok(_) => {
                // SAFETY: A successful Linux `getcpu` initializes the caller's
                // `u32` output before returning.
                unsafe { cpu.assume_init() as usize }
            }
            Err(_) => {
                // The documented failure requires an invalid output pointer;
                // this function owns valid stack storage, so do not fabricate
                // a CPU number or expose a C-style error channel here.
                panic!("Linux getcpu syscall failed")
            }
        }
    }

    /// Reads a Linux task's round-robin scheduling interval.
    ///
    /// This is the raw kernel seam for `sched_rr_get_interval`; the native
    /// facade owns the output storage and validates the returned timespec.
    /// Linux PID zero selects the calling task.
    ///
    /// # Safety
    ///
    /// `interval` must point to writable Linux/AArch64 `struct timespec`
    /// storage for the duration of the syscall.
    #[inline]
    pub unsafe fn sched_rr_get_interval_raw(pid: i32, interval: *mut u8) -> Result<()> {
        // SAFETY: The caller supplies writable timespec storage; `pid` and
        // the pointer are immediate Linux syscall arguments.
        decode(unsafe {
            syscall2(
                SYS_SCHED_RR_GET_INTERVAL,
                pid as usize,
                interval as usize,
            )
        })
        .map(|_| ())
    }

    /// Reads a Linux task's CPU-affinity mask.
    ///
    /// The raw syscall returns the number of bytes written. The native facade
    /// supplies the fixed target mask capacity and clears any unwritten tail.
    /// Linux reports `EINVAL` when that capacity is smaller than the kernel's
    /// affinity mask; this seam preserves that error unchanged.
    ///
    /// # Safety
    ///
    /// `mask` must point to writable storage for `size` bytes for the duration
    /// of the syscall. Linux PID zero selects the calling task.
    #[inline]
    pub unsafe fn sched_getaffinity_raw(
        pid: i32,
        mask: *mut u8,
        size: usize,
    ) -> Result<usize> {
        // SAFETY: The caller supplies writable mask storage for `size` bytes;
        // all three values are immediate Linux syscall arguments.
        decode(unsafe {
            syscall3(
                SYS_SCHED_GETAFFINITY,
                pid as usize,
                size,
                mask as usize,
            )
        })
    }

    /// Sets a Linux task's CPU-affinity mask.
    ///
    /// Linux may intersect the requested mask with CPUs present in the
    /// system and CPUs permitted by the task's cpuset cgroup. An empty
    /// resulting mask is reported by the kernel as `EINVAL`; this seam keeps
    /// that error unchanged.
    ///
    /// # Safety
    ///
    /// `mask` must point to readable storage for `size` bytes for the
    /// duration of the syscall. Linux PID zero selects the calling task.
    #[inline]
    pub unsafe fn sched_setaffinity_raw(
        pid: i32,
        mask: *const u8,
        size: usize,
    ) -> Result<()> {
        // SAFETY: The caller supplies readable mask storage for `size` bytes;
        // all three values are immediate Linux syscall arguments.
        decode(unsafe {
            syscall3(
                SYS_SCHED_SETAFFINITY,
                pid as usize,
                size,
                mask as usize,
            )
        })
        .map(|_| ())
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

/// Direct Linux POSIX message-queue operations.
pub mod ipc {
    use super::{
        decode, decode_i32, syscall1, syscall3, syscall4, syscall5, CStr, MaybeUninit, RawFd,
        Result, SYS_MQ_GETSETATTR, SYS_MQ_OPEN, SYS_MQ_TIMEDRECEIVE, SYS_MQ_TIMEDSEND,
        SYS_MQ_UNLINK,
    };

    /// Linux/AArch64 `struct mq_attr` wire layout.
    ///
    /// The public Rust facade validates and converts these signed native-long
    /// fields before exposing them. The reserved tail is retained because the
    /// kernel copies the complete record for `mq_getsetattr`.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct KernelMqAttr {
        /// Queue status flags, currently `O_NONBLOCK`.
        pub mq_flags: i64,
        /// Maximum number of queued messages.
        pub mq_maxmsg: i64,
        /// Maximum message size in bytes.
        pub mq_msgsize: i64,
        /// Current number of queued messages.
        pub mq_curmsgs: i64,
        /// Linux ABI-reserved words.
        pub reserved: [i64; 4],
    }

    /// Linux/AArch64 `struct timespec` used by absolute mq deadlines.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct KernelMqTimespec {
        /// Seconds since the Unix epoch for `CLOCK_REALTIME` deadlines.
        pub tv_sec: i64,
        /// Nanoseconds within the second.
        pub tv_nsec: i64,
    }

    /// Opens a kernel message queue using its fixed-arity syscall ABI.
    ///
    /// `name` is the Linux kernel spelling without POSIX's required leading
    /// slash; the higher-level facade validates and performs that translation.
    /// `attr` is supplied only for creation and remains borrowed for the call.
    #[inline]
    pub fn open(
        name: &CStr,
        flags: i32,
        mode: u32,
        attr: Option<&KernelMqAttr>,
    ) -> Result<RawFd> {
        // SAFETY: `name` and the optional attribute remain live for the
        // fixed-arity syscall; all other arguments are scalar Linux values.
        decode_i32(unsafe {
            syscall4(
                SYS_MQ_OPEN,
                name.as_ptr() as usize,
                flags as usize,
                mode as usize,
                attr.map_or(0, |value| value as *const KernelMqAttr as usize),
            )
        })
    }

    /// Unlinks a kernel message-queue name.
    #[inline]
    pub fn unlink(name: &CStr) -> Result<()> {
        // SAFETY: `name` remains live for the duration of the direct syscall.
        decode(unsafe { syscall1(SYS_MQ_UNLINK, name.as_ptr() as usize) }).map(|_| ())
    }

    /// Reads or updates queue attributes through `mq_getsetattr`.
    ///
    /// Linux always writes the previous attributes to the output record on a
    /// successful call. `new_attr == None` performs a read-only query.
    #[inline]
    pub fn getsetattr(fd: RawFd, new_attr: Option<&KernelMqAttr>) -> Result<KernelMqAttr> {
        let mut old_attr = MaybeUninit::<KernelMqAttr>::uninit();
        // SAFETY: the optional input and output storage remain live for the
        // syscall; Linux initializes `old_attr` on success.
        decode(unsafe {
            syscall3(
                SYS_MQ_GETSETATTR,
                fd as usize,
                new_attr.map_or(0, |value| value as *const KernelMqAttr as usize),
                old_attr.as_mut_ptr() as usize,
            )
        })?;
        // SAFETY: Linux initialized the complete attribute record on success.
        Ok(unsafe { old_attr.assume_init() })
    }

    /// Sends one caller-borrowed message, optionally with an absolute
    /// `CLOCK_REALTIME` deadline.
    #[inline]
    pub fn timed_send(
        fd: RawFd,
        message: &[u8],
        priority: u32,
        deadline: Option<&KernelMqTimespec>,
    ) -> Result<()> {
        // SAFETY: `message` and the optional deadline remain live for the
        // syscall; Linux reads at most `message.len()` bytes.
        decode(unsafe {
            syscall5(
                SYS_MQ_TIMEDSEND,
                fd as usize,
                message.as_ptr() as usize,
                message.len(),
                priority as usize,
                deadline.map_or(0, |value| value as *const KernelMqTimespec as usize),
            )
        })
        .map(|_| ())
    }

    /// Receives one message into caller-provided storage and returns its byte
    /// length; Linux writes the message priority through `priority`.
    #[inline]
    pub fn timed_receive(
        fd: RawFd,
        buffer: &mut [u8],
        priority: &mut u32,
        deadline: Option<&KernelMqTimespec>,
    ) -> Result<usize> {
        // SAFETY: `buffer`, `priority`, and the optional deadline remain live
        // for the syscall. Linux writes no more than `buffer.len()` bytes on a
        // successful receive and initializes the priority word.
        decode(unsafe {
            syscall5(
                SYS_MQ_TIMEDRECEIVE,
                fd as usize,
                buffer.as_mut_ptr() as usize,
                buffer.len(),
                priority as *mut u32 as usize,
                deadline.map_or(0, |value| value as *const KernelMqTimespec as usize),
            )
        })
    }
}

/// Direct Linux inotify operations.
pub mod inotify {
    use super::{decode, syscall1, syscall2, syscall3, CStr, RawFd, Result,
        SYS_INOTIFY_ADD_WATCH, SYS_INOTIFY_INIT1, SYS_INOTIFY_RM_WATCH};

    /// Creates one Linux inotify descriptor without using libc or TLS
    /// `errno`.
    #[inline]
    pub fn init1(flags: u32) -> Result<RawFd> {
        // SAFETY: `inotify_init1` takes a scalar flag word and returns one
        // fresh descriptor on success; Linux validates the flags.
        decode(unsafe { syscall1(SYS_INOTIFY_INIT1, flags as usize) }).map(|fd| fd as RawFd)
    }

    /// Adds or updates an inotify watch for a live NUL-terminated pathname.
    #[inline]
    pub fn add_watch(fd: RawFd, path: &CStr, mask: u32) -> Result<i32> {
        // SAFETY: `path` supplies a readable NUL-terminated pathname for the
        // duration of the direct call; all remaining arguments are scalars.
        decode(unsafe {
            syscall3(
                SYS_INOTIFY_ADD_WATCH,
                fd as usize,
                path.as_ptr() as usize,
                mask as usize,
            )
        })
        .map(|watch| watch as i32)
    }

    /// Removes one inotify watch from an open descriptor.
    #[inline]
    pub fn rm_watch(fd: RawFd, watch: i32) -> Result<()> {
        // SAFETY: both arguments are immediate Linux scalar values.
        decode(unsafe { syscall2(SYS_INOTIFY_RM_WATCH, fd as usize, watch as usize) }).map(|_| ())
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
    use super::{decode_i32, process, system, Errno};

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
    fn resource_usage_layout_matches_linux_aarch64_initialized_prefix() {
        assert_eq!(core::mem::size_of::<process::KernelRusageTimeval>(), 16);
        assert_eq!(core::mem::size_of::<process::KernelRusage>(), 144);
    }

    #[test]
    fn ioctl_result_keeps_negative_non_errno_successes() {
        assert_eq!(decode_i32(0), Ok(0));
        assert_eq!(decode_i32(-1), Err(Errno::from_raw(1).unwrap()));
        assert_eq!(decode_i32(-4095), Err(Errno::from_raw(4095).unwrap()));
        assert_eq!(decode_i32(-4096), Ok(-4096));
    }
}
