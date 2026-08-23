//! Private, versioned wire contracts for process-singleton crabc runtimes.
//!
//! This module is data-only: libc and the dynamic linker own all runtime
//! state behind these wire values.

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
    pub loader_close: unsafe extern "C" fn(handle: *mut c_void, error: *mut TextV1) -> c_int,
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
    pub thread_join:
        unsafe extern "C" fn(handle: ThreadHandleV1, result: *mut *mut c_void) -> c_int,
    /// Detaches a libc-owned pthread handle.
    pub thread_detach: unsafe extern "C" fn(handle: ThreadHandleV1) -> c_int,
    /// Returns the current libc-owned pthread handle.
    pub thread_self: unsafe extern "C" fn(handle: *mut ThreadHandleV1) -> c_int,
    /// Requests cancellation of a libc-owned pthread. Native wrappers
    /// keep this operation unsafe because cancellation bypasses ordinary
    /// Rust destructor and lock invariants.
    pub thread_cancel: unsafe extern "C" fn(handle: ThreadHandleV1) -> c_int,
    /// Changes the current libc-owned pthread cancellation state.
    pub thread_setcancelstate: unsafe extern "C" fn(state: u32, old_state: *mut u32) -> c_int,
    /// Changes the current libc-owned pthread cancellation type.
    pub thread_setcanceltype:
        unsafe extern "C" fn(cancel_type: u32, old_type: *mut u32) -> c_int,
    /// Tests the current libc-owned pthread cancellation request.
    pub thread_testcancel: unsafe extern "C" fn(),
    /// Creates a libc-owned thread-local key. The destructor executes in
    /// libc's thread-exit cleanup path and therefore has an unsafe Rust
    /// callback contract.
    pub thread_key_create:
        unsafe extern "C" fn(key: *mut u32, destructor: Option<ThreadDestructorV1>) -> c_int,
    /// Deletes a libc-owned thread-local key.
    pub thread_key_delete: unsafe extern "C" fn(key: u32) -> c_int,
    /// Reads the current thread's value for a libc-owned key.
    pub thread_getspecific: unsafe extern "C" fn(key: u32) -> *mut c_void,
    /// Writes the current thread's value for a libc-owned key.
    pub thread_setspecific: unsafe extern "C" fn(key: u32, value: *const c_void) -> c_int,
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
    pub cfile_tell: unsafe extern "C" fn(handle: CFileHandleV1, position: *mut u64) -> c_int,
    /// Copies the end-of-file indicator as zero or one.
    pub cfile_eof: unsafe extern "C" fn(handle: CFileHandleV1, eof: *mut u8) -> c_int,
    /// Copies the stream-error indicator as zero or one.
    pub cfile_error: unsafe extern "C" fn(handle: CFileHandleV1, error: *mut u8) -> c_int,
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
