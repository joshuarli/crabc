//! Native dynamic-loading access through crabc's private runtime table.
//!
//! `libldso.so` owns the process-wide loaded-object graph, loader lock, and
//! thread-local loader diagnostics. This module therefore does not link a
//! second loader implementation and does not call public `dlopen`/`dlsym`/
//! `dlclose`/`dlerror` entry points. It obtains the versioned private runtime
//! table from `libc.so`; that table copies diagnostics and address metadata
//! into caller-owned storage before returning.

use core::ffi::{c_void, CStr};
use core::marker::PhantomData;
use core::mem::{align_of, size_of};
use core::ptr::NonNull;

use bitflags::bitflags;
use crabc_core::runtime::{LoaderAddressV1, RuntimeV1, TextV1, TEXT_CAPACITY, V1_ABI_VERSION};

bitflags! {
    /// Typed `RTLD_*` scope and resolution flags accepted by [`Library::open`].
    ///
    /// The current Linux/AArch64 loader records `GLOBAL` scope and accepts the
    /// lazy/now choice. Other platform-specific dlfcn flags are intentionally not
    /// advertised until their crabc loader semantics have native evidence.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct OpenFlags: i32 {
        /// Resolve relocations lazily (`RTLD_LAZY`).
        const LAZY = 0x1;
        /// Resolve relocations before a successful open returns (`RTLD_NOW`).
        const NOW = 0x2;
        /// Export this library's symbols to later global lookups (`RTLD_GLOBAL`).
        const GLOBAL = 0x100;
    }
}

impl OpenFlags {
    /// Keep the library local to its handle's lookup scope (`RTLD_LOCAL`).
    ///
    /// This is the zero-valued dlfcn flag, represented as an associated
    /// constant rather than a bitflag member.
    pub const LOCAL: Self = Self::empty();
}

/// An owned loader diagnostic.
///
/// Unlike `dlerror`, this value does not borrow thread-local loader storage
/// and remains valid across subsequent loader activity on any thread.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct LoaderError {
    bytes: [u8; TEXT_CAPACITY],
    len: u16,
    truncated: bool,
}

impl LoaderError {
    fn from_wire(text: TextV1) -> Self {
        let len = core::cmp::min(text.len as usize, text.bytes.len());
        let mut error = Self {
            bytes: text.bytes,
            len: len as u16,
            truncated: (text.flags & 1) != 0,
        };
        if error.len == 0 {
            error = Self::message(b"crabc dynamic loader operation failed");
        }
        error
    }

    fn message(message: &[u8]) -> Self {
        let len = core::cmp::min(message.len(), TEXT_CAPACITY);
        let mut bytes = [0; TEXT_CAPACITY];
        bytes[..len].copy_from_slice(&message[..len]);
        Self {
            bytes,
            len: len as u16,
            truncated: len < message.len(),
        }
    }

    /// Returns the copied diagnostic bytes. They need not be UTF-8.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Returns the copied diagnostic when it is valid UTF-8.
    #[inline]
    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(self.as_bytes()).ok()
    }

    /// Returns whether the private bounded runtime wire truncated the source.
    #[inline]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }
}

impl core::fmt::Display for LoaderError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.as_str() {
            Some(message) => formatter.write_str(message),
            None => formatter.write_str("crabc loader diagnostic is not UTF-8"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LoaderError {}

/// Immutable, copied metadata for a loaded address.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AddressInfo {
    image_base: Option<NonNull<c_void>>,
    symbol_address: Option<NonNull<c_void>>,
    image_name: LoaderError,
    symbol_name: LoaderError,
}

impl AddressInfo {
    /// Returns the mapped image base when the loader reported one.
    #[inline]
    pub const fn image_base(&self) -> Option<NonNull<c_void>> {
        self.image_base
    }

    /// Returns the nearest symbol address when the loader reported one.
    #[inline]
    pub const fn symbol_address(&self) -> Option<NonNull<c_void>> {
        self.symbol_address
    }

    /// Returns the copied image name bytes.
    #[inline]
    pub fn image_name(&self) -> &[u8] {
        self.image_name.as_bytes()
    }

    /// Returns the copied nearest-symbol name bytes.
    #[inline]
    pub fn symbol_name(&self) -> &[u8] {
        self.symbol_name.as_bytes()
    }
}

extern "C" {
    fn __crabc_runtime_v1() -> *const RuntimeV1;
}

fn runtime() -> core::result::Result<&'static RuntimeV1, LoaderError> {
    // SAFETY: This is crabc's explicit private runtime getter. A dynamic
    // crabc process resolves it from its loaded libc; the returned table is
    // immutable process-lifetime data.
    let runtime = unsafe { __crabc_runtime_v1() };
    if runtime.is_null() {
        return Err(LoaderError::message(b"crabc dynamic loader runtime unavailable"));
    }
    // SAFETY: The non-null table belongs to the loaded libc runtime and is
    // immutable for the process lifetime by its private ABI contract.
    let runtime = unsafe { &*runtime };
    if runtime.abi_version != V1_ABI_VERSION || runtime.abi_size < size_of::<RuntimeV1>() as u32 {
        return Err(LoaderError::message(b"incompatible crabc dynamic loader runtime"));
    }
    Ok(runtime)
}

fn runtime_error(error: TextV1) -> LoaderError {
    LoaderError::from_wire(error)
}

/// An owned dynamic-library handle.
///
/// It is deliberately not `Send` or `Sync` yet. The loader itself serializes
/// its object graph, but cross-thread handle transfer needs a dedicated native
/// lifecycle fixture before this type promises that Rust-level contract.
pub struct Library {
    handle: Option<NonNull<c_void>>,
    close_on_drop: bool,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl Library {
    /// Opens a shared object using an already validated C-string path.
    pub fn open(path: &CStr, flags: OpenFlags) -> core::result::Result<Self, LoaderError> {
        let runtime = runtime()?;
        let mut handle = core::ptr::null_mut();
        let mut error = TextV1::empty();
        // SAFETY: `path` is NUL-terminated, and both mutable outputs point to
        // stack storage with the private v1 wire layouts.
        if unsafe {
            (runtime.loader_open)(
                path.as_ptr(),
                flags.bits(),
                &mut handle,
                &mut error,
            )
        } != 0
        {
            return Err(runtime_error(error));
        }
        let handle = NonNull::new(handle)
            .ok_or_else(|| LoaderError::message(b"runtime returned a null loader handle"))?;
        Ok(Self {
            handle: Some(handle),
            close_on_drop: true,
            _not_send_or_sync: PhantomData,
        })
    }

    /// Opens the permanent global process lookup scope.
    ///
    /// The returned `Library` does not release that permanent scope on drop.
    pub fn open_main(flags: OpenFlags) -> core::result::Result<Self, LoaderError> {
        let runtime = runtime()?;
        let mut handle = core::ptr::null_mut();
        let mut error = TextV1::empty();
        // SAFETY: A null path is the private table's typed main-program
        // request; both output pointers have their exact v1 layouts.
        if unsafe { (runtime.loader_open)(core::ptr::null(), flags.bits(), &mut handle, &mut error) } != 0 {
            return Err(runtime_error(error));
        }
        let handle = NonNull::new(handle)
            .ok_or_else(|| LoaderError::message(b"runtime returned a null main-program handle"))?;
        Ok(Self {
            handle: Some(handle),
            close_on_drop: false,
            _not_send_or_sync: PhantomData,
        })
    }

    fn raw_handle(&self) -> NonNull<c_void> {
        // A Library only loses its handle during the consuming `close` path,
        // so a borrowed library always has an active opaque loader reference.
        self.handle.expect("active Library must retain its loader handle")
    }

    /// Looks up and unsafely interprets a symbol as `T`.
    ///
    /// # Safety
    ///
    /// `T` must be a pointer-sized, `Copy` ABI representation appropriate for
    /// the named symbol. In particular, calling a function with the wrong C
    /// ABI, argument types, return type, or data/function interpretation is
    /// undefined behavior. The returned [`Symbol`] cannot outlive this
    /// library handle.
    pub unsafe fn symbol<T: Copy>(
        &self,
        name: &CStr,
    ) -> core::result::Result<Symbol<'_, T>, LoaderError> {
        if size_of::<T>() != size_of::<*mut c_void>() || align_of::<T>() > align_of::<*mut c_void>() {
            return Err(LoaderError::message(b"loader symbol type is not pointer-sized"));
        }
        let runtime = runtime()?;
        let mut address = core::ptr::null_mut();
        let mut error = TextV1::empty();
        // SAFETY: The borrowed library retains its valid opaque handle; name
        // is NUL-terminated and the two output pointers use v1 wire layouts.
        if unsafe {
            (runtime.loader_symbol)(
                self.raw_handle().as_ptr(),
                name.as_ptr(),
                &mut address,
                &mut error,
            )
        } != 0
        {
            return Err(runtime_error(error));
        }
        let address = NonNull::new(address)
            .ok_or_else(|| LoaderError::message(b"runtime returned a null symbol address"))?;
        // SAFETY: The caller's unsafe contract establishes that `T` is the
        // pointer-sized ABI representation for this non-null symbol address.
        let value = unsafe { core::mem::transmute_copy::<*mut c_void, T>(&address.as_ptr()) };
        Ok(Symbol {
            value,
            address,
            _library: PhantomData,
        })
    }

    /// Copies loader metadata for an address without borrowing loader storage.
    pub fn address_of(address: NonNull<c_void>) -> core::result::Result<AddressInfo, LoaderError> {
        let runtime = runtime()?;
        let mut raw = LoaderAddressV1::empty();
        let mut error = TextV1::empty();
        // SAFETY: The non-null address is an opaque process address and both
        // mutable outputs point to exact private v1 wire storage.
        if unsafe { (runtime.loader_address)(address.as_ptr(), &mut raw, &mut error) } != 0 {
            return Err(runtime_error(error));
        }
        Ok(AddressInfo {
            image_base: NonNull::new(raw.image_base),
            symbol_address: NonNull::new(raw.symbol_address),
            image_name: LoaderError::from_wire(raw.image_name),
            symbol_name: LoaderError::from_wire(raw.symbol_name),
        })
    }

    /// Closes the handle and reports a loader failure synchronously.
    ///
    /// A failed close leaves the handle in this value so its destructor can
    /// make one best-effort close attempt during unwinding.
    pub fn close(mut self) -> core::result::Result<(), LoaderError> {
        if !self.close_on_drop {
            self.handle = None;
            return Ok(());
        }
        let handle = self.raw_handle();
        let runtime = runtime()?;
        let mut error = TextV1::empty();
        // SAFETY: `handle` is the active opaque reference owned by `self`,
        // and error points to caller-owned v1 output storage.
        if unsafe { (runtime.loader_close)(handle.as_ptr(), &mut error) } != 0 {
            return Err(runtime_error(error));
        }
        self.handle = None;
        Ok(())
    }
}

impl Drop for Library {
    fn drop(&mut self) {
        let Some(handle) = self.handle.take() else {
            return;
        };
        if !self.close_on_drop {
            return;
        }
        let Ok(runtime) = runtime() else {
            return;
        };
        let mut error = TextV1::empty();
        // SAFETY: Drop owns the last native handle reference in this value.
        // Errors cannot be reported from Drop and are intentionally ignored.
        let _ = unsafe { (runtime.loader_close)(handle.as_ptr(), &mut error) };
    }
}

/// A typed symbol whose lifetime is tied to a borrowed [`Library`].
pub struct Symbol<'library, T> {
    value: T,
    address: NonNull<c_void>,
    _library: PhantomData<&'library Library>,
}

impl<T: Copy> Symbol<'_, T> {
    /// Returns the caller-selected typed symbol representation.
    #[inline]
    pub fn get(&self) -> T {
        self.value
    }
}

impl<T> Symbol<'_, T> {
    /// Returns the untyped address for low-level interoperation.
    #[inline]
    pub const fn address(&self) -> NonNull<c_void> {
        self.address
    }
}

#[cfg(test)]
mod tests {
    use super::{LoaderError, OpenFlags};

    #[test]
    fn local_scope_is_zero_while_global_is_explicit() {
        assert!(OpenFlags::LOCAL.is_empty());
        assert_eq!(OpenFlags::GLOBAL.bits(), 0x100);
    }

    #[test]
    fn copied_error_preserves_bytes_and_truncation() {
        let error = LoaderError::message(b"native loader failure");

        assert_eq!(error.as_bytes(), b"native loader failure");
        assert_eq!(error.as_str(), Some("native loader failure"));
        assert!(!error.is_truncated());
    }
}
