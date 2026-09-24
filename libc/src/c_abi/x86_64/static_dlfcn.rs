//! Public C dlfcn surface of the installed static product, which has no
//! dynamic loader.
//!
//! Source-faithful translation of pinned musl 1.2.6 (MIT, revision
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417) static `libc.a` bodies:
//! `src/ldso/dlopen.c` (weak `stub_dlopen`), `dlsym.c` over `__dlsym.c`'s
//! weak stub, `dlclose.c` and `dlinfo.c` over `dlerror.c`'s weak
//! `__dl_invalid_handle` stub, `dladdr.c` (weak `stub_dladdr`),
//! `dl_iterate_phdr.c` (weak `static_dl_iterate_phdr`) and `dlerror.c`.
//! Every open fails, every handle is invalid, no address has an image, and
//! enumeration reports only the executable. `dlopen`, `dladdr` and
//! `dl_iterate_phdr` keep musl's archive `STB_WEAK` spellings so an
//! application definition overrides them; the other four are global.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

#[path = "dlfcn_diagnostic.rs"]
mod diagnostic;
use diagnostic::{invalid_handle, symbol_not_found, Diagnostic};
pub(super) use diagnostic::thread_cleanup;

#[path = "static_dl_iterate_phdr.rs"]
mod static_dl_iterate_phdr;

/// Installed LP64 `struct dl_phdr_info`, filled by the static enumerator.
#[repr(C)]
pub struct DlPhdrInfo {
    dlpi_addr: usize,
    dlpi_name: *const c_char,
    dlpi_phdr: *const c_void,
    dlpi_phnum: u16,
    dlpi_adds: u64,
    dlpi_subs: u64,
    dlpi_tls_modid: usize,
    dlpi_tls_data: *mut c_void,
}

/// musl `stub_dlopen`: no loader exists, including for a null name.
#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn dlopen(_file: *const c_char, _mode: c_int) -> *mut c_void {
    Diagnostic::new().bytes(b"Dynamic loading not supported").publish();
    ptr::null_mut()
}

/// musl `dlsym` -> `stub_dlsym`: `Symbol not found: %s` for every handle,
/// including `RTLD_DEFAULT` and `RTLD_NEXT`.
///
/// # Safety
/// `name` is null or a readable NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn dlsym(_handle: *mut c_void, name: *const c_char) -> *mut c_void {
    unsafe { symbol_not_found(name) }.publish();
    ptr::null_mut()
}

/// musl `dlclose` -> `stub_invalid_handle`: every handle is invalid.
#[no_mangle]
pub extern "C" fn dlclose(handle: *mut c_void) -> c_int {
    invalid_handle(handle).publish();
    1
}

/// musl `dlerror`: consume this thread's pending message.
#[no_mangle]
pub extern "C" fn dlerror() -> *mut c_char { diagnostic::take() }

/// musl `stub_dladdr`: no address belongs to a loaded image; `info` is
/// untouched and no diagnostic is published.
#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn dladdr(_address: *const c_void, _info: *mut c_void) -> c_int { 0 }

/// musl `dlinfo`: the invalid-handle check precedes the request, so every
/// call fails without writing `result`.
#[no_mangle]
pub extern "C" fn dlinfo(handle: *mut c_void, _request: c_int, _result: *mut c_void) -> c_int {
    invalid_handle(handle).publish();
    -1
}

/// musl `static_dl_iterate_phdr`: one callback for the executable.
///
/// # Safety
/// `callback`, when present, obeys the C `dl_iterate_phdr` callback contract
/// and `data` satisfies it. Musl calls a null callback; this entry returns 0.
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn dl_iterate_phdr(
    callback: Option<unsafe extern "C" fn(*mut DlPhdrInfo, usize, *mut c_void) -> c_int>,
    data: *mut c_void,
) -> c_int {
    let Some(callback) = callback else { return 0 };
    unsafe { static_dl_iterate_phdr::iterate(callback, data) }
}
