//! Installed dynamic C ABI over the interpreter's general runtime owner.
//!
//! Object identities, scope, mappings, callbacks and TLS generations belong
//! exclusively to ldso. This leaf owns C diagnostics in real per-thread TLS,
//! not a fixed TID table. Private calls are resolved by the initial loader;
//! there is no ambient/fixed-graph fallback or copied RuntimeV1 extension.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

extern "C" {
    fn __crabc_x86_64_runtime_open(name: *const u8, flags: c_int, error: *mut c_int) -> *mut c_void;
    fn __crabc_x86_64_runtime_symbol(handle: *mut c_void, name: *const u8, caller: usize, error: *mut c_int) -> *mut c_void;
    fn __crabc_x86_64_runtime_close(handle: *mut c_void) -> c_int;
    fn __crabc_x86_64_runtime_address(address: usize, output: *mut c_void) -> c_int;
    fn __crabc_x86_64_runtime_information(handle: *mut c_void, output: *mut *mut c_void) -> c_int;
    fn __crabc_x86_64_runtime_iterate(callback: unsafe extern "C" fn(*mut c_void, usize, *mut c_void) -> c_int, data: *mut c_void) -> c_int;
}

#[thread_local]
static mut ERROR_TEXT: [u8; 1024] = [0; 1024];
#[thread_local]
static mut ERROR_PENDING: bool = false;

unsafe fn diagnostic(prefix: &[u8], name: *const u8, suffix: &[u8]) {
    let output = ptr::addr_of_mut!(ERROR_TEXT).cast::<u8>();
    let mut count = 0;
    for &byte in prefix {
        if count == 1023 { break; }
        unsafe { *output.add(count) = byte; }
        count += 1;
    }
    if !name.is_null() {
        for index in 0..512 {
            let byte = unsafe { *name.add(index) };
            if byte == 0 || count == 1023 { break; }
            unsafe { *output.add(count) = byte; }
            count += 1;
        }
    }
    for &byte in suffix {
        if count == 1023 { break; }
        unsafe { *output.add(count) = byte; }
        count += 1;
    }
    unsafe { *output.add(count) = 0; ERROR_PENDING = true; }
}

struct CancellationGuard { previous: c_int, changed: bool }
impl CancellationGuard {
    unsafe fn enter() -> Self {
        let mut previous = 0;
        let changed = unsafe { super::pthread_cancel::pthread_setcancelstate(1, &mut previous) } == 0;
        // The initial thread currently has no selected cancellation slot.
        // ENOTSUP there does not invent cancellability or block loader use.
        Self { previous, changed }
    }
}
impl Drop for CancellationGuard {
    fn drop(&mut self) {
        if self.changed { unsafe { super::pthread_cancel::pthread_setcancelstate(self.previous, ptr::null_mut()); } }
    }
}

/// # Safety
/// `name` is null or a readable NUL-terminated C pathname.
#[no_mangle]
pub unsafe extern "C" fn dlopen(name: *const c_char, flags: c_int) -> *mut c_void {
    let _cancellation = unsafe { CancellationGuard::enter() };
    let mut error = 0;
    let handle = unsafe { __crabc_x86_64_runtime_open(name.cast(), flags, &mut error) };
    if error != 0 {
        let reason: &[u8] = match error {
            2 => b": No such file or directory", 12 => b": Out of memory",
            13 => b": Permission denied", 22 => b": Invalid argument", 36 => b": Filename too long",
            10001 => b": Invalid ELF object", 10002 => b": Relocation failed",
            10003 => b": TLS preparation failed", 10004 => b": Library is not already loaded",
            10005 => b": Process finalization has begun",
            _ => b": Loader admission failed",
        };
        unsafe { diagnostic(b"Error loading shared library ", name.cast(), reason); }
    }
    handle
}

// SysV AMD64 supplies the original C return address at [rsp]. A tail branch
// carries it as the third argument without adding a Rust wrapper frame, so
// RTLD_NEXT identifies the application caller rather than shared libc.
core::arch::global_asm!(
    ".section .text.dlsym,\"ax\",@progbits",
    ".global dlsym",
    ".type dlsym,@function",
    "dlsym:",
    "mov rdx, qword ptr [rsp]",
    "jmp __crabc_x86_general_dlsym",
    ".size dlsym, .-dlsym",
    ".hidden __crabc_x86_general_dlsym",
);

/// # Safety
/// `name` is a readable C symbol name; `caller` comes from the C trampoline.
#[no_mangle]
unsafe extern "C" fn __crabc_x86_general_dlsym(handle: *mut c_void, name: *const c_char, caller: usize) -> *mut c_void {
    let mut error = 0;
    let address = unsafe { __crabc_x86_64_runtime_symbol(handle, name.cast(), caller, &mut error) };
    if error != 0 {
        if error == 10006 { unsafe { diagnostic(b"Invalid library handle", ptr::null(), b""); } }
        else { unsafe { diagnostic(b"Symbol not found: ", name.cast(), b""); } }
    }
    address
}

/// # Safety
/// A successful handle is borrowed from dlopen; arbitrary invalid values are
/// rejected by identity comparison without dereferencing caller storage.
#[no_mangle]
pub unsafe extern "C" fn dlclose(handle: *mut c_void) -> c_int {
    let result = unsafe { __crabc_x86_64_runtime_close(handle) };
    if result != 0 { unsafe { diagnostic(b"Invalid library handle", ptr::null(), b""); } }
    result
}

/// Consume this thread's pending diagnostic. Storage remains valid until the
/// next loader error in this thread or until this thread exits.
#[no_mangle]
pub extern "C" fn dlerror() -> *mut c_char {
    unsafe {
        if !ERROR_PENDING { return ptr::null_mut(); }
        ERROR_PENDING = false;
        ptr::addr_of_mut!(ERROR_TEXT).cast()
    }
}

/// # Safety
/// `output` is writable storage for the installed header's `Dl_info` layout.
#[no_mangle]
pub unsafe extern "C" fn dladdr(address: *const c_void, output: *mut c_void) -> c_int {
    unsafe { __crabc_x86_64_runtime_address(address as usize, output) }
}

/// # Safety
/// For RTLD_DI_LINKMAP, `output` is writable pointer-sized storage. Returned
/// link-map metadata is borrowed; applications must not mutate it.
#[no_mangle]
pub unsafe extern "C" fn dlinfo(handle: *mut c_void, request: c_int, output: *mut c_void) -> c_int {
    if request != 2 {
        let mut number = [0u8; 12];
        let mut index = number.len();
        let mut value = request.unsigned_abs();
        loop { index -= 1; number[index] = b'0' + (value % 10) as u8; value /= 10; if value == 0 { break; } }
        if request < 0 { index -= 1; number[index] = b'-'; }
        unsafe { diagnostic(b"Unsupported request ", ptr::null(), &number[index..]); }
        return -1;
    }
    let error = unsafe { __crabc_x86_64_runtime_information(handle, output.cast()) };
    if error == 0 { 0 }
    else { unsafe { diagnostic(b"Invalid library handle", ptr::null(), b""); } -1 }
}

/// # Safety
/// `callback` obeys the installed `dl_phdr_info` C ABI and may use `data` for
/// the duration of this call. The info argument is callback-borrowed only.
#[no_mangle]
pub unsafe extern "C" fn dl_iterate_phdr(callback: unsafe extern "C" fn(*mut c_void, usize, *mut c_void) -> c_int, data: *mut c_void) -> c_int {
    unsafe { __crabc_x86_64_runtime_iterate(callback, data) }
}
