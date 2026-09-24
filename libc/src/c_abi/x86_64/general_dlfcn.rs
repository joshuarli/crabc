//! Installed dynamic C ABI over the interpreter's general runtime owner.
//!
//! Object identities, scope, mappings, callbacks and TLS generations belong
//! exclusively to ldso. This leaf owns C diagnostics in real per-thread TLS,
//! not a fixed TID table. Private calls are resolved by the initial loader;
//! there is no ambient/fixed-graph fallback or copied RuntimeV1 extension.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

/// Private dlopen failure record filled by the interpreter. It mirrors ldso's
/// `x86_64_runtime_registry::RuntimeDiagnostic`: a musl message kind, a Linux
/// errno (or relocation type), and up to three NUL-terminated copied names.
#[repr(C)]
struct RuntimeDiagnostic { kind: c_int, number: c_int, text: [u8; 1024] }
impl RuntimeDiagnostic {
    const fn empty() -> Self { Self { kind: 0, number: 0, text: [0; 1024] } }
}
const _: () = assert!(core::mem::size_of::<RuntimeDiagnostic>() == 1032);
const DIAGNOSTIC_LOAD: c_int = 1;
const DIAGNOSTIC_NEEDED: c_int = 2;
const DIAGNOSTIC_NOT_LOADED: c_int = 3;
const DIAGNOSTIC_EXITING: c_int = 4;
const DIAGNOSTIC_SYMBOL: c_int = 5;
const DIAGNOSTIC_INITIAL_EXEC: c_int = 6;
const DIAGNOSTIC_RELOCATION_TYPE: c_int = 7;
const DIAGNOSTIC_RELRO: c_int = 8;
const DIAGNOSTIC_FORK: c_int = 9;

extern "C" {
    fn __crabc_x86_64_runtime_open(name: *const u8, flags: c_int, diagnostic: *mut RuntimeDiagnostic) -> *mut c_void;
    fn __crabc_x86_64_runtime_symbol(handle: *mut c_void, name: *const u8, caller: usize, error: *mut c_int) -> *mut c_void;
    fn __crabc_x86_64_runtime_close(handle: *mut c_void) -> c_int;
    fn __crabc_x86_64_runtime_address(address: usize, output: *mut c_void) -> c_int;
    fn __crabc_x86_64_runtime_information(handle: *mut c_void, output: *mut *mut c_void) -> c_int;
    fn __crabc_x86_64_runtime_iterate(callback: unsafe extern "C" fn(*mut c_void, usize, *mut c_void) -> c_int, data: *mut c_void) -> c_int;
}

#[path = "dlfcn_diagnostic.rs"]
mod diagnostic;
pub(super) use diagnostic::{invalid_handle, symbol_not_found, Diagnostic};

/// Format pinned musl 1.2.6 `ldso/dynlink.c` dlopen diagnostics (MIT,
/// 9fa28ece75d8a2191de7c5bb53bed224c5947417) from the loader's record.
///
/// # Safety
/// `name` is the caller's readable dlopen pathname.
unsafe fn open_diagnostic(name: *const u8, record: &RuntimeDiagnostic) -> Diagnostic {
    let text = &record.text;
    // The loader copies up to three NUL-terminated parts in order.
    let part = |ordinal: usize| -> &[u8] {
        let mut parts = text.split(|byte| *byte == 0);
        parts.nth(ordinal).unwrap_or(&[])
    };
    let message = Diagnostic::new();
    match record.kind {
        DIAGNOSTIC_NEEDED => message.bytes(b"Error loading shared library ").bytes(part(0)).bytes(b": ")
            .errno(record.number).bytes(b" (needed by ").bytes(part(1)).bytes(b")"),
        DIAGNOSTIC_NOT_LOADED => unsafe { message.bytes(b"Library ").text(name) }.bytes(b" is not already loaded"),
        DIAGNOSTIC_EXITING => message.bytes(b"Cannot dlopen while program is exiting."),
        DIAGNOSTIC_SYMBOL => message.bytes(b"Error relocating ").bytes(part(0)).bytes(b": ").bytes(part(1))
            .bytes(b": symbol not found"),
        DIAGNOSTIC_INITIAL_EXEC => message.bytes(b"Error relocating ").bytes(part(0)).bytes(b": ").bytes(part(1))
            .bytes(b": initial-exec TLS resolves to dynamic definition in ").bytes(part(2)),
        DIAGNOSTIC_RELOCATION_TYPE => message.bytes(b"Error relocating ").bytes(part(0))
            .bytes(b": unsupported relocation type ").decimal(record.number),
        DIAGNOSTIC_RELRO => message.bytes(b"Error relocating ").bytes(part(0)).bytes(b": RELRO protection failed: ")
            .errno(record.number),
        DIAGNOSTIC_FORK => message.bytes(b"State of ").bytes(part(0)).bytes(b" is inconsistent due to multithreaded fork\n"),
        // The loader leaves no other kind for a failed named open.
        kind => {
            debug_assert_eq!(kind, DIAGNOSTIC_LOAD);
            unsafe { message.bytes(b"Error loading shared library ").text(name) }.bytes(b": ").errno(record.number)
        }
    }
}

/// Musl disables deferred cancellation across one loader transaction. The
/// private native-facade table shares this guard with the C entry points.
pub(super) struct CancellationGuard { previous: c_int, changed: bool }
impl CancellationGuard {
    pub(super) unsafe fn enter() -> Self {
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

/// One loader open for the RuntimeV1 facade, formatted as `dlopen` would
/// but never published as this thread's `dlerror`. A null `name` is the
/// global handle and cannot fail.
///
/// # Safety
/// `name` is null or a readable NUL-terminated C pathname; the caller holds a
/// [`CancellationGuard`].
pub(super) unsafe fn open_object(name: *const c_char, flags: c_int) -> Result<*mut c_void, Diagnostic> {
    let mut record = RuntimeDiagnostic::empty();
    let handle = unsafe { __crabc_x86_64_runtime_open(name.cast(), flags, &mut record) };
    if handle.is_null() && !name.is_null() { Err(unsafe { open_diagnostic(name.cast(), &record) }) }
    else { Ok(handle) }
}

/// # Safety
/// `name` is null or a readable NUL-terminated C pathname.
#[no_mangle]
pub unsafe extern "C" fn dlopen(name: *const c_char, flags: c_int) -> *mut c_void {
    let _cancellation = unsafe { CancellationGuard::enter() };
    let mut record = RuntimeDiagnostic::empty();
    let handle = unsafe { __crabc_x86_64_runtime_open(name.cast(), flags, &mut record) };
    if handle.is_null() && !name.is_null() { unsafe { open_diagnostic(name.cast(), &record) }.publish(); }
    handle
}

/// Private runtime-symbol error code for a handle outside the registry.
pub(super) const SYMBOL_INVALID_HANDLE: c_int = 10006;

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
        if error == SYMBOL_INVALID_HANDLE { invalid_handle(handle).publish(); }
        else { unsafe { symbol_not_found(name) }.publish(); }
    }
    address
}

/// # Safety
/// A successful handle is borrowed from dlopen; arbitrary invalid values are
/// rejected by identity comparison without dereferencing caller storage.
#[no_mangle]
pub unsafe extern "C" fn dlclose(handle: *mut c_void) -> c_int {
    let result = unsafe { __crabc_x86_64_runtime_close(handle) };
    if result != 0 { invalid_handle(handle).publish(); }
    result
}

/// Consume this thread's pending diagnostic. Storage remains valid until the
/// next loader error in this thread or until this thread exits.
#[no_mangle]
pub extern "C" fn dlerror() -> *mut c_char { diagnostic::take() }

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
    // musl validates the handle before interpreting the request. Validation
    // uses local storage so an unsupported request never writes caller memory.
    let mut link_map = ptr::null_mut();
    if unsafe { __crabc_x86_64_runtime_information(handle, &mut link_map) } != 0 {
        invalid_handle(handle).publish();
        return -1;
    }
    if request != 2 {
        Diagnostic::new().bytes(b"Unsupported request ").decimal(request).publish();
        return -1;
    }
    unsafe { *output.cast::<*mut c_void>() = link_map; }
    0
}

/// # Safety
/// `callback` obeys the installed `dl_phdr_info` C ABI and may use `data` for
/// the duration of this call. The info argument is callback-borrowed only.
#[no_mangle]
pub unsafe extern "C" fn dl_iterate_phdr(callback: unsafe extern "C" fn(*mut c_void, usize, *mut c_void) -> c_int, data: *mut c_void) -> c_int {
    unsafe { __crabc_x86_64_runtime_iterate(callback, data) }
}
