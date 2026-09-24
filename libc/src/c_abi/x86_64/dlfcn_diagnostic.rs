//! Per-thread `dlerror` state and pinned-musl diagnostic formatting shared by
//! the installed dynamic (`general_dlfcn.rs`) and static (`static_dlfcn.rs`)
//! dlfcn leaves. Musl 1.2.6 `src/ldso/dlerror.c` keeps one pending message
//! per thread, replaced by each later error and consumed by `dlerror`; its
//! texts are formatted by `vsnprintf`, whose `%s`, `%p`, `%d` and `%m`
//! spellings this builder reproduces.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

#[thread_local]
static mut ERROR_TEXT: [u8; 1024] = [0; 1024];
#[thread_local]
static mut ERROR_PENDING: bool = false;

/// One formatted pinned-musl loader diagnostic. Musl allocates an exact
/// buffer; this fixed copy truncates only beyond 1023 message bytes. The C
/// entry points publish it as this thread's `dlerror`; the private RuntimeV1
/// facade copies the same bytes into caller-owned wire storage.
pub(in super::super) struct Diagnostic { text: [u8; 1024], count: usize }
impl Diagnostic {
    pub(in super::super) fn new() -> Self { Self { text: [0; 1024], count: 0 } }
    pub(in super::super) fn bytes(mut self, bytes: &[u8]) -> Self {
        let room = 1023 - self.count;
        let length = bytes.len().min(room);
        self.text[self.count..self.count + length].copy_from_slice(&bytes[..length]);
        self.count += length;
        self
    }
    /// Musl `%s`; a null pointer prints `(null)`.
    ///
    /// # Safety
    /// `text` is null or a readable NUL-terminated C string.
    pub(in super::super) unsafe fn text(mut self, text: *const u8) -> Self {
        if text.is_null() { return self.bytes(b"(null)"); }
        let mut index = 0;
        while self.count < 1023 {
            let byte = unsafe { *text.add(index) };
            if byte == 0 { break; }
            self.text[self.count] = byte;
            self.count += 1;
            index += 1;
        }
        self
    }
    /// Musl `%m` after the loader left `error` in errno. This, `%d` and the
    /// facade copy below are dynamic-leaf only; the static leaf has no loader.
    #[cfg_attr(not(crabc_x86_dynamic_runtime), allow(dead_code))]
    pub(in super::super) fn errno(self, error: c_int) -> Self {
        let message = super::super::error_strings::error_message(error);
        self.bytes(&message[..message.len() - 1])
    }
    /// Musl `%d`.
    #[cfg_attr(not(crabc_x86_dynamic_runtime), allow(dead_code))]
    pub(in super::super) fn decimal(self, value: c_int) -> Self {
        let mut digits = [0u8; 12];
        let mut index = digits.len();
        let mut magnitude = value.unsigned_abs();
        loop { index -= 1; digits[index] = b'0' + (magnitude % 10) as u8; magnitude /= 10; if magnitude == 0 { break; } }
        if value < 0 { index -= 1; digits[index] = b'-'; }
        self.bytes(&digits[index..])
    }
    /// Musl `%p`: lowercase hexadecimal with `0x`, and a bare `0` for null.
    pub(in super::super) fn pointer(self, value: usize) -> Self {
        if value == 0 { return self.bytes(b"0"); }
        let mut digits = [0u8; 16];
        let mut index = digits.len();
        let mut rest = value;
        while rest != 0 { index -= 1; digits[index] = b"0123456789abcdef"[rest & 15]; rest >>= 4; }
        self.bytes(b"0x").bytes(&digits[index..])
    }
    /// The formatted message without a terminator.
    #[cfg_attr(not(crabc_x86_dynamic_runtime), allow(dead_code))]
    pub(in super::super) fn as_bytes(&self) -> &[u8] { &self.text[..self.count] }
    /// Replace this thread's pending `dlerror` text.
    pub(in super::super) fn publish(self) {
        unsafe {
            let output = ptr::addr_of_mut!(ERROR_TEXT).cast::<u8>();
            ptr::copy_nonoverlapping(self.text.as_ptr(), output, self.count);
            *output.add(self.count) = 0;
            ERROR_PENDING = true;
        }
    }
}

/// musl `__dl_invalid_handle`: `Invalid library handle %p`.
pub(in super::super) fn invalid_handle(handle: *mut c_void) -> Diagnostic {
    Diagnostic::new().bytes(b"Invalid library handle ").pointer(handle as usize)
}

/// musl `do_dlsym`: `Symbol not found: %s`.
///
/// # Safety
/// `name` is a readable NUL-terminated C symbol name.
pub(in super::super) unsafe fn symbol_not_found(name: *const c_char) -> Diagnostic {
    unsafe { Diagnostic::new().bytes(b"Symbol not found: ").text(name.cast()) }
}

/// musl `dlerror`: return and clear this thread's pending message. Storage
/// remains valid until the next loader error in this thread or thread exit.
pub(in super::super) fn take() -> *mut c_char {
    unsafe {
        if !ERROR_PENDING { return ptr::null_mut(); }
        ERROR_PENDING = false;
        ptr::addr_of_mut!(ERROR_TEXT).cast()
    }
}
