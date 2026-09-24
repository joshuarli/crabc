//! Per-thread `dlerror` state and pinned-musl diagnostic formatting shared by
//! the installed dynamic (`general_dlfcn.rs`) and static (`static_dlfcn.rs`)
//! dlfcn leaves.
//!
//! Source-faithful translation of pinned musl 1.2.6 `src/ldso/dlerror.c`
//! (MIT, 9fa28ece75d8a2191de7c5bb53bed224c5947417): each thread keeps one
//! message in a `__libc_malloc` buffer sized to it (at least a pointer),
//! replaced and freed by that thread's next loader error and consumed by
//! `dlerror`. An exiting thread cannot free, so `__dl_thread_cleanup` pushes
//! its buffer on an atomic list that the next error on any thread drains. A
//! failed allocation leaves musl's fixed out-of-memory text. The builder
//! reproduces the `vsnprintf` spellings of `%s`, `%p`, `%d` and `%m`.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

/// Musl's `(void *)-1` buffer: the last message could not be allocated.
const ALLOCATION_FAILED: *mut u8 = usize::MAX as *mut u8;
const ALLOCATION_FAILED_TEXT: &[u8] = b"Dynamic linker failed to allocate memory for error message\0";

#[thread_local]
static mut ERROR_BUFFER: *mut u8 = ptr::null_mut();
#[thread_local]
static mut ERROR_PENDING: bool = false;

/// Buffers of exited threads; each one's first word links the next.
static FREED_BUFFERS: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());

/// One `vsnprintf` conversion of a musl loader format.
#[derive(Clone, Copy)]
enum Part<'a> {
    Bytes(&'a [u8]),
    /// `%s` of a NUL-terminated C string; null prints `(null)`.
    Text(*const u8),
    /// `%m` of this errno value.
    Errno(c_int),
    Decimal(c_int),
    Pointer(usize),
}

impl Part<'_> {
    /// Call `emit` with the conversion's bytes, in order.
    fn render(self, emit: &mut impl FnMut(&[u8])) {
        match self {
            Self::Bytes(bytes) => emit(bytes),
            Self::Text(text) if text.is_null() => emit(b"(null)"),
            Self::Text(text) => {
                // SAFETY: builder callers pass readable NUL-terminated strings.
                let length = unsafe { (0..).position(|index| *text.add(index) == 0).unwrap_or(0) };
                emit(unsafe { core::slice::from_raw_parts(text, length) });
            }
            Self::Errno(error) => {
                let message = super::super::error_strings::error_message(error);
                emit(&message[..message.len() - 1]);
            }
            Self::Decimal(value) => {
                let mut digits = [0u8; 12];
                let mut index = digits.len();
                let mut magnitude = value.unsigned_abs();
                loop { index -= 1; digits[index] = b'0' + (magnitude % 10) as u8; magnitude /= 10; if magnitude == 0 { break; } }
                if value < 0 { index -= 1; digits[index] = b'-'; }
                emit(&digits[index..]);
            }
            // Musl `%p`: lowercase hexadecimal with `0x`, and a bare `0` for null.
            Self::Pointer(0) => emit(b"0"),
            Self::Pointer(value) => {
                let mut digits = [0u8; 18];
                let mut index = digits.len();
                let mut rest = value;
                while rest != 0 { index -= 1; digits[index] = b"0123456789abcdef"[rest & 15]; rest >>= 4; }
                index -= 2;
                digits[index..index + 2].copy_from_slice(b"0x");
                emit(&digits[index..]);
            }
        }
    }
}

/// The largest musl loader format has eight conversions.
const PARTS: usize = 8;

/// A musl loader diagnostic being built from borrowed conversions.
pub(in super::super) struct Diagnostic<'a> { parts: [Part<'a>; PARTS], count: usize }

impl<'a> Diagnostic<'a> {
    pub(in super::super) fn new() -> Self { Self { parts: [Part::Bytes(&[]); PARTS], count: 0 } }
    fn part(mut self, part: Part<'a>) -> Self {
        assert!(self.count < PARTS, "musl loader formats have at most eight conversions");
        self.parts[self.count] = part;
        self.count += 1;
        self
    }
    pub(in super::super) fn bytes(self, bytes: &'a [u8]) -> Self { self.part(Part::Bytes(bytes)) }
    /// Musl `%s`.
    ///
    /// # Safety
    /// `text` is null or a readable NUL-terminated C string until the
    /// message is finished.
    pub(in super::super) unsafe fn text(self, text: *const u8) -> Self { self.part(Part::Text(text)) }
    /// Musl `%m` for the errno the failure left.
    #[cfg_attr(not(crabc_x86_dynamic_runtime), allow(dead_code))]
    pub(in super::super) fn errno(self, error: c_int) -> Self { self.part(Part::Errno(error)) }
    /// Musl `%d`.
    #[cfg_attr(not(crabc_x86_dynamic_runtime), allow(dead_code))]
    pub(in super::super) fn decimal(self, value: c_int) -> Self { self.part(Part::Decimal(value)) }
    /// Musl `%p`.
    pub(in super::super) fn pointer(self, value: usize) -> Self { self.part(Part::Pointer(value)) }

    /// Format into one `__libc_malloc` buffer sized to the message, at least
    /// a pointer so an exiting thread can link it, as `__dl_vseterr` does.
    pub(in super::super) fn finish(self) -> Message {
        let parts = &self.parts[..self.count];
        let mut length = 0usize;
        for part in parts { part.render(&mut |bytes| length += bytes.len()); }
        let size = length.max(core::mem::size_of::<*mut u8>()) + 1;
        // SAFETY: owned TLS is ready in every dlfcn caller.
        let buffer = unsafe { super::super::allocator::allocate_internal(size) }.cast::<u8>();
        if buffer.is_null() { return Message { buffer: ALLOCATION_FAILED, length: 0 }; }
        let mut used = 0;
        for part in parts {
            part.render(&mut |bytes| {
                // SAFETY: the first pass measured exactly these bytes.
                unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), buffer.add(used), bytes.len()) };
                used += bytes.len();
            });
        }
        // SAFETY: `size` reserves the terminator after `length` bytes.
        unsafe { *buffer.add(used) = 0 };
        Message { buffer, length: used }
    }

    /// Format and replace this thread's pending `dlerror` text.
    pub(in super::super) fn publish(self) { self.finish().publish() }
}

/// One formatted diagnostic that owns its exact-size buffer.
pub(in super::super) struct Message { buffer: *mut u8, length: usize }

impl Message {
    /// The formatted message without a terminator.
    #[cfg_attr(not(crabc_x86_dynamic_runtime), allow(dead_code))]
    pub(in super::super) fn as_bytes(&self) -> &[u8] {
        if self.buffer == ALLOCATION_FAILED { return &ALLOCATION_FAILED_TEXT[..ALLOCATION_FAILED_TEXT.len() - 1]; }
        // SAFETY: the buffer holds `length` formatted bytes.
        unsafe { core::slice::from_raw_parts(self.buffer, self.length) }
    }

    /// Musl `__dl_vseterr`: release exited threads' buffers and this
    /// thread's previous one, then install this message as pending.
    pub(in super::super) fn publish(self) {
        let mut freed = FREED_BUFFERS.swap(ptr::null_mut(), Ordering::Acquire);
        while !freed.is_null() {
            // SAFETY: an exited thread linked this buffer through its first
            // word and transferred ownership to the list.
            let next = unsafe { *freed.cast::<*mut u8>() };
            unsafe { super::super::allocator::deallocate_internal(freed.cast()) };
            freed = next;
        }
        let buffer = self.buffer;
        core::mem::forget(self);
        unsafe {
            if !ERROR_BUFFER.is_null() && ERROR_BUFFER != ALLOCATION_FAILED {
                super::super::allocator::deallocate_internal(ERROR_BUFFER.cast());
            }
            ERROR_BUFFER = buffer;
            ERROR_PENDING = true;
        }
    }
}

impl Drop for Message {
    fn drop(&mut self) {
        if self.buffer != ALLOCATION_FAILED {
            // SAFETY: an unpublished message still owns its buffer.
            unsafe { super::super::allocator::deallocate_internal(self.buffer.cast()) };
        }
    }
}

/// musl `__dl_invalid_handle`: `Invalid library handle %p`.
pub(in super::super) fn invalid_handle(handle: *mut c_void) -> Message {
    Diagnostic::new().bytes(b"Invalid library handle ").pointer(handle as usize).finish()
}

/// musl `do_dlsym`: `Symbol not found: %s`.
///
/// # Safety
/// `name` is a readable NUL-terminated C symbol name.
pub(in super::super) unsafe fn symbol_not_found(name: *const c_char) -> Message {
    unsafe { Diagnostic::new().bytes(b"Symbol not found: ").text(name.cast()) }.finish()
}

/// musl `dlerror`: return and clear this thread's pending message. Storage
/// remains valid until the next loader error in this thread or thread exit.
pub(in super::super) fn take() -> *mut c_char {
    unsafe {
        if !ERROR_PENDING { return ptr::null_mut(); }
        ERROR_PENDING = false;
        if ERROR_BUFFER == ALLOCATION_FAILED { return ALLOCATION_FAILED_TEXT.as_ptr().cast_mut().cast(); }
        ERROR_BUFFER.cast()
    }
}

/// musl `__dl_thread_cleanup`: hand this exiting thread's buffer to the
/// next loader error. It neither frees nor locks.
///
/// # Safety
/// The calling thread is exiting and never reads its `dlerror` state again.
pub(in super::super) unsafe fn thread_cleanup() {
    let buffer = unsafe { ERROR_BUFFER };
    if buffer.is_null() || buffer == ALLOCATION_FAILED { return; }
    unsafe { ERROR_BUFFER = ptr::null_mut(); }
    let mut head = FREED_BUFFERS.load(Ordering::Relaxed);
    loop {
        // SAFETY: every buffer reserves at least one pointer-sized word.
        unsafe { *buffer.cast::<*mut u8>() = head; }
        match FREED_BUFFERS.compare_exchange_weak(head, buffer, Ordering::Release, Ordering::Relaxed) {
            Ok(_) => return,
            Err(current) => head = current,
        }
    }
}
