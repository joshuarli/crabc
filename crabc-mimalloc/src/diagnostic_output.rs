// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/options.c:15-16,111-178,347-549`,
// its `mi_vfprintf_thread` prefix at `src/options.c:498-507`, the selected
// `%tx` formatter route at `src/libc.c:254-261,285-307,313-397`, and Linux
// thread identity at `include/mimalloc/prim-tls.h:170-190` /
// `src/prim/prim-tls.c:34-38`, plus surrounding process ordering in
// `src/init.c:505-550`.
//
// The C source keeps one 16 KiB delayed byte buffer, one lock, independently
// published output function/argument pointers, and an AcqRel warning counter.
// This private owner preserves those observable transitions without exporting
// a `mi_*` ABI or putting callback state in the VM policy. The source's
// built-in callbacks are C statics and can reach static `out_buf` directly.
// Rust permits several test-local owners, so `default_sink` represents those
// three built-ins while the custom callback and opaque argument retain their
// separate source-shaped atomic publication. The source's `fputs(msg,stderr)`
// primitive stays caller-supplied: this owner does not assert that a raw Linux
// descriptor write has FILE buffering, locking, or failure equivalence.

use crate::lock::PrivateLock;
use crabc_core::thread::thread_pointer_identity;
use core::cell::UnsafeCell;
use core::ffi::{c_char, c_void, CStr};
use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicUsize, Ordering};

const INITIAL_MAX_WARNING_COUNT: isize = 16;
const DELAYED_OUTPUT_BYTES: usize = 16 * 1024;
const SOURCE_FORMAT_STORAGE_BYTES: usize = 992;
const SOURCE_FORMAT_PAYLOAD_BYTES: usize = SOURCE_FORMAT_STORAGE_BYTES - 2;

const DEFAULT_DELAYED: u8 = 0;
const DEFAULT_STDERR: u8 = 1;
const DEFAULT_STDERR_AND_DELAYED: u8 = 2;
const DEFAULT_CALLBACK: u8 = 3;

const THREAD_WARNING_PREFIX_BYTES: usize = 64;
const WARNING_PREFIX_HEAD: &[u8] = b"mimalloc: warning: thread 0x";
const WARNING_PREFIX_TAIL: &[u8] = b": ";

/// The three descriptors consumed by this intentionally partial M7 owner.
///
/// This mirrors only `show_errors`, `verbose`, and `max_warnings` in the
/// pinned table. It does not parse an environment, mutate options, or claim
/// any other `src/options.c` descriptor/API.
#[derive(Clone, Copy)]
pub(crate) struct DiagnosticOptionSnapshot {
    show_errors: isize,
    verbose: isize,
    max_warnings: isize,
}

impl DiagnosticOptionSnapshot {
    /// Constructs the exact scalar values used by the selected descriptors.
    #[inline]
    pub(crate) const fn new(show_errors: isize, verbose: isize, max_warnings: isize) -> Self {
        Self {
            show_errors,
            verbose,
            max_warnings,
        }
    }

    /// The pinned normal release defaults: `show_errors=0`, `verbose=0`, and
    /// `max_warnings=32`. `_mi_options_init` changes the static initial
    /// warning cap of 16 to this descriptor value before OS initialization.
    #[inline]
    pub(crate) const fn release_defaults() -> Self {
        Self::new(0, 0, 32)
    }

    #[inline]
    const fn show_errors_enabled(self) -> bool {
        self.show_errors != 0
    }

    #[inline]
    const fn verbose_enabled(self) -> bool {
        self.verbose != 0
    }
}

/// One stack-bounded, already source-formatted message.
///
/// Pinned `mi_vfprintf` has `char buf[992]` and calls `_mi_vsnprintf` with
/// `sizeof(buf)-1`; that formatter consequently emits at most 990 payload
/// bytes plus a terminating NUL. A complete M7 formatter must preserve its
/// format/sanitizing rules before constructing this value. This bounded owner
/// only receives the resulting message, copies it into this stack value, and
/// preserves its source truncation boundary without heap storage.
pub(crate) struct SourceFormattedMessage {
    bytes: [u8; SOURCE_FORMAT_STORAGE_BYTES],
    length: usize,
}

impl SourceFormattedMessage {
    /// Copies an already source-formatted C string through the pinned 990-byte
    /// payload limit. The current selected callers have static deterministic
    /// bodies; general variadic formatting remains open with M7.
    #[inline]
    pub(crate) fn from_source_formatted(message: &CStr) -> Self {
        let source = message.to_bytes();
        let length = core::cmp::min(source.len(), SOURCE_FORMAT_PAYLOAD_BYTES);
        let mut bytes = [0; SOURCE_FORMAT_STORAGE_BYTES];
        bytes[..length].copy_from_slice(&source[..length]);
        Self { bytes, length }
    }

    #[inline]
    fn as_c_str(&self) -> &CStr {
        // SAFETY: construction always places a zero byte immediately after
        // `length`, and only copies the NUL-free contents of a `CStr`.
        unsafe { CStr::from_bytes_with_nul_unchecked(&self.bytes[..=self.length]) }
    }
}

/// One source-sized `mi_vfprintf_thread` prefix for the selected warning.
///
/// Pinned `mi_vfprintf_thread` accepts the static 19-byte warning prefix,
/// forms `char tprefix[64]` with `_mi_snprintf`, and uses `%tx` for
/// `_mi_thread_id()`. `mi_out_num` writes zero as `0`, otherwise writes the
/// shortest uppercase base-16 representation. This private stack image keeps
/// exactly that selected valid-program boundary without general formatting.
struct ThreadWarningPrefix {
    bytes: [u8; THREAD_WARNING_PREFIX_BYTES],
    length: usize,
}

impl ThreadWarningPrefix {
    #[inline]
    fn new(thread_identity: usize) -> Self {
        let mut bytes = [0; THREAD_WARNING_PREFIX_BYTES];
        let mut length = WARNING_PREFIX_HEAD.len();
        bytes[..length].copy_from_slice(WARNING_PREFIX_HEAD);

        if thread_identity == 0 {
            bytes[length] = b'0';
            length += 1;
        } else {
            let mut reversed = [0; core::mem::size_of::<usize>() * 2];
            let mut value = thread_identity;
            let mut digits = 0;
            while value != 0 {
                let digit = (value & 0x0f) as u8;
                reversed[digits] = if digit < 10 { b'0' + digit } else { b'A' + digit - 10 };
                digits += 1;
                value >>= 4;
            }
            while digits != 0 {
                digits -= 1;
                bytes[length] = reversed[digits];
                length += 1;
            }
        }

        bytes[length..length + WARNING_PREFIX_TAIL.len()].copy_from_slice(WARNING_PREFIX_TAIL);
        length += WARNING_PREFIX_TAIL.len();
        debug_assert!(length < THREAD_WARNING_PREFIX_BYTES);
        Self { bytes, length }
    }

    #[inline]
    fn as_c_str(&self) -> &CStr {
        // SAFETY: the zero-initialized final byte follows the 46-byte visible
        // maximum, so the selected 64-bit C string occupies 47 bytes.
        unsafe { CStr::from_bytes_with_nul_unchecked(&self.bytes[..=self.length]) }
    }
}

/// The source `mi_output_fun` shape, retained as a private boundary.
///
/// No public ABI uses this alias yet. The callback receives one NUL-terminated
/// fragment at a time, so a warning emits its prefix and body in two calls.
pub(crate) type OutputCallback = unsafe extern "C" fn(*const c_char, *mut c_void);

/// Private source-shaped `_mi_prim_out_stderr` primitive.
///
/// The supplied function must retain the selected Linux/musl
/// `fputs(message, stderr)` transport contract, including the runtime-owned
/// FILE's locking, buffering, and error/short-write behavior. It receives a
/// non-null, nonempty NUL-terminated message and has no opaque allocator
/// state. The current diagnostic owner has no production receiver for this
/// primitive; a raw `write(2, ...)` substitute is not source-equivalent
/// evidence and cannot close that prerequisite.
pub(crate) type DefaultStderrOutput = unsafe extern "C" fn(*const c_char);

#[derive(Clone, Copy)]
enum DelayedFlushSink {
    Custom {
        output: OutputCallback,
        argument: *mut c_void,
    },
    DefaultStderr(DefaultStderrOutput),
}

/// Private owner for the selected `options.c` output and warning path.
///
/// The fixed delayed storage is intentionally the source `16*1024 + 1` image.
/// `UnsafeCell` is protected by `out_buf_lock`, whose successful acquisition
/// and release provide the critical-section ordering. The C source permits a
/// process to install one handler from one thread because independently stored
/// callback/argument values may otherwise mismatch; `register_output` keeps
/// that exact non-owning contract rather than adding a logger or registration
/// framework.
pub(crate) struct OutputOwner {
    out_buf: UnsafeCell<[u8; DELAYED_OUTPUT_BYTES + 1]>,
    out_len: AtomicUsize,
    out_buf_lock: PrivateLock,
    default_sink: AtomicU8,
    default_stderr_output: DefaultStderrOutput,
    callback: AtomicPtr<()>,
    argument: AtomicPtr<c_void>,
    warning_count: AtomicUsize,
    max_warning_count: isize,
}

// All delayed-byte mutation occurs under `out_buf_lock`. The callback's own
// aliasing and thread-safety obligations remain with the unsafe registration
// caller, matching the opaque source pointer contract.
unsafe impl Sync for OutputOwner {}

impl OutputOwner {
    /// Creates the source's pre-init diagnostic state with its FILE owner.
    ///
    /// `default_stderr_output` is the future private runtime integration
    /// receiver for the pinned `_mi_prim_out_stderr` primitive. It is fixed at
    /// construction because the source's `mi_out_stderr` callback is static;
    /// it is not a registered custom callback or VM policy field.
    #[inline]
    pub(crate) const fn new(default_stderr_output: DefaultStderrOutput) -> Self {
        Self {
            out_buf: UnsafeCell::new([0; DELAYED_OUTPUT_BYTES + 1]),
            out_len: AtomicUsize::new(0),
            out_buf_lock: PrivateLock::new(),
            default_sink: AtomicU8::new(DEFAULT_DELAYED),
            default_stderr_output,
            callback: AtomicPtr::new(core::ptr::null_mut()),
            argument: AtomicPtr::new(core::ptr::null_mut()),
            warning_count: AtomicUsize::new(0),
            max_warning_count: INITIAL_MAX_WARNING_COUNT,
        }
    }

    /// Performs this slice's `_mi_options_init` contribution before OS setup.
    ///
    /// The exclusive borrow encodes the source startup ordering: initialize
    /// the descriptor-derived maximum before the owner becomes shared with
    /// warning emitters. The source does not reset `warning_count` here.
    #[inline]
    pub(crate) fn initialize_options(&mut self, options: DiagnosticOptionSnapshot) {
        self.max_warning_count = options.max_warnings;
    }

    /// Installs the source's one non-owning custom output callback, or the
    /// `NULL` registration stderr route.
    ///
    /// # Safety
    ///
    /// For a non-null callback, `output` and `argument` must remain valid for
    /// every future delivery until a serialized replacement is installed. The
    /// program must register from one thread and must not race any registration
    /// or unrelated default dispatch: like `mi_register_output`, the separately
    /// Release-stored callback and argument can otherwise be observed as a
    /// mismatched pair. The callback/argument being replaced also remain live
    /// until all in-flight deliveries finish. A custom registration flushes
    /// delayed bytes while `out_buf_lock` is held; its callback must therefore
    /// not call `register_output` or `post_init`. Reentrant `raw_message` or
    /// `warning` from that just-installed custom callback is permitted after
    /// the custom default is published and bypasses the delayed-buffer lock.
    pub(crate) unsafe fn register_output(
        &self,
        output: Option<OutputCallback>,
        argument: *mut c_void,
    ) {
        match output {
            Some(callback) => {
                self.callback.store(callback_to_pointer(callback), Ordering::Release);
                // This is the source `mi_out_default` store. It intentionally
                // precedes the independent argument store below.
                self.default_sink.store(DEFAULT_CALLBACK, Ordering::Release);
                self.argument.store(argument, Ordering::Release);
                self.flush_delayed(
                    DelayedFlushSink::Custom {
                        output: callback,
                        argument,
                    },
                    true,
                );
            }
            None => {
                // Source `mi_register_output(NULL,arg)` installs stderr but
                // does not flush or terminally claim the delayed buffer.
                self.default_sink.store(DEFAULT_STDERR, Ordering::Release);
                self.argument.store(argument, Ordering::Release);
            }
        }
    }

    /// Performs `_mi_options_post_init`'s diagnostic transition.
    ///
    /// # Safety
    ///
    /// The caller must invoke this exactly once after automatic thread setup,
    /// before any custom registration, and after source-order option
    /// initialization. It must also serialize this transition against every
    /// unrelated `raw_message` or `warning` dispatch. Calling it from a
    /// callback is invalid because it takes the delayed-buffer lock while
    /// source registration flushing holds it.
    pub(crate) unsafe fn post_init(&self) {
        debug_assert_eq!(self.default_sink.load(Ordering::Relaxed), DEFAULT_DELAYED);
        self.flush_delayed(
            DelayedFlushSink::DefaultStderr(self.default_stderr_output),
            false,
        );
        self.default_sink
            .store(DEFAULT_STDERR_AND_DELAYED, Ordering::Release);
        self.argument.store(core::ptr::null_mut(), Ordering::Release);
    }

    /// Emits a preformatted source message through `_mi_fputs`' default path.
    ///
    /// # Safety
    ///
    /// The caller must serialize this dispatch against `register_output` and
    /// `post_init`, and retain any registered callback/argument until every
    /// in-flight delivery completes. The only permitted overlap is reentry
    /// from the just-installed custom callback during its own registration
    /// flush: the source has already published that default before invoking
    /// the callback. An unrelated thread must not dispatch while a callback
    /// pair is being installed or replaced, because the source intentionally
    /// publishes that pair in separate stores.
    #[inline]
    pub(crate) unsafe fn raw_message(&self, message: SourceFormattedMessage) {
        self.fputs_default(None, message.as_c_str());
    }

    /// Emits the selected `_mi_warning_message` path.
    ///
    /// # Safety
    ///
    /// This has the same dispatch-versus-registration and in-flight callback
    /// lifetime obligations as `raw_message`.
    #[inline]
    pub(crate) unsafe fn warning(
        &self,
        options: DiagnosticOptionSnapshot,
        message: SourceFormattedMessage,
    ) {
        if !options.verbose_enabled() {
            if !options.show_errors_enabled() {
                return;
            }
            if self.max_warning_count >= 0 {
                let count = self.warning_count.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
                if (count as isize) > self.max_warning_count {
                    return;
                }
            }
        }

        // The selected static warning prefix satisfies the source's 32-byte
        // `mi_vfprintf_thread` predicate. Preserve its one stack prefix and
        // separate prefix/body callback deliveries.
        let prefix = ThreadWarningPrefix::new(thread_pointer_identity());
        self.fputs_default(Some(prefix.as_c_str()), message.as_c_str());
    }

    fn fputs_default(&self, prefix: Option<&CStr>, message: &CStr) {
        // On the selected Linux profile, the source's recursion primitive is
        // the no-op/true implementation. The two dispatches remain distinct.
        if let Some(prefix) = prefix {
            self.dispatch_default(prefix);
        }
        self.dispatch_default(message);
    }

    fn dispatch_default(&self, message: &CStr) {
        match self.default_sink.load(Ordering::Acquire) {
            DEFAULT_DELAYED => self.delayed_output(message),
            DEFAULT_STDERR => self.default_stderr(message),
            DEFAULT_STDERR_AND_DELAYED => {
                self.default_stderr(message);
                self.delayed_output(message);
            }
            DEFAULT_CALLBACK => {
                let pointer = self.callback.load(Ordering::Acquire);
                let argument = self.argument.load(Ordering::Acquire);
                if !pointer.is_null() {
                    // SAFETY: `register_output`'s caller supplies the callback
                    // lifetime and single-registration-thread contract.
                    unsafe { invoke_callback(pointer_to_callback(pointer), message, argument) };
                }
            }
            _ => unreachable!("OutputOwner only publishes source-defined sinks"),
        }
    }

    fn delayed_output(&self, message: &CStr) {
        if self.out_len.load(Ordering::Acquire) >= DELAYED_OUTPUT_BYTES {
            return;
        }
        let mut length = message.to_bytes().len();
        if length == 0 || length >= DELAYED_OUTPUT_BYTES {
            return;
        }

        let Ok(_guard) = self.out_buf_lock.lock() else {
            // A valid process-private lock cannot fail here. `mi_lock_acquire`
            // reports its own impossible primitive error; this private port
            // drops this best-effort diagnostic rather than inventing a second
            // error recursion route without the full M7 error owner.
            return;
        };
        let start = self.out_len.fetch_add(length, Ordering::AcqRel);
        if start < DELAYED_OUTPUT_BYTES {
            if start + length >= DELAYED_OUTPUT_BYTES {
                length = DELAYED_OUTPUT_BYTES - start - 1;
            }
            // SAFETY: the lock serializes this mutable access. `start` is
            // below the fixed source maximum and `length` is clipped so the
            // copied range ends before its extra NUL byte.
            let buffer = unsafe { &mut *self.out_buf.get() };
            buffer[start..start + length].copy_from_slice(&message.to_bytes()[..length]);
        }
    }

    fn default_stderr(&self, message: &CStr) {
        // `mi_out_stderr` filters empty messages before it reaches the source
        // primitive, including ordinary NULL-registration dispatches.
        if message.to_bytes().is_empty() {
            return;
        }
        // SAFETY: `message` is source-shaped non-null/nonempty C text and the
        // constructor fixes this primitive for the owner's full lifetime.
        unsafe { (self.default_stderr_output)(message.as_ptr()) };
    }

    fn flush_delayed(&self, sink: DelayedFlushSink, no_more_buffer: bool) {
        let Ok(_guard) = self.out_buf_lock.lock() else {
            return;
        };
        let addend = if no_more_buffer { DELAYED_OUTPUT_BYTES } else { 1 };
        let mut count = self.out_len.fetch_add(addend, Ordering::AcqRel);
        if count > DELAYED_OUTPUT_BYTES {
            count = DELAYED_OUTPUT_BYTES;
        }
        // SAFETY: the lock serializes byte access and the source image has an
        // extra byte so `count == DELAYED_OUTPUT_BYTES` remains NUL-terminated.
        let buffer = unsafe { &mut *self.out_buf.get() };
        buffer[count] = 0;
        let message = buffer.as_ptr().cast::<c_char>();
        match sink {
            DelayedFlushSink::Custom { output, argument } => {
                // SAFETY: `buffer` stays live until this callback returns.
                // The custom callback's validity requirements are documented
                // on `register_output`.
                unsafe { output(message, argument) };
            }
            DelayedFlushSink::DefaultStderr(output) => {
                // `mi_out_stderr` filters the empty delayed image before it
                // reaches `_mi_prim_out_stderr`; preserve that boundary before
                // invoking the nonempty caller-supplied primitive.
                if buffer[0] != 0 {
                    // SAFETY: this is the constructor-fixed source primitive
                    // and `buffer` supplies its non-null NUL-terminated input.
                    unsafe { output(message) };
                }
            }
        }
        if !no_more_buffer {
            buffer[count] = b'\n';
        }
    }
}

#[inline]
fn callback_to_pointer(callback: OutputCallback) -> *mut () {
    callback as *const () as *mut ()
}

#[inline]
fn pointer_to_callback(pointer: *mut ()) -> OutputCallback {
    // SAFETY: only `callback_to_pointer` initializes this atomic storage, and
    // the non-null pointer is loaded before conversion.
    unsafe { core::mem::transmute(pointer) }
}

#[inline]
unsafe fn invoke_callback(callback: OutputCallback, message: &CStr, argument: *mut c_void) {
    // SAFETY: the caller supplies a source-shaped callback/opaque-argument
    // lifetime contract, and `message` remains valid for the call.
    unsafe { callback(message.as_ptr(), argument) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{
        DiagnosticOptionSnapshot, OutputCallback, OutputOwner, SourceFormattedMessage,
        ThreadWarningPrefix,
    };
    use crabc_core::thread::thread_pointer_identity;
    use core::cell::UnsafeCell;
    use core::ffi::{c_char, c_void, CStr};
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard};

    const MAX_MESSAGES: usize = 8;
    const MAX_MESSAGE_BYTES: usize = 256;

    struct Capture {
        count: AtomicUsize,
        lengths: UnsafeCell<[usize; MAX_MESSAGES]>,
        messages: UnsafeCell<[[u8; MAX_MESSAGE_BYTES]; MAX_MESSAGES]>,
    }

    // Test callbacks run on the registration/emission thread. The tests read
    // the fixed storage only after that callback route has returned.
    unsafe impl Sync for Capture {}

    impl Capture {
        const fn new() -> Self {
            Self {
                count: AtomicUsize::new(0),
                lengths: UnsafeCell::new([0; MAX_MESSAGES]),
                messages: UnsafeCell::new([[0; MAX_MESSAGE_BYTES]; MAX_MESSAGES]),
            }
        }

        fn reset(&self) {
            self.count.store(0, Ordering::Relaxed);
        }

        fn count(&self) -> usize {
            self.count.load(Ordering::Relaxed)
        }

        fn message(&self, index: usize) -> &[u8] {
            assert!(index < self.count());
            // SAFETY: callbacks are complete before each assertion reads the
            // single-threaded test capture.
            let lengths = unsafe { &*self.lengths.get() };
            // SAFETY: see the `lengths` access above.
            let messages = unsafe { &*self.messages.get() };
            &messages[index][..lengths[index]]
        }
    }

    unsafe extern "C" fn capture_output(message: *const c_char, argument: *mut c_void) {
        if message.is_null() || argument.is_null() {
            return;
        }
        // SAFETY: every test passes a live `Capture` as the opaque argument.
        let capture = unsafe { &*(argument as *const Capture) };
        // SAFETY: `OutputOwner` invokes an output callback with a NUL-terminated
        // source-form message whose storage remains live for the callback.
        let bytes = unsafe { CStr::from_ptr(message) }.to_bytes();
        let index = capture.count.fetch_add(1, Ordering::Relaxed);
        if index >= MAX_MESSAGES || bytes.len() > MAX_MESSAGE_BYTES {
            return;
        }
        // SAFETY: this test callback is single-threaded and writes its unique
        // fixed slot before the test reads it.
        unsafe {
            let messages = &mut *capture.messages.get();
            let lengths = &mut *capture.lengths.get();
            messages[index][..bytes.len()].copy_from_slice(bytes);
            lengths[index] = bytes.len();
        }
    }

    fn capture_argument(capture: &Capture) -> *mut c_void {
        capture as *const Capture as *mut c_void
    }

    fn assert_live_thread_warning_prefix(prefix: &[u8]) {
        let expected = std::format!(
            "mimalloc: warning: thread 0x{:X}: ",
            thread_pointer_identity(),
        );
        assert_eq!(prefix, expected.as_bytes());
    }

    static DEFAULT_STDERR_CAPTURE: Capture = Capture::new();
    static DEFAULT_STDERR_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn default_stderr_test_guard() -> MutexGuard<'static, ()> {
        DEFAULT_STDERR_TEST_LOCK
            .lock()
            .expect("default stderr capture lock is not poisoned")
    }

    unsafe extern "C" fn test_default_stderr_output(message: *const c_char) {
        // SAFETY: the test suite serializes this fixed test primitive and the
        // static capture remains live for every default delivery.
        unsafe { capture_output(message, capture_argument(&DEFAULT_STDERR_CAPTURE)) };
    }

    fn output_owner() -> OutputOwner {
        OutputOwner::new(test_default_stderr_output)
    }

    fn reset_default_stderr_capture() {
        DEFAULT_STDERR_CAPTURE.reset();
    }

    fn source_message(bytes: &[u8]) -> SourceFormattedMessage {
        SourceFormattedMessage::from_source_formatted(
            CStr::from_bytes_with_nul(bytes).expect("test messages are NUL-terminated"),
        )
    }

    struct LengthCapture {
        count: AtomicUsize,
        last_length: AtomicUsize,
    }

    impl LengthCapture {
        const fn new() -> Self {
            Self {
                count: AtomicUsize::new(0),
                last_length: AtomicUsize::new(0),
            }
        }
    }

    unsafe extern "C" fn capture_length(message: *const c_char, argument: *mut c_void) {
        if message.is_null() || argument.is_null() {
            return;
        }
        // SAFETY: this test passes a live `LengthCapture` and the owner holds
        // the source-shaped buffer live through the callback.
        let capture = unsafe { &*(argument as *const LengthCapture) };
        let length = unsafe { CStr::from_ptr(message) }.to_bytes().len();
        capture.last_length.store(length, Ordering::Relaxed);
        capture.count.fetch_add(1, Ordering::Relaxed);
    }

    #[test]
    fn source_formatted_message_retains_the_990_byte_vfprintf_payload_limit() {
        let mut source = [b'x'; 992];
        source[991] = 0;
        let source = CStr::from_bytes_with_nul(&source).expect("one terminal NUL");

        let bounded = SourceFormattedMessage::from_source_formatted(source);

        assert_eq!(bounded.as_c_str().to_bytes().len(), 990);
    }

    #[test]
    fn default_dispatch_and_registration_are_explicitly_unsafe_contracts() {
        let _ = OutputOwner::register_output
            as unsafe fn(&OutputOwner, Option<OutputCallback>, *mut c_void);
        let _ = OutputOwner::post_init as unsafe fn(&OutputOwner);
        let _ = OutputOwner::raw_message as unsafe fn(&OutputOwner, SourceFormattedMessage);
        let _ = OutputOwner::warning
            as unsafe fn(&OutputOwner, DiagnosticOptionSnapshot, SourceFormattedMessage);
    }

    #[test]
    fn delayed_output_keeps_at_most_16k_minus_its_terminal_nul_then_stops() {
        let owner = output_owner();
        let capture = LengthCapture::new();
        let mut source = [b'x'; 991];
        source[990] = 0;

        for _ in 0..17 {
            // SAFETY: the test has no concurrent registration or dispatch.
            unsafe { owner.raw_message(source_message(&source)) };
        }
        // SAFETY: this is the only registration, and the capture remains live.
        unsafe {
            owner.register_output(
                Some(capture_length),
                &capture as *const LengthCapture as *mut c_void,
            )
        };

        assert_eq!(capture.count.load(Ordering::Relaxed), 1);
        assert_eq!(capture.last_length.load(Ordering::Relaxed), 16 * 1024 - 1);

        // SAFETY: registration is complete before the final custom dispatch.
        unsafe { owner.raw_message(source_message(&source)) };
        assert_eq!(capture.count.load(Ordering::Relaxed), 2);
        assert_eq!(capture.last_length.load(Ordering::Relaxed), 990);
    }

    #[test]
    fn initialized_release_limit_replaces_the_initial_16_warning_cap() {
        let initial_owner = output_owner();
        let initial_capture = Capture::new();
        // SAFETY: the test owns the one callback and serializes all dispatch.
        unsafe {
            initial_owner.register_output(
                Some(capture_output),
                capture_argument(&initial_capture),
            )
        };
        initial_capture.reset();

        for _ in 0..17 {
            // SAFETY: no registration overlaps these isolated pre-init calls.
            unsafe {
                initial_owner.warning(
                    DiagnosticOptionSnapshot::new(1, 0, 32),
                    source_message(b"w\n\0"),
                )
            };
        }
        assert_eq!(initial_capture.count(), 32);

        let initialized_options = DiagnosticOptionSnapshot::new(1, 0, 32);
        let mut initialized_owner = output_owner();
        initialized_owner.initialize_options(DiagnosticOptionSnapshot::release_defaults());
        let initialized_capture = Capture::new();
        // SAFETY: the test owns the one callback and serializes all dispatch.
        unsafe {
            initialized_owner.register_output(
                Some(capture_output),
                capture_argument(&initialized_capture),
            )
        };
        initialized_capture.reset();

        for _ in 0..17 {
            // SAFETY: no registration overlaps these isolated initialized calls.
            unsafe { initialized_owner.warning(initialized_options, source_message(b"w\n\0")) };
        }
        assert_eq!(initialized_capture.count(), 34);
    }

    #[test]
    fn release_default_suppresses_warning_after_custom_registration() {
        let options = DiagnosticOptionSnapshot::release_defaults();
        let mut owner = output_owner();
        owner.initialize_options(options);
        let capture = Capture::new();

        // SAFETY: `capture` and its callback remain live and registration is
        // serialized for this source-shaped test owner.
        unsafe { owner.register_output(Some(capture_output), capture_argument(&capture)) };
        capture.reset(); // Registration flushes the source's empty delayed buffer.

        // SAFETY: this test serializes dispatch with the one registration.
        unsafe { owner.warning(options, source_message(b"selected mbind failure\n\0")) };

        assert_eq!(capture.count(), 0);
    }

    #[test]
    fn thread_warning_prefix_uses_source_zero_minimal_uppercase_and_64_byte_bounds() {
        assert_eq!(ThreadWarningPrefix::new(0).as_c_str().to_bytes(), b"mimalloc: warning: thread 0x0: ");
        assert_eq!(
            ThreadWarningPrefix::new(0x00a_bC0d).as_c_str().to_bytes(),
            b"mimalloc: warning: thread 0xABC0D: ",
        );
        let maximum = ThreadWarningPrefix::new(usize::MAX);
        assert_eq!(
            maximum.as_c_str().to_bytes(),
            b"mimalloc: warning: thread 0xFFFFFFFFFFFFFFFF: ",
        );
        assert_eq!(maximum.length, 46);
        assert_eq!(maximum.as_c_str().to_bytes_with_nul().len(), 47);
        assert!(maximum.length < 64);
    }

    #[test]
    fn enabled_warning_delivers_prefix_then_body() {
        let options = DiagnosticOptionSnapshot::new(1, 0, 1);
        let mut owner = output_owner();
        owner.initialize_options(options);
        let capture = Capture::new();

        // SAFETY: this test keeps the callback and opaque state alive and
        // performs the one source-permitted registration from one thread.
        unsafe { owner.register_output(Some(capture_output), capture_argument(&capture)) };
        capture.reset();

        // SAFETY: this test serializes dispatch with the one registration.
        unsafe { owner.warning(options, source_message(b"selected mbind failure\n\0")) };

        assert_eq!(capture.count(), 2);
        assert_live_thread_warning_prefix(capture.message(0));
        assert_eq!(capture.message(1), b"selected mbind failure\n");
    }

    #[test]
    fn warning_count_cap_suppresses_after_the_source_acqrel_increment() {
        let options = DiagnosticOptionSnapshot::new(1, 0, 1);
        let mut owner = output_owner();
        owner.initialize_options(options);
        let capture = Capture::new();

        // SAFETY: the callback/argument lifetime and serialized-registration
        // obligations hold for this test.
        unsafe { owner.register_output(Some(capture_output), capture_argument(&capture)) };
        capture.reset();

        // SAFETY: this test serializes dispatch with the one registration.
        unsafe {
            owner.warning(options, source_message(b"first\n\0"));
            owner.warning(options, source_message(b"second\n\0"));
        }

        assert_eq!(capture.count(), 2);
        assert_live_thread_warning_prefix(capture.message(0));
        assert_eq!(capture.message(1), b"first\n");
    }

    #[test]
    fn negative_warning_cap_leaves_the_source_counter_gate_unbounded() {
        let options = DiagnosticOptionSnapshot::new(1, 0, -1);
        let mut owner = output_owner();
        owner.initialize_options(options);
        let capture = Capture::new();

        // SAFETY: the callback/argument lifetime and serialized-registration
        // obligations hold for this test.
        unsafe { owner.register_output(Some(capture_output), capture_argument(&capture)) };
        capture.reset();

        // SAFETY: this test serializes dispatch with the one registration.
        unsafe {
            owner.warning(options, source_message(b"first\n\0"));
            owner.warning(options, source_message(b"second\n\0"));
        }

        assert_eq!(capture.count(), 4);
        assert_live_thread_warning_prefix(capture.message(0));
        assert_eq!(capture.message(1), b"first\n");
        assert_live_thread_warning_prefix(capture.message(2));
        assert_eq!(capture.message(3), b"second\n");
    }

    #[test]
    fn verbose_bypasses_show_errors_and_warning_cap() {
        let options = DiagnosticOptionSnapshot::new(0, 1, 0);
        let mut owner = output_owner();
        owner.initialize_options(options);
        let capture = Capture::new();

        // SAFETY: the callback/argument lifetime and serialized-registration
        // obligations hold for this test.
        unsafe { owner.register_output(Some(capture_output), capture_argument(&capture)) };
        capture.reset();

        // SAFETY: this test serializes dispatch with the one registration.
        unsafe {
            owner.warning(options, source_message(b"first\n\0"));
            owner.warning(options, source_message(b"second\n\0"));
        }

        assert_eq!(capture.count(), 4);
        assert_live_thread_warning_prefix(capture.message(0));
        assert_eq!(capture.message(1), b"first\n");
        assert_live_thread_warning_prefix(capture.message(2));
        assert_eq!(capture.message(3), b"second\n");
    }

    #[test]
    fn custom_registration_flushes_delayed_bytes_once_and_stops_the_buffer() {
        let owner = output_owner();
        let capture = Capture::new();

        // SAFETY: this test serializes each dispatch with registration.
        unsafe { owner.raw_message(source_message(b"early\n\0")) };
        // SAFETY: this one registration retains the callback state until the
        // test ends and is not concurrent with another registration.
        unsafe { owner.register_output(Some(capture_output), capture_argument(&capture)) };
        // SAFETY: registration is complete before this dispatch.
        unsafe { owner.raw_message(source_message(b"later\n\0")) };

        assert_eq!(capture.count(), 2);
        assert_eq!(capture.message(0), b"early\n");
        assert_eq!(capture.message(1), b"later\n");
    }

    #[test]
    fn null_registration_keeps_delayed_bytes_for_a_later_custom_registration() {
        let _guard = default_stderr_test_guard();
        let owner = output_owner();
        let capture = Capture::new();
        reset_default_stderr_capture();

        // SAFETY: this test serializes each dispatch with registration.
        unsafe { owner.raw_message(source_message(b"early\n\0")) };
        // SAFETY: the null route still follows the source's serialized
        // registration contract. Its argument is ignored by the stderr sink.
        unsafe { owner.register_output(None, core::ptr::null_mut()) };
        // SAFETY: the null default is installed before this serialized dispatch.
        unsafe { owner.raw_message(source_message(b"stderr\n\0")) };
        // SAFETY: the later custom callback remains live, and there is still
        // only one registration thread.
        unsafe { owner.register_output(Some(capture_output), capture_argument(&capture)) };

        assert_eq!(capture.count(), 1);
        assert_eq!(capture.message(0), b"early\n");
        assert_eq!(DEFAULT_STDERR_CAPTURE.count(), 1);
        assert_eq!(DEFAULT_STDERR_CAPTURE.message(0), b"stderr\n");
    }

    #[test]
    fn post_init_does_not_call_the_stderr_primitive_for_an_empty_delayed_buffer() {
        let _guard = default_stderr_test_guard();
        let owner = output_owner();
        reset_default_stderr_capture();

        // SAFETY: this isolated owner has no dispatch or custom registration.
        unsafe { owner.post_init() };

        assert_eq!(DEFAULT_STDERR_CAPTURE.count(), 0);
    }

    #[test]
    fn post_init_flushes_to_stderr_then_retains_newline_delayed_phase() {
        let _guard = default_stderr_test_guard();
        let owner = output_owner();
        let capture = Capture::new();
        reset_default_stderr_capture();

        // SAFETY: this test serializes each dispatch with post-init.
        unsafe { owner.raw_message(source_message(b"early\n\0")) };
        // SAFETY: the test invokes the source post-init transition before any
        // custom registration and after all pre-init emission for this owner.
        unsafe { owner.post_init() };
        // SAFETY: post-init is complete before this dispatch.
        unsafe { owner.raw_message(source_message(b"later\n\0")) };
        // SAFETY: this is the single custom registration and the capture
        // outlives every callback.
        unsafe { owner.register_output(Some(capture_output), capture_argument(&capture)) };

        assert_eq!(capture.count(), 1);
        assert_eq!(capture.message(0), b"early\n\nlater\n");
        assert_eq!(DEFAULT_STDERR_CAPTURE.count(), 2);
        assert_eq!(DEFAULT_STDERR_CAPTURE.message(0), b"early\n");
        assert_eq!(DEFAULT_STDERR_CAPTURE.message(1), b"later\n");
    }

    struct ReentrantCapture {
        capture: Capture,
        owner: *const OutputOwner,
        reentered: AtomicBool,
    }

    // The callback has the same source-level opaque-pointer obligations as a
    // normal capture; this test creates and consumes it on one thread.
    unsafe impl Sync for ReentrantCapture {}

    impl ReentrantCapture {
        fn new(owner: &OutputOwner) -> Self {
            Self {
                capture: Capture::new(),
                owner,
                reentered: AtomicBool::new(false),
            }
        }
    }

    unsafe extern "C" fn reentrant_output(message: *const c_char, argument: *mut c_void) {
        // SAFETY: the test passes a live `ReentrantCapture` for this callback.
        let capture = unsafe { &*(argument as *const ReentrantCapture) };
        // SAFETY: `capture.capture` has the same callback contract as above.
        unsafe { capture_output(message, capture_argument(&capture.capture)) };
        if !capture.reentered.swap(true, Ordering::Relaxed) {
            // SAFETY: the owner remains live through the registration callback.
            let owner = unsafe { &*capture.owner };
            // SAFETY: source permits this custom-callback reentry after that
            // same registration has published the custom default.
            unsafe { owner.raw_message(source_message(b"reentrant\n\0")) };
        }
    }

    #[test]
    fn registration_callback_can_reenter_default_dispatch_without_relocking_buffer() {
        let owner = output_owner();
        let capture = ReentrantCapture::new(&owner);
        // SAFETY: this test serializes the first dispatch with registration.
        unsafe { owner.raw_message(source_message(b"early\n\0")) };

        // SAFETY: this is one serialized registration. The callback and opaque
        // argument remain valid until it returns; its permitted reentrant
        // emission reaches the already-installed custom default directly.
        unsafe {
            owner.register_output(
                Some(reentrant_output as OutputCallback),
                &capture as *const ReentrantCapture as *mut c_void,
            )
        };

        assert_eq!(capture.capture.count(), 2);
        assert_eq!(capture.capture.message(0), b"early\n");
        assert_eq!(capture.capture.message(1), b"reentrant\n");
    }

    fn print_trace_capture(name: &str, capture: &Capture) {
        std::print!("{name}=");
        for index in 0..capture.count() {
            if index != 0 {
                std::print!(":");
            }
            for byte in capture.message(index) {
                std::print!("{byte:02x}");
            }
        }
        std::println!();
    }

    fn print_trace_thread_identity(name: &str, identity: usize) {
        std::println!("{name}={identity:x}");
    }

    fn print_default_stderr_line(name: &str, bytes: &[u8]) {
        std::eprint!("{name}=");
        for byte in bytes {
            std::eprint!("{byte:02x}");
        }
        std::eprintln!();
    }

    /// Machine-readable Rust half for the uncollected diagnostic C/Rust
    /// producer. The producer retains this raw stream and reconstructs the
    /// comparison from it; this test itself is not native evidence.
    #[test]
    fn diagnostic_output_owner_trace_for_future_pinned_c_comparison() {
        let _guard = default_stderr_test_guard();
        reset_default_stderr_capture();
        std::println!("CRABC_MI_DIAGNOSTIC_OUTPUT_OWNER_TRACE_BEGIN");

        let release = DiagnosticOptionSnapshot::release_defaults();
        let mut release_owner = output_owner();
        release_owner.initialize_options(release);
        let release_capture = Capture::new();
        // SAFETY: this fixture retains the callback state and has one
        // serialized registration.
        unsafe { release_owner.register_output(Some(capture_output), capture_argument(&release_capture)) };
        release_capture.reset();
        let release_thread_identity = thread_pointer_identity();
        // SAFETY: this fixture serializes dispatch with registration.
        unsafe { release_owner.warning(release, source_message(b"selected mbind failure\n\0")) };
        print_trace_capture("release", &release_capture);

        let enabled = DiagnosticOptionSnapshot::new(1, 0, 1);
        let mut enabled_owner = output_owner();
        enabled_owner.initialize_options(enabled);
        let enabled_capture = Capture::new();
        // SAFETY: this fixture retains the callback state and has one
        // serialized registration.
        unsafe { enabled_owner.register_output(Some(capture_output), capture_argument(&enabled_capture)) };
        enabled_capture.reset();
        let enabled_thread_identity = thread_pointer_identity();
        // SAFETY: this fixture serializes dispatch with registration.
        unsafe { enabled_owner.warning(enabled, source_message(b"selected mbind failure\n\0")) };
        print_trace_capture("enabled", &enabled_capture);

        let cap = DiagnosticOptionSnapshot::new(1, 0, 1);
        let mut cap_owner = output_owner();
        cap_owner.initialize_options(cap);
        let cap_capture = Capture::new();
        // SAFETY: this fixture retains the callback state and has one
        // serialized registration.
        unsafe { cap_owner.register_output(Some(capture_output), capture_argument(&cap_capture)) };
        cap_capture.reset();
        let cap_thread_identity = thread_pointer_identity();
        // SAFETY: this fixture serializes dispatch with registration.
        unsafe {
            cap_owner.warning(cap, source_message(b"first\n\0"));
            cap_owner.warning(cap, source_message(b"second\n\0"));
        }
        print_trace_capture("cap", &cap_capture);

        let verbose = DiagnosticOptionSnapshot::new(0, 1, 0);
        let mut verbose_owner = output_owner();
        verbose_owner.initialize_options(verbose);
        let verbose_capture = Capture::new();
        // SAFETY: this fixture retains the callback state and has one
        // serialized registration.
        unsafe { verbose_owner.register_output(Some(capture_output), capture_argument(&verbose_capture)) };
        verbose_capture.reset();
        let verbose_thread_identity = thread_pointer_identity();
        // SAFETY: this fixture serializes dispatch with registration.
        unsafe {
            verbose_owner.warning(verbose, source_message(b"first\n\0"));
            verbose_owner.warning(verbose, source_message(b"second\n\0"));
        }
        print_trace_capture("verbose", &verbose_capture);

        let delayed_owner = output_owner();
        let delayed_capture = Capture::new();
        let delayed_thread_identity = thread_pointer_identity();
        // SAFETY: this fixture serializes dispatch with registration.
        unsafe { delayed_owner.raw_message(source_message(b"early\n\0")) };
        // SAFETY: this fixture retains the callback state and has one
        // serialized registration.
        unsafe { delayed_owner.register_output(Some(capture_output), capture_argument(&delayed_capture)) };
        // SAFETY: registration is complete before this dispatch.
        unsafe { delayed_owner.raw_message(source_message(b"later\n\0")) };
        print_trace_capture("delayed", &delayed_capture);

        let null_owner = output_owner();
        let null_capture = Capture::new();
        let null_thread_identity = thread_pointer_identity();
        // SAFETY: this fixture serializes dispatch with registration.
        unsafe { null_owner.raw_message(source_message(b"early\n\0")) };
        // SAFETY: both registrations are serialized; the null route's
        // argument is ignored and the custom capture remains live.
        unsafe { null_owner.register_output(None, core::ptr::null_mut()) };
        // SAFETY: the null default is installed before this serialized dispatch.
        unsafe { null_owner.raw_message(source_message(b"stderr\n\0")) };
        // SAFETY: see the preceding registration.
        unsafe { null_owner.register_output(Some(capture_output), capture_argument(&null_capture)) };
        print_trace_capture("null", &null_capture);

        let post_owner = output_owner();
        let post_capture = Capture::new();
        let post_init_thread_identity = thread_pointer_identity();
        // SAFETY: this fixture serializes dispatch with post-init.
        unsafe { post_owner.raw_message(source_message(b"early\n\0")) };
        // SAFETY: this follows source post-init before custom registration.
        unsafe { post_owner.post_init() };
        // SAFETY: post-init is complete before this dispatch.
        unsafe { post_owner.raw_message(source_message(b"later\n\0")) };
        // SAFETY: this fixture retains the callback state and has one custom
        // registration after the source post-init transition.
        unsafe { post_owner.register_output(Some(capture_output), capture_argument(&post_capture)) };
        print_trace_capture("post_init", &post_capture);

        std::println!("CRABC_MI_DIAGNOSTIC_OUTPUT_OWNER_TRACE_END");
        std::println!("CRABC_MI_DIAGNOSTIC_OUTPUT_OWNER_THREAD_IDENTITIES_BEGIN");
        print_trace_thread_identity("release", release_thread_identity);
        print_trace_thread_identity("enabled", enabled_thread_identity);
        print_trace_thread_identity("cap", cap_thread_identity);
        print_trace_thread_identity("verbose", verbose_thread_identity);
        print_trace_thread_identity("delayed", delayed_thread_identity);
        print_trace_thread_identity("null", null_thread_identity);
        print_trace_thread_identity("post_init", post_init_thread_identity);
        std::println!("CRABC_MI_DIAGNOSTIC_OUTPUT_OWNER_THREAD_IDENTITIES_END");
        assert_eq!(DEFAULT_STDERR_CAPTURE.count(), 3);
        std::eprintln!("CRABC_MI_DIAGNOSTIC_OUTPUT_OWNER_DEFAULT_STDERR_BEGIN");
        print_default_stderr_line("release", b"");
        print_default_stderr_line("enabled", b"");
        print_default_stderr_line("cap", b"");
        print_default_stderr_line("verbose", b"");
        print_default_stderr_line("delayed", b"");
        print_default_stderr_line("null", DEFAULT_STDERR_CAPTURE.message(0));
        std::eprint!("post_init=");
        for index in 1..DEFAULT_STDERR_CAPTURE.count() {
            if index != 1 {
                std::eprint!(":");
            }
            for byte in DEFAULT_STDERR_CAPTURE.message(index) {
                std::eprint!("{byte:02x}");
            }
        }
        std::eprintln!();
        std::eprintln!("CRABC_MI_DIAGNOSTIC_OUTPUT_OWNER_DEFAULT_STDERR_END");
    }
}
