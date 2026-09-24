//! Rust panics unwinding through C frames in initial and runtime DSOs.
//!
//! Each round passes a Rust callback through `crabc_unwind_call_through`, a C
//! function in another ELF object. The callback captures a backtrace (which
//! walks the DSO frame back into this executable), holds a `Drop` guard, and
//! panics; the panic crosses the C frame, runs the caller's guard, and is
//! caught here. A second round catches the first payload inside the callback
//! and `resume_unwind`s it across the same C frame. Rounds run for the
//! DT_NEEDED DSO and a dlopen'd DSO, on the main thread and a worker.

use std::backtrace::{Backtrace, BacktraceStatus};
use std::ffi::{c_char, c_int, c_void};
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};

type Callback = extern "C-unwind" fn(*mut c_void) -> c_int;
type CallThrough = unsafe extern "C-unwind" fn(Callback, *mut c_void) -> c_int;

const RTLD_NOW: c_int = 2;
const RUNTIME_DSO: &[u8] = b"libcrabc_unwind_frame_runtime.so\0";
const CALL_THROUGH: &[u8] = b"crabc_unwind_call_through\0";

#[link(name = "crabc_unwind_frame_initial")]
unsafe extern "C-unwind" {
    fn crabc_unwind_call_through(callback: Callback, argument: *mut c_void) -> c_int;
}

#[link(name = "dl")]
unsafe extern "C" {
    fn dlopen(path: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

struct Guard<'a>(&'a AtomicUsize);

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

extern "C-unwind" fn panics(argument: *mut c_void) -> c_int {
    // SAFETY: every caller passes a live `AtomicUsize` for the call's duration.
    let drops = unsafe { &*argument.cast::<AtomicUsize>() };
    let _guard = Guard(drops);
    assert_eq!(Backtrace::force_capture().status(), BacktraceStatus::Captured);
    panic::panic_any(73usize)
}

extern "C-unwind" fn resumes(argument: *mut c_void) -> c_int {
    // SAFETY: as for `panics`.
    let drops = unsafe { &*argument.cast::<AtomicUsize>() };
    let _guard = Guard(drops);
    let payload = panic::catch_unwind(|| panics(argument)).expect_err("inner panic must be caught");
    panic::resume_unwind(payload)
}

#[inline(never)]
fn round(call_through: CallThrough, callback: Callback, expected_drops: usize) {
    let drops = AtomicUsize::new(0);
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let _guard = Guard(&drops);
        // SAFETY: the callback and its argument outlive this call.
        unsafe { call_through(callback, (&drops as *const AtomicUsize).cast_mut().cast()) }
    }));
    let payload = result.expect_err("panic must cross the C frame");
    assert_eq!(*payload.downcast::<usize>().expect("payload identity"), 73);
    assert_eq!(drops.load(Ordering::SeqCst), expected_drops);
}

fn rounds(call_through: CallThrough) {
    // Callback guard plus caller guard; `resumes` adds its own guard.
    round(call_through, panics, 2);
    round(call_through, resumes, 3);
}

fn runtime_call_through() -> CallThrough {
    // SAFETY: the name is NUL-terminated and the handle is never closed, so
    // the resolved function stays mapped for the process lifetime.
    unsafe {
        let handle = dlopen(RUNTIME_DSO.as_ptr().cast(), RTLD_NOW);
        assert!(!handle.is_null(), "runtime DSO must load by basename");
        let symbol = dlsym(handle, CALL_THROUGH.as_ptr().cast());
        assert!(!symbol.is_null(), "runtime DSO must export its C frame");
        std::mem::transmute::<*mut c_void, CallThrough>(symbol)
    }
}

fn main() {
    panic::set_hook(Box::new(|_| {}));
    let initial: CallThrough = crabc_unwind_call_through;
    let runtime = runtime_call_through();
    for call_through in [initial, runtime] {
        rounds(call_through);
        std::thread::spawn(move || rounds(call_through)).join().expect("worker rounds");
    }
    println!("unwind: cross-dso cleanup resume initial runtime main worker");
}
