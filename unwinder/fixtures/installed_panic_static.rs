//! Panic cleanup and resume across a C frame linked into an owned static image.

use std::ffi::{c_int, c_void};
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};

type Callback = extern "C-unwind" fn(*mut c_void) -> c_int;

unsafe extern "C-unwind" {
    fn crabc_unwind_call_through(callback: Callback, argument: *mut c_void) -> c_int;
}

struct Guard<'a>(&'a AtomicUsize);

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

extern "C-unwind" fn control(_argument: *mut c_void) -> c_int {
    7
}

extern "C-unwind" fn panics(argument: *mut c_void) -> c_int {
    // SAFETY: `round` keeps the counter alive until the C call returns.
    let drops = unsafe { &*argument.cast::<AtomicUsize>() };
    let _guard = Guard(drops);
    panic::panic_any(73usize)
}

extern "C-unwind" fn resumes(argument: *mut c_void) -> c_int {
    // SAFETY: `round` keeps the counter alive until the C call returns.
    let drops = unsafe { &*argument.cast::<AtomicUsize>() };
    let _guard = Guard(drops);
    let payload = panic::catch_unwind(|| panics(argument)).expect_err("inner panic must reach its catch");
    panic::resume_unwind(payload)
}

fn round(callback: Callback, expected_drops: usize, label: &str) {
    let drops = AtomicUsize::new(0);
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let _guard = Guard(&drops);
        // SAFETY: the callback and the counter stay live during the synchronous C call.
        unsafe { crabc_unwind_call_through(callback, (&drops as *const AtomicUsize).cast_mut().cast()) }
    }));
    let payload = result.expect_err("panic must cross the linked C frame");
    assert_eq!(*payload.downcast::<usize>().expect("panic payload"), 73);
    assert_eq!(drops.load(Ordering::SeqCst), expected_drops);
    println!("panic {label} drops={expected_drops}");
}

fn main() {
    panic::set_hook(Box::new(|_| {}));
    // SAFETY: `control` ignores its argument.
    assert_eq!(unsafe { crabc_unwind_call_through(control, std::ptr::null_mut()) }, 8);
    println!("panic static-control=8");
    round(panics, 2, "direct main");
    round(resumes, 3, "resume main");
    std::thread::spawn(|| {
        round(panics, 2, "direct worker");
        round(resumes, 3, "resume worker");
    }).join().expect("worker panic crossed catch boundaries");
    println!("panic worker-join=0");
}
