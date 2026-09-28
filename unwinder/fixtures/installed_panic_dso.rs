//! Panic cleanup and resume across one loaded C frame on a pthread worker.

use std::ffi::{c_char, c_int, c_void};
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};

type Callback = extern "C-unwind" fn(*mut c_void) -> c_int;
type CallThrough = unsafe extern "C-unwind" fn(Callback, *mut c_void) -> c_int;

const RTLD_NOW: c_int = 2;
const PLUGIN: &[u8] = b"libcrabc_unwind_frame_runtime.so\0";
const ENTRY: &[u8] = b"crabc_unwind_call_through\0";

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

extern "C-unwind" fn control(_argument: *mut c_void) -> c_int {
    7
}

extern "C-unwind" fn panics(argument: *mut c_void) -> c_int {
    // SAFETY: `round` keeps its counter alive until the DSO call returns.
    let drops = unsafe { &*argument.cast::<AtomicUsize>() };
    let _guard = Guard(drops);
    panic::panic_any(73usize)
}

extern "C-unwind" fn resumes(argument: *mut c_void) -> c_int {
    // SAFETY: `round` keeps its counter alive until the DSO call returns.
    let drops = unsafe { &*argument.cast::<AtomicUsize>() };
    let _guard = Guard(drops);
    let payload = panic::catch_unwind(|| panics(argument)).expect_err("inner panic must reach its catch");
    panic::resume_unwind(payload)
}

fn round(call: CallThrough, callback: Callback, expected_drops: usize, label: &str) {
    let drops = AtomicUsize::new(0);
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let _guard = Guard(&drops);
        // SAFETY: the callback and the counter remain live throughout the synchronous call.
        unsafe { call(callback, (&drops as *const AtomicUsize).cast_mut().cast()) }
    }));
    let payload = result.expect_err("panic must cross the mapped DSO frame");
    assert_eq!(*payload.downcast::<usize>().expect("panic payload"), 73);
    assert_eq!(drops.load(Ordering::SeqCst), expected_drops);
    println!("panic {label} drops={expected_drops}");
}

fn main() {
    panic::set_hook(Box::new(|_| {}));
    // SAFETY: the names are NUL terminated and the handle remains open through worker join.
    let call: CallThrough = unsafe {
        let handle = dlopen(PLUGIN.as_ptr().cast(), RTLD_NOW);
        assert!(!handle.is_null(), "owned loader must map the runtime DSO");
        let symbol = dlsym(handle, ENTRY.as_ptr().cast());
        assert!(!symbol.is_null(), "runtime DSO must export the C frame");
        std::mem::transmute(symbol)
    };
    // SAFETY: the callback uses no argument and the DSO stays mapped.
    assert_eq!(unsafe { call(control, std::ptr::null_mut()) }, 8);
    println!("panic mapped-control=8");
    round(call, panics, 2, "direct main");
    round(call, resumes, 3, "resume main");
    std::thread::spawn(move || {
        round(call, panics, 2, "direct worker");
        round(call, resumes, 3, "resume worker");
    }).join().expect("worker panic crossed catch boundaries");
    println!("panic worker-join=0");
}
