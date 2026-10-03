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
use std::cell::RefCell;
use std::ffi::{c_char, c_int, c_void};
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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
    fn dlclose(handle: *mut c_void) -> c_int;
    fn dl_iterate_phdr(callback: unsafe extern "C" fn(*mut PhdrInfo, usize, *mut c_void) -> c_int,
                       data: *mut c_void) -> c_int;
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Phdr {
    kind: u32, flags: u32, offset: u64, address: u64, physical: u64,
    file_size: u64, memory_size: u64, alignment: u64,
}

#[repr(C)]
struct PhdrInfo {
    address: usize, name: *const c_char, headers: *const Phdr, count: u16,
}

struct CloseDuringVisit {
    handle: *mut c_void,
    function: usize,
    closed: bool,
}

unsafe extern "C" fn close_runtime_mapping(info: *mut PhdrInfo, size: usize, data: *mut c_void) -> c_int {
    assert!(size >= std::mem::size_of::<PhdrInfo>());
    // SAFETY: enumeration supplies its live ABI prefix and the synchronous
    // caller supplies one exclusive state pointer for the entire visit.
    let state = unsafe { &mut *data.cast::<CloseDuringVisit>() };
    let base = unsafe { (*info).address };
    let headers = unsafe { (*info).headers };
    let count = unsafe { (*info).count };
    for index in 0..usize::from(count) {
        // SAFETY: the loader's count describes its live program-header table.
        let header = unsafe { headers.add(index).read() };
        if header.kind != 1 || header.flags & 1 == 0 {
            continue;
        }
        let start = base.checked_add(header.address as usize).unwrap();
        let end = start.checked_add(header.memory_size as usize).unwrap();
        if !(start..end).contains(&state.function) {
            continue;
        }
        // SAFETY: the callback's loader-owned name is live and NUL terminated.
        let name = unsafe { std::ffi::CStr::from_ptr((*info).name) }.to_bytes();
        assert_eq!(name.rsplit(|byte| *byte == b'/').next().unwrap(),
                   &RUNTIME_DSO[..RUNTIME_DSO.len() - 1]);
        assert!((0..usize::from(count)).any(|entry| unsafe { headers.add(entry).read().kind == 0x6474e550 }));
        // SAFETY: this is the sole live handle returned by our successful
        // dlopen. The selected loader retains admitted mappings after close,
        // including their program headers and executable unwind frames.
        assert_eq!(unsafe { dlclose(state.handle) }, 0);
        let after = unsafe { headers.add(index).read() };
        assert_eq!((after.kind, after.address, after.memory_size),
                   (header.kind, header.address, header.memory_size));
        state.closed = true;
        return 7;
    }
    0
}

struct Guard<'a> {
    drops: &'a AtomicUsize,
    bytes: Vec<u8>,
}

impl<'a> Guard<'a> {
    fn new(drops: &'a AtomicUsize) -> Self {
        Self { drops, bytes: vec![0x37; 16 * 1024] }
    }
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        assert!(self.bytes.iter().all(|byte| *byte == 0x37));
        // Exercise the calling thread's allocator while compiler-generated
        // unwind cleanup still owns its earlier allocation.
        let scratch = vec![0x71; 32 * 1024];
        assert!(scratch.iter().all(|byte| *byte == 0x71));
        drop(scratch);
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

struct WorkerRetirement {
    completed: Arc<AtomicUsize>,
    parent_bytes: Vec<u8>,
}

impl Drop for WorkerRetirement {
    fn drop(&mut self) {
        assert!(self.parent_bytes.iter().all(|byte| *byte == 0x53));
        let scratch = vec![0x29; 32 * 1024];
        assert!(scratch.iter().all(|byte| *byte == 0x29));
        drop(scratch);
        self.completed.fetch_add(1, Ordering::SeqCst);
    }
}

struct WorkerTls {
    marker: usize,
    retirement: Option<WorkerRetirement>,
}

impl Drop for WorkerTls {
    fn drop(&mut self) {
        if self.retirement.is_some() {
            assert_eq!(self.marker, 99);
            // Release the parent's allocation and allocate during TLS
            // destruction, before this worker retires its allocator owner.
            drop(self.retirement.take());
        }
    }
}

thread_local! {
    static WORKER_TLS: RefCell<WorkerTls> = const {
        RefCell::new(WorkerTls { marker: 47, retirement: None })
    };
}

extern "C-unwind" fn panics(argument: *mut c_void) -> c_int {
    // SAFETY: every caller passes a live `AtomicUsize` for the call's duration.
    let drops = unsafe { &*argument.cast::<AtomicUsize>() };
    let _guard = Guard::new(drops);
    assert_eq!(Backtrace::force_capture().status(), BacktraceStatus::Captured);
    panic::panic_any(73usize)
}

extern "C-unwind" fn resumes(argument: *mut c_void) -> c_int {
    // SAFETY: as for `panics`.
    let drops = unsafe { &*argument.cast::<AtomicUsize>() };
    let _guard = Guard::new(drops);
    let payload = panic::catch_unwind(|| panics(argument)).expect_err("inner panic must be caught");
    panic::resume_unwind(payload)
}

#[inline(never)]
fn round(call_through: CallThrough, callback: Callback, expected_drops: usize) {
    let drops = AtomicUsize::new(0);
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let _guard = Guard::new(&drops);
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

fn runtime_call_through(retained: bool) -> CallThrough {
    // SAFETY: the name is NUL-terminated. The selected loader retains the
    // admitted mapping even when the optional visit closes its last handle.
    unsafe {
        let handle = dlopen(RUNTIME_DSO.as_ptr().cast(), RTLD_NOW);
        assert!(!handle.is_null(), "runtime DSO must load by basename");
        let symbol = dlsym(handle, CALL_THROUGH.as_ptr().cast());
        assert!(!symbol.is_null(), "runtime DSO must export its C frame");
        if retained {
            let mut state = CloseDuringVisit { handle, function: symbol as usize, closed: false };
            assert_eq!(dl_iterate_phdr(close_runtime_mapping, (&mut state as *mut CloseDuringVisit).cast()), 7);
            assert!(state.closed, "enumeration must visit the runtime DSO");
        }
        std::mem::transmute::<*mut c_void, CallThrough>(symbol)
    }
}

fn main() {
    panic::set_hook(Box::new(|_| {}));
    let initial: CallThrough = crabc_unwind_call_through;
    let runtime = runtime_call_through(std::env::args().nth(1).as_deref() == Some("--retained-runtime"));
    WORKER_TLS.with(|state| state.borrow_mut().marker = 101);
    for call_through in [initial, runtime] {
        rounds(call_through);
        for _ in 0..2 {
            let completed = Arc::new(AtomicUsize::new(0));
            let retirement = WorkerRetirement {
                completed: completed.clone(),
                parent_bytes: vec![0x53; 64 * 1024],
            };
            std::thread::spawn(move || {
                WORKER_TLS.with(|state| {
                    let mut state = state.borrow_mut();
                    assert_eq!(state.marker, 47);
                    assert!(state.retirement.is_none());
                    state.marker = 99;
                    state.retirement = Some(retirement);
                });
                rounds(call_through);
            }).join().expect("worker rounds and TLS cleanup");
            assert_eq!(completed.load(Ordering::SeqCst), 1);
            WORKER_TLS.with(|state| assert_eq!(state.borrow().marker, 101));
        }
    }
    println!("unwind: cross-dso cleanup resume initial runtime main worker");
}
