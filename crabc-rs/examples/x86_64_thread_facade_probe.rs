//! Native x86-64 `runtime_thread` facade scenario for the installed product.
//!
//! `compat/x86_64/runtime_private_facades_thread.c` drives this archive and
//! supplies `crabc_x86_64_thread_facade_c_self`, the public `pthread_self`
//! observation used as the identity oracle. Every thread, key, and
//! cancellation operation here reaches only the private RuntimeV1 table.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::ffi::{c_int, c_void};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crabc_rs::runtime_thread::{
    cancel, current, set_cancellation_state, set_cancellation_type, spawn, spawn_raw,
    test_cancellation, CancellationState, CancellationType, Key,
};
use crabc_rs::Errno;

extern "C" {
    /// The C driver's `pthread_self()` for the calling thread.
    fn crabc_x86_64_thread_facade_c_self() -> u64;
}

/// Fixed bump allocator: the probe must not import the C allocator.
struct ProbeAllocator;

const HEAP_SIZE: usize = 64 * 1024;
static NEXT: AtomicUsize = AtomicUsize::new(0);
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

unsafe impl GlobalAlloc for ProbeAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let base = core::ptr::addr_of_mut!(HEAP).cast::<u8>() as usize;
        loop {
            let current = NEXT.load(Ordering::Relaxed);
            let aligned = (base + current + layout.align() - 1) & !(layout.align() - 1);
            let Some(end) = (aligned - base).checked_add(layout.size()) else {
                return core::ptr::null_mut();
            };
            if end > HEAP_SIZE {
                return core::ptr::null_mut();
            }
            if NEXT.compare_exchange(current, end, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                return aligned as *mut u8;
            }
        }
    }

    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
}

#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: `ud2` raises SIGILL, ending this probe process immediately.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

const CANCELED: usize = usize::MAX;
static WORKER_ID: AtomicU64 = AtomicU64::new(0);
static WORKER_C_SELF: AtomicU64 = AtomicU64::new(1);
static DESTROYED: AtomicUsize = AtomicUsize::new(0);
static DESTROYED_VALUE: AtomicUsize = AtomicUsize::new(0);
static KEY: AtomicUsize = AtomicUsize::new(0);
static READY: AtomicUsize = AtomicUsize::new(0);
static RELEASE: AtomicUsize = AtomicUsize::new(0);
static FINISHED: AtomicUsize = AtomicUsize::new(0);

fn wait_for(flag: &AtomicUsize, value: usize) {
    while flag.load(Ordering::Acquire) != value {
        core::hint::spin_loop();
    }
}

unsafe extern "C" fn identity_worker(argument: *mut c_void) -> *mut c_void {
    let id = current().map_or(0, |id| id.as_raw());
    WORKER_ID.store(id, Ordering::Release);
    // SAFETY: the C driver defines this plain observation.
    WORKER_C_SELF.store(unsafe { crabc_x86_64_thread_facade_c_self() }, Ordering::Release);
    argument
}

unsafe extern "C" fn destroy_value(value: *mut c_void) {
    DESTROYED_VALUE.store(value as usize, Ordering::Release);
    DESTROYED.fetch_add(1, Ordering::AcqRel);
}

unsafe extern "C" fn key_worker(argument: *mut c_void) -> *mut c_void {
    // SAFETY: KEY holds a live `Key` owned by the main scenario until join.
    let key = unsafe { &*(KEY.load(Ordering::Acquire) as *const Key) };
    if key.get().is_some() {
        return core::ptr::null_mut();
    }
    let value = NonNull::new(argument);
    // SAFETY: the marker is never dereferenced; the destructor only records it.
    if unsafe { key.set(value) }.is_err() || key.get() != value {
        return core::ptr::null_mut();
    }
    argument
}

unsafe extern "C" fn cancellable_worker(_: *mut c_void) -> *mut c_void {
    READY.store(1, Ordering::Release);
    loop {
        // SAFETY: this worker owns no Rust state which cancellation could
        // abandon; its result is only compared with PTHREAD_CANCELED.
        let _ = unsafe { test_cancellation() };
        core::hint::spin_loop();
    }
}

unsafe extern "C" fn shielded_worker(argument: *mut c_void) -> *mut c_void {
    // SAFETY: disabling cancellation cannot interrupt this worker.
    if unsafe { set_cancellation_state(CancellationState::Disabled) } != Ok(CancellationState::Enabled) {
        return core::ptr::null_mut();
    }
    READY.store(2, Ordering::Release);
    wait_for(&RELEASE, 1);
    // SAFETY: cancellation is disabled, so this point must return.
    let _ = unsafe { test_cancellation() };
    argument
}

unsafe extern "C" fn finishing_worker(argument: *mut c_void) -> *mut c_void {
    FINISHED.fetch_add(1, Ordering::AcqRel);
    argument
}

fn identity() -> c_int {
    let Ok(main) = current() else { return 1 };
    // SAFETY: the callback only publishes identities and returns its marker.
    let Ok(worker) = (unsafe { spawn_raw(identity_worker, 0x4d37 as *mut c_void) }) else { return 2 };
    let Some(id) = worker.id() else { return 3 };
    if worker.join() != Ok(0x4d37 as *mut c_void) {
        return 4;
    }
    let observed = WORKER_ID.load(Ordering::Acquire);
    if observed != id.as_raw() || observed == main.as_raw() || observed != WORKER_C_SELF.load(Ordering::Acquire) {
        return 5;
    }
    0
}

fn typed_spawn() -> c_int {
    let owned = Vec::from([3u64, 5, 7]);
    let Ok(worker) = spawn(move || owned.iter().sum::<u64>() * 2) else { return 10 };
    if worker.join() != Ok(30) {
        return 11;
    }
    0
}

fn keys() -> c_int {
    // SAFETY: the destructor only records its opaque argument.
    let Ok(key) = (unsafe { Key::with_destructor(destroy_value) }) else { return 20 };
    KEY.store(&key as *const Key as usize, Ordering::Release);
    let marker = 0x7100usize as *mut c_void;
    // SAFETY: the worker only stores and reads the opaque marker.
    let Ok(worker) = (unsafe { spawn_raw(key_worker, marker) }) else { return 21 };
    if worker.join() != Ok(marker) {
        return 22;
    }
    // The worker's value was destroyed at its exit; main never set one.
    if DESTROYED.load(Ordering::Acquire) != 1 || DESTROYED_VALUE.load(Ordering::Acquire) != marker as usize {
        return 23;
    }
    if key.get().is_some() {
        return 24;
    }
    let own = NonNull::new(0x7200usize as *mut c_void);
    // SAFETY: main's marker is never dereferenced and is cleared by delete.
    if unsafe { key.set(own) }.is_err() || key.get() != own {
        return 25;
    }
    if key.delete().is_err() || DESTROYED.load(Ordering::Acquire) != 1 {
        return 26;
    }
    // Exhaustion is transported as the positive pthread EAGAIN status.
    let mut created = Vec::new();
    let exhausted = loop {
        match Key::new() {
            Ok(key) if created.len() < 256 => created.push(key),
            Ok(_) => return 27,
            Err(error) => break error,
        }
    };
    if exhausted != Errno::AGAIN || created.is_empty() {
        return 28;
    }
    for key in created {
        if key.delete().is_err() {
            return 29;
        }
    }
    match Key::new().map(Key::delete) {
        Ok(Ok(())) => 0,
        _ => 30,
    }
}

fn cancellation() -> c_int {
    // SAFETY: no cancellation is pending on the main thread.
    if unsafe { set_cancellation_state(CancellationState::Disabled) } != Ok(CancellationState::Enabled)
        || unsafe { set_cancellation_type(CancellationType::Deferred) } != Ok(CancellationType::Deferred)
        || unsafe { set_cancellation_state(CancellationState::Enabled) } != Ok(CancellationState::Disabled)
    {
        return 40;
    }
    // SAFETY: the worker tolerates abandonment at its cancellation point.
    let Ok(worker) = (unsafe { spawn_raw(cancellable_worker, core::ptr::null_mut()) }) else { return 41 };
    let Some(id) = worker.id() else { return 42 };
    wait_for(&READY, 1);
    // SAFETY: `id` names the raw cancellable worker above, not a typed spawn.
    if unsafe { cancel(id) }.is_err() {
        return 43;
    }
    if worker.join() != Ok(CANCELED as *mut c_void) {
        return 44;
    }
    // SAFETY: the shielded worker disables cancellation before its point.
    let Ok(worker) = (unsafe { spawn_raw(shielded_worker, 0x5300 as *mut c_void) }) else { return 45 };
    let Some(id) = worker.id() else { return 46 };
    wait_for(&READY, 2);
    // SAFETY: as above; the request stays pending while disabled.
    if unsafe { cancel(id) }.is_err() {
        return 47;
    }
    RELEASE.store(1, Ordering::Release);
    if worker.join() != Ok(0x5300 as *mut c_void) {
        return 48;
    }
    0
}

fn detach() -> c_int {
    // SAFETY: the callback only counts completion.
    let Ok(worker) = (unsafe { spawn_raw(finishing_worker, core::ptr::null_mut()) }) else { return 50 };
    if worker.detach().is_err() {
        return 51;
    }
    // SAFETY: as above; dropping the handle performs the detach.
    let Ok(dropped) = (unsafe { spawn_raw(finishing_worker, core::ptr::null_mut()) }) else { return 52 };
    drop(dropped);
    wait_for(&FINISHED, 2);
    0
}

/// Returns the facade's current thread identity.
///
/// # Safety
/// `id` is writable.
#[no_mangle]
pub unsafe extern "C" fn crabc_rs_x86_64_thread_facade_current(id: *mut u64) -> c_int {
    match current() {
        Ok(current) if !id.is_null() => {
            unsafe { *id = current.as_raw() };
            0
        }
        _ => 1,
    }
}

/// Runs the ownership, identity, TSD, cancellation, and detach scenario.
#[no_mangle]
pub extern "C" fn crabc_rs_x86_64_thread_facade_probe() -> c_int {
    for step in [identity, typed_spawn, keys, cancellation, detach] {
        let result = step();
        if result != 0 {
            return result;
        }
    }
    0
}
