//! Native behavior probe for the unintegrated x86-64 libc atomic leaf.
//!
//! This executable imports only `libc/src/c_abi/x86_64/atomic.rs`. It does
//! not select or link `crabc-libc`; the module remains source-only evidence
//! until the surrounding x86 C ABI and runtime state are implemented.

#[allow(dead_code)]
#[path = "../../libc/src/c_abi/x86_64/atomic.rs"]
mod atomic;

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

#[no_mangle]
#[inline(never)]
pub extern "C" fn crabc_x86_atomic_probe_compare_exchange(
    address: *mut i32,
    expected: i32,
    desired: i32,
) -> i32 {
    // SAFETY: callers pass the live, aligned `AtomicI32` storage used by the
    // probe. The leaf's exact concurrent-access contract is tested below.
    unsafe { atomic::x86_64_compare_exchange_acqrel_i32(address, expected, desired) }
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn crabc_x86_atomic_probe_swap(address: *mut i32, desired: i32) -> i32 {
    // SAFETY: callers pass the live, aligned `AtomicI32` storage used by the
    // probe.
    unsafe { atomic::x86_64_swap_acqrel_i32(address, desired) }
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn crabc_x86_atomic_probe_fetch_add(address: *mut i32, value: i32) -> i32 {
    // SAFETY: callers pass the live, aligned `AtomicI32` storage used by the
    // probe.
    unsafe { atomic::x86_64_fetch_add_acqrel_i32(address, value) }
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn crabc_x86_atomic_probe_fetch_sub(address: *mut i32, value: i32) -> i32 {
    // SAFETY: callers pass the live, aligned `AtomicI32` storage used by the
    // probe.
    unsafe { atomic::x86_64_fetch_sub_acqrel_i32(address, value) }
}

fn main() {
    let slot = AtomicI32::new(7);
    let address = slot.as_ptr();
    assert_eq!(address as usize % std::mem::align_of::<i32>(), 0);

    // A matching compare-exchange returns the old value and stores desired.
    assert_eq!(
        crabc_x86_atomic_probe_compare_exchange(address, 7, 11),
        7
    );
    assert_eq!(slot.load(Ordering::Relaxed), 11);

    // A mismatch returns the observed value and leaves storage unchanged.
    assert_eq!(
        crabc_x86_atomic_probe_compare_exchange(address, 7, 13),
        11
    );
    assert_eq!(slot.load(Ordering::Relaxed), 11);

    assert_eq!(crabc_x86_atomic_probe_swap(address, 19), 11);
    assert_eq!(slot.load(Ordering::Relaxed), 19);

    // Both directions wrap at the i32 boundary, just like AtomicI32.
    slot.store(i32::MAX, Ordering::Relaxed);
    assert_eq!(
        crabc_x86_atomic_probe_fetch_add(address, 1),
        i32::MAX
    );
    assert_eq!(slot.load(Ordering::Relaxed), i32::MIN);
    assert_eq!(
        crabc_x86_atomic_probe_fetch_sub(address, 1),
        i32::MIN
    );
    assert_eq!(slot.load(Ordering::Relaxed), i32::MAX);

    // Every worker starts together so the locked xadd path is exercised under
    // real contention rather than only in sequential calls.
    const WORKERS: usize = 8;
    const INCREMENTS: usize = 20_000;
    let counter = Arc::new(AtomicI32::new(0));
    let barrier = Arc::new(Barrier::new(WORKERS));
    let mut threads = Vec::with_capacity(WORKERS);
    for _ in 0..WORKERS {
        let counter = Arc::clone(&counter);
        let barrier = Arc::clone(&barrier);
        threads.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..INCREMENTS {
                crabc_x86_atomic_probe_fetch_add(counter.as_ptr(), 1);
            }
        }));
    }
    for thread in threads {
        thread.join().expect("atomic contention worker panicked");
    }
    assert_eq!(
        counter.load(Ordering::Relaxed),
        (WORKERS * INCREMENTS) as i32
    );

    println!("x86 atomic source-only probe: PASS");
}
