//! Stock-`std` lane for raw musl-versus-crabc runtime comparison.
//!
//! The exported witness is intentionally function-scoped so assembly checks
//! can distinguish the native `crabc-rs` process route from unrelated std
//! startup/runtime code.  The dynamic C runtime is compared byte-for-byte at
//! the process boundary, but no LTO-into-DSO claim is made.

use crabc_rs::{io, process, BorrowedFd};
use std::cell::RefCell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// The TLS value owns memory received from the parent. Its destructor also
// allocates and frees on the worker before allocator thread teardown.
struct AllocationCleanup {
    completed: Arc<AtomicUsize>,
    parent_bytes: Vec<u8>,
}

impl Drop for AllocationCleanup {
    fn drop(&mut self) {
        assert!(self.parent_bytes.iter().all(|byte| *byte == 0x37));
        let worker_bytes = vec![0x71_u8; 32 * 1024];
        assert!(worker_bytes.iter().all(|byte| *byte == 0x71));
        self.completed.fetch_add(1, Ordering::SeqCst);
    }
}

thread_local! {
    static ALLOCATION_CLEANUP: RefCell<Option<AllocationCleanup>> = const { RefCell::new(None) };
}


#[no_mangle]
#[inline(never)]
pub extern "C" fn crabc_rs_native_facade_getpid_witness() -> i32 {
    let pid = process::getpid().as_raw_pid();
    if pid > 0 { 0 } else { 1 }
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn native_std_direct_route() -> i32 {
    if crabc_rs_native_facade_getpid_witness() != 0 {
        return 1;
    }
    let completed = Arc::new(AtomicUsize::new(0));
    let cleanup = AllocationCleanup {
        completed: Arc::clone(&completed),
        parent_bytes: vec![0x37; 4096],
    };
    let worker = std::thread::spawn(move || {
        ALLOCATION_CLEANUP.with(|slot| *slot.borrow_mut() = Some(cleanup));
        vec![7_u8; 64 * 1024]
    });
    let worker_bytes = match worker.join() {
        Ok(bytes) => bytes,
        Err(_) => return 2,
    };
    if completed.load(Ordering::SeqCst) != 1 || worker_bytes.len() != 64 * 1024
        || !worker_bytes.iter().all(|byte| *byte == 7) {
        return 2;
    }
    // The returned allocation survives its worker's allocator teardown.
    drop(worker_bytes);
    let mut output = String::from("native-std:ok\n");
    output.shrink_to_fit();
    // SAFETY: stdout is the process-owned descriptor and this borrow never
    // takes ownership or closes it.
    let stdout = unsafe { BorrowedFd::borrow_raw(1) };
    if io::write(stdout, output.as_bytes()) == Ok(output.len()) {
        0
    } else {
        1
    }
}

fn main() {
    std::process::exit(native_std_direct_route());
}
