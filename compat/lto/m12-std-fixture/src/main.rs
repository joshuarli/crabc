//! Stock-`std` M12 lane for raw musl-versus-crabc runtime comparison.
//!
//! The exported witness is intentionally function-scoped so assembly checks
//! can distinguish the native `crabc-rs` process route from unrelated std
//! startup/runtime code.  The dynamic C runtime is compared byte-for-byte at
//! the process boundary, but no LTO-into-DSO claim is made.

use crabc_rs::{io, process, BorrowedFd};

#[no_mangle]
#[inline(never)]
pub extern "C" fn crabc_rs_m12_getpid_witness() -> i32 {
    let pid = process::getpid().as_raw_pid();
    if pid > 0 { 0 } else { 1 }
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn m12_std_direct_route() -> i32 {
    if crabc_rs_m12_getpid_witness() != 0 {
        return 1;
    }
    let worker = std::thread::spawn(|| 7_u8);
    if worker.join().ok() != Some(7) {
        return 2;
    }
    let mut output = String::from("m12-stock-std:ok\n");
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
    std::process::exit(m12_std_direct_route());
}
