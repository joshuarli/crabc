//! Link-free no-std proof for the M10 native current-working-directory seam.
//!
//! This source is intentionally left unregistered until the architecture
//! harness adds the corresponding static-archive and syscall checks.

#![no_std]

use core::mem::MaybeUninit;

use crabc_rs::process;

const PROBE_PATH_CAPACITY: usize = 4096;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_getcwd_direct_probe() -> i32 {
    let mut storage = [MaybeUninit::<u8>::uninit(); PROBE_PATH_CAPACITY];
    let (initialized, untouched) = match process::getcwd(&mut storage) {
        Ok(result) => result,
        Err(error) => return -error.raw(),
    };
    if initialized.is_empty() || initialized.last() != Some(&0) {
        return 1;
    }
    if untouched.len() != PROBE_PATH_CAPACITY - initialized.len() {
        return 2;
    }
    0
}
