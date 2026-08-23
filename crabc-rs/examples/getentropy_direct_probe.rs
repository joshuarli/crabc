//! Link-free no-std proof for the bounded getentropy seam.
//!
//! This source is intentionally unregistered until the architecture harness
//! adds the corresponding static-archive and direct-syscall checks.

#![no_std]

use core::mem::MaybeUninit;

use crabc_rs::rand::{getentropy, GETENTROPY_MAX_LENGTH};
use crabc_rs::Errno;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_getentropy_direct_probe() -> i32 {
    let mut initialized = [0_u8; 16];
    if getentropy(&mut initialized) != Ok(16) {
        return 1;
    }

    let mut maybe_initialized = [MaybeUninit::<u8>::uninit(); 16];
    let (initialized, remaining) = match getentropy(&mut maybe_initialized) {
        Ok(value) => value,
        Err(_) => return 2,
    };
    if initialized.len() != 16 || !remaining.is_empty() {
        return 3;
    }

    let mut oversized = [0_u8; GETENTROPY_MAX_LENGTH + 1];
    if getentropy(&mut oversized) != Err(Errno::IO) {
        return 4;
    }

    0
}
