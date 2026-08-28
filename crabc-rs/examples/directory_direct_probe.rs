//! Link-free no-std proof for the owned directory-stream seam.
//!
//! The native x86 directory-reference gate builds this static archive alongside
//! its raw/pinned-musl syscall proof.

#![no_std]

use core::mem::MaybeUninit;

use crabc_rs::fs::Dir;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_directory_direct_probe() -> i32 {
    let mut storage = [MaybeUninit::uninit(); 4096];
    let mut stream = match Dir::open(&b"/tmp"[..], &mut storage) {
        Ok(stream) => stream,
        Err(error) => return -error.raw(),
    };
    while let Some(entry) = stream.next() {
        if let Err(error) = entry {
            return -error.raw();
        }
    }
    0
}
