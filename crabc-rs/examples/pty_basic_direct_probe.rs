//! Link-free no-std proof for the x86 PTY ownership and naming seam.
//!
//! The probe opens an owned master/slave pair, resolves the slave into
//! caller-provided storage, and proves a one-byte slave-to-master transfer.
//! It deliberately does not create a session, acquire a controlling terminal,
//! or issue a termios ioctl.

#![no_std]

use core::mem::MaybeUninit;

use crabc_rs::io;
use crabc_rs::pty::{self, OpenptFlags, PtyPair};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_pty_basic_direct_probe() -> i32 {
    let pair = match PtyPair::open(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC) {
        Ok(pair) => pair,
        Err(error) => return -error.raw(),
    };
    let mut storage = [MaybeUninit::uninit(); 32];
    let name = match pty::ptsname_into(pair.master(), &mut storage) {
        Ok(name) => name,
        Err(error) => return -error.raw(),
    };
    if !name.to_bytes().starts_with(b"/dev/pts/") {
        return 1;
    }

    match io::write(pair.slave(), b"x") {
        Ok(1) => {}
        Ok(_) => return 2,
        Err(error) => return -error.raw(),
    }
    let mut received = [0_u8; 1];
    match io::read(pair.master(), &mut received) {
        Ok(1) if received == *b"x" => 0,
        Ok(_) => 3,
        Err(error) => -error.raw(),
    }
}
