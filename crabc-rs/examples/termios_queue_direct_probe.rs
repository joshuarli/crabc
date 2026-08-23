//! Link-free no-std proof for the native terminal queue-control quartet.
//!
//! The PTY is disposable, so flow-control mutations do not escape the probe
//! process. The calls below use only typed Rust terminal operations; no C
//! termios entry point, allocator, or TLS errno state is part of the path.

#![no_std]

use crabc_rs::pty::{self, OpenptFlags};
use crabc_rs::termios;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_termios_queue_direct_probe() -> i32 {
    let master = match pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC) {
        Ok(fd) => fd,
        Err(error) => return -error.raw(),
    };
    if let Err(error) = pty::grantpt(&master) {
        return -error.raw();
    }
    if let Err(error) = pty::unlockpt(&master) {
        return -error.raw();
    }

    for queue in [
        termios::QueueSelector::IFlush,
        termios::QueueSelector::OFlush,
        termios::QueueSelector::IOFlush,
    ] {
        if let Err(error) = termios::tcflush(&master, queue) {
            return -error.raw();
        }
    }
    if let Err(error) = termios::tcdrain(&master) {
        return -error.raw();
    }
    if let Err(error) = termios::tcsendbreak(&master) {
        return -error.raw();
    }
    for action in [
        termios::Action::OOff,
        termios::Action::OOn,
        termios::Action::IOff,
        termios::Action::IOn,
    ] {
        if let Err(error) = termios::tcflow(&master, action) {
            return -error.raw();
        }
    }

    0
}
