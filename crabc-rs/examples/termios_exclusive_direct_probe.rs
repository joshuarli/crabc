//! Link-free no-std proof for the direct terminal-exclusive-mode ioctls.

#![no_std]

use crabc_rs::pty::{self, OpenptFlags};
use crabc_rs::termios;

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_termios_exclusive_direct_probe() -> i32 {
    let (master, slave) = match pty::PtyPair::open(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC) {
        Ok(pair) => pair.into_parts(),
        Err(error) => return -error.raw(),
    };

    if let Err(error) = termios::ioctl_tiocexcl(&slave) {
        return -error.raw();
    }
    if let Err(error) = termios::ioctl_tiocnxcl(&slave) {
        return -error.raw();
    }
    0
}
