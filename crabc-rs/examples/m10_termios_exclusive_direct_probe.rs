//! Link-free no-std proof for the direct terminal-exclusive-mode ioctls.

#![no_std]

use crabc_rs::pty::{self, OpenptFlags};
use crabc_rs::termios;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_termios_exclusive_direct_probe() -> i32 {
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
    let slave = match pty::ioctl_tiocgptpeer(
        &master,
        OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC,
    ) {
        Ok(fd) => fd,
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
