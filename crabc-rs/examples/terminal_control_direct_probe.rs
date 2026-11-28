#![cfg(target_os = "linux")]
//! Link-free no-std proof for the borrowed terminal-control ioctl slice.
//!
//! The controlling-terminal transition occurs only in a forked child. The
//! caller's session and foreground process group are therefore untouched while
//! the probe exercises `tcgetattr`, `tcsetattr`, `tcgetpgrp`, `tcsetpgrp`, and
//! `tcgetsid` through crabc-core's direct AArch64 syscall boundary.

#![no_std]
#![no_main]
#![crate_type = "staticlib"]

use crabc_rs::process;
use crabc_rs::pty::{self, OpenptFlags};
use crabc_rs::termios;
use crabc_rs::fs;
use crabc_rs::OwnedFd;

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

fn child_probe(master: &OwnedFd) -> ! {
    let pid = process::getpid();
    if crabc_core::process::setsid().is_err() {
        process::exit_immediately(10);
    }
    let mut name_buffer = [core::mem::MaybeUninit::uninit(); 128];
    let name = match pty::ptsname_into(master, &mut name_buffer) {
        Ok(name) => name,
        Err(_) => process::exit_immediately(11),
    };
    let slave = match fs::open(name, fs::OFlags::RDWR | fs::OFlags::CLOEXEC, fs::Mode::empty()) {
        Ok(slave) => slave,
        Err(_) => process::exit_immediately(11),
    };
    let original = match termios::tcgetattr(&slave) {
        Ok(attributes) => attributes,
        Err(_) => process::exit_immediately(12),
    };
    if termios::tcsetattr(&slave, termios::OptionalActions::Now, &original).is_err() {
        process::exit_immediately(13);
    }
    if termios::tcgetsid(&slave) != Ok(pid) {
        process::exit_immediately(14);
    }
    if termios::tcgetpgrp(&slave) != Ok(pid) {
        process::exit_immediately(15);
    }
    if termios::tcsetpgrp(&slave, pid).is_err() {
        process::exit_immediately(16);
    }
    if termios::tcgetpgrp(&slave) != Ok(pid) {
        process::exit_immediately(17);
    }
    process::exit_immediately(0)
}

#[no_mangle]
pub extern "C" fn crabc_rs_terminal_control_direct_probe() -> i32 {
    let master = match pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC) {
        Ok(master) => master,
        Err(error) => return -error.raw(),
    };
    if let Err(error) = pty::grantpt(&master) {
        return -error.raw();
    }
    if let Err(error) = pty::unlockpt(&master) {
        return -error.raw();
    }

    let child = match crabc_core::process::fork_raw().map(crabc_rs::Pid::from_raw) {
        Ok(Some(child)) => child,
        Ok(None) => child_probe(&master),
        Err(error) => return -error.raw(),
    };
    let mut status = 0;
    // SAFETY: status is writable and the child was created by this probe.
    match unsafe { crabc_core::process::wait4_raw(child.as_raw_pid(), &mut status, 0) } {
        Ok(_) if status & 0x7f == 0 => (status >> 8) & 0xff,
        Ok(_) => 18,
        Err(error) => -error.raw(),
    }
}
