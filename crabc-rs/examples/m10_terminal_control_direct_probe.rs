//! Link-free no-std proof for the borrowed terminal-control ioctl slice.
//!
//! The controlling-terminal transition occurs only in a forked child. The
//! caller's session and foreground process group are therefore untouched while
//! the probe exercises `tcgetattr`, `tcsetattr`, `tcgetpgrp`, `tcsetpgrp`, and
//! `tcgetsid` through crabc-core's direct AArch64 syscall boundary.

#![no_std]
#![no_main]
#![crate_type = "staticlib"]

use crabc_rs::process::{self, ForkResult};
use crabc_rs::pty::{self, OpenptFlags};
use crabc_rs::termios;
use crabc_rs::OwnedFd;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

fn child_probe(master: &OwnedFd) -> ! {
    let pid = process::getpid();
    if process::setsid().is_err() {
        process::exit_immediately(10);
    }
    let slave = match pty::ioctl_tiocgptpeer(master, OpenptFlags::RDWR | OpenptFlags::CLOEXEC) {
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
pub extern "C" fn crabc_rs_m10_terminal_control_direct_probe() -> i32 {
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

    let child = match unsafe { process::fork_raw() } {
        Ok(ForkResult::Parent { child }) => child,
        Ok(ForkResult::Child) => child_probe(&master),
        Err(error) => return -error.raw(),
    };
    match process::waitpid(Some(child), process::WaitOptions::empty()) {
        Ok(Some((_, status))) => status.exit_status().unwrap_or(18),
        Ok(None) => 19,
        Err(error) => -error.raw(),
    }
}
