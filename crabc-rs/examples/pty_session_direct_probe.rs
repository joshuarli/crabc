//! Link-free proof for the owned PTY/session native slice.
//!
//! The probe opens an owned master/slave pair, resolves the slave name into
//! caller storage, and performs the explicit session/controlling-terminal
//! handoff only in a forked child. It does not call `openpty`, `forkpty`,
//! `login_tty`, or any C terminal helper.

#![no_std]
#![no_main]
#![crate_type = "staticlib"]

use core::mem::MaybeUninit;

use crabc_rs::process;
use crabc_rs::pty::{self, OpenptFlags, PtyPair};
use crabc_rs::termios;

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

fn child_probe(pair: &PtyPair) -> ! {
    if unsafe { pair.establish_session_and_controlling_terminal(false) }.is_err() {
        process::exit_immediately(10);
    }
    let pid = process::getpid();
    if termios::tcgetsid(pair.slave()) != Ok(pid) {
        process::exit_immediately(11);
    }
    if termios::tcgetpgrp(pair.slave()) != Ok(pid) {
        process::exit_immediately(12);
    }
    process::exit_immediately(0)
}

#[no_mangle]
pub extern "C" fn crabc_rs_pty_session_direct_probe() -> i32 {
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

    let child = match crabc_core::process::fork_raw().map(crabc_rs::Pid::from_raw) {
        Ok(Some(child)) => child,
        Ok(None) => child_probe(&pair),
        Err(error) => return -error.raw(),
    };
    let mut status = 0;
    // SAFETY: status is writable and the child was created by this probe.
    match unsafe { crabc_core::process::wait4_raw(child.as_raw_pid(), &mut status, 0) } {
        Ok(_) if status & 0x7f == 0 => (status >> 8) & 0xff,
        Ok(_) => 13,
        Err(error) => -error.raw(),
    }
}
