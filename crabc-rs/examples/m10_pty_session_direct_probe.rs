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

use crabc_rs::process::{self, ForkResult};
use crabc_rs::pty::{self, OpenptFlags, PtyPair};
use crabc_rs::termios;

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
pub extern "C" fn crabc_rs_m10_pty_session_direct_probe() -> i32 {
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

    let child = match unsafe { process::fork_raw() } {
        Ok(ForkResult::Parent { child }) => child,
        Ok(ForkResult::Child) => child_probe(&pair),
        Err(error) => return -error.raw(),
    };
    match process::waitpid(Some(child), process::WaitOptions::empty()) {
        Ok(Some((_, status))) => status.exit_status().unwrap_or(13),
        Ok(None) => 14,
        Err(error) => -error.raw(),
    }
}
