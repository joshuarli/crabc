//! Link-free no-std proof for the complete x86 native terminal seam.
//!
//! This probe exercises typed terminal state, queues, exclusivity, tty naming,
//! and the explicit session handoff. The latter runs only after a raw fork, so
//! the probe caller's terminal state is not changed.

#![no_std]
#![crate_type = "staticlib"]

use core::mem::MaybeUninit;

use crabc_core::process as raw_process;
use crabc_rs::pty::{OpenptFlags, PtyPair};
use crabc_rs::termios::{self, Action, OptionalActions, QueueSelector, SpecialCodeIndex};
use crabc_rs::process::Pid;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

fn child_probe(pair: &PtyPair) -> ! {
    // SAFETY: the fork child is the isolated, single-threaded session owner
    // required by the explicit terminal-handoff contract.
    if unsafe { pair.establish_session_and_controlling_terminal(false) }.is_err() {
        raw_process::exit_immediately(10);
    }
    let pid = match Pid::from_raw(raw_process::getpid()) {
        Some(pid) => pid,
        None => raw_process::exit_immediately(11),
    };
    if termios::tcgetsid(pair.slave()) != Ok(pid)
        || termios::tcgetpgrp(pair.slave()) != Ok(pid)
        || termios::tcsetpgrp(pair.slave(), pid).is_err()
    {
        raw_process::exit_immediately(12);
    }
    raw_process::exit_immediately(0)
}

#[no_mangle]
pub extern "C" fn crabc_rs_x86_64_terminal_direct_probe() -> i32 {
    let pair = match PtyPair::open(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC) {
        Ok(pair) => pair,
        Err(error) => return -error.raw(),
    };
    let original = match termios::tcgetattr(pair.slave()) {
        Ok(attributes) => attributes,
        Err(error) => return -error.raw(),
    };
    let mut changed = original.clone();
    changed.make_raw();
    if changed.special_codes[SpecialCodeIndex::VMIN] != 1
        || changed.special_codes[SpecialCodeIndex::VTIME] != 0
    {
        return 1;
    }
    changed.special_codes[SpecialCodeIndex::VINTR] = b'/';
    changed.special_codes[SpecialCodeIndex::VEOL] = b'c';
    if let Err(error) = changed.set_speed(9_600) {
        return -error.raw();
    }
    if let Err(error) = termios::tcsetattr(pair.slave(), OptionalActions::Now, &changed) {
        return -error.raw();
    }
    let observed = match termios::tcgetattr(pair.slave()) {
        Ok(attributes) => attributes,
        Err(error) => return -error.raw(),
    };
    if observed.special_codes[SpecialCodeIndex::VINTR] != b'/'
        || observed.special_codes[SpecialCodeIndex::VEOL] != b'c'
        || observed.input_speed() != 9_600
        || observed.output_speed() != 9_600
    {
        return 2;
    }
    if let Err(error) = changed.set_input_speed(0) {
        return -error.raw();
    }
    if let Err(error) = termios::tcsetattr(pair.slave(), OptionalActions::Now, &changed) {
        return -error.raw();
    }
    let observed = match termios::tcgetattr(pair.slave()) {
        Ok(attributes) => attributes,
        Err(error) => return -error.raw(),
    };
    if observed.input_speed() != 0 || observed.output_speed() != 9_600 {
        return 3;
    }
    if let Err(error) = termios::tcsetattr(pair.slave(), OptionalActions::Drain, &original) {
        return -error.raw();
    }
    if let Err(error) = termios::tcsetattr(pair.slave(), OptionalActions::Flush, &original) {
        return -error.raw();
    }

    for queue in [QueueSelector::IFlush, QueueSelector::OFlush, QueueSelector::IOFlush] {
        if let Err(error) = termios::tcflush(pair.master(), queue) {
            return -error.raw();
        }
    }
    if let Err(error) = termios::tcdrain(pair.master()) {
        return -error.raw();
    }
    if let Err(error) = termios::tcsendbreak(pair.master()) {
        return -error.raw();
    }
    for action in [Action::OOff, Action::OOn, Action::IOff, Action::IOn] {
        if let Err(error) = termios::tcflow(pair.master(), action) {
            return -error.raw();
        }
    }

    let mut name_storage = [MaybeUninit::uninit(); 128];
    let name = match termios::ttyname_into(pair.slave(), &mut name_storage) {
        Ok(name) if name.to_bytes().starts_with(b"/dev/pts/") => name,
        Ok(_) => return 4,
        Err(error) => return -error.raw(),
    };
    if name.to_bytes().len() <= b"/dev/pts/".len() {
        return 5;
    }
    if let Err(error) = termios::ioctl_tiocexcl(pair.slave()) {
        return -error.raw();
    }
    if let Err(error) = termios::ioctl_tiocnxcl(pair.slave()) {
        return -error.raw();
    }

    let child = match raw_process::fork_raw() {
        Ok(child) => child,
        Err(error) => return -error.raw(),
    };
    if child == 0 {
        child_probe(&pair);
    }
    let mut status = 0_i32;
    match unsafe { raw_process::wait4_raw(child, &mut status, 0) } {
        Ok(observed) if observed == child && status == 0 => 0,
        Ok(_) => 6,
        Err(error) => -error.raw(),
    }
}
