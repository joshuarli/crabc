//! Link-free no-std proof for the typed signal-mask-aware `ppoll` facade.
//!
//! The source is intentionally unregistered in the focused slice. It keeps
//! the readiness wait and signal-mask transition on direct Linux/AArch64
//! syscalls, without the public C ABI, TLS `errno`, or allocation.

#![no_std]

use crabc_rs::{event, pipe, process, signal, time};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

unsafe extern "C" fn ppoll_probe_handler(_: process::Signal) {}

#[no_mangle]
pub extern "C" fn crabc_rs_ppoll_direct_probe() -> i32 {
    let (reader, _writer) = match pipe::pipe() {
        Ok(pipe) => pipe,
        Err(error) => return -error.raw(),
    };
    let mut selected = signal::SignalSet::EMPTY;
    selected.insert(process::Signal::USR1);

    let action = signal::SigAction::new(
        signal::SigHandler::Simple(ppoll_probe_handler),
        signal::SignalSet::EMPTY,
        signal::SigActionFlags::empty(),
    );
    let old_action = match unsafe { signal::sigaction(process::Signal::USR1, Some(&action)) } {
        Ok(action) => action,
        Err(error) => return -error.raw(),
    };
    let old_mask = match signal::block(&selected) {
        Ok(mask) => mask,
        Err(error) => return -error.raw(),
    };
    if let Err(error) = signal::raise(process::Signal::USR1) {
        return -error.raw();
    }

    let timeout = time::Timespec::default();
    let mut fds = [event::PollFd::new(&reader, event::PollFlags::IN)];
    if event::ppoll(&mut fds, Some(&timeout), Some(&selected)) != Ok(0) {
        return 1;
    }
    let empty = signal::SignalSet::EMPTY;
    let timeout = time::Timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    if event::ppoll(&mut fds, Some(&timeout), Some(&empty)) != Err(crabc_rs::Errno::INTR) {
        return 2;
    }
    if !signal::current_mask()
        .map(|mask| mask.contains(process::Signal::USR1))
        .unwrap_or(false)
    {
        return 3;
    }
    if signal::set_mask(&old_mask).is_err() {
        return 4;
    }
    if unsafe { signal::sigaction(process::Signal::USR1, Some(&old_action)) }.is_err() {
        return 5;
    }
    0
}
