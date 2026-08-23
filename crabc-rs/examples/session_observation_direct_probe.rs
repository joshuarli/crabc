//! Link-free no-std proof for the native process-group/session observations.
//!
//! This source is intentionally unregistered until the architecture harness
//! adds the corresponding static-archive and direct-syscall checks.

#![no_std]

use crabc_rs::process;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_session_observation_direct_probe() -> i32 {
    let pid = process::getpid();
    let current_group = match process::getpgid(None) {
        Ok(group) => group,
        Err(error) => return -error.raw(),
    };
    let explicit_group = match process::getpgid(Some(pid)) {
        Ok(group) => group,
        Err(error) => return -error.raw(),
    };
    let shorthand_group = process::getpgrp();
    let current_session = match process::getsid(None) {
        Ok(session) => session,
        Err(error) => return -error.raw(),
    };
    let explicit_session = match process::getsid(Some(pid)) {
        Ok(session) => session,
        Err(error) => return -error.raw(),
    };

    if current_group.as_raw_pid() <= 0
        || explicit_group.as_raw_pid() <= 0
        || shorthand_group.as_raw_pid() <= 0
        || current_session.as_raw_pid() <= 0
        || explicit_session.as_raw_pid() <= 0
    {
        return 1;
    }
    if current_group != explicit_group
        || shorthand_group != current_group
        || process::getpgrp() != shorthand_group
        || current_session != explicit_session
    {
        return 2;
    }
    0
}
