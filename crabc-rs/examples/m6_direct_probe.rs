//! Link-free assembly probe for the M6 signal/process direct boundary.
//!
//! The archive makes the native Linux/AArch64 signal, fork, exec, wait, and
//! atfork seams reachable without a public C ABI or TLS errno transition.

#![cfg_attr(not(feature = "std"), no_std)]

use core::ffi::CStr;

use crabc_rs::{process, signal};

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m6_direct_probe() -> i32 {
    let pid = process::getpid();
    if let Err(error) = process::test_kill_process(pid) {
        return -error.raw();
    }
    let mut set = signal::SignalSet::EMPTY;
    set.insert(process::Signal::USR1);
    let old_mask = match signal::block(&set) {
        Ok(mask) => mask,
        Err(error) => return -error.raw(),
    };
    if let Err(error) = signal::pending() {
        return -error.raw();
    }
    if let Err(error) = signal::signalfd(&set, signal::SignalFdFlags::CLOEXEC) {
        return -error.raw();
    }
    let _ = signal::suspend(&set);
    let _ = signal::timed_wait(&set, Some(&crabc_rs::time::Timespec::default()));
    if let Err(error) = signal::set_mask(&old_mask) {
        return -error.raw();
    }
    if let Err(error) = signal::queue_process(pid, process::Signal::USR1, 7) {
        return -error.raw();
    }
    if let Err(error) = signal::kill_thread(crabc_rs::thread::gettid(), process::Signal::USR2) {
        return -error.raw();
    }

    let action = signal::SigAction::new(
        signal::SigHandler::Default,
        signal::SignalSet::EMPTY,
        signal::SigActionFlags::empty(),
    );
    if let Err(error) = unsafe { signal::sigaction(process::Signal::USR1, Some(&action)) } {
        return -error.raw();
    }
    let disabled_stack = signal::Stack::disabled();
    if let Err(error) = unsafe { signal::sigaltstack(Some(&disabled_stack)) } {
        return -error.raw();
    }

    let path = unsafe { CStr::from_bytes_with_nul_unchecked(b"/bin/true\0") };
    let argv = [path.as_ptr().cast(), core::ptr::null()];
    let envp = [core::ptr::null()];
    let executable = match unsafe { process::BorrowedExec::new(path, &argv, &envp) } {
        Ok(executable) => executable,
        Err(error) => return -error.raw(),
    };
    let _ = executable.exec();

    match unsafe { process::fork_raw() } {
        Ok(process::ForkResult::Parent { child }) => {
            let _ = process::waitpid(Some(child), process::WaitOptions::NOHANG);
            let _ = process::waitid(
                process::WaitId::Pid(child),
                process::WaitIdOptions::EXITED | process::WaitIdOptions::NOHANG,
            );
            0
        }
        Ok(process::ForkResult::Child) => process::exit_immediately(0),
        Err(error) => -error.raw(),
    }
}
