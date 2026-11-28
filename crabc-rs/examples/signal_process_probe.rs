#![cfg(target_os = "linux")]
//! Link-free assembly probe for the signal/process direct boundary.
//!
//! The archive makes the native Linux/AArch64 signal, fork, exec, and wait
//! seams reachable without a public C ABI or TLS errno transition. Fork here is
//! the raw crabc-core clone; the facade owns no atfork registry.

#![cfg_attr(not(feature = "std"), no_std)]

use core::ffi::CStr;

use crabc_rs::{process, signal};

#[cfg(not(feature = "std"))]
#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_signal_process_probe() -> i32 {
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
    let _ = signal::timed_wait(&set, Some(&crabc_rs::time::Timespec { tv_sec: 0, tv_nsec: 0 }));
    if let Err(error) = signal::set_mask(&old_mask) {
        return -error.raw();
    }
    if let Err(error) = signal::queue_process(pid, process::Signal::USR1, 7) {
        return -error.raw();
    }
    if let Err(error) = signal::kill_thread(crabc_rs::thread::gettid(), process::Signal::USR2) {
        return -error.raw();
    }

    #[cfg(target_arch = "aarch64")]
    let action = signal::SigAction::new(
        signal::SigHandler::Default,
        signal::SignalSet::EMPTY,
        signal::SigActionFlags::empty(),
    );
    #[cfg(target_arch = "x86_64")]
    let action = signal::SigAction::with_mask(signal::SigHandler::Default, signal::SignalSet::EMPTY, signal::SigActionFlags::empty());
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
    // SAFETY: the path and null-terminated arrays remain live for the syscall.
    let _ = unsafe { crabc_core::process::execve_raw(path.as_ptr().cast(), argv.as_ptr(), envp.as_ptr()) };

    match crabc_core::process::fork_raw().map(crabc_rs::Pid::from_raw) {
        Ok(Some(child)) => {
            let mut status = 0;
            let mut info = crabc_core::signal::SigInfo::zeroed();
            // SAFETY: status and info are writable syscall outputs.
            unsafe {
                let _ = crabc_core::process::wait4_raw(child.as_raw_pid(), &mut status, 1);
                let _ = crabc_core::process::waitid_raw(1, child.as_raw_pid() as u32, &mut info, 5);
            }
            0
        }
        Ok(None) => process::exit_immediately(0),
        Err(error) => -error.raw(),
    }
}
