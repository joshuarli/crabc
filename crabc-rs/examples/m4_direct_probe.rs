//! Link-free assembly probe for the M4 process/system direct boundary.
//!
//! This no-std archive makes every M4 syscall seam reachable without routing
//! through crabc's public C ABI or TLS errno protocol.

#![cfg_attr(not(feature = "std"), no_std)]

use crabc_rs::{mount, process, pty, shm, system, thread};
use core::ffi::CStr;

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! { loop {} }

#[no_mangle]
pub extern "C" fn crabc_rs_m4_direct_probe() -> i32 {
    let pid = process::getpid();
    let _ = process::getppid();
    if let Err(error) = process::test_kill_process(pid) { return -error.raw(); }
    if let Err(error) = process::getpgid(None) { return -error.raw(); }
    if let Err(error) = process::setpgid(None, None) { return -error.raw(); }
    if let Err(error) = process::getsid(None) { return -error.raw(); }
    let _ = process::setsid();
    let _ = thread::gettid();
    thread::sched_yield();

    let _ = system::uname();
    let _ = system::sysinfo();

    let master = match pty::openpt(pty::OpenptFlags::RDWR | pty::OpenptFlags::CLOEXEC) {
        Ok(fd) => fd,
        Err(error) => return -error.raw(),
    };
    if let Err(error) = pty::grantpt(&master) { return -error.raw(); }
    if let Err(error) = pty::unlockpt(&master) { return -error.raw(); }
    drop(master);

    let _ = shm::open(
        "/crabc-rs-m4-static-probe",
        shm::OFlags::RDWR,
        shm::Mode::empty(),
    );
    let _ = mount::mount(
        "none",
        "/crabc-rs-m4-static-probe",
        "none",
        mount::MountFlags::empty(),
        None::<&CStr>,
    );
    let _ = mount::unmount("/crabc-rs-m4-static-probe", mount::UnmountFlags::empty());
    0
}
