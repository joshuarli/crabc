//! Link-free no-std proof for the native current-CPU observation seam.
//!
//! This source is intentionally left unregistered until the architecture
//! harness adds the corresponding release static-archive and direct-syscall
//! checks.

#![no_std]

use crabc_rs::thread;

const LINUX_CPU_SETSIZE: usize = 1024;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_sched_cpu_direct_probe() -> i32 {
    let first = thread::sched_getcpu();
    let second = thread::sched_getcpu();

    if first >= LINUX_CPU_SETSIZE || second >= LINUX_CPU_SETSIZE {
        return 1;
    }
    0
}
