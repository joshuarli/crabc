//! Link-free no-std proof for the M10 native resource-usage query.
//!
//! This source is intentionally unregistered until the architecture harness
//! adds the corresponding static-archive and syscall checks.

#![no_std]

use crabc_rs::process::{self, ResourceUsageTarget};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_rusage_direct_probe() -> i32 {
    let usage = match process::getrusage(ResourceUsageTarget::SelfProcess) {
        Ok(usage) => usage,
        Err(error) => return -error.raw(),
    };

    if usage.user_time.microseconds() < 0
        || usage.user_time.microseconds() >= 1_000_000
        || usage.system_time.microseconds() < 0
        || usage.system_time.microseconds() >= 1_000_000
        || usage.maximum_resident_set_size < 0
        || usage.minor_page_faults < 0
        || usage.major_page_faults < 0
        || usage.voluntary_context_switches < 0
        || usage.involuntary_context_switches < 0
    {
        return 1;
    }
    0
}
