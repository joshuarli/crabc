//! Link-free no-std proof for the native scheduler-priority observation.

#![no_std]

use crabc_rs::process::{self, SchedulerPolicy};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_scheduler_priority_bounds_direct_probe() -> i32 {
    let policies = [
        SchedulerPolicy::Other,
        SchedulerPolicy::Fifo,
        SchedulerPolicy::RoundRobin,
    ];
    let mut index = 0;
    while index < policies.len() {
        let bounds = match process::scheduler_priority_bounds(policies[index]) {
            Ok(bounds) => bounds,
            Err(error) => return -error.raw(),
        };
        if bounds.minimum() > bounds.maximum() {
            return 1;
        }
        index += 1;
    }
    0
}
