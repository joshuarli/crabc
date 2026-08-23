//! Link-free no-std proof for native process umask and resource-limit mutation.

#![no_std]

use crabc_rs::process::{self, Mode, Resource, Rlimit};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_process_limits_umask_direct_probe() -> i32 {
    let previous = process::umask(Mode::empty());
    let _ = process::umask(previous);
    let limit = match process::getrlimit(Resource::Core) {
        Ok(limit) => limit,
        Err(error) => return -error.raw(),
    };
    process::setrlimit(Resource::Core, Rlimit {
        current: limit.current,
        maximum: limit.maximum,
    })
    .map_or_else(|error| -error.raw(), |_| 0)
}
