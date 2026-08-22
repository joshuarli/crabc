//! Link-free no-std proof for owned Linux system-name observation.
//!
//! The native API deliberately reaches `uname` and exposes its owned CStr
//! fields rather than reproducing C gethostname/getdomainname buffer rules.

#![no_std]

use crabc_rs::system;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_system_names_direct_probe() -> i32 {
    let names = system::uname();
    let hostname = names.nodename().to_bytes().len();
    let domainname = names.domainname().to_bytes().len();

    if hostname <= 64 && domainname <= 64 {
        0
    } else {
        1
    }
}
