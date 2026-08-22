//! Link-free no-std proof for the M10 typed `SO_TYPE` seam.
//!
//! This source is intentionally unregistered until the architecture harness
//! adds the corresponding static-archive and direct-syscall checks.

#![no_std]
#![crate_type = "staticlib"]

use crabc_rs::net::{self, AddressFamily, SocketFlags, SocketType};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_network_socket_type_direct_probe() -> i32 {
    let socket = match net::socket(
        AddressFamily::INET,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC,
        None,
    ) {
        Ok(socket) => socket,
        Err(error) => return -error.raw(),
    };

    match net::sockopt::socket_type(&socket) {
        Ok(SocketType::DGRAM) => 0,
        Ok(_) => 1,
        Err(error) => -error.raw(),
    }
}
