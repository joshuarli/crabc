//! Link-free no-std proof for the M10 typed socket-option seam.
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
pub extern "C" fn crabc_rs_m10_network_socket_options_direct_probe() -> i32 {
    let socket = match net::socket(
        AddressFamily::INET,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC,
        None,
    ) {
        Ok(socket) => socket,
        Err(error) => return -error.raw(),
    };

    match net::socket_reuseaddr(&socket) {
        Ok(false) => {}
        Ok(true) => return 1,
        Err(error) => return -error.raw(),
    }
    if let Err(error) = net::set_socket_reuseaddr(&socket, true) {
        return -error.raw();
    }
    match net::socket_reuseaddr(&socket) {
        Ok(true) => {}
        Ok(false) => return 2,
        Err(error) => return -error.raw(),
    }
    if let Err(error) = net::set_socket_reuseaddr(&socket, false) {
        return -error.raw();
    }
    match net::socket_reuseaddr(&socket) {
        Ok(false) => 0,
        Ok(true) => 3,
        Err(error) => -error.raw(),
    }
}
