//! Link-free no-std proof for the typed `SO_PROTOCOL` seam.
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
pub extern "C" fn crabc_rs_network_socket_protocol_direct_probe() -> i32 {
    let socket = match net::socket(
        AddressFamily::INET,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC,
        None,
    ) {
        Ok(socket) => socket,
        Err(error) => return -error.raw(),
    };

    match net::sockopt::socket_protocol(&socket) {
        Ok(Some(protocol)) if protocol.as_raw().get() == 17 => 0,
        Ok(None) => 1,
        Ok(Some(_)) => 2,
        Err(error) => -error.raw(),
    }
}
