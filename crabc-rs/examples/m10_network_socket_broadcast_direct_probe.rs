//! Link-free no-std proof for the direct Linux/AArch64 `SO_BROADCAST` seam.

#![no_std]
#![crate_type = "staticlib"]

use crabc_rs::net::{self, AddressFamily, SocketFlags, SocketType};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_network_socket_broadcast_direct_probe() -> i32 {
    let socket = match net::socket(
        AddressFamily::INET,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC,
        None,
    ) {
        Ok(socket) => socket,
        Err(error) => return -error.raw(),
    };

    match net::sockopt::socket_broadcast(&socket) {
        Ok(false) => {}
        Ok(true) => return 1,
        Err(error) => return -error.raw(),
    }
    if let Err(error) = net::sockopt::set_socket_broadcast(&socket, true) {
        return -error.raw();
    }
    match net::sockopt::socket_broadcast(&socket) {
        Ok(true) => {}
        Ok(false) => return 2,
        Err(error) => return -error.raw(),
    }
    if let Err(error) = net::sockopt::set_socket_broadcast(&socket, false) {
        return -error.raw();
    }
    let result = match net::sockopt::socket_broadcast(&socket) {
        Ok(false) => 0,
        Ok(true) => 3,
        Err(error) => -error.raw(),
    };
    drop(socket);
    result
}
