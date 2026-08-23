//! Link-free no-std proof for the typed `SO_OOBINLINE` seam.

#![no_std]
#![crate_type = "staticlib"]

use crabc_rs::net::{self, AddressFamily, SocketFlags, SocketType};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_network_socket_oobinline_direct_probe() -> i32 {
    let socket = match net::socket(
        AddressFamily::INET,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    ) {
        Ok(socket) => socket,
        Err(error) => return -error.raw(),
    };

    match net::sockopt::socket_oobinline(&socket) {
        Ok(false) => {}
        Ok(true) => return 1,
        Err(error) => return -error.raw(),
    }
    if let Err(error) = net::sockopt::set_socket_oobinline(&socket, true) {
        return -error.raw();
    }
    match net::sockopt::socket_oobinline(&socket) {
        Ok(true) => {}
        Ok(false) => return 2,
        Err(error) => return -error.raw(),
    }
    if let Err(error) = net::sockopt::set_socket_oobinline(&socket, false) {
        return -error.raw();
    }
    let result = match net::sockopt::socket_oobinline(&socket) {
        Ok(false) => 0,
        Ok(true) => 3,
        Err(error) => -error.raw(),
    };
    drop(socket);
    result
}
