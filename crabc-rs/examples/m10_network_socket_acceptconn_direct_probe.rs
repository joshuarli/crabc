#![no_std]
#![crate_type = "staticlib"]

//! Link-free no-std proof for the direct Linux/AArch64 `SO_ACCEPTCONN` seam.

use crabc_rs::net::{self, AddressFamily, SocketFlags, SocketType};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_network_socket_acceptconn_direct_probe() -> i32 {
    let socket = match net::socket(
        AddressFamily::INET,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    ) {
        Ok(socket) => socket,
        Err(error) => return -error.raw(),
    };

    match net::sockopt::socket_acceptconn(&socket) {
        Ok(false) => {}
        Ok(true) => return 1,
        Err(error) => return -error.raw(),
    }
    if let Err(error) = net::listen(&socket, 1) {
        return -error.raw();
    }
    match net::sockopt::socket_acceptconn(&socket) {
        Ok(true) => {
            drop(socket);
            0
        }
        Ok(false) => 2,
        Err(error) => -error.raw(),
    }
}
