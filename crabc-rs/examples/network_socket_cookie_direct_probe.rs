#![no_std]
#![crate_type = "staticlib"]

//! Link-free no-std proof for the direct Linux/AArch64 `SO_COOKIE` seam.

use crabc_rs::net::{self, AddressFamily, SocketFlags, SocketType};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_network_socket_cookie_direct_probe() -> i32 {
    let socket = match net::socket(
        AddressFamily::INET,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC,
        None,
    ) {
        Ok(socket) => socket,
        Err(error) => return -error.raw(),
    };

    let first = match net::sockopt::socket_cookie(&socket) {
        Ok(cookie) => cookie,
        Err(error) => return -error.raw(),
    };
    let second = match net::sockopt::socket_cookie(&socket) {
        Ok(cookie) => cookie,
        Err(error) => return -error.raw(),
    };
    if first == second {
        0
    } else {
        1
    }
}
