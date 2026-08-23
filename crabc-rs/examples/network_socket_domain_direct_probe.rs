#![no_std]
#![crate_type = "staticlib"]

//! Link-free no-std proof for the direct Linux/AArch64 `SO_DOMAIN` seam.

use crabc_rs::net::{self, AddressFamily, SocketFlags, SocketType};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_network_socket_domain_direct_probe() -> i32 {
    let ipv4 = match net::socket(
        AddressFamily::INET,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC,
        None,
    ) {
        Ok(socket) => socket,
        Err(error) => return -error.raw(),
    };
    match net::sockopt::socket_domain(&ipv4) {
        Ok(AddressFamily::INET) => {}
        Ok(_) => return 1,
        Err(error) => return -error.raw(),
    }

    let ipv6 = match net::socket(
        AddressFamily::INET6,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC,
        None,
    ) {
        Ok(socket) => socket,
        Err(error) => return -error.raw(),
    };
    match net::sockopt::socket_domain(&ipv6) {
        Ok(AddressFamily::INET6) => 0,
        Ok(_) => 2,
        Err(error) => -error.raw(),
    }
}
