//! Link-free no-std proof for the native getpeername seam.
//!
//! The probe exercises a connected IPv4 endpoint and checks the typed result
//! without importing libc, a C socket ABI, or TLS `errno`.

#![no_std]

use crabc_rs::net::{self, IpAddress, SocketAddress};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_network_getpeername_direct_probe() -> i32 {
    let socket = match net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    ) {
        Ok(socket) => socket,
        Err(error) => return -error.raw(),
    };
    let expected = SocketAddress::new(IpAddress::V4([127, 0, 0, 1]), 9);
    if let Err(error) = net::connect(&socket, expected) {
        return -error.raw();
    }
    match net::getpeername(&socket) {
        Ok(actual) if actual == expected => 0,
        Ok(_) => 1,
        Err(error) => -error.raw(),
    }
}
