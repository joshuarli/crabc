//! Link-free no-std proof for the network interface-index seam.

#![no_std]

use crabc_rs::net::{self, netdevice};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_network_interface_index_direct_probe() -> i32 {
    let socket = match net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    ) {
        Ok(socket) => socket,
        Err(_) => return -1,
    };
    match netdevice::name_to_index(&socket, "lo") {
        Ok(index) if index > 0 => 0,
        _ => -1,
    }
}
