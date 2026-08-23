#![no_std]
#![crate_type = "staticlib"]

//! Link-free no-std proof for the network interface-index-to-name seam.

use crabc_rs::net::{self, netdevice};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_network_interface_index_name_direct_probe() -> i32 {
    let socket = match net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    ) {
        Ok(socket) => socket,
        Err(error) => return -error.raw(),
    };

    let index = match netdevice::name_to_index(&socket, "lo") {
        Ok(index) if index > 0 => index,
        Ok(_) => return -1,
        Err(error) => return -error.raw(),
    };
    match netdevice::index_to_name_inlined(&socket, index) {
        Ok(name) if name.as_str() == "lo" && name.as_bytes() == b"lo" => 0,
        Ok(_) => 1,
        Err(error) => -error.raw(),
    }
}
