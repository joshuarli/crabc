//! Link-free no-std proof for the M10 native socket-creation seam.
//!
//! This source is intentionally unregistered until the architecture harness
//! adds the corresponding static-archive and syscall checks.

#![no_std]

use crabc_rs::net::{self, AddressFamily, Shutdown, SocketFlags, SocketType};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_network_socket_direct_probe() -> i32 {
    let socket = match net::socket(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    ) {
        Ok(socket) => socket,
        Err(error) => return -error.raw(),
    };
    drop(socket);

    let (left, right) = match net::socketpair(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::empty(),
        None,
    ) {
        Ok(pair) => pair,
        Err(error) => return -error.raw(),
    };
    if let Err(error) = net::shutdown(&left, Shutdown::Both) {
        return -error.raw();
    }
    drop(left);
    drop(right);
    0
}
