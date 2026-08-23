//! Link-free no-std proof for the native listen/accept seam.
//!
//! The listener is deliberately nonblocking so the probe can exercise both
//! address-free and peer-address accept paths without a second process. The
//! expected `EAGAIN` results prove that Linux reached the direct `accept` and
//! `accept4` syscalls; no libc, C socket ABI, or TLS `errno` is involved.
//!
//! This source is intentionally unregistered until the architecture harness
//! adds the corresponding static-archive and syscall checks.

#![no_std]

use crabc_rs::net::{self, IpAddress, SocketAddress};
use crabc_rs::Errno;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

fn expected_again(error: Errno) -> bool {
    error == Errno::AGAIN || error == Errno::WOULDBLOCK
}

#[no_mangle]
pub extern "C" fn crabc_rs_network_listen_accept_direct_probe() -> i32 {
    let listener = match net::socket(
        net::AddressFamily::INET,
        net::SocketType::STREAM,
        net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
        None,
    ) {
        Ok(listener) => listener,
        Err(error) => return -error.raw(),
    };
    if let Err(error) = net::bind(
        &listener,
        SocketAddress::new(IpAddress::V4([127, 0, 0, 1]), 0),
    ) {
        return -error.raw();
    }
    if let Err(error) = net::listen(&listener, 1) {
        return -error.raw();
    }

    match net::accept(&listener) {
        Err(error) if expected_again(error) => {}
        Err(error) => return -error.raw(),
        Ok(_) => return 1,
    }
    match net::accept4(&listener, net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK) {
        Err(error) if expected_again(error) => {}
        Err(error) => return -error.raw(),
        Ok(_) => return 2,
    }
    match net::acceptfrom(&listener) {
        Err(error) if expected_again(error) => 0,
        Err(error) => -error.raw(),
        Ok(_) => 3,
    }
}
