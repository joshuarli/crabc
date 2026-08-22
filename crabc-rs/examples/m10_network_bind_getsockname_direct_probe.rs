//! Link-free no-std proof for the M10 native bind/getsockname seam.
//!
//! This source is intentionally unregistered until the architecture harness
//! adds the corresponding static-archive and syscall checks.

#![no_std]

use crabc_rs::net::{self, IpAddress, SocketAddress};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_network_bind_getsockname_direct_probe() -> i32 {
    let ipv4 = match net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    ) {
        Ok(socket) => socket,
        Err(_) => return 1,
    };
    let endpoint = SocketAddress::new(IpAddress::V4([127, 0, 0, 1]), 0);
    if net::bind(&ipv4, endpoint).is_err() || net::getsockname(&ipv4).is_err() {
        return 1;
    }
    let ipv6 = match net::socket(
        net::AddressFamily::INET6,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    ) {
        Ok(socket) => socket,
        Err(_) => return 1,
    };
    let endpoint = SocketAddress::new(
        IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        0,
    );
    if net::bind(&ipv6, endpoint).is_err() || net::getsockname(&ipv6).is_err() {
        return 1;
    }
    0
}
