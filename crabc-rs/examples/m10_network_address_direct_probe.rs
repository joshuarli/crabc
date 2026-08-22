//! Link-free no-std proof for the M10 native network-byte-order seam.

#![no_std]

use crabc_rs::net::{NetworkU16, NetworkU32};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_network_address_direct_probe() -> i32 {
    let port = NetworkU16::from_host(443);
    if port.to_bytes() != [1, 187] || port.to_host() != 443 {
        return 1;
    }

    let address = NetworkU32::from_bytes([192, 0, 2, 7]);
    if address.to_host() != 0xc000_0207 || NetworkU32::from_host(address.to_host()).to_bytes() != [192, 0, 2, 7] {
        return 2;
    }
    0
}
