//! Link-free no-std proof for the M10 core IP value-type seam.

#![no_std]

use crabc_rs::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_network_ipaddr_direct_probe() -> i32 {
    let ipv4 = Ipv4Addr::new(192, 0, 2, 7);
    if ipv4.octets() != [192, 0, 2, 7] || Ipv4Addr::from_bits(ipv4.to_bits()) != ipv4 {
        return 1;
    }

    let ipv6 = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0x0042, 0x0007);
    if ipv6.octets()
        != [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42, 0, 0x07,
        ]
        || Ipv6Addr::from_bits(ipv6.to_bits()) != ipv6
    {
        return 2;
    }

    let address = IpAddr::V4(ipv4);
    if !address.is_ipv4() || address.is_ipv6() {
        return 3;
    }
    if !matches!(IpAddr::V6(ipv6), IpAddr::V6(value) if value == ipv6) {
        return 4;
    }
    0
}
