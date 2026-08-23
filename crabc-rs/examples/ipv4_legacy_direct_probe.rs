#![no_std]
#![crate_type = "staticlib"]

//! Link-free no-std proof for the musl-compatible legacy IPv4 parser.

use crabc_rs::net::{parse_ipv4_legacy, Ipv4Addr};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_ipv4_legacy_direct_probe() -> i32 {
    let loopback = match parse_ipv4_legacy(b"0177.1") {
        Some(value) => value,
        None => return 1,
    };
    if loopback != Ipv4Addr::new(127, 0, 0, 1) || loopback.octets() != [127, 0, 0, 1] {
        return 2;
    }

    let maximum = match parse_ipv4_legacy(b"0xffffffff") {
        Some(value) => value,
        None => return 3,
    };
    if maximum != Ipv4Addr::new(255, 255, 255, 255) {
        return 4;
    }

    if parse_ipv4_legacy(&[0xff, b'.', 0, 0, 1]).is_some()
        || parse_ipv4_legacy(b"127.0.0.1\0").is_some()
    {
        return 5;
    }
    0
}
