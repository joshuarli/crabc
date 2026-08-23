#![no_std]
#![crate_type = "staticlib"]

//! Link-free no-std proof for musl's classful IPv4 helpers.

use crabc_rs::net::{
    ipv4_local_number, ipv4_network_number, make_ipv4_address, parse_ipv4_network_number, Ipv4Addr,
};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_ipv4_classful_direct_probe() -> i32 {
    if parse_ipv4_network_number(b"0xffffffff") != Some(u32::MAX)
        || parse_ipv4_network_number(b"not-an-address").is_some()
    {
        return 1;
    }

    let class_a = Ipv4Addr::new(127, 0, 0, 1);
    if ipv4_local_number(class_a) != 1 || ipv4_network_number(class_a) != 0x7f {
        return 2;
    }
    let class_b = Ipv4Addr::new(128, 0, 0, 1);
    if ipv4_local_number(class_b) != 1 || ipv4_network_number(class_b) != 0x8000 {
        return 3;
    }
    let class_c = Ipv4Addr::new(192, 0, 0, 1);
    if ipv4_local_number(class_c) != 1 || ipv4_network_number(class_c) != 0x00c0_0000 {
        return 4;
    }

    if make_ipv4_address(0x7f, 1) != class_a
        || make_ipv4_address(0x8000, 1) != class_b
        || make_ipv4_address(0xc00000, 1) != class_c
        || make_ipv4_address(128, 1) != Ipv4Addr::new(128, 128, 0, 1)
    {
        return 5;
    }
    0
}
