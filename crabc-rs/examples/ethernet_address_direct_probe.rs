//! Link-free no-std proof for the owned Ethernet-address codec.

#![no_std]
#![crate_type = "staticlib"]

use crabc_rs::net::EthernetAddress;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_ethernet_address_direct_probe() -> i32 {
    let address = match EthernetAddress::parse(b"0x0:1:02:0X3:4:05") {
        Some(value) => value,
        None => return 1,
    };
    if address.octets() != [0, 1, 2, 3, 4, 5] {
        return 2;
    }

    if address.to_ascii_bytes() != *b"00:01:02:03:04:05" {
        return 3;
    }
    let mut output = [0xa5; 17];
    if address.write_to(&mut output) != Some(17) || output != *b"00:01:02:03:04:05" {
        return 4;
    }
    if EthernetAddress::parse(b"00:11:22:33:44:100").is_some()
        || EthernetAddress::parse(b"00:11:22:33:44").is_some()
    {
        return 5;
    }
    0
}
