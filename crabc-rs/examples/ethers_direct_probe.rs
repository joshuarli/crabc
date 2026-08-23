//! Link-free no-std proof for bounded ethers parsing and IPv6 constants.

#![no_std]
#![crate_type = "staticlib"]

use crabc_rs::net::ethers::{parse_line, EthernetLine, Ipv6Constants};
use crabc_rs::net::Ipv6Addr;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_ethers_direct_probe() -> i32 {
    let EthernetLine::Record(record) = parse_line(b"00:01:02:03:04:05 probe") else {
        return 1;
    };
    if record.address().octets() != [0, 1, 2, 3, 4, 5]
        || record.hostname() != b"probe".as_slice()
    {
        return 2;
    }
    if !matches!(parse_line(b"# comment"), EthernetLine::Comment)
        || !matches!(parse_line(b" \t"), EthernetLine::Blank)
        || !matches!(parse_line(b"bad"), EthernetLine::Invalid)
    {
        return 3;
    }
    if Ipv6Constants::ANY != Ipv6Addr::UNSPECIFIED
        || Ipv6Constants::LOOPBACK != Ipv6Addr::LOCALHOST
    {
        return 4;
    }
    0
}
