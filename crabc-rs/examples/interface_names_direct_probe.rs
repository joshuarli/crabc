#![no_std]
#![crate_type = "staticlib"]

//! Link-free no-std proof for native Linux interface-name enumeration.
//!
//! The callback surface intentionally uses the allocation-free link dump. Its
//! implementation opens a NETLINK_ROUTE socket and crosses the direct
//! socket/sendto/recvfrom/close seams; it does not call the public C ABI,
//! allocator, or TLS `errno` state.

use crabc_rs::net::netdevice;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_interface_names_direct_probe() -> i32 {
    let mut saw_loopback = false;
    let result = netdevice::for_each_link_name(|entry| {
        if entry.as_str() == "lo" && entry.index().get() > 0 {
            saw_loopback = true;
        }
        Ok(())
    });
    match result {
        Ok(()) if saw_loopback => 0,
        Ok(()) => 1,
        Err(error) => -error.raw(),
    }
}
