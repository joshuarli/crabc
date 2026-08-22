//! Link-free no-std proof for the direct Linux process-auxv seam.

#![no_std]

use crabc_rs::param;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_param_auxv_direct_probe() -> i32 {
    let page_size = param::page_size();
    if page_size == 0 || !page_size.is_power_of_two() {
        return 1;
    }
    let (hwcap, _) = param::linux_hwcap();
    if hwcap == 0 {
        return 2;
    }
    if param::linux_minsigstksz() == 0 {
        return 3;
    }
    if param::linux_execfn().to_bytes().is_empty() {
        return 4;
    }
    0
}
