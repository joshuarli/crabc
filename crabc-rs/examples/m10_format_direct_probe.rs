//! Link-free no-std proof for the M10 bounded formatting seam.

#![no_std]

use crabc_rs::stdio::format_to;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_format_direct_probe() -> i32 {
    let mut truncated = [0xa5; 2];
    let result = match format_to(&mut truncated, format_args!("A{}Z", "é")) {
        Ok(result) => result,
        Err(_) => return 1,
    };
    if result.written != 1 || result.required != 4 || !result.truncated() {
        return 2;
    }
    if truncated[0] != b'A' || truncated[1] != 0xa5 {
        return 3;
    }

    let mut complete = [0xa5; 3];
    let result = match format_to(&mut complete, format_args!("x{}", 7)) {
        Ok(result) => result,
        Err(_) => return 4,
    };
    if result.written != 2 || result.required != 2 || result.truncated() {
        return 5;
    }
    if complete[..2] != *b"x7" || complete[2] != 0xa5 {
        return 6;
    }
    0
}
