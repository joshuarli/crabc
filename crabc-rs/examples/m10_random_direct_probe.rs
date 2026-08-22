//! Link-free no-std proof for the M10 owned random-state seam.

#![no_std]

use crabc_rs::rand::{random_u32, RandomState};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_random_direct_probe() -> i32 {
    let mut first = RandomState::new(0x0123_4567_89ab_cdef);
    let mut second = RandomState::new(0x0123_4567_89ab_cdef);
    if random_u32(&mut first) != random_u32(&mut second) {
        return 1;
    }
    if first.next_u64() != second.next_u64() {
        return 2;
    }
    if RandomState::from_entropy().is_err() {
        return 3;
    }
    0
}
