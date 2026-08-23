//! Link-free no-std proof for direct directory cursor positioning.

#![no_std]

use core::mem::MaybeUninit;

use crabc_rs::fs::Dir;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_directory_position_direct_probe() -> i32 {
    let mut storage = [MaybeUninit::uninit(); 4096];
    let mut stream = match Dir::open(&b"/tmp"[..], &mut storage) {
        Ok(stream) => stream,
        Err(error) => return -error.raw(),
    };
    let cookie = match stream.next() {
        Some(Ok(entry)) => entry.next_entry_cookie() as i64,
        Some(Err(error)) => return -error.raw(),
        None => return 1,
    };
    if stream.seek(cookie).is_err() {
        return 2;
    }
    stream.rewind();
    if stream.next().is_none() {
        return 3;
    }
    0
}
