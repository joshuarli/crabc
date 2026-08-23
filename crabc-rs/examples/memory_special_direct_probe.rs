//! Link-free no-std proof for the native special byte-operation seam.

#![no_std]

use crabc_rs::memory::ByteOps;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_memory_special_direct_probe() -> i32 {
    let mut erased = *b"private";
    ByteOps::explicit_bzero(&mut erased);
    if erased != [0; 7] {
        return 1;
    }

    let mut copied = [0xcc; 8];
    let suffix_len = match ByteOps::memccpy(&mut copied, b"abca", b'c') {
        Some(suffix) => suffix.len(),
        None => return 2,
    };
    if copied[..3] != *b"abc" || copied[3] != 0xcc || suffix_len != 5 {
        return 3;
    }

    let mut appended = [0xcc; 7];
    let suffix_len = ByteOps::mempcpy(&mut appended, b"copy").len();
    if appended[..4] != *b"copy" || suffix_len != 3 {
        return 4;
    }

    let mut swapped = [0xcc; 5];
    ByteOps::swab(b"abcde", &mut swapped);
    if swapped != [b'b', b'a', b'd', b'c', 0xcc] {
        return 5;
    }

    0
}
