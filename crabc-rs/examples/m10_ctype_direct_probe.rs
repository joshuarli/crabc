//! Link-free no-std proof for the M10 native byte ctype seam.

#![no_std]

use crabc_rs::text::{
    is_alnum, is_alpha, is_ascii, is_blank, is_cntrl, is_digit, is_graph, is_print, is_punct,
    is_space, is_xdigit, to_ascii, to_lower, to_upper, AsciiClass,
};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_ctype_direct_probe() -> i32 {
    let letter = AsciiClass::classify(b'A');
    if !letter.is_alpha() || !letter.is_upper() || letter.is_digit() {
        return 1;
    }
    if !is_ascii(0x7f) || is_ascii(0x80) {
        return 2;
    }
    if !is_alnum(b'7') || !is_digit(b'7') || !is_xdigit(b'F') {
        return 3;
    }
    if !is_blank(b'\t') || !is_space(b'\n') || is_blank(b'\n') {
        return 4;
    }
    if !is_cntrl(0x7f) || !is_punct(b'!') || !is_graph(b'!') || !is_print(b' ') {
        return 5;
    }
    if is_alpha(0x80) || is_graph(0x80) || is_print(0x80) {
        return 6;
    }
    if to_lower(b'A') != b'a' || to_upper(b'z') != b'Z' {
        return 7;
    }
    if to_lower(0xff) != 0xff || to_upper(0xff) != 0xff || to_ascii(0xff) != 0x7f {
        return 8;
    }
    if !AsciiClass::classify(0x80).is_empty() {
        return 9;
    }
    0
}
