//! Link-free no-std proof for the native byte-string/stateful seam.

#![no_std]

use core::cmp::Ordering;

use crabc_rs::path::{basename_bytes, dirname_bytes};
use crabc_rs::text::{compare_versions, split_fields, tokens, CStrBuilder, CStrWrite};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_text_stateful_direct_probe() -> i32 {
    let mut storage = [0u8; 16];
    let mut builder = match CStrBuilder::new(&mut storage) {
        Ok(builder) => builder,
        Err(_) => return 1,
    };
    if builder.write_exact(b"abc").ok() != Some(3)
        || builder.append_exact(b"def").ok() != Some(3)
        || builder.as_c_str().to_bytes() != b"abcdef"
    {
        return 2;
    }
    if builder.write_padded(b"123456789012345", 15).ok().map(|copy| copy.copied()) != Some(15)
        || builder.as_c_str().to_bytes() != b"123456789012345"
    {
        return 3;
    }

    let mut fields = split_fields(b",a,,b,", b",");
    if fields.next() != Some(&b""[..])
        || fields.next() != Some(&b"a"[..])
        || fields.next() != Some(&b""[..])
        || fields.next() != Some(&b"b"[..])
        || fields.next() != Some(&b""[..])
        || fields.next().is_some()
    {
        return 4;
    }
    let mut first = tokens(b"a::b", b":");
    let mut second = tokens(b"a::b", b":");
    if first.next() != Some(&b"a"[..])
        || second.next() != Some(&b"a"[..])
        || first.next() != Some(&b"b"[..])
        || second.next() != Some(&b"b"[..])
    {
        return 5;
    }

    let left = core::ffi::CStr::from_bytes_with_nul(b"a01\0").unwrap();
    let right = core::ffi::CStr::from_bytes_with_nul(b"a1\0").unwrap();
    if compare_versions(left, right) != Ordering::Less
        || basename_bytes(b"//a//b").unwrap().as_bytes() != b"b"
        || dirname_bytes(b"//a//b").unwrap().as_bytes() != b"//a"
        || basename_bytes(b"a\0/b").is_ok()
    {
        return 6;
    }

    0
}
