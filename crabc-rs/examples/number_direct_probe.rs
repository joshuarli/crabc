//! Link-free no-std proof for the explicit integer parser seam.

#![no_std]

use crabc_rs::text::{NumberParseError, NumberParser};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_number_direct_probe() -> i32 {
    let decimal = NumberParser::decimal();
    if decimal.parse_u64(b"18446744073709551615") != Ok(u64::MAX) {
        return 1;
    }
    if decimal.parse_i64(b"-9223372036854775808") != Ok(i64::MIN) {
        return 2;
    }
    if decimal.parse_i64(b"12tail")
        != Err(NumberParseError::InvalidDigit {
            index: 2,
            byte: b't',
        })
    {
        return 3;
    }

    let hexadecimal = match NumberParser::new(16) {
        Some(parser) => parser,
        None => return 4,
    };
    if hexadecimal.parse_u64(b"deadBEEF") != Ok(0xdead_beef) {
        return 5;
    }
    if hexadecimal.parse_u64(b"0x2a")
        != Err(NumberParseError::InvalidDigit {
            index: 1,
            byte: b'x',
        })
    {
        return 6;
    }
    0
}
