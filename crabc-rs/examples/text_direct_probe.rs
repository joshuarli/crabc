//! Link-free no-std proof for the native text encoding seam.

#![no_std]

use crabc_rs::text::{TextConverter, TextEncoding, Unrepresentable};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_text_direct_probe() -> i32 {
    let mut encoded = [0u8; 16];
    let mut encoder = TextConverter::new(TextEncoding::Utf8, TextEncoding::Utf16Le);
    let encoded_result = match encoder.convert(b"A\xe2\x82\xac\xf0\x9f\x98\x80", &mut encoded) {
        Ok(value) if value.consumed == 8 && value.produced == 8 => value,
        _ => return 1,
    };

    let mut decoded = [0u8; 16];
    let mut decoder = TextConverter::new(TextEncoding::Utf16Le, TextEncoding::Utf8);
    match decoder.convert(&encoded[..encoded_result.produced], &mut decoded) {
        Ok(value)
            if value.consumed == 8
                && &decoded[..value.produced] == b"A\xe2\x82\xac\xf0\x9f\x98\x80" => {}
        _ => return 2,
    }

    let scalar_cases: &[(TextEncoding, &[u8])] = &[
        (
            TextEncoding::Utf16Be,
            &[0x00, 0x41, 0x20, 0xac, 0xd8, 0x3d, 0xde, 0x00],
        ),
        (
            TextEncoding::Utf32Be,
            &[
                0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x20, 0xac, 0x00, 0x01, 0xf6, 0x00,
            ],
        ),
        (
            TextEncoding::WChar,
            &[
                0x41, 0x00, 0x00, 0x00, 0xac, 0x20, 0x00, 0x00, 0x00, 0xf6, 0x01, 0x00,
            ],
        ),
    ];
    for &(encoding, expected) in scalar_cases {
        let mut scalar_encoded = [0u8; 16];
        let mut scalar_encoder = TextConverter::new(TextEncoding::Utf8, encoding);
        let scalar_result =
            match scalar_encoder.convert(b"A\xe2\x82\xac\xf0\x9f\x98\x80", &mut scalar_encoded) {
                Ok(value) if value.consumed == 8 && value.produced == expected.len() => value,
                _ => return 4,
            };
        if &scalar_encoded[..scalar_result.produced] != expected {
            return 5;
        }

        let mut scalar_decoded = [0u8; 16];
        let mut scalar_decoder = TextConverter::new(encoding, TextEncoding::Utf8);
        match scalar_decoder.convert(
            &scalar_encoded[..scalar_result.produced],
            &mut scalar_decoded,
        ) {
            Ok(value)
                if value.consumed == expected.len()
                    && &scalar_decoded[..value.produced] == b"A\xe2\x82\xac\xf0\x9f\x98\x80" => {}
            _ => return 6,
        }
    }

    let mut iso2_decoder = TextConverter::new(TextEncoding::Iso8859_2, TextEncoding::Utf8);
    let mut iso2_utf8 = [0u8; 4];
    match iso2_decoder.convert(&[0xa1], &mut iso2_utf8) {
        Ok(value)
            if value.consumed == 1 && value.produced == 2 && &iso2_utf8[..2] == b"\xc4\x84" => {}
        _ => return 7,
    }

    let mut iso15_encoder = TextConverter::new(TextEncoding::Utf8, TextEncoding::Iso8859_15);
    let mut iso15 = [0u8; 1];
    match iso15_encoder.convert(b"\xe2\x82\xac", &mut iso15) {
        Ok(value) if value.consumed == 3 && value.produced == 1 && iso15[0] == 0xa4 => {}
        _ => return 8,
    }

    let mut replacement = [0u8; 2];
    let mut ascii = TextConverter::new(TextEncoding::Utf8, TextEncoding::Ascii);
    match ascii.convert_with(b"\xc3\xa9", &mut replacement, Unrepresentable::Byte(b'*')) {
        Ok(value)
            if value.consumed == 2
                && value.produced == 1
                && value.substitutions == 1
                && replacement[0] == b'*' => {}
        _ => return 3,
    }

    0
}
