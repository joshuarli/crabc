use crabc_rs::text::{ConvertError, TextConverter, TextEncoding, Unrepresentable};

#[test]
fn native_text_facade_supports_only_the_documented_strict_subset() {
    assert_eq!(TextEncoding::from_name(b"utf8"), Some(TextEncoding::Utf8));
    assert_eq!(TextEncoding::from_name(b"UTF_16LE"), Some(TextEncoding::Utf16Le));
    assert_eq!(TextEncoding::from_name(b"UTF-16BE"), Some(TextEncoding::Utf16Be));
    assert_eq!(TextEncoding::from_name(b"UTF-32LE"), Some(TextEncoding::Utf32Le));
    assert_eq!(TextEncoding::from_name(b"UCS4BE"), Some(TextEncoding::Utf32Be));
    assert_eq!(TextEncoding::from_name(b"wchar-t"), Some(TextEncoding::WChar));
    assert_eq!(TextEncoding::from_name(b"ASCII"), Some(TextEncoding::Ascii));

    // The C iconv vocabulary remains wider than this native Rust slice.
    assert_eq!(
        TextEncoding::from_name(b"ISO-8859-2"),
        Some(TextEncoding::Iso8859_2)
    );
    assert_eq!(
        TextEncoding::from_name(b"ISO_8859_16"),
        Some(TextEncoding::Iso8859_16)
    );
    assert_eq!(
        TextEncoding::from_name(b"TIS-620"),
        Some(TextEncoding::Iso8859_11)
    );
    assert_eq!(TextEncoding::from_name(b"ISO-8859-1"), None);
    assert_eq!(TextEncoding::from_name(b"CP1252"), None);
    assert_eq!(TextEncoding::from_name(b"SHIFTJIS"), None);
}

#[test]
fn native_text_conversion_is_borrowed_typed_and_resumable() {
    let input = "A€😀".as_bytes();
    let mut utf16 = [0u8; 16];
    let mut encoder = TextConverter::new(TextEncoding::Utf8, TextEncoding::Utf16Le);
    let encoded = encoder.convert(input, &mut utf16).expect("encode UTF-16LE");
    assert_eq!(encoded.consumed, input.len());
    assert_eq!(encoded.produced, 2 + 2 + 4);

    let mut utf8 = [0u8; 16];
    let mut decoder = TextConverter::new(TextEncoding::Utf16Le, TextEncoding::Utf8);
    let decoded = decoder
        .convert(&utf16[..encoded.produced], &mut utf8)
        .expect("decode UTF-16LE");
    assert_eq!(&utf8[..decoded.produced], input);

    let mut small = [0u8; 2];
    let error = encoder
        .convert(b"AB", &mut small)
        .expect_err("second scalar does not fit");
    assert_eq!(
        error,
        ConvertError::OutputFull {
            consumed: 1,
            produced: 2,
        }
    );
    assert_eq!(error.consumed(), 1);
    assert_eq!(error.produced(), 2);
}

#[test]
fn native_text_scalar_variants_preserve_explicit_byte_order() {
    let input = "A€😀".as_bytes();
    let cases: &[(TextEncoding, &[u8])] = &[
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

    for &(encoding, expected) in cases {
        let mut encoded = [0u8; 16];
        let mut encoder = TextConverter::new(TextEncoding::Utf8, encoding);
        let encoded_progress = encoder.convert(input, &mut encoded).expect("encode scalars");
        assert_eq!(encoded_progress.consumed, input.len());
        assert_eq!(&encoded[..encoded_progress.produced], expected);

        let mut decoded = [0u8; 16];
        let mut decoder = TextConverter::new(encoding, TextEncoding::Utf8);
        let decoded_progress = decoder
            .convert(&encoded[..encoded_progress.produced], &mut decoded)
            .expect("decode scalars");
        assert_eq!(decoded_progress.consumed, expected.len());
        assert_eq!(&decoded[..decoded_progress.produced], input);
    }

    let mut output = [0u8; 2];
    let mut encoder = TextConverter::new(TextEncoding::Utf8, TextEncoding::Utf16Be);
    assert_eq!(
        encoder.convert(b"AB", &mut output),
        Err(ConvertError::OutputFull {
            consumed: 1,
            produced: 2,
        })
    );
}

#[test]
fn ascii_misses_are_explicit_or_counted_as_substitutions() {
    let mut strict = TextConverter::new(TextEncoding::Utf8, TextEncoding::Ascii);
    assert_eq!(
        strict.convert("é".as_bytes(), &mut [0; 4]),
        Err(ConvertError::Unrepresentable {
            consumed: 0,
            produced: 0,
            codepoint: 0xe9,
        })
    );

    let mut replacing = TextConverter::new(TextEncoding::Utf8, TextEncoding::Ascii);
    let mut output = [0u8; 4];
    let conversion = replacing
        .convert_with("Aé".as_bytes(), &mut output, Unrepresentable::Byte(b'?'))
        .expect("replacement policy is explicit");
    assert_eq!(conversion.consumed, 3);
    assert_eq!(conversion.produced, 2);
    assert_eq!(conversion.substitutions, 1);
    assert_eq!(&output[..2], b"A?");
}

#[test]
fn native_text_iso8859_table_codecs_are_borrowed_and_typed() {
    let encodings = [
        TextEncoding::Iso8859_2,
        TextEncoding::Iso8859_3,
        TextEncoding::Iso8859_4,
        TextEncoding::Iso8859_5,
        TextEncoding::Iso8859_6,
        TextEncoding::Iso8859_7,
        TextEncoding::Iso8859_8,
        TextEncoding::Iso8859_9,
        TextEncoding::Iso8859_10,
        TextEncoding::Iso8859_11,
        TextEncoding::Iso8859_13,
        TextEncoding::Iso8859_14,
        TextEncoding::Iso8859_15,
        TextEncoding::Iso8859_16,
    ];

    for encoding in encodings {
        let mut decoder = TextConverter::new(encoding, TextEncoding::Utf8);
        let mut decoded = [0u8; 4];
        let conversion = decoder
            .convert(&[b'A', 0x80], &mut decoded)
            .expect("table bytes decode as one-byte scalars");
        assert_eq!(conversion.consumed, 2);
        assert_eq!(conversion.produced, 3);
        assert_eq!(&decoded[..3], &[b'A', 0xc2, 0x80]);

        let mut encoder = TextConverter::new(TextEncoding::Utf8, encoding);
        let mut encoded = [0u8; 2];
        let conversion = encoder
            .convert(&decoded[..3], &mut encoded)
            .expect("table scalar round-trip");
        assert_eq!(conversion.consumed, 3);
        assert_eq!(conversion.produced, 2);
        assert_eq!(&encoded, &[b'A', 0x80]);
    }

    let mut iso2 = TextConverter::new(TextEncoding::Iso8859_2, TextEncoding::Utf8);
    let mut utf8 = [0u8; 4];
    let conversion = iso2
        .convert(&[0xa1], &mut utf8)
        .expect("ISO-8859-2 table mapping");
    assert_eq!(&utf8[..conversion.produced], "Ą".as_bytes());

    let mut iso15 = TextConverter::new(TextEncoding::Utf8, TextEncoding::Iso8859_15);
    let mut encoded = [0u8; 1];
    let conversion = iso15
        .convert("€".as_bytes(), &mut encoded)
        .expect("ISO-8859-15 euro mapping");
    assert_eq!(conversion.produced, 1);
    assert_eq!(encoded[0], 0xa4);
}
