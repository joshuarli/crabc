use crabc_rs::text::{
    is_alnum, is_alpha, is_ascii, is_blank, is_cntrl, is_digit, is_graph, is_lower, is_print,
    is_punct, is_space, is_upper, is_xdigit, to_ascii, to_lower, to_upper, AsciiClass,
};

#[test]
fn native_ctype_uses_the_fixed_c_locale_byte_table() {
    assert!(is_ascii(0x00));
    assert!(is_ascii(0x7f));
    assert!(!is_ascii(0x80));

    assert!(is_alpha(b'A'));
    assert!(is_alpha(b'z'));
    assert!(is_digit(b'5'));
    assert!(is_alnum(b'5'));
    assert!(!is_alnum(b'_'));
    assert!(is_blank(b' '));
    assert!(is_blank(b'\t'));
    assert!(is_cntrl(b'\0'));
    assert!(is_cntrl(0x7f));
    assert!(is_graph(b'!'));
    assert!(!is_graph(b' '));
    assert!(is_print(b' '));
    assert!(is_punct(b'~'));
    assert!(is_space(b'\n'));
    assert!(is_upper(b'Q'));
    assert!(is_lower(b'q'));
    assert!(is_xdigit(b'F'));
    assert!(is_xdigit(b'f'));
    assert!(!is_xdigit(b'G'));

    let classes = AsciiClass::classify(b'7');
    assert!(classes.is_digit());
    assert!(classes.is_xdigit());
    assert!(classes.is_alnum());
    assert_eq!(classes.bits(), (AsciiClass::DIGIT.bits() | AsciiClass::XDIGIT.bits()));
}

#[test]
fn native_ctype_makes_high_bytes_and_eof_boundary_explicit() {
    for byte in [0x80, 0xa0, 0xc3, 0xff] {
        assert!(!is_ascii(byte));
        assert_eq!(AsciiClass::classify(byte), AsciiClass::EMPTY);
        assert!(!is_alpha(byte));
        assert!(!is_alnum(byte));
        assert!(!is_graph(byte));
        assert!(!is_print(byte));
        assert_eq!(to_lower(byte), byte);
        assert_eq!(to_upper(byte), byte);
    }

    assert_eq!(to_ascii(0x80), 0);
    assert_eq!(to_ascii(0xff), 0x7f);
    // All native predicates take u8: C's negative EOF sentinel and values
    // greater than UCHAR_MAX must be rejected before they cross the boundary.
    assert!(u8::try_from(-1_i16).is_err());
    assert!(u8::try_from(256_u16).is_err());
}
