use crabc_rs::text::{NumberParseError, NumberParser};

#[test]
fn integer_parser_is_borrowed_complete_and_locale_free() {
    let decimal = NumberParser::decimal();
    assert_eq!(decimal.parse_u64(b"42"), Ok(42));
    assert_eq!(decimal.parse_i64(b"-42"), Ok(-42));

    // A successful parse is always a whole-slice parse; there is no C-style
    // end pointer which silently leaves a suffix for the caller to inspect.
    assert_eq!(
        decimal.parse_i64(b"42ms"),
        Err(NumberParseError::InvalidDigit {
            index: 2,
            byte: b'm',
        })
    );
    assert_eq!(
        decimal.parse_i64(b" 42"),
        Err(NumberParseError::InvalidDigit {
            index: 0,
            byte: b' ',
        })
    );
}

#[test]
fn integer_parser_handles_radix_and_machine_boundaries() {
    let binary = NumberParser::new(2).expect("binary parser");
    assert_eq!(binary.parse_u64(b"11111111"), Ok(255));
    assert_eq!(
        binary.parse_u64(b"11111112"),
        Err(NumberParseError::InvalidDigit {
            index: 7,
            byte: b'2',
        })
    );

    let hexadecimal = NumberParser::new(16).expect("hex parser");
    assert_eq!(hexadecimal.parse_u64(b"FFFFFFFFFFFFFFFF"), Ok(u64::MAX));
    assert_eq!(
        hexadecimal.parse_u64(b"10000000000000000"),
        Err(NumberParseError::Overflow)
    );

    let decimal = NumberParser::decimal();
    assert_eq!(decimal.parse_i64(b"-9223372036854775808"), Ok(i64::MIN));
    assert_eq!(
        decimal.parse_i64(b"-9223372036854775809"),
        Err(NumberParseError::Overflow)
    );
}
