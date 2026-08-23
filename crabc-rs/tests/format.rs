use core::fmt::Write as _;

use crabc_rs::stdio::{format_to, BoundedFormatter, FormatResult};

#[test]
fn native_formatting_reports_complete_size_and_writes_a_prefix() {
    let mut output = [0xa5; 32];
    let result = format_to(&mut output, format_args!("{}:{}", "crabc", 10))
        .expect("the built-in formatter cannot fail");

    assert_eq!(
        result,
        FormatResult {
            written: 8,
            required: 8,
        }
    );
    assert!(!result.truncated());
    assert_eq!(&output[..result.written], b"crabc:10");
    assert_eq!(output[result.written], 0xa5);
}

#[test]
fn truncation_preserves_utf8_boundaries_and_reports_required_bytes() {
    let mut output = [0xa5; 2];
    let result = format_to(&mut output, format_args!("A{}Z", "é"))
        .expect("the built-in formatter cannot fail");

    assert_eq!(
        result,
        FormatResult {
            written: 1,
            required: 4,
        }
    );
    assert!(result.truncated());
    assert_eq!(&output[..result.written], b"A");
    assert_eq!(output[1], 0xa5);
    assert_eq!(core::str::from_utf8(&output[..result.written]), Ok("A"));
}

#[test]
fn empty_destination_still_measures_without_writing() {
    let mut output = [];
    let result = format_to(&mut output, format_args!("{}", "crabc"))
        .expect("the built-in formatter cannot fail");

    assert_eq!(
        result,
        FormatResult {
            written: 0,
            required: 5,
        }
    );
    assert!(result.truncated());
}

#[test]
fn formatter_can_be_used_as_a_typed_fmt_write_sink() {
    let mut output = [0xa5; 4];
    let mut formatter = BoundedFormatter::new(&mut output);
    write!(&mut formatter, "{}-{}", "a", 7).expect("bounded writes do not fail");

    assert_eq!(
        formatter.finish(),
        FormatResult {
            written: 3,
            required: 3,
        }
    );
    assert_eq!(&output[..3], b"a-7");
    assert_eq!(output[3], 0xa5);
}

#[test]
fn a_partial_scalar_blocks_later_chunks_from_backfilling_the_prefix() {
    let mut output = [0xa5; 2];
    let mut formatter = BoundedFormatter::new(&mut output);
    formatter
        .write_str("A")
        .expect("bounded writes do not fail");
    formatter
        .write_str("é")
        .expect("bounded writes do not fail");
    formatter
        .write_str("Z")
        .expect("bounded writes do not fail");

    assert_eq!(
        formatter.finish(),
        FormatResult {
            written: 1,
            required: 4,
        }
    );
    assert_eq!(output, [b'A', 0xa5]);
}

struct FailingDisplay;

impl core::fmt::Display for FailingDisplay {
    fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Err(core::fmt::Error)
    }
}

#[test]
fn custom_formatter_errors_are_not_silently_discarded() {
    let mut output = [0u8; 8];
    assert!(format_to(&mut output, format_args!("{}", FailingDisplay)).is_err());
}
