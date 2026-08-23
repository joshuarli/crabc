use core::cmp::Ordering;

use crabc_rs::path::{basename_bytes, dirname_bytes};
use crabc_rs::text::{
    compare_versions, split_fields, tokens, CStrBuilder, CStrWrite, CStrWriteError,
};

#[test]
fn checked_builder_preserves_nul_and_reports_non_mutating_exact_failure() {
    let mut storage = [0xa5; 8];
    let mut builder = CStrBuilder::new(&mut storage).expect("non-empty destination");
    assert_eq!(builder.write_exact(b"abc").unwrap(), 3);
    assert_eq!(builder.as_bytes(), b"abc");
    assert_eq!(builder.as_c_str().to_bytes_with_nul(), b"abc\0");

    let before = builder.as_c_str().to_bytes_with_nul().to_vec();
    assert_eq!(
        builder.write_exact(b"toolong!"),
        Err(CStrWriteError::Capacity {
            needed: 9,
            capacity: 8,
        })
    );
    assert_eq!(builder.as_c_str().to_bytes_with_nul(), before.as_slice());
}

#[test]
fn bounded_and_padded_writes_are_explicit() {
    let mut storage = [0xcc; 8];
    let mut builder = CStrBuilder::new(&mut storage).unwrap();
    let bounded = builder.write_truncated(b"abcdefgh").unwrap();
    assert_eq!(bounded.copied(), 7);
    assert!(bounded.truncated());
    assert_eq!(builder.as_bytes(), b"abcdefg");

    let padded = builder.write_padded(b"xy", 6).unwrap();
    assert_eq!(padded.copied(), 2);
    assert_eq!(padded.padded(), 4);
    assert_eq!(builder.as_c_str().to_bytes_with_nul(), b"xy\0");

    // A source exactly at the padded width must retain all width bytes; a
    // longer source is truncated only after that complete payload.
    let exact = builder.write_padded(b"1234567", 7).unwrap();
    assert_eq!(exact.copied(), 7);
    assert!(!exact.truncated());
    assert_eq!(builder.as_c_str().to_bytes_with_nul(), b"1234567\0");
    let over = builder.write_padded(b"12345678", 7).unwrap();
    assert_eq!(over.copied(), 7);
    assert!(over.truncated());
    assert_eq!(builder.as_c_str().to_bytes_with_nul(), b"1234567\0");
}

#[test]
fn split_and_token_cursors_have_independent_state() {
    let mut split = split_fields(b",a,,b,", b",");
    assert_eq!(split.next(), Some(&b""[..]));
    assert_eq!(split.next(), Some(&b"a"[..]));
    assert_eq!(split.next(), Some(&b""[..]));
    assert_eq!(split.next(), Some(&b"b"[..]));
    assert_eq!(split.next(), Some(&b""[..]));
    assert_eq!(split.next(), None);

    let mut first = tokens(b"a::b", b":");
    let mut second = tokens(b"a::b", b":");
    assert_eq!(first.next(), Some(&b"a"[..]));
    assert_eq!(second.next(), Some(&b"a"[..]));
    assert_eq!(first.next(), Some(&b"b"[..]));
    assert_eq!(second.next(), Some(&b"b"[..]));
}

#[cfg(feature = "alloc")]
#[test]
fn owned_duplicate_preserves_non_utf8_bytes() {
    let source = core::ffi::CStr::from_bytes_with_nul(b"\xffx\0").unwrap();
    assert_eq!(crabc_rs::text::duplicate(source).as_bytes(), b"\xffx");
    assert_eq!(
        crabc_rs::text::duplicate_n(source, 1).as_bytes(),
        b"\xff"
    );
}

#[test]
fn version_comparison_and_paths_cover_edge_policy() {
    let left = core::ffi::CStr::from_bytes_with_nul(b"a01\0").unwrap();
    let right = core::ffi::CStr::from_bytes_with_nul(b"a1\0").unwrap();
    assert_eq!(compare_versions(left, right), Ordering::Less);
    assert_eq!(basename_bytes(b"//a//b").unwrap().as_bytes(), b"b");
    assert_eq!(dirname_bytes(b"//a//b").unwrap().as_bytes(), b"//a");
    assert_eq!(basename_bytes(b"////").unwrap().as_bytes(), b"/");
    assert_eq!(dirname_bytes(b"a").unwrap().as_bytes(), b".");
    assert!(basename_bytes(b"a\0/b").is_err());
}
