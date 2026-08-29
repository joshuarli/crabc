use core::ffi::CStr;

use crabc_rs::pattern::{fnmatch, FnmatchFlags};

fn cstr(bytes: &'static [u8]) -> &'static CStr {
    CStr::from_bytes_with_nul(bytes).expect("fixture is one NUL-terminated C string")
}

#[test]
fn x86_direct_matcher_handles_wildcards_classes_and_non_utf8_names() {
    assert!(fnmatch(
        cstr(b"*.rs\0"),
        cstr(b"lib.rs\0"),
        FnmatchFlags::empty()
    ));
    assert!(fnmatch(
        cstr(b"[[:alpha:]]*[[:digit:]]\0"),
        cstr(b"crate7\0"),
        FnmatchFlags::empty()
    ));
    assert!(!fnmatch(
        cstr(b"[[:digit:]]\0"),
        cstr(b"x\0"),
        FnmatchFlags::empty()
    ));
    assert!(fnmatch(
        cstr(b"[A]\0"),
        cstr(b"a\0"),
        FnmatchFlags::CASEFOLD
    ));
    assert!(fnmatch(
        cstr(b"*\0"),
        cstr(b"\xff-data\0"),
        FnmatchFlags::empty()
    ));
}

#[test]
fn x86_direct_matcher_preserves_path_period_escape_and_leading_directory_flags() {
    assert!(fnmatch(
        cstr(b"*/lib\0"),
        cstr(b"usr/lib\0"),
        FnmatchFlags::PATHNAME
    ));
    assert!(!fnmatch(
        cstr(b"*\0"),
        cstr(b"usr/lib\0"),
        FnmatchFlags::PATHNAME
    ));
    assert!(!fnmatch(
        cstr(b"*.rs\0"),
        cstr(b".lib.rs\0"),
        FnmatchFlags::PERIOD
    ));
    assert!(fnmatch(
        cstr(b"\\*.rs\0"),
        cstr(b"*.rs\0"),
        FnmatchFlags::empty()
    ));
    assert!(!fnmatch(
        cstr(b"\\*.rs\0"),
        cstr(b"*.rs\0"),
        FnmatchFlags::NOESCAPE
    ));
    assert!(fnmatch(
        cstr(b"usr\0"),
        cstr(b"usr/local\0"),
        FnmatchFlags::PATHNAME | FnmatchFlags::LEADING_DIR
    ));
}
