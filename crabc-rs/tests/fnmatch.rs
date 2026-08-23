use core::ffi::CStr;

use crabc_rs::pattern::{fnmatch, FnmatchFlags};

fn cstr(bytes: &'static [u8]) -> &'static CStr {
    CStr::from_bytes_with_nul(bytes).expect("fixture is one NUL-terminated C string")
}

#[test]
fn native_matcher_handles_wildcards_classes_and_non_utf8_names() {
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
    assert!(!fnmatch(
        cstr(b"[A]\0"),
        cstr(b"a\0"),
        FnmatchFlags::empty()
    ));
    assert!(fnmatch(
        cstr(b"[A]\0"),
        cstr(b"a\0"),
        FnmatchFlags::CASEFOLD
    ));

    let non_utf8 = cstr(b"\xff-data\0");
    assert!(fnmatch(cstr(b"*\0"), non_utf8, FnmatchFlags::empty()));
}

#[test]
fn native_matcher_preserves_path_period_escape_and_casefold_flags() {
    let pathname = FnmatchFlags::PATHNAME;
    assert!(fnmatch(cstr(b"*/lib\0"), cstr(b"usr/lib\0"), pathname));
    assert!(!fnmatch(cstr(b"*\0"), cstr(b"usr/lib\0"), pathname));
    assert!(fnmatch(
        cstr(b"*.rs\0"),
        cstr(b"src/lib.rs\0"),
        FnmatchFlags::empty()
    ));

    assert!(!fnmatch(
        cstr(b"*.rs\0"),
        cstr(b".lib.rs\0"),
        FnmatchFlags::PERIOD
    ));
    assert!(fnmatch(
        cstr(b".*\0"),
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
        FnmatchFlags::NOESCAPE,
    ));
    assert!(fnmatch(
        cstr(b"*.RS\0"),
        cstr(b"lib.rs\0"),
        FnmatchFlags::CASEFOLD
    ));
}

#[test]
fn native_matcher_supports_leading_directory_matches() {
    assert!(fnmatch(
        cstr(b"usr\0"),
        cstr(b"usr/local\0"),
        FnmatchFlags::PATHNAME | FnmatchFlags::LEADING_DIR,
    ));
    assert!(!fnmatch(
        cstr(b"usr\0"),
        cstr(b"usr/local\0"),
        FnmatchFlags::PATHNAME,
    ));
    assert!(fnmatch(
        cstr(b"usr\0"),
        cstr(b"usr/local\0"),
        FnmatchFlags::LEADING_DIR,
    ));
}
