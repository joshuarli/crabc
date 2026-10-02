#![cfg(target_arch = "x86_64")]

use core::ffi::CStr;

use crabc_rs::path::{basename, basename_bytes, dirname, dirname_bytes, PathError, PathPart};

#[test]
fn borrowed_components_preserve_bytes_and_caller_storage() {
    let input = *b"//dir//\xffleaf///\0";
    let original = input;
    let path = CStr::from_bytes_with_nul(&input).expect("terminated byte path");
    let base = basename(path);
    let parent = dirname(path);

    assert_eq!(base.as_bytes(), b"\xffleaf");
    assert_eq!(parent.as_bytes(), b"//dir");
    assert_eq!(base.as_bytes().as_ptr(), input[7..].as_ptr());
    assert_eq!(parent.as_bytes().as_ptr(), input.as_ptr());
    assert_eq!(input, original);
    assert_eq!(PathPart::from_cstr(path).as_bytes(), path.to_bytes());
    assert_eq!(basename_bytes(path.to_bytes()), Ok(base));
    assert_eq!(dirname_bytes(path.to_bytes()), Ok(parent));
}

#[test]
fn empty_relative_and_root_paths_have_explicit_components() {
    for (input, base, parent) in [
        (b"".as_slice(), b".".as_slice(), b".".as_slice()),
        (b"leaf///".as_slice(), b"leaf".as_slice(), b".".as_slice()),
        (b"////".as_slice(), b"/".as_slice(), b"/".as_slice()),
        (b"//dir//leaf///".as_slice(), b"leaf".as_slice(), b"//dir".as_slice()),
    ] {
        assert_eq!(basename_bytes(input).expect("basename").as_bytes(), base);
        assert_eq!(dirname_bytes(input).expect("dirname").as_bytes(), parent);
    }
    assert!(dirname_bytes(b"leaf").expect("relative parent").is_current());
    assert!(basename_bytes(b"////").expect("root basename").is_root());
}

#[test]
fn byte_paths_reject_the_first_interior_nul_before_component_extraction() {
    let input = b"dir/leaf\0/trailing\0";
    let error = PathError::InteriorNul { index: 8 };
    assert_eq!(PathPart::new(input), Err(error));
    assert_eq!(basename_bytes(input), Err(error));
    assert_eq!(dirname_bytes(input), Err(error));
}
