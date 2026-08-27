#![cfg(target_arch = "x86_64")]

use core::ffi::CStr;
use core::mem::MaybeUninit;

use crabc_rs::process;
use crabc_rs::Errno;

const BUFFER_CAPACITY: usize = 4096;
const UNTOUCHED: u8 = 0xa5;

#[test]
fn x86_64_getcwd_returns_exact_current_directory_and_preserves_suffix() {
    let expected = std::env::current_dir().expect("read the test current directory");
    let expected = std::os::unix::ffi::OsStrExt::as_bytes(expected.as_os_str());

    let mut storage = [MaybeUninit::new(UNTOUCHED); BUFFER_CAPACITY];
    let (initialized, untouched) = process::getcwd(&mut storage).expect("read current directory");

    assert_eq!(initialized.len(), expected.len() + 1);
    assert_eq!(initialized.last(), Some(&0));
    let path = CStr::from_bytes_with_nul(initialized).expect("kernel returned one trailing NUL");
    assert_eq!(path.to_bytes(), expected);
    assert!(untouched
        .iter()
        .all(|byte| unsafe { byte.assume_init() } == UNTOUCHED));
}

#[test]
fn x86_64_getcwd_reports_range_for_one_byte_buffer() {
    let mut storage = [MaybeUninit::<u8>::uninit(); 1];
    match process::getcwd(&mut storage) {
        Ok(_) => panic!("a one-byte getcwd buffer must be too small"),
        Err(error) => assert_eq!(error, Errno::RANGE),
    }
}

#[test]
fn x86_64_getcwd_reports_range_for_empty_buffer() {
    let mut storage = [MaybeUninit::<u8>::uninit(); 0];
    match process::getcwd(&mut storage) {
        Ok(_) => panic!("a zero-byte getcwd buffer must not succeed"),
        Err(error) => assert_eq!(error, Errno::RANGE),
    }
}
